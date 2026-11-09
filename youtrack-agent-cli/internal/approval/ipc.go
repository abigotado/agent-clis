package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

const (
	// IPCHeaderBytes is the exact byte length of a protocol-v2 frame header.
	IPCHeaderBytes = 16
	// IPCChallengeSize is the exact byte length of a request challenge.
	IPCChallengeSize = 32
	// IPCChallengeBytes is retained as the protocol challenge-size alias.
	IPCChallengeBytes = IPCChallengeSize
	// IPCVersion is the only accepted frame version.
	IPCVersion uint8 = 2
	// MaxIPCPlanBytes bounds the canonical plan carried by a request.
	MaxIPCPlanBytes = intent.MaxCanonicalPlanBytes

	ipcMagic              = "YTAPIPC\x00"
	ipcSPKIBytes          = p256DERSPKIBytes
	maxIPCRequestPayload  = IPCChallengeSize + MaxIPCPlanBytes
	maxIPCSuccessPayload  = IPCChallengeSize + ipcSPKIBytes + MaxReceiptBytes
	exactIPCErrorPayload  = IPCChallengeSize + 1
	minimumRequestPayload = IPCChallengeSize + 1
	minimumSuccessPayload = IPCChallengeSize + ipcSPKIBytes + 1
)

// IPCFrameKind identifies one protocol-v2 frame payload.
type IPCFrameKind uint8

const (
	IPCFrameRequest IPCFrameKind = 1
	IPCFrameSuccess IPCFrameKind = 2
	IPCFrameError   IPCFrameKind = 3
)

// IPCErrorCode is the complete closed helper-error vocabulary.
type IPCErrorCode uint8

const (
	IPCErrorUserCanceled            IPCErrorCode = 1
	IPCErrorRequestInvalid          IPCErrorCode = 2
	IPCErrorUserPresenceUnavailable IPCErrorCode = 3
	IPCErrorKeyUnavailable          IPCErrorCode = 4
	IPCErrorSigningFailed           IPCErrorCode = 5
	IPCErrorInternalFailure         IPCErrorCode = 6
)

type ipcFrame struct {
	Kind    IPCFrameKind
	Payload []byte
}

// IPCRequest is a validated helper-side request. Snapshot is always non-nil
// for values returned by DecodeIPCRequest.
type IPCRequest struct {
	Challenge [IPCChallengeSize]byte
	Snapshot  *ApprovalSnapshot
}

// IPCSuccess carries the echoed challenge, exact enrolled-key SPKI, and
// canonical signed receipt bytes for helper-side encoding.
type IPCSuccess struct {
	Challenge   [IPCChallengeSize]byte
	SPKIDER     []byte
	ReceiptJSON []byte
}

// IPCFailure carries only the echoed challenge and a closed helper error code.
type IPCFailure struct {
	Challenge [IPCChallengeSize]byte
	Code      IPCErrorCode
}

// ApprovalSnapshot owns one exact canonical plan encoding and the single
// parsed Plan derived from it.
type ApprovalSnapshot struct {
	bytes []byte
	plan  intent.Plan
}

// NewApprovalSnapshot validates and defensively owns one canonical plan.
func NewApprovalSnapshot(raw []byte) (*ApprovalSnapshot, error) {
	if len(raw) == 0 || len(raw) > MaxIPCPlanBytes {
		return nil, responseInvalid("the approval plan snapshot is empty or oversized", nil)
	}
	return newApprovalSnapshotOwned(append([]byte(nil), raw...))
}

// Bytes returns a defensive copy of the exact canonical plan bytes.
func (snapshot *ApprovalSnapshot) Bytes() []byte {
	if snapshot == nil {
		return nil
	}
	return append([]byte(nil), snapshot.bytes...)
}

// ExpectedSigningKey is the enrolled P-256 key authority for one response.
type ExpectedSigningKey struct {
	generation  string
	spkiDER     []byte
	fingerprint string
	publicKey   *ecdsa.PublicKey
}

// NewExpectedSigningKey validates and defensively owns the complete enrolled
// key identity used as authority for response verification.
func NewExpectedSigningKey(generation string, spkiDER []byte, fingerprint string) (*ExpectedSigningKey, error) {
	if !isCanonicalKeyGeneration(generation) {
		return nil, signingKeyMismatch("the enrolled signing-key generation is invalid", nil)
	}
	x963, err := P256DERSPKIToX963(spkiDER)
	if err != nil {
		return nil, signingKeyMismatch("the enrolled signing key is malformed", err)
	}
	want, err := P256SPKIFingerprintSHA256(spkiDER)
	if err != nil || fingerprint != want {
		return nil, signingKeyMismatch("the enrolled signing-key fingerprint does not match its SPKI", err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), x963)
	if x == nil || y == nil {
		return nil, signingKeyMismatch("the enrolled signing key is malformed", nil)
	}
	return &ExpectedSigningKey{
		generation: generation, spkiDER: append([]byte(nil), spkiDER...), fingerprint: fingerprint,
		publicKey: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
	}, nil
}

// Generation returns the enrolled key-generation label.
func (key *ExpectedSigningKey) Generation() string {
	if key == nil {
		return ""
	}
	return key.generation
}

// SPKIDER returns a defensive copy of the enrolled key encoding.
func (key *ExpectedSigningKey) SPKIDER() []byte {
	if key == nil {
		return nil
	}
	return append([]byte(nil), key.spkiDER...)
}

// FingerprintSHA256 returns the enrolled SPKI fingerprint.
func (key *ExpectedSigningKey) FingerprintSHA256() string {
	if key == nil {
		return ""
	}
	return key.fingerprint
}

// HelperFailure contains one validated code from the closed helper vocabulary.
type HelperFailure struct{ Code IPCErrorCode }

// ValidatedIPCResponse is a sealed result. Only the combined decoder creates
// valid success or failure values.
type ValidatedIPCResponse struct {
	receipt *Receipt
	failure *HelperFailure
}

// VerifiedReceipt returns the verified success arm when present.
func (response *ValidatedIPCResponse) VerifiedReceipt() (*Receipt, bool) {
	if response == nil || response.receipt == nil {
		return nil, false
	}
	copy := *response.receipt
	return &copy, true
}

// HelperError returns the validated helper-failure arm when present.
func (response *ValidatedIPCResponse) HelperError() (*HelperFailure, bool) {
	if response == nil || response.failure == nil {
		return nil, false
	}
	copy := *response.failure
	return &copy, true
}

// AsError maps the closed helper code to its stable CodeConfirm contract.
func (failure HelperFailure) AsError() error { return helperFailureError(failure.Code) }

// NewIPCChallenge returns a fresh opaque 256-bit challenge from crypto/rand.
func NewIPCChallenge() ([IPCChallengeSize]byte, error) {
	var challenge [IPCChallengeSize]byte
	if _, err := io.ReadFull(rand.Reader, challenge[:]); err != nil {
		return challenge, fmt.Errorf("allocate approval IPC challenge: %w", err)
	}
	return challenge, nil
}

// EncodeIPCFrame returns one exact bounded protocol-v2 frame.
func EncodeIPCFrame(kind IPCFrameKind, payload []byte) ([]byte, error) {
	if err := validateIPCPayloadLength(kind, uint64(len(payload))); err != nil {
		return nil, responseInvalid("the approval IPC payload length is invalid", err)
	}
	raw := make([]byte, IPCHeaderBytes+len(payload))
	copy(raw[:8], ipcMagic)
	raw[8] = IPCVersion
	raw[9] = byte(kind)
	binary.BigEndian.PutUint32(raw[12:16], uint32(len(payload)))
	copy(raw[IPCHeaderBytes:], payload)
	return raw, nil
}

// EncodeIPCRequest frames an already validated snapshot without re-parsing or
// re-marshalling it.
func EncodeIPCRequest(challenge [IPCChallengeSize]byte, snapshot *ApprovalSnapshot) ([]byte, error) {
	if snapshot == nil || len(snapshot.bytes) == 0 {
		return nil, responseInvalid("the approval plan snapshot is missing", nil)
	}
	payload := make([]byte, IPCChallengeSize+len(snapshot.bytes))
	copy(payload, challenge[:])
	copy(payload[IPCChallengeSize:], snapshot.bytes)
	return EncodeIPCFrame(IPCFrameRequest, payload)
}

// DecodeIPCRequest performs one payload copy and parses the plan only once.
func DecodeIPCRequest(raw []byte) (*IPCRequest, error) {
	frame, err := decodeIPCFrame(raw)
	if err != nil {
		return nil, err
	}
	if frame.Kind != IPCFrameRequest {
		return nil, responseInvalid("the approval IPC frame is not a request", nil)
	}
	request := &IPCRequest{}
	copy(request.Challenge[:], frame.Payload[:IPCChallengeSize])
	request.Snapshot, err = newApprovalSnapshotOwned(frame.Payload[IPCChallengeSize:])
	if err != nil {
		return nil, err
	}
	return request, nil
}

// EncodeIPCSuccess frames a strict helper-side success payload.
func EncodeIPCSuccess(success IPCSuccess) ([]byte, error) {
	if _, err := P256DERSPKIToX963(success.SPKIDER); err != nil {
		return nil, responseInvalid("the approval response SPKI is invalid", err)
	}
	if _, err := ParseReceiptBytes(success.ReceiptJSON); err != nil {
		return nil, responseInvalid("the approval response receipt is invalid", err)
	}
	payload := make([]byte, IPCChallengeSize+len(success.SPKIDER)+len(success.ReceiptJSON))
	copy(payload, success.Challenge[:])
	copy(payload[IPCChallengeSize:], success.SPKIDER)
	copy(payload[IPCChallengeSize+len(success.SPKIDER):], success.ReceiptJSON)
	return EncodeIPCFrame(IPCFrameSuccess, payload)
}

// EncodeIPCFailure frames a closed helper failure without untrusted text.
func EncodeIPCFailure(failure IPCFailure) ([]byte, error) {
	if !failure.Code.valid() {
		return nil, responseInvalid("the approval helper error code is unknown", nil)
	}
	payload := make([]byte, exactIPCErrorPayload)
	copy(payload, failure.Challenge[:])
	payload[IPCChallengeSize] = byte(failure.Code)
	return EncodeIPCFrame(IPCFrameError, payload)
}

// DecodeAndValidateIPCResponse is the sole response decoder. It binds both
// response kinds to the challenge; success also binds the snapshot and the
// enrolled key and caller-supplied expected binding and verifies the signed
// receipt. The expected binding itself is not proof of registry authority.
func DecodeAndValidateIPCResponse(ctx context.Context, raw []byte, expectedChallenge [IPCChallengeSize]byte, snapshot *ApprovalSnapshot, expectedKey *ExpectedSigningKey, expectedBinding *ExpectedReceiptBinding, now time.Time) (*ValidatedIPCResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if snapshot == nil || len(snapshot.bytes) == 0 || expectedKey == nil || expectedKey.publicKey == nil || !expectedBinding.valid() {
		return nil, responseInvalid("approval response validation dependencies are missing", nil)
	}
	frame, err := decodeIPCFrame(raw)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(frame.Payload[:IPCChallengeSize], expectedChallenge[:]) != 1 {
		return nil, challengeMismatch()
	}
	switch frame.Kind {
	case IPCFrameError:
		code := IPCErrorCode(frame.Payload[IPCChallengeSize])
		if !code.valid() {
			return nil, responseInvalid("the approval helper error code is unknown", nil)
		}
		return &ValidatedIPCResponse{failure: &HelperFailure{Code: code}}, nil
	case IPCFrameSuccess:
		if keyGenerationRevision(expectedKey.generation) != expectedBinding.registryRevision {
			return nil, signingKeyMismatch("the enrolled signing key does not match the expected registry revision", nil)
		}
		return validateIPCSuccess(ctx, frame.Payload, expectedChallenge, snapshot, expectedKey, expectedBinding, now)
	default:
		return nil, responseInvalid("an approval response cannot contain a request frame", nil)
	}
}

func validateIPCSuccess(ctx context.Context, payload []byte, challenge [IPCChallengeSize]byte, snapshot *ApprovalSnapshot, key *ExpectedSigningKey, binding *ExpectedReceiptBinding, now time.Time) (*ValidatedIPCResponse, error) {
	spki := payload[IPCChallengeSize : IPCChallengeSize+ipcSPKIBytes]
	if !bytes.Equal(spki, key.spkiDER) {
		return nil, signingKeyMismatch("the response selected a different signing key", nil)
	}
	receipt, err := ParseReceiptBytes(payload[IPCChallengeSize+ipcSPKIBytes:])
	if err != nil {
		return nil, responseInvalid("the approval response receipt is invalid", err)
	}
	if receipt.ChallengeSHA256 != protocolvalue.SHA256Hex(challenge[:]) {
		return nil, challengeMismatch()
	}
	if receipt.KeyGeneration != key.generation || receipt.KeyFingerprintSHA256 != key.fingerprint {
		return nil, signingKeyMismatch("the receipt does not bind the enrolled signing key", nil)
	}
	// Retain direct revision equality as defense in depth alongside the generation checks.
	if receipt.RegistryRevision != binding.registryRevision || receipt.AuthorizationContextSHA256 != binding.authorizationContextSHA256 {
		return nil, responseInvalid("the approval receipt does not match the expected authorization context", nil)
	}
	plan := snapshot.plan
	if receipt.PlanID != plan.PlanID || receipt.PlanSHA256 != protocolvalue.SHA256Hex(snapshot.bytes) || receipt.PlanSHA256 != plan.IntentSHA256 ||
		receipt.ProfileIdentitySHA256 != plan.Profile.IdentitySHA256 || receipt.AccountID != plan.Profile.Account.ID ||
		receipt.ProjectID != plan.Policy.Project.ID || receipt.ProjectKey != plan.Policy.Project.Key ||
		receipt.SchemaSHA256 != plan.Policy.SchemaSHA256 || receipt.RequestSHA256 != plan.RequestSHA256 || receipt.ExpectedSHA256 != plan.ExpectedSHA256 {
		return nil, responseInvalid("the approval receipt does not match the exact mutation plan", nil)
	}
	now = now.UTC()
	if receipt.ExpiresAt.Sub(receipt.IssuedAt) <= 0 || receipt.ExpiresAt.Sub(receipt.IssuedAt) > MaximumReceiptTTL ||
		now.Before(receipt.IssuedAt.Add(-defaultClockSkew)) || !now.Before(receipt.ExpiresAt) {
		return nil, responseInvalid("the approval receipt lifetime is invalid or expired", nil)
	}
	message, err := SigningBytes(receipt)
	if err != nil {
		return nil, responseInvalid("the approval signing message is invalid", err)
	}
	signature, err := DecodeP256DERSignature(receipt.Signature)
	if err != nil {
		return nil, signatureInvalid(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(key.publicKey, digest[:], signature) {
		return nil, signatureInvalid(nil)
	}
	return &ValidatedIPCResponse{receipt: &receipt}, nil
}

func newApprovalSnapshotOwned(owned []byte) (*ApprovalSnapshot, error) {
	plan, err := intent.ParseApprovalSnapshot(owned, MaxIPCPlanBytes)
	if err != nil {
		// Plan decoder diagnostics may contain attacker-controlled content.
		return nil, responseInvalid("the approval plan snapshot is invalid", nil)
	}
	if err := ValidateApprovalDisplayBytes(owned); err != nil {
		return nil, responseInvalid("the approval plan snapshot is invalid", err)
	}
	return &ApprovalSnapshot{bytes: owned, plan: plan}, nil
}

func decodeIPCFrame(raw []byte) (ipcFrame, error) {
	if len(raw) < IPCHeaderBytes {
		return ipcFrame{}, responseInvalid("the approval IPC frame header is truncated", nil)
	}
	if string(raw[:8]) != ipcMagic || raw[8] != IPCVersion || raw[10] != 0 || raw[11] != 0 {
		return ipcFrame{}, responseInvalid("the approval IPC frame header is invalid", nil)
	}
	kind := IPCFrameKind(raw[9])
	length := binary.BigEndian.Uint32(raw[12:16])
	if err := validateIPCPayloadLength(kind, uint64(length)); err != nil {
		return ipcFrame{}, responseInvalid("the approval IPC payload length is invalid", err)
	}
	if uint64(len(raw)-IPCHeaderBytes) != uint64(length) {
		return ipcFrame{}, responseInvalid("the approval IPC frame is truncated or has trailing bytes", nil)
	}
	return ipcFrame{Kind: kind, Payload: append([]byte(nil), raw[IPCHeaderBytes:]...)}, nil
}

func validateIPCPayloadLength(kind IPCFrameKind, length uint64) error {
	switch kind {
	case IPCFrameRequest:
		if length < minimumRequestPayload || length > maxIPCRequestPayload {
			return fmt.Errorf("request payload length is outside %d..%d", minimumRequestPayload, maxIPCRequestPayload)
		}
	case IPCFrameSuccess:
		if length < minimumSuccessPayload || length > maxIPCSuccessPayload {
			return fmt.Errorf("success payload length is outside %d..%d", minimumSuccessPayload, maxIPCSuccessPayload)
		}
	case IPCFrameError:
		if length != exactIPCErrorPayload {
			return fmt.Errorf("error payload length must equal %d", exactIPCErrorPayload)
		}
	default:
		return fmt.Errorf("frame kind is unknown")
	}
	return nil
}

func (code IPCErrorCode) valid() bool {
	return code >= IPCErrorUserCanceled && code <= IPCErrorInternalFailure
}

func responseInvalid(message string, cause error) *errx.Error {
	value := &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_RESPONSE_INVALID", Message: message, Hint: "discard the response and request a new trusted approval"}
	if cause != nil {
		value.Wrap(cause)
	}
	return value
}

func challengeMismatch() *errx.Error {
	return &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_CHALLENGE_MISMATCH", Message: "the approval response does not match this request challenge", Hint: "discard the response and start a new approval request"}
}

func signingKeyMismatch(message string, cause error) *errx.Error {
	value := &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_SIGNING_KEY_MISMATCH", Message: message, Hint: "do not trust the response; verify the enrolled helper signing key"}
	if cause != nil {
		value.Wrap(cause)
	}
	return value
}

func signatureInvalid(cause error) *errx.Error {
	value := &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_SIGNATURE_INVALID", Message: "the approval receipt signature is invalid", Hint: "discard the response and request a new trusted approval"}
	if cause != nil {
		value.Wrap(cause)
	}
	return value
}

func helperFailureError(code IPCErrorCode) *errx.Error {
	switch code {
	case IPCErrorUserCanceled:
		return &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_CANCELED", Message: "the trusted approval was canceled", Hint: "review the plan and request approval again only if still intended"}
	case IPCErrorRequestInvalid:
		return &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_REQUEST_INVALID", Message: "the trusted helper rejected the approval request", Hint: "discard the request and prepare a new mutation plan"}
	case IPCErrorUserPresenceUnavailable, IPCErrorKeyUnavailable:
		return &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_KEY_UNAVAILABLE", Message: "trusted approval or its enrolled signing key is unavailable", Hint: "do not apply the mutation; restore the enrolled helper and retry approval"}
	case IPCErrorSigningFailed, IPCErrorInternalFailure:
		return &errx.Error{Code: errx.CodeConfirm, Reason: "APPROVAL_SIGNING_FAILED", Message: "the trusted helper could not sign the approval", Hint: "do not apply the mutation; request a new approval after the helper is healthy"}
	default:
		return responseInvalid("the approval helper error code is unknown", nil)
	}
}
