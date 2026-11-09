package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

func TestIPCRequestSnapshotOwnsBytesAndParsesOnce(t *testing.T) {
	raw := append([]byte(nil), sharedGate1AFixture(t, "plan-comment-add.json")...)
	want := append([]byte(nil), raw...)
	snapshot, err := NewApprovalSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	returned := snapshot.Bytes()
	returned[0] ^= 1
	if !bytes.Equal(snapshot.Bytes(), want) {
		t.Fatal("snapshot aliases input or returned bytes")
	}
	challenge := ipcChallengeForTest()
	framed, err := EncodeIPCRequest(challenge, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeIPCRequest(framed)
	if err != nil {
		t.Fatal(err)
	}
	if request.Challenge != challenge || !bytes.Equal(request.Snapshot.Bytes(), want) {
		t.Fatal("decoded request changed its bound values")
	}
	framed[IPCHeaderBytes+IPCChallengeSize] ^= 1
	decoded := request.Snapshot.Bytes()
	decoded[0] ^= 1
	if !bytes.Equal(request.Snapshot.Bytes(), want) {
		t.Fatal("decoded snapshot aliases its frame or returned bytes")
	}
}

func TestIPCV2SharedFixtures(t *testing.T) {
	snapshot, key := fixtureSnapshotAndKey(t)
	challenge := ipcChallengeForTest()
	request, err := EncodeIPCRequest(challenge, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustDecodeHex(t, sharedGate1AFixture(t, "ipc-request.hex")); !bytes.Equal(request, want) {
		t.Fatal("request encoding differs from the shared v2 fixture")
	}
	success := mustDecodeHex(t, receiptV3Fixture(t, "ipc-success.hex"))
	response, err := DecodeAndValidateIPCResponse(context.Background(), success, challenge, snapshot, key, expectedReceiptBindingForTest(t), time.Date(2026, 9, 2, 15, 35, 56, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := response.VerifiedReceipt()
	if !ok {
		t.Fatal("shared success fixture did not produce a verified receipt")
	}
	wantReceipt := receiptV3Fixture(t, "ipc-success-receipt.json")
	gotReceipt, err := ReceiptBytes(*receipt)
	if err != nil || !bytes.Equal(gotReceipt, wantReceipt) {
		t.Fatalf("success receipt differs from fixture: %v", err)
	}
	failureRaw := mustDecodeHex(t, sharedGate1AFixture(t, "ipc-error.hex"))
	failureResponse, err := DecodeAndValidateIPCResponse(context.Background(), failureRaw, challenge, snapshot, key, expectedReceiptBindingForTest(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	failure, ok := failureResponse.HelperError()
	if !ok || failure.Code != IPCErrorUserCanceled {
		t.Fatalf("shared error fixture = %#v, %v", failure, ok)
	}
}

func TestDecodeAndValidateIPCResponseBindsChallengePlanAndEnrolledKey(t *testing.T) {
	snapshot, err := NewApprovalSnapshot(sharedGate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := ipcChallengeForTest()
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)
	raw, key := signedResponseForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
	response, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := response.VerifiedReceipt()
	if !ok || receipt.PlanID != snapshot.plan.PlanID {
		t.Fatalf("verified receipt = %#v, %v", receipt, ok)
	}
	if _, ok := response.HelperError(); ok {
		t.Fatal("success also exposed a failure")
	}

	t.Run("outer challenge splice", func(t *testing.T) {
		spliced := append([]byte(nil), raw...)
		newChallenge := challenge
		newChallenge[0] ^= 0xff
		copy(spliced[IPCHeaderBytes:IPCHeaderBytes+IPCChallengeSize], newChallenge[:])
		_, err := DecodeAndValidateIPCResponse(context.Background(), spliced, newChallenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_CHALLENGE_MISMATCH")
	})
	t.Run("replayed response", func(t *testing.T) {
		freshChallenge := challenge
		freshChallenge[len(freshChallenge)-1] ^= 0xff
		_, err := DecodeAndValidateIPCResponse(context.Background(), raw, freshChallenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_CHALLENGE_MISMATCH")
	})
	t.Run("different plan snapshot", func(t *testing.T) {
		otherSnapshot, err := NewApprovalSnapshot(sharedGate1AFixture(t, "plan-issue-update.json"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeAndValidateIPCResponse(context.Background(), raw, challenge, otherSnapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
	})
	t.Run("response-selected key", func(t *testing.T) {
		otherRaw, _ := signedResponseForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
		_, err := DecodeAndValidateIPCResponse(context.Background(), otherRaw, challenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_SIGNING_KEY_MISMATCH")
	})
	t.Run("wrong generation", func(t *testing.T) {
		wrong, err := NewExpectedSigningKey("YTAG-00000000000000000002", key.spkiDER, key.fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, wrong, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_SIGNING_KEY_MISMATCH")
	})
	t.Run("expired receipt", func(t *testing.T) {
		expiredRaw, expiredKey := signedResponseForTest(t, snapshot, challenge, issued, issued.Add(time.Minute), nil)
		_, err := DecodeAndValidateIPCResponse(context.Background(), expiredRaw, challenge, snapshot, expiredKey, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
	})
}

func TestDecodeAndValidateIPCResponseBindsEveryReceiptFieldAndSignature(t *testing.T) {
	snapshot, err := NewApprovalSnapshot(sharedGate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := ipcChallengeForTest()
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Receipt)
		reason string
	}{
		{name: "challenge digest", mutate: func(r *Receipt) { r.ChallengeSHA256 = protocolvalue.SHA256Hex([]byte("other challenge")) }, reason: "APPROVAL_CHALLENGE_MISMATCH"},
		{name: "plan ID", mutate: func(r *Receipt) { r.PlanID = "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA" }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "plan digest", mutate: func(r *Receipt) { r.PlanSHA256 = repeatHex('f') }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "profile identity", mutate: func(r *Receipt) { r.ProfileIdentitySHA256 = repeatHex('f') }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "account", mutate: func(r *Receipt) { r.AccountID = "9-9" }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "project ID", mutate: func(r *Receipt) { r.ProjectID = "9-9" }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "project key", mutate: func(r *Receipt) { r.ProjectKey = "OTHER" }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "schema", mutate: func(r *Receipt) { r.SchemaSHA256 = repeatHex('f') }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "request", mutate: func(r *Receipt) { r.RequestSHA256 = repeatHex('f') }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "expected", mutate: func(r *Receipt) { r.ExpectedSHA256 = repeatHex('f') }, reason: "APPROVAL_RESPONSE_INVALID"},
		{name: "key generation", mutate: func(r *Receipt) { r.KeyGeneration = "YTAG-00000000000000000002"; r.RegistryRevision = 2 }, reason: "APPROVAL_SIGNING_KEY_MISMATCH"},
		{name: "key fingerprint", mutate: func(r *Receipt) { r.KeyFingerprintSHA256 = repeatHex('f') }, reason: "APPROVAL_SIGNING_KEY_MISMATCH"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, key := signedResponseWithMutationForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), private, test.mutate, nil)
			_, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
			assertReason(t, err, test.reason)
		})
	}

	t.Run("signature over different message", func(t *testing.T) {
		raw, key := signedResponseWithMutationForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), private, nil, []byte("different message"))
		_, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(time.Minute))
		assertReason(t, err, "APPROVAL_SIGNATURE_INVALID")
	})
}

func TestDecodeAndValidateIPCResponseTTLAndClockSkewBoundaries(t *testing.T) {
	snapshot, err := NewApprovalSnapshot(sharedGate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := ipcChallengeForTest()
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)
	raw, key := signedResponseForTest(t, snapshot, challenge, issued, issued.Add(MaximumReceiptTTL), nil)
	for name, now := range map[string]time.Time{
		"exact future skew": issued.Add(-defaultClockSkew),
		"inside lifetime":   issued.Add(time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), now); err != nil {
				t.Fatalf("exact protocol boundary rejected: %v", err)
			}
		})
	}
	t.Run("one second beyond future skew", func(t *testing.T) {
		_, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(-defaultClockSkew-time.Second))
		assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
	})
	t.Run("expiry instant", func(t *testing.T) {
		_, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), issued.Add(MaximumReceiptTTL))
		assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
	})
}

func TestDecodeAndValidateIPCResponseFailureUnionAndTyping(t *testing.T) {
	snapshot, key := fixtureSnapshotAndKey(t)
	challenge := ipcChallengeForTest()
	tests := []struct {
		code   IPCErrorCode
		reason string
	}{
		{code: IPCErrorUserCanceled, reason: "APPROVAL_CANCELED"},
		{code: IPCErrorRequestInvalid, reason: "APPROVAL_REQUEST_INVALID"},
		{code: IPCErrorUserPresenceUnavailable, reason: "APPROVAL_KEY_UNAVAILABLE"},
		{code: IPCErrorKeyUnavailable, reason: "APPROVAL_KEY_UNAVAILABLE"},
		{code: IPCErrorSigningFailed, reason: "APPROVAL_SIGNING_FAILED"},
		{code: IPCErrorInternalFailure, reason: "APPROVAL_SIGNING_FAILED"},
	}
	for _, test := range tests {
		t.Run(strconv.Itoa(int(test.code)), func(t *testing.T) {
			raw, err := EncodeIPCFailure(IPCFailure{Challenge: challenge, Code: test.code})
			if err != nil {
				t.Fatal(err)
			}
			response, err := DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			failure, ok := response.HelperError()
			if !ok || failure.Code != test.code {
				t.Fatalf("helper failure = %#v, %v", failure, ok)
			}
			if _, ok := response.VerifiedReceipt(); ok {
				t.Fatal("failure response also exposed a receipt")
			}
			var typed *errx.Error
			if !errors.As(failure.AsError(), &typed) || typed.Code != errx.CodeConfirm || typed.Reason != test.reason {
				t.Fatalf("helper error is not CodeConfirm: %#v", failure.AsError())
			}
		})
	}
	raw, _ := EncodeIPCFailure(IPCFailure{Challenge: challenge, Code: IPCErrorUserCanceled})
	wrong := challenge
	wrong[0] ^= 1
	_, err := DecodeAndValidateIPCResponse(context.Background(), raw, wrong, snapshot, key, expectedReceiptBindingForTest(t), time.Now())
	assertReason(t, err, "APPROVAL_CHALLENGE_MISMATCH")
	raw[len(raw)-1] = byte(IPCErrorInternalFailure + 1)
	_, err = DecodeAndValidateIPCResponse(context.Background(), raw, challenge, snapshot, key, expectedReceiptBindingForTest(t), time.Now())
	assertReason(t, err, "APPROVAL_RESPONSE_INVALID")
}

func TestDecodeAndValidateIPCResponsePreservesContext(t *testing.T) {
	snapshot, key := fixtureSnapshotAndKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DecodeAndValidateIPCResponse(ctx, nil, ipcChallengeForTest(), snapshot, key, expectedReceiptBindingForTest(t), time.Now())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestExpectedSigningKeyValidatesAndDefensivelyCopies(t *testing.T) {
	spki := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.spki.hex"))
	fingerprint := string(sharedGate1AFixture(t, "public-key.fingerprint-sha256"))
	key, err := NewExpectedSigningKey("YTAG-00000000000000000001", spki, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	spki[0] ^= 1
	returned := key.SPKIDER()
	returned[0] ^= 1
	if key.Generation() != "YTAG-00000000000000000001" || key.FingerprintSHA256() != fingerprint || bytes.Equal(key.SPKIDER(), spki) {
		t.Fatal("expected signing key aliases caller bytes")
	}
	for _, generation := range []string{"", "-key", "key:1"} {
		if _, err := NewExpectedSigningKey(generation, key.spkiDER, fingerprint); err == nil {
			t.Fatalf("invalid generation %q accepted", generation)
		}
	}
	if _, err := NewExpectedSigningKey("YTAG-00000000000000000001", key.spkiDER, string(make([]byte, 64))); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
}

func TestIPCFrameBounds(t *testing.T) {
	for _, kind := range []IPCFrameKind{IPCFrameRequest, IPCFrameSuccess, IPCFrameError, 0, 255} {
		if err := validateIPCPayloadLength(kind, math.MaxUint64); err == nil {
			t.Fatalf("kind %d accepted impossible length", kind)
		}
	}
	fixtures := []struct {
		name string
		kind IPCFrameKind
		raw  []byte
		min  uint32
		max  uint32
	}{
		{name: "request", kind: IPCFrameRequest, raw: mustDecodeHex(t, sharedGate1AFixture(t, "ipc-request.hex")), min: minimumRequestPayload, max: maxIPCRequestPayload},
		{name: "success", kind: IPCFrameSuccess, raw: mustDecodeHex(t, receiptV3Fixture(t, "ipc-success.hex")), min: minimumSuccessPayload, max: maxIPCSuccessPayload},
		{name: "error", kind: IPCFrameError, raw: mustDecodeHex(t, sharedGate1AFixture(t, "ipc-error.hex")), min: exactIPCErrorPayload, max: exactIPCErrorPayload},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			cases := map[string][]byte{
				"truncated payload":  fixture.raw[:len(fixture.raw)-1],
				"trailing payload":   append(append([]byte(nil), fixture.raw...), 0),
				"declared under min": ipcHeaderForTest(fixture.kind, fixture.min-1),
				"declared over max":  ipcHeaderForTest(fixture.kind, fixture.max+1),
			}
			for name, raw := range cases {
				t.Run(name, func(t *testing.T) {
					if _, err := decodeIPCFrame(raw); err == nil {
						t.Fatal("malformed per-kind frame accepted")
					}
				})
			}
		})
	}
}

func signedResponseForTest(t *testing.T, snapshot *ApprovalSnapshot, challenge [IPCChallengeSize]byte, issued, expires time.Time, private *ecdsa.PrivateKey) ([]byte, *ExpectedSigningKey) {
	return signedResponseWithMutationForTest(t, snapshot, challenge, issued, expires, private, nil, nil)
}

func signedResponseWithMutationForTest(t *testing.T, snapshot *ApprovalSnapshot, challenge [IPCChallengeSize]byte, issued, expires time.Time, private *ecdsa.PrivateKey, mutate func(*Receipt), overrideMessage []byte) ([]byte, *ExpectedSigningKey) {
	t.Helper()
	if private == nil {
		var err error
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	spki, _ := P256X963ToDERSPKI(elliptic.Marshal(elliptic.P256(), private.X, private.Y))
	fingerprint, _ := P256SPKIFingerprintSHA256(spki)
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, ReceiptID: "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", Nonce: "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAA",
		ChallengeSHA256: protocolvalue.SHA256Hex(challenge[:]), PlanID: snapshot.plan.PlanID, PlanSHA256: snapshot.plan.IntentSHA256,
		RegistryRevision: 1, AuthorizationContextSHA256: repeatHex('a'),
		ProfileIdentitySHA256: snapshot.plan.Profile.IdentitySHA256, AccountID: snapshot.plan.Profile.Account.ID,
		ProjectID: snapshot.plan.Policy.Project.ID, ProjectKey: snapshot.plan.Policy.Project.Key, SchemaSHA256: snapshot.plan.Policy.SchemaSHA256,
		RequestSHA256: snapshot.plan.RequestSHA256, ExpectedSHA256: snapshot.plan.ExpectedSHA256, IssuedAt: issued, ExpiresAt: expires,
		KeyGeneration: "YTAG-00000000000000000001", KeyFingerprintSHA256: fingerprint,
	}
	if mutate != nil {
		mutate(&receipt)
	}
	message := overrideMessage
	if message == nil {
		encoded, err := SigningBytes(receipt)
		if err != nil {
			t.Fatal(err)
		}
		message = encoded
	}
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	order := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		s.Sub(order, s)
	}
	der, _ := asn1.Marshal(p256Signature{R: r, S: s})
	receipt.Signature, _ = EncodeP256DERSignature(der)
	receiptJSON, err := ReceiptBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeIPCSuccess(IPCSuccess{Challenge: challenge, SPKIDER: spki, ReceiptJSON: receiptJSON})
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewExpectedSigningKey("YTAG-00000000000000000001", spki, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return raw, key
}

func repeatHex(value byte) string {
	return string(bytes.Repeat([]byte{value}, sha256.Size*2))
}

func fixtureSnapshotAndKey(t *testing.T) (*ApprovalSnapshot, *ExpectedSigningKey) {
	t.Helper()
	snapshot, err := NewApprovalSnapshot(sharedGate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	spki := mustDecodeHex(t, sharedGate1AFixture(t, "public-key.spki.hex"))
	key, err := NewExpectedSigningKey("YTAG-00000000000000000001", spki, string(sharedGate1AFixture(t, "public-key.fingerprint-sha256")))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, key
}

func assertReason(t *testing.T, err error, reason string) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeConfirm || typed.Reason != reason {
		t.Fatalf("error = %#v, want CodeConfirm/%s", err, reason)
	}
}

func ipcHeaderForTest(kind IPCFrameKind, length uint32) []byte {
	header := make([]byte, IPCHeaderBytes)
	copy(header, ipcMagic)
	header[8] = IPCVersion
	header[9] = byte(kind)
	binary.BigEndian.PutUint32(header[12:], length)
	return header
}

func ipcChallengeForTest() [IPCChallengeSize]byte {
	var challenge [IPCChallengeSize]byte
	for index := range challenge {
		challenge[index] = byte(index)
	}
	return challenge
}
