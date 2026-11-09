package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const (
	suppliedRegistryMaxRecords  = 256
	suppliedRegistryRecordBytes = 4352
	suppliedRegistryBodyBytes   = 4096
	suppliedRegistryEmptyTip    = "0000000000000000000000000000000000000000000000000000000000000000"
	suppliedRegistryKeyTag      = "io.github.abigotado.youtrack-agent.approval.signing.v1/"
	suppliedRegistryTimeLayout  = "2006-01-02T15:04:05Z"
)

// SuppliedRegistryKey is a historical key claim derived from a supplied prefix,
// not a trusted current key or permission to sign, confirm, or commit.
type SuppliedRegistryKey struct {
	Generation        string
	KeyID             string
	KeyTag            string
	SPKI              string
	FingerprintSHA256 string
	Status            string
}

// SuppliedRegistryHistory describes internal consistency of only the supplied
// prefix. It proves neither completeness nor a trusted current tip, does not
// create ExpectedReceiptBinding, and grants no signing, confirmation, commit,
// or cache authority. Digest declarations are not transcript/native evidence.
type SuppliedRegistryHistory struct {
	revision   int
	tip        string
	descriptor string
	keys       []SuppliedRegistryKey
}

// SuppliedRevision returns the supplied prefix's revision, not a current revision.
func (history SuppliedRegistryHistory) SuppliedRevision() int { return history.revision }

// SuppliedTipSHA256 returns the supplied prefix's tip, not a trusted current tip.
func (history SuppliedRegistryHistory) SuppliedTipSHA256() string { return history.tip }

// SuppliedTipDescriptorSHA256 returns the supplied tip's descriptor claim, if any.
// It is not independently established artifact or current-registry authority.
func (history SuppliedRegistryHistory) SuppliedTipDescriptorSHA256() (string, bool) {
	return history.descriptor, history.revision != 0
}

// Keys returns a copy of the supplied prefix's historical key claims. The copy
// cannot change the result and does not authorize signing or confirmation.
func (history SuppliedRegistryHistory) Keys() []SuppliedRegistryKey {
	return append([]SuppliedRegistryKey(nil), history.keys...)
}

// Frozen field order and explicit nullable pointers are the stored-record v1
// contract, independent of request/proposal models and transcript test oracles.
type suppliedRegistryBody struct {
	SchemaVersion            *uint64 `json:"schema_version"`
	RecordType               *string `json:"record_type"`
	TransitionKind           *string `json:"transition_kind"`
	RegistryRevision         *uint64 `json:"registry_revision"`
	PreviousRecordSHA256     *string `json:"previous_record_sha256"`
	RequestSHA256            *string `json:"request_sha256"`
	ProposalSHA256           *string `json:"proposal_sha256"`
	AcceptanceSHA256         *string `json:"acceptance_sha256"`
	ChallengeSHA256          *string `json:"challenge_sha256"`
	ArtifactDescriptorSHA256 *string `json:"artifact_descriptor_sha256"`
	RecoveryEvidenceSHA256   *string `json:"recovery_evidence_sha256"`
	RequestedAt              *string `json:"requested_at"`
	AcceptedAt               *string `json:"accepted_at"`
	CommittedAt              *string `json:"committed_at"`
	TargetGeneration         *string `json:"target_generation"`
	TargetKeyID              *string `json:"target_key_id"`
	TargetKeyTag             *string `json:"target_key_tag"`
	TargetSPKI               *string `json:"target_spki"`
	TargetFingerprintSHA256  *string `json:"target_fingerprint_sha256"`
	TargetPreviousStatus     *string `json:"target_previous_status"`
	TargetNewStatus          *string `json:"target_new_status"`
	NewGeneration            *string `json:"new_generation"`
	NewKeyID                 *string `json:"new_key_id"`
	NewKeyTag                *string `json:"new_key_tag"`
	NewSPKI                  *string `json:"new_spki"`
	NewFingerprintSHA256     *string `json:"new_fingerprint_sha256"`
	NewStatus                *string `json:"new_status"`
	RevokesAllPrior          *bool   `json:"revokes_all_prior"`
}

type suppliedRegistryWire struct {
	suppliedRegistryBody
	OldSignature *string `json:"old_signature"`
	NewSignature *string `json:"new_signature"`
}

type suppliedRegistryRecord struct {
	wire      suppliedRegistryWire
	body      []byte
	target    *SuppliedRegistryKey
	fresh     *SuppliedRegistryKey
	targetKey *ecdsa.PublicKey
	freshKey  *ecdsa.PublicKey
	oldSig    []byte
	newSig    []byte
	requested int64
	accepted  int64
	committed int64
}

// VerifySuppliedRegistryHistory checks a bounded, caller-ordered prefix from
// genesis. Callers must not mutate records or their bytes during the call; all
// bytes are cloned after global bounds checks. All records pass encoding and
// then primitive validation before any replay/signature verification. Success
// is supplied-prefix consistency only, not completeness, current-tip trust,
// native recovery evidence, or authority to bind receipts/sign/confirm/commit.
func VerifySuppliedRegistryHistory(records [][]byte) (SuppliedRegistryHistory, error) {
	if len(records) > suppliedRegistryMaxRecords {
		return SuppliedRegistryHistory{}, suppliedRegistryError("bounds")
	}
	// The joint count/item caps also enforce the normative aggregate bound:
	// 256 * 4,352 = 1,114,112 bytes, before any input is cloned or parsed.
	for _, raw := range records {
		if len(raw) == 0 || len(raw) > suppliedRegistryRecordBytes {
			return SuppliedRegistryHistory{}, suppliedRegistryError("bounds")
		}
	}
	owned := make([][]byte, len(records))
	for i, raw := range records {
		owned[i] = bytes.Clone(raw)
	}
	parsed := make([]suppliedRegistryRecord, len(owned))
	for i, raw := range owned {
		if !suppliedRegistryDecode(raw, &parsed[i].wire) {
			return SuppliedRegistryHistory{}, suppliedRegistryError("encoding")
		}
	}
	for i := range parsed {
		if !suppliedRegistryPrimitives(&parsed[i]) {
			return SuppliedRegistryHistory{}, suppliedRegistryError("grammar")
		}
	}
	history := SuppliedRegistryHistory{tip: suppliedRegistryEmptyTip}
	for i := range parsed {
		if !suppliedRegistryReplay(&history, &parsed[i], i+1) {
			return SuppliedRegistryHistory{}, suppliedRegistryError("replay")
		}
		suppliedRegistryAdvance(&history, owned[i], &parsed[i])
	}
	return history, nil
}

func suppliedRegistryError(stage string) error {
	return &errx.Error{
		Code: errx.CodeUsage, Reason: "REGISTRY_HISTORY_INVALID",
		Message: "supplied registry history failed " + stage + " validation",
		Hint:    "discard the supplied history; obtain complete records from an independently trusted source",
	}
}

func suppliedRegistryDecode(raw []byte, wire *suppliedRegistryWire) bool {
	return suppliedRegistryCanonicalDecode(raw, wire)
}

func suppliedRegistryCanonicalDecode[T suppliedRegistryCanonicalWire](raw []byte, wire *T) bool {
	for _, value := range raw {
		if value < 0x20 || value > 0x7e || value == '\\' {
			return false
		}
	}
	if err := json.Unmarshal(raw, wire); err != nil {
		// Decoder text can echo untrusted bytes; this boundary returns only a stage.
		return false
	}
	canonical, err := json.Marshal(wire)
	if err != nil {
		return false
	}
	return bytes.Equal(raw, canonical)
}

func suppliedRegistryAdvance(history *SuppliedRegistryHistory, raw []byte, record *suppliedRegistryRecord) {
	digest := sha256.Sum256(raw)
	history.tip = hex.EncodeToString(digest[:])
	history.revision = int(*record.wire.RegistryRevision)
	history.descriptor = *record.wire.ArtifactDescriptorSHA256
}

func suppliedRegistryPrimitives(record *suppliedRegistryRecord) bool {
	w := &record.wire
	if w.SchemaVersion == nil || *w.SchemaVersion != 1 || w.RegistryRevision == nil ||
		*w.RegistryRevision < 1 || *w.RegistryRevision > suppliedRegistryMaxRecords || w.RevokesAllPrior == nil ||
		w.RecordType == nil || *w.RecordType != "approval_registry_transition" || w.TransitionKind == nil {
		return false
	}
	switch *w.TransitionKind {
	case "enroll", "rotate", "revoke", "recover":
	default:
		return false
	}
	for _, digest := range []*string{w.PreviousRecordSHA256, w.RequestSHA256, w.ProposalSHA256,
		w.AcceptanceSHA256, w.ChallengeSHA256, w.ArtifactDescriptorSHA256} {
		if digest == nil || !suppliedRegistryHex(*digest, 64) {
			return false
		}
	}
	if w.RecoveryEvidenceSHA256 != nil && !suppliedRegistryHex(*w.RecoveryEvidenceSHA256, 64) {
		return false
	}
	for _, status := range []*string{w.TargetPreviousStatus, w.TargetNewStatus, w.NewStatus} {
		if status != nil && *status != "active" && *status != "retained" && *status != "revoked" {
			return false
		}
	}
	var ok bool
	record.target, record.targetKey, ok = suppliedRegistryTuple(w.TargetGeneration, w.TargetKeyID, w.TargetKeyTag, w.TargetSPKI, w.TargetFingerprintSHA256)
	if !ok {
		return false
	}
	record.fresh, record.freshKey, ok = suppliedRegistryTuple(w.NewGeneration, w.NewKeyID, w.NewKeyTag, w.NewSPKI, w.NewFingerprintSHA256)
	if !ok || (record.fresh != nil && keyGenerationRevision(record.fresh.Generation) != int(*w.RegistryRevision)) {
		return false
	}
	if w.OldSignature != nil {
		var err error
		record.oldSig, err = DecodeP256DERSignature(*w.OldSignature)
		if err != nil {
			return false
		}
	}
	if w.NewSignature != nil {
		var err error
		record.newSig, err = DecodeP256DERSignature(*w.NewSignature)
		if err != nil {
			return false
		}
	}
	record.requested, ok = suppliedRegistryTime(w.RequestedAt)
	if !ok {
		return false
	}
	record.accepted, ok = suppliedRegistryTime(w.AcceptedAt)
	if !ok {
		return false
	}
	record.committed, ok = suppliedRegistryTime(w.CommittedAt)
	if !ok {
		return false
	}
	var err error
	record.body, err = json.Marshal(w.suppliedRegistryBody)
	return err == nil && len(record.body) <= suppliedRegistryBodyBytes
}

func suppliedRegistryHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range value {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func suppliedRegistryTuple(generation, id, tag, spki, fingerprint *string) (*SuppliedRegistryKey, *ecdsa.PublicKey, bool) {
	values := []*string{generation, id, tag, spki, fingerprint}
	nulls := 0
	for _, value := range values {
		if value == nil {
			nulls++
		}
	}
	if nulls == len(values) {
		return nil, nil, true
	}
	if nulls != 0 || keyGenerationRevision(*generation) == 0 || !suppliedRegistryHex(*id, 32) ||
		*tag != suppliedRegistryKeyTag+*id || !suppliedRegistryHex(*fingerprint, 64) ||
		len(*spki) != base64.RawURLEncoding.EncodedLen(p256DERSPKIBytes) {
		return nil, nil, false
	}
	der, err := base64.RawURLEncoding.DecodeString(*spki)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != *spki {
		return nil, nil, false
	}
	point, err := P256DERSPKIToX963(der)
	if err != nil {
		return nil, nil, false
	}
	digest := sha256.Sum256(der)
	if hex.EncodeToString(digest[:]) != *fingerprint {
		return nil, nil, false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, nil, false
	}
	return &SuppliedRegistryKey{Generation: *generation, KeyID: *id, KeyTag: *tag, SPKI: *spki, FingerprintSHA256: *fingerprint}, key, true
}

func suppliedRegistryTime(value *string) (int64, bool) {
	if value == nil || len(*value) != 20 {
		return 0, false
	}
	when, err := time.Parse(suppliedRegistryTimeLayout, *value)
	if err != nil || when.Format(suppliedRegistryTimeLayout) != *value {
		return 0, false
	}
	// Unix seconds safely cover canonical years 0000..9999. Do not reject the
	// valid year-0001 zero instant or compare using overflow-prone durations.
	return when.Unix(), true
}

func suppliedRegistrySameTuple(a, b SuppliedRegistryKey) bool {
	return a.Generation == b.Generation && a.KeyID == b.KeyID && a.KeyTag == b.KeyTag &&
		a.SPKI == b.SPKI && a.FingerprintSHA256 == b.FingerprintSHA256
}

func suppliedRegistrySignature(key *ecdsa.PublicKey, signature []byte, domain string, body []byte) bool {
	if key == nil || len(signature) == 0 {
		return false
	}
	// Only fixed role domains reach here; primitive validation bounded body.
	input := make([]byte, 0, len(domain)+len(body))
	input = append(input, domain...)
	input = append(input, body...)
	digest := sha256.Sum256(input)
	return ecdsa.VerifyASN1(key, digest[:], signature)
}

func suppliedRegistryReplay(history *SuppliedRegistryHistory, record *suppliedRegistryRecord, revision int) bool {
	w := &record.wire
	transition := *w.TransitionKind
	if int(*w.RegistryRevision) != revision || *w.PreviousRecordSHA256 != history.tip ||
		record.requested > record.accepted || record.accepted > record.committed ||
		record.committed-record.requested >= 300 ||
		(w.RecoveryEvidenceSHA256 != nil) != (transition == "recover") ||
		*w.RevokesAllPrior != (transition == "recover") ||
		(w.OldSignature != nil) != (transition == "rotate" || transition == "revoke") ||
		(w.NewSignature != nil) != (transition != "revoke") {
		return false
	}
	active := -1
	for i := range history.keys {
		if history.keys[i].Status == "active" {
			if active != -1 {
				return false
			}
			active = i
		}
	}
	if active == -1 {
		if record.target != nil || w.TargetPreviousStatus != nil || w.TargetNewStatus != nil {
			return false
		}
	} else {
		if record.target == nil || !suppliedRegistrySameTuple(*record.target, history.keys[active]) ||
			w.TargetPreviousStatus == nil || *w.TargetPreviousStatus != "active" || w.TargetNewStatus == nil {
			return false
		}
		status := "revoked"
		if transition == "rotate" {
			status = "retained"
		}
		if *w.TargetNewStatus != status {
			return false
		}
	}
	switch transition {
	case "enroll":
		if revision != 1 || len(history.keys) != 0 {
			return false
		}
	case "rotate", "revoke":
		if active == -1 {
			return false
		}
	case "recover":
		if len(history.keys) == 0 {
			return false
		}
	}
	if transition == "revoke" {
		if record.fresh != nil || w.NewStatus != nil {
			return false
		}
	} else {
		if record.fresh == nil || w.NewStatus == nil || *w.NewStatus != "active" {
			return false
		}
		for _, prior := range history.keys {
			fresh := record.fresh
			if fresh.Generation == prior.Generation || fresh.KeyID == prior.KeyID || fresh.KeyTag == prior.KeyTag ||
				fresh.SPKI == prior.SPKI || fresh.FingerprintSHA256 == prior.FingerprintSHA256 {
				return false
			}
		}
	}
	if w.OldSignature != nil && !suppliedRegistrySignature(record.targetKey, record.oldSig, "YTA-REGISTRY-RECORD-OLD-V1\x00", record.body) {
		return false
	}
	if w.NewSignature != nil && !suppliedRegistrySignature(record.freshKey, record.newSig, "YTA-REGISTRY-RECORD-NEW-V1\x00", record.body) {
		return false
	}
	if transition == "recover" {
		for i := range history.keys {
			history.keys[i].Status = "revoked"
		}
	} else if active != -1 {
		history.keys[active].Status = *w.TargetNewStatus
	}
	if record.fresh != nil {
		fresh := *record.fresh
		fresh.Status = "active"
		history.keys = append(history.keys, fresh)
	}
	return true
}
