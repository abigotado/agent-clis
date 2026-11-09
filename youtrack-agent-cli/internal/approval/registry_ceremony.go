package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

// SuppliedRegistryCeremony contains exact supplied transcript bytes, not live
// connection, user-presence, Keychain, or registry authority. RecoveryEvidence
// is absent only when nil; a non-nil empty slice is invalid. Callers must not
// mutate any supplied slices during verification.
type SuppliedRegistryCeremony struct {
	Request          []byte
	RecoveryEvidence []byte
	UnsignedProposal []byte
	SignedProposal   []byte
	Acceptance       []byte
	FinalBody        []byte
	Record           []byte
}

// These wire types freeze the registry-v1 transcript independently of live
// protocols and test oracles. Nullable members are present as literal null.
type suppliedCeremonyRequest struct {
	SchemaVersion            *uint64 `json:"schema_version"`
	MessageType              *string `json:"message_type"`
	TransitionKind           *string `json:"transition_kind"`
	RecoveryMode             *string `json:"recovery_mode"`
	Challenge                *string `json:"challenge"`
	ExpectedRegistryRevision *uint64 `json:"expected_registry_revision"`
	PreviousRecordSHA256     *string `json:"previous_record_sha256"`
	ArtifactDescriptorSHA256 *string `json:"artifact_descriptor_sha256"`
	TargetGeneration         *string `json:"target_generation"`
	NewGeneration            *string `json:"new_generation"`
	RequestedAt              *string `json:"requested_at"`
	ExpiresAt                *string `json:"expires_at"`
}

type suppliedCeremonyRecovery struct {
	SchemaVersion            *uint64 `json:"schema_version"`
	MessageType              *string `json:"message_type"`
	RequestSHA256            *string `json:"request_sha256"`
	ChallengeSHA256          *string `json:"challenge_sha256"`
	RegistryRevision         *uint64 `json:"registry_revision"`
	PreviousRecordSHA256     *string `json:"previous_record_sha256"`
	ArtifactDescriptorSHA256 *string `json:"artifact_descriptor_sha256"`
	TargetGeneration         *string `json:"target_generation"`
	TargetKeyTag             *string `json:"target_key_tag"`
	Eligibility              *string `json:"eligibility"`
	KeyLookupResult          *string `json:"key_lookup_result"`
	ContinuityProbeResult    *string `json:"continuity_probe_result"`
	ProbedAt                 *string `json:"probed_at"`
}

type suppliedCeremonyProposal struct {
	SchemaVersion            *uint64 `json:"schema_version"`
	MessageType              *string `json:"message_type"`
	TransitionKind           *string `json:"transition_kind"`
	RequestSHA256            *string `json:"request_sha256"`
	ChallengeSHA256          *string `json:"challenge_sha256"`
	RegistryRevision         *uint64 `json:"registry_revision"`
	PreviousRecordSHA256     *string `json:"previous_record_sha256"`
	ArtifactDescriptorSHA256 *string `json:"artifact_descriptor_sha256"`
	RecoveryEvidenceSHA256   *string `json:"recovery_evidence_sha256"`
	TargetGeneration         *string `json:"target_generation"`
	TargetKeyID              *string `json:"target_key_id"`
	TargetKeyTag             *string `json:"target_key_tag"`
	TargetSPKI               *string `json:"target_spki"`
	TargetFingerprintSHA256  *string `json:"target_fingerprint_sha256"`
	NewGeneration            *string `json:"new_generation"`
	NewKeyID                 *string `json:"new_key_id"`
	NewKeyTag                *string `json:"new_key_tag"`
	NewSPKI                  *string `json:"new_spki"`
	NewFingerprintSHA256     *string `json:"new_fingerprint_sha256"`
	ProposedAt               *string `json:"proposed_at"`
	ExpiresAt                *string `json:"expires_at"`
	ProposalSignerRole       *string `json:"proposal_signer_role"`
}

type suppliedCeremonySignedProposal struct {
	suppliedCeremonyProposal
	ProposalSignature *string `json:"proposal_signature"`
}

type suppliedCeremonyAcceptance struct {
	SchemaVersion            *uint64 `json:"schema_version"`
	MessageType              *string `json:"message_type"`
	TransitionKind           *string `json:"transition_kind"`
	RequestSHA256            *string `json:"request_sha256"`
	ProposalSHA256           *string `json:"proposal_sha256"`
	ChallengeSHA256          *string `json:"challenge_sha256"`
	RegistryRevision         *uint64 `json:"registry_revision"`
	PreviousRecordSHA256     *string `json:"previous_record_sha256"`
	ArtifactDescriptorSHA256 *string `json:"artifact_descriptor_sha256"`
	RecoveryEvidenceSHA256   *string `json:"recovery_evidence_sha256"`
	TargetGeneration         *string `json:"target_generation"`
	NewGeneration            *string `json:"new_generation"`
	AcceptedAt               *string `json:"accepted_at"`
	ExpiresAt                *string `json:"expires_at"`
	Accepted                 *bool   `json:"accepted"`
}

// A closed type set prevents a permissive dynamic object from entering shared
// canonical decoding; every admitted type has an independently frozen wire.
type suppliedRegistryCanonicalWire interface {
	suppliedRegistryWire | suppliedRegistryBody | suppliedCeremonyRequest |
		suppliedCeremonyRecovery | suppliedCeremonyProposal |
		suppliedCeremonySignedProposal | suppliedCeremonyAcceptance
}

type suppliedCeremonyParsed struct {
	request     suppliedCeremonyRequest
	recovery    suppliedCeremonyRecovery
	unsigned    suppliedCeremonyProposal
	proposal    suppliedCeremonySignedProposal
	acceptance  suppliedCeremonyAcceptance
	body        suppliedRegistryBody
	requested   int64
	expires     int64
	proposed    int64
	accepted    int64
	probed      int64
	challenge   []byte
	proposalSig []byte
}

// VerifySuppliedRegistryCeremony verifies one complete supplied ceremony after
// a supplied genesis-based prefix. All raw bounds precede copying; all canonical
// encodings and then all primitive grammars precede replay or signatures. It
// returns only complete offline consistency claims: not a trusted current tip,
// fresh challenge, native recovery fact, authenticated connection, user presence,
// authority, receipt binding, or permission to commit/sign/confirm/send/cache.
func VerifySuppliedRegistryCeremony(prefixRecords [][]byte, ceremony SuppliedRegistryCeremony) (SuppliedRegistryHistory, error) {
	if !suppliedCeremonyBounds(prefixRecords, ceremony) {
		return SuppliedRegistryHistory{}, suppliedCeremonyError("bounds")
	}
	prefix := make([][]byte, len(prefixRecords))
	for i, raw := range prefixRecords {
		prefix[i] = bytes.Clone(raw)
	}
	owned := SuppliedRegistryCeremony{
		Request: bytes.Clone(ceremony.Request), RecoveryEvidence: bytes.Clone(ceremony.RecoveryEvidence),
		UnsignedProposal: bytes.Clone(ceremony.UnsignedProposal), SignedProposal: bytes.Clone(ceremony.SignedProposal),
		Acceptance: bytes.Clone(ceremony.Acceptance), FinalBody: bytes.Clone(ceremony.FinalBody), Record: bytes.Clone(ceremony.Record),
	}
	records := make([]suppliedRegistryRecord, len(prefix)+1)
	for i, raw := range prefix {
		if !suppliedRegistryDecode(raw, &records[i].wire) {
			return SuppliedRegistryHistory{}, suppliedCeremonyError("encoding")
		}
	}
	var parsed suppliedCeremonyParsed
	if !suppliedCeremonyDecode(owned, &parsed, &records[len(prefix)].wire) {
		return SuppliedRegistryHistory{}, suppliedCeremonyError("encoding")
	}
	for i := range records {
		if !suppliedRegistryPrimitives(&records[i]) {
			return SuppliedRegistryHistory{}, suppliedCeremonyError("grammar")
		}
	}
	if !suppliedCeremonyPrimitives(owned, &parsed) {
		return SuppliedRegistryHistory{}, suppliedCeremonyError("grammar")
	}
	history := SuppliedRegistryHistory{tip: suppliedRegistryEmptyTip}
	for i, raw := range prefix {
		if !suppliedRegistryReplay(&history, &records[i], i+1) {
			return SuppliedRegistryHistory{}, suppliedCeremonyError("verification")
		}
		suppliedRegistryAdvance(&history, raw, &records[i])
	}
	candidate := &records[len(prefix)]
	if !suppliedCeremonyVerify(&history, owned, &parsed, candidate) ||
		!suppliedRegistryReplay(&history, candidate, len(records)) {
		return SuppliedRegistryHistory{}, suppliedCeremonyError("verification")
	}
	suppliedRegistryAdvance(&history, owned.Record, candidate)
	return history, nil
}

func suppliedCeremonyError(stage string) error {
	return &errx.Error{
		Code: errx.CodeUsage, Reason: "REGISTRY_CEREMONY_INVALID",
		Message: "supplied registry ceremony failed " + stage + " validation",
		Hint:    "discard the supplied ceremony; obtain complete transcript records from an independently trusted source",
	}
}

func suppliedCeremonyBounds(prefix [][]byte, c SuppliedRegistryCeremony) bool {
	if len(prefix) >= suppliedRegistryMaxRecords {
		return false
	}
	// Prefix plus candidate count and per-record caps derive the exact aggregate
	// bound (256 * 4,352) before copying any input. Transcript caps are separate.
	for _, raw := range prefix {
		if len(raw) == 0 || len(raw) > suppliedRegistryRecordBytes {
			return false
		}
	}
	for _, raw := range [][]byte{c.Request, c.Acceptance} {
		if len(raw) == 0 || len(raw) > 2048 {
			return false
		}
	}
	if c.RecoveryEvidence != nil && (len(c.RecoveryEvidence) == 0 || len(c.RecoveryEvidence) > 2048) {
		return false
	}
	for _, raw := range [][]byte{c.UnsignedProposal, c.SignedProposal, c.FinalBody} {
		if len(raw) == 0 || len(raw) > 4096 {
			return false
		}
	}
	return len(c.Record) != 0 && len(c.Record) <= suppliedRegistryRecordBytes
}

func suppliedCeremonyDecode(c SuppliedRegistryCeremony, p *suppliedCeremonyParsed, record *suppliedRegistryWire) bool {
	if !suppliedRegistryCanonicalDecode(c.Request, &p.request) ||
		!suppliedRegistryCanonicalDecode(c.UnsignedProposal, &p.unsigned) ||
		!suppliedRegistryCanonicalDecode(c.SignedProposal, &p.proposal) ||
		!suppliedRegistryCanonicalDecode(c.Acceptance, &p.acceptance) ||
		!suppliedRegistryCanonicalDecode(c.FinalBody, &p.body) ||
		!suppliedRegistryDecode(c.Record, record) {
		return false
	}
	return c.RecoveryEvidence == nil || suppliedRegistryCanonicalDecode(c.RecoveryEvidence, &p.recovery)
}

func suppliedCeremonyHeader(schema *uint64, message *string, expected string) bool {
	return schema != nil && *schema == 1 && message != nil && *message == expected
}

func suppliedCeremonyTransition(kind *string) bool {
	return kind != nil && (*kind == "enroll" || *kind == "rotate" || *kind == "revoke" || *kind == "recover")
}

func suppliedCeremonyRevision(revision *uint64, zeroAllowed bool) bool {
	return revision != nil && *revision <= suppliedRegistryMaxRecords && (zeroAllowed || *revision != 0)
}

func suppliedCeremonyDigests(values ...*string) bool {
	for _, value := range values {
		if value == nil || !suppliedRegistryHex(*value, 64) {
			return false
		}
	}
	return true
}

func suppliedCeremonyGeneration(value *string) bool {
	return value == nil || keyGenerationRevision(*value) != 0
}

func suppliedCeremonyBase64(value *string, size int) ([]byte, bool) {
	if value == nil || len(*value) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(*value)
	return raw, err == nil && len(raw) == size && base64.RawURLEncoding.EncodeToString(raw) == *value
}

func suppliedCeremonyProposalPrimitives(p *suppliedCeremonyProposal) bool {
	if !suppliedCeremonyHeader(p.SchemaVersion, p.MessageType, "registry_proposal") ||
		!suppliedCeremonyTransition(p.TransitionKind) || !suppliedCeremonyRevision(p.RegistryRevision, false) ||
		!suppliedCeremonyDigests(p.RequestSHA256, p.ChallengeSHA256, p.PreviousRecordSHA256, p.ArtifactDescriptorSHA256) ||
		(p.RecoveryEvidenceSHA256 != nil && !suppliedRegistryHex(*p.RecoveryEvidenceSHA256, 64)) ||
		p.ProposalSignerRole == nil || (*p.ProposalSignerRole != "old" && *p.ProposalSignerRole != "new") {
		return false
	}
	_, _, ok := suppliedRegistryTuple(p.TargetGeneration, p.TargetKeyID, p.TargetKeyTag, p.TargetSPKI, p.TargetFingerprintSHA256)
	if !ok {
		return false
	}
	fresh, _, ok := suppliedRegistryTuple(p.NewGeneration, p.NewKeyID, p.NewKeyTag, p.NewSPKI, p.NewFingerprintSHA256)
	if !ok || (fresh != nil && keyGenerationRevision(fresh.Generation) != int(*p.RegistryRevision)) {
		return false
	}
	_, proposedOK := suppliedRegistryTime(p.ProposedAt)
	_, expiresOK := suppliedRegistryTime(p.ExpiresAt)
	return proposedOK && expiresOK
}

func suppliedCeremonyPrimitives(c SuppliedRegistryCeremony, p *suppliedCeremonyParsed) bool {
	q := &p.request
	if !suppliedCeremonyHeader(q.SchemaVersion, q.MessageType, "registry_request") ||
		!suppliedCeremonyTransition(q.TransitionKind) || !suppliedCeremonyRevision(q.ExpectedRegistryRevision, true) ||
		!suppliedCeremonyDigests(q.PreviousRecordSHA256, q.ArtifactDescriptorSHA256) ||
		!suppliedCeremonyGeneration(q.TargetGeneration) || !suppliedCeremonyGeneration(q.NewGeneration) ||
		(q.RecoveryMode != nil && *q.RecoveryMode != "missing_key_item_or_disabled_registry") {
		return false
	}
	var ok bool
	p.challenge, ok = suppliedCeremonyBase64(q.Challenge, 32)
	if !ok {
		return false
	}
	p.requested, ok = suppliedRegistryTime(q.RequestedAt)
	if !ok {
		return false
	}
	p.expires, ok = suppliedRegistryTime(q.ExpiresAt)
	if !ok {
		return false
	}
	if !suppliedCeremonyProposalPrimitives(&p.unsigned) || !suppliedCeremonyProposalPrimitives(&p.proposal.suppliedCeremonyProposal) || p.proposal.ProposalSignature == nil {
		return false
	}
	var err error
	p.proposalSig, err = DecodeP256DERSignature(*p.proposal.ProposalSignature)
	if err != nil {
		return false
	}
	p.proposed, ok = suppliedRegistryTime(p.proposal.ProposedAt)
	if !ok {
		return false
	}
	a := &p.acceptance
	if !suppliedCeremonyHeader(a.SchemaVersion, a.MessageType, "registry_acceptance") ||
		!suppliedCeremonyTransition(a.TransitionKind) || !suppliedCeremonyRevision(a.RegistryRevision, false) ||
		!suppliedCeremonyDigests(a.RequestSHA256, a.ProposalSHA256, a.ChallengeSHA256, a.PreviousRecordSHA256, a.ArtifactDescriptorSHA256) ||
		(a.RecoveryEvidenceSHA256 != nil && !suppliedRegistryHex(*a.RecoveryEvidenceSHA256, 64)) ||
		!suppliedCeremonyGeneration(a.TargetGeneration) || !suppliedCeremonyGeneration(a.NewGeneration) || a.Accepted == nil {
		return false
	}
	p.accepted, ok = suppliedRegistryTime(a.AcceptedAt)
	if !ok {
		return false
	}
	if _, ok := suppliedRegistryTime(a.ExpiresAt); !ok {
		return false
	}
	body := suppliedRegistryRecord{wire: suppliedRegistryWire{suppliedRegistryBody: p.body}}
	if !suppliedRegistryPrimitives(&body) {
		return false
	}
	if c.RecoveryEvidence == nil {
		return true
	}
	e := &p.recovery
	if !suppliedCeremonyHeader(e.SchemaVersion, e.MessageType, "registry_recovery_evidence") ||
		!suppliedCeremonyRevision(e.RegistryRevision, true) ||
		!suppliedCeremonyDigests(e.RequestSHA256, e.ChallengeSHA256, e.PreviousRecordSHA256, e.ArtifactDescriptorSHA256) ||
		!suppliedCeremonyGeneration(e.TargetGeneration) || e.Eligibility == nil || e.KeyLookupResult == nil || e.ContinuityProbeResult == nil ||
		(*e.Eligibility != "active_key_item_not_found" && *e.Eligibility != "registry_disabled") ||
		(*e.KeyLookupResult != "errSecItemNotFound:-25300" && *e.KeyLookupResult != "not_attempted:registry_disabled") ||
		(*e.ContinuityProbeResult != "not_attempted:no_key" && *e.ContinuityProbeResult != "not_attempted:no_active_generation") {
		return false
	}
	if e.TargetKeyTag != nil && (len(*e.TargetKeyTag) != len(suppliedRegistryKeyTag)+32 || (*e.TargetKeyTag)[:len(suppliedRegistryKeyTag)] != suppliedRegistryKeyTag ||
		!suppliedRegistryHex((*e.TargetKeyTag)[len(suppliedRegistryKeyTag):], 32)) {
		return false
	}
	p.probed, ok = suppliedRegistryTime(e.ProbedAt)
	return ok
}

func suppliedCeremonyEqual(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func suppliedCeremonyDigest(domain string, raw []byte) string {
	input := make([]byte, 0, len(domain)+len(raw))
	input = append(input, domain...)
	input = append(input, raw...)
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}

func suppliedCeremonyVerify(history *SuppliedRegistryHistory, c SuppliedRegistryCeremony, p *suppliedCeremonyParsed, record *suppliedRegistryRecord) bool {
	q, proposal, a, b := &p.request, &p.proposal, &p.acceptance, &record.wire
	unsigned, err := json.Marshal(proposal.suppliedCeremonyProposal)
	if err != nil || !bytes.Equal(unsigned, c.UnsignedProposal) || !bytes.Equal(record.body, c.FinalBody) {
		return false
	}
	if int(*q.ExpectedRegistryRevision) != history.revision || *q.PreviousRecordSHA256 != history.tip ||
		p.expires <= p.requested || p.expires-p.requested > 300 ||
		p.proposed < p.requested || p.accepted < p.proposed || record.committed < p.accepted ||
		p.proposed >= p.expires || p.accepted >= p.expires || record.committed >= p.expires ||
		!suppliedCeremonyEqual(proposal.ExpiresAt, q.ExpiresAt) || !suppliedCeremonyEqual(a.ExpiresAt, q.ExpiresAt) ||
		!suppliedCeremonyEqual(b.RequestedAt, q.RequestedAt) || !suppliedCeremonyEqual(b.AcceptedAt, a.AcceptedAt) || !*a.Accepted {
		return false
	}
	kind := *q.TransitionKind
	requestDigest := suppliedCeremonyDigest("YTA-REGISTRY-REQUEST-V1\x00", c.Request)
	proposalDigest := suppliedCeremonyDigest("YTA-REGISTRY-PROPOSAL-DIGEST-V1\x00", c.SignedProposal)
	acceptanceDigest := suppliedCeremonyDigest("YTA-REGISTRY-ACCEPTANCE-V1\x00", c.Acceptance)
	challengeDigest := suppliedCeremonyDigest("", p.challenge)
	for _, fields := range []struct {
		kind, previous, descriptor, request, challenge, recovery, target, fresh *string
		revision                                                                *uint64
	}{
		{proposal.TransitionKind, proposal.PreviousRecordSHA256, proposal.ArtifactDescriptorSHA256, proposal.RequestSHA256, proposal.ChallengeSHA256, proposal.RecoveryEvidenceSHA256, proposal.TargetGeneration, proposal.NewGeneration, proposal.RegistryRevision},
		{a.TransitionKind, a.PreviousRecordSHA256, a.ArtifactDescriptorSHA256, a.RequestSHA256, a.ChallengeSHA256, a.RecoveryEvidenceSHA256, a.TargetGeneration, a.NewGeneration, a.RegistryRevision},
		{b.TransitionKind, b.PreviousRecordSHA256, b.ArtifactDescriptorSHA256, b.RequestSHA256, b.ChallengeSHA256, b.RecoveryEvidenceSHA256, b.TargetGeneration, b.NewGeneration, b.RegistryRevision},
	} {
		if *fields.kind != kind || *fields.previous != history.tip || *fields.descriptor != *q.ArtifactDescriptorSHA256 ||
			*fields.request != requestDigest || *fields.challenge != challengeDigest || int(*fields.revision) != history.revision+1 ||
			!suppliedCeremonyEqual(fields.target, q.TargetGeneration) || !suppliedCeremonyEqual(fields.fresh, q.NewGeneration) {
			return false
		}
		if c.RecoveryEvidence == nil {
			if fields.recovery != nil {
				return false
			}
		} else if fields.recovery == nil || *fields.recovery != suppliedCeremonyDigest("YTA-REGISTRY-RECOVERY-EVIDENCE-V1\x00", c.RecoveryEvidence) {
			return false
		}
	}
	if *a.ProposalSHA256 != proposalDigest || *b.ProposalSHA256 != proposalDigest || *b.AcceptanceSHA256 != acceptanceDigest {
		return false
	}
	for _, pair := range [][2]*string{
		{proposal.TargetGeneration, b.TargetGeneration}, {proposal.TargetKeyID, b.TargetKeyID}, {proposal.TargetKeyTag, b.TargetKeyTag},
		{proposal.TargetSPKI, b.TargetSPKI}, {proposal.TargetFingerprintSHA256, b.TargetFingerprintSHA256},
		{proposal.NewGeneration, b.NewGeneration}, {proposal.NewKeyID, b.NewKeyID}, {proposal.NewKeyTag, b.NewKeyTag},
		{proposal.NewSPKI, b.NewSPKI}, {proposal.NewFingerprintSHA256, b.NewFingerprintSHA256},
	} {
		if !suppliedCeremonyEqual(pair[0], pair[1]) {
			return false
		}
	}
	if !suppliedCeremonyVerifyRecovery(history, c, p, requestDigest, challengeDigest) {
		return false
	}
	role, key := "new", record.freshKey
	if kind == "revoke" {
		role, key = "old", record.targetKey
	}
	return *proposal.ProposalSignerRole == role && suppliedRegistrySignature(key, p.proposalSig, "YTA-REGISTRY-PROPOSAL-V1\x00", c.UnsignedProposal)
}

func suppliedCeremonyVerifyRecovery(history *SuppliedRegistryHistory, c SuppliedRegistryCeremony, p *suppliedCeremonyParsed, requestDigest, challengeDigest string) bool {
	q, e := &p.request, &p.recovery
	if *q.TransitionKind != "recover" {
		return c.RecoveryEvidence == nil && q.RecoveryMode == nil
	}
	if c.RecoveryEvidence == nil || q.RecoveryMode == nil || *q.RecoveryMode != "missing_key_item_or_disabled_registry" ||
		*e.RequestSHA256 != requestDigest || *e.ChallengeSHA256 != challengeDigest ||
		int(*e.RegistryRevision) != history.revision || *e.PreviousRecordSHA256 != history.tip ||
		*e.ArtifactDescriptorSHA256 != *q.ArtifactDescriptorSHA256 ||
		p.probed < p.requested || p.probed > p.proposed || p.probed >= p.expires {
		return false
	}
	for _, key := range history.keys {
		if key.Status == "active" {
			return e.TargetGeneration != nil && *e.TargetGeneration == key.Generation &&
				e.TargetKeyTag != nil && *e.TargetKeyTag == key.KeyTag &&
				*e.Eligibility == "active_key_item_not_found" && *e.KeyLookupResult == "errSecItemNotFound:-25300" &&
				*e.ContinuityProbeResult == "not_attempted:no_key"
		}
	}
	return e.TargetGeneration == nil && e.TargetKeyTag == nil && *e.Eligibility == "registry_disabled" &&
		*e.KeyLookupResult == "not_attempted:registry_disabled" && *e.ContinuityProbeResult == "not_attempted:no_active_generation"
}
