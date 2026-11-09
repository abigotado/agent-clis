//go:build ignore

// Test-only public scalars and reused nonces: NEVER use these keys or signing
// routines outside this synthetic corpus. Run from the repository root with
// go run ./testdata/gate1a-registry/generate.go [-check]. No runtime codec is used.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type field struct {
	name string
	raw  string
}
type object []field

func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func str(name, value string) field         { return field{name, quote(value)} }
func integer(name string, value int) field { return field{name, fmt.Sprint(value)} }
func nullable(name string, value *string) field {
	if value == nil {
		return field{name, "null"}
	}
	return str(name, *value)
}
func pointer(value string) *string { return &value }
func (o object) raw() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quote(f.name))
		b.WriteByte(':')
		b.WriteString(f.raw)
	}
	b.WriteByte('}')
	return b.String()
}
func (o object) replace(name, raw string) {
	for i := range o {
		if o[i].name == name {
			o[i].raw = raw
			return
		}
	}
	panic("unknown fixture field " + name)
}
func (o object) get(name string) string {
	for _, f := range o {
		if f.name == name {
			return f.raw
		}
	}
	panic("unknown fixture field " + name)
}
func (o object) text(name string) string {
	var s string
	if err := json.Unmarshal([]byte(o.get(name)), &s); err != nil {
		panic(err)
	}
	return s
}
func sum(raw string) string           { d := sha256.Sum256([]byte(raw)); return hex.EncodeToString(d[:]) }
func domain(purpose string) string    { return "YTA-REGISTRY-" + purpose + "-V1\x00" }
func hash(purpose, raw string) string { return sum(domain(purpose) + raw) }

type key struct {
	Generation  string `json:"generation"`
	ID          string `json:"key_id"`
	Tag         string `json:"key_tag"`
	SPKI        string `json:"spki"`
	Fingerprint string `json:"fingerprint_sha256"`
	scalar      int64
}

func newKey(revision int, scalar int64) key {
	x, y := elliptic.P256().ScalarBaseMult(big.NewInt(scalar).Bytes())
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		panic(err)
	}
	id := fmt.Sprintf("%032x", scalar)
	return key{fmt.Sprintf("YTAG-%020d", revision), id, "io.github.abigotado.youtrack-agent.approval.signing.v1/" + id, base64.RawURLEncoding.EncodeToString(der), sum(string(der)), scalar}
}
func sign(raw string, k key, high bool) string {
	// Public d and fixed k=7 make every signature independently reproducible.
	curve := elliptic.P256()
	n := curve.Params().N
	r, _ := curve.ScalarBaseMult([]byte{7})
	r.Mod(r, n)
	h := sha256.Sum256([]byte(raw))
	s := new(big.Int).SetBytes(h[:])
	s.Add(s, new(big.Int).Mul(r, big.NewInt(k.scalar)))
	s.Mul(s, new(big.Int).ModInverse(big.NewInt(7), n))
	s.Mod(s, n)
	if s.Sign() == 0 {
		panic("zero fixture signature")
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	if high {
		s.Sub(n, s)
	}
	x, y := curve.ScalarBaseMult(big.NewInt(k.scalar).Bytes())
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, h[:], r, s) {
		panic("synthetic signature arithmetic failed")
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}
func tuple(prefix string, k *key) object {
	if k == nil {
		return object{{prefix + "generation", "null"}, {prefix + "key_id", "null"}, {prefix + "key_tag", "null"}, {prefix + "spki", "null"}, {prefix + "fingerprint_sha256", "null"}}
	}
	return object{str(prefix+"generation", k.Generation), str(prefix+"key_id", k.ID), str(prefix+"key_tag", k.Tag), str(prefix+"spki", k.SPKI), str(prefix+"fingerprint_sha256", k.Fingerprint)}
}

type transcript struct {
	Request          string  `json:"request"`
	RecoveryEvidence *string `json:"recovery_evidence"`
	UnsignedProposal string  `json:"unsigned_proposal"`
	Proposal         string  `json:"proposal"`
	Acceptance       string  `json:"acceptance"`
	FinalBody        string  `json:"final_body"`
	Record           string  `json:"record"`
}
type manifestEntry struct {
	Purpose  string `json:"purpose"`
	InputHex string `json:"input_hex"`
	SHA256   string `json:"sha256"`
}
type stateEntry struct {
	Generation string `json:"generation"`
	Status     string `json:"status"`
}
type positive struct {
	ID     string   `json:"id"`
	Prefix []string `json:"prefix"`
	transcript
	Manifest      []manifestEntry `json:"manifest"`
	ExpectedState []stateEntry    `json:"expected_state"`
}
type negative struct {
	ID            string     `json:"id"`
	Base          string     `json:"base"`
	Change        string     `json:"change"`
	Reason        string     `json:"reason_class"`
	Prefix        []string   `json:"prefix"`
	Transcript    transcript `json:"transcript"`
	PrefixRecords []string   `json:"prefix_records,omitempty"`
}
type statusVector struct {
	ID       string `json:"id"`
	Raw      string `json:"raw"`
	Accepted bool   `json:"accepted"`
}
type corpus struct {
	SchemaVersion int            `json:"schema_version"`
	Scope         string         `json:"scope"`
	Keys          []key          `json:"keys"`
	Positives     []positive     `json:"positives"`
	Negatives     []negative     `json:"negatives"`
	OSStatus      []statusVector `json:"osstatus"`
}

type config struct {
	id, kind      string
	revision      int
	prefix        []string
	previous      string
	target, fresh *key
	state         []stateEntry
}

// Hooks deliberately modify one normative fact before all later hashes and
// signatures are regenerated. This is not a validator or expected-state oracle.
type edits struct {
	request, evidence, proposal, acceptance, body func(object)
	proposalDomain, oldDomain, newDomain          string
	proposalSignature                             func(string) string
	proposalHigh                                  bool
	omitEvidence                                  bool
	proposalKey                                   *key
	missingOld, missingNew                        bool
}

func build(c config, e edits) positive {
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i + c.revision*17)
	}
	challengeEncoded := base64.RawURLEncoding.EncodeToString(challenge)
	requested := "2026-09-01T12:00:00Z"
	proposed := "2026-09-01T12:00:01Z"
	accepted := "2026-09-01T12:00:02Z"
	committed := "2026-09-01T12:00:03Z"
	expires := "2026-09-01T12:05:00Z"
	var recoveryMode, targetGeneration, newGeneration *string
	if c.kind == "recover" {
		recoveryMode = pointer("missing_key_item_or_disabled_registry")
	}
	if c.target != nil {
		targetGeneration = &c.target.Generation
	}
	if c.fresh != nil {
		newGeneration = &c.fresh.Generation
	}
	r := object{integer("schema_version", 1), str("message_type", "registry_request"), str("transition_kind", c.kind), nullable("recovery_mode", recoveryMode), str("challenge", challengeEncoded), integer("expected_registry_revision", c.revision-1), str("previous_record_sha256", c.previous), str("artifact_descriptor_sha256", strings.Repeat("a", 64)), nullable("target_generation", targetGeneration), nullable("new_generation", newGeneration), str("requested_at", requested), str("expires_at", expires)}
	if e.request != nil {
		e.request(r)
	}
	t := transcript{Request: r.raw()}
	requestDigest := hash("REQUEST", t.Request)
	challengeDigest := sum(string(challenge))
	var evidenceDigest *string
	if c.kind == "recover" && !e.omitEvidence {
		eligibility, lookup, probe := "registry_disabled", "not_attempted:registry_disabled", "not_attempted:no_active_generation"
		var tag *string
		if c.target != nil {
			eligibility = "active_key_item_not_found"
			lookup = "errSecItemNotFound:-25300"
			probe = "not_attempted:no_key"
			tag = &c.target.Tag
		}
		x := object{integer("schema_version", 1), str("message_type", "registry_recovery_evidence"), str("request_sha256", requestDigest), str("challenge_sha256", challengeDigest), integer("registry_revision", c.revision-1), str("previous_record_sha256", r.text("previous_record_sha256")), str("artifact_descriptor_sha256", r.text("artifact_descriptor_sha256")), nullable("target_generation", targetGeneration), nullable("target_key_tag", tag), str("eligibility", eligibility), str("key_lookup_result", lookup), str("continuity_probe_result", probe), str("probed_at", proposed)}
		if e.evidence != nil {
			e.evidence(x)
		}
		t.RecoveryEvidence = pointer(x.raw())
		evidenceDigest = pointer(hash("RECOVERY-EVIDENCE", *t.RecoveryEvidence))
	}
	p := object{integer("schema_version", 1), str("message_type", "registry_proposal"), str("transition_kind", c.kind), str("request_sha256", requestDigest), str("challenge_sha256", challengeDigest), integer("registry_revision", c.revision), str("previous_record_sha256", r.text("previous_record_sha256")), str("artifact_descriptor_sha256", r.text("artifact_descriptor_sha256")), nullable("recovery_evidence_sha256", evidenceDigest)}
	p = append(p, tuple("target_", c.target)...)
	p = append(p, tuple("new_", c.fresh)...)
	role := "new"
	signer := c.fresh
	if c.kind == "revoke" {
		role = "old"
		signer = c.target
	}
	p = append(p, str("proposed_at", proposed), str("expires_at", r.text("expires_at")), str("proposal_signer_role", role))
	if e.proposal != nil {
		e.proposal(p)
	}
	t.UnsignedProposal = p.raw()
	pd := domain("PROPOSAL")
	if e.proposalDomain != "" {
		pd = e.proposalDomain
	}
	if e.proposalKey != nil {
		signer = e.proposalKey
	}
	signature := sign(pd+t.UnsignedProposal, *signer, e.proposalHigh)
	if e.proposalSignature != nil {
		signature = e.proposalSignature(signature)
	}
	t.Proposal = append(append(object{}, p...), str("proposal_signature", signature)).raw()
	proposalDigest := hash("PROPOSAL-DIGEST", t.Proposal)
	a := object{integer("schema_version", 1), str("message_type", "registry_acceptance"), str("transition_kind", c.kind), str("request_sha256", requestDigest), str("proposal_sha256", proposalDigest), str("challenge_sha256", challengeDigest), integer("registry_revision", c.revision), str("previous_record_sha256", r.text("previous_record_sha256")), str("artifact_descriptor_sha256", r.text("artifact_descriptor_sha256")), nullable("recovery_evidence_sha256", evidenceDigest), nullable("target_generation", targetGeneration), nullable("new_generation", newGeneration), str("accepted_at", accepted), str("expires_at", r.text("expires_at")), {"accepted", "true"}}
	if e.acceptance != nil {
		e.acceptance(a)
	}
	t.Acceptance = a.raw()
	f := object{integer("schema_version", 1), str("record_type", "approval_registry_transition"), str("transition_kind", c.kind), integer("registry_revision", c.revision), str("previous_record_sha256", r.text("previous_record_sha256")), str("request_sha256", requestDigest), str("proposal_sha256", proposalDigest), str("acceptance_sha256", hash("ACCEPTANCE", t.Acceptance)), str("challenge_sha256", challengeDigest), str("artifact_descriptor_sha256", r.text("artifact_descriptor_sha256")), nullable("recovery_evidence_sha256", evidenceDigest), str("requested_at", r.text("requested_at")), str("accepted_at", a.text("accepted_at")), str("committed_at", committed)}
	f = append(f, tuple("target_", c.target)...)
	var previousStatus, nextStatus, newStatus *string
	if c.target != nil {
		previousStatus = pointer("active")
		nextStatus = pointer("revoked")
		if c.kind == "rotate" {
			nextStatus = pointer("retained")
		}
	}
	if c.fresh != nil {
		newStatus = pointer("active")
	}
	f = append(f, nullable("target_previous_status", previousStatus), nullable("target_new_status", nextStatus))
	f = append(f, tuple("new_", c.fresh)...)
	f = append(f, nullable("new_status", newStatus), field{"revokes_all_prior", fmt.Sprint(c.kind == "recover")})
	if e.body != nil {
		e.body(f)
	}
	t.FinalBody = f.raw()
	var oldSig, newSig *string
	od, nd := domain("RECORD-OLD"), domain("RECORD-NEW")
	if e.oldDomain != "" {
		od = e.oldDomain
	}
	if e.newDomain != "" {
		nd = e.newDomain
	}
	if (c.kind == "rotate" || c.kind == "revoke") && !e.missingOld {
		oldSig = pointer(sign(od+t.FinalBody, *c.target, false))
	}
	if c.fresh != nil && !e.missingNew {
		newSig = pointer(sign(nd+t.FinalBody, *c.fresh, false))
	}
	t.Record = append(append(object{}, f...), nullable("old_signature", oldSig), nullable("new_signature", newSig)).raw()
	result := positive{ID: c.id, Prefix: c.prefix, transcript: t, ExpectedState: c.state}
	inputs := []struct{ purpose, input string }{{"request_digest", domain("REQUEST") + t.Request}, {"proposal_signature", domain("PROPOSAL") + t.UnsignedProposal}, {"proposal_digest", domain("PROPOSAL-DIGEST") + t.Proposal}, {"acceptance_digest", domain("ACCEPTANCE") + t.Acceptance}, {"record_digest", domain("COMMIT") + t.Record}, {"predecessor_digest", t.Record}}
	if t.RecoveryEvidence != nil {
		inputs = append(inputs, struct{ purpose, input string }{"recovery_evidence_digest", domain("RECOVERY-EVIDENCE") + *t.RecoveryEvidence})
	}
	if oldSig != nil {
		inputs = append(inputs, struct{ purpose, input string }{"old_signature", domain("RECORD-OLD") + t.FinalBody})
	}
	if newSig != nil {
		inputs = append(inputs, struct{ purpose, input string }{"new_signature", domain("RECORD-NEW") + t.FinalBody})
	}
	for _, input := range inputs {
		result.Manifest = append(result.Manifest, manifestEntry{input.purpose, hex.EncodeToString([]byte(input.input)), sum(input.input)})
	}
	return result
}

func rawSlot(t *transcript, name string) *string {
	switch name {
	case "request":
		return &t.Request
	case "recovery_evidence":
		return t.RecoveryEvidence
	case "unsigned_proposal":
		return &t.UnsignedProposal
	case "proposal":
		return &t.Proposal
	case "acceptance":
		return &t.Acceptance
	case "final_body":
		return &t.FinalBody
	case "record":
		return &t.Record
	default:
		panic("unknown object " + name)
	}
}
func cloned(t transcript) transcript {
	if t.RecoveryEvidence != nil {
		t.RecoveryEvidence = pointer(*t.RecoveryEvidence)
	}
	return t
}

func makeCorpus() corpus {
	k1, k2, k4, k3 := newKey(1, 1), newKey(2, 2), newKey(4, 4), newKey(3, 3)
	g1, g2, g3, g4 := k1.Generation, k2.Generation, k3.Generation, k4.Generation
	// Expected states are hand-reviewed protocol literals, not replay output.
	configs := []config{
		{id: "enroll1", kind: "enroll", revision: 1, prefix: []string{}, previous: strings.Repeat("0", 64), fresh: &k1, state: []stateEntry{{g1, "active"}}},
		{id: "rotate2", kind: "rotate", revision: 2, prefix: []string{"enroll1"}, target: &k1, fresh: &k2, state: []stateEntry{{g1, "retained"}, {g2, "active"}}},
		{id: "revoke3", kind: "revoke", revision: 3, prefix: []string{"enroll1", "rotate2"}, target: &k2, state: []stateEntry{{g1, "retained"}, {g2, "revoked"}}},
		{id: "recover-disabled4", kind: "recover", revision: 4, prefix: []string{"enroll1", "rotate2", "revoke3"}, fresh: &k4, state: []stateEntry{{g1, "revoked"}, {g2, "revoked"}, {g4, "active"}}},
		{id: "recover-active3", kind: "recover", revision: 3, prefix: []string{"enroll1", "rotate2"}, target: &k2, fresh: &k3, state: []stateEntry{{g1, "revoked"}, {g2, "revoked"}, {g3, "active"}}},
	}
	result := corpus{SchemaVersion: 1, Scope: "registry-transcript-core", Keys: []key{k1, k2, k3, k4}}
	byID := make(map[string]positive)
	for i := range configs {
		c := &configs[i]
		if len(c.prefix) > 0 {
			c.previous = sum(byID[c.prefix[len(c.prefix)-1]].Record)
		}
		p := build(*c, edits{})
		result.Positives = append(result.Positives, p)
		byID[p.ID] = p
	}
	add := func(id, base, change, reason string, t transcript) {
		result.Negatives = append(result.Negatives, negative{ID: id, Base: base, Change: change, Reason: reason, Prefix: byID[base].Prefix, Transcript: t})
	}
	semantic := func(id string, c config, e edits, reason, change string) {
		add(id, c.id, change, reason, build(c, e).transcript)
	}
	// Every object has independent raw-cap and canonical-byte rejection vectors.
	objects := []struct {
		name string
		cap  int
	}{{"request", 2048}, {"recovery_evidence", 2048}, {"unsigned_proposal", 4096}, {"proposal", 4096}, {"acceptance", 2048}, {"final_body", 4096}, {"record", 4352}}
	for _, obj := range objects {
		base := byID["recover-active3"]
		mutations := []struct {
			id    string
			apply func(string) string
		}{
			{"missing", func(s string) string { return strings.Replace(s, `"schema_version":1,`, "", 1) }},
			{"duplicate", func(s string) string {
				return strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
			}},
			{"unknown", func(s string) string { return s[:len(s)-1] + `,"UNTRUSTED_SENTINEL":"inert"}` }},
			{"reordered", func(s string) string {
				end := strings.IndexByte(s[20:], ',') + 20
				first := strings.IndexByte(s, ',')
				return "{" + s[first+1:end] + "," + s[1:first] + s[end:]
			}},
			{"escaped", func(s string) string { return strings.Replace(s, `"schema_version"`, `"schema_\u0076ersion"`, 1) }},
			{"whitespace", func(s string) string { return " " + s }},
			{"trailing", func(s string) string { return s + "null" }},
			{"nonobject", func(string) string { return "[]" }},
		}
		for _, m := range mutations {
			t := cloned(base.transcript)
			slot := rawSlot(&t, obj.name)
			*slot = m.apply(*slot)
			add("encoding-"+obj.name+"-"+m.id, base.ID, obj.name+": "+m.id, "canonical_encoding", t)
		}
		t := cloned(base.transcript)
		*rawSlot(&t, obj.name) = strings.Repeat(" ", obj.cap+1)
		add("size-"+obj.name+"-over", base.ID, fmt.Sprintf("%s: %d bytes before parsing", obj.name, obj.cap+1), "bounds_grammar", t)
		// Exactly-at-cap malformed input must progress past the size gate, then
		// fail canonical encoding. This distinguishes > from >= cap regressions.
		t = cloned(base.transcript)
		*rawSlot(&t, obj.name) = strings.Repeat(" ", obj.cap)
		add("size-"+obj.name+"-at", base.ID, fmt.Sprintf("%s: exactly %d malformed bytes", obj.name, obj.cap), "canonical_encoding", t)
	}
	rotate := configs[1]
	activeRecovery := configs[4]
	semantic("digest-request-without-nul", rotate, edits{proposal: func(o object) {
		o.replace("request_sha256", quote(sum("YTA-REGISTRY-REQUEST-V1"+byID[rotate.id].Request)))
	}}, "digest_domain", "proposal request digest omits domain NUL; all downstream objects resigned")
	semantic("digest-request-splice", rotate, edits{proposal: func(o object) { o.replace("request_sha256", quote(strings.Repeat("b", 64))) }}, "digest_domain", "proposal request digest substituted; downstream resigned")
	semantic("digest-acceptance-splice", rotate, edits{body: func(o object) { o.replace("acceptance_sha256", quote(strings.Repeat("b", 64))) }}, "digest_domain", "final acceptance digest substituted; final signatures regenerated")
	semantic("digest-predecessor", rotate, edits{request: func(o object) { o.replace("previous_record_sha256", quote(strings.Repeat("b", 64))) }}, "digest_domain", "all transcript predecessor digests replaced consistently and resigned")
	semantic("signature-proposal-domain", rotate, edits{proposalDomain: domain("RECORD-NEW")}, "signature", "proposal signed with wrong domain; downstream resigned")
	semantic("signature-proposal-domain-without-nul", rotate, edits{proposalDomain: "YTA-REGISTRY-PROPOSAL-V1"}, "signature", "proposal signing input omits domain NUL; downstream resigned")
	semantic("signature-proposal-wrong-key", rotate, edits{proposalKey: &k1}, "signature", "new-role proposal signed by old key; downstream resigned")
	semantic("signature-old-wrong-domain", rotate, edits{oldDomain: domain("RECORD-NEW")}, "signature", "old final signature uses new role domain")
	semantic("signature-new-wrong-domain", rotate, edits{newDomain: domain("RECORD-OLD")}, "signature", "new final signature uses old role domain")
	semantic("signature-missing-old", rotate, edits{missingOld: true}, "signature", "required old final signature replaced with null")
	semantic("signature-missing-new", rotate, edits{missingNew: true}, "signature", "required new final signature replaced with null")
	semantic("grammar-high-s", rotate, edits{proposalHigh: true}, "bounds_grammar", "proposal signature replaced by mathematically valid high-S alias; downstream resigned")
	semantic("time-proposal-at-expiry", rotate, edits{proposal: func(o object) { o.replace("proposed_at", quote("2026-09-01T12:05:00Z")) }}, "temporal", "proposal at exclusive expiry; valid signatures")
	semantic("time-acceptance-before-proposal", rotate, edits{acceptance: func(o object) { o.replace("accepted_at", quote("2026-09-01T12:00:00Z")) }}, "temporal", "acceptance before proposal; final accepted_at follows and valid signatures")
	semantic("time-commit-at-expiry", rotate, edits{body: func(o object) { o.replace("committed_at", quote("2026-09-01T12:05:00Z")) }}, "temporal", "commit at exclusive expiry; final resigned")
	semantic("time-request-window-over", rotate, edits{request: func(o object) { o.replace("expires_at", quote("2026-09-01T12:05:01Z")) }}, "temporal", "request TTL is 301 seconds; downstream expires_at matches and resigned")
	semantic("acceptance-false", rotate, edits{acceptance: func(o object) { o.replace("accepted", "false") }}, "state_transition", "acceptance denied; final acceptance digest/signatures recomputed")
	semantic("state-revoke-all-false", activeRecovery, edits{body: func(o object) { o.replace("revokes_all_prior", "false") }}, "state_transition", "recovery does not revoke all prior; final resigned")
	wrongTarget := rotate
	wrongTarget.id = "revoke3"
	wrongTarget.kind = "revoke"
	wrongTarget.revision = 3
	wrongTarget.prefix = configs[2].prefix
	wrongTarget.previous = configs[2].previous
	wrongTarget.fresh = nil
	semantic("state-wrong-target", wrongTarget, edits{}, "state_transition", "revocation targets retained generation1 with valid old-key signatures")
	reused := k1
	reused.Generation = k3.Generation
	reuse := activeRecovery
	reuse.fresh = &reused
	semantic("state-key-reuse", reuse, edits{}, "state_transition", "recovery introduces generation3 but reuses generation1 ID/tag/SPKI/fingerprint; valid new-key signatures")
	gap := activeRecovery
	gap.revision = 4
	gap.fresh = &k4
	semantic("state-revision-gap", gap, edits{}, "state_transition", "validly signed recovery revision4 after prefix revisions1,2")
	for _, v := range []struct{ id, lookup, probe string }{
		{"lookup-success", "errSecSuccess:0", "not_attempted:no_key"},
		{"continuity-success", "errSecItemNotFound:-25300", "success"},
		{"lookup-canceled", "errSecUserCanceled:-128", "not_attempted:no_key"},
		{"lookup-auth-failed", "errSecAuthFailed:-25293", "not_attempted:no_key"},
		{"lookup-interaction", "errSecInteractionNotAllowed:-25308", "not_attempted:no_key"},
		{"lookup-unknown", "unknown:1", "not_attempted:no_key"},
	} {
		semantic("recovery-"+v.id, activeRecovery, edits{evidence: func(o object) {
			o.replace("key_lookup_result", quote(v.lookup))
			o.replace("continuity_probe_result", quote(v.probe))
		}}, "recovery_eligibility", "recovery evidence: "+v.id+"; all subsequent digests/signatures valid")
	}
	semantic("recovery-wrong-eligibility", activeRecovery, edits{evidence: func(o object) { o.replace("eligibility", quote("registry_disabled")) }}, "recovery_eligibility", "active ledger claimed disabled; all subsequent digests/signatures valid")
	semantic("recovery-evidence-missing", activeRecovery, edits{omitEvidence: true}, "recovery_eligibility", "recovery evidence and downstream digests null; all signatures regenerated")
	badPrefix := build(configs[1], edits{newDomain: domain("RECORD-OLD")})
	t := cloned(byID[activeRecovery.id].transcript)
	add("recovery-invalid-prefix-signature", activeRecovery.id, "prefix rotate2 new signature uses wrong role domain; recovery cannot bypass prior validation", "signature", t)
	result.Negatives[len(result.Negatives)-1].PrefixRecords = []string{byID["enroll1"].Record, badPrefix.Record}
	// These candidate transcripts remain untouched. Each record-only prefix
	// has one resigned semantic defect, proving replay does not silently omit
	// checks performed when the original live transcript is available.
	badTime := build(configs[0], edits{body: func(o object) {
		o.replace("accepted_at", quote("2026-09-01T11:59:59Z"))
	}})
	add("prefix-time-reversed", "rotate2", "prefix enrollment accepted_at precedes requested_at; valid final signature", "temporal", cloned(byID["rotate2"].transcript))
	result.Negatives[len(result.Negatives)-1].PrefixRecords = []string{badTime.Record}
	unexpectedEvidence := build(configs[0], edits{body: func(o object) {
		o.replace("recovery_evidence_sha256", quote(strings.Repeat("b", 64)))
	}})
	add("prefix-recovery-digest-unexpected", "rotate2", "prefix enrollment has nonnull recovery evidence digest; valid final signature", "recovery_eligibility", cloned(byID["rotate2"].transcript))
	result.Negatives[len(result.Negatives)-1].PrefixRecords = []string{unexpectedEvidence.Record}
	missingEvidence := build(activeRecovery, edits{body: func(o object) {
		o.replace("recovery_evidence_sha256", "null")
	}})
	add("prefix-recovery-digest-missing", "recover-disabled4", "prefix recovery has null recovery evidence digest; valid final signature", "recovery_eligibility", cloned(byID["recover-disabled4"].transcript))
	result.Negatives[len(result.Negatives)-1].PrefixRecords = []string{byID["enroll1"].Record, byID["rotate2"].Record, missingEvidence.Record}
	// Grammar cases retain all downstream signatures where the field is in a
	// signed stage; raw canonical numbers remain nonnegative except OSStatus.
	for _, value := range []int{-1, 0, 257} {
		semantic(fmt.Sprintf("grammar-record-revision-%d", value), rotate, edits{body: func(o object) { o.replace("registry_revision", fmt.Sprint(value)) }}, "bounds_grammar", "record revision outside stored 1..256 range; final resigned")
	}
	semantic("grammar-request-negative-revision", rotate, edits{request: func(o object) { o.replace("expected_registry_revision", "-1") }}, "bounds_grammar", "negative non-OSStatus request revision; downstream resigned")
	semantic("grammar-schema-negative", rotate, edits{proposal: func(o object) { o.replace("schema_version", "-1") }}, "bounds_grammar", "negative non-OSStatus schema version; downstream resigned")
	wrongGenerationKey := k2
	wrongGenerationKey.Generation = k1.Generation
	wrongGeneration := rotate
	wrongGeneration.fresh = &wrongGenerationKey
	semantic("grammar-generation-revision", wrongGeneration, edits{}, "bounds_grammar", "all new-generation fields consistently name generation1 for introduction revision2; valid signatures")
	semantic("grammar-partial-tuple", rotate, edits{proposal: func(o object) { o.replace("new_key_tag", "null") }}, "bounds_grammar", "new tuple has one null member; downstream resigned")
	semantic("grammar-fingerprint", rotate, edits{proposal: func(o object) { o.replace("new_fingerprint_sha256", quote(strings.Repeat("b", 64))) }}, "bounds_grammar", "fingerprint does not hash DER SPKI; downstream resigned")
	semantic("grammar-challenge-padding", rotate, edits{request: func(o object) { o.replace("challenge", quote(o.text("challenge")+"=")) }}, "bounds_grammar", "challenge has forbidden base64url padding; downstream resigned")
	semantic("grammar-time-fraction", rotate, edits{body: func(o object) { o.replace("committed_at", quote("2026-09-01T12:00:03.0Z")) }}, "bounds_grammar", "time is not whole-second canonical UTC; final resigned")
	semantic("grammar-signature-der", rotate, edits{proposalSignature: func(string) string { return base64.RawURLEncoding.EncodeToString([]byte{0x30, 0}) }}, "bounds_grammar", "proposal signature empty DER sequence; downstream resigned")
	semantic("grammar-signature-nonminimal-der", rotate, edits{proposalSignature: func(s string) string {
		der, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			panic(err)
		}
		// Redundant zero in positive R; lengths adjusted, integer unchanged.
		der = append(append(append([]byte{}, der[:4]...), 0), der[4:]...)
		der[1]++
		der[3]++
		return base64.RawURLEncoding.EncodeToString(der)
	}}, "bounds_grammar", "proposal signature DER R has redundant zero; downstream resigned")
	semantic("grammar-spki-der", rotate, edits{proposal: func(o object) { o.replace("new_spki", quote(base64.RawURLEncoding.EncodeToString(make([]byte, 91)))) }}, "bounds_grammar", "new SPKI is 91 zero bytes; downstream resigned")
	semantic("grammar-spki-offcurve", rotate, edits{proposal: func(o object) {
		der, err := base64.RawURLEncoding.DecodeString(k2.SPKI)
		if err != nil {
			panic(err)
		}
		for i := 27; i < len(der); i++ {
			der[i] = 0
		}
		o.replace("new_spki", quote(base64.RawURLEncoding.EncodeToString(der)))
		o.replace("new_fingerprint_sha256", quote(sum(string(der))))
	}}, "bounds_grammar", "new SPKI valid DER header with off-curve zero coordinates and matching fingerprint; downstream resigned")
	semantic("grammar-key-tag", rotate, edits{proposal: func(o object) { o.replace("new_key_tag", quote(k1.Tag)) }}, "bounds_grammar", "new key tag names different key ID; downstream resigned")
	semantic("grammar-digest-uppercase", rotate, edits{proposal: func(o object) { o.replace("request_sha256", quote(strings.ToUpper(o.text("request_sha256")))) }}, "bounds_grammar", "request digest uppercase alias; downstream resigned")
	semantic("grammar-spki-padding", rotate, edits{proposal: func(o object) { o.replace("new_spki", quote(k2.SPKI+"==")) }}, "bounds_grammar", "new SPKI base64url padding; downstream resigned")
	semantic("encoding-schema-fraction", rotate, edits{proposal: func(o object) { o.replace("schema_version", "1.0") }}, "canonical_encoding", "schema number encoded as 1.0; downstream resigned")
	for i, raw := range []string{"-2147483648", "-25300", "-1", "0", "1", "2147483647"} {
		result.OSStatus = append(result.OSStatus, statusVector{fmt.Sprintf("valid-%d", i), raw, true})
	}
	for i, raw := range []string{"-2147483649", "2147483648", "-0", "+1", "01", "-01", "1.0", "1e0", `"-25300"`, "null"} {
		result.OSStatus = append(result.OSStatus, statusVector{fmt.Sprintf("invalid-%d", i), raw, false})
	}
	return result
}

func main() {
	check := flag.Bool("check", false, "check deterministic corpus without writing")
	flag.Parse()
	if err := generate(*check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func generate(check bool) error {
	c := makeCorpus()
	// Construction checks catch a misspelled replacement/duplicate ID without
	// teaching the generator the consumers' acceptance or rejection decisions.
	bases := make(map[string]transcript)
	ids := make(map[string]bool)
	for _, p := range c.Positives {
		if ids[p.ID] {
			return fmt.Errorf("duplicate positive fixture ID %s", p.ID)
		}
		ids[p.ID] = true
		bases[p.ID] = p.transcript
	}
	for _, n := range c.Negatives {
		if ids[n.ID] {
			return fmt.Errorf("duplicate negative fixture ID %s", n.ID)
		}
		ids[n.ID] = true
		base, ok := bases[n.Base]
		if !ok {
			return fmt.Errorf("unknown negative base %s", n.Base)
		}
		before, err := json.Marshal(base)
		if err != nil {
			return fmt.Errorf("encode base fixture: %w", err)
		}
		after, err := json.Marshal(n.Transcript)
		if err != nil {
			return fmt.Errorf("encode negative fixture: %w", err)
		}
		if bytes.Equal(before, after) && len(n.PrefixRecords) == 0 {
			return fmt.Errorf("negative fixture %s did not change bytes", n.ID)
		}
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode corpus: %w", err)
	}
	raw = append(raw, '\n')
	const path = "testdata/gate1a-registry/corpus.json"
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read corpus: %w", err)
		}
		if !bytes.Equal(got, raw) {
			return fmt.Errorf("corpus is stale: %s", path)
		}
		return nil
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write corpus: %w", err)
	}
	return nil
}
