package approval

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type registryTranscript struct {
	Request          string  `json:"request"`
	RecoveryEvidence *string `json:"recovery_evidence"`
	UnsignedProposal string  `json:"unsigned_proposal"`
	Proposal         string  `json:"proposal"`
	Acceptance       string  `json:"acceptance"`
	FinalBody        string  `json:"final_body"`
	Record           string  `json:"record"`
}
type registryStateEntry struct {
	Generation string `json:"generation"`
	Status     string `json:"status"`
}
type registryManifestEntry struct {
	Purpose  string `json:"purpose"`
	InputHex string `json:"input_hex"`
	SHA256   string `json:"sha256"`
}
type registryPositive struct {
	registryTranscript
	ID            string                  `json:"id"`
	Prefix        []string                `json:"prefix"`
	Manifest      []registryManifestEntry `json:"manifest"`
	ExpectedState []registryStateEntry    `json:"expected_state"`
}
type registryNegative struct {
	ID            string             `json:"id"`
	Base          string             `json:"base"`
	Change        string             `json:"change"`
	ReasonClass   string             `json:"reason_class"`
	Prefix        []string           `json:"prefix"`
	PrefixRecords *[]string          `json:"prefix_records"`
	Transcript    registryTranscript `json:"transcript"`
}
type registryCorpus struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	Keys          []struct {
		Generation        string `json:"generation"`
		KeyID             string `json:"key_id"`
		KeyTag            string `json:"key_tag"`
		SPKI              string `json:"spki"`
		FingerprintSHA256 string `json:"fingerprint_sha256"`
	} `json:"keys"`
	Positives []registryPositive `json:"positives"`
	Negatives []registryNegative `json:"negatives"`
	OSStatus  []struct {
		ID       string `json:"id"`
		Raw      string `json:"raw"`
		Accepted bool   `json:"accepted"`
	} `json:"osstatus"`
}

func readRegistryCorpus(t *testing.T) registryCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate1a-registry", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus registryCorpus
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	var trailing json.RawMessage
	if d.Decode(&trailing) != io.EOF {
		t.Fatal("trailing corpus data")
	}
	if corpus.SchemaVersion != 1 || corpus.Scope != "registry-transcript-core" {
		t.Fatal("unexpected registry corpus schema")
	}
	return corpus
}

func registryPositiveMap(t *testing.T, c registryCorpus) map[string]registryPositive {
	t.Helper()
	m := make(map[string]registryPositive)
	for _, p := range c.Positives {
		if _, exists := m[p.ID]; exists {
			t.Fatal("duplicate ceremony vector")
		}
		m[p.ID] = p
	}
	for _, id := range []string{"enroll1", "rotate2", "revoke3", "recover-disabled4", "recover-active3"} {
		if _, ok := m[id]; !ok {
			t.Fatalf("missing ceremony %s", id)
		}
	}
	if len(m) != 5 {
		t.Fatal("unexpected ceremony count")
	}
	return m
}

func registryPrefix(t *testing.T, ids []string, positives map[string]registryPositive) []string {
	t.Helper()
	var result []string
	for _, id := range ids {
		p, ok := positives[id]
		if !ok {
			t.Fatal("unknown prefix vector")
		}
		result = append(result, p.Record)
	}
	return result
}

func TestSharedRegistryCeremonyCorpus(t *testing.T) {
	c := readRegistryCorpus(t)
	positives := registryPositiveMap(t, c)
	gen := func(n int) string { return "YTAG-" + strings.Repeat("0", 19) + strconv.Itoa(n) }
	want := map[string][]registryStateEntry{
		"enroll1":           {{gen(1), "active"}},
		"rotate2":           {{gen(1), "retained"}, {gen(2), "active"}},
		"revoke3":           {{gen(1), "retained"}, {gen(2), "revoked"}},
		"recover-disabled4": {{gen(1), "revoked"}, {gen(2), "revoked"}, {gen(4), "active"}},
		"recover-active3":   {{gen(1), "revoked"}, {gen(2), "revoked"}, {gen(3), "active"}},
	}
	wantPrefixes := map[string][]string{"enroll1": {}, "rotate2": {"enroll1"}, "revoke3": {"enroll1", "rotate2"}, "recover-disabled4": {"enroll1", "rotate2", "revoke3"}, "recover-active3": {"enroll1", "rotate2"}}
	if len(c.Keys) != 4 {
		t.Fatal("unexpected synthetic public key roster size")
	}
	keys := make(map[string][5]string)
	for _, key := range c.Keys {
		values := [5]string{key.Generation, key.KeyID, key.KeyTag, key.SPKI, key.FingerprintSHA256}
		if registryGeneration(key.Generation) == 0 || !registryHex(key.KeyID, 32) || key.KeyTag != "io.github.abigotado.youtrack-agent.approval.signing.v1/"+key.KeyID {
			t.Fatal("invalid public key roster grammar")
		}
		spki, ok := registryBase64(key.SPKI, 91)
		if !ok {
			t.Fatal("invalid public key roster SPKI")
		}
		if _, err := P256DERSPKIToX963(spki); err != nil || registryHash("", string(spki)) != key.FingerprintSHA256 {
			t.Fatal("invalid public key roster fingerprint")
		}
		for _, old := range keys {
			for i := range old {
				if old[i] == values[i] {
					t.Fatal("reused public key roster tuple component")
				}
			}
		}
		keys[key.Generation] = values
	}
	for _, p := range c.Positives {
		t.Run(p.ID, func(t *testing.T) {
			if !reflect.DeepEqual(p.Prefix, wantPrefixes[p.ID]) {
				t.Fatal("fixture predecessor chain differs from literal expectation")
			}
			state, reason := registryVerifyTranscript(p.registryTranscript, registryPrefix(t, p.Prefix, positives))
			if reason != "" {
				t.Fatalf("ceremony rejected: %s", reason)
			}
			if !reflect.DeepEqual(state, want[p.ID]) || !reflect.DeepEqual(p.ExpectedState, want[p.ID]) {
				t.Fatal("derived or fixture state differs from literal expectation")
			}
			registryCheckManifest(t, p)
			record, why := registryParse(p.Record, "record")
			if why != "" {
				t.Fatal(why)
			}
			for _, prefix := range []string{"new_", "target_"} {
				tuple, why := registryTuple(record, prefix)
				if why != "" {
					t.Fatal(why)
				}
				if tuple[0] != "" && keys[tuple[0]] != tuple {
					t.Fatal("transcript public key not equal to supplied SPKI roster")
				}
			}
		})
	}
}

func TestSharedRegistryNegativeCorpus(t *testing.T) {
	c := readRegistryCorpus(t)
	positives := registryPositiveMap(t, c)
	seen := make(map[string]bool)
	for _, n := range c.Negatives {
		t.Run(n.ID, func(t *testing.T) {
			if seen[n.ID] {
				t.Fatal("duplicate negative")
			}
			seen[n.ID] = true
			if n.ReasonClass != registryExpectedReason(n.ID) {
				t.Fatal("fixture reason class differs from independently pinned taxonomy")
			}
			base, ok := positives[n.Base]
			if !ok {
				t.Fatal("unknown negative base")
			}
			prefix := registryPrefix(t, n.Prefix, positives)
			if n.PrefixRecords != nil {
				prefix = *n.PrefixRecords
			}
			if reflect.DeepEqual(n.Transcript, base.registryTranscript) && reflect.DeepEqual(prefix, registryPrefix(t, base.Prefix, positives)) {
				t.Fatal("negative does not change its base")
			}
			_, reason := registryVerifyTranscript(n.Transcript, prefix)
			if reason != n.ReasonClass || reason == "" {
				t.Fatalf("got reason %q, want %q", reason, n.ReasonClass)
			}
			// Exact equality to the closed reason class is also the redaction
			// contract: no decoder text or supplied value can appear in it.
		})
	}
	required := []string{
		"digest-request-without-nul", "digest-request-splice", "digest-acceptance-splice", "digest-predecessor",
		"signature-proposal-domain", "signature-proposal-domain-without-nul", "signature-proposal-wrong-key", "signature-old-wrong-domain", "signature-new-wrong-domain", "signature-missing-old", "signature-missing-new", "grammar-high-s",
		"time-proposal-at-expiry", "time-acceptance-before-proposal", "time-commit-at-expiry", "time-request-window-over", "acceptance-false",
		"state-revoke-all-false", "state-wrong-target", "state-key-reuse", "state-revision-gap",
		"recovery-lookup-success", "recovery-continuity-success", "recovery-lookup-canceled", "recovery-lookup-auth-failed", "recovery-lookup-interaction", "recovery-lookup-unknown", "recovery-wrong-eligibility", "recovery-evidence-missing", "recovery-invalid-prefix-signature",
		"grammar-record-revision--1", "grammar-record-revision-0", "grammar-record-revision-257", "grammar-request-negative-revision", "grammar-schema-negative", "grammar-generation-revision", "grammar-partial-tuple", "grammar-fingerprint", "grammar-challenge-padding", "grammar-time-fraction",
		"grammar-signature-der", "grammar-signature-nonminimal-der", "grammar-spki-der", "grammar-spki-offcurve", "grammar-key-tag", "grammar-digest-uppercase", "grammar-spki-padding", "encoding-schema-fraction",
		"prefix-time-reversed", "prefix-recovery-digest-unexpected", "prefix-recovery-digest-missing",
	}
	for _, object := range []string{"request", "recovery_evidence", "unsigned_proposal", "proposal", "acceptance", "final_body", "record"} {
		for _, change := range []string{"missing", "duplicate", "unknown", "reordered", "escaped", "whitespace", "trailing", "nonobject"} {
			required = append(required, "encoding-"+object+"-"+change)
		}
		for _, size := range []string{"over", "at"} {
			required = append(required, "size-"+object+"-"+size)
		}
	}
	for _, id := range required {
		if !seen[id] {
			t.Fatalf("missing required negative %s", id)
		}
	}
	if len(seen) != len(required) {
		t.Fatal("unexpected negative vector ID")
	}
}

func registryExpectedReason(id string) string {
	switch id {
	case "recovery-invalid-prefix-signature":
		return "signature"
	case "acceptance-false":
		return "state_transition"
	case "prefix-time-reversed":
		return "temporal"
	case "prefix-recovery-digest-unexpected", "prefix-recovery-digest-missing":
		return "recovery_eligibility"
	}
	switch {
	case strings.HasPrefix(id, "encoding-"), strings.HasPrefix(id, "size-") && strings.HasSuffix(id, "-at"):
		return "canonical_encoding"
	case strings.HasPrefix(id, "grammar-"), strings.HasPrefix(id, "size-"):
		return "bounds_grammar"
	case strings.HasPrefix(id, "digest-"):
		return "digest_domain"
	case strings.HasPrefix(id, "signature-"):
		return "signature"
	case strings.HasPrefix(id, "time-"):
		return "temporal"
	case strings.HasPrefix(id, "recovery-"):
		return "recovery_eligibility"
	case strings.HasPrefix(id, "state-"):
		return "state_transition"
	default:
		return ""
	}
}

func TestRegistryCombinedFaultPrecedence(t *testing.T) {
	c := readRegistryCorpus(t)
	positives := registryPositiveMap(t, c)
	base := positives["recover-active3"]
	missing := base.registryTranscript
	missing.RecoveryEvidence = nil
	request, reason := registryParse(missing.Request, "request")
	if reason != "" {
		t.Fatal(reason)
	}
	request["previous_record_sha256"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
	missing.Request = string(registryObjectBytes(request, registryFields("request")))
	var invalidPrefix []string
	var badEvidence registryTranscript
	for _, n := range c.Negatives {
		switch n.ID {
		case "recovery-invalid-prefix-signature":
			if n.PrefixRecords == nil {
				t.Fatal("missing invalid prefix records")
			}
			invalidPrefix = *n.PrefixRecords
		case "recovery-continuity-success":
			badEvidence = n.Transcript
		}
	}
	if len(invalidPrefix) == 0 || badEvidence.Record == "" {
		t.Fatal("missing compound-fault source fixture")
	}
	record, reason := registryParse(badEvidence.Record, "record")
	if reason != "" {
		t.Fatal(reason)
	}
	baseRecord, reason := registryParse(base.Record, "record")
	if reason != "" {
		t.Fatal(reason)
	}
	record["new_signature"] = baseRecord["new_signature"]
	badEvidence.Record = string(registryObjectBytes(record, registryFields("record")))
	for _, tc := range []struct {
		name   string
		tr     registryTranscript
		prefix []string
		want   string
	}{
		{"missing evidence before wrong candidate digest", missing, registryPrefix(t, base.Prefix, positives), "recovery_eligibility"},
		{"invalid prefix before missing evidence", missing, invalidPrefix, "signature"},
		{"signature before evidence content eligibility", badEvidence, registryPrefix(t, base.Prefix, positives), "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, reason := registryVerifyTranscript(tc.tr, tc.prefix); reason != tc.want {
				t.Fatalf("got %q, want %q", reason, tc.want)
			}
		})
	}
}

func TestRegistrySignatureVerifierRejectsMalformedKeys(t *testing.T) {
	c := readRegistryCorpus(t)
	base := registryPositiveMap(t, c)["enroll1"]
	proposal, reason := registryParse(base.Proposal, "proposal")
	if reason != "" {
		t.Fatal(reason)
	}
	signature := registryString(proposal, "proposal_signature")
	validKey := registryString(proposal, "new_spki")
	if !registryVerifySignature(validKey, signature, "YTA-REGISTRY-PROPOSAL-V1\x00", base.UnsignedProposal) {
		t.Fatal("valid signature control rejected")
	}
	spki, ok := registryBase64(validKey, 91)
	if !ok {
		t.Fatal("invalid control SPKI")
	}
	clear(spki[len(spki)-64:]) // Preserve DER and point tag, replace X/Y with an off-curve point.
	for _, key := range []string{"", "not-base64", base64.RawURLEncoding.EncodeToString(spki)} {
		t.Run(key, func(t *testing.T) {
			if registryVerifySignature(key, signature, "YTA-REGISTRY-PROPOSAL-V1\x00", base.UnsignedProposal) {
				t.Fatal("malformed or off-curve public key accepted")
			}
		})
	}
}

// This checks fixture grammar consistency only. It does not exercise a
// production OSStatus parser or the native Security.framework boundary.
func TestSharedRegistryOSStatusFixtureConsistency(t *testing.T) {
	c := readRegistryCorpus(t)
	positives := make(map[string]bool)
	negatives := make(map[string]bool)
	seen := make(map[string]bool)
	for _, v := range c.OSStatus {
		t.Run(v.ID, func(t *testing.T) {
			if seen[v.ID] {
				t.Fatal("duplicate OSStatus ID")
			}
			seen[v.ID] = true
			n, err := strconv.ParseInt(v.Raw, 10, 32)
			accepted := err == nil && strconv.FormatInt(n, 10) == v.Raw
			if accepted != v.Accepted {
				t.Fatal("OSStatus acceptance mismatch")
			}
			if accepted {
				positives[v.Raw] = true
			} else {
				negatives[v.Raw] = true
			}
		})
	}
	for _, raw := range []string{"-2147483648", "-25300", "-1", "0", "1", "2147483647"} {
		if !positives[raw] {
			t.Fatal("missing required OSStatus positive")
		}
	}
	for _, raw := range []string{"-2147483649", "2147483648", "-0", "+1", "01", "-01", "1.0", "1e0", `"-25300"`, "null"} {
		if !negatives[raw] {
			t.Fatal("missing required OSStatus negative")
		}
	}
}

func registryCheckManifest(t *testing.T, p registryPositive) {
	t.Helper()
	inputs := map[string]string{
		"request_digest":     "YTA-REGISTRY-REQUEST-V1\x00" + p.Request,
		"proposal_signature": "YTA-REGISTRY-PROPOSAL-V1\x00" + p.UnsignedProposal,
		"proposal_digest":    "YTA-REGISTRY-PROPOSAL-DIGEST-V1\x00" + p.Proposal,
		"acceptance_digest":  "YTA-REGISTRY-ACCEPTANCE-V1\x00" + p.Acceptance,
		"predecessor_digest": p.Record,
		"record_digest":      "YTA-REGISTRY-COMMIT-V1\x00" + p.Record,
	}
	record, why := registryParse(p.Record, "record")
	if why != "" {
		t.Fatal(why)
	}
	if string(record["old_signature"]) != "null" {
		inputs["old_signature"] = "YTA-REGISTRY-RECORD-OLD-V1\x00" + p.FinalBody
	}
	if string(record["new_signature"]) != "null" {
		inputs["new_signature"] = "YTA-REGISTRY-RECORD-NEW-V1\x00" + p.FinalBody
	}
	if p.RecoveryEvidence != nil {
		inputs["recovery_evidence_digest"] = "YTA-REGISTRY-RECOVERY-EVIDENCE-V1\x00" + *p.RecoveryEvidence
	}
	seen := make(map[string]bool)
	for _, m := range p.Manifest {
		input, ok := inputs[m.Purpose]
		if !ok || seen[m.Purpose] {
			t.Fatal("unknown or duplicate manifest entry")
		}
		seen[m.Purpose] = true
		if m.InputHex != hex.EncodeToString([]byte(input)) || m.SHA256 != registryHash("", input) {
			t.Fatalf("manifest mismatch: %s", m.Purpose)
		}
	}
	if len(seen) != len(inputs) {
		t.Fatal("missing manifest entry")
	}
}

func registryVerifyTranscript(tr registryTranscript, prefix []string) ([]registryStateEntry, string) {
	raws := []string{tr.Request, tr.UnsignedProposal, tr.Proposal, tr.Acceptance, tr.FinalBody, tr.Record}
	kinds := []string{"request", "proposal_unsigned", "proposal", "acceptance", "final_body", "record"}
	if tr.RecoveryEvidence != nil {
		raws = append(raws, *tr.RecoveryEvidence)
		kinds = append(kinds, "recovery_evidence")
	}
	allRaws := append(append([]string{}, raws...), prefix...)
	allKinds := append([]string{}, kinds...)
	for range prefix {
		allKinds = append(allKinds, "record")
	}
	if len(prefix) > 256 {
		return nil, "bounds_grammar"
	}
	total := len(tr.Record)
	for _, raw := range prefix {
		total += len(raw)
	}
	if total > 1114112 {
		return nil, "bounds_grammar"
	}
	for i, raw := range allRaws {
		if len(raw) > registryCap(allKinds[i]) {
			return nil, "bounds_grammar"
		}
	}
	// All canonical shapes and then all primitive grammars precede any hashing
	// or cryptography, even when a later object is malformed.
	allObjects := make([]registryObject, len(allRaws))
	for i, raw := range allRaws {
		o, why := registryParseCanonical(raw, allKinds[i])
		if why != "" {
			return nil, why
		}
		allObjects[i] = o
	}
	for i, o := range allObjects {
		if why := registryValidateGrammar(o, allKinds[i]); why != "" {
			return nil, why
		}
	}
	state, tuples, reason := registryReplay(prefix, allObjects[len(raws):])
	if reason != "" {
		return nil, reason
	}
	objects := allObjects[:len(raws)]
	q, u, p, a, b, r := objects[0], objects[1], objects[2], objects[3], objects[4], objects[5]
	transition := registryString(q, "transition_kind")
	// Missing recovery evidence is a structural eligibility failure, after the
	// entire prefix is validated but before candidate digest comparisons.
	if transition == "recover" && tr.RecoveryEvidence == nil {
		return nil, "recovery_eligibility"
	}
	if string(registryObjectBytes(p, registryFields("proposal_unsigned"))) != tr.UnsignedProposal || string(registryObjectBytes(r, registryFields("final_body"))) != tr.FinalBody {
		return nil, "digest_domain"
	}
	requestDigest := registryHash("YTA-REGISTRY-REQUEST-V1\x00", tr.Request)
	proposalDigest := registryHash("YTA-REGISTRY-PROPOSAL-DIGEST-V1\x00", tr.Proposal)
	acceptanceDigest := registryHash("YTA-REGISTRY-ACCEPTANCE-V1\x00", tr.Acceptance)
	challenge, ok := registryBase64(registryString(q, "challenge"), 32)
	if !ok {
		return nil, "bounds_grammar"
	}
	challengeDigest := registryHash("", string(challenge))
	previous := strings.Repeat("0", 64)
	if len(prefix) > 0 {
		previous = registryHash("", prefix[len(prefix)-1])
	}
	recoveryDigest := ""
	if tr.RecoveryEvidence != nil {
		recoveryDigest = registryHash("YTA-REGISTRY-RECOVERY-EVIDENCE-V1\x00", *tr.RecoveryEvidence)
	}
	for _, o := range objects {
		if value, exists := o["request_sha256"]; exists && string(value) != `"`+requestDigest+`"` {
			return nil, "digest_domain"
		}
		if value, exists := o["proposal_sha256"]; exists && string(value) != `"`+proposalDigest+`"` {
			return nil, "digest_domain"
		}
		if value, exists := o["acceptance_sha256"]; exists && string(value) != `"`+acceptanceDigest+`"` {
			return nil, "digest_domain"
		}
		if value, exists := o["challenge_sha256"]; exists && string(value) != `"`+challengeDigest+`"` {
			return nil, "digest_domain"
		}
		if registryString(o, "previous_record_sha256") != previous || !registryEqual(o, "artifact_descriptor_sha256", q, "artifact_descriptor_sha256") {
			return nil, "digest_domain"
		}
		if value, exists := o["recovery_evidence_sha256"]; exists {
			expected := "null"
			if recoveryDigest != "" {
				expected = `"` + recoveryDigest + `"`
			}
			if string(value) != expected {
				return nil, "digest_domain"
			}
		}
	}
	role := registryString(p, "proposal_signer_role")
	signer := "new_spki"
	if role == "old" {
		signer = "target_spki"
	} else if role != "new" {
		return nil, "bounds_grammar"
	}
	if !registryVerifySignature(registryString(p, signer), registryString(p, "proposal_signature"), "YTA-REGISTRY-PROPOSAL-V1\x00", tr.UnsignedProposal) {
		return nil, "signature"
	}
	if !registrySignatureShape(r, transition) {
		return nil, "signature"
	}
	for _, s := range []struct{ field, key, domain string }{{"old_signature", "target_spki", "YTA-REGISTRY-RECORD-OLD-V1\x00"}, {"new_signature", "new_spki", "YTA-REGISTRY-RECORD-NEW-V1\x00"}} {
		if string(r[s.field]) != "null" && !registryVerifySignature(registryString(r, s.key), registryString(r, s.field), s.domain, tr.FinalBody) {
			return nil, "signature"
		}
	}
	issued, expiry := registryTime(q, "requested_at"), registryTime(q, "expires_at")
	if !expiry.After(issued) || expiry.Sub(issued) > 5*time.Minute {
		return nil, "temporal"
	}
	last := issued
	for _, pair := range []struct {
		o     registryObject
		field string
	}{{p, "proposed_at"}, {a, "accepted_at"}, {b, "committed_at"}} {
		current := registryTime(pair.o, pair.field)
		if current.Before(last) || !current.Before(expiry) {
			return nil, "temporal"
		}
		last = current
	}
	if !registryEqual(p, "expires_at", q, "expires_at") || !registryEqual(a, "expires_at", q, "expires_at") || !registryEqual(b, "requested_at", q, "requested_at") || !registryEqual(b, "accepted_at", a, "accepted_at") {
		return nil, "temporal"
	}
	if tr.RecoveryEvidence != nil {
		probed := registryTime(objects[6], "probed_at")
		if probed.Before(issued) || probed.After(registryTime(p, "proposed_at")) || !probed.Before(expiry) {
			return nil, "temporal"
		}
	}
	active := ""
	for _, entry := range state {
		if entry.Status == "active" {
			active = entry.Generation
		}
	}
	if transition == "recover" {
		if registryString(q, "recovery_mode") != "missing_key_item_or_disabled_registry" {
			return nil, "recovery_eligibility"
		}
		e := objects[6]
		eligibility, lookup, probe := "registry_disabled", "not_attempted:registry_disabled", "not_attempted:no_active_generation"
		if active != "" {
			eligibility, lookup, probe = "active_key_item_not_found", "errSecItemNotFound:-25300", "not_attempted:no_key"
		}
		if registryString(e, "eligibility") != eligibility || registryString(e, "key_lookup_result") != lookup || registryString(e, "continuity_probe_result") != probe || registryString(e, "target_generation") != active || registryNumber(e, "registry_revision") != registryNumber(q, "expected_registry_revision") {
			return nil, "recovery_eligibility"
		}
		if active != "" {
			if registryString(e, "target_key_tag") != tuples[active][2] {
				return nil, "recovery_eligibility"
			}
		} else if string(e["target_key_tag"]) != "null" || string(e["target_generation"]) != "null" {
			return nil, "recovery_eligibility"
		}
	} else if tr.RecoveryEvidence != nil || string(q["recovery_mode"]) != "null" {
		return nil, "recovery_eligibility"
	}
	for _, o := range []registryObject{u, p, a, b, r} {
		if registryString(o, "transition_kind") != transition || !registryEqual(o, "target_generation", q, "target_generation") || !registryEqual(o, "new_generation", q, "new_generation") {
			return nil, "state_transition"
		}
		if registryNumber(o, "registry_revision") != len(prefix)+1 {
			return nil, "state_transition"
		}
	}
	if registryNumber(q, "expected_registry_revision") != len(prefix) || string(a["accepted"]) != "true" {
		return nil, "state_transition"
	}
	for _, field := range []string{"generation", "key_id", "key_tag", "spki", "fingerprint_sha256"} {
		for _, key := range []string{"target_", "new_"} {
			if !registryEqual(p, key+field, b, key+field) {
				return nil, "state_transition"
			}
		}
	}
	if (transition == "revoke" && role != "old") || (transition != "revoke" && role != "new") {
		return nil, "state_transition"
	}
	return registryApply(state, tuples, b, r, len(prefix)+1)
}

// Inputs have completed the all-caps, all-canonical, all-grammar preflight.
func registryReplay(records []string, objects []registryObject) ([]registryStateEntry, map[string][5]string, string) {
	state := []registryStateEntry{}
	tuples := make(map[string][5]string)
	previous := strings.Repeat("0", 64)
	for i, raw := range records {
		r := objects[i]
		if registryString(r, "previous_record_sha256") != previous {
			return nil, nil, "digest_domain"
		}
		body := string(registryObjectBytes(r, registryFields("final_body")))
		transition := registryString(r, "transition_kind")
		if !registrySignatureShape(r, transition) {
			return nil, nil, "signature"
		}
		for _, s := range []struct{ field, key, domain string }{{"old_signature", "target_spki", "YTA-REGISTRY-RECORD-OLD-V1\x00"}, {"new_signature", "new_spki", "YTA-REGISTRY-RECORD-NEW-V1\x00"}} {
			if string(r[s.field]) != "null" && !registryVerifySignature(registryString(r, s.key), registryString(r, s.field), s.domain, body) {
				return nil, nil, "signature"
			}
		}
		if registryTime(r, "accepted_at").Before(registryTime(r, "requested_at")) || registryTime(r, "committed_at").Before(registryTime(r, "accepted_at")) {
			return nil, nil, "temporal"
		}
		if (string(r["recovery_evidence_sha256"]) != "null") != (transition == "recover") {
			return nil, nil, "recovery_eligibility"
		}
		var reason string
		state, reason = registryApply(state, tuples, r, r, i+1)
		if reason != "" {
			return nil, nil, reason
		}
		previous = registryHash("", raw)
	}
	return state, tuples, ""
}

func registrySignatureShape(record registryObject, transition string) bool {
	return (string(record["old_signature"]) != "null") == (transition == "rotate" || transition == "revoke") &&
		(string(record["new_signature"]) != "null") == (transition != "revoke")
}

func registryApply(state []registryStateEntry, tuples map[string][5]string, b, r registryObject, revision int) ([]registryStateEntry, string) {
	if registryNumber(b, "registry_revision") != revision {
		return nil, "state_transition"
	}
	transition := registryString(b, "transition_kind")
	active := ""
	for _, e := range state {
		if e.Status == "active" {
			if active != "" {
				return nil, "state_transition"
			}
			active = e.Generation
		}
	}
	target, why := registryTuple(b, "target_")
	if why != "" {
		return nil, why
	}
	fresh, why := registryTuple(b, "new_")
	if why != "" {
		return nil, why
	}
	if target[0] != active || (active != "" && target != tuples[active]) {
		return nil, "state_transition"
	}
	newRequired := transition != "revoke"
	if !registrySignatureShape(r, transition) {
		return nil, "state_transition"
	}
	if (string(b["revokes_all_prior"]) == "true") != (transition == "recover") {
		return nil, "state_transition"
	}
	if active == "" {
		if string(b["target_previous_status"]) != "null" || string(b["target_new_status"]) != "null" {
			return nil, "state_transition"
		}
	} else {
		want := "revoked"
		if transition == "rotate" {
			want = "retained"
		}
		if registryString(b, "target_previous_status") != "active" || registryString(b, "target_new_status") != want {
			return nil, "state_transition"
		}
	}
	switch transition {
	case "enroll":
		if len(state) != 0 || revision != 1 {
			return nil, "state_transition"
		}
	case "rotate", "revoke":
		if active == "" {
			return nil, "state_transition"
		}
	case "recover":
		if len(state) == 0 {
			return nil, "state_transition"
		}
	default:
		return nil, "state_transition"
	}
	if newRequired {
		if registryGeneration(fresh[0]) != revision || registryString(b, "new_status") != "active" {
			return nil, "state_transition"
		}
		for _, old := range tuples {
			for i := range fresh {
				if fresh[i] == old[i] {
					return nil, "state_transition"
				}
			}
		}
	} else if fresh[0] != "" || string(b["new_status"]) != "null" {
		return nil, "state_transition"
	}
	for i := range state {
		if transition == "recover" || state[i].Generation == active {
			if transition == "rotate" {
				state[i].Status = "retained"
			} else {
				state[i].Status = "revoked"
			}
		}
	}
	if newRequired {
		tuples[fresh[0]] = fresh
		state = append(state, registryStateEntry{fresh[0], "active"})
	}
	return state, ""
}
