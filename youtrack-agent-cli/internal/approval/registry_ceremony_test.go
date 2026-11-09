package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const ceremonyTestRequestFields = "schema_version message_type transition_kind recovery_mode challenge expected_registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation new_generation requested_at expires_at"
const ceremonyTestProposalFields = "schema_version message_type transition_kind request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 proposed_at expires_at proposal_signer_role"
const ceremonyTestAcceptanceFields = "schema_version message_type transition_kind request_sha256 proposal_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation new_generation accepted_at expires_at accepted"
const ceremonyTestEvidenceFields = "schema_version message_type request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation target_key_tag eligibility key_lookup_result continuity_probe_result probed_at"

func ceremonyTestInput(tr registryTranscript) SuppliedRegistryCeremony {
	c := SuppliedRegistryCeremony{Request: []byte(tr.Request), UnsignedProposal: []byte(tr.UnsignedProposal), SignedProposal: []byte(tr.Proposal), Acceptance: []byte(tr.Acceptance), FinalBody: []byte(tr.FinalBody), Record: []byte(tr.Record)}
	if tr.RecoveryEvidence != nil {
		c.RecoveryEvidence = []byte(*tr.RecoveryEvidence)
	}
	return c
}

func ceremonyTestPrefix(t *testing.T, n registryNegative, c registryCorpus) [][]byte {
	t.Helper()
	prefix := registryPrefix(t, n.Prefix, registryPositiveMap(t, c))
	if n.PrefixRecords != nil {
		prefix = *n.PrefixRecords
	}
	var out [][]byte
	for _, raw := range prefix {
		out = append(out, []byte(raw))
	}
	return out
}

func ceremonyTestFailure(t *testing.T, prefix [][]byte, c SuppliedRegistryCeremony, stage string) {
	t.Helper()
	result, err := VerifySuppliedRegistryCeremony(prefix, c)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeUsage || typed.Reason != "REGISTRY_CEREMONY_INVALID" || typed.Message != "supplied registry ceremony failed "+stage+" validation" {
		t.Fatalf("wrong %s refusal: %+v", stage, err)
	}
	_, present := result.SuppliedTipDescriptorSHA256()
	if result.SuppliedRevision() != 0 || result.SuppliedTipSHA256() != "" || present || len(result.Keys()) != 0 {
		t.Fatal("refusal leaked partial verification")
	}
	if typed.Hint == "" || errors.Unwrap(typed) != nil || strings.Contains(fmt.Sprintf("%+v", typed), "UNTRUSTED_SENTINEL") || strings.Contains(fmt.Sprintf("%+v", typed), "999999999") {
		t.Fatal("unsafe refusal diagnostics")
	}
}

func ceremonyTestStage(t *testing.T, id string) string {
	t.Helper()
	if strings.HasPrefix(id, "size-") {
		if strings.HasSuffix(id, "-over") {
			return "bounds"
		}
		return "encoding"
	}
	if strings.HasPrefix(id, "encoding-") {
		return "encoding"
	}
	if containsHistoryName([]string{"grammar-record-revision--1", "grammar-request-negative-revision", "grammar-schema-negative"}, id) {
		return "encoding"
	}
	if strings.HasPrefix(id, "grammar-") {
		return "grammar"
	}
	if containsHistoryName([]string{"recovery-lookup-success", "recovery-continuity-success", "recovery-lookup-canceled", "recovery-lookup-auth-failed", "recovery-lookup-interaction", "recovery-lookup-unknown"}, id) {
		return "grammar"
	}
	for _, family := range []string{"digest-", "signature-", "time-", "state-", "recovery-", "prefix-"} {
		if strings.HasPrefix(id, family) {
			return "verification"
		}
	}
	if id == "acceptance-false" {
		return "verification"
	}
	t.Fatalf("unreviewed negative %s", id)
	return ""
}

func TestSuppliedRegistryCeremonyPinnedPositives(t *testing.T) {
	c := readRegistryCorpus(t)
	positive := registryPositiveMap(t, c)
	cases := []struct {
		id          string
		prefix      []string
		generations []int
		statuses    []string
		hash        string
	}{
		{"enroll1", nil, []int{1}, []string{"active"}, "c8154cd7d2a72f7e23dcbfa9f52d1b9ca97afad557c6becedf9eaf7a772db16b"},
		{"rotate2", []string{"enroll1"}, []int{1, 2}, []string{"retained", "active"}, "4c4394736cf2e1e619e5cdef3a45104b9dddd344d5febff6061d4bd37a877f5c"},
		{"revoke3", []string{"enroll1", "rotate2"}, []int{1, 2}, []string{"retained", "revoked"}, "8fc41f67fcc9b80d7eac1cf16f2e4bb581b753e2c4f3c2a87bc2125247ad3f75"},
		{"recover-disabled4", []string{"enroll1", "rotate2", "revoke3"}, []int{1, 2, 4}, []string{"revoked", "revoked", "active"}, "083686890e6a8b2fa969143f74d5a147415aaa125df7917344da9a636fa15f7c"},
		{"recover-active3", []string{"enroll1", "rotate2"}, []int{1, 2, 3}, []string{"revoked", "revoked", "active"}, "6d1f7ea55313a4ffd01cd5c2ddb732dcf871b2fe722699779e83b1b0b33453e6"},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			p := positive[test.id]
			if !reflect.DeepEqual(p.Prefix, append([]string{}, test.prefix...)) {
				t.Fatal("positive prefix changed")
			}
			prefix := historyTestRecords(t, test.prefix...)
			input := ceremonyTestInput(p.registryTranscript)
			result, err := VerifySuppliedRegistryCeremony(prefix, input)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, present := result.SuppliedTipDescriptorSHA256()
			if result.SuppliedRevision() != len(test.prefix)+1 || result.SuppliedTipSHA256() != test.hash || !present || descriptor != strings.Repeat("a", 64) {
				t.Fatal("pinned result differs")
			}
			var keys []SuppliedRegistryKey
			for i, g := range test.generations {
				_, key := historyTestKey(t, g)
				key.Status = test.statuses[i]
				keys = append(keys, key)
			}
			if !reflect.DeepEqual(result.Keys(), keys) {
				t.Fatal("pinned tuples/statuses differ")
			}
			copied := result.Keys()
			copied[0].Status = "changed"
			for _, raw := range append(prefix, input.Request, input.RecoveryEvidence, input.UnsignedProposal, input.SignedProposal, input.Acceptance, input.FinalBody, input.Record) {
				for i := range raw {
					raw[i] = 'x'
				}
			}
			if !reflect.DeepEqual(result.Keys(), keys) || result.SuppliedTipSHA256() != test.hash {
				t.Fatal("result borrows caller memory")
			}
		})
	}
}

func TestSuppliedRegistryCeremonyAllCoreNegatives(t *testing.T) {
	c := readRegistryCorpus(t)
	if len(c.Negatives) != 121 {
		t.Fatal("negative inventory changed")
	}
	for _, n := range c.Negatives {
		t.Run(n.ID, func(t *testing.T) {
			ceremonyTestFailure(t, ceremonyTestPrefix(t, n, c), ceremonyTestInput(n.Transcript), ceremonyTestStage(t, n.ID))
		})
	}
}

func TestSuppliedRegistryCeremonySemanticFixturesHaveValidSignatures(t *testing.T) {
	c := readRegistryCorpus(t)
	names := []string{"digest-predecessor", "acceptance-false", "state-revoke-all-false", "state-wrong-target", "state-key-reuse", "state-revision-gap", "time-proposal-at-expiry", "time-acceptance-before-proposal", "time-commit-at-expiry", "time-request-window-over", "recovery-lookup-success", "recovery-continuity-success", "recovery-lookup-canceled", "recovery-lookup-auth-failed", "recovery-lookup-interaction", "recovery-lookup-unknown", "recovery-wrong-eligibility", "recovery-evidence-missing"}
	seen := 0
	for _, n := range c.Negatives {
		if !containsHistoryName(names, n.ID) {
			continue
		}
		seen++
		t.Run(n.ID, func(t *testing.T) {
			proposal := historyTestObject(t, []byte(n.Transcript.Proposal))
			record := historyTestObject(t, []byte(n.Transcript.Record))
			value := func(o map[string]json.RawMessage, f string) string {
				var s string
				if err := json.Unmarshal(o[f], &s); err != nil {
					t.Fatal(err)
				}
				return s
			}
			role := value(proposal, "proposal_signer_role")
			spki := "new_spki"
			if role == "old" {
				spki = "target_spki"
			}
			if !registryVerifySignature(value(proposal, spki), value(proposal, "proposal_signature"), "YTA-REGISTRY-PROPOSAL-V1\x00", n.Transcript.UnsignedProposal) {
				t.Fatal("semantic fixture fails earlier proposal signature")
			}
			for _, pair := range []struct{ field, key, domain string }{{"old_signature", "target_spki", "YTA-REGISTRY-RECORD-OLD-V1\x00"}, {"new_signature", "new_spki", "YTA-REGISTRY-RECORD-NEW-V1\x00"}} {
				if string(record[pair.field]) == "null" {
					continue
				}
				if !registryVerifySignature(value(record, pair.key), value(record, pair.field), pair.domain, n.Transcript.FinalBody) {
					t.Fatal("semantic fixture fails earlier final signature")
				}
			}
		})
	}
	if seen != len(names) {
		t.Fatal("semantic control disappeared")
	}
}

func TestSuppliedRegistryCeremonyPhasesPresenceAndRedaction(t *testing.T) {
	c := readRegistryCorpus(t)
	positives := registryPositiveMap(t, c)
	var wrong registryNegative
	for _, n := range c.Negatives {
		if n.ID == "signature-proposal-wrong-key" {
			wrong = n
		}
	}
	first := ceremonyTestInput(wrong.Transcript)
	prefix := ceremonyTestPrefix(t, wrong, c)
	ceremonyTestFailure(t, prefix, first, "verification")
	for _, test := range []struct {
		name, stage string
		change      func(*SuppliedRegistryCeremony)
	}{
		{"later-encoding-beats-signature", "encoding", func(x *SuppliedRegistryCeremony) { x.Record = append(x.Record, '\n') }},
		{"later-grammar-beats-signature", "grammar", func(x *SuppliedRegistryCeremony) {
			x.Record = bytes.Replace(x.Record, []byte(`"registry_revision":2`), []byte(`"registry_revision":257`), 1)
		}},
		{"later-bounds-beats-encoding", "bounds", func(x *SuppliedRegistryCeremony) {
			x.Request = []byte("bad")
			x.Record = bytes.Repeat([]byte{'x'}, 4353)
		}},
		{"later-encoding-beats-grammar", "encoding", func(x *SuppliedRegistryCeremony) {
			x.Request = bytes.Replace(x.Request, []byte(`"schema_version":1`), []byte(`"schema_version":0`), 1)
			x.Record = append(x.Record, '\n')
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := ceremonyTestInput(wrong.Transcript)
			test.change(&input)
			ceremonyTestFailure(t, prefix, input, test.stage)
		})
	}
	enroll := positives["enroll1"].registryTranscript
	recover := positives["recover-active3"].registryTranscript
	input := ceremonyTestInput(enroll)
	input.RecoveryEvidence = []byte{}
	ceremonyTestFailure(t, nil, input, "bounds")
	input = ceremonyTestInput(recover)
	input.RecoveryEvidence = nil
	ceremonyTestFailure(t, historyTestRecords(t, "enroll1", "rotate2"), input, "verification")
	input = ceremonyTestInput(enroll)
	input.RecoveryEvidence = []byte(*recover.RecoveryEvidence)
	ceremonyTestFailure(t, nil, input, "verification")
	for _, raw := range [][]byte{[]byte(`{"UNTRUSTED_SENTINEL":0,"UNTRUSTED_SENTINEL":1}`), bytes.Replace([]byte(enroll.Request), []byte(`"expected_registry_revision":0`), []byte(`"expected_registry_revision":"UNTRUSTED_SENTINEL"`), 1), bytes.Replace([]byte(enroll.Request), []byte(`"expected_registry_revision":0`), []byte(`"expected_registry_revision":999999999999999999999999999999999999999`), 1)} {
		input = ceremonyTestInput(enroll)
		input.Request = raw
		ceremonyTestFailure(t, nil, input, "encoding")
	}
	var probe struct {
		Revision uint64 `json:"expected_registry_revision"`
	}
	err := json.Unmarshal([]byte(`{"expected_registry_revision":999999999999999999999999999999999999999}`), &probe)
	if err == nil || !strings.Contains(err.Error(), "999999999") {
		t.Fatal("numeric positive control did not reach decoder diagnostic")
	}
	d := json.NewDecoder(strings.NewReader(`{"UNTRUSTED_SENTINEL":0}`))
	d.DisallowUnknownFields()
	err = d.Decode(&probe)
	if err == nil || !strings.Contains(err.Error(), "UNTRUSTED_SENTINEL") {
		t.Fatal("unknown-field positive control did not reach decoder diagnostic")
	}
	input = ceremonyTestInput(enroll)
	ceremonyTestFailure(t, make([][]byte, 256), input, "bounds")
}

func ceremonyTestEncode(o map[string]json.RawMessage, fields string) []byte {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, f := range strings.Fields(fields) {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(`"` + f + `":`)
		out.Write(o[f])
	}
	out.WriteByte('}')
	return out.Bytes()
}

func ceremonyTestSignature(t *testing.T, message []byte, key *ecdsa.PrivateKey) json.RawMessage {
	t.Helper()
	h := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	if !ecdsa.Verify(&key.PublicKey, h[:], r, s) {
		t.Fatal("synthetic proposal signature invalid")
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return historyTestString(base64.RawURLEncoding.EncodeToString(der))
}

// Rebuild independently from literal schemas and standard crypto, never calling
// a production encoder or the full transcript verdict oracle.
func ceremonyTestRebuild(t *testing.T, c SuppliedRegistryCeremony, target, fresh *ecdsa.PrivateKey) SuppliedRegistryCeremony {
	t.Helper()
	q := historyTestObject(t, c.Request)
	p := historyTestObject(t, c.SignedProposal)
	a := historyTestObject(t, c.Acceptance)
	r := historyTestObject(t, c.Record)
	for _, o := range []map[string]json.RawMessage{p, a, r} {
		for _, field := range []string{"transition_kind", "previous_record_sha256", "artifact_descriptor_sha256", "target_generation", "new_generation"} {
			o[field] = q[field]
		}
	}
	request := ceremonyTestEncode(q, ceremonyTestRequestFields)
	var text string
	if err := json.Unmarshal(q["challenge"], &text); err != nil {
		t.Fatal(err)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []map[string]json.RawMessage{p, a, r} {
		o["request_sha256"] = historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-REQUEST-V1\x00"), request...)))
		o["challenge_sha256"] = historyTestString(historyTestHash(challenge))
		o["registry_revision"] = r["registry_revision"]
	}
	p["expires_at"] = q["expires_at"]
	a["expires_at"] = q["expires_at"]
	r["requested_at"] = q["requested_at"]
	r["accepted_at"] = a["accepted_at"]
	for _, field := range []string{"generation", "key_id", "key_tag", "spki", "fingerprint_sha256"} {
		for _, prefix := range []string{"target_", "new_"} {
			p[prefix+field] = r[prefix+field]
		}
	}
	signer := fresh
	role := "new"
	if string(q["transition_kind"]) == `"revoke"` {
		signer = target
		role = "old"
	}
	p["proposal_signer_role"] = historyTestString(role)
	unsigned := ceremonyTestEncode(p, ceremonyTestProposalFields)
	p["proposal_signature"] = ceremonyTestSignature(t, append([]byte("YTA-REGISTRY-PROPOSAL-V1\x00"), unsigned...), signer)
	proposal := ceremonyTestEncode(p, ceremonyTestProposalFields+" proposal_signature")
	for _, o := range []map[string]json.RawMessage{a, r} {
		o["proposal_sha256"] = historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-PROPOSAL-DIGEST-V1\x00"), proposal...)))
	}
	acceptance := ceremonyTestEncode(a, ceremonyTestAcceptanceFields)
	r["acceptance_sha256"] = historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-ACCEPTANCE-V1\x00"), acceptance...)))
	oldSigner := target
	if string(q["transition_kind"]) == `"enroll"` || string(q["transition_kind"]) == `"recover"` {
		oldSigner = nil
	}
	record := historyTestSign(t, r, oldSigner, fresh)
	return SuppliedRegistryCeremony{Request: request, RecoveryEvidence: c.RecoveryEvidence, UnsignedProposal: unsigned, SignedProposal: proposal, Acceptance: acceptance, FinalBody: historyTestEncode(r, true), Record: record}
}

func TestSuppliedRegistryCeremonyUnsignedProjectionEquality(t *testing.T) {
	positive := registryPositiveMap(t, readRegistryCorpus(t))["enroll1"].registryTranscript
	candidate := ceremonyTestInput(positive)
	key, tuple := historyTestKey(t, 1)
	unsigned := historyTestObject(t, candidate.UnsignedProposal)
	unsigned["proposed_at"] = historyTestString("2026-09-01T12:00:02Z")
	candidate.UnsignedProposal = ceremonyTestEncode(unsigned, ceremonyTestProposalFields)
	proposal := historyTestObject(t, candidate.SignedProposal)
	proposal["proposal_signature"] = ceremonyTestSignature(t, append([]byte("YTA-REGISTRY-PROPOSAL-V1\x00"), candidate.UnsignedProposal...), key)
	candidate.SignedProposal = ceremonyTestEncode(proposal, ceremonyTestProposalFields+" proposal_signature")
	var signature string
	if err := json.Unmarshal(proposal["proposal_signature"], &signature); err != nil {
		t.Fatal(err)
	}
	if !registryVerifySignature(tuple.SPKI, signature, "YTA-REGISTRY-PROPOSAL-V1\x00", string(candidate.UnsignedProposal)) {
		t.Fatal("projection control's proposal signature is not valid over supplied unsigned bytes")
	}
	if registryVerifySignature(tuple.SPKI, signature, "YTA-REGISTRY-PROPOSAL-V1\x00", positive.UnsignedProposal) {
		t.Fatal("projection control still signs original projection")
	}
	acceptance := historyTestObject(t, candidate.Acceptance)
	record := historyTestObject(t, candidate.Record)
	proposalDigest := historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-PROPOSAL-DIGEST-V1\x00"), candidate.SignedProposal...)))
	acceptance["proposal_sha256"], record["proposal_sha256"] = proposalDigest, proposalDigest
	candidate.Acceptance = ceremonyTestEncode(acceptance, ceremonyTestAcceptanceFields)
	record["acceptance_sha256"] = historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-ACCEPTANCE-V1\x00"), candidate.Acceptance...)))
	candidate.Record = historyTestSign(t, record, nil, key)
	candidate.FinalBody = historyTestEncode(record, true)
	// Repair only downstream digest bindings: rebuilding the whole ceremony
	// would erase the deliberately different redundant unsigned projection.
	ceremonyTestFailure(t, nil, candidate, "verification")
}

func TestSuppliedRegistryCeremonyFinalBodyProjectionEquality(t *testing.T) {
	positive := registryPositiveMap(t, readRegistryCorpus(t))["enroll1"].registryTranscript
	candidate := ceremonyTestInput(positive)
	if _, err := VerifySuppliedRegistryCeremony(nil, candidate); err != nil {
		t.Fatal(err)
	}
	candidate.FinalBody = bytes.Replace(candidate.FinalBody, []byte(`"revokes_all_prior":false`), []byte(`"revokes_all_prior":true`), 1)
	if bytes.Equal(candidate.FinalBody, []byte(positive.FinalBody)) {
		t.Fatal("projection mutation not exercised")
	}
	// The complete signed record and all digest bindings stay unchanged.
	ceremonyTestFailure(t, nil, candidate, "verification")
}

func TestSuppliedRegistryCeremonyMaximalCandidateAndDescriptorUpgrade(t *testing.T) {
	positives := registryPositiveMap(t, readRegistryCorpus(t))
	base := historyTestObject(t, []byte(positives["enroll1"].Record))
	var prefix [][]byte
	var old *ecdsa.PrivateKey
	var previous SuppliedRegistryKey
	for revision := 1; revision <= 255; revision++ {
		fresh, tuple := historyTestKey(t, revision)
		r := historyTestObject(t, historyTestEncode(base, false))
		r["registry_revision"] = json.RawMessage(fmt.Sprint(revision))
		for field, value := range map[string]string{"new_generation": tuple.Generation, "new_key_id": tuple.KeyID, "new_key_tag": tuple.KeyTag, "new_spki": tuple.SPKI, "new_fingerprint_sha256": tuple.FingerprintSHA256} {
			r[field] = historyTestString(value)
		}
		if revision > 1 {
			for field, value := range map[string]string{"transition_kind": "rotate", "previous_record_sha256": historyTestHash(prefix[len(prefix)-1]), "target_generation": previous.Generation, "target_key_id": previous.KeyID, "target_key_tag": previous.KeyTag, "target_spki": previous.SPKI, "target_fingerprint_sha256": previous.FingerprintSHA256, "target_previous_status": "active", "target_new_status": "retained"} {
				r[field] = historyTestString(value)
			}
		}
		prefix = append(prefix, historyTestSign(t, r, old, fresh))
		old, previous = fresh, tuple
	}
	fresh, tuple := historyTestKey(t, 256)
	candidate := ceremonyTestInput(positives["rotate2"].registryTranscript)
	q := historyTestObject(t, candidate.Request)
	r := historyTestObject(t, candidate.Record)
	q["expected_registry_revision"] = json.RawMessage("255")
	r["registry_revision"] = json.RawMessage("256")
	for field, value := range map[string]string{"previous_record_sha256": historyTestHash(prefix[254]), "target_generation": previous.Generation, "new_generation": tuple.Generation, "artifact_descriptor_sha256": strings.Repeat("b", 64)} {
		q[field] = historyTestString(value)
	}
	for field, value := range map[string]string{"target_key_id": previous.KeyID, "target_key_tag": previous.KeyTag, "target_spki": previous.SPKI, "target_fingerprint_sha256": previous.FingerprintSHA256, "new_key_id": tuple.KeyID, "new_key_tag": tuple.KeyTag, "new_spki": tuple.SPKI, "new_fingerprint_sha256": tuple.FingerprintSHA256} {
		r[field] = historyTestString(value)
	}
	candidate.Request = ceremonyTestEncode(q, ceremonyTestRequestFields)
	candidate.Record = historyTestEncode(r, false)
	candidate = ceremonyTestRebuild(t, candidate, old, fresh)
	result, err := VerifySuppliedRegistryCeremony(prefix, candidate)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, present := result.SuppliedTipDescriptorSHA256()
	if result.SuppliedRevision() != 256 || len(result.Keys()) != 256 || result.SuppliedTipSHA256() != historyTestHash(candidate.Record) || !present || descriptor != strings.Repeat("b", 64) {
		t.Fatal("maximal candidate differs")
	}
	for i, key := range result.Keys() {
		want := "retained"
		if i == 255 {
			want = "active"
		}
		if key.Status != want {
			t.Fatal("maximal candidate status differs")
		}
	}
	ceremonyTestFailure(t, append(prefix, candidate.Record), candidate, "bounds")
	// A descriptor may change between events, but all objects of this event
	// must agree. Re-sign the record after changing acceptance's descriptor.
	a := historyTestObject(t, candidate.Acceptance)
	a["artifact_descriptor_sha256"] = historyTestString(strings.Repeat("c", 64))
	candidate.Acceptance = ceremonyTestEncode(a, ceremonyTestAcceptanceFields)
	r = historyTestObject(t, candidate.Record)
	r["acceptance_sha256"] = historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-ACCEPTANCE-V1\x00"), candidate.Acceptance...)))
	candidate.Record = historyTestSign(t, r, old, fresh)
	candidate.FinalBody = historyTestEncode(r, true)
	ceremonyTestFailure(t, prefix, candidate, "verification")
}

func TestSuppliedRegistryCeremonySignedCalendarAndExpiry(t *testing.T) {
	positive := registryPositiveMap(t, readRegistryCorpus(t))["enroll1"].registryTranscript
	key, _ := historyTestKey(t, 1)
	for _, test := range []struct{ name, requested, proposed, accepted, committed, expires, stage string }{
		{"year-zero-leap", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", "0000-02-29T12:00:01Z", ""},
		{"year-one", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:01Z", ""},
		{"year-max", "9999-12-31T23:59:58Z", "9999-12-31T23:59:58Z", "9999-12-31T23:59:58Z", "9999-12-31T23:59:58Z", "9999-12-31T23:59:59Z", ""},
		{"ttl-300-commit-299", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:04:59Z", "2000-01-01T00:05:00Z", ""},
		{"ttl-301", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:05:01Z", "verification"},
		{"large-span", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "verification"},
		{"invalid-century-leap", "1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z", "1500-02-29T00:00:01Z", "grammar"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := ceremonyTestInput(positive)
			q, p, a, r := historyTestObject(t, candidate.Request), historyTestObject(t, candidate.SignedProposal), historyTestObject(t, candidate.Acceptance), historyTestObject(t, candidate.Record)
			q["requested_at"], q["expires_at"] = historyTestString(test.requested), historyTestString(test.expires)
			p["proposed_at"], a["accepted_at"], r["committed_at"] = historyTestString(test.proposed), historyTestString(test.accepted), historyTestString(test.committed)
			candidate.Request, candidate.SignedProposal, candidate.Acceptance, candidate.Record = ceremonyTestEncode(q, ceremonyTestRequestFields), ceremonyTestEncode(p, ceremonyTestProposalFields+" proposal_signature"), ceremonyTestEncode(a, ceremonyTestAcceptanceFields), historyTestEncode(r, false)
			candidate = ceremonyTestRebuild(t, candidate, nil, key)
			if test.stage != "" {
				ceremonyTestFailure(t, nil, candidate, test.stage)
				return
			}
			result, err := VerifySuppliedRegistryCeremony(nil, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if result.SuppliedRevision() != 1 || result.SuppliedTipSHA256() != historyTestHash(candidate.Record) {
				t.Fatal("calendar result differs")
			}
		})
	}
}

type ceremonyTestBindingMutation struct {
	name, fixture, object, field string
	value                        json.RawMessage
}

// Each mutation runs after its upstream hashes have been repaired. Literal
// bindings are never synchronized: doing so would erase the mismatch under test.
func ceremonyTestStagedBinding(t *testing.T, original SuppliedRegistryCeremony, mutation ceremonyTestBindingMutation, target, fresh *ecdsa.PrivateKey) SuppliedRegistryCeremony {
	t.Helper()
	q, p := historyTestObject(t, original.Request), historyTestObject(t, original.SignedProposal)
	a, r := historyTestObject(t, original.Acceptance), historyTestObject(t, original.Record)
	change := func(stage string, object map[string]json.RawMessage) {
		if mutation.object == stage {
			if bytes.Equal(object[mutation.field], mutation.value) {
				t.Fatal("binding mutation did not change its field")
			}
			object[mutation.field] = mutation.value
		}
	}
	change("request", q)
	request := ceremonyTestEncode(q, ceremonyTestRequestFields)
	requestDigest := historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-REQUEST-V1\x00"), request...)))
	for _, object := range []map[string]json.RawMessage{p, a, r} {
		object["request_sha256"] = requestDigest
	}
	var evidence []byte
	if original.RecoveryEvidence != nil {
		e := historyTestObject(t, original.RecoveryEvidence)
		e["request_sha256"] = requestDigest
		change("evidence", e)
		evidence = ceremonyTestEncode(e, ceremonyTestEvidenceFields)
		digest := historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-RECOVERY-EVIDENCE-V1\x00"), evidence...)))
		for _, object := range []map[string]json.RawMessage{p, a, r} {
			object["recovery_evidence_sha256"] = digest
		}
	}
	change("proposal", p)
	unsigned := ceremonyTestEncode(p, ceremonyTestProposalFields)
	signer := fresh
	if string(p["proposal_signer_role"]) == `"old"` {
		signer = target
	}
	p["proposal_signature"] = ceremonyTestSignature(t, append([]byte("YTA-REGISTRY-PROPOSAL-V1\x00"), unsigned...), signer)
	proposal := ceremonyTestEncode(p, ceremonyTestProposalFields+" proposal_signature")
	proposalDigest := historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-PROPOSAL-DIGEST-V1\x00"), proposal...)))
	a["proposal_sha256"], r["proposal_sha256"] = proposalDigest, proposalDigest
	change("acceptance", a)
	acceptance := ceremonyTestEncode(a, ceremonyTestAcceptanceFields)
	r["acceptance_sha256"] = historyTestString(historyTestHash(append([]byte("YTA-REGISTRY-ACCEPTANCE-V1\x00"), acceptance...)))
	change("body", r)
	oldSigner := target
	if string(q["transition_kind"]) == `"enroll"` || string(q["transition_kind"]) == `"recover"` {
		oldSigner = nil
	}
	record := historyTestSign(t, r, oldSigner, fresh)
	candidate := SuppliedRegistryCeremony{Request: request, RecoveryEvidence: evidence, UnsignedProposal: unsigned, SignedProposal: proposal, Acceptance: acceptance, FinalBody: historyTestEncode(r, true), Record: record}
	if mutation.object != "" {
		objects := map[string][]byte{"request": request, "evidence": evidence, "proposal": proposal, "acceptance": acceptance, "body": candidate.FinalBody}
		if !bytes.Equal(historyTestObject(t, objects[mutation.object])[mutation.field], mutation.value) {
			t.Fatal("downstream repair erased the binding mutation")
		}
	}
	// Verify the complete transmitted signatures with standard crypto, separately
	// from the verifier under test, including old-role revocation proposals.
	for _, signature := range []struct {
		value  json.RawMessage
		body   []byte
		domain string
		key    *ecdsa.PrivateKey
	}{
		{p["proposal_signature"], unsigned, "YTA-REGISTRY-PROPOSAL-V1\x00", signer},
		{r["old_signature"], candidate.FinalBody, "YTA-REGISTRY-RECORD-OLD-V1\x00", oldSigner},
		{r["new_signature"], candidate.FinalBody, "YTA-REGISTRY-RECORD-NEW-V1\x00", fresh},
	} {
		if signature.key == nil {
			if string(signature.value) != "null" {
				t.Fatal("unexpected signature in binding control")
			}
			continue
		}
		var encoded string
		if err := json.Unmarshal(signature.value, &encoded); err != nil {
			t.Fatal(err)
		}
		der, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(append([]byte(signature.domain), signature.body...))
		if !ecdsa.VerifyASN1(&signature.key.PublicKey, digest[:], der) {
			t.Fatal("binding control has an invalid transmitted signature")
		}
	}
	return candidate
}

func TestSuppliedRegistryCeremonySignedBindings(t *testing.T) {
	positives := registryPositiveMap(t, readRegistryCorpus(t))
	fixtures := []struct {
		name          string
		target, fresh int
		generations   []int
		statuses      []string
	}{
		{"enroll1", 0, 1, []int{1}, []string{"active"}},
		{"rotate2", 1, 2, []int{1, 2}, []string{"retained", "active"}},
		{"revoke3", 2, 0, []int{1, 2}, []string{"retained", "revoked"}},
		{"recover-active3", 2, 3, []int{1, 2, 3}, []string{"revoked", "revoked", "active"}},
		{"recover-disabled4", 0, 4, []int{1, 2, 4}, []string{"revoked", "revoked", "active"}},
	}
	build := func(t *testing.T, name string, mutation ceremonyTestBindingMutation) ([][]byte, SuppliedRegistryCeremony) {
		t.Helper()
		for _, fixture := range fixtures {
			if fixture.name != name {
				continue
			}
			var target, fresh *ecdsa.PrivateKey
			if fixture.target != 0 {
				target, _ = historyTestKey(t, fixture.target)
			}
			if fixture.fresh != 0 {
				fresh, _ = historyTestKey(t, fixture.fresh)
			}
			positive := positives[name]
			return historyTestRecords(t, positive.Prefix...), ceremonyTestStagedBinding(t, ceremonyTestInput(positive.registryTranscript), mutation, target, fresh)
		}
		t.Fatalf("unknown binding fixture %s", name)
		return nil, SuppliedRegistryCeremony{}
	}
	for _, fixture := range fixtures {
		t.Run("control-"+fixture.name, func(t *testing.T) {
			prefix, candidate := build(t, fixture.name, ceremonyTestBindingMutation{})
			result, err := VerifySuppliedRegistryCeremony(prefix, candidate)
			if err != nil {
				t.Fatal(err)
			}
			var expected []SuppliedRegistryKey
			for i, generation := range fixture.generations {
				_, key := historyTestKey(t, generation)
				key.Status = fixture.statuses[i]
				expected = append(expected, key)
			}
			if result.SuppliedRevision() != len(prefix)+1 || result.SuppliedTipSHA256() != historyTestHash(candidate.Record) || !reflect.DeepEqual(result.Keys(), expected) {
				t.Fatal("rebuilt binding control changed the expected history")
			}
		})
	}
	wrongDigest := historyTestString(strings.Repeat("b", 64))
	_, other := historyTestKey(t, 1)
	generation, tag := historyTestString(other.Generation), historyTestString(other.KeyTag)
	for _, mutation := range []ceremonyTestBindingMutation{
		{"recovery-request-digest", "recover-active3", "evidence", "request_sha256", wrongDigest},
		{"recovery-challenge-digest", "recover-active3", "evidence", "challenge_sha256", wrongDigest},
		{"recovery-revision", "recover-active3", "evidence", "registry_revision", json.RawMessage("1")},
		{"recovery-predecessor", "recover-active3", "evidence", "previous_record_sha256", wrongDigest},
		{"recovery-descriptor", "recover-active3", "evidence", "artifact_descriptor_sha256", wrongDigest},
		{"recovery-active-target-generation", "recover-active3", "evidence", "target_generation", generation},
		{"recovery-active-target-tag", "recover-active3", "evidence", "target_key_tag", tag},
		{"recovery-active-eligibility", "recover-active3", "evidence", "eligibility", historyTestString("registry_disabled")},
		{"recovery-active-lookup", "recover-active3", "evidence", "key_lookup_result", historyTestString("not_attempted:registry_disabled")},
		{"recovery-active-continuity", "recover-active3", "evidence", "continuity_probe_result", historyTestString("not_attempted:no_active_generation")},
		{"recovery-disabled-target-generation", "recover-disabled4", "evidence", "target_generation", generation},
		{"recovery-disabled-target-tag", "recover-disabled4", "evidence", "target_key_tag", tag},
		{"recovery-disabled-eligibility", "recover-disabled4", "evidence", "eligibility", historyTestString("active_key_item_not_found")},
		{"recovery-disabled-lookup", "recover-disabled4", "evidence", "key_lookup_result", historyTestString("errSecItemNotFound:-25300")},
		{"recovery-disabled-continuity", "recover-disabled4", "evidence", "continuity_probe_result", historyTestString("not_attempted:no_key")},
		{"recovery-probe-before-request", "recover-active3", "evidence", "probed_at", historyTestString("2026-09-01T11:59:59Z")},
		{"recovery-probe-after-proposal", "recover-active3", "evidence", "probed_at", historyTestString("2026-09-01T12:00:02Z")},
		{"acceptance-kind", "rotate2", "acceptance", "transition_kind", historyTestString("enroll")},
		{"acceptance-request-digest", "rotate2", "acceptance", "request_sha256", wrongDigest},
		{"acceptance-challenge", "rotate2", "acceptance", "challenge_sha256", wrongDigest},
		{"acceptance-revision", "rotate2", "acceptance", "registry_revision", json.RawMessage("1")},
		{"acceptance-predecessor", "rotate2", "acceptance", "previous_record_sha256", wrongDigest},
		{"acceptance-target-generation", "rotate2", "acceptance", "target_generation", json.RawMessage("null")},
		{"acceptance-new-generation", "rotate2", "acceptance", "new_generation", json.RawMessage("null")},
		{"proposal-kind", "rotate2", "proposal", "transition_kind", historyTestString("enroll")},
		{"proposal-challenge", "rotate2", "proposal", "challenge_sha256", wrongDigest},
		// Revocation has no fresh tuple whose grammar already fixes the revision.
		{"proposal-revision", "revoke3", "proposal", "registry_revision", json.RawMessage("1")},
		{"body-challenge", "rotate2", "body", "challenge_sha256", wrongDigest},
		{"proposal-recovery-digest", "recover-active3", "proposal", "recovery_evidence_sha256", wrongDigest},
		{"acceptance-recovery-digest", "recover-active3", "acceptance", "recovery_evidence_sha256", wrongDigest},
		{"body-recovery-digest", "recover-active3", "body", "recovery_evidence_sha256", wrongDigest},
		{"acceptance-proposal-digest", "rotate2", "acceptance", "proposal_sha256", wrongDigest},
		{"body-proposal-digest", "rotate2", "body", "proposal_sha256", wrongDigest},
		{"request-revision", "rotate2", "request", "expected_registry_revision", json.RawMessage("0")},
		{"request-predecessor", "rotate2", "request", "previous_record_sha256", wrongDigest},
		{"proposal-expiry", "rotate2", "proposal", "expires_at", historyTestString("2026-09-01T12:04:59Z")},
		{"acceptance-expiry", "rotate2", "acceptance", "expires_at", historyTestString("2026-09-01T12:04:59Z")},
		{"body-requested-at", "rotate2", "body", "requested_at", historyTestString("2026-09-01T12:00:01Z")},
		{"body-accepted-at", "rotate2", "body", "accepted_at", historyTestString("2026-09-01T12:00:03Z")},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			prefix, candidate := build(t, mutation.fixture, mutation)
			if mutation.object == "request" {
				if _, err := VerifySuppliedRegistryHistory(append(prefix, candidate.Record)); err != nil {
					t.Fatalf("request-only mismatch changed the valid candidate history: %v", err)
				}
			}
			ceremonyTestFailure(t, prefix, candidate, "verification")
		})
	}
	for _, endpoint := range []struct{ name, time string }{
		{"recovery-probe-at-request", "2026-09-01T12:00:00Z"},
		{"recovery-probe-at-proposal", "2026-09-01T12:00:01Z"},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			mutation := ceremonyTestBindingMutation{object: "evidence", field: "probed_at", value: historyTestString(endpoint.time)}
			// The proposal endpoint equals the pinned evidence time already.
			if endpoint.name == "recovery-probe-at-proposal" {
				mutation = ceremonyTestBindingMutation{}
			}
			prefix, candidate := build(t, "recover-active3", mutation)
			if !bytes.Equal(historyTestObject(t, candidate.RecoveryEvidence)["probed_at"], historyTestString(endpoint.time)) {
				t.Fatal("probe endpoint control did not exercise the requested boundary")
			}
			if _, err := VerifySuppliedRegistryCeremony(prefix, candidate); err != nil {
				t.Fatal(err)
			}
		})
	}
}
