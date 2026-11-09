package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

// Independent fixture construction only: neither the production decoder nor
// the transcript oracle determines field order, signatures, or expected state.
const historyTestFields = "schema_version record_type transition_kind registry_revision previous_record_sha256 request_sha256 proposal_sha256 acceptance_sha256 challenge_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 requested_at accepted_at committed_at target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 target_previous_status target_new_status new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 new_status revokes_all_prior old_signature new_signature"

func historyTestHash(raw []byte) string {
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}

func historyTestObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func historyTestEncode(object map[string]json.RawMessage, body bool) []byte {
	fields := strings.Fields(historyTestFields)
	if body {
		fields = fields[:28]
	}
	var out bytes.Buffer
	out.WriteByte('{')
	for i, field := range fields {
		if i != 0 {
			out.WriteByte(',')
		}
		out.WriteString(`"` + field + `":`)
		out.Write(object[field])
	}
	out.WriteByte('}')
	return out.Bytes()
}

func historyTestString(value string) json.RawMessage { return json.RawMessage(`"` + value + `"`) }

func historyTestKey(t *testing.T, revision int) (*ecdsa.PrivateKey, SuppliedRegistryKey) {
	t.Helper()
	// Public synthetic scalars are intentionally unsafe and never enrolled.
	d := big.NewInt(int64(revision))
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("%032x", revision)
	return key, SuppliedRegistryKey{Generation: fmt.Sprintf("YTAG-%020d", revision), KeyID: id,
		KeyTag: "io.github.abigotado.youtrack-agent.approval.signing.v1/" + id,
		SPKI:   base64.RawURLEncoding.EncodeToString(der), FingerprintSHA256: historyTestHash(der), Status: "active"}
}

func historyTestSign(t *testing.T, object map[string]json.RawMessage, old, fresh *ecdsa.PrivateKey) []byte {
	t.Helper()
	body := historyTestEncode(object, true)
	for _, signer := range []struct {
		field, domain string
		key           *ecdsa.PrivateKey
	}{
		{"old_signature", "YTA-REGISTRY-RECORD-OLD-V1\x00", old},
		{"new_signature", "YTA-REGISTRY-RECORD-NEW-V1\x00", fresh},
	} {
		object[signer.field] = json.RawMessage("null")
		if signer.key == nil {
			continue
		}
		d := sha256.Sum256(append([]byte(signer.domain), body...))
		r, s, err := ecdsa.Sign(rand.Reader, signer.key, d[:])
		if err != nil {
			t.Fatal(err)
		}
		n := elliptic.P256().Params().N
		if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
			s.Sub(n, s)
		}
		if !ecdsa.Verify(&signer.key.PublicKey, d[:], r, s) {
			t.Fatal("synthetic semantic record has invalid signature")
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatal(err)
		}
		object[signer.field] = historyTestString(base64.RawURLEncoding.EncodeToString(der))
	}
	return historyTestEncode(object, false)
}

func historyTestRecords(t *testing.T, names ...string) [][]byte {
	t.Helper()
	positives := registryPositiveMap(t, readRegistryCorpus(t))
	var records [][]byte
	for _, name := range names {
		records = append(records, []byte(positives[name].Record))
	}
	return records
}

func historyTestFailure(t *testing.T, records [][]byte, stage string) {
	t.Helper()
	result, err := VerifySuppliedRegistryHistory(records)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeUsage || typed.Reason != "REGISTRY_HISTORY_INVALID" {
		t.Fatalf("wrong refusal: %v", err)
	}
	if typed.Message != "supplied registry history failed "+stage+" validation" {
		t.Fatalf("stage: %q", typed.Message)
	}
	if errors.Unwrap(typed) != nil {
		t.Fatal("refusal exposes underlying diagnostics")
	}
	_, descriptor := result.SuppliedTipDescriptorSHA256()
	if result.SuppliedRevision() != 0 || result.SuppliedTipSHA256() != "" || descriptor || len(result.Keys()) != 0 {
		t.Fatal("refusal returned partial replay")
	}
	if typed.Hint == "" || strings.Contains(typed.Hint, "UNTRUSTED_SENTINEL") {
		t.Fatal("unsafe or absent recovery hint")
	}
}

func TestSuppliedRegistryHistoryPinnedPrefixes(t *testing.T) {
	hashes := map[string]string{
		"enroll1":           "c8154cd7d2a72f7e23dcbfa9f52d1b9ca97afad557c6becedf9eaf7a772db16b",
		"rotate2":           "4c4394736cf2e1e619e5cdef3a45104b9dddd344d5febff6061d4bd37a877f5c",
		"revoke3":           "8fc41f67fcc9b80d7eac1cf16f2e4bb581b753e2c4f3c2a87bc2125247ad3f75",
		"recover-disabled4": "083686890e6a8b2fa969143f74d5a147415aaa125df7917344da9a636fa15f7c",
		"recover-active3":   "6d1f7ea55313a4ffd01cd5c2ddb732dcf871b2fe722699779e83b1b0b33453e6",
	}
	for _, scenario := range []struct {
		names       []string
		statuses    [][]string
		generations [][]int
	}{
		{[]string{"enroll1", "rotate2", "revoke3", "recover-disabled4"}, [][]string{{"active"}, {"retained", "active"}, {"retained", "revoked"}, {"revoked", "revoked", "active"}}, [][]int{{1}, {1, 2}, {1, 2}, {1, 2, 4}}},
		{[]string{"enroll1", "rotate2", "recover-active3"}, [][]string{{"active"}, {"retained", "active"}, {"revoked", "revoked", "active"}}, [][]int{{1}, {1, 2}, {1, 2, 3}}},
	} {
		records := historyTestRecords(t, scenario.names...)
		for count := 0; count <= len(records); count++ {
			t.Run(fmt.Sprintf("%s/prefix-%d", scenario.names[len(scenario.names)-1], count), func(t *testing.T) {
				result, err := VerifySuppliedRegistryHistory(records[:count])
				if err != nil {
					t.Fatal(err)
				}
				if result.SuppliedRevision() != count {
					t.Fatal("revision differs")
				}
				descriptor, present := result.SuppliedTipDescriptorSHA256()
				if count == 0 {
					if present || descriptor != "" || result.SuppliedTipSHA256() != strings.Repeat("0", 64) || len(result.Keys()) != 0 {
						t.Fatal("empty history differs")
					}
					return
				}
				if !present || descriptor != strings.Repeat("a", 64) || result.SuppliedTipSHA256() != hashes[scenario.names[count-1]] {
					t.Fatal("tip binding differs")
				}
				var expected []SuppliedRegistryKey
				for i, generation := range scenario.generations[count-1] {
					_, k := historyTestKey(t, generation)
					k.Status = scenario.statuses[count-1][i]
					expected = append(expected, k)
				}
				if !reflect.DeepEqual(result.Keys(), expected) {
					t.Fatal("independently derived key tuples/statuses differ")
				}
			})
		}
	}
}

func TestSuppliedRegistryHistoryApplicableCorpusNegatives(t *testing.T) {
	c := readRegistryCorpus(t)
	positives := registryPositiveMap(t, c)
	stages := map[string]string{
		"encoding-record-missing": "encoding", "encoding-record-duplicate": "encoding", "encoding-record-unknown": "encoding", "encoding-record-reordered": "encoding", "encoding-record-escaped": "encoding", "encoding-record-whitespace": "encoding", "encoding-record-trailing": "encoding", "encoding-record-nonobject": "encoding", "size-record-over": "bounds", "size-record-at": "encoding",
		"digest-predecessor": "replay", "signature-old-wrong-domain": "replay", "signature-new-wrong-domain": "replay", "signature-missing-old": "replay", "signature-missing-new": "replay",
		"state-revoke-all-false": "replay", "state-wrong-target": "replay", "state-key-reuse": "replay", "state-revision-gap": "replay", "recovery-invalid-prefix-signature": "replay", "prefix-time-reversed": "replay", "prefix-recovery-digest-unexpected": "replay", "prefix-recovery-digest-missing": "replay",
		"grammar-record-revision--1": "encoding", "grammar-record-revision-0": "grammar", "grammar-record-revision-257": "grammar", "grammar-generation-revision": "grammar", "grammar-time-fraction": "grammar", "recovery-evidence-missing": "replay", "time-commit-at-expiry": "replay",
	}
	seen := make(map[string]bool)
	for _, negative := range c.Negatives {
		stage, applicable := stages[negative.ID]
		if !applicable {
			continue
		}
		seen[negative.ID] = true
		t.Run(negative.ID, func(t *testing.T) {
			prefix := registryPrefix(t, negative.Prefix, positives)
			if negative.PrefixRecords != nil {
				prefix = *negative.PrefixRecords
			}
			var records [][]byte
			for _, raw := range prefix {
				records = append(records, []byte(raw))
			}
			records = append(records, []byte(negative.Transcript.Record))
			historyTestFailure(t, records, stage)
		})
	}
	if len(seen) != len(stages) {
		t.Fatal("applicable negative disappeared")
	}
}

func TestSuppliedRegistryHistoryDoesNotInferMissingTranscriptEvidence(t *testing.T) {
	want := []string{"digest-request-without-nul", "digest-acceptance-splice", "recovery-lookup-success", "recovery-continuity-success", "grammar-schema-negative", "grammar-partial-tuple", "grammar-fingerprint", "grammar-spki-der", "grammar-spki-offcurve", "grammar-key-tag", "grammar-digest-uppercase", "grammar-spki-padding", "encoding-schema-fraction", "grammar-high-s"}
	c := readRegistryCorpus(t)
	positives := registryPositiveMap(t, c)
	seen := 0
	for _, n := range c.Negatives {
		if !containsHistoryName(want, n.ID) {
			continue
		}
		seen++
		t.Run(n.ID, func(t *testing.T) {
			var records [][]byte
			for _, raw := range registryPrefix(t, n.Prefix, positives) {
				records = append(records, []byte(raw))
			}
			records = append(records, []byte(n.Transcript.Record))
			if _, err := VerifySuppliedRegistryHistory(records); err != nil {
				t.Fatalf("inferred absent transcript evidence: %v", err)
			}
		})
	}
	if seen != len(want) {
		t.Fatal("scope vector disappeared")
	}
}

func containsHistoryName(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

func TestSuppliedRegistryHistoryPhasesAndRedaction(t *testing.T) {
	base := historyTestRecords(t, "enroll1", "rotate2")
	badSignature := historyTestObject(t, base[0])
	key, _ := historyTestKey(t, 2)
	first := historyTestSign(t, badSignature, nil, key)
	historyTestFailure(t, [][]byte{first}, "replay")
	lateGrammar := historyTestObject(t, base[1])
	lateGrammar["registry_revision"] = json.RawMessage("257")
	lateEncoding := append(append([]byte{}, base[1]...), '\n')
	for _, test := range []struct {
		name    string
		records [][]byte
		stage   string
	}{
		{"later-encoding-before-earlier-signature", [][]byte{first, lateEncoding}, "encoding"},
		{"later-grammar-before-earlier-signature", [][]byte{first, historyTestEncode(lateGrammar, false)}, "grammar"},
		{"later-bounds-before-earlier-encoding", [][]byte{lateEncoding, bytes.Repeat([]byte{'x'}, 4353)}, "bounds"},
		{"empty-record", [][]byte{nil}, "bounds"},
		{"item-at-cap-parsed", [][]byte{bytes.Repeat([]byte{'x'}, 4352)}, "encoding"},
		{"item-over-cap", [][]byte{bytes.Repeat([]byte{'x'}, 4353)}, "bounds"},
		{"count257", make([][]byte, 257), "bounds"},
		{"aggregate-at", make([][]byte, 256), "encoding"},
		{"late-item-over-cap", make([][]byte, 256), "bounds"},
	} {
		if test.name == "aggregate-at" || test.name == "late-item-over-cap" {
			for i := range test.records {
				test.records[i] = bytes.Repeat([]byte{'x'}, 4352)
			}
			if test.name == "late-item-over-cap" {
				test.records[255] = bytes.Repeat([]byte{'x'}, 4353)
			}
		}
		t.Run(test.name, func(t *testing.T) { historyTestFailure(t, test.records, test.stage) })
	}
	for _, raw := range [][]byte{
		[]byte(`{"UNTRUSTED_SENTINEL":0,"UNTRUSTED_SENTINEL":1}`),
		bytes.Replace(base[0], []byte(`"registry_revision":1`), []byte(`"registry_revision":"UNTRUSTED_SENTINEL"`), 1),
		bytes.Replace(base[0], []byte(`"registry_revision":1`), []byte(`"registry_revision":9999999999999999999999999999999999999999999999999999999999`), 1),
	} {
		historyTestFailure(t, [][]byte{raw}, "encoding")
		_, err := VerifySuppliedRegistryHistory([][]byte{raw})
		if strings.Contains(fmt.Sprintf("%+v", err), "UNTRUSTED_SENTINEL") || strings.Contains(fmt.Sprintf("%+v", err), "999999999") {
			t.Fatal("untrusted diagnostics escaped")
		}
	}
	// Positive control: the standard decoder really includes supplied text on
	// this path. The public verifier must replace, not wrap, those diagnostics.
	var diagnostic struct {
		Revision uint64 `json:"registry_revision"`
	}
	probe := []byte(`{"registry_revision":9999999999999999999999999999999999999999999999999999999999}`)
	decoderErr := json.Unmarshal(probe, &diagnostic)
	if decoderErr == nil || !strings.Contains(decoderErr.Error(), "999999999") {
		t.Fatal("redaction positive control did not reach decoder diagnostic")
	}
}

func TestSuppliedRegistryHistoryRecordCryptoGrammar(t *testing.T) {
	base := historyTestRecords(t, "enroll1")[0]
	object := historyTestObject(t, base)
	var encoded string
	if err := json.Unmarshal(object["new_signature"], &encoded); err != nil {
		t.Fatal(err)
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var signature struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &signature); err != nil || len(rest) != 0 {
		t.Fatalf("fixture signature: %v", err)
	}
	signature.S.Sub(elliptic.P256().Params().N, signature.S)
	high, err := asn1.Marshal(signature)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := historyTestKey(t, 1)
	digest := sha256.Sum256(append([]byte("YTA-REGISTRY-RECORD-NEW-V1\x00"), historyTestEncode(object, true)...))
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], high) {
		t.Fatal("high-S rejection control is not a mathematically valid alias")
	}
	for _, test := range []struct {
		name, field string
		value       json.RawMessage
	}{
		{"high-s-record", "new_signature", historyTestString(base64.RawURLEncoding.EncodeToString(high))},
		{"empty-der", "new_signature", historyTestString(base64.RawURLEncoding.EncodeToString([]byte{0x30, 0}))},
		{"spki-padding", "new_spki", historyTestString(strings.Trim(string(object["new_spki"]), `"`) + "=")},
		{"spki-zeros", "new_spki", historyTestString(base64.RawURLEncoding.EncodeToString(make([]byte, 91)))},
		{"fingerprint-mismatch", "new_fingerprint_sha256", historyTestString(strings.Repeat("0", 64))},
		{"key-tag-mismatch", "new_key_tag", historyTestString("io.github.abigotado.youtrack-agent.approval.signing.v1/" + strings.Repeat("2", 32))},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := historyTestObject(t, base)
			candidate[test.field] = test.value
			historyTestFailure(t, [][]byte{historyTestEncode(candidate, false)}, "grammar")
		})
	}
}

func TestSuppliedRegistryHistoryRawCanonicalAndNulls(t *testing.T) {
	base := historyTestRecords(t, "enroll1")[0]
	for _, test := range []struct {
		name  string
		raw   []byte
		stage string
	}{
		{"bom", append([]byte{0xef, 0xbb, 0xbf}, base...), "encoding"},
		{"invalid-utf8", append(append([]byte{}, base...), 0xff), "encoding"},
		{"leading-space", append([]byte{' '}, base...), "encoding"},
		{"escaped-value", bytes.Replace(base, []byte(`"enroll"`), []byte(`"\u0065nroll"`), 1), "encoding"},
		{"exponent", bytes.Replace(base, []byte(`"registry_revision":1`), []byte(`"registry_revision":1e0`), 1), "encoding"},
		{"negative-zero", bytes.Replace(base, []byte(`"registry_revision":1`), []byte(`"registry_revision":-0`), 1), "encoding"},
		{"required-null", bytes.Replace(base, []byte(`"record_type":"approval_registry_transition"`), []byte(`"record_type":null`), 1), "grammar"},
		{"forbidden-enroll-target", bytes.Replace(base, []byte(`"target_generation":null`), []byte(`"target_generation":"YTAG-00000000000000000001"`), 1), "grammar"},
		{"bool-null", bytes.Replace(base, []byte(`"revokes_all_prior":false`), []byte(`"revokes_all_prior":null`), 1), "grammar"},
	} {
		t.Run(test.name, func(t *testing.T) { historyTestFailure(t, [][]byte{test.raw}, test.stage) })
	}
	for _, field := range strings.Fields(historyTestFields) {
		object := historyTestObject(t, base)
		if string(object[field]) != "null" {
			continue
		}
		t.Run("missing-null-"+field, func(t *testing.T) {
			needle := []byte(`,"` + field + `":null`)
			raw := bytes.Replace(base, needle, nil, 1)
			if bytes.Equal(raw, base) {
				t.Fatal("mutation not exercised")
			}
			historyTestFailure(t, [][]byte{raw}, "encoding")
		})
	}
}

func TestSuppliedRegistryHistoryHTMLPhase(t *testing.T) {
	records := historyTestRecords(t, "enroll1", "rotate2")
	earlierGrammar := bytes.Replace(records[0], []byte(`"registry_revision":1`), []byte(`"registry_revision":257`), 1)
	for _, value := range []string{"<", ">", "&"} {
		t.Run(value, func(t *testing.T) {
			laterEncoding := bytes.Replace(records[1], []byte(`"record_type":"approval_registry_transition"`), []byte(`"record_type":"`+value+`"`), 1)
			if bytes.Equal(laterEncoding, records[1]) {
				t.Fatal("HTML regression mutation not exercised")
			}
			historyTestFailure(t, [][]byte{laterEncoding}, "encoding")
			historyTestFailure(t, [][]byte{earlierGrammar, laterEncoding}, "encoding")
		})
	}
}

func TestSuppliedRegistryHistorySignedTimes(t *testing.T) {
	base := historyTestRecords(t, "enroll1")[0]
	key, _ := historyTestKey(t, 1)
	for _, test := range []struct{ name, requested, accepted, committed, stage string }{
		{"year-zero-leap", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", ""},
		{"year-one-zero-instant", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", ""},
		{"year-max", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", ""},
		{"gregorian-cutover", "1582-10-10T00:00:00Z", "1582-10-10T00:00:01Z", "1582-10-10T00:00:02Z", ""},
		{"invalid-century-leap", "1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z", "grammar"},
		{"299-seconds", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:04:59Z", ""},
		{"300-seconds", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:05:00Z", "replay"},
		{"reverse-acceptance", "2000-01-01T00:00:01Z", "2000-01-01T00:00:00Z", "2000-01-01T00:00:02Z", "replay"},
		{"reverse-commit", "2000-01-01T00:00:00Z", "2000-01-01T00:00:02Z", "2000-01-01T00:00:01Z", "replay"},
		{"full-calendar-range", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "replay"},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := historyTestObject(t, base)
			object["requested_at"] = historyTestString(test.requested)
			object["accepted_at"] = historyTestString(test.accepted)
			object["committed_at"] = historyTestString(test.committed)
			raw := historyTestSign(t, object, nil, key)
			if test.stage != "" {
				historyTestFailure(t, [][]byte{raw}, test.stage)
			} else if _, err := VerifySuppliedRegistryHistory([][]byte{raw}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSuppliedRegistryHistorySignedRecoveryAndAliases(t *testing.T) {
	records := historyTestRecords(t, "enroll1", "rotate2", "recover-active3")
	fresh, _ := historyTestKey(t, 3)
	object := historyTestObject(t, records[2])
	for _, field := range strings.Fields(historyTestFields) {
		if strings.HasPrefix(field, "target_") {
			object[field] = json.RawMessage("null")
		}
	}
	historyTestFailure(t, [][]byte{records[0], records[1], historyTestSign(t, object, nil, fresh)}, "replay")
	historyTestFailure(t, [][]byte{records[2]}, "replay")
	historyTestFailure(t, [][]byte{records[1], records[0]}, "replay")
	historyTestFailure(t, [][]byte{records[0], records[0]}, "replay")
	historyTestFailure(t, [][]byte{records[0], records[2]}, "replay")
	result, err := VerifySuppliedRegistryHistory(records)
	if err != nil {
		t.Fatal(err)
	}
	keys := result.Keys()
	keys[0].Status = "active"
	keys[0].SPKI = "changed"
	for _, raw := range records {
		for i := range raw {
			raw[i] = 'x'
		}
	}
	if result.SuppliedRevision() != 3 || result.Keys()[0].Status != "revoked" || result.Keys()[0].SPKI == "changed" || result.SuppliedTipSHA256() != "6d1f7ea55313a4ffd01cd5c2ddb732dcf871b2fe722699779e83b1b0b33453e6" {
		t.Fatal("result aliases caller-owned values")
	}
}

func TestSuppliedRegistryHistorySeparatelyRejectsIdentityAndPublicKeyReuse(t *testing.T) {
	records := historyTestRecords(t, "enroll1", "rotate2")
	old, previous := historyTestKey(t, 1)
	fresh, _ := historyTestKey(t, 2)
	for _, group := range []string{"identity", "public-key"} {
		t.Run(group, func(t *testing.T) {
			object := historyTestObject(t, records[1])
			signer := fresh
			if group == "identity" {
				object["new_key_id"] = historyTestString(previous.KeyID)
				object["new_key_tag"] = historyTestString(previous.KeyTag)
			} else {
				object["new_spki"] = historyTestString(previous.SPKI)
				object["new_fingerprint_sha256"] = historyTestString(previous.FingerprintSHA256)
				signer = old
			}
			historyTestFailure(t, [][]byte{records[0], historyTestSign(t, object, old, signer)}, "replay")
		})
	}
}

func TestSuppliedRegistryHistoryGenerationTokenGrammar(t *testing.T) {
	records := historyTestRecords(t, "enroll1", "rotate2")
	values := []struct{ name, value string }{
		{"zero", "YTAG-" + strings.Repeat("0", 20)},
		{"short", "YTAG-" + strings.Repeat("0", 18) + "1"},
		{"long", "YTAG-" + strings.Repeat("0", 20) + "1"},
		{"sign", "YTAG-+" + strings.Repeat("0", 18) + "1"},
		{"nondigit", "YTAG-" + strings.Repeat("0", 19) + "x"},
	}
	for _, field := range []string{"new_generation", "target_generation"} {
		for _, value := range values {
			t.Run(field+"/"+value.name, func(t *testing.T) {
				object := historyTestObject(t, records[1])
				object[field] = historyTestString(value.value)
				// The other four tuple members remain populated, avoiding a partial-tuple
				// refusal that would mask the generation token's own validation.
				historyTestFailure(t, [][]byte{records[0], historyTestEncode(object, false)}, "grammar")
			})
		}
	}
}

func TestSuppliedRegistryHistoryForbiddenSignatureRolesAndRevokeTuple(t *testing.T) {
	records := historyTestRecords(t, "enroll1", "rotate2", "revoke3")
	one, _ := historyTestKey(t, 1)
	two, _ := historyTestKey(t, 2)
	three, newTuple := historyTestKey(t, 3)
	t.Run("enroll-old-signature", func(t *testing.T) {
		object := historyTestObject(t, records[0])
		historyTestFailure(t, [][]byte{historyTestSign(t, object, one, one)}, "replay")
	})
	t.Run("recover-old-signature", func(t *testing.T) {
		recovery := historyTestRecords(t, "recover-active3")[0]
		object := historyTestObject(t, recovery)
		historyTestFailure(t, [][]byte{records[0], records[1], historyTestSign(t, object, two, three)}, "replay")
	})
	t.Run("revoke-new-signature", func(t *testing.T) {
		object := historyTestObject(t, records[2])
		historyTestFailure(t, [][]byte{records[0], records[1], historyTestSign(t, object, two, three)}, "replay")
	})
	t.Run("revoke-new-tuple-and-status", func(t *testing.T) {
		object := historyTestObject(t, records[2])
		object["new_generation"] = historyTestString(newTuple.Generation)
		object["new_key_id"] = historyTestString(newTuple.KeyID)
		object["new_key_tag"] = historyTestString(newTuple.KeyTag)
		object["new_spki"] = historyTestString(newTuple.SPKI)
		object["new_fingerprint_sha256"] = historyTestString(newTuple.FingerprintSHA256)
		object["new_status"] = historyTestString("active")
		// Generation 3 is grammatically legal at revision 3; a fresh valid old-key
		// signature ensures the revoke event's field combination causes refusal.
		historyTestFailure(t, [][]byte{records[0], records[1], historyTestSign(t, object, two, nil)}, "replay")
	})
	t.Run("old-high-s-valid-alias", func(t *testing.T) {
		object := historyTestObject(t, records[1])
		var encoded string
		if err := json.Unmarshal(object["old_signature"], &encoded); err != nil {
			t.Fatal(err)
		}
		der, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		var signature struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(der, &signature); err != nil || len(rest) != 0 {
			t.Fatalf("fixture signature: %v", err)
		}
		signature.S.Sub(elliptic.P256().Params().N, signature.S)
		high, err := asn1.Marshal(signature)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(append([]byte("YTA-REGISTRY-RECORD-OLD-V1\x00"), historyTestEncode(object, true)...))
		if !ecdsa.VerifyASN1(&one.PublicKey, digest[:], high) {
			t.Fatal("old high-S alias is not mathematically valid")
		}
		object["old_signature"] = historyTestString(base64.RawURLEncoding.EncodeToString(high))
		historyTestFailure(t, [][]byte{records[0], historyTestEncode(object, false)}, "grammar")
	})
}

func TestSuppliedRegistryHistoryMaximalLedgerAndDescriptorUpgrade(t *testing.T) {
	base := historyTestObject(t, historyTestRecords(t, "enroll1")[0])
	var records [][]byte
	var old *ecdsa.PrivateKey
	var previous SuppliedRegistryKey
	for revision := 1; revision <= 256; revision++ {
		fresh, k := historyTestKey(t, revision)
		object := make(map[string]json.RawMessage, len(base))
		for field, value := range base {
			object[field] = append(json.RawMessage{}, value...)
		}
		object["registry_revision"] = json.RawMessage(fmt.Sprint(revision))
		object["new_generation"] = historyTestString(k.Generation)
		object["new_key_id"] = historyTestString(k.KeyID)
		object["new_key_tag"] = historyTestString(k.KeyTag)
		object["new_spki"] = historyTestString(k.SPKI)
		object["new_fingerprint_sha256"] = historyTestString(k.FingerprintSHA256)
		if revision > 1 {
			object["transition_kind"] = historyTestString("rotate")
			object["previous_record_sha256"] = historyTestString(historyTestHash(records[len(records)-1]))
			object["target_generation"] = historyTestString(previous.Generation)
			object["target_key_id"] = historyTestString(previous.KeyID)
			object["target_key_tag"] = historyTestString(previous.KeyTag)
			object["target_spki"] = historyTestString(previous.SPKI)
			object["target_fingerprint_sha256"] = historyTestString(previous.FingerprintSHA256)
			object["target_previous_status"] = historyTestString("active")
			object["target_new_status"] = historyTestString("retained")
		}
		if revision == 256 {
			object["artifact_descriptor_sha256"] = historyTestString(strings.Repeat("b", 64))
		}
		records = append(records, historyTestSign(t, object, old, fresh))
		old = fresh
		previous = k
	}
	result, err := VerifySuppliedRegistryHistory(records)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, present := result.SuppliedTipDescriptorSHA256()
	if result.SuppliedRevision() != 256 || len(result.Keys()) != 256 || !present || descriptor != strings.Repeat("b", 64) {
		t.Fatal("bounded complete supplied history differs")
	}
	for i, k := range result.Keys() {
		want := "retained"
		if i == 255 {
			want = "active"
		}
		if k.Status != want {
			t.Fatal("maximal ledger status differs")
		}
	}
	historyTestFailure(t, append(records, records[255]), "bounds")
}
