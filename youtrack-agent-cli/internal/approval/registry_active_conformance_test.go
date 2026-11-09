package approval

// Test-only supplied-fixture oracle. Validation order is fixture integrity,
// not evidence of runtime acquisition, freshness, ownership, or authorization.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

type registryActiveVector struct {
	ID              string `json:"id"`
	IntentID        string `json:"intent_id"`
	RawHex          string `json:"raw_hex"`
	SigningInputHex string `json:"signing_input_hex,omitempty"`
	SHA256          string `json:"sha256"`
	Base            string `json:"base,omitempty"`
	ReasonClass     string `json:"reason_class,omitempty"`
}

type registryActiveCorpus struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	Sources       []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"sources"`
	Positives []registryActiveVector `json:"positives"`
	Negatives []registryActiveVector `json:"negatives"`
}

func readRegistryActiveCorpus(t *testing.T) registryActiveCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/gate1a-registry-active/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c registryActiveCorpus
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		t.Fatal(err)
	}
	var trailing json.RawMessage
	if d.Decode(&trailing) != io.EOF {
		t.Fatal("trailing active corpus data")
	}
	if c.SchemaVersion != 1 || c.Scope != "registry-active-intent-binding" || len(c.Sources) != 2 {
		t.Fatal("unexpected active corpus schema")
	}
	for i, path := range []string{"testdata/gate1a-registry/corpus.json", "testdata/gate1a-registry-intent/corpus.json"} {
		if c.Sources[i].Path != path {
			t.Fatal("unexpected active source path")
		}
		source, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		if registryHash("", string(source)) != c.Sources[i].SHA256 {
			t.Fatal("active source digest mismatch")
		}
	}
	return c
}

func registryIntentPositiveMap(t *testing.T) map[string]registryIntentVector {
	t.Helper()
	intents := make(map[string]registryIntentVector)
	for _, v := range readRegistryIntentCorpus(t).Positives {
		if _, exists := intents[v.ID]; exists {
			t.Fatal("duplicate intent fixture")
		}
		intents[v.ID] = v
	}
	return intents
}

func TestRegistryActiveFixtureIntegrity(t *testing.T) {
	for _, damage := range []string{"missing intent", "unlinked intent", "missing core", "missing prefix", "invalid core", "invalid prefix", "invalid intent", "invalid intent binding", "invalid intent digest"} {
		t.Run(damage, func(t *testing.T) {
			intents := registryIntentPositiveMap(t)
			cores := registryPositiveMap(t, readRegistryCorpus(t))
			id := "intent-rotate2"
			intent := intents[id]
			switch damage {
			case "missing intent":
				delete(intents, id)
			case "unlinked intent":
				intent.CoreID = nil
				intents[id] = intent
			case "missing core":
				delete(cores, "rotate2")
			case "missing prefix":
				delete(cores, "enroll1")
			case "invalid core":
				core := cores["rotate2"]
				core.Proposal = "UNTRUSTED_SENTINEL"
				cores["rotate2"] = core
			case "invalid prefix":
				core := cores["enroll1"]
				core.Record = "UNTRUSTED_SENTINEL"
				cores["enroll1"] = core
			case "invalid intent":
				intent.RawHex = hex.EncodeToString([]byte("UNTRUSTED_SENTINEL"))
				intents[id] = intent
			case "invalid intent binding":
				coreID := "enroll1"
				intent.CoreID = &coreID
				intents[id] = intent
			case "invalid intent digest":
				intent.SHA256 = strings.Repeat("0", 64)
				intents[id] = intent
			}
			// Invalid references must win even over undecodable active fixture bytes.
			reason, err := registryVerifyActive(registryActiveVector{IntentID: id, RawHex: "not hex"}, intents, cores)
			if reason != "" || err == nil || !strings.HasPrefix(err.Error(), "fixture integrity:") || strings.Contains(err.Error(), "raw hex") || strings.Contains(err.Error(), "UNTRUSTED_SENTINEL") {
				t.Fatalf("got %q, %v", reason, err)
			}
		})
	}
}

func registryParseActive(raw []byte) (registryObject, string) {
	if len(raw) > 4096 {
		return nil, "bounds_grammar"
	}
	if !utf8.Valid(raw) {
		return nil, "canonical_encoding"
	}
	var o registryObject
	if json.Unmarshal(raw, &o) != nil || o == nil {
		return nil, "canonical_encoding"
	}
	fields := strings.Fields("schema_version record_type lease_id operation_kind coordinator_session_id cli_audit_token_sha256 artifact_descriptor_sha256 authorization_context_sha256 registry_revision plan_id journal_revision receipt_sha256 registry_intent_sha256 created_at expires_at")
	if len(o) != len(fields) {
		return nil, "canonical_encoding"
	}
	for _, field := range fields {
		if _, ok := o[field]; !ok {
			return nil, "canonical_encoding"
		}
	}
	if !bytes.Equal(raw, registryObjectBytes(o, fields)) {
		return nil, "canonical_encoding"
	}
	for _, field := range fields {
		value := string(o[field])
		switch field {
		case "authorization_context_sha256", "registry_revision", "plan_id", "journal_revision", "receipt_sha256":
			// Canonical scalars reach the branch check; nested/noncanonical
			// values are rejected at the same lexical boundary as other fields.
			if value == "null" || value == "true" || value == "false" || registryIntegerToken(value) {
				continue
			}
		case "schema_version":
			if !registryIntegerToken(value) {
				return nil, "canonical_encoding"
			}
			continue
		}
		var s string
		if value == "null" || json.Unmarshal(o[field], &s) != nil || value != `"`+s+`"` {
			return nil, "canonical_encoding"
		}
		for i := range s {
			if s[i] < 0x20 || s[i] > 0x7e || s[i] == '\\' {
				return nil, "canonical_encoding"
			}
		}
	}
	if string(o["schema_version"]) != "1" || registryString(o, "record_type") != "apply_coordinator_active" || registryString(o, "operation_kind") != "registry_commit" {
		return nil, "bounds_grammar"
	}
	for _, field := range []string{"authorization_context_sha256", "registry_revision", "plan_id", "journal_revision", "receipt_sha256"} {
		if string(o[field]) != "null" {
			return nil, "bounds_grammar"
		}
	}
	if protocolvalue.ValidateCanonicalBase32ID(registryString(o, "lease_id"), "YTAL-") != nil {
		return nil, "bounds_grammar"
	}
	if _, ok := registryBase64(registryString(o, "coordinator_session_id"), 32); !ok {
		return nil, "bounds_grammar"
	}
	for _, field := range []string{"cli_audit_token_sha256", "artifact_descriptor_sha256", "registry_intent_sha256"} {
		if !registryHex(registryString(o, field), 64) {
			return nil, "bounds_grammar"
		}
	}
	for _, field := range []string{"created_at", "expires_at"} {
		s := registryString(o, field)
		when, err := time.Parse("2006-01-02T15:04:05Z", s)
		if err != nil || when.Format("2006-01-02T15:04:05Z") != s {
			return nil, "bounds_grammar"
		}
	}
	duration := registryTime(o, "expires_at").Sub(registryTime(o, "created_at"))
	if duration < time.Second || duration > 600*time.Second {
		return nil, "temporal"
	}
	return o, ""
}

func registryVerifyActive(v registryActiveVector, intents map[string]registryIntentVector, cores map[string]registryPositive) (string, error) {
	intent, ok := intents[v.IntentID]
	if !ok {
		return "", fmt.Errorf("fixture integrity: missing intent")
	}
	if intent.CoreID == nil {
		return "", fmt.Errorf("fixture integrity: missing intent core")
	}
	if reason, err := registryVerifyIntent(intent, cores); err != nil || reason != "" {
		return "", fmt.Errorf("fixture integrity: invalid intent or core")
	}
	intentRaw, err := hex.DecodeString(intent.RawHex)
	if err != nil {
		return "", fmt.Errorf("fixture integrity: invalid intent hex")
	}
	parsedIntent, reason := registryParseIntent(intentRaw)
	if reason != "" {
		return "", fmt.Errorf("fixture integrity: invalid intent")
	}
	raw, err := hex.DecodeString(v.RawHex)
	if err != nil || hex.EncodeToString(raw) != v.RawHex {
		return "", fmt.Errorf("fixture integrity: invalid raw hex")
	}
	o, reason := registryParseActive(raw)
	if reason != "" {
		return reason, nil
	}
	if !registryHex(v.SHA256, 64) || registryHash("YTA-APPLY-COORDINATOR-ACTIVE-V1\x00", string(raw)) != v.SHA256 {
		return "digest_domain", nil
	}
	if registryString(o, "registry_intent_sha256") != intent.SHA256 || !registryEqual(o, "artifact_descriptor_sha256", parsedIntent, "artifact_descriptor_sha256") {
		return "active_binding", nil
	}
	return "", nil
}

func TestSharedRegistryActiveCorpus(t *testing.T) {
	c := readRegistryActiveCorpus(t)
	intents := registryIntentPositiveMap(t)
	cores := registryPositiveMap(t, readRegistryCorpus(t))
	// Literal bytes, references and hashes are separate from generated verdicts.
	want := map[string]struct{ intent, intentDigest, expiry, digest string }{
		"active-enroll1":           {"intent-enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", "12:10:00", "caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942"},
		"active-rotate2":           {"intent-rotate2", "e122718b57b090b792ad13ecbb347a0d3181d9e3c1217bd590d061af0cc56c87", "12:10:00", "c8212115dbfedbcc7e4f62a95b507d1f06eba6646029f0fb3bb70e44af8e5188"},
		"active-revoke3":           {"intent-revoke3", "713452b672826409337bbd53668ab09157a265cfe2db5ce2884d33adbb5b387f", "12:10:00", "3501fae949ef93dbac4c8fa779eb79f63e71f8f564439188bbd0ecf450d0651b"},
		"active-recover-disabled4": {"intent-recover-disabled4", "8ccd7960f14afea3c3efbb4605f4e01c537f39facf4ac7403da19b8b03442612", "12:10:00", "2a80ebbe805fef70364c30ab4ceca1aa420fc0aadb45fbd4aa32ac97d33a8116"},
		"active-recover-active3":   {"intent-recover-active3", "de2c3928d468b22ed606840441758ccfadcae491a17493dc93f8adf8065f51f9", "12:10:00", "fcd9911c103141b81e6319ca67898f298f3e3efa5a6ba101c127ccfe2ee86905"},
		"ttl-1s":                   {"intent-enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", "12:00:01", "04c41ff1321d8b32ec08aac7efaf1e4eb693c1d348b5fc3a6e198af5b589c16e"},
		"ttl-600s":                 {"intent-enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", "12:10:00", "caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942"},
	}
	seen := make(map[string]bool)
	var baseRawHex string
	for _, v := range c.Positives {
		if v.ID == "active-enroll1" {
			baseRawHex = v.RawHex
		}
		t.Run(v.ID, func(t *testing.T) {
			p, ok := want[v.ID]
			if !ok || seen[v.ID] {
				t.Fatal("unknown or duplicate positive")
			}
			seen[v.ID] = true
			if v.IntentID != p.intent || v.Base != "" || v.ReasonClass != "" {
				t.Fatal("unexpected positive metadata")
			}
			raw := fmt.Sprintf(`{"schema_version":1,"record_type":"apply_coordinator_active","lease_id":"YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE","operation_kind":"registry_commit","coordinator_session_id":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","cli_audit_token_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","artifact_descriptor_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authorization_context_sha256":null,"registry_revision":null,"plan_id":null,"journal_revision":null,"receipt_sha256":null,"registry_intent_sha256":"%s","created_at":"2026-09-01T12:00:00Z","expires_at":"2026-09-01T%sZ"}`, p.intentDigest, p.expiry)
			input := "YTA-APPLY-COORDINATOR-ACTIVE-V1\x00" + raw
			if v.RawHex != hex.EncodeToString([]byte(raw)) || v.SigningInputHex != hex.EncodeToString([]byte(input)) || v.SHA256 != p.digest || registryHash("", input) != p.digest {
				t.Fatal("positive differs from literal canonical input/hash")
			}
			if reason, err := registryVerifyActive(v, intents, cores); err != nil || reason != "" {
				t.Fatalf("active rejected: %q, %v", reason, err)
			}
		})
	}
	if len(seen) != len(want) {
		t.Fatal("missing positive active")
	}
	expected := make(map[string]string)
	for reason, ids := range map[string]string{
		"canonical_encoding": "canonical-empty canonical-malformed canonical-bom canonical-unknown canonical-duplicate canonical-missing canonical-reordered canonical-whitespace canonical-trailing-lf canonical-trailing-token canonical-escaped-key canonical-escaped-value canonical-invalid-utf8 canonical-schema-string canonical-schema-bool canonical-null canonical-array canonical-object canonical-schema-fraction canonical-schema-exponent canonical-schema-leading-zero canonical-schema-plus canonical-schema-negative-zero canonical-size-4096 canonical-forbidden-array canonical-forbidden-object",
		"bounds_grammar":     "bounds-size-4097 schema-version field-record-type field-operation-kind field-lease-prefix field-lease-case field-lease-alphabet field-lease-15-bytes field-lease-17-bytes field-lease-padding field-lease-pad-bits field-session-31-bytes field-session-33-bytes field-session-alphabet field-session-padding field-session-pad-bits field-forbidden-authorization_context_sha256 field-forbidden-registry_revision field-forbidden-plan_id field-forbidden-journal_revision field-forbidden-receipt_sha256",
		"temporal":           "temporal-zero temporal-negative temporal-601s",
		"digest_domain":      "digest-wrong digest-no-nul digest-wrong-domain digest-plain-hash digest-lf-hash",
		"active_binding":     "binding-intent binding-candidate-record binding-descriptor",
	} {
		for _, id := range strings.Fields(ids) {
			expected[id] = reason
		}
	}
	for _, field := range []string{"cli_audit_token_sha256", "artifact_descriptor_sha256", "registry_intent_sha256"} {
		expected["canonical-"+field+"-null"] = "canonical_encoding"
		for _, suffix := range []string{"empty", "short", "long", "uppercase", "nonhex"} {
			expected["field-"+field+"-"+suffix] = "bounds_grammar"
		}
	}
	for _, field := range []string{"created_at", "expires_at"} {
		for _, suffix := range []string{"offset", "fraction", "invalid"} {
			expected["field-"+field+"-"+suffix] = "bounds_grammar"
		}
	}
	seen = make(map[string]bool)
	for _, v := range c.Negatives {
		t.Run(v.ID, func(t *testing.T) {
			want, ok := expected[v.ID]
			if !ok || seen[v.ID] {
				t.Fatal("unknown or duplicate negative")
			}
			seen[v.ID] = true
			if v.ReasonClass != want || v.Base != "active-enroll1" || v.IntentID != "intent-enroll1" || v.SigningInputHex != "" {
				t.Fatal("unexpected negative metadata")
			}
			raw, err := hex.DecodeString(v.RawHex)
			if err != nil {
				t.Fatal(err)
			}
			if want != "digest_domain" && v.SHA256 != registryHash("YTA-APPLY-COORDINATOR-ACTIVE-V1\x00", string(raw)) {
				t.Fatal("negative must hash exact original bytes")
			}
			if v.ID == "canonical-bom" && (baseRawHex == "" || v.RawHex != "efbbbf"+baseRawHex) {
				t.Fatal("BOM must prefix exact base bytes")
			}
			if v.ID == "field-lease-case" {
				base, err := hex.DecodeString(baseRawHex)
				if err != nil {
					t.Fatal(err)
				}
				exact := strings.Replace(string(base), `"lease_id":"YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE"`, `"lease_id":"YTAL-eeqscijbeeqscijbeeqscijbee"`, 1)
				if string(raw) != exact {
					t.Fatal("lease case vector must lowercase only the body with the exact YTAL- prefix intact")
				}
			}
			if v.ID == "binding-candidate-record" {
				candidate := registryHash("YTA-REGISTRY-COMMIT-V1\x00", cores["enroll1"].Record)
				if candidate != "f86e37d14900784636e841daa65e31d16d39e0b7c5be24f07c84e95d825ba9b9" {
					t.Fatal("candidate commit digest differs from pinned core")
				}
				base, err := hex.DecodeString(baseRawHex)
				if err != nil {
					t.Fatal(err)
				}
				exact := strings.Replace(string(base), "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", candidate, 1)
				if string(raw) != exact {
					t.Fatal("candidate vector must replace only intent digest with actual candidate commit digest")
				}
			}
			if reason, err := registryVerifyActive(v, intents, cores); err != nil || reason != want {
				t.Fatalf("got %q, %v; want %q", reason, err, want)
			}
		})
	}
	if len(seen) != len(expected) {
		t.Fatal("missing negative active")
	}
}
