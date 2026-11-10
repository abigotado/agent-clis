package approval

// Test-only byte oracle: this establishes neither coordinator ownership nor a
// production registry verifier, trusted clock, or nonce freshness authority.
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
)

type registryIntentVector struct {
	ID              string  `json:"id"`
	CoreID          *string `json:"core_id"`
	RawHex          string  `json:"raw_hex"`
	SigningInputHex string  `json:"signing_input_hex,omitempty"`
	SHA256          string  `json:"sha256"`
	Base            string  `json:"base,omitempty"`
	ReasonClass     string  `json:"reason_class,omitempty"`
}

type registryIntentCorpus struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	Source        struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"source"`
	Positives []registryIntentVector `json:"positives"`
	Negatives []registryIntentVector `json:"negatives"`
}

func registryParseIntent(raw []byte) (registryObject, string) {
	if len(raw) > 1024 {
		return nil, "bounds_grammar"
	}
	if !utf8.Valid(raw) {
		return nil, "canonical_encoding"
	}
	var o registryObject
	if json.Unmarshal(raw, &o) != nil || o == nil {
		return nil, "canonical_encoding"
	}
	fields := strings.Fields("schema_version intent_type transition_kind artifact_descriptor_sha256 ceremony_nonce requested_at expires_at")
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
		if value == "null" {
			return nil, "canonical_encoding"
		}
		if field == "schema_version" {
			if !registryIntegerToken(value) {
				return nil, "canonical_encoding"
			}
			continue
		}
		var s string
		if json.Unmarshal(o[field], &s) != nil || value != `"`+s+`"` {
			return nil, "canonical_encoding"
		}
		for i := range s {
			if s[i] < 0x20 || s[i] > 0x7e || s[i] == '\\' {
				return nil, "canonical_encoding"
			}
		}
	}
	if string(o["schema_version"]) != "1" || registryString(o, "intent_type") != "registry_commit" {
		return nil, "bounds_grammar"
	}
	switch registryString(o, "transition_kind") {
	case "enroll", "rotate", "revoke", "recover":
	default:
		return nil, "bounds_grammar"
	}
	if !registryHex(registryString(o, "artifact_descriptor_sha256"), 64) {
		return nil, "bounds_grammar"
	}
	if _, ok := registryBase64(registryString(o, "ceremony_nonce"), 32); !ok {
		return nil, "bounds_grammar"
	}
	for _, field := range []string{"requested_at", "expires_at"} {
		s := registryString(o, field)
		when, err := time.Parse("2006-01-02T15:04:05Z", s)
		if err != nil || when.Format("2006-01-02T15:04:05Z") != s {
			return nil, "bounds_grammar"
		}
	}
	duration := registryTime(o, "expires_at").Sub(registryTime(o, "requested_at"))
	if duration < time.Second || duration > 300*time.Second {
		return nil, "temporal"
	}
	return o, ""
}

// Fixture integrity is a separate error boundary, never a public refusal class.
// Resolve and verify the entire core and predecessor chain before parsing intent.
func registryVerifyIntent(v registryIntentVector, cores map[string]registryPositive) (string, error) {
	var request registryObject
	if v.CoreID != nil {
		core, ok := cores[*v.CoreID]
		if !ok {
			return "", fmt.Errorf("fixture integrity: missing core")
		}
		prefix := make([]string, 0, len(core.Prefix))
		for _, id := range core.Prefix {
			previous, ok := cores[id]
			if !ok {
				return "", fmt.Errorf("fixture integrity: missing prefix")
			}
			prefix = append(prefix, previous.Record)
		}
		if _, reason := registryVerifyTranscript(core.registryTranscript, prefix); reason != "" {
			return "", fmt.Errorf("fixture integrity: invalid core (%s)", reason)
		}
		var reason string
		request, reason = registryParse(core.Request, "request")
		if reason != "" {
			return "", fmt.Errorf("fixture integrity: invalid request")
		}
	}
	raw, err := hex.DecodeString(v.RawHex)
	if err != nil || hex.EncodeToString(raw) != v.RawHex {
		return "", fmt.Errorf("fixture integrity: invalid raw hex")
	}
	o, reason := registryParseIntent(raw)
	if reason != "" {
		return reason, nil
	}
	if !registryHex(v.SHA256, 64) || registryHash("YTA-REGISTRY-INTENT-V1\x00", string(raw)) != v.SHA256 {
		return "digest_domain", nil
	}
	if request != nil {
		nonce, ok := registryBase64(registryString(o, "ceremony_nonce"), 32)
		if !ok {
			return "bounds_grammar", nil
		}
		challenge, ok := registryBase64(registryString(request, "challenge"), 32)
		if !ok {
			return "", fmt.Errorf("fixture integrity: invalid challenge")
		}
		if !registryEqual(o, "transition_kind", request, "transition_kind") || !registryEqual(o, "artifact_descriptor_sha256", request, "artifact_descriptor_sha256") || !bytes.Equal(nonce, challenge) || !registryEqual(o, "expires_at", request, "expires_at") {
			return "intent_binding", nil
		}
	}
	return "", nil
}

func readRegistryIntentCorpus(t *testing.T) registryIntentCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/gate1a-registry-intent/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c registryIntentCorpus
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		t.Fatal(err)
	}
	var trailing json.RawMessage
	if d.Decode(&trailing) != io.EOF {
		t.Fatal("trailing intent corpus data")
	}
	if c.SchemaVersion != 1 || c.Scope != "registry-intent-binding" || c.Source.Path != "testdata/gate1a-registry/corpus.json" {
		t.Fatal("unexpected intent corpus schema")
	}
	coreRaw, err := os.ReadFile("../../testdata/gate1a-registry/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	if registryHash("", string(coreRaw)) != c.Source.SHA256 {
		t.Fatal("core corpus source digest mismatch")
	}
	return c
}

func TestRegistryIntentFixtureIntegrity(t *testing.T) {
	cores := registryPositiveMap(t, readRegistryCorpus(t))
	for _, tc := range []struct {
		name, coreID string
		damage       string
	}{
		{"missing core", "absent", ""}, {"missing prefix", "rotate2", "missing"},
		{"invalid full core", "enroll1", "core"}, {"invalid prefix", "rotate2", "prefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyCores := make(map[string]registryPositive, len(cores))
			for id, core := range cores {
				copyCores[id] = core
			}
			switch tc.damage {
			case "missing":
				delete(copyCores, "enroll1")
			case "core":
				core := copyCores["enroll1"]
				core.Proposal = "{}"
				copyCores["enroll1"] = core
			case "prefix":
				core := copyCores["enroll1"]
				core.Record = "{}"
				copyCores["enroll1"] = core
			}
			// Malformed hex would fail later; core integrity must win first.
			reason, err := registryVerifyIntent(registryIntentVector{CoreID: &tc.coreID, RawHex: "not hex"}, copyCores)
			if err == nil || reason != "" || !strings.HasPrefix(err.Error(), "fixture integrity:") || strings.Contains(err.Error(), "raw hex") {
				t.Fatalf("got reason %q, error %v", reason, err)
			}
		})
	}
}

func TestSharedRegistryIntentCorpus(t *testing.T) {
	c := readRegistryIntentCorpus(t)
	cores := registryPositiveMap(t, readRegistryCorpus(t))
	// These literal values and hashes are independent expectations, not facts
	// inferred from fixture labels, their claimed verdicts, or their manifest.
	want := map[string]struct{ core, transition, nonce, expiry, digest string }{
		"intent-enroll1":           {"enroll1", "enroll", "ERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzA", "12:05:00", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67"},
		"intent-rotate2":           {"rotate2", "rotate", "IiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEE", "12:05:00", "e122718b57b090b792ad13ecbb347a0d3181d9e3c1217bd590d061af0cc56c87"},
		"intent-revoke3":           {"revoke3", "revoke", "MzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVI", "12:05:00", "713452b672826409337bbd53668ab09157a265cfe2db5ce2884d33adbb5b387f"},
		"intent-recover-disabled4": {"recover-disabled4", "recover", "REVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmM", "12:05:00", "8ccd7960f14afea3c3efbb4605f4e01c537f39facf4ac7403da19b8b03442612"},
		"intent-recover-active3":   {"recover-active3", "recover", "MzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVI", "12:05:00", "de2c3928d468b22ed606840441758ccfadcae491a17493dc93f8adf8065f51f9"},
		"ttl-1s":                   {"", "enroll", "ERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzA", "12:00:01", "2abebaaa0750eb86ce1cfe7d360742623afca9a49e8b831f20476fbf56014e73"},
		"ttl-300s":                 {"", "enroll", "ERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzA", "12:05:00", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67"},
	}
	var baseRawHex string
	seen := make(map[string]bool)
	for _, v := range c.Positives {
		if v.ID == "intent-enroll1" {
			baseRawHex = v.RawHex
		}
		t.Run(v.ID, func(t *testing.T) {
			p, ok := want[v.ID]
			if !ok || seen[v.ID] {
				t.Fatal("unknown or duplicate positive")
			}
			seen[v.ID] = true
			if (v.CoreID == nil) != (p.core == "") || (v.CoreID != nil && *v.CoreID != p.core) || v.Base != "" || v.ReasonClass != "" {
				t.Fatal("unexpected positive metadata")
			}
			raw := fmt.Sprintf(`{"schema_version":1,"intent_type":"registry_commit","transition_kind":"%s","artifact_descriptor_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ceremony_nonce":"%s","requested_at":"2026-09-01T12:00:00Z","expires_at":"2026-09-01T%sZ"}`, p.transition, p.nonce, p.expiry)
			input := "YTA-REGISTRY-INTENT-V1\x00" + raw
			if v.RawHex != hex.EncodeToString([]byte(raw)) || v.SigningInputHex != hex.EncodeToString([]byte(input)) || v.SHA256 != p.digest || registryHash("", input) != p.digest {
				t.Fatal("positive differs from literal canonical input/hash")
			}
			if reason, err := registryVerifyIntent(v, cores); err != nil || reason != "" {
				t.Fatalf("intent rejected: %q, %v", reason, err)
			}
		})
	}
	if len(seen) != len(want) {
		t.Fatal("missing positive intent")
	}

	expected := make(map[string]string)
	for reason, ids := range map[string]string{
		"canonical_encoding": "canonical-empty canonical-malformed canonical-unknown canonical-duplicate canonical-missing canonical-reordered canonical-whitespace canonical-trailing-lf canonical-bom canonical-trailing-token canonical-escaped-key canonical-escaped-value canonical-invalid-utf8 canonical-schema-string canonical-schema-bool canonical-null canonical-array canonical-object canonical-schema-fraction canonical-schema-exponent canonical-schema-leading-zero canonical-schema-plus canonical-schema-negative-zero canonical-size-1024",
		"bounds_grammar":     "bounds-size-1025 schema-version field-intent-type field-transition field-descriptor-uppercase field-descriptor-short field-descriptor-long field-descriptor-nonhex field-nonce-padding field-nonce-alphabet field-nonce-31-bytes field-nonce-33-bytes field-nonce-pad-bits field-date-offset field-date-fraction field-date-invalid",
		"temporal":           "temporal-zero temporal-negative temporal-301s",
		"digest_domain":      "digest-wrong digest-no-nul digest-wrong-domain digest-plain-hash digest-lf-hash",
		"intent_binding":     "binding-transition binding-descriptor binding-nonce binding-expiry",
	} {
		for _, id := range strings.Fields(ids) {
			expected[id] = reason
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
			if v.ReasonClass != want || v.Base != "intent-enroll1" || v.SigningInputHex != "" {
				t.Fatal("negative metadata differs from independent expectation")
			}
			if (v.CoreID != nil) != (want == "intent_binding") || (v.CoreID != nil && *v.CoreID != "enroll1") {
				t.Fatal("unexpected negative core reference")
			}
			if v.ID == "canonical-bom" {
				if baseRawHex == "" || v.RawHex != "efbbbf"+baseRawHex {
					t.Fatal("BOM vector must prefix the exact base bytes")
				}
				raw, err := hex.DecodeString(v.RawHex)
				if err != nil {
					t.Fatal(err)
				}
				if v.SHA256 != registryHash("YTA-REGISTRY-INTENT-V1\x00", string(raw)) {
					t.Fatal("BOM vector must hash the domain and original bytes")
				}
			}
			if reason, err := registryVerifyIntent(v, cores); err != nil || reason != want {
				t.Fatalf("got %q, %v; want %q", reason, err, want)
			}
		})
	}
	if len(seen) != len(expected) {
		t.Fatal("missing negative intent")
	}
}
