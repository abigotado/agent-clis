package approval

// Test-only retained-candidate oracle: supplied linkage is not evidence of an
// owner's quiescence, a durable close, chronology, or a verified outcome.
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

type registryClosedVector struct {
	ID              string `json:"id"`
	ActiveID        string `json:"active_id"`
	RawHex          string `json:"raw_hex"`
	SigningInputHex string `json:"signing_input_hex,omitempty"`
	SHA256          string `json:"sha256"`
	Base            string `json:"base,omitempty"`
	ReasonClass     string `json:"reason_class,omitempty"`
}

type registryClosedCorpus struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	Sources       []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"sources"`
	Positives []registryClosedVector `json:"positives"`
	Negatives []registryClosedVector `json:"negatives"`
}

func registryActivePositiveMap(t *testing.T) map[string]registryActiveVector {
	t.Helper()
	m := make(map[string]registryActiveVector)
	for _, v := range readRegistryActiveCorpus(t).Positives {
		if _, exists := m[v.ID]; exists {
			t.Fatal("duplicate active fixture")
		}
		m[v.ID] = v
	}
	return m
}

func readRegistryClosedCorpus(t *testing.T) registryClosedCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/gate1a-registry-closed/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c registryClosedCorpus
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		t.Fatal(err)
	}
	var trailing json.RawMessage
	if d.Decode(&trailing) != io.EOF {
		t.Fatal("trailing closed corpus data")
	}
	if c.SchemaVersion != 1 || c.Scope != "registry-closed-retained-candidate-binding" || len(c.Sources) != 3 {
		t.Fatal("unexpected closed corpus schema")
	}
	for i, want := range []struct{ path, digest string }{
		{"testdata/gate1a-registry/corpus.json", "b0fbce184a136c8b20689d51bb9eae0a46ecf510447c78a45728f8f4d88fde61"},
		{"testdata/gate1a-registry-intent/corpus.json", "ef65c0ae8132a37a0d6a04be2ba742537fa56ac78f32d4ce537f94c363557a05"},
		{"testdata/gate1a-registry-active/corpus.json", "5fbe731e9ffa05c340586d0210d2a07ee7778e49c0d157d8d277cc029cb828c0"},
	} {
		if c.Sources[i].Path != want.path || c.Sources[i].SHA256 != want.digest {
			t.Fatal("unexpected closed source pin")
		}
		b, err := os.ReadFile("../../" + want.path)
		if err != nil {
			t.Fatal(err)
		}
		if registryHash("", string(b)) != want.digest {
			t.Fatal("closed source digest mismatch")
		}
	}
	return c
}

func TestRegistryClosedFixtureIntegrity(t *testing.T) {
	for _, damage := range []string{"missing active", "invalid active", "invalid active digest", "invalid active binding", "missing intent", "unlinked intent", "invalid intent", "missing core", "invalid core", "missing prefix", "invalid prefix"} {
		t.Run(damage, func(t *testing.T) {
			actives := registryActivePositiveMap(t)
			intents := registryIntentPositiveMap(t)
			cores := registryPositiveMap(t, readRegistryCorpus(t))
			a := actives["active-rotate2"]
			in := intents["intent-rotate2"]
			core := cores["rotate2"]
			prefix := cores["enroll1"]
			switch damage {
			case "missing active":
				delete(actives, "active-rotate2")
			case "invalid active":
				a.RawHex = hex.EncodeToString([]byte("UNTRUSTED_SENTINEL"))
				actives[a.ID] = a
			case "invalid active digest":
				a.SHA256 = strings.Repeat("0", 64)
				actives[a.ID] = a
			case "invalid active binding":
				a.IntentID = "intent-enroll1"
				actives[a.ID] = a
			case "missing intent":
				delete(intents, "intent-rotate2")
			case "unlinked intent":
				in.CoreID = nil
				intents[in.ID] = in
			case "invalid intent":
				in.RawHex = hex.EncodeToString([]byte("UNTRUSTED_SENTINEL"))
				intents[in.ID] = in
			case "missing core":
				delete(cores, "rotate2")
			case "invalid core":
				core.Record = "UNTRUSTED_SENTINEL"
				cores[core.ID] = core
			case "missing prefix":
				delete(cores, "enroll1")
			case "invalid prefix":
				prefix.Record = "UNTRUSTED_SENTINEL"
				cores[prefix.ID] = prefix
			}
			reason, err := registryVerifyRetainedCandidateClosed(registryClosedVector{ActiveID: "active-rotate2", RawHex: "not hex"}, actives, intents, cores)
			want := "fixture integrity: invalid active or ancestry"
			if damage == "missing active" {
				want = "fixture integrity: missing active"
			}
			if reason != "" || err == nil || err.Error() != want {
				t.Fatalf("got %q, %v; want fixed fixture error", reason, err)
			}
		})
	}
}

func registryParseRetainedCandidateClosed(raw []byte) (registryObject, string, error) {
	if len(raw) > 4096 {
		return nil, "bounds_grammar", nil
	}
	if !utf8.Valid(raw) {
		return nil, "canonical_encoding", nil
	}
	var o registryObject
	if json.Unmarshal(raw, &o) != nil || o == nil {
		return nil, "canonical_encoding", nil
	}
	fields := strings.Fields("schema_version record_type lease_id active_sha256 permit_sha256 receipt_sha256 operation_kind terminal_outcome journal_revision registry_record_sha256 closed_at close_mode")
	if len(o) != len(fields) {
		return nil, "canonical_encoding", nil
	}
	for _, f := range fields {
		if _, ok := o[f]; !ok {
			return nil, "canonical_encoding", nil
		}
	}
	if !bytes.Equal(raw, registryObjectBytes(o, fields)) {
		return nil, "canonical_encoding", nil
	}
	for _, f := range fields {
		value := string(o[f])
		switch f {
		case "permit_sha256", "receipt_sha256", "journal_revision":
			if value == "null" || value == "true" || value == "false" || registryIntegerToken(value) {
				continue
			}
		case "registry_record_sha256":
			if value == "null" {
				continue
			}
		case "schema_version":
			if !registryIntegerToken(value) {
				return nil, "canonical_encoding", nil
			}
			continue
		}
		var s string
		if value == "null" || json.Unmarshal(o[f], &s) != nil || value != `"`+s+`"` {
			return nil, "canonical_encoding", nil
		}
		for i := range s {
			if s[i] < 0x20 || s[i] > 0x7e || s[i] == '\\' {
				return nil, "canonical_encoding", nil
			}
		}
	}
	if string(o["schema_version"]) != "1" || registryString(o, "record_type") != "apply_coordinator_closed" || registryString(o, "close_mode") != "normal" {
		return nil, "bounds_grammar", nil
	}
	op := registryString(o, "operation_kind")
	if op == "apply" {
		return nil, "", fmt.Errorf("test scope: apply close unsupported")
	}
	if op != "registry_commit" {
		return nil, "bounds_grammar", nil
	}
	switch registryString(o, "terminal_outcome") {
	case "registry_committed", "registry_not_committed":
	case "ambiguous", "failed_before_mutation", "applied":
		return nil, "", fmt.Errorf("test scope: outcome unsupported")
	default:
		return nil, "bounds_grammar", nil
	}
	if string(o["registry_record_sha256"]) == "null" {
		if registryString(o, "terminal_outcome") == "registry_committed" {
			return nil, "bounds_grammar", nil
		}
		return nil, "", fmt.Errorf("test scope: missing retained candidate")
	}
	for _, f := range []string{"permit_sha256", "receipt_sha256", "journal_revision"} {
		if string(o[f]) != "null" {
			return nil, "bounds_grammar", nil
		}
	}
	if protocolvalue.ValidateCanonicalBase32ID(registryString(o, "lease_id"), "YTAL-") != nil {
		return nil, "bounds_grammar", nil
	}
	for _, f := range []string{"active_sha256", "registry_record_sha256"} {
		if !registryHex(registryString(o, f), 64) {
			return nil, "bounds_grammar", nil
		}
	}
	s := registryString(o, "closed_at")
	when, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil || when.Format("2006-01-02T15:04:05Z") != s {
		return nil, "bounds_grammar", nil
	}
	return o, "", nil
}

func registryVerifyRetainedCandidateClosed(v registryClosedVector, actives map[string]registryActiveVector, intents map[string]registryIntentVector, cores map[string]registryPositive) (string, error) {
	active, ok := actives[v.ActiveID]
	if !ok {
		return "", fmt.Errorf("fixture integrity: missing active")
	}
	if reason, err := registryVerifyActive(active, intents, cores); err != nil || reason != "" {
		return "", fmt.Errorf("fixture integrity: invalid active or ancestry")
	}
	activeRaw, err := hex.DecodeString(active.RawHex)
	if err != nil {
		return "", fmt.Errorf("fixture integrity: invalid active hex")
	}
	parsedActive, reason := registryParseActive(activeRaw)
	if reason != "" {
		return "", fmt.Errorf("fixture integrity: invalid active")
	}
	intent := intents[active.IntentID]
	if intent.CoreID == nil {
		return "", fmt.Errorf("fixture integrity: missing candidate reference")
	}
	core, ok := cores[*intent.CoreID]
	if !ok {
		return "", fmt.Errorf("fixture integrity: missing candidate")
	}
	candidate := registryHash("YTA-REGISTRY-COMMIT-V1\x00", core.Record)
	raw, err := hex.DecodeString(v.RawHex)
	if err != nil || hex.EncodeToString(raw) != v.RawHex {
		return "", fmt.Errorf("fixture integrity: invalid closed hex")
	}
	o, reason, err := registryParseRetainedCandidateClosed(raw)
	if reason != "" || err != nil {
		return reason, err
	}
	if !registryHex(v.SHA256, 64) || registryHash("YTA-APPLY-COORDINATOR-CLOSED-V1\x00", string(raw)) != v.SHA256 {
		return "digest_domain", nil
	}
	if !registryEqual(o, "lease_id", parsedActive, "lease_id") || registryString(o, "active_sha256") != active.SHA256 || registryString(o, "registry_record_sha256") != candidate {
		return "closed_binding", nil
	}
	return "", nil
}

func TestSharedRegistryClosedCorpus(t *testing.T) {
	c := readRegistryClosedCorpus(t)
	actives := registryActivePositiveMap(t)
	intents := registryIntentPositiveMap(t)
	cores := registryPositiveMap(t, readRegistryCorpus(t))
	// Independent literal pins constrain every byte without trusting generator verdicts.
	pins := map[string]struct{ active, candidate, committed, notCommitted string }{
		"enroll1":           {"caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942", "f86e37d14900784636e841daa65e31d16d39e0b7c5be24f07c84e95d825ba9b9", "862b4c9b20628832198090aa3082c10a1bd9ca52f4ab15bd75e7a1af0c2f8986", "1c1c35708d77a8a956ae1e2aa20bc2f3172b7809c6e2df8595e819da7e21eefb"},
		"rotate2":           {"c8212115dbfedbcc7e4f62a95b507d1f06eba6646029f0fb3bb70e44af8e5188", "85a529ae814b7df9bd079efa80105bb3ff88d016e0666777e8e9b9a59c1252e6", "5f54cb81201abe1d6306eed060fdff599bd8c6d279a8efa143e0a46f32468f29", "ad21d8367f65a5b96a827e0f8c79b6ea8b41074da38c018e9520149a3def6c4a"},
		"revoke3":           {"3501fae949ef93dbac4c8fa779eb79f63e71f8f564439188bbd0ecf450d0651b", "4e79377de06250b3f7beb7bff3d6ecee8ddec8010cdae1b16735f97b3b72a8c4", "74af1573fe30eea94c59f065aa19cadef85df665264986c5ebfbc3636e932a3f", "86e7f921d60a17bd5ec3ed1e7d9abbe9b3efcabc91c1bbcb3bb8d888ecfa019c"},
		"recover-disabled4": {"2a80ebbe805fef70364c30ab4ceca1aa420fc0aadb45fbd4aa32ac97d33a8116", "b009d402b328c95af51abd92b84555e4d42cb66a39f73b6b8642f2638eb9ae8c", "0b397898c96502e8da09496147a64b4f22f7604737ed3e3d06e29e159e58bf30", "d3a12fb30d66fe2b58b2c44076f662fbcf2d77344673b3b3031b59f39341eb95"},
		"recover-active3":   {"fcd9911c103141b81e6319ca67898f298f3e3efa5a6ba101c127ccfe2ee86905", "60d954ac63dd2d4fa7a83b389f97f9352cab52b4285c4ad08c70008ed60d4797", "c1980fba695ea5f1ab25ab333676f9b0f6dc298ee3f930fd4a64a3bba56de847", "0c16b9285a6ffb792295f3bebae550d3fd2b218e977a7aacae8e20c0890d3323"},
	}
	type pin struct{ active, raw, digest string }
	want := make(map[string]pin)
	for id, p := range pins {
		for suffix, digest := range map[string]string{"committed": p.committed, "not-committed": p.notCommitted} {
			outcome := "registry_" + strings.ReplaceAll(suffix, "-", "_")
			raw := fmt.Sprintf(`{"schema_version":1,"record_type":"apply_coordinator_closed","lease_id":"YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE","active_sha256":"%s","permit_sha256":null,"receipt_sha256":null,"operation_kind":"registry_commit","terminal_outcome":"%s","journal_revision":null,"registry_record_sha256":"%s","closed_at":"2026-09-01T12:00:04Z","close_mode":"normal"}`, p.active, outcome, p.candidate)
			want["closed-"+id+"-"+suffix] = pin{"active-" + id, raw, digest}
		}
	}
	for _, p := range []struct{ id, date, digest string }{
		{"date-grammar-year-zero", "0000-01-01T00:00:00Z", "13a0fdbda3f28cf415fbf39db457773bbace1e04249bca66d3e38d44545d45e7"},
		{"date-grammar-year-one", "0001-01-01T00:00:00Z", "10fae6f87684b87ef066a3123a137644bbb2fcbaa82b74f6f41943e164e6ae21"},
		{"date-grammar-year-max", "9999-12-31T23:59:59Z", "3c6aca19e8f8284c539673a20908657d7a5bbab42552ab382ab3c5a25fe30e54"},
		{"date-grammar-year-zero-leap", "0000-02-29T12:00:00Z", "b24c73a9463e57994632d19920bd3c176b150f7d332d04c9180c91ab60775bcb"},
		{"date-grammar-century-leap", "2000-02-29T12:00:00Z", "f5e8eea4ef783fceb9e684dd5a976a2901a800d17aa8582645fab6d3f73be8ff"},
		{"date-grammar-gregorian-cutover", "1582-10-10T12:00:00Z", "13a3e41224954cc7d898bbb71aa4ac684eb0680e1356c2545df4b2fbb6cd667c"},
	} {
		raw := strings.Replace(want["closed-enroll1-committed"].raw, "2026-09-01T12:00:04Z", p.date, 1)
		want[p.id] = pin{"active-enroll1", raw, p.digest}
	}
	seen := make(map[string]bool)
	for _, v := range c.Positives {
		t.Run(v.ID, func(t *testing.T) {
			p, ok := want[v.ID]
			if !ok || seen[v.ID] {
				t.Fatal("unknown or duplicate positive")
			}
			seen[v.ID] = true
			input := "YTA-APPLY-COORDINATOR-CLOSED-V1\x00" + p.raw
			if v.ActiveID != p.active || v.Base != "" || v.ReasonClass != "" || v.RawHex != hex.EncodeToString([]byte(p.raw)) || v.SigningInputHex != hex.EncodeToString([]byte(input)) || v.SHA256 != p.digest || registryHash("", input) != p.digest {
				t.Fatal("positive differs from literal bytes/hash/reference")
			}
			if reason, err := registryVerifyRetainedCandidateClosed(v, actives, intents, cores); err != nil || reason != "" {
				t.Fatalf("closed rejected: %q, %v", reason, err)
			}
		})
	}
	if len(seen) != len(want) {
		t.Fatal("missing positive close")
	}
	expected := make(map[string]string)
	for reason, ids := range map[string]string{
		"canonical_encoding": "canonical-empty canonical-malformed canonical-bom canonical-unknown canonical-duplicate canonical-missing canonical-reordered canonical-whitespace canonical-trailing-lf canonical-trailing-token canonical-escaped-key canonical-escaped-value canonical-invalid-utf8 canonical-schema-string canonical-schema-bool canonical-null canonical-array canonical-object canonical-schema-fraction canonical-schema-exponent canonical-schema-leading-zero canonical-schema-plus canonical-schema-negative-zero canonical-size-4096 canonical-active_sha256-null",
		"bounds_grammar":     "bounds-size-4097 schema-version field-record-type field-operation-kind field-terminal-outcome field-close-mode field-lease-prefix field-lease-case field-lease-alphabet field-lease-15-bytes field-lease-17-bytes field-lease-padding field-lease-pad-bits field-closed_at-offset field-closed_at-fraction field-closed_at-invalid field-closed_at-century-nonleap field-closed_at-year-zero-invalid-day",
		"digest_domain":      "digest-wrong digest-no-nul digest-wrong-domain digest-plain-hash digest-lf-hash",
		"closed_binding":     "binding-lease binding-active binding-candidate binding-candidate-plain-hash binding-candidate-intent",
	} {
		for _, id := range strings.Fields(ids) {
			expected[id] = reason
		}
	}
	for _, f := range []string{"active_sha256", "registry_record_sha256"} {
		for _, suffix := range []string{"empty", "short", "long", "uppercase", "nonhex"} {
			expected["field-"+f+"-"+suffix] = "bounds_grammar"
		}
	}
	for _, f := range []string{"permit_sha256", "receipt_sha256", "journal_revision"} {
		expected["field-forbidden-"+f] = "bounds_grammar"
		for _, suffix := range []string{"array", "object"} {
			expected["canonical-"+f+"-"+suffix] = "canonical_encoding"
		}
	}
	base := want["closed-enroll1-committed"].raw
	candidatePins := map[string]pin{}
	for _, tc := range []struct{ id, value, isolated, apply, mode string }{
		{"true", "true", "7dac967f7b7ad5626d3cf3221128f8f6a5c0ae8fd3a9a546986f9ad43b1032e0", "876388ef077b0e40dbf16ad5250892b75d1aac0bcdc14e4a329c2a7a0cd3d84a", "27b9a4e70f94e872106480d21d18123cc8a7a7d0942e166fe6cbfb7a6a85b195"},
		{"false", "false", "fb64061e3fcaaec1796cf2049eceb77c1bff7c27b48d8492bed62dd968000092", "c1470ee32498e27c8aee428fd222a27c2301a52a7dfef0841845e21e3c6799ef", "7b35f07705b730b6115901bc4aa368ab14c2827bfa13bc167558ea8ad8ae866a"},
		{"integer", "0", "9deb863679c21330dcdbe52ccd696385b84013052ae847cd996f9a600903fc4d", "c3a4b5da8d4b9032d76ae68277bdfcc96c1ef2b49db60f1b94683dbf0ab48f4e", "23c215f5298501023ebfc6486dcaf9d19984d733ed68b0a920e36acf4bb51f0e"},
		{"fraction", "1.0", "4dfc72c6e862d7bf2f076960aa3cb6c4d3a27005ff303648a2f24fa685faa344", "e423c2a7adfcdf3c0a4176baa39d145a9be052d59ca8182c0d1a3851787ca19a", "f75a753518a80ea1eb2b5bbc1e69d402ea5dc1adef5555319538334d7606ff55"},
		{"array", "[]", "ea41a04f4899a2dba334611000a303f2ca039341fa70d799f0c45de6a97e003f", "c6fbe9ca369e14bbd4a0cc1335fdd0d65c173dc3704588b7a4afbe3fc415e33e", "94821943b0c58fc2ab6175976886593170690f96224240462d2617052bb4c4db"},
		{"object", "{}", "b73c1081adc7a5a8d967819691594836b02667f34471241d933eca3be7861542", "219865277faec7646e5cacfba7ddcc3694ada6ed08e2e8c5e4482668c422233e", "a0dc8b6722fa8da8d5dbf29dce46080fddfce7bd385d98c21f714a5f3d2667ba"},
	} {
		raw := strings.Replace(base, `"registry_record_sha256":"`+pins["enroll1"].candidate+`"`, `"registry_record_sha256":`+tc.value, 1)
		candidatePins["canonical-candidate-"+tc.id] = pin{raw: raw, digest: tc.isolated}
		candidatePins["canonical-candidate-"+tc.id+"-apply"] = pin{raw: strings.Replace(raw, `"operation_kind":"registry_commit"`, `"operation_kind":"apply"`, 1), digest: tc.apply}
		candidatePins["canonical-candidate-"+tc.id+"-close-mode"] = pin{raw: strings.Replace(raw, `"close_mode":"normal"`, `"close_mode":"unknown"`, 1), digest: tc.mode}
	}
	for id := range candidatePins {
		expected[id] = "canonical_encoding"
	}
	candidatePins["field-candidate-committed-null"] = pin{raw: strings.Replace(base, `"registry_record_sha256":"`+pins["enroll1"].candidate+`"`, `"registry_record_sha256":null`, 1), digest: "94c3d9cf3c4790a1526ed5d339301b537fbc646ca16cbda4d95c394770ec1a67"}
	expected["field-candidate-committed-null"] = "bounds_grammar"
	seen = make(map[string]bool)
	for _, v := range c.Negatives {
		t.Run(v.ID, func(t *testing.T) {
			wantReason, ok := expected[v.ID]
			if !ok || seen[v.ID] {
				t.Fatal("unknown or duplicate negative")
			}
			seen[v.ID] = true
			if v.ReasonClass != wantReason || v.Base != "closed-enroll1-committed" || v.ActiveID != "active-enroll1" || v.SigningInputHex != "" {
				t.Fatal("unexpected negative metadata")
			}
			raw, err := hex.DecodeString(v.RawHex)
			if err != nil {
				t.Fatal(err)
			}
			if wantReason != "digest_domain" && v.SHA256 != registryHash("YTA-APPLY-COORDINATOR-CLOSED-V1\x00", string(raw)) {
				t.Fatal("negative must hash original bytes")
			}
			var exact string
			if p, ok := candidatePins[v.ID]; ok {
				exact = p.raw
				if v.SHA256 != p.digest {
					t.Fatal("candidate primitive vector differs from literal digest")
				}
			}
			switch v.ID {
			case "canonical-bom":
				exact = "\xef\xbb\xbf" + base
			case "field-lease-case":
				exact = strings.Replace(base, "YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE", "YTAL-eeqscijbeeqscijbeeqscijbee", 1)
			case "field-closed_at-century-nonleap":
				exact = strings.Replace(base, "2026-09-01T12:00:04Z", "1900-02-29T12:00:00Z", 1)
				if v.SHA256 != "b04bf7a78452a85c87d9df1f3542ba349cd09518a814b5b23dbdfbe8fcf65d57" {
					t.Fatal("century non-leap digest differs from literal pin")
				}
			case "field-closed_at-year-zero-invalid-day":
				exact = strings.Replace(base, "2026-09-01T12:00:04Z", "0000-02-30T12:00:00Z", 1)
				if v.SHA256 != "89739181ca2de095ea4c101feecf577ccc8c30a89e8c1096205f7a6acac05b3b" {
					t.Fatal("year-zero invalid-day digest differs from literal pin")
				}
			case "binding-candidate-plain-hash":
				exact = strings.Replace(base, pins["enroll1"].candidate, registryHash("", cores["enroll1"].Record), 1)
			case "binding-candidate-intent":
				exact = strings.Replace(base, pins["enroll1"].candidate, "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", 1)
			}
			if exact != "" && string(raw) != exact {
				t.Fatal("boundary vector differs from exact required replacement")
			}
			if reason, err := registryVerifyRetainedCandidateClosed(v, actives, intents, cores); err != nil || reason != wantReason {
				t.Fatalf("got %q, %v; want %q", reason, err, wantReason)
			}
		})
	}
	if len(seen) != len(expected) {
		t.Fatal("missing negative close")
	}
}

func TestRegistryClosedScopeAndOpaqueErrors(t *testing.T) {
	c := readRegistryClosedCorpus(t)
	actives := registryActivePositiveMap(t)
	intents := registryIntentPositiveMap(t)
	cores := registryPositiveMap(t, readRegistryCorpus(t))
	base := c.Positives[0]
	raw, err := hex.DecodeString(base.RawHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, replacement, want string }{
		{"apply", `"operation_kind":"registry_commit"`, `"operation_kind":"apply"`, "test scope: apply close unsupported"},
		{"ambiguous", `"terminal_outcome":"registry_committed"`, `"terminal_outcome":"ambiguous"`, "test scope: outcome unsupported"},
		{"applied", `"terminal_outcome":"registry_committed"`, `"terminal_outcome":"applied"`, "test scope: outcome unsupported"},
		{"failed", `"terminal_outcome":"registry_committed"`, `"terminal_outcome":"failed_before_mutation"`, "test scope: outcome unsupported"},
		{"pre-candidate", `"registry_record_sha256":"f86e37d14900784636e841daa65e31d16d39e0b7c5be24f07c84e95d825ba9b9"`, `"registry_record_sha256":null`, "test scope: missing retained candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			altered := strings.Replace(string(raw), tc.old, tc.replacement, 1)
			if tc.name == "pre-candidate" {
				altered = strings.Replace(altered, "registry_committed", "registry_not_committed", 1)
			}
			v.RawHex = hex.EncodeToString([]byte(altered))
			v.SHA256 = registryHash("YTA-APPLY-COORDINATOR-CLOSED-V1\x00", altered)
			reason, err := registryVerifyRetainedCandidateClosed(v, actives, intents, cores)
			if reason != "" || err == nil || err.Error() != tc.want {
				t.Fatalf("got %q, %v; want scope error", reason, err)
			}
		})
	}
	for _, altered := range []string{`{"UNTRUSTED_SENTINEL":`, strings.Replace(string(raw), `"schema_version":1`, `"schema_version":99999999999999999999999999UNTRUSTED_SENTINEL`, 1)} {
		v := base
		v.RawHex = hex.EncodeToString([]byte(altered))
		reason, err := registryVerifyRetainedCandidateClosed(v, actives, intents, cores)
		if reason != "canonical_encoding" || err != nil {
			t.Fatalf("untrusted target must produce fixed canonical reason: %q, %v", reason, err)
		}
	}
}
