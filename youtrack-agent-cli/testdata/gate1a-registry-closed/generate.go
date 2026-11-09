//go:build ignore

// Generate synthetic retained-candidate registry close fixtures, not runtime evidence.
// Run from repository root: go run ./testdata/gate1a-registry-closed/generate.go [-check].
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const corePath = "testdata/gate1a-registry/corpus.json"
const intentPath = "testdata/gate1a-registry-intent/corpus.json"
const activePath = "testdata/gate1a-registry-active/corpus.json"
const outputPath = "testdata/gate1a-registry-closed/corpus.json"
const domain = "YTA-APPLY-COORDINATOR-CLOSED-V1\x00"
const commitDomain = "YTA-REGISTRY-COMMIT-V1\x00"

type closed struct {
	SchemaVersion        int     `json:"schema_version"`
	RecordType           string  `json:"record_type"`
	LeaseID              string  `json:"lease_id"`
	ActiveSHA256         string  `json:"active_sha256"`
	PermitSHA256         *string `json:"permit_sha256"`
	ReceiptSHA256        *string `json:"receipt_sha256"`
	OperationKind        string  `json:"operation_kind"`
	TerminalOutcome      string  `json:"terminal_outcome"`
	JournalRevision      *int    `json:"journal_revision"`
	RegistryRecordSHA256 string  `json:"registry_record_sha256"`
	ClosedAt             string  `json:"closed_at"`
	CloseMode            string  `json:"close_mode"`
}
type source struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type positive struct {
	ID              string `json:"id"`
	ActiveID        string `json:"active_id"`
	RawHex          string `json:"raw_hex"`
	SigningInputHex string `json:"signing_input_hex"`
	SHA256          string `json:"sha256"`
}
type negative struct {
	ID          string `json:"id"`
	Base        string `json:"base"`
	ActiveID    string `json:"active_id"`
	RawHex      string `json:"raw_hex"`
	SHA256      string `json:"sha256"`
	ReasonClass string `json:"reason_class"`
}
type corpus struct {
	SchemaVersion int        `json:"schema_version"`
	Scope         string     `json:"scope"`
	Sources       []source   `json:"sources"`
	Positives     []positive `json:"positives"`
	Negatives     []negative `json:"negatives"`
}
type sourcePositive struct {
	ID       string  `json:"id"`
	CoreID   *string `json:"core_id"`
	IntentID string  `json:"intent_id"`
	RawHex   string  `json:"raw_hex"`
	SHA256   string  `json:"sha256"`
	Record   string  `json:"record"`
}

func sum(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func generate() ([]byte, error) {
	c := corpus{SchemaVersion: 1, Scope: "registry-closed-retained-candidate-binding"}
	sources := make(map[string]map[string]sourcePositive)
	for _, path := range []string{corePath, intentPath, activePath} {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read source: %w", err)
		}
		var s struct {
			Positives []sourcePositive `json:"positives"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("decode source: %w", err)
		}
		c.Sources = append(c.Sources, source{path, sum(string(b))})
		sources[path] = make(map[string]sourcePositive)
		for _, p := range s.Positives {
			if _, exists := sources[path][p.ID]; exists {
				return nil, fmt.Errorf("duplicate source ID")
			}
			sources[path][p.ID] = p
		}
	}
	var first closed
	var firstRecord, firstIntentHash string
	for n, id := range []string{"enroll1", "rotate2", "revoke3", "recover-disabled4", "recover-active3"} {
		a, ok := sources[activePath]["active-"+id]
		if !ok {
			return nil, fmt.Errorf("missing active source")
		}
		i, ok := sources[intentPath][a.IntentID]
		if !ok || i.CoreID == nil {
			return nil, fmt.Errorf("missing linked intent")
		}
		r, ok := sources[corePath][*i.CoreID]
		if !ok || r.ID != id || r.Record == "" {
			return nil, fmt.Errorf("missing linked candidate")
		}
		raw, err := hex.DecodeString(a.RawHex)
		if err != nil {
			return nil, fmt.Errorf("decode active hex: %w", err)
		}
		var av struct {
			LeaseID              string `json:"lease_id"`
			RegistryIntentSHA256 string `json:"registry_intent_sha256"`
		}
		if err := json.Unmarshal(raw, &av); err != nil {
			return nil, fmt.Errorf("decode active: %w", err)
		}
		if av.RegistryIntentSHA256 != i.SHA256 || a.SHA256 != sum("YTA-APPLY-COORDINATOR-ACTIVE-V1\x00"+string(raw)) {
			return nil, fmt.Errorf("source digest mismatch")
		}
		v := closed{SchemaVersion: 1, RecordType: "apply_coordinator_closed", LeaseID: av.LeaseID, ActiveSHA256: a.SHA256, OperationKind: "registry_commit", RegistryRecordSHA256: sum(commitDomain + r.Record), ClosedAt: "2026-09-01T12:00:04Z", CloseMode: "normal"}
		for _, outcome := range []struct{ suffix, value string }{{"committed", "registry_committed"}, {"not-committed", "registry_not_committed"}} {
			v.TerminalOutcome = outcome.value
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("marshal closed: %w", err)
			}
			c.Positives = append(c.Positives, positive{"closed-" + id + "-" + outcome.suffix, a.ID, hex.EncodeToString(b), hex.EncodeToString([]byte(domain + string(b))), sum(domain + string(b))})
			if n == 0 && outcome.suffix == "committed" {
				first = v
				firstRecord = r.Record
				firstIntentHash = i.SHA256
			}
		}
	}
	// These exercise date grammar only, not historical closure chronology.
	for _, tc := range []struct{ id, date string }{
		{"date-grammar-year-zero", "0000-01-01T00:00:00Z"},
		{"date-grammar-year-one", "0001-01-01T00:00:00Z"},
		{"date-grammar-year-max", "9999-12-31T23:59:59Z"},
		{"date-grammar-year-zero-leap", "0000-02-29T12:00:00Z"},
		{"date-grammar-century-leap", "2000-02-29T12:00:00Z"},
		{"date-grammar-gregorian-cutover", "1582-10-10T12:00:00Z"},
	} {
		v := first
		v.ClosedAt = tc.date
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal date grammar close: %w", err)
		}
		c.Positives = append(c.Positives, positive{tc.id, "active-enroll1", hex.EncodeToString(b), hex.EncodeToString([]byte(domain + string(b))), sum(domain + string(b))})
	}
	b, err := json.Marshal(first)
	if err != nil {
		return nil, fmt.Errorf("marshal base: %w", err)
	}
	base := string(b)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, fmt.Errorf("decode base fields: %w", err)
	}
	replace := func(field, value string) string {
		return strings.Replace(base, `"`+field+`":`+string(fields[field]), `"`+field+`":`+value, 1)
	}
	add := func(id, raw, reason string) {
		c.Negatives = append(c.Negatives, negative{id, "closed-enroll1-committed", "active-enroll1", hex.EncodeToString([]byte(raw)), sum(domain + raw), reason})
	}
	for _, tc := range []struct{ id, raw string }{
		{"canonical-empty", ""}, {"canonical-malformed", "{"}, {"canonical-bom", "\xef\xbb\xbf" + base},
		{"canonical-unknown", strings.TrimSuffix(base, "}") + `,"unknown":0}`},
		{"canonical-duplicate", strings.Replace(base, `"schema_version":1,`, `"schema_version":1,"schema_version":1,`, 1)},
		{"canonical-missing", strings.Replace(base, `"record_type":"apply_coordinator_closed",`, "", 1)},
		{"canonical-reordered", strings.Replace(base, `"schema_version":1,"record_type":"apply_coordinator_closed"`, `"record_type":"apply_coordinator_closed","schema_version":1`, 1)},
		{"canonical-whitespace", " " + base}, {"canonical-trailing-lf", base + "\n"}, {"canonical-trailing-token", base + "{}"},
		{"canonical-escaped-key", strings.Replace(base, "schema_version", `schema_\u0076ersion`, 1)},
		{"canonical-escaped-value", strings.Replace(base, "registry_commit", `registry_\u0063ommit`, 1)},
		{"canonical-invalid-utf8", strings.Replace(base, "registry_commit", "registry_\xffcommit", 1)},
		{"canonical-schema-string", replace("schema_version", `"1"`)}, {"canonical-schema-bool", replace("schema_version", "true")},
		{"canonical-null", replace("record_type", "null")}, {"canonical-array", replace("record_type", "[]")}, {"canonical-object", replace("record_type", "{}")},
		{"canonical-schema-fraction", replace("schema_version", "1.0")}, {"canonical-schema-exponent", replace("schema_version", "1e0")},
		{"canonical-schema-leading-zero", replace("schema_version", "01")}, {"canonical-schema-plus", replace("schema_version", "+1")}, {"canonical-schema-negative-zero", replace("schema_version", "-0")},
		{"canonical-size-4096", strings.Repeat("x", 4096)},
	} {
		add(tc.id, tc.raw, "canonical_encoding")
	}
	add("bounds-size-4097", strings.Repeat("x", 4097), "bounds_grammar")
	for _, tc := range []struct{ id, value string }{
		{"true", "true"}, {"false", "false"}, {"integer", "0"}, {"fraction", "1.0"}, {"array", "[]"}, {"object", "{}"},
	} {
		raw := replace("registry_record_sha256", tc.value)
		add("canonical-candidate-"+tc.id, raw, "canonical_encoding")
		add("canonical-candidate-"+tc.id+"-apply", strings.Replace(raw, `"operation_kind":"registry_commit"`, `"operation_kind":"apply"`, 1), "canonical_encoding")
		add("canonical-candidate-"+tc.id+"-close-mode", strings.Replace(raw, `"close_mode":"normal"`, `"close_mode":"unknown"`, 1), "canonical_encoding")
	}
	add("field-candidate-committed-null", replace("registry_record_sha256", "null"), "bounds_grammar")
	for _, tc := range []struct{ id, field, value string }{
		{"schema-version", "schema_version", "2"}, {"field-record-type", "record_type", `"unknown"`}, {"field-operation-kind", "operation_kind", `"unknown"`},
		{"field-terminal-outcome", "terminal_outcome", `"unknown"`}, {"field-close-mode", "close_mode", `"unknown"`},
		{"field-lease-prefix", "lease_id", `"BADL-` + first.LeaseID[5:] + `"`},
		{"field-lease-case", "lease_id", `"YTAL-` + strings.ToLower(first.LeaseID[5:]) + `"`},
		{"field-lease-alphabet", "lease_id", `"YTAL-0` + first.LeaseID[6:] + `"`},
		{"field-lease-15-bytes", "lease_id", `"YTAL-` + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{0x21}, 15)) + `"`},
		{"field-lease-17-bytes", "lease_id", `"YTAL-` + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{0x21}, 17)) + `"`},
		{"field-lease-padding", "lease_id", `"` + first.LeaseID + `="`},
		{"field-lease-pad-bits", "lease_id", `"` + first.LeaseID[:30] + `F"`},
	} {
		add(tc.id, replace(tc.field, tc.value), "bounds_grammar")
	}
	for _, field := range []string{"active_sha256", "registry_record_sha256"} {
		// The committed-null refusal is covered separately; not-committed null is deferred.
		if field == "active_sha256" {
			add("canonical-active_sha256-null", replace(field, "null"), "canonical_encoding")
		}
		for _, tc := range []struct{ id, value string }{{"empty", ""}, {"short", strings.Repeat("a", 63)}, {"long", strings.Repeat("a", 65)}, {"uppercase", strings.Repeat("A", 64)}, {"nonhex", strings.Repeat("g", 64)}} {
			add("field-"+field+"-"+tc.id, replace(field, `"`+tc.value+`"`), "bounds_grammar")
		}
	}
	for _, field := range []string{"permit_sha256", "receipt_sha256", "journal_revision"} {
		value := `"` + strings.Repeat("d", 64) + `"`
		if field == "journal_revision" {
			value = "1"
		}
		add("field-forbidden-"+field, replace(field, value), "bounds_grammar")
		add("canonical-"+field+"-array", replace(field, "[]"), "canonical_encoding")
		add("canonical-"+field+"-object", replace(field, "{}"), "canonical_encoding")
	}
	for _, tc := range []struct{ id, value string }{
		{"offset", "2026-09-01T12:00:04+00:00"}, {"fraction", "2026-09-01T12:00:04.0Z"}, {"invalid", "2026-02-30T12:00:04Z"},
		{"century-nonleap", "1900-02-29T12:00:00Z"}, {"year-zero-invalid-day", "0000-02-30T12:00:00Z"},
	} {
		add("field-closed_at-"+tc.id, replace("closed_at", `"`+tc.value+`"`), "bounds_grammar")
	}
	for _, tc := range []struct{ id, digest string }{{"digest-wrong", strings.Repeat("0", 64)}, {"digest-no-nul", sum(strings.TrimSuffix(domain, "\x00") + base)}, {"digest-wrong-domain", sum("YTA-APPLY-COORDINATOR-ACTIVE-V1\x00" + base)}, {"digest-plain-hash", sum(base)}, {"digest-lf-hash", sum(domain + base + "\n")}} {
		add(tc.id, base, "digest_domain")
		c.Negatives[len(c.Negatives)-1].SHA256 = tc.digest
	}
	add("binding-lease", replace("lease_id", `"YTAL-`+base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{0x22}, 16))+`"`), "closed_binding")
	add("binding-active", replace("active_sha256", `"`+strings.Repeat("b", 64)+`"`), "closed_binding")
	add("binding-candidate", replace("registry_record_sha256", `"`+strings.Repeat("b", 64)+`"`), "closed_binding")
	add("binding-candidate-plain-hash", replace("registry_record_sha256", `"`+sum(firstRecord)+`"`), "closed_binding")
	add("binding-candidate-intent", replace("registry_record_sha256", `"`+firstIntentHash+`"`), "closed_binding")
	encoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode closed corpus: %w", err)
	}
	return append(encoded, '\n'), nil
}
func run() error {
	check := flag.Bool("check", false, "verify committed corpus without writing")
	flag.Parse()
	generated, err := generate()
	if err != nil {
		return err
	}
	if *check {
		current, err := os.ReadFile(outputPath)
		if err != nil {
			return fmt.Errorf("read closed corpus: %w", err)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("closed corpus differs; regenerate with go run ./testdata/gate1a-registry-closed/generate.go")
		}
		return nil
	}
	if err := os.WriteFile(outputPath, generated, 0644); err != nil {
		return fmt.Errorf("write closed corpus: %w", err)
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
