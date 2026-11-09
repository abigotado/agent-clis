//go:build ignore

// Generate synthetic test-only active/intent fixtures independently of runtime codecs.
// Run from the repository root: go run ./testdata/gate1a-registry-active/generate.go [-check].
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const corePath = "testdata/gate1a-registry/corpus.json"
const intentPath = "testdata/gate1a-registry-intent/corpus.json"
const outputPath = "testdata/gate1a-registry-active/corpus.json"
const domain = "YTA-APPLY-COORDINATOR-ACTIVE-V1\x00"

type active struct {
	SchemaVersion              int     `json:"schema_version"`
	RecordType                 string  `json:"record_type"`
	LeaseID                    string  `json:"lease_id"`
	OperationKind              string  `json:"operation_kind"`
	CoordinatorSessionID       string  `json:"coordinator_session_id"`
	CLIAuditTokenSHA256        string  `json:"cli_audit_token_sha256"`
	ArtifactDescriptorSHA256   string  `json:"artifact_descriptor_sha256"`
	AuthorizationContextSHA256 *string `json:"authorization_context_sha256"`
	RegistryRevision           *int    `json:"registry_revision"`
	PlanID                     *string `json:"plan_id"`
	JournalRevision            *int    `json:"journal_revision"`
	ReceiptSHA256              *string `json:"receipt_sha256"`
	RegistryIntentSHA256       string  `json:"registry_intent_sha256"`
	CreatedAt                  string  `json:"created_at"`
	ExpiresAt                  string  `json:"expires_at"`
}
type source struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type positive struct {
	ID              string `json:"id"`
	IntentID        string `json:"intent_id"`
	RawHex          string `json:"raw_hex"`
	SigningInputHex string `json:"signing_input_hex"`
	SHA256          string `json:"sha256"`
}
type negative struct {
	ID          string `json:"id"`
	Base        string `json:"base"`
	IntentID    string `json:"intent_id"`
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

func sum(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func rawActive(a active) (string, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("marshal active: %w", err)
	}
	return string(b), nil
}
func generate() ([]byte, error) {
	coreBytes, err := os.ReadFile(corePath)
	if err != nil {
		return nil, fmt.Errorf("read core: %w", err)
	}
	intentBytes, err := os.ReadFile(intentPath)
	if err != nil {
		return nil, fmt.Errorf("read intent: %w", err)
	}
	var intents struct {
		Positives []struct {
			ID     string `json:"id"`
			RawHex string `json:"raw_hex"`
			SHA256 string `json:"sha256"`
		} `json:"positives"`
	}
	if err := json.Unmarshal(intentBytes, &intents); err != nil {
		return nil, fmt.Errorf("decode intents: %w", err)
	}
	var core struct {
		Positives []struct {
			ID     string `json:"id"`
			Record string `json:"record"`
		} `json:"positives"`
	}
	if err := json.Unmarshal(coreBytes, &core); err != nil {
		return nil, fmt.Errorf("decode core: %w", err)
	}
	wanted := []string{"enroll1", "rotate2", "revoke3", "recover-disabled4", "recover-active3"}
	if len(intents.Positives) != 7 || len(core.Positives) != 5 {
		return nil, fmt.Errorf("unexpected source positive counts")
	}
	c := corpus{SchemaVersion: 1, Scope: "registry-active-intent-binding", Sources: []source{{corePath, sum(string(coreBytes))}, {intentPath, sum(string(intentBytes))}}}
	var first active
	addPositive := func(id, intentID string, a active) error {
		raw, err := rawActive(a)
		if err != nil {
			return err
		}
		c.Positives = append(c.Positives, positive{id, intentID, hex.EncodeToString([]byte(raw)), hex.EncodeToString([]byte(domain + raw)), sum(domain + raw)})
		return nil
	}
	for n, id := range wanted {
		p := intents.Positives[n]
		if p.ID != "intent-"+id || core.Positives[n].ID != id {
			return nil, fmt.Errorf("unexpected source positive order")
		}
		raw, err := hex.DecodeString(p.RawHex)
		if err != nil {
			return nil, fmt.Errorf("decode intent hex: %w", err)
		}
		var i struct {
			ArtifactDescriptorSHA256 string `json:"artifact_descriptor_sha256"`
			RequestedAt              string `json:"requested_at"`
		}
		if err := json.Unmarshal(raw, &i); err != nil {
			return nil, fmt.Errorf("decode intent: %w", err)
		}
		created, err := time.Parse(time.RFC3339, i.RequestedAt)
		if err != nil {
			return nil, fmt.Errorf("parse intent issue: %w", err)
		}
		a := active{SchemaVersion: 1, RecordType: "apply_coordinator_active", LeaseID: "YTAL-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{0x21}, 16)), OperationKind: "registry_commit", CoordinatorSessionID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)), CLIAuditTokenSHA256: strings.Repeat("c", 64), ArtifactDescriptorSHA256: i.ArtifactDescriptorSHA256, RegistryIntentSHA256: p.SHA256, CreatedAt: i.RequestedAt, ExpiresAt: created.Add(600 * time.Second).Format(time.RFC3339)}
		if n == 0 {
			first = a
		}
		if err := addPositive("active-"+id, p.ID, a); err != nil {
			return nil, err
		}
	}
	for _, tc := range []struct{ id, expiry string }{{"ttl-1s", "2026-09-01T12:00:01Z"}, {"ttl-600s", "2026-09-01T12:10:00Z"}} {
		a := first
		a.ExpiresAt = tc.expiry
		if err := addPositive(tc.id, "intent-enroll1", a); err != nil {
			return nil, err
		}
	}
	base, err := rawActive(first)
	if err != nil {
		return nil, err
	}
	add := func(id, raw, reason string) {
		c.Negatives = append(c.Negatives, negative{id, "active-enroll1", "intent-enroll1", hex.EncodeToString([]byte(raw)), sum(domain + raw), reason})
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &fields); err != nil {
		return nil, fmt.Errorf("decode synthetic active fields: %w", err)
	}
	replace := func(field, value string) string {
		return strings.Replace(base, `"`+field+`":`+string(fields[field]), `"`+field+`":`+value, 1)
	}
	for _, tc := range []struct{ id, raw string }{
		{"canonical-empty", ""}, {"canonical-malformed", "{"}, {"canonical-bom", "\xef\xbb\xbf" + base},
		{"canonical-unknown", strings.TrimSuffix(base, "}") + `,"unknown":0}`},
		{"canonical-duplicate", strings.Replace(base, `"schema_version":1,`, `"schema_version":1,"schema_version":1,`, 1)},
		{"canonical-missing", strings.Replace(base, `"record_type":"apply_coordinator_active",`, "", 1)},
		{"canonical-reordered", strings.Replace(base, `"schema_version":1,"record_type":"apply_coordinator_active"`, `"record_type":"apply_coordinator_active","schema_version":1`, 1)},
		{"canonical-whitespace", " " + base}, {"canonical-trailing-lf", base + "\n"}, {"canonical-trailing-token", base + "{}"},
		{"canonical-escaped-key", strings.Replace(base, "schema_version", `schema_\u0076ersion`, 1)},
		{"canonical-escaped-value", strings.Replace(base, "registry_commit", `registry_\u0063ommit`, 1)},
		{"canonical-invalid-utf8", strings.Replace(base, "registry_commit", "registry_\xffcommit", 1)},
		{"canonical-schema-string", replace("schema_version", `"1"`)}, {"canonical-schema-bool", replace("schema_version", "true")},
		{"canonical-null", replace("record_type", "null")}, {"canonical-array", replace("record_type", "[]")}, {"canonical-object", replace("record_type", "{}")},
		{"canonical-forbidden-array", replace("authorization_context_sha256", "[]")},
		{"canonical-forbidden-object", replace("registry_revision", "{}")},
		{"canonical-schema-fraction", replace("schema_version", "1.0")}, {"canonical-schema-exponent", replace("schema_version", "1e0")},
		{"canonical-schema-leading-zero", replace("schema_version", "01")}, {"canonical-schema-plus", replace("schema_version", "+1")}, {"canonical-schema-negative-zero", replace("schema_version", "-0")},
		{"canonical-size-4096", strings.Repeat("x", 4096)},
	} {
		add(tc.id, tc.raw, "canonical_encoding")
	}
	add("bounds-size-4097", strings.Repeat("x", 4097), "bounds_grammar")
	for _, tc := range []struct{ id, field, value string }{
		{"schema-version", "schema_version", "2"}, {"field-record-type", "record_type", `"unknown"`}, {"field-operation-kind", "operation_kind", `"apply"`},
		{"field-lease-prefix", "lease_id", `"BADL-` + first.LeaseID[5:] + `"`},
		{"field-lease-case", "lease_id", `"YTAL-` + strings.ToLower(first.LeaseID[5:]) + `"`},
		{"field-lease-alphabet", "lease_id", `"YTAL-0` + first.LeaseID[6:] + `"`},
		{"field-lease-15-bytes", "lease_id", `"YTAL-` + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{0x21}, 15)) + `"`},
		{"field-lease-17-bytes", "lease_id", `"YTAL-` + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{0x21}, 17)) + `"`},
		{"field-lease-padding", "lease_id", `"` + first.LeaseID + `="`},
		{"field-lease-pad-bits", "lease_id", `"` + first.LeaseID[:30] + `F"`},
		{"field-session-31-bytes", "coordinator_session_id", `"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 31)) + `"`},
		{"field-session-33-bytes", "coordinator_session_id", `"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 33)) + `"`},
		{"field-session-alphabet", "coordinator_session_id", `"+` + first.CoordinatorSessionID[1:] + `"`},
		{"field-session-padding", "coordinator_session_id", `"` + first.CoordinatorSessionID + `="`},
		{"field-session-pad-bits", "coordinator_session_id", `"` + first.CoordinatorSessionID[:42] + `J"`},
	} {
		add(tc.id, replace(tc.field, tc.value), "bounds_grammar")
	}
	for _, field := range []string{"cli_audit_token_sha256", "artifact_descriptor_sha256", "registry_intent_sha256"} {
		add("canonical-"+field+"-null", replace(field, "null"), "canonical_encoding")
		for _, tc := range []struct{ id, value string }{{"empty", ""}, {"short", strings.Repeat("a", 63)}, {"long", strings.Repeat("a", 65)}, {"uppercase", strings.Repeat("A", 64)}, {"nonhex", strings.Repeat("g", 64)}} {
			add("field-"+field+"-"+tc.id, replace(field, `"`+tc.value+`"`), "bounds_grammar")
		}
	}
	for _, tc := range []struct{ field, value string }{{"authorization_context_sha256", `"` + strings.Repeat("d", 64) + `"`}, {"registry_revision", "1"}, {"plan_id", `"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"`}, {"journal_revision", "1"}, {"receipt_sha256", `"` + strings.Repeat("d", 64) + `"`}} {
		add("field-forbidden-"+tc.field, replace(tc.field, tc.value), "bounds_grammar")
	}
	for _, field := range []string{"created_at", "expires_at"} {
		for _, tc := range []struct{ id, value string }{{"offset", "2026-09-01T12:00:00+00:00"}, {"fraction", "2026-09-01T12:00:00.0Z"}, {"invalid", "2026-02-30T12:00:00Z"}} {
			add("field-"+field+"-"+tc.id, replace(field, `"`+tc.value+`"`), "bounds_grammar")
		}
	}
	for _, tc := range []struct{ id, expiry string }{{"temporal-zero", first.CreatedAt}, {"temporal-negative", "2026-09-01T11:59:59Z"}, {"temporal-601s", "2026-09-01T12:10:01Z"}} {
		add(tc.id, replace("expires_at", `"`+tc.expiry+`"`), "temporal")
	}
	for _, tc := range []struct{ id, digest string }{{"digest-wrong", strings.Repeat("0", 64)}, {"digest-no-nul", sum(strings.TrimSuffix(domain, "\x00") + base)}, {"digest-wrong-domain", sum("YTA-REGISTRY-INTENT-V1\x00" + base)}, {"digest-plain-hash", sum(base)}, {"digest-lf-hash", sum(domain + base + "\n")}} {
		add(tc.id, base, "digest_domain")
		c.Negatives[len(c.Negatives)-1].SHA256 = tc.digest
	}
	add("binding-intent", replace("registry_intent_sha256", `"`+strings.Repeat("b", 64)+`"`), "active_binding")
	add("binding-candidate-record", replace("registry_intent_sha256", `"`+sum("YTA-REGISTRY-COMMIT-V1\x00"+core.Positives[0].Record)+`"`), "active_binding")
	add("binding-descriptor", replace("artifact_descriptor_sha256", `"`+strings.Repeat("b", 64)+`"`), "active_binding")
	encoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode active corpus: %w", err)
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
			return fmt.Errorf("read active corpus: %w", err)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("active corpus differs; regenerate with go run ./testdata/gate1a-registry-active/generate.go")
		}
		return nil
	}
	if err := os.WriteFile(outputPath, generated, 0644); err != nil {
		return fmt.Errorf("write active corpus: %w", err)
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
