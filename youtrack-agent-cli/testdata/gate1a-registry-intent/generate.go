//go:build ignore

// Generate the synthetic, test-only registry intent corpus from immutable core
// positives. Run from the repository root: go run ./testdata/gate1a-registry-intent/generate.go [-check].
// This generator uses only the standard library and never invokes a runtime codec.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const sourcePath = "testdata/gate1a-registry/corpus.json"
const outputPath = "testdata/gate1a-registry-intent/corpus.json"
const domain = "YTA-REGISTRY-INTENT-V1\x00"

type intent struct {
	SchemaVersion            int    `json:"schema_version"`
	IntentType               string `json:"intent_type"`
	TransitionKind           string `json:"transition_kind"`
	ArtifactDescriptorSHA256 string `json:"artifact_descriptor_sha256"`
	CeremonyNonce            string `json:"ceremony_nonce"`
	RequestedAt              string `json:"requested_at"`
	ExpiresAt                string `json:"expires_at"`
}
type positive struct {
	ID              string  `json:"id"`
	CoreID          *string `json:"core_id"`
	RawHex          string  `json:"raw_hex"`
	SigningInputHex string  `json:"signing_input_hex"`
	SHA256          string  `json:"sha256"`
}
type negative struct {
	ID          string  `json:"id"`
	Base        string  `json:"base"`
	CoreID      *string `json:"core_id"`
	RawHex      string  `json:"raw_hex"`
	SHA256      string  `json:"sha256"`
	ReasonClass string  `json:"reason_class"`
}
type corpus struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	Source        struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"source"`
	Positives []positive `json:"positives"`
	Negatives []negative `json:"negatives"`
}

func sum(raw string) string { d := sha256.Sum256([]byte(raw)); return hex.EncodeToString(d[:]) }
func rawIntent(i intent) (string, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("marshal intent: %w", err)
	}
	return string(b), nil
}

func generate() ([]byte, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("read core corpus: %w", err)
	}
	var core struct {
		Positives []struct {
			ID      string `json:"id"`
			Request string `json:"request"`
		} `json:"positives"`
	}
	if err := json.Unmarshal(source, &core); err != nil {
		return nil, fmt.Errorf("decode core corpus: %w", err)
	}
	wanted := []string{"enroll1", "rotate2", "revoke3", "recover-disabled4", "recover-active3"}
	if len(core.Positives) != len(wanted) {
		return nil, fmt.Errorf("core corpus must contain exactly five original positives")
	}
	c := corpus{SchemaVersion: 1, Scope: "registry-intent-binding"}
	c.Source.Path, c.Source.SHA256 = sourcePath, sum(string(source))
	var first intent
	for n, p := range core.Positives {
		if p.ID != wanted[n] {
			return nil, fmt.Errorf("unexpected core positive %q", p.ID)
		}
		var request struct {
			TransitionKind           string `json:"transition_kind"`
			ArtifactDescriptorSHA256 string `json:"artifact_descriptor_sha256"`
			Challenge                string `json:"challenge"`
			RequestedAt              string `json:"requested_at"`
			ExpiresAt                string `json:"expires_at"`
		}
		if err := json.Unmarshal([]byte(p.Request), &request); err != nil {
			return nil, fmt.Errorf("decode core request %s: %w", p.ID, err)
		}
		i := intent{1, "registry_commit", request.TransitionKind, request.ArtifactDescriptorSHA256, request.Challenge, request.RequestedAt, request.ExpiresAt}
		if n == 0 {
			first = i
		}
		raw, err := rawIntent(i)
		if err != nil {
			return nil, err
		}
		id := p.ID
		c.Positives = append(c.Positives, positive{"intent-" + id, &id, hex.EncodeToString([]byte(raw)), hex.EncodeToString([]byte(domain + raw)), sum(domain + raw)})
	}
	for _, ttl := range []struct{ id, expiry string }{{"ttl-1s", "2026-09-01T12:00:01Z"}, {"ttl-300s", "2026-09-01T12:05:00Z"}} {
		i := first
		i.ExpiresAt = ttl.expiry
		raw, err := rawIntent(i)
		if err != nil {
			return nil, err
		}
		c.Positives = append(c.Positives, positive{ttl.id, nil, hex.EncodeToString([]byte(raw)), hex.EncodeToString([]byte(domain + raw)), sum(domain + raw)})
	}
	base, err := rawIntent(first)
	if err != nil {
		return nil, err
	}
	add := func(id, raw, reason string) {
		c.Negatives = append(c.Negatives, negative{id, "intent-enroll1", nil, hex.EncodeToString([]byte(raw)), sum(domain + raw), reason})
	}
	// All byte-level malformed rows are classified before primitive grammars.
	for _, tc := range []struct{ id, raw string }{
		{"canonical-empty", ""}, {"canonical-malformed", "{"},
		{"canonical-unknown", strings.TrimSuffix(base, "}") + `,"unknown":0}`},
		{"canonical-duplicate", strings.Replace(base, `"schema_version":1,`, `"schema_version":1,"schema_version":1,`, 1)},
		{"canonical-missing", strings.Replace(base, `"intent_type":"registry_commit",`, "", 1)},
		{"canonical-reordered", strings.Replace(base, `"schema_version":1,"intent_type":"registry_commit"`, `"intent_type":"registry_commit","schema_version":1`, 1)},
		{"canonical-whitespace", " " + base}, {"canonical-trailing-lf", base + "\n"},
		{"canonical-bom", "\xef\xbb\xbf" + base},
		{"canonical-trailing-token", base + "{}"},
		{"canonical-escaped-key", strings.Replace(base, `schema_version`, `schema_\u0076ersion`, 1)},
		{"canonical-escaped-value", strings.Replace(base, `registry_commit`, `registry_\u0063ommit`, 1)},
		{"canonical-invalid-utf8", strings.Replace(base, "registry_commit", "registry_\xffcommit", 1)},
		{"canonical-schema-string", strings.Replace(base, `"schema_version":1`, `"schema_version":"1"`, 1)},
		{"canonical-schema-bool", strings.Replace(base, `"schema_version":1`, `"schema_version":true`, 1)},
		{"canonical-null", strings.Replace(base, `"intent_type":"registry_commit"`, `"intent_type":null`, 1)},
		{"canonical-array", strings.Replace(base, `"intent_type":"registry_commit"`, `"intent_type":[]`, 1)},
		{"canonical-object", strings.Replace(base, `"intent_type":"registry_commit"`, `"intent_type":{}`, 1)},
		{"canonical-schema-fraction", strings.Replace(base, `"schema_version":1`, `"schema_version":1.0`, 1)},
		{"canonical-schema-exponent", strings.Replace(base, `"schema_version":1`, `"schema_version":1e0`, 1)},
		{"canonical-schema-leading-zero", strings.Replace(base, `"schema_version":1`, `"schema_version":01`, 1)},
		{"canonical-schema-plus", strings.Replace(base, `"schema_version":1`, `"schema_version":+1`, 1)},
		{"canonical-schema-negative-zero", strings.Replace(base, `"schema_version":1`, `"schema_version":-0`, 1)},
		{"canonical-size-1024", strings.Repeat("x", 1024)},
	} {
		add(tc.id, tc.raw, "canonical_encoding")
	}
	add("bounds-size-1025", strings.Repeat("x", 1025), "bounds_grammar")
	for _, tc := range []struct{ id, old, value string }{
		{"schema-version", `"schema_version":1`, `"schema_version":2`},
		{"field-intent-type", "registry_commit", "apply"}, {"field-transition", "enroll", "unknown"},
		{"field-descriptor-uppercase", first.ArtifactDescriptorSHA256, strings.Repeat("A", 64)},
		{"field-descriptor-short", first.ArtifactDescriptorSHA256, strings.Repeat("a", 63)},
		{"field-descriptor-long", first.ArtifactDescriptorSHA256, strings.Repeat("a", 65)},
		{"field-descriptor-nonhex", first.ArtifactDescriptorSHA256, strings.Repeat("g", 64)},
		{"field-nonce-padding", first.CeremonyNonce, first.CeremonyNonce + "="},
		{"field-nonce-alphabet", first.CeremonyNonce, "+" + first.CeremonyNonce[1:]},
		{"field-nonce-31-bytes", first.CeremonyNonce, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 31))},
		{"field-nonce-33-bytes", first.CeremonyNonce, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 33))},
		{"field-nonce-pad-bits", first.CeremonyNonce, first.CeremonyNonce[:42] + "B"},
		{"field-date-offset", first.RequestedAt, "2026-09-01T12:00:00+00:00"},
		{"field-date-fraction", first.RequestedAt, "2026-09-01T12:00:00.0Z"},
		{"field-date-invalid", first.RequestedAt, "2026-02-30T12:00:00Z"},
	} {
		add(tc.id, strings.Replace(base, tc.old, tc.value, 1), "bounds_grammar")
	}
	for _, tc := range []struct{ id, expiry string }{{"temporal-zero", first.RequestedAt}, {"temporal-negative", "2026-09-01T11:59:59Z"}, {"temporal-301s", "2026-09-01T12:05:01Z"}} {
		i := first
		i.ExpiresAt = tc.expiry
		raw, err := rawIntent(i)
		if err != nil {
			return nil, err
		}
		add(tc.id, raw, "temporal")
	}
	for _, tc := range []struct{ id, digest string }{
		{"digest-wrong", strings.Repeat("0", 64)},
		{"digest-no-nul", sum(strings.TrimSuffix(domain, "\x00") + base)},
		{"digest-wrong-domain", sum("YTA-REGISTRY-REQUEST-V1\x00" + base)},
		{"digest-plain-hash", sum(base)}, {"digest-lf-hash", sum(domain + base + "\n")},
	} {
		add(tc.id, base, "digest_domain")
		c.Negatives[len(c.Negatives)-1].SHA256 = tc.digest
	}
	// Each splice changes one valid intent field; the referenced signed core
	// transcript remains byte-for-byte untouched and independently valid.
	for _, field := range []string{"transition", "descriptor", "nonce", "expiry"} {
		i := first
		switch field {
		case "transition":
			i.TransitionKind = "rotate"
		case "descriptor":
			i.ArtifactDescriptorSHA256 = strings.Repeat("b", 64)
		case "nonce":
			i.CeremonyNonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32))
		case "expiry":
			i.ExpiresAt = "2026-09-01T12:04:59Z"
		}
		raw, err := rawIntent(i)
		if err != nil {
			return nil, err
		}
		add("binding-"+field, raw, "intent_binding")
		id := "enroll1"
		c.Negatives[len(c.Negatives)-1].CoreID = &id
	}
	encoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode corpus: %w", err)
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
			return fmt.Errorf("read intent corpus: %w", err)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("intent corpus differs; regenerate with go run ./testdata/gate1a-registry-intent/generate.go")
		}
		return nil
	}
	if err := os.WriteFile(outputPath, generated, 0644); err != nil {
		return fmt.Errorf("write intent corpus: %w", err)
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
