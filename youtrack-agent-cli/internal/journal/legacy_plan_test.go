package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

// These complete records are frozen independently of the current Plan type.
// In particular, an optional field added to a current operation must not
// silently broaden either historical v1 or prepared-v2 byte grammar.
func TestJournalCodecFrozenOperationBranches(t *testing.T) {
	for _, tc := range []struct {
		name, v1File, v1SHA256, v2File, v2SHA256 string
		kind                                     intent.Kind
	}{
		{"create", "codec-create-v1.json", "cef3fc8b9e4f28adefd912c45e864434028dddc1394cec78f4aee8fb57da4083", "codec-create-v2.json", "db05e174e45793d62f3978cd6ffd8e7f5c2d2e77c0740627443e399e490b6455", intent.KindIssueCreate},
		{"update", "", historicalV1PreparedSHA256, "codec-update-v2.json", "b514318862f94724403a9a99355fb84edf5916145cb2a3da0d2f33e3d3d6037b", intent.KindIssueUpdate},
		{"comment", "codec-comment-v1.json", "cd0aa0432bd050fc00d35eaa267c94005742db46696af8377e37458c34b82e8c", "codec-comment-v2.json", "e4399a1d19c4b90551063e4ff87e72f927fdd6edc0f3e2df937c495b9964365c", intent.KindCommentAdd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v1 []byte
			if tc.v1File == "" {
				v1 = []byte(historicalV1Prepared)
			} else {
				v1 = codecReadFixture(t, tc.v1File)
			}
			v2 := codecReadFixture(t, tc.v2File)
			if got := codecDigest(v1); got != tc.v1SHA256 {
				t.Fatalf("frozen v1 bytes changed: %s", got)
			}
			if got := codecDigest(v2); got != tc.v2SHA256 {
				t.Fatalf("frozen v2 bytes changed: %s", got)
			}
			classified, err := ClassifyLegacyV1(v1)
			if err != nil {
				t.Fatalf("historical v1 record rejected: %v", err)
			}
			if classified.Disposition != LegacyV1Migratable || classified.SHA256 != tc.v1SHA256 ||
				classified.Record.Plan.Kind != tc.kind {
				t.Fatalf("unexpected v1 classification: %#v", classified)
			}
			encoded, err := EncodePreparedV2(PreparedV2Record{
				Revision: 1, Plan: classified.Record.Plan,
				CreatedAt: classified.Record.CreatedAt, UpdatedAt: classified.Record.UpdatedAt,
			})
			if err != nil || !bytes.Equal(encoded, v2) {
				t.Fatalf("v2 %s encoder changed frozen bytes: %v", tc.name, err)
			}
			decoded, err := DecodePreparedV2(v2)
			if err != nil || decoded.Plan.Kind != tc.kind ||
				decoded.Plan.IntentSHA256 != classified.Record.Plan.IntentSHA256 {
				t.Fatalf("frozen v2 %s decoder changed bindings: %#v, %v", tc.name, decoded, err)
			}
		})
	}
}

func codecReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("%s must have one terminal LF", name)
	}
	return raw
}

func TestJournalCodecFrozenNestedGrammarAndDigests(t *testing.T) {
	for _, tc := range []struct {
		name, v1File, v2File, operationNeedle, operationReplacement string
	}{
		{"create", "codec-create-v1.json", "codec-create-v2.json", `"summary": "new card",`, "\"summary\": \"new card\",\n          \"future_optional\": true,"},
		{"update", "", "codec-update-v2.json", `"summary": "new"`, "\"summary\": \"new\",\n            \"future_optional\": true"},
		{"comment", "codec-comment-v1.json", "codec-comment-v2.json", `"text": "comment body\n\nAgent plan: YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA",`, "\"text\": \"comment body\\n\\nAgent plan: YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA\",\n          \"future_optional\": true,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v1 []byte
			if tc.v1File == "" {
				v1 = []byte(historicalV1Prepared)
			} else {
				v1 = codecReadFixture(t, tc.v1File)
			}
			v2 := codecReadFixture(t, tc.v2File)
			for _, wire := range []struct {
				name  string
				raw   []byte
				parse func([]byte) error
			}{
				{"v1", v1, func(raw []byte) error { _, err := ClassifyLegacyV1(raw); return err }},
				{"v2", v2, func(raw []byte) error { _, err := DecodePreparedV2(raw); return err }},
			} {
				t.Run(wire.name, func(t *testing.T) {
					for _, mutation := range []struct {
						name, old, replacement string
					}{
						{"future plan field", `"schema_version": 1,`, "\"schema_version\": 1,\n    \"future_optional\": true,"},
						{"future operation field", tc.operationNeedle, tc.operationReplacement},
					} {
						t.Run(mutation.name, func(t *testing.T) {
							candidate := codecReplaceOnce(t, wire.raw, mutation.old, mutation.replacement)
							if !json.Valid(candidate) {
								t.Fatal("nested grammar probe must remain valid JSON")
							}
							if err := wire.parse(candidate); err == nil {
								t.Fatal("accepted changed frozen grammar or digest")
							}
						})
					}
					for _, field := range []string{"request_sha256", "expected_sha256", "intent_sha256"} {
						t.Run(field+" mismatch", func(t *testing.T) {
							candidate := codecFlipDigest(t, wire.raw, field)
							if !json.Valid(candidate) {
								t.Fatal("digest mismatch probe must remain valid JSON")
							}
							if err := wire.parse(candidate); err == nil {
								t.Fatal("accepted valid-grammar but incorrect digest")
							}
						})
					}
				})
			}
		})
	}
}

func codecFlipDigest(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	candidate := append([]byte(nil), raw...)
	needle := []byte(`"` + name + `": "`)
	start := bytes.Index(candidate, needle)
	if start < 0 || bytes.Count(candidate, needle) != 1 {
		t.Fatalf("%s not unique in frozen fixture", name)
	}
	index := start + len(needle)
	if candidate[index] == '0' {
		candidate[index] = '1'
	} else {
		candidate[index] = '0'
	}
	return candidate
}

func TestJournalCodecErrorsAreTypedAndRedacted(t *testing.T) {
	const sentinel = "9999999999999999999999999999999999999999"
	for _, tc := range []struct {
		name  string
		raw   []byte
		parse func([]byte) error
	}{
		{"v1", []byte(historicalV1Prepared), func(raw []byte) error { _, err := ClassifyLegacyV1(raw); return err }},
		{"v2", codecReadFixture(t, "codec-update-v2.json"), func(raw []byte) error { _, err := DecodePreparedV2(raw); return err }},
		{"marker", []byte("{\n  \"schema_version\": 1,\n  \"record_sha256\": \"" + historicalV1PreparedSHA256 + "\",\n  \"state\": \"confirmed\",\n  \"reason\": \"" + quarantineReason + "\",\n  \"detected_at\": \"2026-09-28T15:00:00Z\"\n}\n"), func(raw []byte) error { _, err := DecodeQuarantineMarker(raw); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			field := `"revision": 1`
			if tc.name == "marker" {
				field = `"schema_version": 1`
			}
			raw := codecReplaceOnce(t, tc.raw, field, strings.Replace(field, "1", sentinel, 1))
			err := tc.parse(raw)
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Code != errx.CodeInternal || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("error is untyped or leaks untrusted bytes: %v", err)
			}
		})
	}
}

func TestJournalCodecMaximumShapedPreparedBranchesFitV2(t *testing.T) {
	base := journalPlan(t)
	fieldType := strings.Repeat("<", 128)
	fieldText := strings.Repeat("<", 8<<10)
	fields := `[{"field_id":"1","field_type":"` + fieldType + `","text_value":"` + fieldText +
		`"},{"field_id":"2","field_type":"` + fieldType + `","text_value":"` + fieldText +
		`"},{"field_id":"3","field_type":"` + fieldType + `","text_value":"` + fieldText + `"}]`
	for _, tc := range []struct {
		name, capability, request, expected string
		kind                                intent.Kind
	}{
		{"create", "issue-create", `{"summary":"` + strings.Repeat("<", 1024) +
			`","description":"` + strings.Repeat("<", 32<<10) +
			`","visibility":{"mode":"public"},"custom_fields":` + fields + `,"marker":"none"}`,
			`{"project_state_sha256":"` + strings.Repeat("d", 64) + `"}`, intent.KindIssueCreate},
		{"update", "issue-update", `{"issue_id":"APP-1","set":{"summary":"` + strings.Repeat("<", 1024) +
			`","description":"` + strings.Repeat("<", 32<<10) + `","custom_fields":` + fields + `}}`,
			`{"issue_id":"APP-1","issue_state_sha256":"` + strings.Repeat("d", 64) +
				`","touched_fields_sha256":"` + strings.Repeat("e", 64) + `"}`, intent.KindIssueUpdate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.request) > intent.MaxRequestBytes {
				t.Fatalf("boundary probe exceeds request cap: %d", len(tc.request))
			}
			policy := base.Policy
			policy.AuthorizedCapability = tc.capability
			plan, err := intent.PrepareWithSource(base.Profile, policy, tc.kind,
				[]byte(tc.request), []byte(tc.expected), fixedID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
			if err != nil {
				t.Fatal(err)
			}
			record := Record{Version: recordVersion, Revision: 1, State: StatePrepared,
				Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime}
			v1 := legacyCodecBytes(t, record)
			classification, err := ClassifyLegacyV1(v1)
			if err != nil || classification.Disposition != LegacyV1Migratable {
				t.Fatalf("largest-shaped valid v1 branch cannot migrate: %#v, %v", classification, err)
			}
			v2, err := EncodePreparedV2(PreparedV2Record{
				Revision: 1, Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime,
			})
			if err != nil || len(v2) <= 300<<10 || len(v2) > maxPreparedLineageV2Bytes {
				t.Fatalf("largest-shaped valid branch v2 size=%d, error=%v", len(v2), err)
			}
			if _, err := DecodePreparedV2(v2); err != nil {
				t.Fatalf("largest-shaped valid branch could not round-trip: %v", err)
			}
		})
	}
}
