package operatorwrite

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/endpoint"
)

func testSnapshot(t *testing.T, kind Kind) Snapshot {
	t.Helper()
	mcp, err := endpoint.CanonicalMCPURL("https://tracker.example")
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Version: Version, Lane: Lane, Kind: kind, CapturedAt: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
		Binding: Binding{ProfileName: "work-write", ProfileIdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32)),
			AccountID: "1-1", AccountLogin: "operator", InstanceURL: "https://tracker.example", RESTBaseURL: "https://tracker.example/api", MCPURL: mcp,
			OAuthClientID: "cli", OAuthIssuerURL: "https://hub.example", OAuthAuthorizationEndpoint: "https://hub.example/api/rest/oauth2/auth", OAuthTokenEndpoint: "https://hub.example/api/rest/oauth2/token",
			PolicySHA256: strings.Repeat("b", 64), PolicyRevision: 1}, Issue: Issue{ID: "2-3", ReadableID: "BGR-1073", ProjectID: "0-1", ProjectKey: "BGR", Updated: 100}}
	if kind == KindIssueUpdate {
		s.Field = &Field{IssueFieldID: "92-1", ProjectFieldID: "94-1", GlobalFieldID: "58-1", Name: "Stage", Type: "StateIssueCustomField", ProjectFieldType: "StateProjectCustomField", ValueType: "state", FieldTypeID: "state[1]", FieldTypeType: "FieldType", IsPublic: true, BundleID: "10-1", BundleType: "StateBundle", CurrentValue: &Value{ID: "20-1", Name: "Open", Type: "StateBundleElement"}, TargetValue: &Value{ID: "20-2", Name: "PR Review", Type: "StateBundleElement"}}
	}
	return s
}

func testPlan(t *testing.T, kind Kind) Plan {
	t.Helper()
	s := testSnapshot(t, kind)
	q := Request{Kind: kind}
	if kind == KindCommentAdd {
		q.CommentText = "Reviewed the change."
	}
	p, err := Prepare(s, q, s.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrepareFrozenBoundedPlan(t *testing.T) {
	for _, kind := range []Kind{KindIssueUpdate, KindCommentAdd} {
		t.Run(string(kind), func(t *testing.T) {
			s := testSnapshot(t, kind)
			q := Request{Kind: kind, CommentText: ""}
			if kind == KindCommentAdd {
				q.CommentText = "A public comment."
			}
			p, err := Prepare(s, q, s.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePlan(p); err != nil {
				t.Fatal(err)
			}
			if p.Version != PlanVersionFor(kind) || p.Version != map[Kind]int{KindIssueUpdate: PlanVersion4, KindCommentAdd: PlanVersion5}[kind] || !p.ExpiresAt.IsZero() || p.ConfirmationMode != ConfirmationMode || p.Notifications != Notifications {
				t.Fatalf("incorrect plan metadata: %+v", p)
			}
			if kind == KindIssueUpdate {
				s.Field.TargetValue.Name = "MUTATED"
				if p.Snapshot.Field.TargetValue.Name == "MUTATED" {
					t.Fatal("snapshot pointer not frozen")
				}
			} else if p.Request.CommentText != q.CommentText {
				t.Fatal("comment text was not sent verbatim")
			}
			p.Request.CommentText = "TAMPER_SENTINEL"
			if ValidatePlan(p) == nil {
				t.Fatal("tampered request accepted")
			}
		})
	}
}

func TestPrepareRejectsUnsupportedSnapshots(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Snapshot)
	}{
		{"wrong lane", func(s *Snapshot) { s.Lane = "native" }},
		{"identity", func(s *Snapshot) { s.Binding.ProfileIdentitySHA256 = "SENTINEL" }},
		{"unbound generation", func(s *Snapshot) { s.Binding.CredentialGeneration = "" }},
		{"oauth topology", func(s *Snapshot) { s.Binding.OAuthTokenEndpoint = "https://evil.example/token" }},
		{"bare MCP", func(s *Snapshot) { s.Binding.MCPURL = "https://tracker.example/mcp" }},
		{"unknown issue field", func(s *Snapshot) { s.Field.IssueFieldID = "" }},
		{"unknown project field", func(s *Snapshot) { s.Field.ProjectFieldID = "" }},
		{"unknown global field", func(s *Snapshot) { s.Field.GlobalFieldID = "" }},
		{"multi", func(s *Snapshot) { s.Field.IsMultiValue = true }},
		{"schema type", func(s *Snapshot) { s.Field.ProjectFieldType = "EnumProjectCustomField" }},
		{"schema value type", func(s *Snapshot) { s.Field.ValueType = "enum" }},
		{"missing field type identity", func(s *Snapshot) { s.Field.FieldTypeID = "" }},
		{"wrong field type identity", func(s *Snapshot) { s.Field.FieldTypeID = "state[2]" }},
		{"wrong field type entity", func(s *Snapshot) { s.Field.FieldTypeType = "UnknownFieldType" }},
		{"missing target type", func(s *Snapshot) { s.Field.TargetValue.Type = "" }},
		{"wrong target type", func(s *Snapshot) { s.Field.TargetValue.Type = "EnumBundleElement" }},
		{"missing current type", func(s *Snapshot) { s.Field.CurrentValue.Type = "" }},
		{"wrong current type", func(s *Snapshot) { s.Field.CurrentValue.Type = "EnumBundleElement" }},
		{"schema bundle type", func(s *Snapshot) { s.Field.BundleType = "EnumBundle" }},
		{"archived target", func(s *Snapshot) { s.Field.TargetValue.Archived = true }},
		{"missing target", func(s *Snapshot) { s.Field.TargetValue.ID = "" }},
		{"null forbidden", func(s *Snapshot) { s.Field.CurrentValue = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := testSnapshot(t, KindIssueUpdate)
			test.change(&s)
			if _, err := Prepare(s, Request{Kind: KindIssueUpdate}, s.CapturedAt.Add(time.Minute)); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	s := testSnapshot(t, KindIssueUpdate)
	s.Field.CurrentValue = nil
	s.Field.CanBeEmpty = true
	if _, err := Prepare(s, Request{Kind: KindIssueUpdate}, s.CapturedAt.Add(time.Minute)); err != nil {
		t.Fatalf("nullable current value refused: %v", err)
	}
	s.Field.Type = "SingleEnumIssueCustomField"
	s.Field.ProjectFieldType = "EnumProjectCustomField"
	s.Field.ValueType = "enum"
	s.Field.FieldTypeID = "enum[1]"
	s.Field.BundleType = "EnumBundle"
	s.Field.TargetValue.Type = "EnumBundleElement"
	if _, err := Prepare(s, Request{Kind: KindIssueUpdate}, s.CapturedAt.Add(time.Minute)); err != nil {
		t.Fatalf("scalar enum refused: %v", err)
	}
}

func TestTouchedSchemaProjectionIsDigestBound(t *testing.T) {
	for _, field := range []string{"visibility", "field type identity", "field type entity", "target entity type", "current entity type"} {
		t.Run(field, func(t *testing.T) {
			p := testPlan(t, KindIssueUpdate)
			switch field {
			case "visibility":
				p.Snapshot.Field.IsPublic = !p.Snapshot.Field.IsPublic
			case "field type identity":
				p.Snapshot.Field.FieldTypeID = "enum[1]"
			case "field type entity":
				p.Snapshot.Field.FieldTypeType = "OtherFieldType"
			case "target entity type":
				p.Snapshot.Field.TargetValue.Type = "EnumBundleElement"
			case "current entity type":
				p.Snapshot.Field.CurrentValue.Type = "EnumBundleElement"
			}
			if ValidatePlan(p) == nil {
				t.Fatal("schema mutation accepted with old digest")
			}
		})
	}
	// A private field is supported, but its visibility is part of the intent.
	s := testSnapshot(t, KindIssueUpdate)
	s.Field.IsPublic = false
	if _, err := Prepare(s, Request{Kind: KindIssueUpdate}, s.CapturedAt.Add(time.Minute)); err != nil {
		t.Fatalf("private scalar field refused: %v", err)
	}
}

func TestPlanLifetimeAndInputBounds(t *testing.T) {
	p := testPlan(t, KindIssueUpdate)
	if CheckFresh(p, p.CreatedAt.Add(-time.Nanosecond)) == nil {
		t.Fatal("future plan accepted")
	}
	if err := CheckFresh(p, p.CreatedAt.Add(24*time.Hour)); err != nil {
		t.Fatalf("v2 plan expired by wall clock: %v", err)
	}
	legacy := p
	legacy.Version, legacy.ExpiresAt = LegacyPlanVersion1, p.CreatedAt.Add(LegacyPlanTTL)
	var err error
	legacy.SHA256, err = digest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{legacy.CreatedAt.Add(-time.Nanosecond), legacy.ExpiresAt, legacy.ExpiresAt.Add(time.Minute)} {
		if CheckFresh(legacy, now) == nil {
			t.Fatal("expired or future plan accepted")
		}
	}
	if err := CheckFresh(legacy, legacy.CreatedAt); err != nil {
		t.Fatal(err)
	}
	s := testSnapshot(t, KindCommentAdd)
	for _, text := range []string{"", " \n\t", strings.Repeat("x", MaxCommentBytes+1), "sentinel\x00", " padded", "padded\n"} {
		if _, err := Prepare(s, Request{Kind: KindCommentAdd, CommentText: text}, s.CapturedAt.Add(time.Minute)); err == nil {
			t.Fatal("invalid final comment accepted")
		}
	}
	if _, err := Prepare(s, Request{Kind: KindIssueUpdate}, s.CapturedAt.Add(time.Minute)); err == nil {
		t.Fatal("operation switch accepted")
	}
	if _, err := Prepare(s, Request{Kind: KindCommentAdd, CommentText: "ok"}, s.CapturedAt.Add(SnapshotTTL)); err == nil {
		t.Fatal("stale snapshot accepted")
	}
}

func TestDecodeRejectsUnknownDuplicateOversizedAndRedacts(t *testing.T) {
	p := withMarker(t, testPlan(t, KindCommentAdd), PlanVersion2)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePlan(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`{"SECRET_SENTINEL":"SECRET_SENTINEL"}`,
		strings.Replace(string(raw), `"version":2`, `"version":2,"version":2`, 1),
		string(raw) + ` {"SECRET_SENTINEL":true}`,
		strings.Repeat("x", MaxPlanBytes+1),
		`{"request":{"kind":"comment.add","comment_text":"SECRET_SENTINEL"}}`,
	} {
		_, err := DecodePlan(strings.NewReader(input))
		if err == nil {
			t.Fatal("invalid input accepted")
		}
		if strings.Contains(err.Error(), "SECRET_SENTINEL") {
			t.Fatal("untrusted content leaked in error")
		}
	}
	if ValidateID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA") == nil {
		t.Fatal("native plan id accepted")
	}
	if _, err := DecodeRequest(strings.NewReader(`{"kind":"issue.update","target":"SECRET_SENTINEL"}`)); err == nil || strings.Contains(err.Error(), "SECRET_SENTINEL") {
		t.Fatalf("unknown target decoding: %v", err)
	}
}
