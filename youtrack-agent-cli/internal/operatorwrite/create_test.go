package operatorwrite

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func testCreateSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testSnapshot(t, KindIssueCreate)
	s.Issue = Issue{}
	s.Project = &Project{ID: "0-1", Key: "TAC"}
	s.Fields = []Field{
		{ProjectFieldID: "189-8", GlobalFieldID: "58-1", Name: "Stage", Type: "StateIssueCustomField", ProjectFieldType: "StateProjectCustomField", ValueType: "state", FieldTypeID: "state[1]", FieldTypeType: "FieldType", IsPublic: true, BundleID: "10-1", BundleType: "StateBundle", TargetValue: Value{ID: "20-2", Name: "In Progress", Type: "StateBundleElement"}},
		{ProjectFieldID: "189-7", GlobalFieldID: "58-2", Name: "Priority", Type: "SingleEnumIssueCustomField", ProjectFieldType: "EnumProjectCustomField", ValueType: "enum", FieldTypeID: "enum[1]", FieldTypeType: "FieldType", IsPublic: true, BundleID: "11-1", BundleType: "EnumBundle", TargetValue: Value{ID: "21-3", Name: "Normal", Type: "EnumBundleElement"}},
	}
	return s
}

// The golden plans were captured from the binary before issue.create existed.
// They must still decode with their stored digest, or prepared plans on an
// operator's disk would stop being appliable after an upgrade.
func TestGoldenV1PlansKeepBytesAndDigest(t *testing.T) {
	for _, name := range []string{"plan-v1-issue-update.json", "plan-v1-comment-add.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			p, err := DecodePlan(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("stored v1 plan no longer decodes: %v", err)
			}
			again, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, raw) {
				t.Fatalf("stored plan bytes changed:\n%s\n%s", raw, again)
			}
			if sha, err := digest(p); err != nil || sha != p.SHA256 {
				t.Fatalf("digest=%s stored=%s err=%v", sha, p.SHA256, err)
			}
		})
	}
}

func TestPrepareCreateAddsMarkerAndOmitsIssue(t *testing.T) {
	tests := []struct {
		name, body string
		want       func(id string) string
	}{
		{"body", "Started: harness MR.\nRepo: tackroom", func(id string) string { return "Started: harness MR.\nRepo: tackroom\n\n" + Marker(id) }},
		{"empty body", "", Marker},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := testCreateSnapshot(t)
			p, err := Prepare(s, Request{Kind: KindIssueCreate, Summary: "Harness MR", Description: test.body}, s.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if p.Request.Description != test.want(p.ID) || p.Request.Summary != "Harness MR" {
				t.Fatalf("request=%#v", p.Request)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"issue":`) || !strings.Contains(string(raw), `"project":{"id":"0-1","key":"TAC"}`) {
				t.Fatalf("create plan shape=%s", raw)
			}
			decoded, err := DecodePlan(bytes.NewReader(raw))
			if err != nil || decoded.SHA256 != p.SHA256 {
				t.Fatalf("round trip=%v %v", decoded.SHA256, err)
			}
		})
	}
}

func TestPrepareCreateRejectsNonCanonicalText(t *testing.T) {
	long := strings.Repeat("a", MaxDescriptionBytes)
	tests := []struct {
		name    string
		request Request
	}{
		{"blank summary", Request{Kind: KindIssueCreate, Summary: "  "}},
		{"leading space", Request{Kind: KindIssueCreate, Summary: " Title"}},
		{"trailing space", Request{Kind: KindIssueCreate, Summary: "Title "}},
		{"newline summary", Request{Kind: KindIssueCreate, Summary: "Title\nmore"}},
		{"tab summary", Request{Kind: KindIssueCreate, Summary: "Title\tmore"}},
		{"line separator summary", Request{Kind: KindIssueCreate, Summary: "Title\u2028more"}},
		{"paragraph separator summary", Request{Kind: KindIssueCreate, Summary: "Title\u2029more"}},
		{"oversized summary", Request{Kind: KindIssueCreate, Summary: strings.Repeat("a", MaxSummaryBytes+1)}},
		{"invalid utf8", Request{Kind: KindIssueCreate, Summary: "Title\xff"}},
		{"carriage return", Request{Kind: KindIssueCreate, Summary: "Title", Description: "one\r\ntwo"}},
		{"trailing newline", Request{Kind: KindIssueCreate, Summary: "Title", Description: "one\n"}},
		{"blank description", Request{Kind: KindIssueCreate, Summary: "Title", Description: " \n "}},
		{"nul description", Request{Kind: KindIssueCreate, Summary: "Title", Description: "a\x00b"}},
		{"oversized with marker", Request{Kind: KindIssueCreate, Summary: "Title", Description: long}},
		{"comment text", Request{Kind: KindIssueCreate, Summary: "Title", CommentText: "x"}},
		{"kind mismatch", Request{Kind: KindCommentAdd, CommentText: "x"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := testCreateSnapshot(t)
			if _, err := Prepare(s, test.request, s.CapturedAt.Add(time.Minute)); err == nil {
				t.Fatal("non-canonical create request accepted")
			}
		})
	}
}

func TestCreateSnapshotShapeIsKindExclusive(t *testing.T) {
	tests := []struct {
		name   string
		kind   Kind
		change func(*Snapshot)
	}{
		{"create with issue", KindIssueCreate, func(s *Snapshot) { s.Issue = testSnapshot(t, KindCommentAdd).Issue }},
		{"create without project", KindIssueCreate, func(s *Snapshot) { s.Project = nil }},
		{"create bad key", KindIssueCreate, func(s *Snapshot) { s.Project.Key = "tac" }},
		{"create single field", KindIssueCreate, func(s *Snapshot) { s.Field = &s.Fields[0] }},
		{"create issue field identity", KindIssueCreate, func(s *Snapshot) { s.Fields[0].IssueFieldID = "92-1" }},
		{"create current value", KindIssueCreate, func(s *Snapshot) { s.Fields[0].CurrentValue = &s.Fields[0].TargetValue }},
		{"create duplicate project field", KindIssueCreate, func(s *Snapshot) { s.Fields[1].ProjectFieldID = s.Fields[0].ProjectFieldID }},
		{"create duplicate global field", KindIssueCreate, func(s *Snapshot) { s.Fields[1].GlobalFieldID = s.Fields[0].GlobalFieldID }},
		{"create duplicate field name", KindIssueCreate, func(s *Snapshot) { s.Fields[1].Name = s.Fields[0].Name }},
		{"create oversized field name", KindIssueCreate, func(s *Snapshot) { s.Fields[0].Name = strings.Repeat("n", MaxCreateFieldNameBytes+1) }},
		{"create archived target", KindIssueCreate, func(s *Snapshot) { s.Fields[0].TargetValue.Archived = true }},
		{"create mismatched type", KindIssueCreate, func(s *Snapshot) { s.Fields[0].Type = "SingleEnumIssueCustomField" }},
		{"create too many fields", KindIssueCreate, func(s *Snapshot) {
			for len(s.Fields) <= MaxCreateFields {
				f := s.Fields[0]
				f.ProjectFieldID, f.GlobalFieldID = f.ProjectFieldID+"0", f.GlobalFieldID+"0"
				s.Fields = append(s.Fields, f)
			}
		}},
		{"update with project", KindIssueUpdate, func(s *Snapshot) { s.Project = &Project{ID: "0-1", Key: "BGR"} }},
		{"comment with fields", KindCommentAdd, func(s *Snapshot) { s.Fields = []Field{} }},
		{"unknown kind", KindIssueUpdate, func(s *Snapshot) { s.Kind = "issue.delete" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := testSnapshot(t, test.kind)
			if test.kind == KindIssueCreate {
				s = testCreateSnapshot(t)
			}
			test.change(&s)
			if ValidateSnapshot(s) == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	if err := ValidateSnapshot(testCreateSnapshot(t)); err != nil {
		t.Fatalf("valid create snapshot refused: %v", err)
	}
	s := testCreateSnapshot(t)
	s.Fields = nil
	if err := ValidateSnapshot(s); err != nil {
		t.Fatalf("create without custom fields refused: %v", err)
	}
}

func TestCreatePlanTextTamperingBreaksValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Plan)
	}{
		{"marker removed", func(p *Plan) { p.Request.Description = "Body" }},
		{"marker duplicated", func(p *Plan) { p.Request.Description = Marker(p.ID) + "\n\n" + p.Request.Description }},
		{"other plan marker", func(p *Plan) { p.Request.Description = "Body\n\n" + Marker("YTOW-AAAAAAAAAAAAAAAAAAAAAAAAAA") }},
		{"marker glued", func(p *Plan) { p.Request.Description = "Body" + Marker(p.ID) }},
		{"summary made non-canonical", func(p *Plan) { p.Request.Summary = "Title " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := testCreateSnapshot(t)
			p, err := Prepare(s, Request{Kind: KindIssueCreate, Summary: "Title", Description: "Body"}, s.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			test.change(&p)
			// Re-digest so only the text rules, not the hash, can reject.
			if p.SHA256, err = digest(p); err != nil {
				t.Fatal(err)
			}
			if ValidatePlan(p) == nil {
				t.Fatal("tampered create plan accepted")
			}
		})
	}
}

func TestDecodeRequestKindExclusiveText(t *testing.T) {
	tests := []struct {
		raw string
		ok  bool
	}{
		{`{"kind":"issue.create","summary":"Title","description":"Body"}`, true},
		{`{"kind":"issue.create","summary":"Title"}`, true},
		{`{"kind":"issue.create"}`, false},
		{`{"kind":"issue.create","summary":"Title","description":"Body\r\n"}`, false},
		{`{"kind":"issue.update","summary":"Title"}`, false},
		{`{"kind":"comment.add","comment_text":"x","description":"y"}`, false},
		{`{"kind":"issue.delete"}`, false},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			_, err := DecodeRequest(strings.NewReader(test.raw))
			if (err == nil) != test.ok {
				t.Fatalf("err=%v want ok=%v", err, test.ok)
			}
		})
	}
}
