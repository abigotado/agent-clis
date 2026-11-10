package operatorwrite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func editSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testSnapshot(t, KindIssueEdit)
	oldSummary, oldDescription := "old summary sentinel", "old description sentinel"
	s.Text = &TextPrecondition{SummarySHA256: HashText(&oldSummary), DescriptionSHA256: HashText(&oldDescription)}
	return s
}

func prepareEdit(t *testing.T, s Snapshot, q Request) (Plan, error) {
	t.Helper()
	return Prepare(s, q, s.CapturedAt.Add(time.Minute))
}

func TestHashText(t *testing.T) {
	empty, text, other := "", "text", "Text"
	hashes := map[string]string{
		"null": HashText(nil), "empty": HashText(&empty), "text": HashText(&text), "other": HashText(&other),
	}
	seen := map[string]string{}
	for name, hash := range hashes {
		if len(hash) != 64 {
			t.Fatalf("%s hash = %q", name, hash)
		}
		if previous, ok := seen[hash]; ok {
			t.Fatalf("%s and %s share a hash", name, previous)
		}
		seen[hash] = name
	}
	again := "text"
	if HashText(&again) != hashes["text"] || HashText(nil) != hashes["null"] {
		t.Fatal("HashText is not deterministic")
	}
}

func TestIssueEditRequestValidation(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		valid bool
	}{
		{"summary only", `{"kind":"issue.edit","summary":"New title"}`, true},
		{"description only", `{"kind":"issue.edit","description":"Line one\nLine two"}`, true},
		{"both", `{"kind":"issue.edit","summary":"New title","description":"Body"}`, true},
		{"neither", `{"kind":"issue.edit"}`, false},
		{"both empty", `{"kind":"issue.edit","summary":"","description":""}`, false},
		{"summary with explicit empty description", `{"kind":"issue.edit","summary":"X","description":""}`, false},
		{"explicit empty summary with description", `{"kind":"issue.edit","summary":"","description":"X"}`, false},
		{"explicit null description", `{"kind":"issue.edit","summary":"X","description":null}`, false},
		{"explicit null summary", `{"kind":"issue.edit","summary":null,"description":"X"}`, false},
		{"description omitted", `{"kind":"issue.edit","summary":"X"}`, true},
		{"whitespace-only summary", `{"kind":"issue.edit","summary":"   "}`, false},
		{"whitespace-only description", `{"kind":"issue.edit","description":"\n  "}`, false},
		{"newline in summary", `{"kind":"issue.edit","summary":"a\nb"}`, false},
		{"carriage return in summary", `{"kind":"issue.edit","summary":"a\rb"}`, false},
		{"NUL in summary", `{"kind":"issue.edit","summary":"a\u0000b"}`, false},
		{"NUL in description", `{"kind":"issue.edit","description":"a\u0000b"}`, false},
		{"CR in description", `{"kind":"issue.edit","description":"a\r\nb"}`, false},
		{"trailing whitespace summary", `{"kind":"issue.edit","summary":"title "}`, false},
		{"leading whitespace summary", `{"kind":"issue.edit","summary":" title"}`, false},
		{"trailing whitespace description", `{"kind":"issue.edit","description":"body\n"}`, false},
		{"summary at cap", `{"kind":"issue.edit","summary":"` + strings.Repeat("a", MaxSummaryBytes) + `"}`, true},
		{"oversized summary", `{"kind":"issue.edit","summary":"` + strings.Repeat("a", MaxSummaryBytes+1) + `"}`, false},
		{"description at cap", `{"kind":"issue.edit","description":"` + strings.Repeat("a", MaxDescriptionBytes) + `"}`, true},
		{"oversized description", `{"kind":"issue.edit","description":"` + strings.Repeat("a", MaxDescriptionBytes+1) + `"}`, false},
		{"comment text", `{"kind":"issue.edit","summary":"x","comment_text":"c"}`, false},
		{"unknown member", `{"kind":"issue.edit","summary":"x","extra":1}`, false},
		{"duplicate key", `{"kind":"issue.edit","summary":"x","summary":"y"}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			q, err := DecodeRequest(strings.NewReader(test.raw))
			if (err == nil) != test.valid {
				t.Fatalf("DecodeRequest() = %+v, %v; want valid=%v", q, err, test.valid)
			}
		})
	}
}

func TestOtherKindsRefuseEditText(t *testing.T) {
	for _, q := range []Request{
		{Kind: KindIssueUpdate, Summary: "x"},
		{Kind: KindCommentDelete, Description: "x"},
		{Kind: KindCommentAdd, CommentText: "c", Summary: "x"},
	} {
		if validRequest(q) {
			t.Fatalf("validRequest(%+v) = true", q)
		}
	}
	s := testSnapshot(t, KindIssueUpdate)
	s.Text = &TextPrecondition{SummarySHA256: HashText(nil), DescriptionSHA256: HashText(nil)}
	if ValidateSnapshot(s) == nil {
		t.Fatal("issue.update snapshot accepted a text precondition")
	}
}

func TestIssueEditSnapshotValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		valid  bool
	}{
		{"valid", func(*Snapshot) {}, true},
		{"missing text", func(s *Snapshot) { s.Text = nil }, false},
		{"empty summary hash", func(s *Snapshot) { s.Text.SummarySHA256 = "" }, false},
		{"empty description hash", func(s *Snapshot) { s.Text.DescriptionSHA256 = "" }, false},
		{"short hash", func(s *Snapshot) { s.Text.SummarySHA256 = "abc" }, false},
		{"uppercase hash", func(s *Snapshot) { s.Text.DescriptionSHA256 = strings.ToUpper(s.Text.DescriptionSHA256) }, false},
		{"non-hex hash", func(s *Snapshot) { s.Text.SummarySHA256 = strings.Repeat("z", 64) }, false},
		{"extra field", func(s *Snapshot) { s.Field = testSnapshot(t, KindIssueUpdate).Field }, false},
		{"extra comment", func(s *Snapshot) { s.Comment = testCommentDeleteSnapshot(t).Comment }, false},
		{"extra project", func(s *Snapshot) { s.Project = &Project{ID: "0-1", Key: "BGR"} }, false},
		{"missing issue identity", func(s *Snapshot) { s.Issue = Issue{} }, false},
		{"zero updated", func(s *Snapshot) { s.Issue.Updated = 0 }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := editSnapshot(t)
			test.mutate(&s)
			if got := ValidateSnapshot(s) == nil; got != test.valid {
				t.Fatalf("ValidateSnapshot() valid=%v, want %v", got, test.valid)
			}
		})
	}
}

func TestIssueEditSnapshotRejectsUnknownTextMember(t *testing.T) {
	raw, err := json.Marshal(editSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(raw)); err != nil {
		t.Fatalf("DecodeSnapshot(valid): %v", err)
	}
	mutated := bytes.Replace(raw, []byte(`"description_sha256"`), []byte(`"old_description":"leak","description_sha256"`), 1)
	if _, err := DecodeSnapshot(bytes.NewReader(mutated)); err == nil {
		t.Fatal("DecodeSnapshot accepted an extra text member")
	}
}

func TestIssueEditPlanVersionRules(t *testing.T) {
	if got := PlanVersionFor(KindIssueEdit); got != PlanVersion4 {
		t.Fatalf("PlanVersionFor(issue.edit) = %d", got)
	}
	s := editSnapshot(t)
	base, err := prepareEdit(t, s, Request{Kind: KindIssueEdit, Summary: "New title", Description: "New body"})
	if err != nil {
		t.Fatal(err)
	}
	if base.Version != PlanVersion4 || !durablePlanVersion(base.Version) || PlanLifetime(base.Version) != CurrentPlanLifetime || !base.ExpiresAt.IsZero() {
		t.Fatalf("plan = %+v", base)
	}
	for _, version := range []int{LegacyPlanVersion1, PlanVersion2, PlanVersion3, PlanVersion4, 5} {
		t.Run("v"+string(rune('0'+version)), func(t *testing.T) {
			plan := base
			plan.Version = version
			if version == LegacyPlanVersion1 {
				plan.ExpiresAt = plan.CreatedAt.Add(LegacyPlanTTL)
			}
			plan.SHA256, err = digest(plan)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := ValidatePlan(plan) == nil, version == PlanVersion4; got != want {
				t.Fatalf("ValidatePlan accepted=%v, want %v", got, want)
			}
		})
	}
}

func TestIssueEditPrepareBindsTextAndHashes(t *testing.T) {
	s := editSnapshot(t)
	q := Request{Kind: KindIssueEdit, Summary: "New title", Description: "New body"}
	base, err := prepareEdit(t, s, q)
	if err != nil {
		t.Fatal(err)
	}
	if base.Request.Summary != q.Summary || base.Request.Description != q.Description {
		t.Fatalf("plan request = %+v; text must be stored verbatim without a marker", base.Request)
	}
	redigest := func(p Plan) string {
		t.Helper()
		sha, err := digest(p)
		if err != nil {
			t.Fatal(err)
		}
		return sha
	}
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"summary", func(p *Plan) { p.Request.Summary = "Other title" }},
		{"description", func(p *Plan) { p.Request.Description = "Other body" }},
		{"summary hash", func(p *Plan) { p.Snapshot.Text.SummarySHA256 = HashText(nil) }},
		{"description hash", func(p *Plan) { p.Snapshot.Text.DescriptionSHA256 = HashText(nil) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Deep copy so the shared base plan stays unchanged.
			raw, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var changed Plan
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&changed)
			if redigest(changed) == base.SHA256 {
				t.Fatal("digest did not change")
			}
			if ValidatePlan(changed) == nil {
				t.Fatal("ValidatePlan accepted a plan whose digest no longer matches")
			}
		})
	}
	t.Run("summary only and description only plans differ", func(t *testing.T) {
		a, err := prepareEdit(t, s, Request{Kind: KindIssueEdit, Summary: "New title"})
		if err != nil {
			t.Fatal(err)
		}
		b, err := prepareEdit(t, s, Request{Kind: KindIssueEdit, Description: "New body"})
		if err != nil {
			t.Fatal(err)
		}
		if a.SHA256 == b.SHA256 || a.SHA256 == base.SHA256 {
			t.Fatal("plans for different edits share a digest")
		}
	})
	t.Run("old text is never stored", func(t *testing.T) {
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		for _, sentinel := range []string{"old summary sentinel", "old description sentinel"} {
			if bytes.Contains(raw, []byte(sentinel)) {
				t.Fatalf("plan contains %q", sentinel)
			}
		}
	})
	t.Run("round trip through the codec", func(t *testing.T) {
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodePlan(bytes.NewReader(raw))
		if err != nil || decoded.SHA256 != base.SHA256 {
			t.Fatalf("DecodePlan() = %+v, %v", decoded, err)
		}
	})
	t.Run("prepare refuses invalid request or snapshot", func(t *testing.T) {
		if _, err := prepareEdit(t, s, Request{Kind: KindIssueEdit}); err == nil {
			t.Fatal("Prepare accepted an empty edit")
		}
		noText := s
		noText.Text = nil
		if _, err := prepareEdit(t, noText, q); err == nil {
			t.Fatal("Prepare accepted a snapshot without text hashes")
		}
		if _, err := prepareEdit(t, s, Request{Kind: KindIssueUpdate}); err == nil {
			t.Fatal("Prepare accepted a mismatched request kind")
		}
	})
}
