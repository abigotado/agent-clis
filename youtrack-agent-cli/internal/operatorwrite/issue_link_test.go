package operatorwrite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func linkSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s := testSnapshot(t, KindIssueLink)
	s.Link = &Link{
		Target:    Issue{ID: "2-9", ReadableID: "OPS-7", ProjectID: "0-2", ProjectKey: "OPS", Updated: 200},
		Type:      LinkType{ID: "105-1", Name: "Depend", Directed: true, SourceToTarget: "depends on", TargetToSource: "is required for"},
		Direction: LinkOutward, Phrase: "depends on", LinkID: "105-1s",
	}
	return s
}

func TestIssueLinkSnapshotValidation(t *testing.T) {
	undirected := func(s *Snapshot) {
		s.Link.Type = LinkType{ID: "105-0", Name: "Relates", SourceToTarget: "relates to", TargetToSource: "relates to"}
		s.Link.Direction, s.Link.Phrase, s.Link.LinkID = LinkUndirected, "relates to", "105-0"
	}
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		valid  bool
	}{
		{"valid outward", func(*Snapshot) {}, true},
		{"valid inward", func(s *Snapshot) {
			s.Link.Direction, s.Link.Phrase, s.Link.LinkID = LinkInward, "is required for", "105-1t"
		}, true},
		{"valid undirected", undirected, true},
		{"valid aggregation", func(s *Snapshot) { s.Link.Type.Aggregation = true }, true},
		{"server link id is not derived from the type", func(s *Snapshot) { s.Link.LinkID = "opaque.link:9" }, true},
		{"missing link", func(s *Snapshot) { s.Link = nil }, false},
		{"self link by id", func(s *Snapshot) { s.Link.Target.ID = s.Issue.ID }, false},
		{"self link by readable id", func(s *Snapshot) { s.Link.Target.ReadableID = s.Issue.ReadableID }, false},
		{"target without identity", func(s *Snapshot) { s.Link.Target = Issue{} }, false},
		{"target zero updated", func(s *Snapshot) { s.Link.Target.Updated = 0 }, false},
		{"target bad project key", func(s *Snapshot) { s.Link.Target.ProjectKey = "ops" }, false},
		{"phrase differs from outward side", func(s *Snapshot) { s.Link.Phrase = "Depends On" }, false},
		{"outward phrase names the inward side", func(s *Snapshot) { s.Link.Phrase = "is required for" }, false},
		{"inward phrase names the outward side", func(s *Snapshot) { s.Link.Direction, s.Link.LinkID = LinkInward, "105-1t" }, false},
		{"unknown direction", func(s *Snapshot) { s.Link.Direction = "both" }, false},
		{"empty direction", func(s *Snapshot) { s.Link.Direction = "" }, false},
		{"undirected direction on a directed type", func(s *Snapshot) { s.Link.Direction = LinkUndirected }, false},
		{"outward direction on an undirected type", func(s *Snapshot) {
			undirected(s)
			s.Link.Direction = LinkOutward
		}, false},
		{"directed type with equal phrases", func(s *Snapshot) { s.Link.Type.TargetToSource = "depends on" }, false},
		{"empty link id", func(s *Snapshot) { s.Link.LinkID = "" }, false},
		{"link id with a path separator", func(s *Snapshot) { s.Link.LinkID = "105-1/s" }, false},
		{"link id with a query", func(s *Snapshot) { s.Link.LinkID = "105-1s?x=1" }, false},
		{"empty type name", func(s *Snapshot) { s.Link.Type.Name = "" }, false},
		{"empty source phrase", func(s *Snapshot) { s.Link.Type.SourceToTarget = "" }, false},
		{"bad type id", func(s *Snapshot) { s.Link.Type.ID = "../1" }, false},
		{"extra text precondition", func(s *Snapshot) { s.Text = editSnapshot(t).Text }, false},
		{"extra comment", func(s *Snapshot) { s.Comment = testCommentDeleteSnapshot(t).Comment }, false},
		{"extra field", func(s *Snapshot) { s.Field = testSnapshot(t, KindIssueUpdate).Field }, false},
		{"extra project", func(s *Snapshot) { s.Project = &Project{ID: "0-1", Key: "BGR"} }, false},
		{"missing source identity", func(s *Snapshot) { s.Issue = Issue{} }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := linkSnapshot(t)
			test.mutate(&s)
			if got := ValidateSnapshot(s) == nil; got != test.valid {
				t.Fatalf("ValidateSnapshot() valid=%v, want %v", got, test.valid)
			}
		})
	}
}

func TestOtherKindsRefuseALink(t *testing.T) {
	for _, kind := range []Kind{KindIssueUpdate, KindIssueEdit, KindCommentDelete, KindCommentAdd, KindAttachmentAdd} {
		t.Run(string(kind), func(t *testing.T) {
			var s Snapshot
			switch kind {
			case KindIssueEdit:
				s = editSnapshot(t)
			case KindCommentDelete:
				s = testCommentDeleteSnapshot(t)
			case KindAttachmentAdd:
				s = attachmentSnapshot(t)
			default:
				s = testSnapshot(t, kind)
			}
			s.Link = linkSnapshot(t).Link
			if ValidateSnapshot(s) == nil {
				t.Fatalf("%s snapshot accepted a link", kind)
			}
		})
	}
}

func TestIssueLinkRequestCarriesNoPayload(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		valid bool
	}{
		{"bare kind", `{"kind":"issue.link"}`, true},
		{"summary", `{"kind":"issue.link","summary":"x"}`, false},
		{"description", `{"kind":"issue.link","description":"x"}`, false},
		{"comment", `{"kind":"issue.link","comment_text":"x"}`, false},
		{"unknown member", `{"kind":"issue.link","target":"OPS-7"}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeRequest(strings.NewReader(test.raw))
			if (err == nil) != test.valid {
				t.Fatalf("DecodeRequest() error = %v, want valid=%v", err, test.valid)
			}
		})
	}
}

func TestIssueLinkPlanVersionRules(t *testing.T) {
	if got := PlanVersionFor(KindIssueLink); got != PlanVersion4 {
		t.Fatalf("PlanVersionFor(issue.link) = %d", got)
	}
	s := linkSnapshot(t)
	base, err := Prepare(s, Request{Kind: KindIssueLink}, s.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if base.Version != PlanVersion4 || !durablePlanVersion(base.Version) || PlanLifetime(base.Version) != CurrentPlanLifetime || !base.ExpiresAt.IsZero() {
		t.Fatalf("plan = %+v", base)
	}
	for _, version := range []int{LegacyPlanVersion1, PlanVersion2, PlanVersion3, PlanVersion4, 5} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
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

func TestIssueLinkPlanDigestBindsEveryLinkMember(t *testing.T) {
	s := linkSnapshot(t)
	base, err := Prepare(s, Request{Kind: KindIssueLink}, s.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlan(base); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Plan){
		"target id":       func(p *Plan) { p.Snapshot.Link.Target.ID = "2-10" },
		"target project":  func(p *Plan) { p.Snapshot.Link.Target.ProjectKey = "XYZ" },
		"type name":       func(p *Plan) { p.Snapshot.Link.Type.Name = "Other" },
		"aggregation":     func(p *Plan) { p.Snapshot.Link.Type.Aggregation = true },
		"link id":         func(p *Plan) { p.Snapshot.Link.LinkID = "105-1x" },
		"source issue id": func(p *Plan) { p.Snapshot.Issue.ID = "2-4" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := base
			link := *base.Snapshot.Link
			plan.Snapshot.Link = &link
			mutate(&plan)
			if ValidatePlan(plan) == nil {
				t.Fatal("mutated plan kept its digest")
			}
		})
	}
}

func TestIssueLinkSnapshotRejectsUnknownAndCaseVariantMembers(t *testing.T) {
	raw, err := json.Marshal(linkSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(raw)); err != nil {
		t.Fatalf("DecodeSnapshot(valid): %v", err)
	}
	for name, mutated := range map[string][]byte{
		"extra member":     bytes.Replace(raw, []byte(`"link_id"`), []byte(`"extra":1,"link_id"`), 1),
		"case variant key": bytes.Replace(raw, []byte(`"link_id"`), []byte(`"Link_Id"`), 1),
		"duplicate key":    bytes.Replace(raw, []byte(`"phrase"`), []byte(`"direction":"outward","phrase"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSnapshot(bytes.NewReader(mutated)); err == nil {
				t.Fatal("DecodeSnapshot accepted a non-canonical link")
			}
		})
	}
}

func TestIssueLinkProjectRefs(t *testing.T) {
	s := linkSnapshot(t)
	if refs := s.ProjectRefs(); len(refs) != 2 || refs[0] != (Project{ID: "0-1", Key: "BGR"}) || refs[1] != (Project{ID: "0-2", Key: "OPS"}) {
		t.Fatalf("cross-project refs = %+v", refs)
	}
	s.Link.Target.ProjectID, s.Link.Target.ProjectKey = s.Issue.ProjectID, s.Issue.ProjectKey
	if refs := s.ProjectRefs(); len(refs) != 1 {
		t.Fatalf("same-project refs = %+v", refs)
	}
	if refs := testSnapshot(t, KindIssueUpdate).ProjectRefs(); len(refs) != 1 {
		t.Fatalf("non-link refs = %+v", refs)
	}
}
