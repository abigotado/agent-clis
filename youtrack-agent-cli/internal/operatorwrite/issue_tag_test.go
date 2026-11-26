package operatorwrite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var tagKinds = []Kind{KindIssueTag, KindIssueUntag}

func tagSnapshot(t *testing.T, kind Kind) Snapshot {
	t.Helper()
	s := testSnapshot(t, kind)
	s.Tag = &Tag{ID: "6-1", Name: "release", Type: "IssueTag", OwnerID: "1-1", OwnerLogin: "operator", UntagOnResolve: true, Shared: true}
	return s
}

func TestIssueTagSnapshotValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		valid  bool
	}{
		{"valid", func(*Snapshot) {}, true},
		{"type Tag", func(s *Snapshot) { s.Tag.Type = "Tag" }, true},
		{"unshared", func(s *Snapshot) { s.Tag.Shared, s.Tag.UntagOnResolve = false, false }, true},
		{"name with spaces and unicode", func(s *Snapshot) { s.Tag.Name = "Релиз 1 / beta" }, true},
		{"name at the byte limit", func(s *Snapshot) { s.Tag.Name = strings.Repeat("a", 255) }, true},
		{"missing tag", func(s *Snapshot) { s.Tag = nil }, false},
		{"empty id", func(s *Snapshot) { s.Tag.ID = "" }, false},
		{"id with a path separator", func(s *Snapshot) { s.Tag.ID = "6-1/x" }, false},
		{"id with a query", func(s *Snapshot) { s.Tag.ID = "6-1?x=1" }, false},
		{"empty name", func(s *Snapshot) { s.Tag.Name = "" }, false},
		{"blank name", func(s *Snapshot) { s.Tag.Name = "  " }, false},
		{"name over the byte limit", func(s *Snapshot) { s.Tag.Name = strings.Repeat("a", 256) }, false},
		{"name with a newline", func(s *Snapshot) { s.Tag.Name = "a\nb" }, false},
		{"name with a NUL", func(s *Snapshot) { s.Tag.Name = "a\x00b" }, false},
		{"name with a tab", func(s *Snapshot) { s.Tag.Name = "a\tb" }, false},
		{"name with DEL", func(s *Snapshot) { s.Tag.Name = "a\x7fb" }, false},
		{"name with invalid utf8", func(s *Snapshot) { s.Tag.Name = "a\xffb" }, false},
		{"empty type", func(s *Snapshot) { s.Tag.Type = "" }, false},
		{"case variant type", func(s *Snapshot) { s.Tag.Type = "issuetag" }, false},
		{"unknown type", func(s *Snapshot) { s.Tag.Type = "SavedQuery" }, false},
		{"missing owner id", func(s *Snapshot) { s.Tag.OwnerID = "" }, false},
		{"owner id with a separator", func(s *Snapshot) { s.Tag.OwnerID = "1/1" }, false},
		{"missing owner login", func(s *Snapshot) { s.Tag.OwnerLogin = "" }, false},
		{"extra link", func(s *Snapshot) { s.Link = unlinkSnapshot(t).Link }, false},
		{"extra text precondition", func(s *Snapshot) { s.Text = editSnapshot(t).Text }, false},
		{"extra comment", func(s *Snapshot) { s.Comment = testCommentDeleteSnapshot(t).Comment }, false},
		{"extra field", func(s *Snapshot) { s.Field = testSnapshot(t, KindIssueUpdate).Field }, false},
		{"extra project", func(s *Snapshot) { s.Project = &Project{ID: "0-1", Key: "BGR"} }, false},
		{"extra attachment", func(s *Snapshot) { s.Attachment = attachmentSnapshot(t).Attachment }, false},
		{"missing issue identity", func(s *Snapshot) { s.Issue = Issue{} }, false},
	}
	for _, kind := range tagKinds {
		for _, test := range tests {
			t.Run(string(kind)+"/"+test.name, func(t *testing.T) {
				s := tagSnapshot(t, kind)
				test.mutate(&s)
				if got := ValidateSnapshot(s) == nil; got != test.valid {
					t.Fatalf("ValidateSnapshot() valid=%v, want %v", got, test.valid)
				}
			})
		}
	}
}

func TestOtherKindsRefuseATag(t *testing.T) {
	kinds := []Kind{KindIssueUpdate, KindIssueEdit, KindCommentDelete, KindCommentAdd, KindAttachmentAdd, KindIssueLink, KindIssueUnlink}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			var s Snapshot
			switch kind {
			case KindIssueEdit:
				s = editSnapshot(t)
			case KindCommentDelete:
				s = testCommentDeleteSnapshot(t)
			case KindAttachmentAdd:
				s = attachmentSnapshot(t)
			case KindIssueLink:
				s = linkSnapshot(t)
			case KindIssueUnlink:
				s = unlinkSnapshot(t)
			default:
				s = testSnapshot(t, kind)
			}
			s.Tag = tagSnapshot(t, KindIssueTag).Tag
			if ValidateSnapshot(s) == nil {
				t.Fatalf("%s snapshot accepted a tag", kind)
			}
		})
	}
}

func TestIssueTagRequestCarriesNoPayload(t *testing.T) {
	for _, kind := range tagKinds {
		tests := []struct {
			name  string
			raw   string
			valid bool
		}{
			{"bare kind", `{"kind":"` + string(kind) + `"}`, true},
			{"summary", `{"kind":"` + string(kind) + `","summary":"x"}`, false},
			{"description", `{"kind":"` + string(kind) + `","description":"x"}`, false},
			{"comment", `{"kind":"` + string(kind) + `","comment_text":"x"}`, false},
			{"unknown member", `{"kind":"` + string(kind) + `","tag":"release"}`, false},
		}
		for _, test := range tests {
			t.Run(string(kind)+"/"+test.name, func(t *testing.T) {
				_, err := DecodeRequest(strings.NewReader(test.raw))
				if (err == nil) != test.valid {
					t.Fatalf("DecodeRequest() error = %v, want valid=%v", err, test.valid)
				}
			})
		}
	}
}

func TestIssueTagPlanVersionRules(t *testing.T) {
	for _, kind := range tagKinds {
		t.Run(string(kind), func(t *testing.T) {
			if got := PlanVersionFor(kind); got != PlanVersion4 {
				t.Fatalf("PlanVersionFor(%s) = %d", kind, got)
			}
			s := tagSnapshot(t, kind)
			base, err := Prepare(s, Request{Kind: kind}, s.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if base.Version != PlanVersion4 || !durablePlanVersion(base.Version) || PlanLifetime(base.Version) != CurrentPlanLifetime || !base.ExpiresAt.IsZero() {
				t.Fatalf("plan = %+v", base)
			}
			for _, version := range []int{LegacyPlanVersion1, PlanVersion2, PlanVersion3, PlanVersion4, 5} {
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
					t.Fatalf("version %d: ValidatePlan accepted=%v, want %v", version, got, want)
				}
			}
		})
	}
}

func TestIssueTagPlanDigestBindsEveryTagMember(t *testing.T) {
	for _, kind := range tagKinds {
		s := tagSnapshot(t, kind)
		base, err := Prepare(s, Request{Kind: kind}, s.CapturedAt.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidatePlan(base); err != nil {
			t.Fatal(err)
		}
		tests := map[string]func(*Plan){
			"id":               func(p *Plan) { p.Snapshot.Tag.ID = "6-2" },
			"name":             func(p *Plan) { p.Snapshot.Tag.Name = "other" },
			"type":             func(p *Plan) { p.Snapshot.Tag.Type = "Tag" },
			"owner id":         func(p *Plan) { p.Snapshot.Tag.OwnerID = "1-2" },
			"owner login":      func(p *Plan) { p.Snapshot.Tag.OwnerLogin = "someone" },
			"untag on resolve": func(p *Plan) { p.Snapshot.Tag.UntagOnResolve = !p.Snapshot.Tag.UntagOnResolve },
			"shared":           func(p *Plan) { p.Snapshot.Tag.Shared = !p.Snapshot.Tag.Shared },
			"issue id":         func(p *Plan) { p.Snapshot.Issue.ID = "2-4" },
		}
		for name, mutate := range tests {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				plan := base
				tag := *base.Snapshot.Tag
				plan.Snapshot.Tag = &tag
				mutate(&plan)
				if ValidatePlan(plan) == nil {
					t.Fatal("mutated plan kept its digest")
				}
			})
		}
	}
}

func TestIssueTagSnapshotRejectsUnknownAndCaseVariantMembers(t *testing.T) {
	for _, kind := range tagKinds {
		raw, err := json.Marshal(tagSnapshot(t, kind))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSnapshot(bytes.NewReader(raw)); err != nil {
			t.Fatalf("DecodeSnapshot(valid %s): %v", kind, err)
		}
		for name, mutated := range map[string][]byte{
			"extra member":     bytes.Replace(raw, []byte(`"owner_id"`), []byte(`"extra":1,"owner_id"`), 1),
			"case variant key": bytes.Replace(raw, []byte(`"owner_id"`), []byte(`"Owner_Id"`), 1),
			"duplicate key":    bytes.Replace(raw, []byte(`"owner_id"`), []byte(`"name":"release","owner_id"`), 1),
			"case variant tag": bytes.Replace(raw, []byte(`"tag":`), []byte(`"Tag":`), 1),
		} {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				if _, err := DecodeSnapshot(bytes.NewReader(mutated)); err == nil {
					t.Fatal("DecodeSnapshot accepted a non-canonical tag")
				}
			})
		}
	}
}

func TestIssueTagProjectRefsAreTheIssueProjectOnly(t *testing.T) {
	for _, kind := range tagKinds {
		s := tagSnapshot(t, kind)
		if refs := s.ProjectRefs(); len(refs) != 1 || refs[0] != (Project{ID: "0-1", Key: "BGR"}) {
			t.Fatalf("%s refs = %+v", kind, refs)
		}
	}
}

func TestIssueTagAndUntagAreDistinctKinds(t *testing.T) {
	s := tagSnapshot(t, KindIssueTag)
	if _, err := Prepare(s, Request{Kind: KindIssueUntag}, s.CapturedAt.Add(time.Minute)); err == nil {
		t.Fatal("an issue.tag snapshot prepared with an issue.untag request")
	}
	if _, err := Prepare(s, Request{Kind: KindIssueLink}, s.CapturedAt.Add(time.Minute)); err == nil {
		t.Fatal("an issue.tag snapshot prepared with an issue.link request")
	}
	u := tagSnapshot(t, KindIssueUntag)
	if _, err := Prepare(u, Request{Kind: KindIssueTag}, u.CapturedAt.Add(time.Minute)); err == nil {
		t.Fatal("an issue.untag snapshot prepared with an issue.tag request")
	}
}

func TestLegacyPlanKindExcludesTagKinds(t *testing.T) {
	for _, kind := range tagKinds {
		if legacyPlanKind(kind) {
			t.Fatalf("legacyPlanKind(%s) = true", kind)
		}
	}
}
