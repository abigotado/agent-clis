package operatorwrite

import (
	"strings"
	"testing"
)

// withMarker rewrites a prepared create or comment plan into the shape an
// older release produced: the marker appended and the given version, expiry
// and digest.
func withMarker(t *testing.T, plan Plan, version int) Plan {
	t.Helper()
	switch plan.Request.Kind {
	case KindIssueCreate:
		plan.Request.Description = finalDescription(plan.Request.Description, plan.ID)
	case KindCommentAdd:
		plan.Request.CommentText += "\n\n" + Marker(plan.ID)
	}
	plan.Version = version
	if version == LegacyPlanVersion1 {
		plan.ExpiresAt = plan.CreatedAt.Add(LegacyPlanTTL)
	}
	var err error
	if plan.SHA256, err = digest(plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestPrepareSendsTextVerbatim(t *testing.T) {
	create := testCreateSnapshot(t)
	comment := testSnapshot(t, KindCommentAdd)
	for _, test := range []struct {
		name     string
		snapshot Snapshot
		request  Request
	}{
		{"description", create, Request{Kind: KindIssueCreate, Summary: "S", Description: "Line one\n\nLine two"}},
		{"empty description", create, Request{Kind: KindIssueCreate, Summary: "S"}},
		{"comment", comment, Request{Kind: KindCommentAdd, CommentText: "Hello\n\nthere"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Prepare(test.snapshot, test.request, test.snapshot.CapturedAt.Add(1))
			if err != nil {
				t.Fatal(err)
			}
			if plan.Version != PlanVersion5 || plan.Request != test.request || plan.CarriesMarker() || strings.Contains(plan.Request.Description+plan.Request.CommentText, "operator-write") {
				t.Fatalf("plan is not verbatim v5: %+v", plan)
			}
		})
	}
}

func TestVersion5CommentTextMustBeCanonical(t *testing.T) {
	snapshot := testSnapshot(t, KindCommentAdd)
	for _, text := range []string{" a", "a ", "a\n", "\na", "a\r\nb", "a\x00b"} {
		if _, err := Prepare(snapshot, Request{Kind: KindCommentAdd, CommentText: text}, snapshot.CapturedAt.Add(1)); err == nil {
			t.Fatalf("non-canonical comment %q accepted", text)
		}
	}
}

func TestHistoricalMarkerPlansStillValidate(t *testing.T) {
	create, comment := testCreateSnapshot(t), testSnapshot(t, KindCommentAdd)
	for _, test := range []struct {
		name     string
		snapshot Snapshot
		request  Request
		versions []int
	}{
		{"create", create, Request{Kind: KindIssueCreate, Summary: "S", Description: "Body"}, []int{LegacyPlanVersion1, PlanVersion2, PlanVersion4}},
		{"empty create", create, Request{Kind: KindIssueCreate, Summary: "S"}, []int{PlanVersion4}},
		{"comment", comment, Request{Kind: KindCommentAdd, CommentText: "Hi\r\nthere "}, []int{LegacyPlanVersion1, PlanVersion2}},
	} {
		plan, err := Prepare(test.snapshot, test.request, test.snapshot.CapturedAt.Add(1))
		if test.name == "comment" {
			plan, err = prepareLegacyComment(t, test.snapshot, test.request)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, version := range test.versions {
			old := withMarker(t, plan, version)
			if err := ValidatePlan(old); err != nil || !old.CarriesMarker() {
				t.Fatalf("%s v%d: err=%v carries=%v", test.name, version, err, old.CarriesMarker())
			}
			// A footer-less plan of an old version is refused.
			stripped := old
			stripped.Request = plan.Request
			stripped.SHA256, _ = digest(stripped)
			if ValidatePlan(stripped) == nil {
				t.Fatalf("%s v%d without marker accepted", test.name, version)
			}
		}
	}
}

// prepareLegacyComment builds the canonical plan for a comment whose text is
// not valid in version 5, so the historical rules are exercised.
func prepareLegacyComment(t *testing.T, snapshot Snapshot, request Request) (Plan, error) {
	t.Helper()
	valid := request
	valid.CommentText = "placeholder"
	plan, err := Prepare(snapshot, valid, snapshot.CapturedAt.Add(1))
	if err != nil {
		return Plan{}, err
	}
	plan.Request = request
	return plan, nil
}

func TestValidatePlanVersion5Kinds(t *testing.T) {
	create, err := prepareSnapshot(testCreateSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	update := testPlan(t, KindIssueUpdate)
	for _, test := range []struct {
		name string
		plan Plan
		want bool
	}{
		{"create", create, true},
		{"update at v5", update, false},
	} {
		plan := test.plan
		plan.Version = PlanVersion5
		plan.SHA256, _ = digest(plan)
		if got := ValidatePlan(plan) == nil; got != test.want {
			t.Fatalf("%s: accepted=%v want %v", test.name, got, test.want)
		}
	}
	timed := create
	timed.ExpiresAt = timed.CreatedAt.Add(LegacyPlanTTL)
	timed.SHA256, _ = digest(timed)
	if ValidatePlan(timed) == nil {
		t.Fatal("v5 plan with expiry accepted")
	}
}

func TestValidatePlanVersion5RefusesOtherKindsAndItsOwnMarker(t *testing.T) {
	for _, test := range []struct {
		snapshot Snapshot
		request  Request
	}{
		{testCommentDeleteSnapshot(t), Request{Kind: KindCommentDelete}},
		{editSnapshot(t), Request{Kind: KindIssueEdit, Summary: "New title"}},
		{linkSnapshot(t), Request{Kind: KindIssueLink}},
		{attachmentSnapshot(t), Request{Kind: KindAttachmentAdd}},
		{testSnapshot(t, KindIssueUpdate), Request{Kind: KindIssueUpdate}},
	} {
		plan, err := Prepare(test.snapshot, test.request, test.snapshot.CapturedAt.Add(1))
		if err != nil {
			t.Fatal(err)
		}
		plan.Version = PlanVersion5
		plan.SHA256, _ = digest(plan)
		if ValidatePlan(plan) == nil {
			t.Fatalf("v5 plan accepted for kind %s", test.request.Kind)
		}
	}
	create, err := prepareSnapshot(testCreateSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	comment := testPlan(t, KindCommentAdd)
	for _, plan := range []Plan{create, comment} {
		plan.Request.Description = map[bool]string{true: plan.Request.Description + "\n\n" + Marker(plan.ID), false: ""}[plan.Request.Kind == KindIssueCreate]
		if plan.Request.Kind == KindCommentAdd {
			plan.Request.CommentText += "\n\n" + Marker(plan.ID)
		}
		plan.SHA256, _ = digest(plan)
		if ValidatePlan(plan) == nil {
			t.Fatalf("v5 %s plan carrying its own marker accepted", plan.Request.Kind)
		}
	}
}
