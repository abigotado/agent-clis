package operatorwrite

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVersion2PlansOutliveLegacyWindowForEveryWriteKind(t *testing.T) {
	tests := []struct {
		name     string
		snapshot func(*testing.T) Snapshot
		request  Request
	}{
		{"issue create", testCreateSnapshot, Request{Kind: KindIssueCreate, Summary: "Durable plan", Description: "Body"}},
		{"issue update", func(t *testing.T) Snapshot { return testSnapshot(t, KindIssueUpdate) }, Request{Kind: KindIssueUpdate}},
		{"comment add", func(t *testing.T) Snapshot { return testSnapshot(t, KindCommentAdd) }, Request{Kind: KindCommentAdd, CommentText: "Durable comment"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := test.snapshot(t)
			plan, err := Prepare(snapshot, test.request, snapshot.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if plan.Version != PlanVersion2 || !plan.ExpiresAt.IsZero() || PlanLifetime(plan.Version) != CurrentPlanLifetime {
				t.Fatalf("durable metadata = %#v", plan)
			}
			raw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(`"expires_at"`)) {
				t.Fatalf("v2 plan retained a legacy expiry: %s", raw)
			}
			for _, delayed := range []time.Duration{LegacyPlanTTL + time.Nanosecond, 72 * time.Hour} {
				if err := CheckFresh(plan, plan.CreatedAt.Add(delayed)); err != nil {
					t.Fatalf("v2 plan was stale after %s: %v", delayed, err)
				}
			}
		})
	}
}

func TestPlanValidationRejectsRedigestedInvalidVersionAndExpiryCombinations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Plan)
	}{
		{"unsupported version", func(plan *Plan) { plan.Version = 99 }},
		{"v2 with expiry", func(plan *Plan) { plan.ExpiresAt = plan.CreatedAt.Add(LegacyPlanTTL) }},
		{"v1 without expiry", func(plan *Plan) { plan.Version, plan.ExpiresAt = LegacyPlanVersion1, time.Time{} }},
		{"v1 zero expiry with legacy-shaped dates", func(plan *Plan) {
			plan.Version = LegacyPlanVersion1
			plan.Snapshot.CapturedAt = time.Date(0, time.December, 31, 23, 44, 0, 0, time.UTC)
			plan.CreatedAt = time.Date(0, time.December, 31, 23, 45, 0, 0, time.UTC)
			plan.ExpiresAt = time.Time{}
		}},
		{"future snapshot", func(plan *Plan) { plan.Snapshot.CapturedAt = plan.CreatedAt.Add(time.Nanosecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := testPlan(t, KindIssueUpdate)
			test.mutate(&plan)
			var err error
			plan.SHA256, err = digest(plan)
			if err != nil {
				t.Fatal(err)
			}
			if ValidatePlan(plan) == nil {
				t.Fatal("invalid plan accepted with a matching digest")
			}
		})
	}
}

func TestFrozenLegacyCreatePlanKeepsBytesDigestAndLifetime(t *testing.T) {
	raw, err := os.ReadFile("testdata/plan-v1-issue-create.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	plan, err := DecodePlan(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, raw) {
		t.Fatalf("v1 create bytes changed:\n%s\n%s", raw, again)
	}
	if !bytes.Contains(raw, []byte(`"expires_at"`)) || !strings.Contains(string(raw), `"version":1`) {
		t.Fatalf("frozen v1 create bytes changed:\n%s\n%s", raw, again)
	}
	if digest, err := digest(plan); err != nil || digest != plan.SHA256 {
		t.Fatalf("frozen v1 create digest=%q stored=%q err=%v", digest, plan.SHA256, err)
	}
	if err := CheckFresh(plan, plan.ExpiresAt); err == nil {
		t.Fatal("v1 create plan was accepted at its exact legacy expiry")
	}
}
