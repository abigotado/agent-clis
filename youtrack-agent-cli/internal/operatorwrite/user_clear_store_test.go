//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"context"
	"testing"
	"time"
)

func TestStoreClaimsAndFinalizesVersion4Plans(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot func(*testing.T) Snapshot
	}{
		{"state update", func(t *testing.T) Snapshot { return testSnapshot(t, KindIssueUpdate) }},
		{"user set", userSnapshot},
		{"clear", clearSnapshot},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := New(t.TempDir())
			plan, err := prepareSnapshot(test.snapshot(t))
			if err != nil {
				t.Fatal(err)
			}
			if plan.Version != PlanVersion4 {
				t.Fatalf("plan version = %d", plan.Version)
			}
			if _, err := store.Create(ctx, plan); err != nil {
				t.Fatal(err)
			}
			claimedAt := plan.CreatedAt.Add(3 * 24 * time.Hour)
			attempt, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt)
			if err != nil {
				t.Fatalf("v4 claim: %v", err)
			}
			record, err := store.Get(ctx, plan.ID)
			if err != nil || record.State != StateInFlight || record.Attempt == nil || record.Plan.Version != PlanVersion4 {
				t.Fatalf("claimed v4 record = %+v, %v", record, err)
			}
			record, err = store.Finalize(ctx, plan.ID, attempt, Result{State: StateApplied, Code: "WRITE_APPLIED", RemoteID: "2-3"}, claimedAt.Add(time.Minute))
			if err != nil || record.State != StateApplied {
				t.Fatalf("finalize v4 plan: %+v, %v", record, err)
			}
			reread, err := store.Get(ctx, plan.ID)
			if err != nil || reread.State != StateApplied || reread.Plan.SHA256 != plan.SHA256 || (reread.Plan.Snapshot.Field.TargetValue == nil) != (plan.Snapshot.Field.TargetValue == nil) {
				t.Fatalf("reread v4 record = %+v, %v", reread, err)
			}
		})
	}
}
