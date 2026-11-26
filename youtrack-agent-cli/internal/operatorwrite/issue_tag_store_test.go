//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"testing"
	"time"
)

func TestStoreClaimsAndFinalizesIssueTagPlans(t *testing.T) {
	for _, kind := range tagKinds {
		t.Run(string(kind), func(t *testing.T) {
			ctx := t.Context()
			store := New(t.TempDir())
			s := tagSnapshot(t, kind)
			plan, err := Prepare(s, Request{Kind: kind}, s.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Create(ctx, plan); err != nil {
				t.Fatal(err)
			}
			claimedAt := plan.CreatedAt.Add(3 * 24 * time.Hour)
			attempt, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt)
			if err != nil {
				t.Fatalf("v4 %s claim: %v", kind, err)
			}
			record, err := store.Finalize(ctx, plan.ID, attempt, Result{State: StateApplied, Code: "WRITE_APPLIED", RemoteID: "6-1"}, claimedAt.Add(time.Minute))
			if err != nil || record.State != StateApplied {
				t.Fatalf("finalize = %+v, %v", record, err)
			}
			reread, err := store.Get(ctx, plan.ID)
			if err != nil || reread.Plan.SHA256 != plan.SHA256 || reread.Plan.Snapshot.Tag == nil || *reread.Plan.Snapshot.Tag != *plan.Snapshot.Tag {
				t.Fatalf("reread = %+v, %v", reread, err)
			}
			if _, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt.Add(time.Hour)); err == nil {
				t.Fatalf("applied %s plan was claimable again", kind)
			}
		})
	}
}
