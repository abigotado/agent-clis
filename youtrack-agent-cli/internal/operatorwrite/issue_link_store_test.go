//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"testing"
	"time"
)

func TestStoreClaimsAndFinalizesIssueLinkPlan(t *testing.T) {
	ctx := t.Context()
	store := New(t.TempDir())
	s := linkSnapshot(t)
	plan, err := Prepare(s, Request{Kind: KindIssueLink}, s.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	claimedAt := plan.CreatedAt.Add(3 * 24 * time.Hour)
	attempt, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt)
	if err != nil {
		t.Fatalf("v4 issue.link claim: %v", err)
	}
	record, err := store.Finalize(ctx, plan.ID, attempt, Result{State: StateApplied, Code: "WRITE_APPLIED", RemoteID: "2-9"}, claimedAt.Add(time.Minute))
	if err != nil || record.State != StateApplied {
		t.Fatalf("finalize = %+v, %v", record, err)
	}
	reread, err := store.Get(ctx, plan.ID)
	if err != nil || reread.Plan.SHA256 != plan.SHA256 || reread.Plan.Snapshot.Link == nil || *reread.Plan.Snapshot.Link != *plan.Snapshot.Link {
		t.Fatalf("reread = %+v, %v", reread, err)
	}
	if _, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt.Add(time.Hour)); err == nil {
		t.Fatal("applied issue.link plan was claimable again")
	}
}
