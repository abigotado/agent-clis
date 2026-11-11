//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"testing"
	"time"
)

func TestStoreClaimsAndFinalizesIssueEditPlan(t *testing.T) {
	ctx := t.Context()
	store := New(t.TempDir())
	s := editSnapshot(t)
	plan, err := Prepare(s, Request{Kind: KindIssueEdit, Summary: "New title"}, s.CapturedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	claimedAt := plan.CreatedAt.Add(3 * 24 * time.Hour)
	attempt, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt)
	if err != nil {
		t.Fatalf("v4 issue.edit claim: %v", err)
	}
	record, err := store.Finalize(ctx, plan.ID, attempt, Result{State: StateApplied, Code: "WRITE_APPLIED", RemoteID: "2-3"}, claimedAt.Add(time.Minute))
	if err != nil || record.State != StateApplied {
		t.Fatalf("finalize = %+v, %v", record, err)
	}
	reread, err := store.Get(ctx, plan.ID)
	if err != nil || reread.Plan.SHA256 != plan.SHA256 || reread.Plan.Snapshot.Text == nil || *reread.Plan.Snapshot.Text != *plan.Snapshot.Text {
		t.Fatalf("reread = %+v, %v", reread, err)
	}
	if _, err := store.Claim(ctx, plan.ID, plan.SHA256, claimedAt.Add(time.Hour)); err == nil {
		t.Fatal("applied issue.edit plan was claimable again")
	}
}
