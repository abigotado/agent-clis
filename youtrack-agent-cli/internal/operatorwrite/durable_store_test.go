//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDurableStoreReopensAndNeverReplaysUnknownOutcomeAfterDays(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	plan := testPlan(t, KindIssueUpdate)
	if _, err := New(directory).Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	claimedAt := plan.CreatedAt.Add(3 * 24 * time.Hour)
	attempt, err := New(directory).Claim(ctx, plan.ID, plan.SHA256, claimedAt)
	if err != nil {
		t.Fatalf("reopened durable plan claim: %v", err)
	}
	if _, err := New(directory).Finalize(ctx, plan.ID, attempt, Result{State: StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN"}, claimedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reopened := New(directory)
	record, err := reopened.Get(ctx, plan.ID)
	if err != nil || record.State != StateUnknown || !record.NonReplayable() {
		t.Fatalf("reopened record = %#v, %v", record, err)
	}
	if _, err := reopened.Claim(ctx, plan.ID, plan.SHA256, claimedAt.Add(30*24*time.Hour)); err == nil {
		t.Fatal("unknown durable outcome replayed after a long delay")
	}
}

func TestDurableStoreAllowsOnlyOneLateConcurrentClaim(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir())
	plan := testPlan(t, KindCommentAdd)
	if _, err := store.Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := store.Claim(ctx, plan.ID, plan.SHA256, plan.CreatedAt.Add(7*24*time.Hour)); err == nil {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("late claims succeeded = %d, want 1", winners.Load())
	}
}
