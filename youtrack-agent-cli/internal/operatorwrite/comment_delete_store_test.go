//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCommentDeleteStoreClaimsRemainDurableAcrossRestart(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, Plan, string)
	}{
		{
			name: "reopened unknown outcome remains consumed",
			run: func(t *testing.T, plan Plan, root string) {
				store := New(root)
				attempt, err := store.Claim(t.Context(), plan.ID, plan.SHA256, plan.CreatedAt.Add(30*24*time.Hour))
				if err != nil {
					t.Fatalf("Claim() after reopen: %v", err)
				}
				if _, err := store.Finalize(t.Context(), plan.ID, attempt, Result{State: StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN"}, attempt.ClaimedAt.Add(time.Minute)); err != nil {
					t.Fatalf("Finalize() unknown: %v", err)
				}
				reopened, err := New(root).Get(t.Context(), plan.ID)
				if err != nil || reopened.State != StateUnknown || !reopened.NonReplayable() || reopened.Attempt == nil || *reopened.Attempt != attempt {
					t.Fatalf("reopened record=%#v err=%v", reopened, err)
				}
				if _, err := New(root).Claim(t.Context(), plan.ID, plan.SHA256, attempt.ClaimedAt.Add(24*time.Hour)); err == nil {
					t.Fatal("reopened unknown comment deletion was replayable")
				}
			},
		},
		{
			name: "concurrent reopened claims permit one dispatch",
			run: func(t *testing.T, plan Plan, root string) {
				var winners atomic.Int32
				var group sync.WaitGroup
				for range 16 {
					group.Add(1)
					go func() {
						defer group.Done()
						if _, err := New(root).Claim(context.Background(), plan.ID, plan.SHA256, plan.CreatedAt.Add(30*24*time.Hour)); err == nil {
							winners.Add(1)
						}
					}()
				}
				group.Wait()
				if winners.Load() != 1 {
					t.Fatalf("concurrent reopened claims=%d, want 1", winners.Load())
				}
				reopened, err := New(root).Get(t.Context(), plan.ID)
				if err != nil || reopened.State != StateInFlight || !reopened.NonReplayable() || reopened.Attempt == nil {
					t.Fatalf("reopened record=%#v err=%v", reopened, err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testCommentDeleteSnapshot(t)
			plan, err := Prepare(snapshot, Request{Kind: KindCommentDelete}, snapshot.CapturedAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			if _, err := New(root).Create(t.Context(), plan); err != nil {
				t.Fatal(err)
			}
			test.run(t, plan, root)
		})
	}
}
