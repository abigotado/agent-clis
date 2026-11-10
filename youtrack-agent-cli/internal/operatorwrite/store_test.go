//go:build linux || (darwin && cgo)

package operatorwrite

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreExclusiveClaimAndConsumedFinalization(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir())
	p := testPlan(t, KindIssueUpdate)
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, p); err == nil {
		t.Fatal("duplicate plan replaced")
	}
	if _, err := s.Claim(ctx, p.ID, "bad", p.CreatedAt); err == nil {
		t.Fatal("wrong digest accepted")
	}
	r, err := s.Get(ctx, p.ID)
	if err != nil || r.State != StatePrepared {
		t.Fatalf("failed prechecks consumed plan: %+v %v", r, err)
	}
	claimedAt := p.CreatedAt.Add(24 * time.Hour)
	a, err := s.Claim(ctx, p.ID, p.SHA256, claimedAt)
	if err != nil {
		t.Fatalf("v2 claim expired by wall clock: %v", err)
	}
	r, err = s.Get(ctx, p.ID)
	if err != nil || r.State != StateInFlight || !r.NonReplayable() {
		t.Fatalf("claim not durable: %+v %v", r, err)
	}
	for _, result := range []Result{{State: StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN"}, {State: StateOperatorRequired, Code: "OPERATOR_REQUIRED"}, {State: StateReconciled, Code: "OBSERVED_APPLIED", RemoteID: "4-1"}} {
		r, err = s.Finalize(ctx, p.ID, a, result, claimedAt.Add(time.Minute))
		if err != nil || !r.NonReplayable() {
			t.Fatalf("finalization: %+v %v", r, err)
		}
		if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt.Add(time.Minute)); err == nil {
			t.Fatal("consumed plan claimed again")
		}
	}
	if _, err := s.Finalize(ctx, p.ID, a, Result{State: StatePrepared, Code: "RESET"}, time.Now()); err == nil {
		t.Fatal("finalization restored eligibility")
	}
	if _, err := os.Stat(filepath.Join(s.Root(), p.ID+".claim")); err != nil {
		t.Fatal("consumption erased")
	}
}

func TestConcurrentClaimsAllowOneAttempt(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir())
	p := testPlan(t, KindCommentAdd)
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("claims succeeded = %d, want 1", winners.Load())
	}
}

func TestClaimFailuresRetainConsumptionAndDoNotReturnPermission(t *testing.T) {
	for _, failure := range []string{"partial write", "file sync", "directory sync"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			s := New(t.TempDir())
			p := testPlan(t, KindIssueUpdate)
			if _, err := s.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("injected durability failure")
			switch failure {
			case "partial write":
				s.writeFile = func(f *os.File, b []byte) (int, error) {
					n, err := f.Write(b[:1])
					return n, errors.Join(err, sentinel)
				}
			case "file sync":
				s.syncFile = func(*os.File) error { return sentinel }
			case "directory sync":
				s.syncDir = func(*os.File) error { return sentinel }
			}
			a, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt)
			if err == nil || a.ID != "" {
				t.Fatal("failed durability authorized dispatch")
			}
			if _, err := os.Stat(filepath.Join(s.Root(), p.ID+".claim")); err != nil {
				t.Fatal("partial consumption not retained")
			}
			s.writeFile = nil
			s.syncFile = nil
			s.syncDir = nil
			if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
				t.Fatal("partially persisted claim replayed")
			}
		})
	}
}

func TestFinalizeFailurePreservesConsumption(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir())
	p := testPlan(t, KindIssueUpdate)
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	a, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	s.syncDir = func(*os.File) error { return errors.New("sync failure") }
	if _, err := s.Finalize(ctx, p.ID, a, Result{State: StateApplied, Code: "APPLIED"}, p.CreatedAt); err == nil {
		t.Fatal("finalization failure hidden")
	}
	s.syncDir = nil
	if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
		t.Fatal("finalization erased consumption")
	}
}

func TestPrivateFilesystemTraps(t *testing.T) {
	for _, trap := range []string{"symlink", "hardlink", "broad permissions", "oversized", "directory"} {
		t.Run(trap, func(t *testing.T) {
			ctx := context.Background()
			s := New(t.TempDir())
			p := testPlan(t, KindCommentAdd)
			if _, err := s.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.Root(), p.ID+".json")
			switch trap {
			case "symlink":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "broad permissions":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(MaxPlanBytes + 1); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Get(ctx, p.ID); err == nil {
				t.Fatal("unsafe plan read")
			}
			if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
				t.Fatal("unsafe plan dispatched")
			}
		})
	}
}

func TestClaimMarkerTrapAlwaysConsumes(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir())
	p := testPlan(t, KindIssueUpdate)
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(s.Root(), p.ID+".claim")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
		t.Fatal("dangling claim marker bypassed")
	}
}

func TestPrivateExclusiveExports(t *testing.T) {
	ctx := context.Background()
	privateParent := t.TempDir()
	if err := os.Chmod(privateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateParent, "snapshot.json")
	snapshot := testSnapshot(t, KindIssueUpdate)
	if err := ValidateExportPath(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(ctx, path, snapshot); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("export permissions: %v %v", info, err)
	}
	if err := WriteSnapshot(ctx, path, snapshot); err == nil {
		t.Fatal("existing export replaced")
	}
	if err := ValidateExportPath(ctx, path); err == nil {
		t.Fatal("existing export precheck passed")
	}
	sentinelPath := filepath.Join(privateParent, "sentinel")
	if err := WritePlan(ctx, sentinelPath, testPlan(t, KindCommentAdd)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(sentinelPath), "link")
	if err := os.Symlink(sentinelPath, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePlan(ctx, link, testPlan(t, KindCommentAdd)); err == nil {
		t.Fatal("symlink export overwritten")
	}
}

func TestExportParentMustAlreadyBePrivate(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "snapshot.json")
	if err := ValidateExportPath(ctx, path); err == nil {
		t.Fatal("0755 export parent passed read-only validation")
	}
	if err := WriteSnapshot(ctx, path, testSnapshot(t, KindIssueUpdate)); err == nil {
		t.Fatal("0755 export parent accepted snapshot")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused export created an artifact: %v", err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("export helper changed parent permissions to %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("refused export created %d entries", len(entries))
	}
	missingParent := filepath.Join(parent, "absent")
	if err := ValidateExportPath(ctx, filepath.Join(missingParent, "snapshot.json")); err == nil {
		t.Fatal("missing export parent passed validation")
	}
	if _, err := os.Stat(missingParent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only validation created a parent: %v", err)
	}
}

func TestStoreRefusesInsecureNamespaceAndOrphanResults(t *testing.T) {
	for _, kind := range []string{"shared namespace", "namespace symlink", "orphan result", "tampered digest"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			s := New(t.TempDir())
			p := testPlan(t, KindIssueUpdate)
			if _, err := s.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "shared namespace":
				if err := os.Chmod(s.Root(), 0o755); err != nil {
					t.Fatal(err)
				}
			case "namespace symlink":
				if err := os.Rename(s.Root(), s.Root()+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(s.Root()+".old", s.Root()); err != nil {
					t.Fatal(err)
				}
			case "orphan result":
				d, err := openDirectory(s.Root(), false)
				if err != nil {
					t.Fatal(err)
				}
				if err := d.create(p.ID+".result", []byte(`{"state":"applied","code":"APPLIED"}`), nil); err != nil {
					t.Fatal(err)
				}
				if err := d.close(); err != nil {
					t.Fatal(err)
				}
			case "tampered digest":
				p.Snapshot.Issue.Updated++
				raw, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(filepath.Join(s.Root(), p.ID+".json"), os.O_WRONLY|os.O_TRUNC, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(raw); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Get(ctx, p.ID); err == nil {
				t.Fatal("invalid store accepted")
			}
			if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
				t.Fatal("invalid store dispatched")
			}
		})
	}
}

func TestFinalizationRequiresClaimOwnership(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir())
	p := testPlan(t, KindIssueUpdate)
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	a, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	a.ID = "YTOA-AAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := s.Finalize(ctx, p.ID, a, Result{State: StateApplied, Code: "APPLIED"}, p.CreatedAt); err == nil {
		t.Fatal("wrong claim token finalized")
	}
	r, err := s.Get(ctx, p.ID)
	if err != nil || r.State != StateInFlight {
		t.Fatalf("claim changed after refused token: %+v %v", r, err)
	}
}

func TestTerminalEvidenceCannotBeDowngradedOrChanged(t *testing.T) {
	for _, terminal := range []State{StateApplied, StateRejected, StateReconciled} {
		t.Run(string(terminal), func(t *testing.T) {
			ctx := context.Background()
			s := New(t.TempDir())
			p := testPlan(t, KindCommentAdd)
			if _, err := s.Create(ctx, p); err != nil {
				t.Fatal(err)
			}
			a, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			original := Result{State: terminal, Code: "VERIFIED_TERMINAL", RemoteID: "4-1"}
			if _, err := s.Finalize(ctx, p.ID, a, original, p.CreatedAt); err != nil {
				t.Fatal(err)
			}
			// Repeating the identical durable result is harmless and idempotent.
			if _, err := s.Finalize(ctx, p.ID, a, original, p.CreatedAt); err != nil {
				t.Fatal(err)
			}
			for _, changed := range []Result{
				{State: StateOperatorRequired, Code: "OPERATOR_REQUIRED"},
				{State: StateUnknown, Code: "WRITE_OUTCOME_UNKNOWN"},
				{State: StateReconciled, Code: "OTHER_OBSERVATION", RemoteID: "4-2"},
				{State: terminal, Code: "VERIFIED_TERMINAL", RemoteID: "4-2"},
			} {
				if _, err := s.Finalize(ctx, p.ID, a, changed, p.CreatedAt.Add(time.Minute)); err == nil {
					t.Fatalf("terminal evidence replaced by %+v", changed)
				}
			}
			r, err := s.Get(ctx, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if r.State != terminal || r.Result == nil || *r.Result != original {
				t.Fatalf("terminal evidence changed: %+v", r)
			}
			if _, err := s.Claim(ctx, p.ID, p.SHA256, p.CreatedAt); err == nil {
				t.Fatal("terminal result restored dispatch eligibility")
			}
		})
	}
}

func TestCanceledStoreDoesNotCreateFiles(t *testing.T) {
	s := New(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Create(ctx, testPlan(t, KindIssueUpdate)); err == nil {
		t.Fatal("canceled create succeeded")
	}
	if _, err := os.Stat(s.Root()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled create changed storage: %v", err)
	}
}
