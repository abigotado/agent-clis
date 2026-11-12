package secretstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const stagedMax = 1024

func newStaged(f *fakeKeychain) *stagedStore {
	return newStagedStore(f, "keychain", stagedMax)
}

// wantError asserts err is an *Error of the given kind, op and status.
func wantError(t *testing.T, err error, op string, kind Kind, status int64) {
	t.Helper()
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want an *Error", err)
	}
	if se.Op != op || se.Kind != kind || se.Status != status || se.Backend != "keychain" {
		t.Fatalf("err = {op %q backend %q kind %v status %d}, want {op %q backend keychain kind %v status %d}",
			se.Op, se.Backend, se.Kind, se.Status, op, kind, status)
	}
	for _, leak := range []string{fakeService, fakeAccount} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error text %q contains the key part %q", err.Error(), leak)
		}
	}
}

func mustLoad(t *testing.T, s Store, want string) {
	t.Helper()
	got, err := s.Load(t.Context(), fakeKey)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Load = %q, want %q", got, want)
	}
}

func wantNoStage(t *testing.T, f *fakeKeychain) {
	t.Helper()
	if v, ok := f.value(fakeStageName); ok {
		t.Fatalf("a stage is left behind holding %q", v)
	}
}

func TestStageNameCannotCollideWithAnAccount(t *testing.T) {
	stage := fakeAcctName.stage()
	if stage.service != fakeService || stage.account != fakeAccount+"␟stage" {
		t.Fatalf("stage = %+v, want %q + U+241F + stage", stage, fakeAccount)
	}
	if err := validateKey("save", "keychain", Key{Service: stage.service, Account: stage.account}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a stage name passes key validation: %v", err)
	}
}

func TestSaveSequence(t *testing.T) {
	for _, tt := range []struct {
		name string
		old  string // empty: no account item yet
		want []string
	}{
		{"new item", "", []string{"add stage", "delete acct", "add acct", "delete stage"}},
		{"replace", "old", []string{"add stage", "delete acct", "add acct", "delete stage"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			if tt.old != "" {
				f.put(fakeAcctName, tt.old)
			}
			s := newStaged(f)
			var steps []int
			s.afterStep = func(n int) { steps = append(steps, n) }
			if err := s.Save(t.Context(), fakeKey, []byte("new")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if got := f.mutations(); !slices.Equal(got, tt.want) {
				t.Fatalf("mutations = %v, want %v", got, tt.want)
			}
			if !slices.Equal(steps, []int{1, 2, 3, 4}) {
				t.Fatalf("afterStep calls = %v, want 1 2 3 4", steps)
			}
			if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "new"}) {
				t.Fatalf("store = %v, want only the account holding new", got)
			}
		})
	}
}

// TestCrashWindows kills the process after each mutation of a Save, then loads
// and saves again as a restarted process would.
func TestCrashWindows(t *testing.T) {
	for _, tt := range []struct {
		name       string
		old        string
		crashAfter int
		wantStage  bool
		wantAcct   string // "" means the account item is absent
	}{
		{"after step 1 with an old value", "old", 1, true, "old"},
		{"after step 1 without an old value", "", 1, true, ""},
		{"after step 2", "old", 2, true, ""},
		{"after step 2 without an old value", "", 2, true, ""},
		{"after step 3", "old", 3, true, "v2"},
		{"after step 4", "old", 4, false, "v2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			if tt.old != "" {
				f.put(fakeAcctName, tt.old)
			}
			s := newStaged(f)
			f.crashAfterMutations(tt.crashAfter)
			runUntilCrash(t, f, func() { _ = s.Save(t.Context(), fakeKey, []byte("v2")) })

			if _, ok := f.value(fakeStageName); ok != tt.wantStage {
				t.Fatalf("stage present = %v, want %v", ok, tt.wantStage)
			}
			acct, ok := f.value(fakeAcctName)
			if ok != (tt.wantAcct != "") || acct != tt.wantAcct {
				t.Fatalf("account = %q (present %v), want %q", acct, ok, tt.wantAcct)
			}

			s = newStaged(f)
			mustLoad(t, s, "v2")
			if exists, err := s.Exists(t.Context(), fakeKey); err != nil || !exists {
				t.Fatalf("Exists after the crash = %v, %v, want true", exists, err)
			}

			if err := s.Save(t.Context(), fakeKey, []byte("v3")); err != nil {
				t.Fatalf("Save after the crash: %v", err)
			}
			wantNoStage(t, f)
			mustLoad(t, s, "v3")
			if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "v3"}) {
				t.Fatalf("store = %v, want only the account holding v3", got)
			}
		})
	}
}

// TestRollForwardKeepsTheNewestValue: a leftover stage is the newest value, so a
// Save that then fails to start must not have lost it.
func TestRollForwardKeepsTheNewestValue(t *testing.T) {
	f := newFakeKeychain()
	f.put(fakeAcctName, "old")
	f.put(fakeStageName, "newest")
	f.before = func(call string) error {
		if call == "add stage" {
			return &statusError{status: -1}
		}
		return nil
	}
	s := newStaged(f)
	wantError(t, s.Save(t.Context(), fakeKey, []byte("v3")), "save", KindReadOnly, -1)
	f.before = nil
	wantNoStage(t, f)
	if v, _ := f.value(fakeAcctName); v != "newest" {
		t.Fatalf("account = %q, want the leftover stage rolled forward into it", v)
	}
	mustLoad(t, s, "newest")
}

func TestRollForwardCrashWindows(t *testing.T) {
	for crashAfter := 1; crashAfter <= 3; crashAfter++ {
		t.Run(fmt.Sprintf("after mutation %d", crashAfter), func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.put(fakeStageName, "newest")
			f.crashAfterMutations(crashAfter)
			runUntilCrash(t, f, func() { _ = newStaged(f).Save(t.Context(), fakeKey, []byte("v3")) })
			s := newStaged(f)
			mustLoad(t, s, "newest")
			if err := s.Save(t.Context(), fakeKey, []byte("v3")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			wantNoStage(t, f)
			mustLoad(t, s, "v3")
		})
	}
}

func TestSaveIgnoresContextAfterStepOne(t *testing.T) {
	for _, afterStep := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("cancel after step %d", afterStep), func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			s := newStaged(f)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s.afterStep = func(n int) {
				if n == afterStep {
					cancel()
				}
			}
			if err := s.Save(ctx, fakeKey, []byte("new")); err != nil {
				t.Fatalf("Save after a cancel at step %d: %v", afterStep, err)
			}
			if ctx.Err() == nil {
				t.Fatal("the context was never canceled")
			}
			wantNoStage(t, f)
			mustLoad(t, s, "new")
		})
	}
}

func TestSaveCanceledBeforeStepOneTouchesNothing(t *testing.T) {
	f := newFakeKeychain()
	f.put(fakeAcctName, "old")
	s := newStaged(f)
	ctx, cancel := context.WithCancel(t.Context())
	// The context dies once the leftover-stage read is done, which is after
	// the first store access and before step 1.
	f.before = func(call string) error {
		if call == "read stage" {
			cancel()
		}
		return nil
	}
	err := s.Save(ctx, fakeKey, []byte("new"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Save = %v, want context.Canceled", err)
	}
	if got := f.mutations(); len(got) != 0 {
		t.Fatalf("mutations = %v, want none", got)
	}
	mustLoad(t, s, "old")
}

func TestPreChecksTouchNothing(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	long := strings.Repeat("a", stagedMax+1)
	for _, tt := range []struct {
		name string
		run  func(s *stagedStore) error
		want func(t *testing.T, err error)
	}{
		{"canceled save", func(s *stagedStore) error { return s.Save(canceled, fakeKey, []byte("x")) }, func(t *testing.T, err error) {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		}},
		{"canceled load", func(s *stagedStore) error { _, err := s.Load(canceled, fakeKey); return err }, func(t *testing.T, err error) {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		}},
		{"canceled exists", func(s *stagedStore) error { _, err := s.Exists(canceled, fakeKey); return err }, func(t *testing.T, err error) {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		}},
		{"canceled delete", func(s *stagedStore) error { return s.Delete(canceled, fakeKey) }, func(t *testing.T, err error) {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		}},
		{"invalid key on save", func(s *stagedStore) error {
			return s.Save(t.Context(), Key{Service: "bad/service", Account: "a"}, []byte("x"))
		}, func(t *testing.T, err error) {
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		}},
		{"invalid key on load", func(s *stagedStore) error {
			_, err := s.Load(t.Context(), Key{Service: fakeService, Account: "a#b"})
			return err
		}, func(t *testing.T, err error) {
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		}},
		{"invalid key on exists", func(s *stagedStore) error {
			_, err := s.Exists(t.Context(), Key{Service: fakeService, Account: ""})
			return err
		}, func(t *testing.T, err error) {
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		}},
		{"invalid key on delete", func(s *stagedStore) error { return s.Delete(t.Context(), Key{Service: "", Account: "a"}) }, func(t *testing.T, err error) {
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		}},
		{"empty secret", func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, nil) }, func(t *testing.T, err error) {
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		}},
		{"secret above the bound", func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte(long)) }, func(t *testing.T, err error) {
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			tt.want(t, tt.run(newStaged(f)))
			if got := f.calls(); len(got) != 0 {
				t.Fatalf("store calls = %v, want none", got)
			}
		})
	}
}

func TestSaveAtTheBoundSucceeds(t *testing.T) {
	f := newFakeKeychain()
	s := newStaged(f)
	secret := []byte(strings.Repeat("z", stagedMax))
	if err := s.Save(t.Context(), fakeKey, secret); err != nil {
		t.Fatalf("Save of exactly the bound: %v", err)
	}
	mustLoad(t, s, string(secret))
}

func TestForeignStage(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int64
	}{
		{"auth failed", statusAuthFailed},
		{"interaction not allowed on an unlocked keychain", statusInteractionNotAllowed},
	} {
		t.Run("Load ignores a stage: "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "mine")
			f.putForeign(fakeStageName, tt.status)
			mustLoad(t, newStaged(f), "mine")
			if _, ok := f.value(fakeStageName); !ok {
				t.Fatal("Load deleted the foreign stage")
			}
		})
		t.Run("Save deletes a stage: "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "mine")
			f.putForeign(fakeStageName, tt.status)
			s := newStaged(f)
			if err := s.Save(t.Context(), fakeKey, []byte("new")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			want := []string{"delete stage", "add stage", "delete acct", "add acct", "delete stage"}
			if got := f.mutations(); !slices.Equal(got, want) {
				t.Fatalf("mutations = %v, want %v", got, want)
			}
			mustLoad(t, s, "new")
			wantNoStage(t, f)
		})
	}

	t.Run("a lone foreign stage is not a value", func(t *testing.T) {
		f := newFakeKeychain()
		f.putForeign(fakeStageName, statusAuthFailed)
		s := newStaged(f)
		_, err := s.Load(t.Context(), fakeKey)
		wantError(t, err, "load", KindNotFound, statusItemNotFound)
		// Exists works by reference and cannot tell, so it is advisory.
		if ok, err := s.Exists(t.Context(), fakeKey); err != nil || !ok {
			t.Fatalf("Exists = %v, %v, want true", ok, err)
		}
	})
}

func TestLockedKeychainKeepsTheStage(t *testing.T) {
	setup := func() (*fakeKeychain, *stagedStore) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.put(fakeStageName, "newest")
		f.setLocked(true)
		return f, newStaged(f)
	}
	t.Run("Save", func(t *testing.T) {
		f, s := setup()
		wantError(t, s.Save(t.Context(), fakeKey, []byte("v3")), "save", KindInteractionRequired, statusInteractionNotAllowed)
		if got := f.mutations(); len(got) != 0 {
			t.Fatalf("mutations = %v, want none", got)
		}
		f.setLocked(false)
		if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "old", fakeStageName: "newest"}) {
			t.Fatalf("store = %v, want the stage and the account untouched", got)
		}
		mustLoad(t, s, "newest")
	})
	t.Run("Load does not fall back to the older account", func(t *testing.T) {
		_, s := setup()
		_, err := s.Load(t.Context(), fakeKey)
		wantError(t, err, "load", KindInteractionRequired, statusInteractionNotAllowed)
	})
}

// TestInteractionNotAllowedClassification covers the -25308 rule: AccessDenied
// only when the item's own keychain was unlocked both before and after the read.
func TestInteractionNotAllowedClassification(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(f *fakeKeychain)
		want  Kind
		// stageKept says whether Save must leave the stage in place.
		stageKept bool
	}{
		{
			name:  "unlocked before and after is a refused access list",
			setup: func(f *fakeKeychain) { f.putForeign(fakeStageName, statusInteractionNotAllowed) },
			want:  KindAccessDenied,
		},
		{
			name: "locked before and after",
			setup: func(f *fakeKeychain) {
				f.put(fakeStageName, "newest")
				f.setLocked(true)
			},
			want:      KindInteractionRequired,
			stageKept: true,
		},
		{
			// A: the keychain is unlocked between the read and the status check.
			name: "unlocked between the read and the second status",
			setup: func(f *fakeKeychain) {
				f.put(fakeStageName, "newest")
				f.setLocked(true)
				f.after = func(call string) {
					if call == "read stage" {
						f.setLocked(false)
					}
				}
			},
			want:      KindInteractionRequired,
			stageKept: true,
		},
		{
			name: "locked between the read and the second status",
			setup: func(f *fakeKeychain) {
				f.putForeign(fakeStageName, statusInteractionNotAllowed)
				f.after = func(call string) {
					if call == "read stage" {
						f.setLocked(true)
					}
				}
			},
			want:      KindInteractionRequired,
			stageKept: true,
		},
		{
			name: "status lookup fails after the read",
			setup: func(f *fakeKeychain) {
				f.putForeign(fakeStageName, statusInteractionNotAllowed)
				statusCalls := 0
				f.before = func(call string) error {
					if call != "status stage" {
						return nil
					}
					statusCalls++
					if statusCalls == 2 {
						return &statusError{status: -1}
					}
					return nil
				}
			},
			want:      KindInteractionRequired,
			stageKept: true,
		},
		{
			name: "status lookup fails before the read",
			setup: func(f *fakeKeychain) {
				f.putForeign(fakeStageName, statusInteractionNotAllowed)
				statusCalls := 0
				f.before = func(call string) error {
					if call != "status stage" {
						return nil
					}
					statusCalls++
					if statusCalls == 1 {
						return &statusError{status: -1}
					}
					return nil
				}
			},
			want:      KindInteractionRequired,
			stageKept: true,
		},
	} {
		t.Run("Save: "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			tt.setup(f)
			err := newStaged(f).Save(t.Context(), fakeKey, []byte("v3"))
			if tt.want == KindAccessDenied {
				// The stage was deleted and the Save went on.
				if err != nil {
					t.Fatalf("Save: %v", err)
				}
				return
			}
			wantError(t, err, "save", tt.want, statusInteractionNotAllowed)
			if _, ok := f.value(fakeStageName); ok != tt.stageKept {
				t.Fatalf("stage present = %v, want %v", ok, tt.stageKept)
			}
			if v, _ := f.value(fakeAcctName); v != "old" {
				t.Fatalf("account = %q, want it untouched", v)
			}
			if got := f.mutations(); len(got) != 0 {
				t.Fatalf("mutations = %v, want none", got)
			}
		})
		t.Run("Load: "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			tt.setup(f)
			s := newStaged(f)
			got, err := s.Load(t.Context(), fakeKey)
			if tt.want == KindAccessDenied {
				if err != nil || string(got) != "old" {
					t.Fatalf("Load = %q, %v, want the account value", got, err)
				}
				return
			}
			wantError(t, err, "load", tt.want, statusInteractionNotAllowed)
		})
	}
}

func TestContendedKeepsTheStage(t *testing.T) {
	f := newFakeKeychain()
	f.put(fakeAcctName, "old")
	// Someone recreates the account item between steps 2 and 3.
	f.after = func(call string) {
		if call == "delete acct" {
			f.put(fakeAcctName, "squatter")
			f.after = nil
		}
	}
	s := newStaged(f)
	err := s.Save(t.Context(), fakeKey, []byte("new"))
	wantError(t, err, "save", KindContended, statusDuplicateItem)
	if !errors.Is(err, ErrContended) {
		t.Fatalf("err = %v, want ErrContended", err)
	}
	if v, ok := f.value(fakeStageName); !ok || v != "new" {
		t.Fatalf("stage = %q (present %v), want it kept holding new", v, ok)
	}
	if v, _ := f.value(fakeAcctName); v != "squatter" {
		t.Fatalf("account = %q, want the other writer's item left alone", v)
	}
	mustLoad(t, s, "new")

	// The next Save rolls the kept stage forward, replacing the squatter.
	if err := s.Save(t.Context(), fakeKey, []byte("v3")); err != nil {
		t.Fatalf("Save after contention: %v", err)
	}
	wantNoStage(t, f)
	mustLoad(t, s, "v3")
}

func TestStageAddedByAnotherWriterIsNotDeleted(t *testing.T) {
	f := newFakeKeychain()
	f.put(fakeAcctName, "old")
	f.before = func(call string) error {
		if call == "add stage" {
			f.put(fakeStageName, "theirs")
			f.before = nil
		}
		return nil
	}
	err := newStaged(f).Save(t.Context(), fakeKey, []byte("new"))
	wantError(t, err, "save", KindContended, statusDuplicateItem)
	if v, _ := f.value(fakeStageName); v != "theirs" {
		t.Fatalf("stage = %q, want the other writer's stage untouched", v)
	}
	if v, _ := f.value(fakeAcctName); v != "old" {
		t.Fatalf("account = %q, want it untouched", v)
	}
}

// TestSaveFailureCleanup pins which steps delete the stage on failure: only a
// failure before step 2 completes.
func TestSaveFailureCleanup(t *testing.T) {
	failOn := func(f *fakeKeychain, target string, status int64) {
		f.before = func(call string) error {
			if call == target {
				return &statusError{status: status}
			}
			return nil
		}
	}
	for _, tt := range []struct {
		name      string
		fail      string
		status    int64
		wantKind  Kind
		stageKept bool
		wantAcct  string // "" means absent
	}{
		{"step 1 add stage", "add stage", -1, KindReadOnly, false, "old"},
		{"step 2 delete account", "delete acct", -1, KindReadOnly, false, "old"},
		{"step 2 delete account locked", "delete acct", statusInteractionNotAllowed, KindInteractionRequired, false, "old"},
		{"step 3 add account", "add acct", -1, KindReadOnly, true, ""},
		{"step 3 add account canceled", "add acct", statusUserCanceled, KindCanceled, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			failOn(f, tt.fail, tt.status)
			s := newStaged(f)
			wantError(t, s.Save(t.Context(), fakeKey, []byte("new")), "save", tt.wantKind, tt.status)
			f.before = nil
			if _, ok := f.value(fakeStageName); ok != tt.stageKept {
				t.Fatalf("stage present = %v, want %v", ok, tt.stageKept)
			}
			if v, ok := f.value(fakeAcctName); ok != (tt.wantAcct != "") || v != tt.wantAcct {
				t.Fatalf("account = %q (present %v), want %q", v, ok, tt.wantAcct)
			}
			// Whatever state the failure left, Load returns the newest
			// value the store still holds and a retry succeeds.
			if tt.stageKept {
				mustLoad(t, s, "new")
			} else {
				mustLoad(t, s, "old")
			}
			if err := s.Save(t.Context(), fakeKey, []byte("again")); err != nil {
				t.Fatalf("retry: %v", err)
			}
			mustLoad(t, s, "again")
			wantNoStage(t, f)
		})
	}

	t.Run("step 4 delete stage", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.before = func(call string) error {
			if call == "delete stage" {
				return &statusError{status: -1}
			}
			return nil
		}
		s := newStaged(f)
		wantError(t, s.Save(t.Context(), fakeKey, []byte("new")), "save", KindReadOnly, -1)
		f.before = nil
		if v, _ := f.value(fakeAcctName); v != "new" {
			t.Fatalf("account = %q, want new", v)
		}
		mustLoad(t, s, "new")
		if err := s.Save(t.Context(), fakeKey, []byte("again")); err != nil {
			t.Fatalf("retry: %v", err)
		}
		wantNoStage(t, f)
		mustLoad(t, s, "again")
	})
}

// TestSaveFailureAtTheLeftoverStage: any stage error other than AccessDenied
// aborts Save with nothing touched.
func TestSaveFailureAtTheLeftoverStage(t *testing.T) {
	for _, tt := range []struct {
		name     string
		status   int64
		wantKind Kind
	}{
		{"canceled", statusUserCanceled, KindCanceled},
		{"unclassified", -7, KindOther},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.put(fakeStageName, "newest")
			f.before = func(call string) error {
				if call == "read stage" {
					return &statusError{status: tt.status}
				}
				return nil
			}
			wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v3")), "save", tt.wantKind, tt.status)
			if got := f.mutations(); len(got) != 0 {
				t.Fatalf("mutations = %v, want none", got)
			}
			if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "old", fakeStageName: "newest"}) {
				t.Fatalf("store = %v, want it untouched", got)
			}
		})
	}
	t.Run("corrupt stage", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.put(fakeStageName, "")
		wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v3")), "save", KindCorrupt, 0)
		if got := f.mutations(); len(got) != 0 {
			t.Fatalf("mutations = %v, want none", got)
		}
	})
	t.Run("delete of an unreadable stage fails", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.putForeign(fakeStageName, statusAuthFailed)
		f.before = func(call string) error {
			if call == "delete stage" {
				return &statusError{status: -1}
			}
			return nil
		}
		wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v3")), "save", KindReadOnly, -1)
		if v, _ := f.value(fakeAcctName); v != "old" {
			t.Fatalf("account = %q, want it untouched", v)
		}
	})
}

// TestStatusTable pins every row of the status classification for reads,
// lookups and writes.
func TestStatusTable(t *testing.T) {
	failWith := func(target string, status int64) func(f *fakeKeychain) {
		return func(f *fakeKeychain) {
			f.before = func(call string) error {
				if call == target {
					return &statusError{status: status}
				}
				return nil
			}
		}
	}
	readRows := []struct {
		name   string
		status int64
		want   Kind
	}{
		{"not found", statusItemNotFound, KindNotFound},
		{"auth failed", statusAuthFailed, KindAccessDenied},
		{"user canceled", statusUserCanceled, KindCanceled},
		{"duplicate on a read is not contention", statusDuplicateItem, KindOther},
		{"unclassified", -4242, KindOther},
	}
	for _, tt := range readRows {
		t.Run("read "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "v")
			failWith("read acct", tt.status)(f)
			_, err := newStaged(f).Load(t.Context(), fakeKey)
			wantError(t, err, "load", tt.want, tt.status)
		})
	}
	t.Run("read failure without a status", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "v")
		f.before = func(call string) error {
			if call == "read acct" {
				return errors.New("some allocation failure")
			}
			return nil
		}
		_, err := newStaged(f).Load(t.Context(), fakeKey)
		wantError(t, err, "load", KindOther, 0)
	})
	t.Run("stored value above the bound", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, strings.Repeat("x", stagedMax+1))
		_, err := newStaged(f).Load(t.Context(), fakeKey)
		wantError(t, err, "load", KindTooLarge, 0)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("stored value empty", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "")
		_, err := newStaged(f).Load(t.Context(), fakeKey)
		wantError(t, err, "load", KindCorrupt, 0)
	})
	t.Run("stored value of exactly the bound", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, strings.Repeat("x", stagedMax))
		if got, err := newStaged(f).Load(t.Context(), fakeKey); err != nil || len(got) != stagedMax {
			t.Fatalf("Load = %d bytes, %v, want %d bytes", len(got), err, stagedMax)
		}
	})

	for _, tt := range []struct {
		name   string
		status int64
		want   Kind
	}{
		{"auth failed", statusAuthFailed, KindAccessDenied},
		{"interaction not allowed", statusInteractionNotAllowed, KindInteractionRequired},
		{"user canceled", statusUserCanceled, KindCanceled},
		{"unclassified", -4242, KindOther},
	} {
		t.Run("exists lookup "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			failWith("exists acct", tt.status)(f)
			_, err := newStaged(f).Exists(t.Context(), fakeKey)
			wantError(t, err, "exists", tt.want, tt.status)
		})
	}

	for _, tt := range []struct {
		name   string
		target string
		status int64
		want   Kind
	}{
		{"step 1 duplicate", "add stage", statusDuplicateItem, KindContended},
		{"step 3 duplicate", "add acct", statusDuplicateItem, KindContended},
		{"add auth failed", "add stage", statusAuthFailed, KindAccessDenied},
		{"add interaction not allowed", "add stage", statusInteractionNotAllowed, KindInteractionRequired},
		{"add canceled", "add stage", statusUserCanceled, KindCanceled},
		{"add unclassified is read-only", "add stage", 100001, KindReadOnly},
		{"delete unclassified is read-only", "delete acct", 100001, KindReadOnly},
	} {
		t.Run("write "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			failWith(tt.target, tt.status)(f)
			wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("new")), "save", tt.want, tt.status)
		})
	}
}

func TestExists(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(f *fakeKeychain)
		want  bool
	}{
		{"nothing", func(f *fakeKeychain) {}, false},
		{"account only", func(f *fakeKeychain) { f.put(fakeAcctName, "v") }, true},
		{"stage only", func(f *fakeKeychain) { f.put(fakeStageName, "v") }, true},
		{"account and stage", func(f *fakeKeychain) {
			f.put(fakeAcctName, "v")
			f.put(fakeStageName, "v")
		}, true},
		{"locked account", func(f *fakeKeychain) {
			f.put(fakeAcctName, "v")
			f.setLocked(true)
		}, true},
		{"another account of the service", func(f *fakeKeychain) {
			f.put(itemName{service: fakeService, account: "other"}, "v")
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			tt.setup(f)
			got, err := newStaged(f).Exists(t.Context(), fakeKey)
			if err != nil || got != tt.want {
				t.Fatalf("Exists = %v, %v, want %v", got, err, tt.want)
			}
			for _, call := range f.calls() {
				if strings.HasPrefix(call, "read ") || isMutation(call) {
					t.Fatalf("Exists made the call %q; it must only look items up by reference", call)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	t.Run("removes the account and the stage", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "v")
		f.put(fakeStageName, "newer")
		f.put(itemName{service: fakeService, account: "other"}, "keep")
		s := newStaged(f)
		if err := s.Delete(t.Context(), fakeKey); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		want := map[itemName]string{{service: fakeService, account: "other"}: "keep"}
		if got := f.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("store = %v, want only the other account", got)
		}
		if _, err := s.Load(t.Context(), fakeKey); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Load after Delete = %v, want ErrNotFound", err)
		}
	})
	t.Run("missing item succeeds", func(t *testing.T) {
		if err := newStaged(newFakeKeychain()).Delete(t.Context(), fakeKey); err != nil {
			t.Fatalf("Delete of a missing key: %v", err)
		}
	})
	t.Run("a stage that cannot be removed does not stop the account delete", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "v")
		f.put(fakeStageName, "newer")
		f.before = func(call string) error {
			if call == "delete stage" {
				return &statusError{status: -1}
			}
			return nil
		}
		wantError(t, newStaged(f).Delete(t.Context(), fakeKey), "delete", KindReadOnly, -1)
		if _, ok := f.value(fakeAcctName); ok {
			t.Fatal("the account item was not deleted")
		}
	})
	t.Run("locked keychain", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "v")
		f.setLocked(true)
		wantError(t, newStaged(f).Delete(t.Context(), fakeKey), "delete", KindInteractionRequired, statusInteractionNotAllowed)
	})
}

// interleavings calls visit with every non-decreasing assignment of a writer
// progress (0..4 completed Save steps) to each of n store calls.
func interleavings(n int, visit func(progress []int)) {
	progress := make([]int, n)
	var rec func(i, lowest int)
	rec = func(i, lowest int) {
		if i == n {
			visit(slices.Clone(progress))
			return
		}
		for p := lowest; p <= 4; p++ {
			progress[i] = p
			rec(i+1, p)
		}
	}
	rec(0, 0)
}

// advanceWriter applies steps from..to-1 of a concurrent Save of "new" to the
// store, directly, as another process's Save would.
func advanceWriter(f *fakeKeychain, from, to int) {
	for step := from + 1; step <= to; step++ {
		switch step {
		case 1:
			f.put(fakeStageName, "new")
		case 2:
			f.remove(fakeAcctName)
		case 3:
			f.put(fakeAcctName, "new")
		case 4:
			f.remove(fakeStageName)
		}
	}
}

// reader runs op against a store whose account holds "old" while a writer
// Save advances to the given progress before each store call.
func raceReader(progress []int, op func(s *stagedStore) error) error {
	f := newFakeKeychain()
	f.put(fakeAcctName, "old")
	call, applied := 0, 0
	f.before = func(string) error {
		if call < len(progress) && progress[call] > applied {
			advanceWriter(f, applied, progress[call])
			applied = progress[call]
		}
		call++
		return nil
	}
	return op(newStaged(f))
}

func TestLoadAmidAConcurrentSave(t *testing.T) {
	interleavings(8, func(progress []int) {
		var got []byte
		err := raceReader(progress, func(s *stagedStore) error {
			var err error
			got, err = s.Load(t.Context(), fakeKey)
			return err
		})
		if err != nil || (string(got) != "old" && string(got) != "new") {
			t.Fatalf("Load with the writer at %v = %q, %v, want old or new", progress, got, err)
		}
	})
}

func TestExistsAmidAConcurrentSave(t *testing.T) {
	interleavings(3, func(progress []int) {
		var found bool
		err := raceReader(progress, func(s *stagedStore) error {
			var err error
			found, err = s.Exists(t.Context(), fakeKey)
			return err
		})
		if err != nil || !found {
			t.Fatalf("Exists with the writer at %v = %v, %v, want true", progress, found, err)
		}
	})
}

// TestLoadRetriesAreBounded: a store that keeps hiding the item makes Load
// stop after stage, account, stage, account.
func TestLoadRetriesAreBounded(t *testing.T) {
	f := newFakeKeychain()
	_, err := newStaged(f).Load(t.Context(), fakeKey)
	wantError(t, err, "load", KindNotFound, statusItemNotFound)
	var reads []string
	for _, call := range f.calls() {
		if strings.HasPrefix(call, "read ") {
			reads = append(reads, call)
		}
	}
	want := []string{"read stage", "read acct", "read stage", "read acct"}
	if !slices.Equal(reads, want) {
		t.Fatalf("reads = %v, want %v", reads, want)
	}
}

func TestLoadReturnsACopy(t *testing.T) {
	f := newFakeKeychain()
	f.put(fakeAcctName, "secret")
	s := newStaged(f)
	got, err := s.Load(t.Context(), fakeKey)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	clear(got)
	mustLoad(t, s, "secret")
}
