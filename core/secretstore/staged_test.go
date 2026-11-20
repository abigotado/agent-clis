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

// wantError asserts err is an *Error of the given kind, op and status, with
// no Reason.
func wantError(t *testing.T, err error, op string, kind Kind, status int64) {
	t.Helper()
	wantErrorReason(t, err, op, kind, status, "")
}

// wantErrorReason asserts err is an *Error of the given kind, op, status and
// reason.
func wantErrorReason(t *testing.T, err error, op string, kind Kind, status int64, reason Reason) {
	t.Helper()
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want an *Error", err)
	}
	if se.Op != op || se.Kind != kind || se.Status != status || se.Reason != reason || se.Backend != "keychain" {
		t.Fatalf("err = {op %q backend %q kind %v status %d reason %q}, want {op %q backend keychain kind %v status %d reason %q}",
			se.Op, se.Backend, se.Kind, se.Status, se.Reason, op, kind, status, reason)
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
	wantError(t, s.Save(t.Context(), fakeKey, []byte("v3")), "save", KindOther, -1)
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

// lockStatuses are the statuses a locked keychain returns with the UI disabled:
// -25308 on some systems and -25293 on a locked file keychain.
var lockStatuses = []struct {
	name   string
	status int64
}{
	{"interaction not allowed", statusInteractionNotAllowed},
	{"auth failed", statusAuthFailed},
}

// TestLockedKeychainKeepsTheStage: a locked keychain needs the user whichever
// status it reports, and nothing it refuses may be taken for a foreign identity
// whose stage Save then deletes.
func TestLockedKeychainKeepsTheStage(t *testing.T) {
	for _, ls := range lockStatuses {
		setup := func() (*fakeKeychain, *stagedStore) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.put(fakeStageName, "newest")
			f.setLockedWith(ls.status)
			return f, newStaged(f)
		}
		t.Run(ls.name+"/Save", func(t *testing.T) {
			f, s := setup()
			wantError(t, s.Save(t.Context(), fakeKey, []byte("v3")), "save", KindInteractionRequired, ls.status)
			if got := f.mutations(); len(got) != 0 {
				t.Fatalf("mutations = %v, want none", got)
			}
			f.setLocked(false)
			if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "old", fakeStageName: "newest"}) {
				t.Fatalf("store = %v, want the stage and the account untouched", got)
			}
			mustLoad(t, s, "newest")
		})
		t.Run(ls.name+"/Load does not fall back to the older account", func(t *testing.T) {
			_, s := setup()
			_, err := s.Load(t.Context(), fakeKey)
			wantError(t, err, "load", KindInteractionRequired, ls.status)
		})
		t.Run(ls.name+"/Save of a new item", func(t *testing.T) {
			f := newFakeKeychain()
			f.setLockedWith(ls.status)
			wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v1")), "save", KindInteractionRequired, ls.status)
			if got := f.snapshot(); len(got) != 0 {
				t.Fatalf("store = %v, want it empty", got)
			}
		})
		t.Run(ls.name+"/Save of a new item whose stage read is refused too", func(t *testing.T) {
			// The real keychain refuses even the read of a stage that is not
			// there, so the read must not delete anything either.
			f := newFakeKeychain()
			f.setLockedWith(ls.status)
			f.before = func(call string) error {
				if call == "read stage" {
					return &statusError{status: ls.status}
				}
				return nil
			}
			wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v1")), "save", KindInteractionRequired, ls.status)
			if got := f.mutations(); len(got) != 0 {
				t.Fatalf("mutations = %v, want none", got)
			}
		})
		t.Run(ls.name+"/Save over an item", func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.setLockedWith(ls.status)
			wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v2")), "save", KindInteractionRequired, ls.status)
			f.setLocked(false)
			if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "old"}) {
				t.Fatalf("store = %v, want the account untouched", got)
			}
		})
		t.Run(ls.name+"/Delete", func(t *testing.T) {
			f, s := setup()
			wantError(t, s.Delete(t.Context(), fakeKey), "delete", KindInteractionRequired, ls.status)
			f.setLocked(false)
			if got := f.snapshot(); !reflect.DeepEqual(got, map[itemName]string{fakeAcctName: "old", fakeStageName: "newest"}) {
				t.Fatalf("store = %v, want it untouched", got)
			}
		})
	}
}

// TestLockSensitiveClassification covers the rule for -25308 and -25293 alike:
// AccessDenied only when the item's own keychain was unlocked at both probes,
// before and after the read, whichever status the keychain returned.
func TestLockSensitiveClassification(t *testing.T) {
	for _, ls := range lockStatuses {
		t.Run(ls.name, func(t *testing.T) { testLockSensitiveClassification(t, ls.status) })
	}
}

func testLockSensitiveClassification(t *testing.T, status int64) {
	for _, tt := range []struct {
		name  string
		setup func(f *fakeKeychain)
		want  Kind
		// stageKept says whether Save must leave the stage in place.
		stageKept bool
	}{
		{
			name:  "unlocked before and after is a refused access list",
			setup: func(f *fakeKeychain) { f.putForeign(fakeStageName, status) },
			want:  KindAccessDenied,
		},
		{
			name: "locked before and after",
			setup: func(f *fakeKeychain) {
				f.put(fakeStageName, "newest")
				f.setLockedWith(status)
			},
			want:      KindInteractionRequired,
			stageKept: true,
		},
		{
			// A: the keychain is unlocked between the read and the status check.
			name: "unlocked between the read and the second status",
			setup: func(f *fakeKeychain) {
				f.put(fakeStageName, "newest")
				f.setLockedWith(status)
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
				f.putForeign(fakeStageName, status)
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
				f.putForeign(fakeStageName, status)
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
				f.putForeign(fakeStageName, status)
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
			wantError(t, err, "save", tt.want, status)
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
			wantError(t, err, "load", tt.want, status)
		})
	}
}

// TestLockRaceOnWrites: a refused add or delete reads as AccessDenied only if
// the keychain was unlocked both before and after the call. The hook fails the
// call and flips the lock while the call is in flight, so the probe taken
// before it and the probe taken after it disagree.
func TestLockRaceOnWrites(t *testing.T) {
	for _, ls := range lockStatuses {
		for _, tt := range []struct {
			name         string
			target       string
			lockedBefore bool
			lockedAfter  bool
			want         Kind
		}{
			{"add, unlocked before and after", "add stage", false, false, KindAccessDenied},
			{"add, locked before and after", "add stage", true, true, KindInteractionRequired},
			{"add, unlocked during the call", "add stage", true, false, KindInteractionRequired},
			{"add, locked during the call", "add stage", false, true, KindInteractionRequired},
			{"delete, unlocked before and after", "delete acct", false, false, KindAccessDenied},
			{"delete, locked before and after", "delete acct", true, true, KindInteractionRequired},
			{"delete, unlocked during the call", "delete acct", true, false, KindInteractionRequired},
			{"delete, locked during the call", "delete acct", false, true, KindInteractionRequired},
		} {
			t.Run(ls.name+"/"+tt.name, func(t *testing.T) {
				f := newFakeKeychain()
				f.put(fakeAcctName, "old")
				// The delete rows reach step 2 only with an unlocked keychain,
				// so the lock before the call is set once step 1 is done.
				lock := func() { f.setLocked(tt.lockedBefore) }
				if tt.target == "delete acct" {
					f.after = func(call string) {
						if call == "add stage" {
							lock()
						}
					}
				} else {
					lock()
				}
				f.before = func(call string) error {
					if call != tt.target {
						return nil
					}
					f.setLocked(tt.lockedAfter)
					return &statusError{status: ls.status}
				}
				err := newStaged(f).Save(t.Context(), fakeKey, []byte("new"))
				wantError(t, err, "save", tt.want, ls.status)
			})
		}
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
		// lockDuring locks the keychain during the failing call, so the
		// failure reads as a lock and the stage cleanup fails too.
		lockDuring bool
	}{
		{"step 1 add stage", "add stage", -1, KindOther, false, "old", false},
		{"step 2 delete account", "delete acct", -1, KindOther, false, "old", false},
		{"step 2 delete account locked", "delete acct", statusInteractionNotAllowed, KindInteractionRequired, true, "old", true},
		{"step 2 delete account locked, auth failed", "delete acct", statusAuthFailed, KindInteractionRequired, true, "old", true},
		{"step 2 delete account refused on an unlocked keychain", "delete acct", statusAuthFailed, KindAccessDenied, false, "old", false},
		{"step 3 add account", "add acct", -1, KindOther, true, "", false},
		{"step 3 add account canceled", "add acct", statusUserCanceled, KindCanceled, true, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			failOn(f, tt.fail, tt.status)
			if tt.lockDuring {
				inject := f.before
				f.before = func(call string) error {
					err := inject(call)
					if err != nil {
						f.setLocked(true)
					}
					return err
				}
			}
			s := newStaged(f)
			wantError(t, s.Save(t.Context(), fakeKey, []byte("new")), "save", tt.wantKind, tt.status)
			f.before = nil
			f.setLocked(false)
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
		wantError(t, s.Save(t.Context(), fakeKey, []byte("new")), "save", KindOther, -1)
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
		wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("v3")), "save", KindOther, -1)
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
	// Both lock-sensitive statuses mean AccessDenied only on a keychain
	// confirmed unlocked, and InteractionRequired on a locked one.
	readRows := []struct {
		name   string
		status int64
		locked bool
		want   Kind
	}{
		{"not found", statusItemNotFound, false, KindNotFound},
		{"auth failed on an unlocked keychain", statusAuthFailed, false, KindAccessDenied},
		{"auth failed on a locked keychain", statusAuthFailed, true, KindInteractionRequired},
		{"interaction not allowed on an unlocked keychain", statusInteractionNotAllowed, false, KindAccessDenied},
		{"interaction not allowed on a locked keychain", statusInteractionNotAllowed, true, KindInteractionRequired},
		{"user canceled", statusUserCanceled, false, KindCanceled},
		{"duplicate on a read is not contention", statusDuplicateItem, false, KindOther},
		{"unclassified", -4242, false, KindOther},
	}
	for _, tt := range readRows {
		t.Run("read "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "v")
			f.setLocked(tt.locked)
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
		locked bool
		want   Kind
	}{
		{"auth failed on an unlocked keychain", statusAuthFailed, false, KindAccessDenied},
		{"auth failed on a locked keychain", statusAuthFailed, true, KindInteractionRequired},
		{"interaction not allowed on an unlocked keychain", statusInteractionNotAllowed, false, KindAccessDenied},
		{"interaction not allowed on a locked keychain", statusInteractionNotAllowed, true, KindInteractionRequired},
		{"user canceled", statusUserCanceled, false, KindCanceled},
		{"unclassified", -4242, false, KindOther},
	} {
		t.Run("exists lookup "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.setLocked(tt.locked)
			failWith("exists acct", tt.status)(f)
			_, err := newStaged(f).Exists(t.Context(), fakeKey)
			wantError(t, err, "exists", tt.want, tt.status)
		})
	}

	for _, tt := range []struct {
		name   string
		target string
		status int64
		// lockedBefore is the call after which the keychain is locked, so the
		// failing call sees it locked before it runs; "start" is from the
		// beginning and "" is never.
		lockedBefore string
		want         Kind
	}{
		{"step 1 duplicate", "add stage", statusDuplicateItem, "", KindContended},
		{"step 3 duplicate", "add acct", statusDuplicateItem, "", KindContended},
		{"add auth failed on an unlocked keychain", "add stage", statusAuthFailed, "", KindAccessDenied},
		{"add auth failed on a locked keychain", "add stage", statusAuthFailed, "start", KindInteractionRequired},
		{"add interaction not allowed on an unlocked keychain", "add stage", statusInteractionNotAllowed, "", KindAccessDenied},
		{"add interaction not allowed on a locked keychain", "add stage", statusInteractionNotAllowed, "start", KindInteractionRequired},
		{"delete auth failed on an unlocked keychain", "delete acct", statusAuthFailed, "", KindAccessDenied},
		{"delete auth failed on a locked keychain", "delete acct", statusAuthFailed, "add stage", KindInteractionRequired},
		{"delete interaction not allowed on a locked keychain", "delete acct", statusInteractionNotAllowed, "add stage", KindInteractionRequired},
		{"add canceled", "add stage", statusUserCanceled, "", KindCanceled},
		{"add sandbox write denial is read-only", "add stage", statusSandboxWriteDenied, "", KindReadOnly},
		{"delete sandbox write denial is read-only", "delete acct", statusSandboxWriteDenied, "", KindReadOnly},
		{"add errSecWrPerm is read-only", "add stage", statusWritePermission, "", KindReadOnly},
		{"add errSecReadOnly is read-only", "add stage", statusReadOnly, "", KindReadOnly},
		{"add unclassified is other", "add stage", -4242, "", KindOther},
		{"delete unclassified is other", "delete acct", -4242, "", KindOther},
	} {
		t.Run("write "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			switch tt.lockedBefore {
			case "":
			case "start":
				f.setLocked(true)
			default:
				f.after = func(call string) {
					if call == tt.lockedBefore {
						f.setLocked(true)
					}
				}
			}
			failWith(tt.target, tt.status)(f)
			wantError(t, newStaged(f).Save(t.Context(), fakeKey, []byte("new")), "save", tt.want, tt.status)
		})
	}
}

// TestWriteStatusClassification pins which write statuses read as read-only.
// Only a status that says the store refused the write while reads work is
// KindReadOnly; every other unrecognised status keeps its value under KindOther,
// whichever step of Save or Delete it stops, and never matches ErrReadOnly.
// The probe is working in every row, so none of them is the unusable keychain.
func TestWriteStatusClassification(t *testing.T) {
	const (
		missingDefaultKeychain int64 = -25307 // errSecNoDefaultKeychain
		ioError                int64 = -36    // ioErr
		arbitraryPositive      int64 = 7
	)
	for _, st := range []struct {
		name     string
		status   int64
		wantKind Kind
	}{
		{"sandbox write denial", statusSandboxWriteDenied, KindReadOnly},
		{"errSecWrPerm", statusWritePermission, KindReadOnly},
		{"errSecReadOnly", statusReadOnly, KindReadOnly},
		{"missing default keychain", missingDefaultKeychain, KindOther},
		{"I/O error", ioError, KindOther},
		{"errSecParam with a working probe", statusParam, KindOther},
		{"arbitrary positive status", arbitraryPositive, KindOther},
	} {
		for _, op := range []struct {
			name  string
			fail  string
			setup func(f *fakeKeychain)
			run   func(s *stagedStore) error
			op    string
		}{
			{"save step 1 add stage", "add stage", func(*fakeKeychain) {}, func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v")) }, "save"},
			{"save step 2 delete account", "delete acct", func(f *fakeKeychain) { f.put(fakeAcctName, "old") }, func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v")) }, "save"},
			{"save step 3 add account", "add acct", func(f *fakeKeychain) { f.put(fakeAcctName, "old") }, func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v")) }, "save"},
			{"save step 4 delete stage", "delete stage", func(f *fakeKeychain) { f.put(fakeAcctName, "old") }, func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v")) }, "save"},
			{"delete account", "delete acct", func(f *fakeKeychain) { f.put(fakeAcctName, "v") }, func(s *stagedStore) error { return s.Delete(t.Context(), fakeKey) }, "delete"},
			{"delete stage", "delete stage", func(f *fakeKeychain) { f.put(fakeStageName, "v") }, func(s *stagedStore) error { return s.Delete(t.Context(), fakeKey) }, "delete"},
		} {
			t.Run(st.name+"/"+op.name, func(t *testing.T) {
				f := newFakeKeychain()
				op.setup(f)
				f.before = func(call string) error {
					if call == op.fail {
						return &statusError{status: st.status}
					}
					return nil
				}
				err := op.run(newStaged(f))
				wantError(t, err, op.op, st.wantKind, st.status)
				if got := errors.Is(err, ErrReadOnly); got != (st.wantKind == KindReadOnly) {
					t.Fatalf("errors.Is(err, ErrReadOnly) = %v for kind %v", got, st.wantKind)
				}
				if errors.Is(err, ErrUnavailable) {
					t.Fatalf("err = %v, must not be Unavailable", err)
				}
			})
		}
	}

	// Reads never become read-only, whatever the status.
	for _, st := range []int64{statusSandboxWriteDenied, statusWritePermission, statusReadOnly} {
		t.Run(fmt.Sprintf("a read failing with %d is not read-only", st), func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "v")
			f.before = func(call string) error {
				if call == "read acct" {
					return &statusError{status: st}
				}
				return nil
			}
			_, err := newStaged(f).Load(t.Context(), fakeKey)
			wantError(t, err, "load", KindOther, st)
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
		wantError(t, newStaged(f).Delete(t.Context(), fakeKey), "delete", KindOther, -1)
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

// TestAddClassificationUsesTheAddTargetProbe: an add is classified by the
// keychain it goes to, never by the one that holds an item of the same name,
// so the add probe decides and the item probe is not consulted.
func TestAddClassificationUsesTheAddTargetProbe(t *testing.T) {
	refused := &statusError{status: statusAuthFailed}
	for _, tt := range []struct {
		name string
		// failing is the probe call that errors; the other answers unlocked.
		failing string
		want    Kind
	}{
		{"add probe cannot tell", "addstatus stage", KindInteractionRequired},
		{"item probe is not consulted", "status stage", KindAccessDenied},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			f.before = func(call string) error {
				switch call {
				case "add stage":
					return refused
				case tt.failing:
					return &statusError{status: -1}
				}
				return nil
			}
			err := newStaged(f).Save(t.Context(), fakeKey, []byte("v"))
			wantError(t, err, "save", tt.want, statusAuthFailed)
		})
	}
}

// wantUnusable asserts err says the keychain cannot be used from this process:
// Unavailable with -50 and ReasonKeychainUnusable, and never a result that
// reads as absent or refused.
func wantUnusable(t *testing.T, err error, op string) {
	t.Helper()
	wantErrorReason(t, err, op, KindUnavailable, statusParam, ReasonKeychainUnusable)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
	}
	for _, other := range []error{ErrNotFound, ErrReadOnly, ErrInteractionRequired, ErrAccessDenied} {
		if errors.Is(err, other) {
			t.Fatalf("errors.Is(%v, %v) = true, want false", err, other)
		}
	}
}

// wantSkipped asserts the call after each logged fault was not primitive: the
// operation stopped at the probe instead of going on to the primitive.
func wantSkipped(t *testing.T, f *fakeKeychain, fired []int, primitive string) {
	t.Helper()
	if len(fired) == 0 {
		t.Fatal("the injected fault never fired")
	}
	calls := f.calls()
	for _, at := range fired {
		if at+1 < len(calls) && calls[at+1] == primitive {
			t.Fatalf("calls = %v: %q ran right after the failed probe at %d", calls, primitive, at)
		}
	}
}

// TestUnusableKeychainStopsBeforeThePrimitive injects -50 at the GetStatus step
// of exactly one probe call per row. Every site that takes a probe before a
// primitive must stop there with KindUnavailable and ReasonKeychainUnusable,
// never reach the primitive, and never turn the unusable store into not-found,
// read-only or a nil error.
func TestUnusableKeychainStopsBeforeThePrimitive(t *testing.T) {
	exists := func(s *stagedStore) error { _, err := s.Exists(t.Context(), fakeKey); return err }
	load := func(s *stagedStore) error { _, err := s.Load(t.Context(), fakeKey); return err }
	del := func(s *stagedStore) error { return s.Delete(t.Context(), fakeKey) }
	save := func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("new")) }

	for _, tt := range []struct {
		name   string
		acct   string // initial account value, "" for none
		stage  string // initial stage value, "" for none
		op     string
		run    func(*stagedStore) error
		faults []probeFault
		// skipped is the primitive that must not follow the failed probe.
		skipped string
		// wantAcct and wantStage are the values left behind, "" for absent.
		wantAcct, wantStage string
		// wantLoad is what Load returns once the fault is gone, "" to not check.
		wantLoad string
		// mutations, when not nil, is the exact list of add and delete calls.
		mutations []string
	}{
		{name: "Exists: first account lookup", op: "exists", run: exists, skipped: "exists acct",
			faults: []probeFault{{"status acct", 1, unusableProbe}}},
		{name: "Exists: stage lookup", op: "exists", run: exists, skipped: "exists stage",
			faults: []probeFault{{"status stage", 1, unusableProbe}}},
		{name: "Exists: second account lookup", op: "exists", run: exists, skipped: "exists acct",
			faults: []probeFault{{"status acct", 2, unusableProbe}}},

		{name: "Load: stage read", acct: "old", wantAcct: "old", op: "load", run: load, skipped: "read stage",
			faults: []probeFault{{"status stage", 1, unusableProbe}}},
		{name: "Load: account read after a good stage probe", acct: "old", wantAcct: "old", op: "load", run: load, skipped: "read acct",
			faults: []probeFault{{"status acct", 1, unusableProbe}}},
		{name: "Load: second round stage read", op: "load", run: load, skipped: "read stage",
			faults: []probeFault{{"status stage", 2, unusableProbe}}},
		{name: "Load: second round account read", op: "load", run: load, skipped: "read acct",
			faults: []probeFault{{"status acct", 2, unusableProbe}}},

		{name: "Delete: stage", acct: "old", stage: "newer", wantAcct: "", wantStage: "newer", op: "delete", run: del, skipped: "delete stage",
			faults: []probeFault{{"status stage", 1, unusableProbe}}},
		{name: "Delete: account", acct: "old", wantAcct: "old", op: "delete", run: del, skipped: "delete acct",
			faults: []probeFault{{"status acct", 1, unusableProbe}}},
		{name: "Delete: nothing stored is not a success", op: "delete", run: del, skipped: "delete acct",
			faults: []probeFault{{"status acct", 1, unusableProbe}}},

		{name: "Save: leftover stage read", acct: "old", wantAcct: "old", op: "save", run: save, skipped: "read stage",
			faults: []probeFault{{"status stage", 1, unusableProbe}}, wantLoad: "old", mutations: []string{}},
		{name: "Save step 1: add-target probe", acct: "old", wantAcct: "old", op: "save", run: save, skipped: "add stage",
			faults: []probeFault{{"addstatus stage", 1, unusableProbe}}, wantLoad: "old", mutations: []string{}},
		{name: "Save step 2: probe, cleanup removes the stage", acct: "old", wantAcct: "old", op: "save", run: save, skipped: "delete acct",
			faults: []probeFault{{"status acct", 1, unusableProbe}}, wantLoad: "old",
			mutations: []string{"add stage", "delete stage"}},
		{name: "Save step 2: probe and cleanup probe both keep the stage", acct: "old", wantAcct: "old", wantStage: "new", op: "save", run: save,
			skipped: "delete acct", wantLoad: "new", mutations: []string{"add stage"},
			faults: []probeFault{{"status acct", 1, unusableProbe}, {"status stage", 2, unusableProbe}}},
		{name: "Save step 3: add-target probe keeps the stage with the new value", acct: "old", wantAcct: "", wantStage: "new", op: "save", run: save,
			skipped: "add acct", wantLoad: "new", mutations: []string{"add stage", "delete acct"},
			faults: []probeFault{{"addstatus acct", 1, unusableProbe}}},
		{name: "Save step 4: stage probe", acct: "old", wantAcct: "new", wantStage: "new", op: "save", run: save,
			skipped: "delete stage", wantLoad: "new", mutations: []string{"add stage", "delete acct", "add acct"},
			faults: []probeFault{{"status stage", 2, unusableProbe}}},

		{name: "roll-forward: delete-account probe", acct: "old", stage: "newest", wantAcct: "old", wantStage: "newest", op: "save", run: save,
			skipped: "delete acct", wantLoad: "newest", mutations: []string{},
			faults: []probeFault{{"status acct", 1, unusableProbe}}},
		{name: "roll-forward: add-account probe", acct: "old", stage: "newest", wantAcct: "", wantStage: "newest", op: "save", run: save,
			skipped: "add acct", wantLoad: "newest", mutations: []string{"delete acct"},
			faults: []probeFault{{"addstatus acct", 1, unusableProbe}}},
		{name: "roll-forward: stage delete probe", acct: "old", stage: "newest", wantAcct: "newest", wantStage: "newest", op: "save", run: save,
			skipped: "delete stage", wantLoad: "newest", mutations: []string{"delete acct", "add acct"},
			faults: []probeFault{{"status stage", 2, unusableProbe}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			if tt.acct != "" {
				f.put(fakeAcctName, tt.acct)
			}
			if tt.stage != "" {
				f.put(fakeStageName, tt.stage)
			}
			fired := f.injectFaults(tt.faults...)
			s := newStaged(f)
			err := tt.run(s)
			if err == nil {
				t.Fatal("the operation succeeded on a keychain that cannot be used")
			}
			wantUnusable(t, err, tt.op)
			wantSkipped(t, f, *fired, tt.skipped)
			if tt.mutations != nil {
				if got := f.mutations(); !slices.Equal(got, tt.mutations) {
					t.Fatalf("mutations = %v, want %v", got, tt.mutations)
				}
			}
			f.before = nil
			for _, item := range []struct {
				name itemName
				want string
				what string
			}{{fakeAcctName, tt.wantAcct, "account"}, {fakeStageName, tt.wantStage, "stage"}} {
				if tt.op == "exists" || tt.op == "load" && tt.acct == "" {
					break
				}
				if got, ok := f.value(item.name); got != item.want || ok != (item.want != "") {
					t.Fatalf("%s = %q (present %v), want %q", item.what, got, ok, item.want)
				}
			}
			if tt.wantLoad != "" {
				mustLoad(t, s, tt.wantLoad)
			}
			if tt.op == "save" {
				if err := s.Save(t.Context(), fakeKey, []byte("again")); err != nil {
					t.Fatalf("retry once the keychain is usable: %v", err)
				}
				mustLoad(t, s, "again")
				wantNoStage(t, f)
			}
		})
	}
}

// TestOtherMinus50DoesNotMeanUnusable: only -50 at the GetStatus step is the
// unusable signal. -50 from the lookup, copy-keychain or copy-default step, from
// a step that is not known, from a primitive, or from the probe taken after a
// failed primitive keeps today's meaning.
func TestOtherMinus50DoesNotMeanUnusable(t *testing.T) {
	for _, step := range []struct {
		name string
		step probeStep
	}{
		{"lookup", probeStepLookup},
		{"copy-keychain", probeStepCopyKeychain},
		{"copy-default", probeStepCopyDefault},
		{"unknown", probeStepUnknown},
	} {
		probeErr := &statusError{status: statusParam, step: step.step}
		for _, tt := range []struct {
			name string
			// run returns the error and the op; the store holds a foreign stage
			// that refuses with auth-failed, so a probe that cannot confirm
			// the lock reads InteractionRequired and a confirmed one AccessDenied.
			run    func(*stagedStore) error
			op     string
			faults []probeFault
		}{
			{"Load stage probe", func(s *stagedStore) error { _, err := s.Load(t.Context(), fakeKey); return err }, "load",
				[]probeFault{{"status stage", 1, probeErr}}},
			{"Save leftover stage probe", func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v3")) }, "save",
				[]probeFault{{"status stage", 1, probeErr}}},
		} {
			t.Run(step.name+": "+tt.name, func(t *testing.T) {
				f := newFakeKeychain()
				f.put(fakeAcctName, "old")
				f.putForeign(fakeStageName, statusAuthFailed)
				f.injectFaults(tt.faults...)
				err := tt.run(newStaged(f))
				wantError(t, err, tt.op, KindInteractionRequired, statusAuthFailed)
				if errors.Is(err, ErrUnavailable) {
					t.Fatalf("err = %v, must not be Unavailable", err)
				}
			})
		}
		t.Run(step.name+": add-target probe", func(t *testing.T) {
			f := newFakeKeychain()
			refused := &statusError{status: statusAuthFailed}
			f.before = func(call string) error {
				switch call {
				case "add stage":
					return refused
				case "addstatus stage":
					return probeErr
				}
				return nil
			}
			err := newStaged(f).Save(t.Context(), fakeKey, []byte("v"))
			wantError(t, err, "save", KindInteractionRequired, statusAuthFailed)
		})
	}

	t.Run("a primitive's own -50 with a working probe", func(t *testing.T) {
		for _, tt := range []struct {
			name    string
			fail    string
			setup   func(f *fakeKeychain)
			run     func(*stagedStore) error
			op      string
			want    Kind
			wantErr bool
		}{
			{"exists", "exists acct", func(*fakeKeychain) {}, func(s *stagedStore) error { _, err := s.Exists(t.Context(), fakeKey); return err }, "exists", KindOther, true},
			{"read", "read acct", func(f *fakeKeychain) { f.put(fakeAcctName, "v") }, func(s *stagedStore) error { _, err := s.Load(t.Context(), fakeKey); return err }, "load", KindOther, true},
			{"add", "add stage", func(*fakeKeychain) {}, func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v")) }, "save", KindOther, true},
			{"delete", "delete acct", func(f *fakeKeychain) { f.put(fakeAcctName, "v") }, func(s *stagedStore) error { return s.Delete(t.Context(), fakeKey) }, "delete", KindOther, true},
		} {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeKeychain()
				tt.setup(f)
				f.before = func(call string) error {
					if call == tt.fail {
						return &statusError{status: statusParam}
					}
					return nil
				}
				err := tt.run(newStaged(f))
				wantError(t, err, tt.op, tt.want, statusParam)
				if errors.Is(err, ErrUnavailable) {
					t.Fatalf("err = %v, must not be Unavailable", err)
				}
			})
		}
	})

	t.Run("a -50 only from the probe after a failed primitive", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			run  func(*stagedStore) error
			op   string
		}{
			{"Load", func(s *stagedStore) error { _, err := s.Load(t.Context(), fakeKey); return err }, "load"},
			{"Save", func(s *stagedStore) error { return s.Save(t.Context(), fakeKey, []byte("v3")) }, "save"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				f := newFakeKeychain()
				f.put(fakeAcctName, "old")
				f.putForeign(fakeStageName, statusAuthFailed)
				f.injectFaults(probeFault{"status stage", 2, unusableProbe})
				err := tt.run(newStaged(f))
				wantError(t, err, tt.op, KindInteractionRequired, statusAuthFailed)
				if v, ok := f.value(fakeStageName); !ok || v != "foreign-secret" {
					t.Fatalf("stage = %q (present %v), want it kept", v, ok)
				}
			})
		}
	})
}

// TestLookupFailureFallsBackToTheAddTarget: the item probe searches before it
// reads the lock state, and a search that fails before GetStatus says nothing
// about whether the keychain is usable. The add-target probe then decides.
func TestLookupFailureFallsBackToTheAddTarget(t *testing.T) {
	for _, step := range []struct {
		name string
		step probeStep
	}{
		{"lookup", probeStepLookup},
		{"copy-keychain", probeStepCopyKeychain},
	} {
		probeErr := &statusError{status: -1, step: step.step}
		t.Run(step.name+" failure and an unusable add target", func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.putForeign(fakeStageName, statusAuthFailed)
			fired := f.injectFaults(
				probeFault{"status stage", 1, probeErr},
				probeFault{"addstatus stage", 1, unusableProbe})
			_, err := newStaged(f).Load(t.Context(), fakeKey)
			wantUnusable(t, err, "load")
			wantSkipped(t, f, *fired, "read stage")
		})
		t.Run(step.name+" failure and a good add target keeps today's result", func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.putForeign(fakeStageName, statusAuthFailed)
			f.injectFaults(probeFault{"status stage", 1, probeErr})
			_, err := newStaged(f).Load(t.Context(), fakeKey)
			wantError(t, err, "load", KindInteractionRequired, statusAuthFailed)
			var asked int
			for _, call := range f.calls() {
				if call == "addstatus stage" {
					asked++
				}
			}
			if asked != 1 {
				t.Fatalf("add-target probe taken %d times, want once as the fallback", asked)
			}
		})
		t.Run(step.name+" failure and an add target that fails at another step", func(t *testing.T) {
			f := newFakeKeychain()
			f.put(fakeAcctName, "old")
			f.putForeign(fakeStageName, statusAuthFailed)
			f.injectFaults(
				probeFault{"status stage", 1, probeErr},
				probeFault{"addstatus stage", 1, &statusError{status: statusParam, step: probeStepCopyDefault}})
			_, err := newStaged(f).Load(t.Context(), fakeKey)
			wantError(t, err, "load", KindInteractionRequired, statusAuthFailed)
		})
	}

	t.Run("a probe that fails at GetStatus with another status takes no fallback", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.injectFaults(probeFault{"status stage", 1, &statusError{status: -1, step: probeStepGetStatus}})
		mustLoad(t, newStaged(f), "old")
		if slices.Contains(f.calls(), "addstatus stage") {
			t.Fatalf("calls = %v, the add-target probe must not run", f.calls())
		}
	})

	t.Run("the add-target probe itself takes no fallback", func(t *testing.T) {
		f := newFakeKeychain()
		f.before = func(call string) error {
			if call == "addstatus stage" {
				return &statusError{status: -1, step: probeStepLookup}
			}
			return nil
		}
		if err := newStaged(f).Save(t.Context(), fakeKey, []byte("v")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		n := 0
		for _, call := range f.calls() {
			if call == "addstatus stage" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("add-target probe taken %d times, want once", n)
		}
	})
}
