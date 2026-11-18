//go:build darwin && cgo

package secretstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// None of these tests reaches the keychain: the status and dictionary tests
// compare constants and dry-run descriptions, and the store tests run over the
// in-memory fakeKeychain.

func TestStatusLiteralsMatchSecurityFramework(t *testing.T) {
	for _, tt := range []struct {
		name    string
		literal int64
		c       int64
	}{
		{"errSecItemNotFound", statusItemNotFound, cStatusItemNotFound},
		{"errSecAuthFailed", statusAuthFailed, cStatusAuthFailed},
		{"errSecInteractionNotAllowed", statusInteractionNotAllowed, cStatusInteractionNotAllowed},
		{"errSecDuplicateItem", statusDuplicateItem, cStatusDuplicateItem},
		{"errSecUserCanceled", statusUserCanceled, cStatusUserCanceled},
		{"errSecParam", statusParam, cStatusParam},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.literal != tt.c {
				t.Fatalf("staged.go says %d, Security.framework says %d", tt.literal, tt.c)
			}
		})
	}
	// The literals are the ones the classification table documents.
	want := map[string]int64{
		"not found": -25300, "auth failed": -25293, "interaction not allowed": -25308,
		"duplicate": -25299, "user canceled": -128, "param": -50,
	}
	got := map[string]int64{
		"not found": cStatusItemNotFound, "auth failed": cStatusAuthFailed,
		"interaction not allowed": cStatusInteractionNotAllowed, "duplicate": cStatusDuplicateItem,
		"user canceled": cStatusUserCanceled, "param": cStatusParam,
	}
	for name, status := range want {
		if got[name] != status {
			t.Errorf("%s = %d, want %d", name, got[name], status)
		}
	}
}

// TestProbeStepsMatchTheCStages pins the stage numbers the C probe reports to
// the steps the classification reads, and checks a dry-run probe reports the
// step it stopped at.
func TestProbeStepsMatchTheCStages(t *testing.T) {
	// Literal arguments: a test file cannot import "C", so no C.int variable.
	for _, tt := range []struct {
		stage int
		got   probeStep
		want  probeStep
	}{
		{0, probeStepOf(0), probeStepUnknown},
		{1, probeStepOf(1), probeStepLookup},
		{2, probeStepOf(2), probeStepCopyKeychain},
		{3, probeStepOf(3), probeStepCopyDefault},
		{4, probeStepOf(4), probeStepGetStatus},
		{99, probeStepOf(99), probeStepUnknown},
	} {
		if tt.got != tt.want {
			t.Errorf("probeStepOf(%d) = %d, want %d", tt.stage, tt.got, tt.want)
		}
	}

	var traces []queryTrace
	items := &keychainItems{dry: &traces}
	_, err := items.keychainUnlocked(t.Context(), itemName{service: "svc.test", account: "acct"})
	var se *statusError
	if !errors.As(err, &se) || se.step != probeStepLookup {
		t.Fatalf("dry-run probe error = %v, want a statusError at the lookup step", err)
	}
}

func TestOpenKeychainModes(t *testing.T) {
	for _, tt := range []struct {
		name        string
		interaction Interaction
		setterErr   error
		wantCalls   []bool
		wantErr     *Error
	}{
		{"never turns prompts off once", InteractionNever, nil, []bool{false}, nil},
		{"allowed leaves the setting alone", InteractionAllowed, nil, nil, nil},
		{"never fails closed when prompts cannot be turned off", InteractionNever, &statusError{status: -50}, []bool{false},
			&Error{Op: "open", Backend: "keychain", Kind: KindOther, Status: -50}},
		{"never fails closed on an error without a status", InteractionNever, errors.New("boom"), []bool{false},
			&Error{Op: "open", Backend: "keychain", Kind: KindOther}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []bool
			store, err := openKeychain(Options{MaxSecretBytes: 10, Interaction: tt.interaction}, func(allowed bool) error {
				calls = append(calls, allowed)
				return tt.setterErr
			})
			if !slices.Equal(calls, tt.wantCalls) {
				t.Fatalf("setter calls = %v, want %v", calls, tt.wantCalls)
			}
			if tt.wantErr != nil {
				var got *Error
				if !errors.As(err, &got) || *got != *tt.wantErr || store != nil {
					t.Fatalf("openKeychain = %v, %v, want %+v and no store", store, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("openKeychain: %v", err)
			}
			ks, ok := store.(*keychainStore)
			if !ok {
				t.Fatalf("store is %T, want *keychainStore", store)
			}
			if _, ok := store.(ACLRepairer); !ok {
				t.Fatal("the keychain store must implement ACLRepairer")
			}
			items, ok := ks.api.(*keychainItems)
			if !ok {
				t.Fatalf("store backend is %T, want *keychainItems", ks.api)
			}
			if items.target != 0 {
				t.Fatal("the production store must use the default keychain (a zero target)")
			}
			if wantUIFail := tt.interaction == InteractionNever; items.uiFail != wantUIFail {
				t.Fatalf("uiFail = %v, want %v", items.uiFail, wantUIFail)
			}
			if ks.backend != "keychain" || ks.max != 10 {
				t.Fatalf("backend %q max %d, want keychain 10", ks.backend, ks.max)
			}
			if ks.afterStep != nil {
				t.Fatal("afterStep must be nil in production")
			}
		})
	}
}

// TestEveryPrimitiveNamesTheTargetKeychain runs each primitive in dry-run mode
// against a placeholder target and checks the dictionary it built, so a
// primitive that forgot the target cannot reach the user's login keychain
// from a test that meant a scratch one.
func TestEveryPrimitiveNamesTheTargetKeychain(t *testing.T) {
	ref, release := newPlaceholderKeychainRef()
	defer release()
	name := itemName{service: "svc.test", account: "acct"}

	run := func(items *keychainItems) []queryTrace {
		ctx := t.Context()
		_, _ = items.exists(ctx, name)
		_, _ = items.read(ctx, name, 16)
		_ = items.add(ctx, name, []byte("v"))
		_ = items.delete(ctx, name)
		_, _ = items.keychainUnlocked(ctx, name)
		return *items.dry
	}

	for _, tt := range []struct {
		name   string
		target keychainRef
		uiFail bool
	}{
		{"scratch keychain, prompts off", ref, true},
		{"scratch keychain, prompts allowed", ref, false},
		{"default keychain, prompts off", 0, true},
		{"default keychain, prompts allowed", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var traces []queryTrace
			got := run(&keychainItems{target: tt.target, uiFail: tt.uiFail, dry: &traces})
			wantOps := []string{"exists", "read", "add", "delete", "status"}
			if len(got) != len(wantOps) {
				t.Fatalf("traced %d primitives, want %d: %+v", len(got), len(wantOps), got)
			}
			for i, tr := range got {
				if tr.op != wantOps[i] {
					t.Fatalf("trace %d is %q, want %q", i, tr.op, wantOps[i])
				}
				isAdd := tr.op == "add"
				if want := tt.target != 0 && isAdd; tr.useKeychain != want {
					t.Errorf("%s: kSecUseKeychain = %v, want %v", tr.op, tr.useKeychain, want)
				}
				if want := tt.target != 0 && !isAdd; tr.searchList != want {
					t.Errorf("%s: kSecMatchSearchList = %v, want %v", tr.op, tr.searchList, want)
				}
				// The lock probe always fails fast, so it never raises its own
				// dialog; an add never carries the key.
				wantUI := (tt.uiFail || tr.op == "status") && !isAdd
				if tr.uiFail != wantUI {
					t.Errorf("%s: UI fail = %v, want %v (never on add, always on the probe)", tr.op, tr.uiFail, wantUI)
				}
				if !tr.named {
					t.Errorf("%s: dictionary lacks the service or account", tr.op)
				}
				if tr.valueData != isAdd {
					t.Errorf("%s: value data = %v, want %v", tr.op, tr.valueData, isAdd)
				}
				if tr.returnData != (tr.op == "read") {
					t.Errorf("%s: return data = %v", tr.op, tr.returnData)
				}
				if wantRef := !isAdd && tr.op != "read"; tr.returnRef != wantRef {
					t.Errorf("%s: return ref = %v, want %v", tr.op, tr.returnRef, wantRef)
				}
			}
		})
	}
}

// recordingAPI wraps an itemAPI and keeps the buffers handed to add.
type recordingAPI struct {
	itemAPI
	added [][]byte
}

func (r *recordingAPI) add(ctx context.Context, name itemName, value []byte) error {
	r.added = append(r.added, value)
	return r.itemAPI.add(ctx, name, value)
}

func newTestKeychainStore(f *fakeKeychain, interaction Interaction) *keychainStore {
	return newKeychainStoreOver(f, Options{MaxSecretBytes: stagedMax, Interaction: interaction})
}

func TestRepairAccess(t *testing.T) {
	t.Run("refuses under InteractionNever without touching the store", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "v")
		err := newTestKeychainStore(f, InteractionNever).RepairAccess(t.Context(), fakeKey)
		wantError(t, err, "repair", KindInteractionRequired, 0)
		if !errors.Is(err, ErrInteractionRequired) {
			t.Fatalf("err = %v, want ErrInteractionRequired", err)
		}
		if calls := f.calls(); len(calls) != 0 {
			t.Fatalf("store calls = %v, want none", calls)
		}
	})

	t.Run("checks the context and key first", func(t *testing.T) {
		f := newFakeKeychain()
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		s := newTestKeychainStore(f, InteractionAllowed)
		if err := s.RepairAccess(canceled, fakeKey); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled: err = %v, want context.Canceled", err)
		}
		if err := s.RepairAccess(t.Context(), Key{Service: "bad/svc", Account: "a"}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("invalid key: err = %v, want ErrInvalidArgument", err)
		}
		if calls := f.calls(); len(calls) != 0 {
			t.Fatalf("store calls = %v, want none", calls)
		}
	})

	t.Run("rewrites an item this binary can read", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "secret")
		s := newTestKeychainStore(f, InteractionAllowed)
		if err := s.RepairAccess(t.Context(), fakeKey); err != nil {
			t.Fatalf("RepairAccess: %v", err)
		}
		want := []string{"add stage", "delete acct", "add acct", "delete stage"}
		if got := f.mutations(); !slices.Equal(got, want) {
			t.Fatalf("mutations = %v, want a fresh staged save %v", got, want)
		}
		mustLoad(t, s, "secret")
		wantNoStage(t, f)
	})

	t.Run("keeps the newest value when a stage is left over", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.put(fakeStageName, "newest")
		s := newTestKeychainStore(f, InteractionAllowed)
		if err := s.RepairAccess(t.Context(), fakeKey); err != nil {
			t.Fatalf("RepairAccess: %v", err)
		}
		mustLoad(t, s, "newest")
		wantNoStage(t, f)
	})

	t.Run("refuses when an unreadable stage may hold a newer value", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.putForeign(fakeStageName, statusAuthFailed)
		before := f.snapshot()
		err := newTestKeychainStore(f, InteractionAllowed).RepairAccess(t.Context(), fakeKey)
		wantError(t, err, "repair", KindAccessDenied, 0)
		if got := f.mutations(); len(got) != 0 {
			t.Fatalf("mutations = %v, want none", got)
		}
		if got := f.snapshot(); fmt.Sprint(got) != fmt.Sprint(before) {
			t.Fatalf("store = %v, want %v", got, before)
		}
	})

	t.Run("zeroes the buffers it handled", func(t *testing.T) {
		f := newFakeKeychain()
		f.put(fakeAcctName, "secret")
		rec := &recordingAPI{itemAPI: f}
		s := newKeychainStoreOver(rec, Options{MaxSecretBytes: stagedMax, Interaction: InteractionAllowed})
		if err := s.RepairAccess(t.Context(), fakeKey); err != nil {
			t.Fatalf("RepairAccess: %v", err)
		}
		if len(rec.added) == 0 {
			t.Fatal("no value was saved")
		}
		for i, buf := range rec.added {
			for _, b := range buf {
				if b != 0 {
					t.Fatalf("buffer %d still holds %q after RepairAccess", i, buf)
				}
			}
		}
	})

	for _, tt := range []struct {
		name  string
		setup func(f *fakeKeychain)
		want  Kind
		code  int64
	}{
		{"missing item", func(f *fakeKeychain) {}, KindNotFound, statusItemNotFound},
		{"item of another identity", func(f *fakeKeychain) { f.putForeign(fakeAcctName, statusAuthFailed) }, KindAccessDenied, statusAuthFailed},
		{"locked keychain", func(f *fakeKeychain) {
			f.put(fakeAcctName, "v")
			f.setLocked(true)
		}, KindInteractionRequired, statusInteractionNotAllowed},
	} {
		t.Run("fails under repair and changes nothing: "+tt.name, func(t *testing.T) {
			f := newFakeKeychain()
			tt.setup(f)
			before := f.snapshot()
			err := newTestKeychainStore(f, InteractionAllowed).RepairAccess(t.Context(), fakeKey)
			wantError(t, err, "repair", tt.want, tt.code)
			if got := f.mutations(); len(got) != 0 {
				t.Fatalf("mutations = %v, want none", got)
			}
			f.setLocked(false)
			if got := f.snapshot(); fmt.Sprint(got) != fmt.Sprint(before) {
				t.Fatalf("store = %v, want %v", got, before)
			}
		})
	}
}

// TestRepairAccessStageLookup: a stage lookup refused with -25293 reads as
// AccessDenied only when the keychain was unlocked at both probes; a locked
// keychain needs the user, and the stage stays either way. Any other failure
// of the stage lookup or read propagates, relabelled "repair".
func TestRepairAccessStageLookup(t *testing.T) {
	const other = 100001
	// stageReadable seeds an account and a readable stage; Load takes the
	// stage, so the first "read stage" is Load's and a second one is the
	// repair's own readStage.
	setup := func() *fakeKeychain {
		f := newFakeKeychain()
		f.put(fakeAcctName, "old")
		f.put(fakeStageName, "newest")
		return f
	}
	refuseLookup := func(f *fakeKeychain, status int64) {
		f.before = func(call string) error {
			if call == "exists stage" {
				return &statusError{status: status}
			}
			return nil
		}
	}
	keep := func(t *testing.T, f *fakeKeychain) {
		t.Helper()
		f.setLocked(false)
		if got := f.snapshot(); fmt.Sprint(got) != fmt.Sprint(map[itemName]string{fakeAcctName: "old", fakeStageName: "newest"}) {
			t.Fatalf("store = %v, want account and stage untouched", got)
		}
		if got := f.mutations(); len(got) != 0 {
			t.Fatalf("mutations = %v, want none", got)
		}
	}

	t.Run("lookup refused while locked needs the user", func(t *testing.T) {
		f := setup()
		refuseLookup(f, statusAuthFailed)
		f.after = func(call string) {
			if call == "read stage" {
				f.setLocked(true)
			}
		}
		err := newTestKeychainStore(f, InteractionAllowed).RepairAccess(t.Context(), fakeKey)
		wantError(t, err, "repair", KindInteractionRequired, statusAuthFailed)
		keep(t, f)
	})

	t.Run("lookup refused while unlocked is access denied", func(t *testing.T) {
		f := setup()
		refuseLookup(f, statusAuthFailed)
		err := newTestKeychainStore(f, InteractionAllowed).RepairAccess(t.Context(), fakeKey)
		wantError(t, err, "repair", KindAccessDenied, statusAuthFailed)
		keep(t, f)
	})

	t.Run("lookup failure of another kind propagates", func(t *testing.T) {
		f := setup()
		refuseLookup(f, other)
		err := newTestKeychainStore(f, InteractionAllowed).RepairAccess(t.Context(), fakeKey)
		wantError(t, err, "repair", KindOther, other)
		keep(t, f)
	})

	t.Run("stage read failure of another kind propagates", func(t *testing.T) {
		f := setup()
		reads := 0
		f.before = func(call string) error {
			if call != "read stage" {
				return nil
			}
			if reads++; reads == 2 {
				return &statusError{status: other}
			}
			return nil
		}
		err := newTestKeychainStore(f, InteractionAllowed).RepairAccess(t.Context(), fakeKey)
		wantError(t, err, "repair", KindOther, other)
		keep(t, f)
	})

	t.Run("a readable stage proceeds", func(t *testing.T) {
		f := setup()
		s := newTestKeychainStore(f, InteractionAllowed)
		if err := s.RepairAccess(t.Context(), fakeKey); err != nil {
			t.Fatalf("RepairAccess: %v", err)
		}
		mustLoad(t, s, "newest")
		wantNoStage(t, f)
	})
}

func TestKeychainStoreRunsTheStagedSave(t *testing.T) {
	f := newFakeKeychain()
	s := newTestKeychainStore(f, InteractionNever)
	var steps []int
	s.afterStep = func(n int) { steps = append(steps, n) }
	if err := s.Save(t.Context(), fakeKey, []byte("v")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !slices.Equal(steps, []int{1, 2, 3, 4}) {
		t.Fatalf("afterStep calls = %v, want 1 2 3 4", steps)
	}
	mustLoad(t, s, "v")
}
