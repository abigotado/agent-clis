package secretstore

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeKeychain is an itemAPI over a map, with a hook before and after every
// primitive so a test can inject a fault, a crash or a concurrent writer at
// any call. Calls are recorded as "<op> <acct|stage>"; the hooks see the same
// label. The hooks run without the lock held, so they may touch the fake.
type fakeKeychain struct {
	mu     sync.Mutex
	items  map[itemName]*fakeItem
	locked bool
	// lockStatus is what a locked keychain returns to a read, add or delete.
	// Zero means statusInteractionNotAllowed; a locked file keychain with the
	// UI disabled really returns statusAuthFailed.
	lockStatus int64
	log        []string
	// before may return an error, which the primitive then returns without
	// touching the store.
	before func(call string) error
	// after runs once a primitive has taken effect and may panic to model a
	// crash at exactly that point.
	after func(call string)
}

type fakeItem struct {
	value []byte
	// denyStatus, when not zero, is what reading the item returns: an item
	// written by another code identity.
	denyStatus int64
}

const (
	fakeService = "svc.test"
	fakeAccount = "profile"
)

var (
	fakeKey       = Key{Service: fakeService, Account: fakeAccount}
	fakeAcctName  = itemName{service: fakeService, account: fakeAccount}
	fakeStageName = fakeAcctName.stage()
)

func newFakeKeychain() *fakeKeychain {
	return &fakeKeychain{items: make(map[itemName]*fakeItem)}
}

func (f *fakeKeychain) put(name itemName, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[name] = &fakeItem{value: []byte(value)}
}

func (f *fakeKeychain) putForeign(name itemName, status int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[name] = &fakeItem{value: []byte("foreign-secret"), denyStatus: status}
}

func (f *fakeKeychain) remove(name itemName) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, name)
}

func (f *fakeKeychain) setLocked(locked bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked = locked
}

// setLockedWith locks the keychain and makes it fail with status.
func (f *fakeKeychain) setLockedWith(status int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked = true
	f.lockStatus = status
}

// lockedStatus is the status a locked keychain returns. The caller holds mu.
func (f *fakeKeychain) lockedStatus() int64 {
	if f.lockStatus == 0 {
		return statusInteractionNotAllowed
	}
	return f.lockStatus
}

// value returns the stored value, and false if the item is absent.
func (f *fakeKeychain) value(name itemName) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	item, ok := f.items[name]
	if !ok {
		return "", false
	}
	return string(item.value), true
}

func (f *fakeKeychain) snapshot() map[itemName]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[itemName]string, len(f.items))
	for name, item := range f.items {
		out[name] = string(item.value)
	}
	return out
}

func (f *fakeKeychain) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

// mutations returns the recorded add and delete calls, in order.
func (f *fakeKeychain) mutations() []string {
	var out []string
	for _, call := range f.calls() {
		if isMutation(call) {
			out = append(out, call)
		}
	}
	return out
}

func isMutation(call string) bool {
	return strings.HasPrefix(call, "add ") || strings.HasPrefix(call, "delete ")
}

func label(op string, name itemName) string {
	if strings.HasSuffix(name.account, stageSuffix) {
		return op + " stage"
	}
	return op + " acct"
}

func (f *fakeKeychain) enter(ctx context.Context, op string, name itemName) error {
	call := label(op, name)
	f.mu.Lock()
	f.log = append(f.log, call)
	before := f.before
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if before != nil {
		return before(call)
	}
	return nil
}

func (f *fakeKeychain) leave(op string, name itemName) {
	f.mu.Lock()
	after := f.after
	f.mu.Unlock()
	if after != nil {
		after(label(op, name))
	}
}

func (f *fakeKeychain) exists(ctx context.Context, name itemName) (bool, error) {
	if err := f.enter(ctx, "exists", name); err != nil {
		return false, err
	}
	f.mu.Lock()
	_, ok := f.items[name]
	f.mu.Unlock()
	f.leave("exists", name)
	return ok, nil
}

func (f *fakeKeychain) read(ctx context.Context, name itemName, limit int) ([]byte, error) {
	if err := f.enter(ctx, "read", name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	item, ok := f.items[name]
	locked, lockStatus := f.locked, f.lockedStatus()
	f.mu.Unlock()
	f.leave("read", name)
	switch {
	case !ok:
		return nil, &statusError{status: statusItemNotFound}
	case locked:
		return nil, &statusError{status: lockStatus}
	case item.denyStatus != 0:
		return nil, &statusError{status: item.denyStatus}
	case len(item.value) > limit:
		return nil, errValueTooLarge
	}
	return bytes.Clone(item.value), nil
}

func (f *fakeKeychain) add(ctx context.Context, name itemName, value []byte) error {
	if err := f.enter(ctx, "add", name); err != nil {
		return err
	}
	f.mu.Lock()
	var err error
	switch _, exists := f.items[name]; {
	case f.locked:
		err = &statusError{status: f.lockedStatus()}
	case exists:
		err = &statusError{status: statusDuplicateItem}
	default:
		f.items[name] = &fakeItem{value: bytes.Clone(value)}
	}
	f.mu.Unlock()
	if err != nil {
		return err
	}
	f.leave("add", name)
	return nil
}

func (f *fakeKeychain) delete(ctx context.Context, name itemName) error {
	if err := f.enter(ctx, "delete", name); err != nil {
		return err
	}
	f.mu.Lock()
	var err error
	switch _, exists := f.items[name]; {
	case f.locked:
		err = &statusError{status: f.lockedStatus()}
	case !exists:
		err = &statusError{status: statusItemNotFound}
	default:
		delete(f.items, name)
	}
	f.mu.Unlock()
	if err != nil && !isNotFound(err) {
		return err
	}
	// A delete of a missing item has run to completion too, so a crash
	// after "step 2" is reachable when there was no account item.
	f.leave("delete", name)
	return err
}

func isNotFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.status == statusItemNotFound
}

// keychainUnlocked reports the lock state of the one keychain the fake models,
// for an item that exists and for one that does not (an add's target).
func (f *fakeKeychain) keychainUnlocked(ctx context.Context, name itemName) (bool, error) {
	if err := f.enter(ctx, "status", name); err != nil {
		return false, err
	}
	f.mu.Lock()
	unlocked := !f.locked
	f.mu.Unlock()
	f.leave("status", name)
	return unlocked, nil
}

// addKeychainUnlocked reports the lock state of the add target; the fake has
// one keychain, so it is the same state under its own call label.
func (f *fakeKeychain) addKeychainUnlocked(ctx context.Context, name itemName) (bool, error) {
	if err := f.enter(ctx, "addstatus", name); err != nil {
		return false, err
	}
	f.mu.Lock()
	unlocked := !f.locked
	f.mu.Unlock()
	f.leave("addstatus", name)
	return unlocked, nil
}

// crashed is the panic value that models the process dying.
type crashed struct{}

// crashAfterMutations makes the process "die" right after the n-th successful
// add or delete.
func (f *fakeKeychain) crashAfterMutations(n int) {
	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()
	f.after = func(call string) {
		if !isMutation(call) {
			return
		}
		count++
		if count == n {
			panic(crashed{})
		}
	}
}

// runUntilCrash runs fn, which must die with crashed, and clears the hooks so
// the "restarted" process behaves normally.
func runUntilCrash(t *testing.T, f *fakeKeychain, fn func()) {
	t.Helper()
	defer func() {
		f.mu.Lock()
		f.before, f.after = nil, nil
		f.mu.Unlock()
		switch r := recover().(type) {
		case nil:
			t.Fatal("expected the simulated crash, but the operation returned")
		case crashed:
		default:
			panic(r)
		}
	}()
	fn()
}

// probeFault makes the nth call (1-based) of one label, such as "status acct"
// or "addstatus stage", return err instead of reaching the fake's own logic.
type probeFault struct {
	call string
	nth  int
	err  error
}

// unusableProbe is the error the lock probe returns when GetStatus is refused
// as a malformed call, which is how a sandbox that denies the keychain shows.
var unusableProbe = &statusError{status: statusParam, step: probeStepGetStatus}

// injectFaults installs before-hooks for the faults and returns the log
// positions where they fired, which the caller reads after the run.
func (f *fakeKeychain) injectFaults(faults ...probeFault) *[]int {
	counts := make(map[string]int)
	fired := new([]int)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.before = func(call string) error {
		counts[call]++
		for _, fault := range faults {
			if fault.call == call && fault.nth == counts[call] {
				f.mu.Lock()
				*fired = append(*fired, len(f.log)-1)
				f.mu.Unlock()
				return fault.err
			}
		}
		return nil
	}
	return fired
}
