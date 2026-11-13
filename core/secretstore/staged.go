package secretstore

import (
	"context"
	"errors"
	"strconv"

	"github.com/abigotado/agent-clis/core/secretstore/internal/rules"
)

// This file holds the crash-safe Save sequence of the keychain backend. It is
// untagged and talks to the keychain only through itemAPI, so every crash
// window and every status classification is testable on any platform.
//
// An item is never updated in place. Save writes the new value to a stage item
// first, replaces the account item, then removes the stage:
//
//  1. add <account>␟stage with the new value
//  2. delete <account>
//  3. add <account>; a duplicate means someone recreated it, which is
//     ErrContended and keeps the stage
//  4. delete <account>␟stage
//
// A stage left behind therefore means an interrupted Save and holds the newest
// value. Load reads it first and Save rolls it forward before its own sequence.

// The OSStatus values the classification below depends on. The darwin backend
// has a test that pins each of them to the Security.framework constant, so the
// literals here cannot drift from what the system returns.
const (
	statusItemNotFound          int64 = -25300 // errSecItemNotFound
	statusAuthFailed            int64 = -25293 // errSecAuthFailed
	statusInteractionNotAllowed int64 = -25308 // errSecInteractionNotAllowed
	statusDuplicateItem         int64 = -25299 // errSecDuplicateItem
	statusUserCanceled          int64 = -128   // errSecUserCanceled
)

// stageSuffix is appended to an account name to name its stage. U+241F is
// rejected by key validation, so a stage name never collides with an account.
const stageSuffix = string(rules.ReservedRune) + "stage"

// loadRounds bounds Load: stage, account, stage, account. The second round
// covers a writer that finished between the reads of the first one.
const loadRounds = 2

// itemName names one item in the backing store.
type itemName struct {
	service string
	account string
}

func (n itemName) stage() itemName {
	return itemName{service: n.service, account: n.account + stageSuffix}
}

// statusError is the error an itemAPI returns for a failed operating-system
// call. It never reaches a caller: the store classifies it into an *Error.
type statusError struct {
	status int64
}

func (e *statusError) Error() string {
	return "secretstore: os status " + strconv.FormatInt(e.status, 10)
}

// errValueTooLarge is what itemAPI.read returns for a stored value above the
// bound, before the value is copied.
var errValueTooLarge = errors.New("secretstore: stored value exceeds the bound")

// itemAPI is the set of primitives the staged sequence needs. Implementations
// never prompt: a call that would need the user fails with a statusError.
type itemAPI interface {
	// exists reports whether the item exists, by reference and without
	// decrypting it. A missing item is (false, nil).
	exists(ctx context.Context, name itemName) (bool, error)
	// read returns a copy of the value, decrypting it. A missing item is a
	// statusError with statusItemNotFound; a value longer than max is
	// errValueTooLarge.
	read(ctx context.Context, name itemName, max int) ([]byte, error)
	// add creates the item with the store's access control. An existing item
	// is a statusError with statusDuplicateItem; add never updates.
	add(ctx context.Context, name itemName, value []byte) error
	// delete removes the item. A missing item is a statusError with
	// statusItemNotFound.
	delete(ctx context.Context, name itemName) error
	// keychainUnlocked reports whether the keychain holding the item is
	// unlocked. For an item that does not exist it reports the keychain an add
	// of that item would go to. It never decrypts and never prompts, and any
	// failure to find out is an error, which callers treat as "not confirmed
	// unlocked".
	keychainUnlocked(ctx context.Context, name itemName) (bool, error)
	// addKeychainUnlocked reports whether the keychain an add goes to is
	// unlocked, without looking at any item: a same-named item in another
	// keychain says nothing about the add target. Same failure rule.
	addKeychainUnlocked(ctx context.Context, name itemName) (bool, error)
}

// stagedStore implements Store over an itemAPI with the staged Save.
type stagedStore struct {
	api     itemAPI
	backend string
	max     int
	// afterStep, when not nil, runs after step n (1..4) of Save's own sequence
	// has succeeded. Crash tests use it; production leaves it nil.
	afterStep func(step int)
}

var _ Store = (*stagedStore)(nil)

func newStagedStore(api itemAPI, backend string, maxSecretBytes int) *stagedStore {
	return &stagedStore{api: api, backend: backend, max: maxSecretBytes}
}

func (s *stagedStore) step(n int) {
	if s.afterStep != nil {
		s.afterStep(n)
	}
}

// begin runs the checks every operation performs before the store is touched.
func (s *stagedStore) begin(ctx context.Context, op string, key Key) error {
	if err := ctx.Err(); err != nil {
		return contextError(op, err)
	}
	return validateKey(op, s.backend, key)
}

func (s *stagedStore) fail(op string, kind Kind, status int64) *Error {
	return &Error{Op: op, Backend: s.backend, Kind: kind, Status: status}
}

// failure classifies an error from a primitive without any knowledge of the
// keychain's lock state. write says whether the primitive changes the store,
// which decides how an unrecognised status reads.
//
// -25293 and -25308 are both what a locked keychain returns with the UI
// disabled (a locked file keychain returns -25293, not -25308), and both are
// what a refused access control list returns. Without a confirmed unlocked
// keychain they mean the user is needed, never a foreign code identity; only
// classify can upgrade them to KindAccessDenied.
func (s *stagedStore) failure(op string, err error, write bool) *Error {
	if errors.Is(err, errValueTooLarge) {
		return s.fail(op, KindTooLarge, 0)
	}
	var se *statusError
	if !errors.As(err, &se) {
		return s.fail(op, KindOther, 0)
	}
	switch se.status {
	case statusItemNotFound:
		return s.fail(op, KindNotFound, se.status)
	case statusAuthFailed, statusInteractionNotAllowed:
		return s.fail(op, KindInteractionRequired, se.status)
	case statusUserCanceled:
		return s.fail(op, KindCanceled, se.status)
	case statusDuplicateItem:
		if write {
			return s.fail(op, KindContended, se.status)
		}
	}
	if write {
		// Temporary rule: a write refused with a status not listed above is
		// reported as read-only. Two sandboxes are measured: a sandbox-exec
		// profile that denies file writes to the keychain returns 100001, and
		// Codex's read-only sandbox (codex-cli 0.167.1, macOS 26.6.2, 2026-11-13)
		// refuses every keychain call, reads included, with -50 (errSecParam),
		// which is also what a malformed call returns. Neither status names the
		// sandbox, so an exact classification needs more than the status.
		return s.fail(op, KindReadOnly, se.status)
	}
	return s.fail(op, KindOther, se.status)
}

// unlocked reports whether the keychain of name is confirmed unlocked. A
// failed lookup is not confirmed. With forAdd it asks for the keychain an add
// of name goes to instead of the one that holds an existing item.
func (s *stagedStore) unlocked(ctx context.Context, name itemName, forAdd bool) bool {
	probe := s.api.keychainUnlocked
	if forAdd {
		probe = s.api.addKeychainUnlocked
	}
	unlocked, err := probe(ctx, name)
	return err == nil && unlocked
}

// classify classifies a failed primitive on name. unlockedBefore is the lock
// state taken before the call; forAdd says the primitive was an add, whose
// keychain is the add target rather than the one that holds an item of that
// name. A lock-sensitive status (see failure) means AccessDenied, which lets
// Save delete a stage nobody can read, only when that keychain was confirmed
// unlocked both before and after the call. The two probes are two instants:
// a lock and unlock that both happen between them is not detected. Anything
// else, including a failed lookup, is InteractionRequired, which keeps the
// stage.
func (s *stagedStore) classify(ctx context.Context, op string, name itemName, unlockedBefore, forAdd bool, err error, write bool) *Error {
	var se *statusError
	if errors.As(err, &se) && (se.status == statusAuthFailed || se.status == statusInteractionNotAllowed) &&
		unlockedBefore && s.unlocked(ctx, name, forAdd) {
		return s.fail(op, KindAccessDenied, se.status)
	}
	return s.failure(op, err, write)
}

// lookup reports whether name exists, by reference.
func (s *stagedStore) lookup(ctx context.Context, op string, name itemName) (bool, error) {
	before := s.unlocked(ctx, name, false)
	found, err := s.api.exists(ctx, name)
	if err != nil {
		return false, s.classify(ctx, op, name, before, false, err, false)
	}
	return found, nil
}

// readItem reads and checks one item: a missing item is KindNotFound, an empty
// value KindCorrupt and a value above the bound KindTooLarge.
func (s *stagedStore) readItem(ctx context.Context, op string, name itemName) ([]byte, error) {
	// The keychain state is taken before the read because it cannot be taken
	// later: a lock that opens during the call must not read as unlocked.
	before := s.unlocked(ctx, name, false)
	value, err := s.api.read(ctx, name, s.max)
	if err != nil {
		clear(value)
		return nil, s.classify(ctx, op, name, before, false, err, false)
	}
	if len(value) == 0 {
		return nil, s.fail(op, KindCorrupt, 0)
	}
	if len(value) > s.max {
		clear(value)
		return nil, s.fail(op, KindTooLarge, 0)
	}
	return value, nil
}

// addItem creates one item; a failure is classified with the lock state.
func (s *stagedStore) addItem(ctx context.Context, op string, name itemName, value []byte) error {
	before := s.unlocked(ctx, name, true)
	if err := s.api.add(ctx, name, value); err != nil {
		return s.classify(ctx, op, name, before, true, err, true)
	}
	return nil
}

func kindOf(err error, kind Kind) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == kind
}

// readStage reads the stage for op. An absent stage and a stage this identity
// cannot decrypt (a leftover of another signing identity) both report
// found == false; any other failure is returned and must not be skipped,
// because the account item would then be an older value.
func (s *stagedStore) readStage(ctx context.Context, op string, stage itemName) (value []byte, found bool, err error) {
	value, err = s.readItem(ctx, op, stage)
	switch {
	case err == nil:
		return value, true, nil
	case kindOf(err, KindNotFound), kindOf(err, KindAccessDenied):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// Exists implements Store. It decrypts nothing: it is true if the account item
// or its stage exists by reference. A lone stage this identity cannot read
// counts, so Exists may be true where Load is ErrNotFound.
func (s *stagedStore) Exists(ctx context.Context, key Key) (bool, error) {
	if err := s.begin(ctx, "exists", key); err != nil {
		return false, err
	}
	name := itemName{service: key.Service, account: key.Account}
	// Account, stage, account: a writer between steps 2 and 3 hides the
	// account, and one that finishes after the stage check hides the stage.
	for _, item := range []itemName{name, name.stage(), name} {
		if err := ctx.Err(); err != nil {
			return false, contextError("exists", err)
		}
		found, err := s.lookup(ctx, "exists", item)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// Load implements Store. A readable stage is the newest value and wins; a stage
// nobody here can read is ignored. The reads are stage, account, stage,
// account so a concurrent Save cannot make an existing item look missing.
func (s *stagedStore) Load(ctx context.Context, key Key) ([]byte, error) {
	if err := s.begin(ctx, "load", key); err != nil {
		return nil, err
	}
	name := itemName{service: key.Service, account: key.Account}
	var last error
	for round := 0; round < loadRounds; round++ {
		if err := ctx.Err(); err != nil {
			return nil, contextError("load", err)
		}
		value, found, err := s.readStage(ctx, "load", name.stage())
		if err != nil {
			return nil, err
		}
		if found {
			return value, nil
		}
		value, err = s.readItem(ctx, "load", name)
		if err == nil {
			return value, nil
		}
		if !kindOf(err, KindNotFound) {
			return nil, err
		}
		last = err
	}
	return nil, last
}

// deleteItem deletes one item; a missing item is success.
func (s *stagedStore) deleteItem(ctx context.Context, op string, name itemName) error {
	before := s.unlocked(ctx, name, false)
	err := s.api.delete(ctx, name)
	if err == nil {
		return nil
	}
	if failure := s.classify(ctx, op, name, before, false, err, true); failure.Kind != KindNotFound {
		return failure
	}
	return nil
}

// Delete implements Store. It removes the stage first, so a delete that stops
// halfway cannot leave a newer value to be loaded in place of the older one,
// and it still attempts the account item if the stage could not be removed.
func (s *stagedStore) Delete(ctx context.Context, key Key) error {
	if err := s.begin(ctx, "delete", key); err != nil {
		return err
	}
	name := itemName{service: key.Service, account: key.Account}
	stageErr := s.deleteItem(ctx, "delete", name.stage())
	if err := s.deleteItem(ctx, "delete", name); err != nil {
		return err
	}
	return stageErr
}

// Save implements Store with the staged sequence described at the top of the
// file. The caller serialises Saves of one key.
func (s *stagedStore) Save(ctx context.Context, key Key, secret []byte) error {
	if err := s.begin(ctx, "save", key); err != nil {
		return err
	}
	if len(secret) == 0 {
		return s.fail("save", KindInvalidArgument, 0)
	}
	if len(secret) > s.max {
		return s.fail("save", KindTooLarge, 0)
	}
	name := itemName{service: key.Service, account: key.Account}
	stage := name.stage()

	if err := s.rollForward(ctx, name, stage); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return contextError("save", err)
	}

	// Step 1. Nothing exists of this Save yet, so a failure leaves nothing to
	// clean up, and in particular no stage that is not ours to delete.
	if err := s.addItem(ctx, "save", stage, secret); err != nil {
		return err
	}
	s.step(1)

	// From here the stage may be the only copy of the newest value, so the
	// context no longer applies and the sequence runs to its end.
	ctx = context.WithoutCancel(ctx)

	// Step 2. The stage is removed only when this step fails: until it
	// completes the account item still holds the previous value.
	if err := s.deleteItem(ctx, "save", name); err != nil {
		// The error returned is the delete failure; a stage that cannot be
		// removed either is picked up by the next Save's roll-forward.
		_ = s.deleteItem(ctx, "save", stage)
		return err
	}
	s.step(2)

	// Step 3. A duplicate means someone recreated the account item in the
	// window. The stage is kept: it may be the only copy.
	if err := s.addItem(ctx, "save", name, secret); err != nil {
		return err
	}
	s.step(3)

	// Step 4. The account item holds the new value, so a stage that stays is
	// the same value and harmless, but the Save is reported as failed because
	// the store is not clean; a retry only repeats the roll-forward.
	if err := s.deleteItem(ctx, "save", stage); err != nil {
		return err
	}
	s.step(4)
	return nil
}

// rollForward completes an interrupted Save: a readable stage becomes the
// account item and is removed, and a stage this identity cannot read is
// deleted because its value is unreachable. Any other failure reading the
// stage aborts the Save with the stage untouched.
func (s *stagedStore) rollForward(ctx context.Context, name, stage itemName) error {
	value, err := s.readItem(ctx, "save", stage)
	switch {
	case err == nil:
	case kindOf(err, KindNotFound):
		return nil
	case kindOf(err, KindAccessDenied):
		if ctxErr := ctx.Err(); ctxErr != nil {
			return contextError("save", ctxErr)
		}
		return s.deleteItem(ctx, "save", stage)
	default:
		return err
	}
	defer clear(value)
	if err := ctx.Err(); err != nil {
		return contextError("save", err)
	}

	// The same steps 2 to 4 as a Save, and uncancelable for the same reason.
	ctx = context.WithoutCancel(ctx)
	if err := s.deleteItem(ctx, "save", name); err != nil {
		return err
	}
	if err := s.addItem(ctx, "save", name, value); err != nil {
		return err
	}
	return s.deleteItem(ctx, "save", stage)
}
