//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
)

// These tests run the real macOS backend against a scratch keychain: a file
// keychain created in t.TempDir() that is never on the user's search list, and
// that the backend is pointed at explicitly. They never read or write the login
// keychain. They do change one process-wide setting, the system prompt switch,
// which they turn off first and restore afterwards. Run them on a machine you
// do not mind that on; CI runs them on a disposable runner.
//
// Production uses the default keychain (a NULL target). These tests cover the
// explicit-keychain query shape only; the NULL path is not exercised here.
//
// t.Cleanup does not run when a test dies on a timeout panic (go test -timeout)
// or on SIGINT, in these files and in the helper files of this suite. Two things
// can then be left behind. A throwaway keychain file stays in TMPDIR (a
// TestKeychain* directory made by t.TempDir); delete it by hand. And the prompt
// switch can stay off in a process that was holding it. TestInteractionFlagScope
// measures that switch as per process, as far as its getter shows, so the
// process that changed it ending is enough and nothing needs restoring. If that
// test failed, or the switch reads off in a fresh process, run its restore
// action from core/ and read the result:
//
//	SECRETSTORE_SCOPE_HELPER=restore go test -count=1 -v -tags keychainintegration \
//	  -run '^TestInteractionScopeHelper$' ./secretstore
//
// It prints RESULT allowed=true when the switch is on again. Nothing on the
// user's search list is touched either way.

// unusable reports an environment that cannot run the tests. CI sets
// SECRETSTORE_REQUIRE_KEYCHAIN=1, where this fails instead of skipping, so a
// runner that lost the keychain cannot pass by testing nothing. The error
// carries a call name and an OSStatus only.
func unusable(t *testing.T, what string, err error) {
	t.Helper()
	if os.Getenv("SECRETSTORE_REQUIRE_KEYCHAIN") == "1" {
		t.Fatalf("a scratch keychain is required but %s failed: %v", what, err)
	}
	t.Skipf("a scratch keychain is not usable: %s failed: %v", what, err)
}

// scratch is the outer test's fixture.
type scratch struct {
	kc *kctest.Keychain
}

// promptsOff turns the process's prompt setting off and restores what it was
// when the test ends. It runs before any keychain is created or opened, so that
// nothing in the test can show a dialog; SetInteractionAllowed reads the value
// back, which makes a restore that did not take effect an error.
func promptsOff(t *testing.T) {
	t.Helper()
	previous, err := kctest.InteractionAllowed()
	if err != nil {
		unusable(t, "reading the prompt setting", err)
	}
	t.Cleanup(func() {
		if err := kctest.SetInteractionAllowed(previous); err != nil {
			t.Errorf("restore the prompt setting to %t: %v", previous, err)
		}
	})
	if err := kctest.SetInteractionAllowed(false); err != nil {
		unusable(t, "turning prompts off", err)
	}
}

// newScratch prepares the process and returns a scratch keychain, in this
// order: record the user's keychain configuration and the prompt setting, turn
// prompts off, create the keychain. Cleanup runs in reverse: delete the
// keychain, restore the prompt setting, and check the configuration is what it
// was.
func newScratch(t *testing.T) *scratch {
	t.Helper()

	before, err := kctest.Snapshot()
	if err != nil {
		unusable(t, "reading the keychain search list", err)
	}
	t.Cleanup(func() {
		after, err := kctest.Snapshot()
		if err != nil {
			t.Errorf("read the keychain configuration after the test: %v", err)
			return
		}
		if !before.Equal(after) {
			t.Errorf("the user's keychain configuration changed: before %s, after %s", before, after)
		}
	})

	promptsOff(t)

	kc, err := kctest.Create(t.TempDir())
	if err != nil {
		unusable(t, "creating the scratch keychain", err)
	}
	t.Cleanup(func() {
		if err := kc.Delete(); err != nil {
			t.Errorf("delete the scratch keychain: %v", err)
		}
	})

	// A scratch keychain on the search list would put every test item within the
	// reach of other programs, and a default-keychain change would redirect
	// production-shaped queries. Neither may happen.
	afterCreate, err := kctest.Snapshot()
	if err != nil {
		t.Fatalf("read the keychain configuration after creating the keychain: %v", err)
	}
	if !before.Equal(afterCreate) {
		t.Fatalf("creating the scratch keychain changed the user's keychain configuration: before %s, after %s", before, afterCreate)
	}
	if slices.Contains(afterCreate.SearchList, kc.Path()) || afterCreate.Default == kc.Path() {
		t.Fatal("the scratch keychain is on the search list or is the default keychain")
	}
	unlocked, err := kc.Unlocked()
	if err != nil {
		t.Fatalf("read the scratch keychain status: %v", err)
	}
	if !unlocked {
		t.Fatal("the scratch keychain is locked right after creation")
	}
	return &scratch{kc: kc}
}

func (s *scratch) store(t *testing.T, max int, interaction secretstore.Interaction) secretstore.Store {
	t.Helper()
	store, err := secretstore.NewKeychainStoreForTest(max, interaction, s.kc.Ref())
	if err != nil {
		t.Fatalf("build the store over the scratch keychain: %v", err)
	}
	return store
}

// lock locks the scratch keychain and unlocks it again when the test ends,
// whatever happens, so a failure cannot leave later rows on a locked keychain.
func (s *scratch) lock(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if err := s.kc.Unlock(); err != nil {
			t.Errorf("unlock the scratch keychain: %v", err)
		}
	})
	if err := s.kc.Lock(); err != nil {
		t.Fatalf("lock the scratch keychain: %v", err)
	}
	if unlocked, err := s.kc.Unlocked(); err != nil || unlocked {
		t.Fatalf("scratch keychain unlocked = %t, status error %v, want locked", unlocked, err)
	}
}

func (s *scratch) unlock(t *testing.T) {
	t.Helper()
	if err := s.kc.Unlock(); err != nil {
		t.Fatalf("unlock the scratch keychain: %v", err)
	}
	if unlocked, err := s.kc.Unlocked(); err != nil || !unlocked {
		t.Fatalf("scratch keychain unlocked = %t, status error %v, want unlocked", unlocked, err)
	}
}

func scratchKey(t *testing.T) secretstore.Key {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return secretstore.Key{Service: "secretstore-test-" + hex.EncodeToString(b), Account: "account"}
}

func TestKeychainScratch(t *testing.T) {
	s := newScratch(t)

	for _, tt := range []struct {
		name        string
		max         int
		interaction secretstore.Interaction
	}{
		{"never 256", 256, secretstore.InteractionNever},
		{"never 4096", 4096, secretstore.InteractionNever},
		// Prompts are off for the process, so a lookup that would need the user
		// fails instead of waiting; this runs the dictionaries without
		// kSecUseAuthenticationUIFail.
		{"allowed 1024", 1024, secretstore.InteractionAllowed},
	} {
		t.Run("contract/"+tt.name, func(t *testing.T) {
			secretstoretest.Contract(t, s.store(t, tt.max, tt.interaction), tt.max)
		})
	}

	t.Run("a nil target is refused", func(t *testing.T) {
		store, err := secretstore.NewKeychainStoreForTest(256, secretstore.InteractionNever, 0)
		if err == nil || store != nil {
			t.Fatalf("NewKeychainStoreForTest(zero target) = %v, %v, want a refusal", store, err)
		}
	})

	t.Run("save under never succeeds", func(t *testing.T) {
		store := s.store(t, 256, secretstore.InteractionNever)
		if failsUI, err := secretstore.KeychainStoreFailsUIForTest(store); err != nil || !failsUI {
			t.Fatalf("store fails UI = %t, error %v, want true: this row must run under InteractionNever", failsUI, err)
		}
		key := scratchKey(t)
		// The add dictionary must not carry kSecUseAuthenticationUI: SecItemAdd
		// rejects it, so a Save that works proves it is absent.
		if err := store.Save(t.Context(), key, []byte("first")); err != nil {
			t.Fatalf("Save under InteractionNever: %v", err)
		}
		got, err := store.Load(t.Context(), key)
		if err != nil || !bytes.Equal(got, []byte("first")) {
			t.Fatalf("Load = %q, %v, want the saved value", got, err)
		}
	})

	t.Run("access control list of an item", func(t *testing.T) {
		store := s.store(t, 256, secretstore.InteractionNever)
		key := scratchKey(t)
		if err := store.Save(t.Context(), key, []byte("acl-value")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		entries, err := s.kc.ACL(key.Service, key.Account)
		if err != nil {
			t.Fatalf("dump the item's access control list: %v", err)
		}
		assertAccessList(t, "account item", entries)

		// A stage is created by the same primitive, so it must carry the same list.
		if err := secretstore.AddLeftoverStageForTest(t.Context(), store, key, []byte("stage-value")); err != nil {
			t.Fatalf("add a stage: %v", err)
		}
		entries, err = s.kc.ACL(key.Service, secretstore.StageAccountForTest(key))
		if err != nil {
			t.Fatalf("dump the stage's access control list: %v", err)
		}
		assertAccessList(t, "stage item", entries)
	})

	t.Run("a locked keychain under never needs the user", func(t *testing.T) {
		store := s.store(t, 256, secretstore.InteractionNever)
		key := scratchKey(t)
		if err := store.Save(t.Context(), key, []byte("kept")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		s.lock(t)

		if _, err := store.Load(t.Context(), key); !errors.Is(err, secretstore.ErrInteractionRequired) {
			t.Errorf("Load on a locked keychain: err = %v, want ErrInteractionRequired", err)
		}
		if err := store.Save(t.Context(), scratchKey(t), []byte("new")); !errors.Is(err, secretstore.ErrInteractionRequired) {
			t.Errorf("Save on a locked keychain: err = %v, want ErrInteractionRequired", err)
		}
		if err := store.Save(t.Context(), key, []byte("replaced")); !errors.Is(err, secretstore.ErrInteractionRequired) {
			t.Errorf("Save over an item on a locked keychain: err = %v, want ErrInteractionRequired", err)
		}

		s.unlock(t)
		got, err := store.Load(t.Context(), key)
		if err != nil || !bytes.Equal(got, []byte("kept")) {
			t.Fatalf("Load after unlocking = %q, %v, want the value saved before the lock", got, err)
		}
	})

	t.Run("a locked keychain keeps a leftover stage", func(t *testing.T) {
		store := s.store(t, 256, secretstore.InteractionNever)
		key := scratchKey(t)
		if err := store.Save(t.Context(), key, []byte("old")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		// The stage an interrupted Save leaves holds the newest value.
		if err := secretstore.AddLeftoverStageForTest(t.Context(), store, key, []byte("newest")); err != nil {
			t.Fatalf("add a stage: %v", err)
		}
		s.lock(t)

		// A locked keychain must not read as a stage nobody can decrypt: that
		// would let Save delete the only copy of the newest value.
		err := store.Save(t.Context(), key, []byte("later"))
		if !errors.Is(err, secretstore.ErrInteractionRequired) {
			t.Fatalf("Save with a leftover stage on a locked keychain: err = %v, want ErrInteractionRequired", err)
		}

		s.unlock(t)
		present, err := secretstore.StageExistsForTest(t.Context(), store, key)
		if err != nil || !present {
			t.Fatalf("stage exists = %t, error %v, want the stage intact after the refused Save", present, err)
		}
		got, err := store.Load(t.Context(), key)
		if err != nil || !bytes.Equal(got, []byte("newest")) {
			t.Fatalf("Load = %q, %v, want the stage's value", got, err)
		}

		// With the keychain unlocked the next Save rolls the stage forward and
		// then writes its own value.
		if err := store.Save(t.Context(), key, []byte("later")); err != nil {
			t.Fatalf("Save after unlocking: %v", err)
		}
		got, err = store.Load(t.Context(), key)
		if err != nil || !bytes.Equal(got, []byte("later")) {
			t.Fatalf("Load after the second Save = %q, %v, want the new value", got, err)
		}
		if present, err := secretstore.StageExistsForTest(t.Context(), store, key); err != nil || present {
			t.Fatalf("stage exists = %t, error %v, want no stage after a completed Save", present, err)
		}
	})

	t.Run("prompts stayed off", func(t *testing.T) {
		allowed, err := kctest.InteractionAllowed()
		if err != nil || allowed {
			t.Fatalf("prompt setting = %t, error %v, want off for the whole run", allowed, err)
		}
	})
}

// assertAccessList checks the whole entry set of an item's access control list
// against rule 1: the owner entry (ChangeACL) and the one decrypt entry trust
// this binary and nobody else, the decrypt entry does not require the login
// password, and the only entry open to any application is the one that lets
// anybody encrypt, which Apple's SecAccessCreate adds and which exposes nothing.
func assertAccessList(t *testing.T, what string, entries []kctest.ACLEntry) {
	t.Helper()
	var lines []string
	for i, e := range entries {
		lines = append(lines, "  entry "+strconv.Itoa(i)+": "+e.String())
	}
	dump := strings.Join(lines, "\n")
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf("%s: "+format+"\nfull dump:\n%s", append(append([]any{what}, args...), dump)...)
	}
	onlySelf := func(e kctest.ACLEntry) bool { return e.Applications == 1 && e.SelfApplications == 1 }

	var decrypt, change, rest []kctest.ACLEntry
	for _, e := range entries {
		switch {
		case e.Has(kctest.AuthDecrypt) && e.Has(kctest.AuthChangeACL):
			fail("one entry covers both decrypt and ChangeACL: %s", e)
		case e.Has(kctest.AuthDecrypt):
			decrypt = append(decrypt, e)
		case e.Has(kctest.AuthChangeACL):
			change = append(change, e)
		default:
			rest = append(rest, e)
		}
	}

	if len(decrypt) != 1 {
		fail("%d entries cover decrypt, want exactly one", len(decrypt))
	} else {
		if !onlySelf(decrypt[0]) {
			fail("the decrypt entry is not exactly [this binary]: %s", decrypt[0])
		}
		if decrypt[0].PromptSelector&kctest.PromptRequirePassphrase != 0 {
			fail("the decrypt entry still requires the passphrase: %s", decrypt[0])
		}
	}
	if len(change) != 1 {
		fail("%d entries cover ChangeACL, want exactly one", len(change))
	} else if !onlySelf(change[0]) {
		fail("the ChangeACL entry is not exactly [this binary]: %s", change[0])
	}
	if len(rest) != 1 {
		fail("%d entries beyond decrypt and ChangeACL, want exactly one encrypt-only entry", len(rest))
		return
	}
	if !slices.Equal(rest[0].Authorizations, []string{kctest.AuthEncrypt}) || rest[0].Applications != -1 {
		fail("the remaining entry is not the encrypt-only entry open to any application: %s", rest[0])
	}
}
