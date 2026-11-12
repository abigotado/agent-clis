//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// t.Cleanup does not run on a test timeout panic or SIGINT, so a killed run can
// leave a scratch keychain file in TMPDIR and the process's prompt switch off;
// see the note in keychain_integration_darwin_test.go for what to do then.
//
// TestKeychainHelper is the other half of TestKeychainAcrossBinaries. The outer
// test builds this test binary, signs copies of it as different code identities,
// and runs each copy with -test.run=^TestKeychainHelper$ and one action in the
// environment. A copy does that one action against the scratch keychain and
// prints what it saw.
//
// Protocol:
//
//   - The action, the keychain path, the item key and a step number come in
//     environment variables. None of them is secret.
//   - The first line of standard input is a JSON object with the scratch
//     keychain's password and the values to save. Secrets are never arguments or
//     environment variables.
//   - Standard output carries lines "RESULT name=value" and nothing else the
//     outer test reads. A value is a short token: a Kind name, "present", a
//     digest. It is never a secret, an error message or an account name.
//   - The helper turns the system prompts off before anything else and checks
//     that they are off, then opens the keychain and checks it is unlocked.
//
// Without the action variable the test does nothing, so a normal run of the
// package skips it. That skip is by design, not an environment limit.
const (
	helperActionEnv   = "SECRETSTORE_KEYCHAIN_HELPER"
	helperKeychainEnv = "SECRETSTORE_KEYCHAIN_HELPER_KEYCHAIN"
	helperServiceEnv  = "SECRETSTORE_KEYCHAIN_HELPER_SERVICE"
	helperAccountEnv  = "SECRETSTORE_KEYCHAIN_HELPER_ACCOUNT"
	helperStepEnv     = "SECRETSTORE_KEYCHAIN_HELPER_STEP"

	helperResultPrefix = "RESULT "
	// helperCrashExit is the exit status of a helper that stopped itself in the
	// middle of Save.
	helperCrashExit = 42
	// helperGoLine is what the outer test sends to a paused helper.
	helperGoLine = "go"
	// helperMaxSecret is the store's bound in the helper.
	helperMaxSecret = 4096
)

// The actions a helper runs.
const (
	actionSave        = "save"
	actionLoad        = "load"
	actionSaveTwice   = "save-twice"
	actionCrash       = "crash"
	actionContend     = "contend"
	actionAddAccount  = "add-account"
	actionAddStage    = "add-stage"
	actionRepairNever = "repair-never"
	actionRepair      = "repair"
)

// helperInput is the first line of the helper's standard input.
type helperInput struct {
	Password string   `json:"password"`
	Secrets  [][]byte `json:"secrets"`
}

// kindName names an error for a result line. It carries the Kind and never the
// error text.
func kindName(err error) string {
	if err == nil {
		return "none"
	}
	var se *secretstore.Error
	if errors.As(err, &se) {
		return se.Kind.String()
	}
	return "unclassified"
}

func digestOf(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type helperSession struct {
	t       *testing.T
	in      *bufio.Reader
	kc      *kctest.Keychain
	key     secretstore.Key
	secrets [][]byte
}

func (h *helperSession) emit(name, value string) {
	h.t.Helper()
	if _, err := fmt.Fprintf(os.Stdout, "%s%s=%s\n", helperResultPrefix, name, value); err != nil {
		h.t.Fatalf("write the result %q: %v", name, err)
	}
}

func (h *helperSession) secret(i int) []byte {
	h.t.Helper()
	if i >= len(h.secrets) {
		h.t.Fatalf("the action needs secret %d, standard input carried %d", i, len(h.secrets))
	}
	return h.secrets[i]
}

func (h *helperSession) requireUnlocked(when string) {
	h.t.Helper()
	unlocked, err := h.kc.Unlocked()
	if err != nil {
		h.t.Fatalf("read the keychain status %s: %v", when, err)
	}
	if !unlocked {
		h.t.Fatalf("the keychain is locked %s, so a refusal would not say anything about the code identity", when)
	}
}

// newHelperSession does the work every action starts with, in the order that
// keeps a dialog from ever showing: prompts off and checked, then the keychain.
func newHelperSession(t *testing.T) *helperSession {
	t.Helper()
	if err := kctest.SetInteractionAllowed(false); err != nil {
		t.Fatalf("turn the system prompts off: %v", err)
	}
	if allowed, err := kctest.InteractionAllowed(); err != nil || allowed {
		t.Fatalf("prompts allowed = %t, error %v, want off", allowed, err)
	}

	h := &helperSession{t: t, in: bufio.NewReader(os.Stdin)}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("find the running binary: %v", err)
	}
	h.emit("interaction", "off")
	h.emit("binary", exe)
	h.emit("marker", kctest.BuildMarker())

	line, err := h.in.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read the input line: %v", err)
	}
	var input helperInput
	if err := json.Unmarshal(line, &input); err != nil {
		t.Fatalf("decode the input line: %v", err)
	}
	h.secrets = input.Secrets
	t.Cleanup(func() {
		for _, s := range h.secrets {
			clear(s)
		}
	})

	h.key = secretstore.Key{Service: os.Getenv(helperServiceEnv), Account: os.Getenv(helperAccountEnv)}
	if h.key.Service == "" || h.key.Account == "" {
		t.Fatal("the item key is not in the environment")
	}
	path := os.Getenv(helperKeychainEnv)
	if !filepath.IsAbs(path) {
		t.Fatal("the keychain path is not in the environment")
	}
	h.kc, err = kctest.Open(path, input.Password)
	if err != nil {
		t.Fatalf("open the scratch keychain: %v", err)
	}
	t.Cleanup(h.kc.Close)
	h.requireUnlocked("before the action")
	return h
}

func (h *helperSession) store(interaction secretstore.Interaction) secretstore.Store {
	h.t.Helper()
	store, err := secretstore.NewKeychainStoreForTest(helperMaxSecret, interaction, h.kc.Ref())
	if err != nil {
		h.t.Fatalf("build the store over the scratch keychain: %v", err)
	}
	return store
}

// emitStage reports whether the key's stage item exists, found by reference, so
// a stage this identity cannot read still shows.
func (h *helperSession) emitStage(store secretstore.Store) {
	h.t.Helper()
	present, err := secretstore.StageExistsForTest(h.t.Context(), store, h.key)
	if err != nil {
		h.t.Fatalf("look up the stage: %v", err)
	}
	state := "absent"
	if present {
		state = "present"
	}
	h.emit("stage", state)
}

// emitLoad loads the key and reports the Kind and the value's digest.
func (h *helperSession) emitLoad(store secretstore.Store, errName string) {
	h.t.Helper()
	value, err := store.Load(h.t.Context(), h.key)
	h.emit(errName, kindName(err))
	if err == nil {
		h.emit("value", digestOf(value))
	}
	clear(value)
}

func (h *helperSession) finish() {
	h.t.Helper()
	h.requireUnlocked("after the action")
	h.emit("unlocked", "true")
}

func TestKeychainHelper(t *testing.T) {
	action := os.Getenv(helperActionEnv)
	if action == "" {
		t.Skip("runs only as the helper process of TestKeychainAcrossBinaries")
	}
	h := newHelperSession(t)
	ctx := t.Context()

	switch action {
	case actionSave:
		store := h.store(secretstore.InteractionNever)
		h.emit("error", kindName(store.Save(ctx, h.key, h.secret(0))))
		h.emitStage(store)

	case actionLoad:
		store := h.store(secretstore.InteractionNever)
		h.emitLoad(store, "error")
		h.emitStage(store)

	case actionSaveTwice:
		store := h.store(secretstore.InteractionNever)
		h.emit("save1", kindName(store.Save(ctx, h.key, h.secret(0))))
		h.emit("save2", kindName(store.Save(ctx, h.key, h.secret(1))))
		h.emitStage(store)

	case actionCrash:
		step, err := strconv.Atoi(os.Getenv(helperStepEnv))
		if err != nil || step < 1 || step > 3 {
			t.Fatalf("the crash step %q is not 1, 2 or 3", os.Getenv(helperStepEnv))
		}
		store := h.store(secretstore.InteractionNever)
		hook := func(done int) {
			if done != step {
				return
			}
			h.emit("crashing", strconv.Itoa(done))
			// A crash, not a failure: nothing after this runs, no deferred call and
			// no cleanup, the way a killed process leaves the keychain.
			os.Exit(helperCrashExit)
		}
		if err := secretstore.SetAfterStepForTest(store, hook); err != nil {
			t.Fatalf("install the crash hook: %v", err)
		}
		// Reached only if the hook never fired, which the outer test reports.
		h.emit("error", kindName(store.Save(ctx, h.key, h.secret(0))))

	case actionContend:
		store := h.store(secretstore.InteractionNever)
		hook := func(done int) {
			if done != 2 {
				return
			}
			// The account item is gone and the stage holds the new value: the
			// window another writer uses. Wait for the outer test to have used it.
			h.emit("paused", "1")
			line, err := h.in.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != helperGoLine {
				t.Fatalf("no go signal after the pause: %v", err)
			}
		}
		if err := secretstore.SetAfterStepForTest(store, hook); err != nil {
			t.Fatalf("install the pause hook: %v", err)
		}
		h.emit("error", kindName(store.Save(ctx, h.key, h.secret(0))))
		h.emitStage(store)
		h.emitLoad(store, "load_error")

	case actionAddAccount:
		store := h.store(secretstore.InteractionNever)
		err := secretstore.AddAccountItemForTest(ctx, store, h.key, h.secret(0))
		if err != nil {
			t.Fatalf("add the account item: %v", err)
		}
		h.emit("error", "none")

	case actionAddStage:
		store := h.store(secretstore.InteractionNever)
		if err := secretstore.AddLeftoverStageForTest(ctx, store, h.key, h.secret(0)); err != nil {
			t.Fatalf("add the stage item: %v", err)
		}
		h.emit("error", "none")

	case actionRepairNever:
		store := h.store(secretstore.InteractionNever)
		repairer, ok := store.(secretstore.ACLRepairer)
		if !ok {
			t.Fatalf("%T does not implement ACLRepairer", store)
		}
		h.emit("error", kindName(repairer.RepairAccess(ctx, h.key)))
		h.emitLoad(store, "load_error")
		h.emitStage(store)

	case actionRepair:
		store := h.store(secretstore.InteractionAllowed)
		repairer, ok := store.(secretstore.ACLRepairer)
		if !ok {
			t.Fatalf("%T does not implement ACLRepairer", store)
		}
		// What the item trusted before: an item another build wrote lists that
		// build's path, so this binary counts zero. Reading the list is by
		// reference and cannot prompt, but it may be refused; the row asserts
		// only what comes after, so a refusal is reported, not failed.
		before := "unreadable"
		if entries, err := h.kc.ACL(h.key.Service, h.key.Account); err == nil {
			before = decryptSelfApplications(entries)
		}
		h.emit("acl_before_self", before)

		h.emit("error", kindName(repairer.RepairAccess(ctx, h.key)))
		h.emitLoad(store, "load_error")
		h.emitStage(store)

		entries, err := h.kc.ACL(h.key.Service, h.key.Account)
		if err != nil {
			t.Fatalf("dump the repaired item's access control list: %v", err)
		}
		assertAccessList(t, "repaired item", entries)
		if !t.Failed() {
			h.emit("acl", "rule1")
		}

	default:
		t.Fatalf("unknown helper action %q", action)
	}
	h.finish()
}

// decryptSelfApplications reports how many applications of the item's decrypt
// entry are this binary.
func decryptSelfApplications(entries []kctest.ACLEntry) string {
	for _, e := range entries {
		if e.Has(kctest.AuthDecrypt) {
			return strconv.Itoa(e.SelfApplications)
		}
	}
	return "no-decrypt-entry"
}
