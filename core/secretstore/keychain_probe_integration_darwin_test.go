//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// t.Cleanup does not run on a test timeout panic or SIGINT, so a killed run can
// leave a scratch keychain file in TMPDIR and the process's prompt switch off;
// see the note in keychain_integration_darwin_test.go for what to do then.

// TestKeychainProbeOfAKeychainThatIsNotUsable measures what the lock probe says
// for scratch keychains that cannot be used for a reason other than a sandbox:
// a keychain whose file was deleted under a live reference, and a reference to
// a path where no keychain exists. The store reads a -50 at the get-status step
// as "this process cannot use the keychain", which is how Codex's sandbox
// shows; if one of these ordinary failures also showed -50 there, the rule
// would name a sandbox where there is none. Each row logs the step and status
// of both probes, and fails if the store would report keychain-unusable.
//
// It needs no codex and no sandbox and runs on CI.
func TestKeychainProbeOfAKeychainThatIsNotUsable(t *testing.T) {
	// The fixture supplies the prompt switch and the configuration check.
	newScratch(t)

	rows := []struct {
		name string
		// keychain returns the keychain to probe, with the cleanup registered.
		keychain func(t *testing.T) *kctest.Keychain
	}{
		{"the keychain file was deleted under a live reference", func(t *testing.T) *kctest.Keychain {
			kc, err := kctest.Create(t.TempDir())
			if err != nil {
				unusable(t, "creating the second scratch keychain", err)
			}
			t.Cleanup(kc.Close)
			// The reference stays; the file goes. kc.Path is a file kctest.Create
			// made under this test's own temporary directory, nothing else.
			if err := os.Remove(kc.Path()); err != nil {
				t.Fatalf("remove the scratch keychain file: %v", err)
			}
			return kc
		}},
		{"the keychain path does not exist", func(t *testing.T) *kctest.Keychain {
			// The name carries the prefix OpenWithoutUnlock requires, so it can
			// only ever name a scratch keychain; nothing creates the file.
			kc, err := kctest.OpenWithoutUnlock(filepath.Join(t.TempDir(), "secretstore-test-missing.keychain-db"))
			if err != nil {
				t.Fatalf("open a reference to a path with no keychain: %v", err)
			}
			t.Cleanup(kc.Close)
			return kc
		}},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			kc := tt.keychain(t)
			store, err := secretstore.NewKeychainStoreForTest(helperMaxSecret, secretstore.InteractionNever, kc.Ref())
			if err != nil {
				t.Fatalf("build the store: %v", err)
			}
			key := scratchKey(t)
			item, add, err := secretstore.ProbeKeychainForTest(t.Context(), store, key)
			if err != nil {
				t.Fatalf("probe the keychain: %v", err)
			}
			t.Logf("item probe: step %s, OSStatus %d, unusable %t; add-target probe: step %s, OSStatus %d, unusable %t",
				item.Step, item.Status, item.Unusable, add.Step, add.Status, add.Unusable)
			for name, probe := range map[string]secretstore.KeychainProbe{"item": item, "add-target": add} {
				if probe.Unusable {
					t.Errorf("the %s probe reads as keychain-unusable (step %s, OSStatus %d); the rule would name a sandbox for a keychain that is merely broken",
						name, probe.Step, probe.Status)
				}
			}

			_, loadErr := store.Load(t.Context(), key)
			var se *secretstore.Error
			if errors.As(loadErr, &se) {
				t.Logf("Load: kind %s, OSStatus %d, reason %q", se.Kind, se.Status, se.Reason)
				if se.Reason == secretstore.ReasonKeychainUnusable || se.Status == -50 {
					t.Errorf("Load reports keychain-unusable or -50 for a keychain that is merely broken: kind %s, OSStatus %d, reason %q", se.Kind, se.Status, se.Reason)
				}
			} else if loadErr == nil {
				t.Error("Load of a key that was never stored succeeded")
			} else {
				t.Errorf("Load error is not an *Error: %T", loadErr)
			}
		})
	}
}
