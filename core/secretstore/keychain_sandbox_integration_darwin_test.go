//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// t.Cleanup does not run on a test timeout panic or SIGINT, so a killed run can
// leave a scratch keychain file in TMPDIR and the process's prompt switch off;
// see the note in keychain_integration_darwin_test.go for what to do then.

const (
	sandboxExecPath = "/usr/bin/sandbox-exec"
	// sandboxAllowAll is a profile that changes nothing; it is the control.
	sandboxAllowAll = `(version 1)(allow default)`
	// sandboxDenyScratch denies every write under the directory in SCRATCH and
	// allows everything else.
	sandboxDenyScratch = `(version 1)(allow default)(deny file-write* (subpath (param "SCRATCH")))`
)

// sandboxPrefix is the command prefix that runs a helper under profile, with
// the scratch directory as the parameter SCRATCH. The directory is resolved
// through symlinks first: the sandbox matches real paths, and a temp directory
// on macOS is under the symlink /var.
func sandboxPrefix(t *testing.T, profile, scratchDir string) []string {
	t.Helper()
	real, err := filepath.EvalSymlinks(scratchDir)
	if err != nil {
		t.Fatalf("resolve the scratch directory: %v", err)
	}
	return []string{sandboxExecPath, "-D", "SCRATCH=" + real, "-p", profile}
}

// sandboxProbeTimeout bounds the probe that runs /usr/bin/true under
// sandbox-exec. It is a hang guard, far above what the probe takes.
const sandboxProbeTimeout = 30 * time.Second

// requireKeychain reports whether the run demands a usable keychain environment,
// as CI does: where it is set, a missing prerequisite fails and never skips.
func requireKeychain() bool {
	return os.Getenv("SECRETSTORE_REQUIRE_KEYCHAIN") == "1"
}

// requireSandboxExec stops the row when this environment cannot run a program
// under sandbox-exec, which is the case inside another sandbox and on a machine
// without the tool. Under SECRETSTORE_REQUIRE_KEYCHAIN=1 that fails the row, so a
// runner that lost sandbox-exec cannot pass by testing nothing; without it the
// row skips and, on GitHub Actions, prints a notice.
func requireSandboxExec(t *testing.T) {
	t.Helper()
	reason := ""
	if _, err := os.Stat(sandboxExecPath); err != nil {
		reason = "sandbox-exec is not installed: " + err.Error()
	} else {
		ctx, cancel := context.WithTimeout(t.Context(), sandboxProbeTimeout)
		defer cancel()
		if out, err := exec.CommandContext(ctx, sandboxExecPath, "-p", sandboxAllowAll, "/usr/bin/true").CombinedOutput(); err != nil {
			reason = "sandbox-exec cannot run a program here: " + err.Error() + ": " + tail(out, 512)
		}
	}
	if reason == "" {
		return
	}
	if requireKeychain() {
		t.Fatalf("the sandbox-exec row is required but cannot run: %s", reason)
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		// A workflow command, so the skip is visible in the run summary.
		fmt.Printf("::notice title=keychain integration::the sandbox-exec row did not run: %s\n", reason)
	}
	t.Skip(reason)
}

// stoppedAtKeychainOpen reports whether a helper that did not reach Save stopped
// where a read-only keychain directory is expected to stop it: it printed its
// start fields, which come before the keychain is opened, and it names the failed
// open. The helper's testing package writes a fatal message to standard output,
// so both streams are searched.
func (r helperResult) stoppedAtKeychainOpen() bool {
	_, binary := r.fields["binary"]
	_, marker := r.fields["marker"]
	if !binary || !marker {
		return false
	}
	return strings.Contains(r.stderr, "open the scratch keychain") ||
		strings.Contains(strings.Join(r.other, "\n"), "open the scratch keychain")
}

// TestKeychainSaveInReadOnlySandbox approximates the macOS sandbox that allows
// reads and refuses writes, which is where ErrReadOnly comes from. A helper runs
// under /usr/bin/sandbox-exec with a profile that allows everything except file
// writes under the scratch keychain's directory, and saves into the scratch
// keychain. The backend has no exact status for that refusal yet, so Save is
// expected to report it through the temporary rule in stagedStore.failure: an
// unclassified status on a write is KindReadOnly. The row records the status the
// refusal carried, which is what the exact classification will be written from.
//
// This is an approximation of the real sandbox, not the real one: the status
// that Codex's sandbox returns (100001 in the notes) can differ from what
// sandbox-exec's file-write denial gives. The real classification is a local run
// of the same save under `codex sandbox macos`, recorded with the versions.
//
// The control runs the same helper under a profile that denies nothing and
// expects the save to succeed, so a refusal that comes from sandbox-exec or the
// helper itself, and not from the denial, fails the row instead of passing it.
//
// Run it with:
//
//	SECRETSTORE_REQUIRE_KEYCHAIN=1 go test -race -count=1 -v -tags keychainintegration \
//	  -run '^TestKeychainSaveInReadOnlySandbox$' ./secretstore
func TestKeychainSaveInReadOnlySandbox(t *testing.T) {
	requireSandboxExec(t)
	s := newScratch(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("find the running binary: %v", err)
	}
	self := testBinary{name: "this test binary", path: exe, marker: kctest.BuildMarker()}
	f := &fixture{scratch: s}
	scratchDir := filepath.Dir(s.kc.Path())

	call := func(t *testing.T, profile string, key secretstore.Key, secret []byte) *helperProcess {
		t.Helper()
		return f.start(t, helperCall{
			bin:     self,
			action:  actionSaveStatus,
			key:     key,
			secrets: [][]byte{secret},
			sandbox: sandboxPrefix(t, profile, scratchDir),
		})
	}

	t.Run("control: a profile that denies nothing lets Save succeed", func(t *testing.T) {
		key, secret := scratchKey(t), randomSecret(t)
		r := call(t, sandboxAllowAll, key, secret).finish(t)
		r.wantExit(t, 0)
		r.verifyBinary(t, self)
		r.want(t, "error", "none")
		f.expectLoad(t, self, key, secret)
	})

	t.Run("Save under a profile that denies writes to the keychain is read-only", func(t *testing.T) {
		key, secret := scratchKey(t), randomSecret(t)
		r := call(t, sandboxDenyScratch, key, secret).finish(t)
		if _, reached := r.fields["error"]; !reached {
			// The helper did not get as far as Save. Only one reason is an
			// environmental limit: opening a keychain whose directory is read-only
			// failed first, which says the profile is too strict for this row, not
			// what Save maps to. Anything else, a crash or a helper that never
			// started included, is a failure, and so is that reason under
			// SECRETSTORE_REQUIRE_KEYCHAIN=1.
			if !requireKeychain() && r.stoppedAtKeychainOpen() {
				t.Skipf("the helper did not reach Save under the deny profile (exit %d); the denial stops the keychain from even opening\n%s", r.exit, r.describe())
			}
			t.Fatalf("the helper did not reach Save under the deny profile (exit %d)\n%s", r.exit, r.describe())
		}
		r.wantExit(t, 0)
		r.verifyBinary(t, self)
		t.Logf("Save under a denied write: kind %s, OSStatus %s", r.get(t, "error"), r.get(t, "status"))
		r.want(t, "error", "read-only")
		// A refused write changed nothing: outside the sandbox the key is absent
		// and so is its stage item.
		ctx := context.WithoutCancel(t.Context())
		store := s.store(t, helperMaxSecret, secretstore.InteractionNever)
		if _, err := store.Load(ctx, key); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("Load after the refused Save: %v, want not-found", err)
		}
		staged, err := secretstore.StageExistsForTest(ctx, store, key)
		if err != nil {
			t.Fatalf("look up the stage after the refused Save: %v", err)
		}
		if staged {
			t.Error("the refused Save left a stage item behind")
		}
	})
}
