//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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

// requireSandboxExec skips the row when this environment cannot run a program
// under sandbox-exec, which is the case inside another sandbox and on a machine
// without the tool. It is a documented environmental limit: CI prints a notice
// and does not fail.
func requireSandboxExec(t *testing.T) {
	t.Helper()
	reason := ""
	if _, err := os.Stat(sandboxExecPath); err != nil {
		reason = "sandbox-exec is not installed: " + err.Error()
	} else if out, err := exec.CommandContext(t.Context(), sandboxExecPath, "-p", sandboxAllowAll, "/usr/bin/true").CombinedOutput(); err != nil {
		reason = "sandbox-exec cannot run a program here: " + err.Error() + ": " + tail(out, 512)
	}
	if reason == "" {
		return
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		// A workflow command, so the skip is visible in the run summary.
		fmt.Printf("::notice title=keychain integration::the sandbox-exec row did not run: %s\n", reason)
	}
	t.Skip(reason)
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

	call := func(profile string, key secretstore.Key, secret []byte) *helperProcess {
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
		r := call(sandboxAllowAll, key, secret).finish(t)
		r.wantExit(t, 0)
		r.verifyBinary(t, self)
		r.want(t, "error", "none")
		f.expectLoad(t, self, key, secret)
	})

	t.Run("Save under a profile that denies writes to the keychain is read-only", func(t *testing.T) {
		key, secret := scratchKey(t), randomSecret(t)
		r := call(sandboxDenyScratch, key, secret).finish(t)
		if _, reached := r.fields["error"]; !reached {
			// The helper could not get as far as Save: opening a keychain whose
			// directory is read-only failed first. That says the profile is too
			// strict for this row, not what Save maps to.
			t.Skipf("the helper did not reach Save under the deny profile (exit %d); the denial stops the keychain from even opening\n%s", r.exit, r.describe())
		}
		r.wantExit(t, 0)
		r.verifyBinary(t, self)
		t.Logf("Save under a denied write: kind %s, OSStatus %s", r.get(t, "error"), r.get(t, "status"))
		r.want(t, "error", "read-only")
		// A refused write changed nothing: outside the sandbox the key is absent.
		_, err := s.store(t, helperMaxSecret, secretstore.InteractionNever).Load(context.WithoutCancel(t.Context()), key)
		if !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("Load after the refused Save: %v, want not-found", err)
		}
	})
}
