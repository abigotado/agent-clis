//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
// This is an approximation of the real sandbox, not the real one. The real one
// is the opt-in codex rows below, run locally: there the lock probe itself is
// refused with -50, so Save reports unavailable (keychain-unusable) where this
// profile's file-write denial, with a working probe, gives 100001 and read-only.
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
		wantReadOnlySave(t, s, self, r, key)
	})

	// The open-only mode the codex rows need, without a sandbox: Save must
	// succeed through a keychain the helper opened without an unlock, so a
	// refusal in the codex rows comes from the sandbox and not from the mode.
	// It needs no codex and runs on CI.
	t.Run("control: the open-only helper saves without a sandbox", func(t *testing.T) {
		f.requireUnlocked(t)
		key, secret := scratchKey(t), randomSecret(t)
		r := f.start(t, helperCall{
			bin:      self,
			action:   actionSaveStatus,
			key:      key,
			secrets:  [][]byte{secret},
			openOnly: true,
		}).finish(t)
		r.wantExit(t, 0)
		r.verifyBinary(t, self)
		r.want(t, "error", "none")
		// Outside a sandbox neither probe reads as unusable, so the codex rows'
		// unavailable result is the sandbox's and not the mode's.
		r.want(t, "probe_unusable", "false")
		r.want(t, "add_unusable", "false")
		f.expectLoad(t, self, key, secret)

		// And it reads the item back, so an unavailable result in the codex
		// Load row is the sandbox's and not the mode's.
		l := f.start(t, helperCall{bin: self, action: actionLoad, key: key, openOnly: true}).finish(t)
		l.wantExit(t, 0)
		l.verifyBinary(t, self)
		l.want(t, "error", "none")
		l.want(t, "value", digestOf(secret))
		l.want(t, "probe_unusable", "false")
		l.want(t, "raw_error", "none")
	})

	// The real sandbox, run only where a developer points SECRETSTORE_CODEX_SANDBOX
	// at a codex binary. It is opt-in and local: a CI runner has no codex, so the
	// rows skip there even under SECRETSTORE_REQUIRE_KEYCHAIN=1, and CI does not
	// require them to pass. SECRETSTORE_CODEX_PROFILE picks the policy; the
	// default :read-only runs with an empty CODEX_HOME and a scratch working
	// directory, so no user or project config can select another one.
	//
	// Measured with codex-cli 0.167.1 on macOS 26.6.2 (2026-11-13) under
	// :read-only: reading the keychain's status returns -50, unlocking it
	// returns -50, searches find nothing and the add returns -50. So the helper
	// only opens the keychain and this process, outside, shows it is unlocked.
	// The store's lock probe is refused at the get-status step, and every
	// operation reports unavailable with keychain-unusable instead of reading
	// the empty search as not-found, success or read-only.
	//
	// Each row stores an item outside, runs one operation inside, and branches
	// on what the probe measured there. If the probe says unusable, the
	// operation must report that, and a raw read that bypasses the store's gate
	// must fail too: a raw read that works while the probe says unusable means
	// the rule is wider than the sandbox and must narrow. If the probe says the
	// keychain is usable, the operation must behave normally.
	for _, op := range []string{actionLoad, actionSaveStatus, actionExists, actionDelete} {
		t.Run("codex sandbox: "+op, func(t *testing.T) {
			sb := codexSandbox(t)
			f.requireUnlocked(t)
			key, old, replacement := scratchKey(t), randomSecret(t), randomSecret(t)
			f.save(t, self, key, old)
			call := helperCall{
				bin:      self,
				action:   op,
				key:      key,
				secrets:  [][]byte{replacement},
				sandbox:  sb.prefix,
				dir:      sb.dir,
				openOnly: true,
			}
			r := f.start(t, call).finish(t)
			r.wantExit(t, 0)
			r.verifyBinary(t, self)
			wantCodexOutcome(t, f, self, sb, op, key, old, replacement, r)
		})
	}
}

// wantCodexOutcome checks one codex row against what the probe measured inside
// the sandbox, and logs one line per row so a run can be recorded.
func wantCodexOutcome(t *testing.T, f *fixture, self testBinary, sb codexPolicy, op string, key secretstore.Key, old, replacement []byte, r helperResult) {
	t.Helper()
	// Load reports its own fields; the others share error, status and reason.
	errField, statusField, reasonField := "error", "status", "reason"
	if op == actionLoad {
		statusField, reasonField = "load-status", "load-reason"
	}
	probeUnusable := r.get(t, "probe_unusable") == "true"
	addUnusable := r.get(t, "add_unusable") == "true"
	// Save starts with a read of its stage and then adds, so either probe stops it.
	unusable := probeUnusable || (op == actionSaveStatus && addUnusable)
	t.Logf("codex profile %s, write probe refused %t, operation %s: item probe %s status %s unusable %t, add-target probe %s status %s unusable %t, raw read %s status %s; result %s status %s reason %s",
		sb.profile, sb.writeRefused, op,
		r.get(t, "probe_step"), r.get(t, "probe_status"), probeUnusable,
		r.get(t, "add_step"), r.get(t, "add_status"), addUnusable,
		r.get(t, "raw_error"), r.get(t, "raw_status"),
		r.get(t, errField), r.get(t, statusField), r.get(t, reasonField))

	if !unusable {
		wantCodexUsable(t, f, self, op, key, old, replacement, r)
		return
	}
	if raw := r.get(t, "raw_error"); raw == "none" {
		if probeUnusable {
			t.Errorf("probe -50 with a working read: rule must narrow (raw read of the stored item succeeded while the probe said unusable)\n%s", r.describe())
		} else {
			// Only the add target is unusable while reads work: narrowing would
			// keep gating the add, so this is not evidence the read rule is wide.
			t.Errorf("add-target probe -50 with a working read: decide whether Save should still be gated\n%s", r.describe())
		}
	}
	r.want(t, errField, "unavailable")
	r.want(t, statusField, "-50")
	r.want(t, reasonField, string(secretstore.ReasonKeychainUnusable))
	if op == actionExists {
		r.want(t, "exists", "false")
	}
	if _, ok := r.fields["value"]; ok {
		t.Errorf("an unusable keychain still produced a value\n%s", r.describe())
	}
	// Nothing was stored, removed or replaced from inside.
	f.expectLoad(t, self, key, old)
}

// wantCodexUsable checks a row whose probe found the keychain usable: the
// operation behaves as it does outside a sandbox.
func wantCodexUsable(t *testing.T, f *fixture, self testBinary, op string, key secretstore.Key, old, replacement []byte, r helperResult) {
	t.Helper()
	// A usable keychain under a policy that denies keychain writes (measured:
	// a profile extending :workspace with extra filesystem rules) reads
	// normally while Save and Delete report read-only and change nothing.
	if (op == actionSaveStatus || op == actionDelete) && r.get(t, "error") == "read-only" {
		f.expectLoad(t, self, key, old)
		return
	}
	r.want(t, "error", "none")
	switch op {
	case actionLoad:
		r.want(t, "value", digestOf(old))
	case actionSaveStatus:
		f.expectLoad(t, self, key, replacement)
	case actionExists:
		r.want(t, "exists", "true")
	case actionDelete:
		l := f.invoke(t, helperCall{bin: self, action: actionLoad, key: key})
		l.want(t, "error", "not-found")
	}
}

// codexPolicy is the sandbox a codex row runs under.
type codexPolicy struct {
	// prefix is the command prefix that runs a helper under codex sandbox.
	prefix []string
	// dir is the helper's working directory, or empty to inherit.
	dir string
	// profile is the policy the row ran under, for the log line.
	profile string
	// writeRefused records whether the probe's file write was refused.
	writeRefused bool
}

// codexConfigProfile selects the user's real codex config in place of a
// built-in permission profile.
const codexConfigProfile = "config"

// codexSandbox returns the sandbox for SECRETSTORE_CODEX_PROFILE, or skips when
// SECRETSTORE_CODEX_SANDBOX is not set. The profile is :read-only by default,
// any other value starting with ":" is passed to -P, and "config" uses the
// user's real codex config: no CODEX_HOME override, no -P and no -C, with the
// helper's working directory a temporary one. "config:NAME" uses the real
// config with its named permission profile NAME (-P NAME, -C a temporary
// dir). The test writes nothing under the user's codex home; under "config" codex itself may update its own state
// there, as on any run.
//
// Before returning it runs a file write under the same prefix and records
// whether it was refused. Only under :read-only a write that succeeds fails the
// row, so the rows cannot pass under a policy that allows writes while claiming
// the read-only one.
func codexSandbox(t *testing.T) codexPolicy {
	t.Helper()
	codex := os.Getenv(codexSandboxEnv)
	if codex == "" {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			fmt.Printf("::notice title=keychain integration::the codex sandbox rows are local only; %s is not set\n", codexSandboxEnv)
		}
		t.Skipf("set %s to a codex binary to run this local row", codexSandboxEnv)
	}
	profile := os.Getenv(codexProfileEnv)
	if profile == "" {
		profile = codexReadOnlyProfile
	}
	policy := codexPolicy{profile: profile}
	switch {
	case profile == codexConfigProfile:
		policy.prefix = []string{codex, "sandbox", "--"}
		policy.dir = t.TempDir()
	case strings.HasPrefix(profile, codexConfigProfile+":") && len(profile) > len(codexConfigProfile)+1:
		// A named profile from the user's real codex config.
		policy.prefix = []string{codex, "sandbox", "-P", strings.TrimPrefix(profile, codexConfigProfile+":"), "-C", t.TempDir(), "--"}
		policy.dir = t.TempDir()
	case strings.HasPrefix(profile, ":"):
		policy.prefix = []string{"/usr/bin/env", "CODEX_HOME=" + t.TempDir(), codex, "sandbox", "-P", profile, "-C", t.TempDir(), "--"}
	default:
		t.Fatalf("%s = %q, want %q, a profile starting with %q, %q, or %q", codexProfileEnv, profile, codexReadOnlyProfile, ":", codexConfigProfile, codexConfigProfile+":NAME")
	}

	target := filepath.Join(t.TempDir(), "write-probe")
	ctx, cancel := context.WithTimeout(t.Context(), sandboxProbeTimeout)
	defer cancel()
	probe := append(slices.Clone(policy.prefix), "/usr/bin/touch", target)
	cmd := exec.CommandContext(ctx, probe[0], probe[1:]...)
	cmd.Dir = policy.dir
	out, err := cmd.CombinedOutput()
	policy.writeRefused = err != nil
	_, statErr := os.Stat(target)
	switch {
	case profile != codexReadOnlyProfile:
		// A broader policy may allow the write; it is recorded in the row's log.
	case err == nil:
		t.Fatalf("a file write under codex sandbox succeeded, so the policy is not read-only:\n%s", tail(out, 512))
	case !errors.Is(statErr, os.ErrNotExist):
		t.Fatalf("the write probe's file exists after a refused write: %v", statErr)
	case !strings.Contains(string(out), "Operation not permitted"):
		t.Fatalf("the write probe failed for another reason than the sandbox: %v\n%s", err, tail(out, 512))
	}
	return policy
}

// codexReadOnlyProfile is the default permission profile of the codex rows.
const codexReadOnlyProfile = ":read-only"

// codexProfileEnv names the permission profile the codex rows run under.
const codexProfileEnv = "SECRETSTORE_CODEX_PROFILE"

// codexSandboxEnv names the codex binary for the opt-in codex sandbox row.
const codexSandboxEnv = "SECRETSTORE_CODEX_SANDBOX"

// wantReadOnlySave checks a helper's Save that a sandbox refused: the helper
// exited cleanly, reported read-only, and outside the sandbox neither the key
// nor its stage item exists.
func wantReadOnlySave(t *testing.T, s *scratch, self testBinary, r helperResult, key secretstore.Key) {
	t.Helper()
	r.wantExit(t, 0)
	r.verifyBinary(t, self)
	t.Logf("Save under a denied write: kind %s, OSStatus %s", r.get(t, "error"), r.get(t, "status"))
	r.want(t, "error", "read-only")
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
}
