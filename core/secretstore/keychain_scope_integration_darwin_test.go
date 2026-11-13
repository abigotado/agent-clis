//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// scopeHelperEnv selects the action of the scope helper process.
const scopeHelperEnv = "SECRETSTORE_SCOPE_HELPER"

// The actions of the scope helper.
const (
	// scopeRead reports the switch and changes nothing.
	scopeRead = "read"
	// scopeHold turns the switch off, reports it, waits for a line, then
	// turns it on and reports that.
	scopeHold = "hold"
	// scopeRestore turns the switch on and reports it.
	scopeRestore = "restore"
)

// TestInteractionScopeHelper is the other half of TestInteractionFlagScope. It
// does nothing without the action variable.
func TestInteractionScopeHelper(t *testing.T) {
	action := os.Getenv(scopeHelperEnv)
	if action == "" {
		t.Skip("runs only as the helper process of TestInteractionFlagScope")
	}
	report := func(name, value string) {
		t.Helper()
		if _, err := os.Stdout.WriteString(helperResultPrefix + name + "=" + value + "\n"); err != nil {
			t.Fatalf("write the result %q: %v", name, err)
		}
	}
	read := func(name string) {
		t.Helper()
		allowed, err := kctest.InteractionAllowed()
		if err != nil {
			t.Fatalf("read the prompt setting: %v", err)
		}
		report(name, strconv.FormatBool(allowed))
	}

	switch action {
	case scopeRead:
		read("allowed")
	case scopeHold:
		read("before")
		if err := kctest.SetInteractionAllowed(false); err != nil {
			t.Fatalf("turn the prompts off: %v", err)
		}
		restored := false
		defer func() {
			// A failure between here and the restore below must not leave
			// this process's prompts off on its way out.
			if restored {
				return
			}
			if err := kctest.SetInteractionAllowed(true); err != nil {
				t.Errorf("turn the prompts on again after a failure: %v", err)
			}
		}()
		read("held")
		report("paused", "1")
		if line, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil || strings.TrimSpace(line) != helperGoLine {
			t.Fatalf("no go signal after the pause: %v", err)
		}
		if err := kctest.SetInteractionAllowed(true); err != nil {
			t.Fatalf("turn the prompts on again: %v", err)
		}
		restored = true
		read("restored")
	case scopeRestore:
		if err := kctest.SetInteractionAllowed(true); err != nil {
			t.Fatalf("turn the prompts on: %v", err)
		}
		read("allowed")
	default:
		t.Fatalf("unknown scope helper action %q", action)
	}
}

// scopeProcess starts the scope helper with action. The helper is this test
// binary, which carries no signature the scope depends on.
func scopeProcess(ctx context.Context, t *testing.T, action string) *helperProcess {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("find the running binary: %v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	call := helperCall{bin: testBinary{name: "scope helper " + action, path: exe}}
	cmd := helperCommand(ctx, call, []string{"-test.run=^TestInteractionScopeHelper$", "-test.count=1", "-test.timeout=2m"})
	cmd.Env = helperEnv(scopeHelperEnv + "=" + action)
	return launchHelper(t, call, cmd, cancel)
}

// scopeRun runs the scope helper to its end and returns what it reported.
func scopeRun(ctx context.Context, t *testing.T, action string) helperResult {
	t.Helper()
	r := scopeProcess(ctx, t, action).finish(t)
	r.wantExit(t, 0)
	return r
}

// t.Cleanup does not run on a test timeout panic or SIGINT, so a killed run can
// leave the prompt switch off in a helper; see the note in
// keychain_integration_darwin_test.go for what to do then.
//
// TestInteractionFlagScope measures the scope of the switch InteractionNever
// relies on, SecKeychainSetUserInteractionAllowed, as far as its getter shows it:
// whether turning it off in one process changes what another process reads back
// from SecKeychainGetUserInteractionAllowed. It does not show that a dialog still
// appears in the other process; it shows that the getter, which is all the test
// can read, is not affected.
//
// The backend calls it in Open under InteractionNever and its comment calls the
// setting process-wide and possibly session-wide. The package relies on the
// narrow reading: a program that opens a Store under InteractionNever turns the
// prompts off for itself, and an interactive program running next to it must not
// lose its dialogs. This test fails when another process's getter reads the
// wide value.
//
// It uses only fresh helper processes, so the process running the test never
// changes the switch. Process A turns it off, stays alive, and restores it.
// The cleanup restores the switch and checks it, in a process of its own, even
// when the test failed half-way, because a wider scope is exactly the case where
// a killed A would leave the whole session with its prompts off.
//
// The baseline is read by a fresh process first, and a fresh process that reads
// the switch as off is a failure: under the narrow reading nothing a finished
// helper did can reach it, so an off switch there is the wide reading, or a
// session that had it off before the test, and in either case the rest of the
// test could not tell the two readings apart. Earlier tests' helpers turn the
// switch off and exit without restoring it, which is harmless exactly when the
// narrow reading holds, and which this baseline would show if it did not.
//
// This test runs in the session of whoever starts it. On CI that is a headless
// session; whether the result is the same in a logged-in GUI session is a local
// run of this same test.
//
// The helper is this test binary, run with the action in scopeHelperEnv. It
// reports RESULT lines like the keychain helper does, and the paused one waits
// for a line on standard input.
//
// Run it with:
//
//	SECRETSTORE_REQUIRE_KEYCHAIN=1 go test -race -count=1 -v -tags keychainintegration \
//	  -run '^TestInteractionFlagScope$' ./secretstore
func TestInteractionFlagScope(t *testing.T) {
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

	// Registered before P0 and before A start, so it runs whatever happens to
	// either or to the assertions below, a failed baseline included: restore the
	// switch in a process of its own, then read it in another.
	t.Cleanup(func() {
		// The test's context is canceled before its cleanups run.
		ctx := context.WithoutCancel(t.Context())
		restored := scopeRun(ctx, t, scopeRestore)
		restored.want(t, "allowed", "true")
		if got := scopeRun(ctx, t, scopeRead).get(t, "allowed"); got != "true" {
			t.Errorf("after the test the prompt switch reads %q in a fresh process, want true: it was left off", got)
		}
	})

	// P0: what a fresh process reads before anything here has changed it. A fresh
	// process that reads it as off is the wide reading, or a session that had it
	// off already; either way the baseline is not the one the test needs.
	if got := scopeRun(t.Context(), t, scopeRead).get(t, "allowed"); got != "true" {
		t.Fatalf("a fresh process reads the prompt switch as %q before this test changed it, want true: "+
			"a process that never turned it off sees it off, so the switch is wider than one process (or the session had it off already)", got)
	}

	a := scopeProcess(t.Context(), t, scopeHold)
	a.waitFor(t, "paused")
	seen := helperResult{fields: a.fields}
	seen.want(t, "before", "true")
	seen.want(t, "held", "false")

	// While A has the switch off, a second, independent process reads it. This is
	// the getter in another process, not a dialog.
	b := scopeRun(t.Context(), t, scopeRead)
	if got := b.get(t, "allowed"); got != "true" {
		t.Errorf("process B reads the prompt switch as %q while process A has it off, want true: "+
			"the getter is affected across processes, so the backend's reading of the switch as process-local does not hold", got)
	}

	a.send(t, "go\n")
	r := a.finish(t)
	r.wantExit(t, 0)
	r.want(t, "restored", "true")

	// A restored it; a fresh process sees the baseline again.
	if got := scopeRun(t.Context(), t, scopeRead).get(t, "allowed"); got != "true" {
		t.Errorf("after A restored the switch a fresh process reads %q, want true", got)
	}
}
