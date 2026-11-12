//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// TestKeychainAcrossBinaries runs the keychain backend as several different
// programs against one scratch keychain: a rebuild of the program that wrote an
// item, at a new path, and programs with another identity. What the backend
// promises about access depends on which program asks, and one process cannot be
// two programs. See keychain_signing_integration_darwin_test.go for how the
// binaries are made and TestKeychainHelper for what each one does.
//
// Like TestKeychainScratch it never touches the login keychain, and it restores
// the process-wide prompt setting. Every helper process turns prompts off before
// its first keychain call.
//
// Run it with:
//
//	SECRETSTORE_REQUIRE_KEYCHAIN=1 go test -race -count=1 -v -tags keychainintegration \
//	  -run '^TestKeychainAcrossBinaries$' ./secretstore
func TestKeychainAcrossBinaries(t *testing.T) {
	s := newScratch(t)
	config, err := kctest.Snapshot()
	if err != nil {
		t.Fatalf("read the keychain configuration: %v", err)
	}
	// Registered after newScratch, so it runs first and the scratch fixture's own
	// check of the configuration, which runs last, sees the final state.
	t.Cleanup(func() {
		after, err := kctest.Snapshot()
		if err != nil {
			t.Errorf("read the keychain configuration after the test: %v", err)
			return
		}
		if !config.Equal(after) {
			t.Errorf("the user's keychain configuration changed: before %s, after %s", config, after)
		}
	})

	f := &fixture{scratch: s, binaries: newBinarySet(t, config)}

	t.Run("a rebuild at a new path loads what the original saved", func(t *testing.T) {
		key, secret := scratchKey(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, secret)
		f.expectLoad(t, f.binaries.a2, key, secret)
		f.expectLoad(t, f.binaries.a1, key, secret)
	})

	for _, foreign := range []struct {
		name string
		pick func(binarySet) testBinary
	}{
		// With no second certificate B differs by identifier, which is still
		// another identity.
		{"a program with another identity is denied", func(b binarySet) testBinary { return b.b }},
		{"an ad hoc program is denied", func(b binarySet) testBinary { return b.adhoc }},
	} {
		t.Run(foreign.name, func(t *testing.T) {
			key, secret := scratchKey(t), randomSecret(t)
			f.save(t, f.binaries.a1, key, secret)
			bin := foreign.pick(f.binaries)
			r := f.invoke(t, helperCall{bin: bin, action: actionLoad, key: key})
			r.want(t, "error", "access-denied")
			r.want(t, "unlocked", "true")
			// The refusal changed nothing.
			f.expectLoad(t, f.binaries.a1, key, secret)
			f.requireUnlocked(t)
		})
	}

	t.Run("a different certificate with the same identifier is denied", func(t *testing.T) {
		if !f.binaries.certificates {
			// The documented gap of the ad hoc fallback, announced when the binaries
			// are signed; it does not fail under SECRETSTORE_REQUIRE_KEYCHAIN.
			t.Skipf("not run: %s", f.binaries.method)
		}
		key, secret := scratchKey(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, secret)
		r := f.invoke(t, helperCall{bin: f.binaries.b, action: actionLoad, key: key})
		r.want(t, "error", "access-denied")
		r.want(t, "unlocked", "true")
		f.expectLoad(t, f.binaries.a1, key, secret)
	})

	t.Run("two saves by a rebuild leave no stage for the original", func(t *testing.T) {
		key, first, second, third := scratchKey(t), randomSecret(t), randomSecret(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, first)
		r := f.invoke(t, helperCall{bin: f.binaries.a2, action: actionSaveTwice, key: key, secrets: [][]byte{second, third}})
		r.want(t, "save1", "none")
		r.want(t, "save2", "none")
		r.want(t, "stage", "absent")
		f.expectLoad(t, f.binaries.a1, key, third)
	})

	for _, step := range []int{1, 2, 3} {
		t.Run("a crash after step "+strconv.Itoa(step), func(t *testing.T) {
			key, old, newest, next := scratchKey(t), randomSecret(t), randomSecret(t), randomSecret(t)
			f.save(t, f.binaries.a1, key, old)

			call := helperCall{bin: f.binaries.a2, action: actionCrash, key: key, secrets: [][]byte{newest}, step: step}
			crashed := f.start(t, call).finish(t)
			crashed.verifyBinary(t, call.bin)
			if crashed.exit != helperCrashExit {
				t.Fatalf("the helper exited with %d, want the crash status %d (it did not stop after step %d)\n%s",
					crashed.exit, helperCrashExit, step, crashed.describe())
			}
			crashed.want(t, "crashing", strconv.Itoa(step))

			// The stage holds the newest value in every window, and so Load, which
			// reads it first, returns it.
			r := f.invoke(t, helperCall{bin: f.binaries.a1, action: actionLoad, key: key})
			r.want(t, "error", "none")
			r.want(t, "value", digestOf(newest))
			r.want(t, "stage", "present")

			// The next Save rolls the stage forward and leaves none.
			f.save(t, f.binaries.a1, key, next)
			f.expectLoad(t, f.binaries.a2, key, next)
		})
	}

	t.Run("a writer that recreates the account item makes Save contended", func(t *testing.T) {
		key, old, mine, intruder := scratchKey(t), randomSecret(t), randomSecret(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, old)

		saver := f.start(t, helperCall{bin: f.binaries.a1, action: actionContend, key: key, secrets: [][]byte{mine}})
		saver.waitFor(t, "paused")
		// The saver has deleted the account item and holds the new value in the
		// stage. Another identity takes the free name.
		add := f.invoke(t, helperCall{bin: f.binaries.b, action: actionAddAccount, key: key, secrets: [][]byte{intruder}})
		add.want(t, "error", "none")
		saver.send(t, helperGoLine+"\n")

		r := saver.finish(t)
		r.wantExit(t, 0)
		r.verifyBinary(t, f.binaries.a1)
		r.want(t, "error", "contended")
		r.want(t, "stage", "present")
		r.want(t, "load_error", "none")
		r.want(t, "value", digestOf(mine))
		r.want(t, "unlocked", "true")
	})

	t.Run("a stage written by another identity is ignored by Load and deleted by Save", func(t *testing.T) {
		key, first, foreign, second := scratchKey(t), randomSecret(t), randomSecret(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, first)
		add := f.invoke(t, helperCall{bin: f.binaries.b, action: actionAddStage, key: key, secrets: [][]byte{foreign}})
		add.want(t, "error", "none")

		r := f.invoke(t, helperCall{bin: f.binaries.a1, action: actionLoad, key: key})
		r.want(t, "error", "none")
		r.want(t, "value", digestOf(first))
		r.want(t, "stage", "present") // it is there, and Load did not take it.

		save := f.invoke(t, helperCall{bin: f.binaries.a1, action: actionSave, key: key, secrets: [][]byte{second}})
		save.want(t, "error", "none")
		save.want(t, "stage", "absent") // Save deleted the stage it could not read.
		f.expectLoad(t, f.binaries.a1, key, second)
	})

	t.Run("RepairAccess is refused under never and leaves the item alone", func(t *testing.T) {
		key, secret := scratchKey(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, secret)
		r := f.invoke(t, helperCall{bin: f.binaries.a2, action: actionRepairNever, key: key})
		r.want(t, "error", "interaction-required")
		r.want(t, "load_error", "none")
		r.want(t, "value", digestOf(secret))
		r.want(t, "stage", "absent")
	})

	t.Run("RepairAccess rewrites an item a rebuild can read to its own access list", func(t *testing.T) {
		key, secret := scratchKey(t), randomSecret(t)
		f.save(t, f.binaries.a1, key, secret)
		r := f.invoke(t, helperCall{bin: f.binaries.a2, action: actionRepair, key: key})
		r.want(t, "error", "none")
		r.want(t, "load_error", "none")
		r.want(t, "value", digestOf(secret))
		r.want(t, "stage", "absent")
		// The helper dumped the list and checked it against rule 1 for the
		// rebuild, whose path the item did not name before.
		r.want(t, "acl", "rule1")
		t.Logf("trusted-application count of the rebuild before the repair: %s", r.get(t, "acl_before_self"))
		f.expectLoad(t, f.binaries.a1, key, secret)
	})

	t.Run("prompts stayed off and the keychain stayed unlocked", func(t *testing.T) {
		allowed, err := kctest.InteractionAllowed()
		if err != nil || allowed {
			t.Fatalf("prompt setting = %t, error %v, want off for the whole run", allowed, err)
		}
		f.requireUnlocked(t)
	})
}

// fixture is what every row shares.
type fixture struct {
	scratch  *scratch
	binaries binarySet
}

// requireUnlocked fails unless the scratch keychain is unlocked, which every
// "denied" row needs: a locked keychain refuses everybody.
func (f *fixture) requireUnlocked(t *testing.T) {
	t.Helper()
	if unlocked, err := f.scratch.kc.Unlocked(); err != nil || !unlocked {
		t.Fatalf("scratch keychain unlocked = %t, status error %v, want unlocked: a refusal would not mean what the row says", unlocked, err)
	}
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return []byte("secret-" + hex.EncodeToString(b))
}

// helperCall is one helper run.
type helperCall struct {
	bin     testBinary
	action  string
	key     secretstore.Key
	secrets [][]byte
	// step is the step a crash helper stops after.
	step int
}

// save has bin save secret under key and requires it to succeed.
func (f *fixture) save(t *testing.T, bin testBinary, key secretstore.Key, secret []byte) {
	t.Helper()
	r := f.invoke(t, helperCall{bin: bin, action: actionSave, key: key, secrets: [][]byte{secret}})
	r.want(t, "error", "none")
	r.want(t, "stage", "absent")
}

// expectLoad has bin load key and requires the value, with no stage left.
func (f *fixture) expectLoad(t *testing.T, bin testBinary, key secretstore.Key, secret []byte) {
	t.Helper()
	r := f.invoke(t, helperCall{bin: bin, action: actionLoad, key: key})
	r.want(t, "error", "none")
	r.want(t, "value", digestOf(secret))
	r.want(t, "stage", "absent")
}

// invoke runs a helper to its end and requires a clean exit from the binary the
// call named.
func (f *fixture) invoke(t *testing.T, call helperCall) helperResult {
	t.Helper()
	r := f.start(t, call).finish(t)
	r.wantExit(t, 0)
	r.verifyBinary(t, call.bin)
	return r
}

// helperProcess is a running helper.
type helperProcess struct {
	call   helperCall
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	stderr *bytes.Buffer
	cancel context.CancelFunc
	fields map[string]string
	other  []string
	done   bool
}

const helperTimeout = 3 * time.Minute

func (f *fixture) start(t *testing.T, call helperCall) *helperProcess {
	t.Helper()
	input, err := json.Marshal(helperInput{Password: f.scratch.kc.Password(), Secrets: call.secrets})
	if err != nil {
		t.Fatalf("encode the helper input: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), helperTimeout)
	cmd := exec.CommandContext(ctx, call.bin.path, "-test.run=^TestKeychainHelper$", "-test.count=1", "-test.timeout=2m")
	cmd.Env = append(os.Environ(),
		helperActionEnv+"="+call.action,
		helperKeychainEnv+"="+f.scratch.kc.Path(),
		helperServiceEnv+"="+call.key.Service,
		helperAccountEnv+"="+call.key.Account,
		helperStepEnv+"="+strconv.Itoa(call.step),
	)
	cmd.WaitDelay = 10 * time.Second
	p := &helperProcess{call: call, cmd: cmd, lines: make(chan string, 1024), stderr: new(bytes.Buffer), cancel: cancel, fields: map[string]string{}}
	cmd.Stderr = p.stderr
	if p.stdin, err = cmd.StdinPipe(); err != nil {
		cancel()
		t.Fatalf("open the helper's standard input: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("open the helper's standard output: %v", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start %s: %v", call.bin.name, err)
	}
	t.Cleanup(p.abort)
	go func() {
		defer close(p.lines)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			p.lines <- scanner.Text()
		}
		// A read error ends the stream like EOF does: the process is gone or the
		// pipe closed, and finish reports what it got.
	}()

	if _, err := p.stdin.Write(append(input, '\n')); err != nil {
		t.Fatalf("write the helper input: %v", err)
	}
	return p
}

// abort stops a helper that is still running and reaps it. It is the cleanup of
// every helper, so a failing row cannot leave a paused process behind.
func (p *helperProcess) abort() {
	if p.done {
		return
	}
	p.done = true
	p.cancel()
	for range p.lines {
		// Drain so the reader goroutine can finish.
	}
	// The result of a killed process says nothing; the row has already failed.
	_ = p.cmd.Wait()
}

// take records one line of standard output.
func (p *helperProcess) take(line string) string {
	rest, isResult := strings.CutPrefix(line, helperResultPrefix)
	name, value, hasValue := strings.Cut(rest, "=")
	if !isResult || !hasValue {
		if len(p.other) < 40 {
			p.other = append(p.other, line)
		}
		return ""
	}
	p.fields[name] = value
	return name
}

// waitFor reads the helper's output until the named result arrives.
func (p *helperProcess) waitFor(t *testing.T, name string) {
	t.Helper()
	for line := range p.lines {
		if p.take(line) == name {
			return
		}
	}
	p.abort()
	t.Fatalf("the helper ended before it reported %q\n%s", name, p.describe())
}

func (p *helperProcess) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(p.stdin, line); err != nil {
		t.Fatalf("write to the helper: %v", err)
	}
}

// helperResult is what a finished helper reported.
type helperResult struct {
	fields map[string]string
	exit   int
	other  []string
	stderr string
}

// finish closes the helper's input, reads the rest of its output and waits for
// it to exit.
func (p *helperProcess) finish(t *testing.T) helperResult {
	t.Helper()
	if err := p.stdin.Close(); err != nil {
		t.Logf("close the helper's standard input: %v", err)
	}
	for line := range p.lines {
		p.take(line)
	}
	err := p.cmd.Wait()
	p.done = true
	p.cancel()
	exit := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exit = exitErr.ExitCode()
	default:
		t.Fatalf("wait for the helper: %v", err)
	}
	return helperResult{fields: p.fields, exit: exit, other: p.other, stderr: tail(p.stderr.Bytes(), 2048)}
}

func (p *helperProcess) describe() string {
	return helperResult{fields: p.fields, other: p.other, stderr: tail(p.stderr.Bytes(), 2048)}.describe()
}

// describe lists everything a failed helper said. None of it is secret: results
// are tokens and digests, and the rest is the test binary's own output.
func (r helperResult) describe() string {
	var b strings.Builder
	for name, value := range r.fields {
		fmt.Fprintf(&b, "  %s=%s\n", name, value)
	}
	for _, line := range r.other {
		fmt.Fprintf(&b, "  output: %s\n", line)
	}
	if r.stderr != "" {
		fmt.Fprintf(&b, "  stderr: %s\n", r.stderr)
	}
	return b.String()
}

func (r helperResult) get(t *testing.T, name string) string {
	t.Helper()
	value, ok := r.fields[name]
	if !ok {
		t.Fatalf("the helper did not report %q\n%s", name, r.describe())
	}
	return value
}

func (r helperResult) want(t *testing.T, name, want string) {
	t.Helper()
	if got := r.get(t, name); got != want {
		t.Errorf("helper reported %s = %q, want %q\n%s", name, got, want, r.describe())
	}
}

func (r helperResult) wantExit(t *testing.T, want int) {
	t.Helper()
	if r.exit != want {
		t.Fatalf("the helper exited with %d, want %d\n%s", r.exit, want, r.describe())
	}
}

// verifyBinary checks that the process that answered is the binary the row
// meant to run, built with the marker it was meant to have, with prompts off.
func (r helperResult) verifyBinary(t *testing.T, bin testBinary) {
	t.Helper()
	r.want(t, "interaction", "off")
	r.want(t, "marker", bin.marker)
	got, err := filepath.EvalSymlinks(r.get(t, "binary"))
	if err != nil {
		t.Fatalf("resolve the helper's binary path: %v", err)
	}
	want, err := filepath.EvalSymlinks(bin.path)
	if err != nil {
		t.Fatalf("resolve %s: %v", bin.name, err)
	}
	if got != want {
		t.Errorf("ran %s, want %s (%s)", got, want, bin.name)
	}
}
