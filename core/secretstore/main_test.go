package secretstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// helperEnv selects a scenario that must run in a fresh process, because it
// depends on or changes process-wide state (the interaction mode, rlimits).
const helperEnv = "SECRETSTORE_TEST_HELPER"

func TestMain(m *testing.M) {
	if name := os.Getenv(helperEnv); name != "" {
		os.Exit(runHelper(name))
	}
	os.Exit(m.Run())
}

// platformHelpers holds the scenarios that platform-specific test files add in
// an init function; they run in a fresh process like the ones below.
var platformHelpers = map[string]func() error{}

func runHelper(name string) int {
	var err error
	switch name {
	case "mode-conflict":
		err = helperModeConflict()
	case "failed-first-open":
		err = helperFailedFirstOpen()
	case "invalid-options-do-not-record":
		err = helperInvalidOptionsDoNotRecord()
	case "core-dumps":
		err = helperCoreDumps()
	case "isolated-bus-env":
		err = helperIsolatedBusEnv()
	default:
		if helper, ok := platformHelpers[name]; ok {
			err = helper()
		} else {
			err = fmt.Errorf("unknown helper %q", name)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("ok")
	return 0
}

// helperEnvironment is the environment of a helper process: the parent's, with
// the session bus hidden. A helper calls Open, which on Linux dials the session
// bus and probes the Secret Service, so a helper must never inherit the
// developer's bus: neither DBUS_SESSION_BUS_ADDRESS nor the
// $XDG_RUNTIME_DIR/bus socket Open falls back to. The overrides come last, so
// they win over the parent's values.
func helperEnvironment(t *testing.T, name string) []string {
	t.Helper()
	return append(os.Environ(),
		helperEnv+"="+name,
		"DBUS_SESSION_BUS_ADDRESS=",
		"XDG_RUNTIME_DIR="+t.TempDir(),
	)
}

// runHelperProcess re-executes the test binary for one scenario.
func runHelperProcess(t *testing.T, name string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0])
	cmd.Env = helperEnvironment(t, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %q failed: %v\n%s", name, err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "ok" {
		t.Fatalf("helper %q printed %q, want ok", name, got)
	}
}

// helperIsolatedBusEnv fails if the process can see a session bus: it asserts
// the environment runHelperProcess built.
func helperIsolatedBusEnv() error {
	if addr, ok := os.LookupEnv("DBUS_SESSION_BUS_ADDRESS"); !ok || addr != "" {
		return errors.New("DBUS_SESSION_BUS_ADDRESS is not set to the empty string")
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return errors.New("XDG_RUNTIME_DIR is empty, so it would not hide a bus socket")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read XDG_RUNTIME_DIR: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("XDG_RUNTIME_DIR holds %d entries, want an empty directory", len(entries))
	}
	return nil
}

func notInvalidArgument(step string, err error) error {
	if errors.Is(err, ErrInvalidArgument) {
		return fmt.Errorf("%s: unexpected invalid argument: %w", step, err)
	}
	return nil
}

func wantInvalidOpen(step string, err error) error {
	var se *Error
	if !errors.Is(err, ErrInvalidArgument) || !errors.As(err, &se) || se.Op != "open" || se.Kind != KindInvalidArgument {
		return fmt.Errorf("%s: got %v, want an open ErrInvalidArgument", step, err)
	}
	return nil
}

func helperModeConflict() error {
	ctx := context.Background()
	never := Options{MaxSecretBytes: 1024, Interaction: InteractionNever}
	allowed := Options{MaxSecretBytes: 1024, Interaction: InteractionAllowed}
	_, err := Open(ctx, never)
	if err := notInvalidArgument("first Open", err); err != nil {
		return err
	}
	_, err = Open(ctx, allowed)
	if err := wantInvalidOpen("conflicting Open", err); err != nil {
		return err
	}
	_, err = Open(ctx, never)
	return notInvalidArgument("repeated Open", err)
}

func helperFailedFirstOpen() error {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Open(canceled, Options{MaxSecretBytes: 1024, Interaction: InteractionNever})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalidArgument) {
		return fmt.Errorf("first Open with a canceled context: got %v, want context.Canceled", err)
	}
	_, err = Open(context.Background(), Options{MaxSecretBytes: 1024, Interaction: InteractionAllowed})
	return wantInvalidOpen("Open after a failed first Open", err)
}

func helperInvalidOptionsDoNotRecord() error {
	ctx := context.Background()
	_, err := Open(ctx, Options{MaxSecretBytes: 0, Interaction: InteractionAllowed})
	if err := wantInvalidOpen("zero bound", err); err != nil {
		return err
	}
	_, err = Open(ctx, Options{MaxSecretBytes: 10, Interaction: Interaction(99)})
	if err := wantInvalidOpen("unknown interaction", err); err != nil {
		return err
	}
	_, err = Open(ctx, Options{MaxSecretBytes: 10, Interaction: InteractionNever})
	return notInvalidArgument("valid Open after rejected options", err)
}

func helperCoreDumps() error {
	if err := DisableCoreDumps(); err != nil {
		return fmt.Errorf("DisableCoreDumps: %w", err)
	}
	cur, limit, supported, err := readCoreLimit()
	if err != nil {
		return fmt.Errorf("read core limit: %w", err)
	}
	if supported && (cur != 0 || limit != 0) {
		return fmt.Errorf("core limit soft=%d hard=%d, want 0/0", cur, limit)
	}
	return DisableCoreDumps()
}
