//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// t.Cleanup does not run on a test timeout panic or SIGINT, so a killed run can
// leave a scratch keychain file in TMPDIR and the process's prompt switch off;
// see the note in keychain_integration_darwin_test.go for what to do then.

const (
	injectHelperEnv = "SECRETSTORE_INJECT_HELPER"
	injectMarkerEnv = "SECRETSTORE_INJECT_MARKER"
	injectSource    = "testdata/inject/inject.c"
	xcrunPath       = "/usr/bin/xcrun"
)

// TestInjectionHelper is the program TestHardenedRuntimeRefusesInjection runs.
// It does nothing without the helper variable. It reports whether the dynamic
// loader left DYLD_INSERT_LIBRARIES in its environment, which is only
// information: the test judges by the marker the injected library writes.
func TestInjectionHelper(t *testing.T) {
	if os.Getenv(injectHelperEnv) == "" {
		t.Skip("runs only as the helper process of TestHardenedRuntimeRefusesInjection")
	}
	dyld := "unset"
	if _, ok := os.LookupEnv("DYLD_INSERT_LIBRARIES"); ok {
		dyld = "set"
	}
	for _, line := range []string{helperResultPrefix + "ran=1\n", helperResultPrefix + "dyld_env=" + dyld + "\n"} {
		if _, err := os.Stdout.WriteString(line); err != nil {
			t.Fatalf("write a result: %v", err)
		}
	}
}

// buildInjectLibrary compiles testdata/inject/inject.c into a dylib in a temp
// directory and returns its path. The compiler is the Xcode one; without it the
// environment cannot run the row, which CI treats as a failure.
func buildInjectLibrary(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(xcrunPath); err != nil {
		unusable(t, "finding xcrun to build the injected library", err)
	}
	source, err := filepath.Abs(injectSource)
	if err != nil {
		t.Fatalf("resolve %s: %v", injectSource, err)
	}
	arch := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[runtime.GOARCH]
	if arch == "" {
		unusable(t, "choosing a compiler architecture", errors.New("unsupported GOARCH "+runtime.GOARCH))
	}
	out := filepath.Join(t.TempDir(), "inject.dylib")
	ctx, cancel := context.WithTimeout(t.Context(), helperBuildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, xcrunPath, "clang", "-dynamiclib", "-arch", arch, "-o", out, source)
	cmd.Env = helperEnv()
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		unusable(t, "compiling the injected library with xcrun clang", fmt.Errorf("%w\n%s", err, tail(output.Bytes(), 2048)))
	}
	// The linker signs a dylib ad hoc on arm64 already; this makes it explicit
	// and the same on every architecture, so an unsigned library is never the
	// reason the control does not load it.
	if err := codesign(t.Context(), "--force", "--sign", "-", out); err != nil {
		unusable(t, "signing the injected library", err)
	}
	return out
}

// runInjected runs bin with the injected library in DYLD_INSERT_LIBRARIES and
// reports whether the library's constructor ran, by its marker file.
func runInjected(t *testing.T, bin testBinary, dylib string) (loaded bool, r helperResult) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "marker")
	ctx, cancel := context.WithTimeout(t.Context(), helperTimeout)
	call := helperCall{bin: bin}
	cmd := helperCommand(ctx, call, []string{"-test.run=^TestInjectionHelper$", "-test.count=1", "-test.timeout=2m"})
	cmd.Env = helperEnv(
		injectHelperEnv+"=1",
		injectMarkerEnv+"="+marker,
		"DYLD_INSERT_LIBRARIES="+dylib,
	)
	r = launchHelper(t, call, cmd, cancel).finish(t)
	r.wantExit(t, 0)
	r.want(t, "ran", "1")

	data, err := os.ReadFile(marker)
	switch {
	case err == nil:
		if string(data) != "loaded\n" {
			t.Errorf("the marker of %s holds %q, want the constructor's word", bin.name, data)
		}
		return true, r
	case errors.Is(err, fs.ErrNotExist):
		return false, r
	default:
		t.Fatalf("read the marker of %s: %v", bin.name, err)
		return false, r
	}
}

// TestHardenedRuntimeRefusesInjection shows that a helper signed with the
// hardened runtime flag, the way a released binary is, does not load a library
// named in DYLD_INSERT_LIBRARIES, and that the same library does load into a
// helper without the flag. That control is what keeps the refusal from being a
// result of a broken library, a wrong architecture or a loader that never
// honoured the variable in this environment.
//
// The ad hoc control differs from A1 in more than the flag: the signature kind
// and the designated requirement too. A second control pins the refusal on the
// flag alone: a copy of the same ad hoc binary, signed ad hoc again with the
// runtime flag and nothing else changed, must not load the library either.
//
// The helpers are the signed binaries of TestKeychainAcrossBinaries: A1 carries
// the flag, the ad hoc one does not. Building and signing them takes as long as
// it does there.
//
// Run it with:
//
//	SECRETSTORE_REQUIRE_KEYCHAIN=1 go test -race -count=1 -v -tags keychainintegration \
//	  -run '^TestHardenedRuntimeRefusesInjection$' -timeout 20m ./secretstore
func TestHardenedRuntimeRefusesInjection(t *testing.T) {
	config, err := kctest.Snapshot()
	if err != nil {
		unusable(t, "reading the keychain search list", err)
	}
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
	// Signing creates a signing keychain; nothing here may show a dialog.
	promptsOff(t)

	dylib := buildInjectLibrary(t)
	set := newBinarySet(t, config)
	hardened, control := set.a1, set.adhoc

	// The two helpers differ in the one property under test.
	hardenedSig, err := kctest.CodeSignature(hardened.path)
	if err != nil {
		t.Fatalf("read the signature of the hardened helper: %v", err)
	}
	if !hardenedSig.Runtime() {
		t.Fatalf("the hardened helper is signed without the runtime flag (flags 0x%x), so the row would test nothing", hardenedSig.Flags)
	}
	controlSig, err := kctest.CodeSignature(control.path)
	if err != nil {
		t.Fatalf("read the signature of the control helper: %v", err)
	}
	if controlSig.Runtime() {
		t.Fatalf("the control helper is signed with the runtime flag (flags 0x%x), so it cannot show the library loads", controlSig.Flags)
	}

	loaded, r := runInjected(t, control, dylib)
	t.Logf("control, no runtime flag: library loaded %t, DYLD_INSERT_LIBRARIES in its environment: %s", loaded, r.fields["dyld_env"])
	if !loaded {
		t.Fatalf("the control helper without the runtime flag did not load the library, so a refusal by the hardened helper proves nothing\n%s", r.describe())
	}

	// The same ad hoc binary with the flag added: the flag is the only difference
	// from the control that loads the library.
	flagged := testBinary{name: "ad hoc with the runtime flag", path: filepath.Join(t.TempDir(), "adhoc-runtime", "secretstore.test")}
	copyExecutable(t, control.path, flagged.path)
	if err := codesign(t.Context(), "--force", "--sign", "-", "--options", "runtime", flagged.path); err != nil {
		unusable(t, "signing the ad hoc copy with the runtime flag", err)
	}
	flaggedSig, err := kctest.CodeSignature(flagged.path)
	if err != nil {
		t.Fatalf("read the signature of the ad hoc copy with the runtime flag: %v", err)
	}
	if !flaggedSig.AdHoc() || !flaggedSig.Runtime() {
		t.Fatalf("the ad hoc copy is not signed ad hoc with the runtime flag (flags 0x%x), so it cannot pin the refusal on the flag", flaggedSig.Flags)
	}
	loaded, r = runInjected(t, flagged, dylib)
	t.Logf("ad hoc with the runtime flag: library loaded %t, DYLD_INSERT_LIBRARIES in its environment: %s", loaded, r.fields["dyld_env"])
	if loaded {
		t.Errorf("the ad hoc helper with only the runtime flag added loaded a library from DYLD_INSERT_LIBRARIES\n%s", r.describe())
	}

	loaded, r = runInjected(t, hardened, dylib)
	t.Logf("hardened runtime: library loaded %t, DYLD_INSERT_LIBRARIES in its environment: %s", loaded, r.fields["dyld_env"])
	if loaded {
		t.Errorf("the helper signed with the hardened runtime loaded a library from DYLD_INSERT_LIBRARIES\n%s", r.describe())
	}
}
