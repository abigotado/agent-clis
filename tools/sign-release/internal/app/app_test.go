package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/release"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

const (
	testGH      = "/opt/test/bin/gh"
	testCertSHA = "7b35c316aa0000000000000000000000000a8531"
	sentinel    = "ghp_SENTINEL_TOKEN_VALUE"
)

type recorder struct {
	calls [][]string
	err   error
}

func (r *recorder) Run(_ context.Context, argv []string, _ []byte) ([]byte, []byte, error) {
	r.calls = append(r.calls, slices.Clone(argv))
	return nil, nil, r.err
}

// harness counts every seam, so a test can show which ones a run reached.
type harness struct {
	t    *testing.T
	deps Deps
	out  *bytes.Buffer

	lookups, symlinks, runners, workdirs int
	gotEnv                               []string
	gotPrograms                          []string
	gotMax                               int64
	rec                                  *recorder
	lookPath                             string
	resolved                             string
	newRunnerErr                         error
	environ                              []string
}

func shippedConfig(t *testing.T, withCert bool) []byte {
	t.Helper()
	data, err := os.ReadFile("../../config.json")
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	if withCert {
		data = bytes.Replace(data, []byte(`"cert_sha1": ""`), []byte(`"cert_sha1": "`+testCertSHA+`"`), 1)
	}
	return data
}

func newHarness(t *testing.T, args ...string) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		out:      &bytes.Buffer{},
		rec:      &recorder{err: errors.New("stop here")},
		lookPath: "/usr/local/bin/gh",
		resolved: testGH,
		environ: []string{
			"PATH=/usr/bin", "HOME=/home/op", "LANG=en_US.UTF-8",
			"GH_TOKEN=" + sentinel, "GITHUB_TOKEN=" + sentinel, "GH_HOST=evil.example.com",
			"HTTPS_PROXY=http://proxy.invalid", "GH_REPO=evil/repo", "GH_CONFIG_DIR=/home/op/.config/gh",
		},
	}
	h.deps = Deps{
		ConfigJSON: shippedConfig(t, true),
		Args:       args,
		Environ:    func() []string { return h.environ },
		LookPath: func(file string) (string, error) {
			h.lookups++
			if file != "gh" {
				t.Errorf("LookPath(%q), want gh", file)
			}
			return h.lookPath, nil
		},
		EvalSymlinks: func(path string) (string, error) {
			h.symlinks++
			if path != h.lookPath {
				t.Errorf("EvalSymlinks(%q), want the LookPath result %q", path, h.lookPath)
			}
			return h.resolved, nil
		},
		NewRunner: func(maxStdout int64, env []string, programs ...string) (runner.Runner, error) {
			h.runners++
			h.gotMax, h.gotEnv, h.gotPrograms = maxStdout, slices.Clone(env), slices.Clone(programs)
			if h.newRunnerErr != nil {
				return nil, h.newRunnerErr
			}
			return h.rec, nil
		},
		MkWorkDir: func() (string, error) {
			h.workdirs++
			return os.MkdirTemp(t.TempDir(), "work") // 0700, as the real seam makes it
		},
		Stdin:  strings.NewReader(""),
		Stderr: h.out,
	}
	return h
}

func (h *harness) run() int { return Main(h.t.Context(), h.deps) }

func (h *harness) wantNoMachineAccess() {
	h.t.Helper()
	if h.lookups+h.symlinks+h.runners+h.workdirs != 0 || len(h.rec.calls) != 0 {
		h.t.Fatalf("lookups=%d symlinks=%d runners=%d workdirs=%d calls=%q, want none", h.lookups, h.symlinks, h.runners, h.workdirs, h.rec.calls)
	}
}

// TestMainBuildsTheRunnerFromMinimalEnv shows that the environment a program
// gets is runner.MinimalEnv of the parent's and never the parent's itself.
func TestMainBuildsTheRunnerFromMinimalEnv(t *testing.T) {
	h := newHarness(t, "youtrack-agent-cli", "0.13.0")
	if code := h.run(); code != ExitFailure {
		t.Fatalf("Main() = %d, want %d (the fake runner stops the run)", code, ExitFailure)
	}
	if want := runner.MinimalEnv(h.environ); !slices.Equal(h.gotEnv, want) {
		t.Fatalf("runner env = %q, want MinimalEnv of the parent = %q", h.gotEnv, want)
	}
	for _, kv := range h.gotEnv {
		for _, banned := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "HTTPS_PROXY", "GH_REPO", sentinel} {
			if strings.Contains(kv, banned) {
				t.Fatalf("runner env holds %q", kv)
			}
		}
	}
	if !slices.Contains(h.gotEnv, "GH_CONFIG_DIR=/home/op/.config/gh") {
		t.Fatalf("runner env %q lost the variable gh needs to find its login", h.gotEnv)
	}
	if strings.Contains(h.out.String(), sentinel) {
		t.Fatal("stderr holds a token")
	}
}

func TestMainBuildsTheRunnerForGHAndCodesignOnly(t *testing.T) {
	h := newHarness(t, "youtrack-agent-cli", "0.13.0")
	h.run()
	if want := []string{testGH, "/usr/bin/codesign"}; !slices.Equal(h.gotPrograms, want) {
		t.Fatalf("programs = %q, want %q", h.gotPrograms, want)
	}
	if h.gotMax < release.DefaultLimits().MaxArchive {
		t.Fatalf("stdout bound %d is under the archive bound %d", h.gotMax, release.DefaultLimits().MaxArchive)
	}
	if h.lookups != 1 || h.symlinks != 1 || h.runners != 1 || h.workdirs != 1 {
		t.Fatalf("lookups=%d symlinks=%d runners=%d workdirs=%d, want one each", h.lookups, h.symlinks, h.runners, h.workdirs)
	}
}

func TestMainStartsWithGHAuthStatus(t *testing.T) {
	h := newHarness(t, "youtrack-agent-cli", "0.13.0")
	h.run()
	want := []string{testGH, "auth", "status", "--hostname", "github.com"}
	if len(h.rec.calls) != 1 || !slices.Equal(h.rec.calls[0], want) {
		t.Fatalf("commands = %q, want exactly %q", h.rec.calls, want)
	}
}

// TestMainRefusesBeforeAnyCommand shows that nothing that finds gh, builds a
// runner, makes a directory or starts a program happens until the
// configuration parses and the expectation builds.
func TestMainRefusesBeforeAnyCommand(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		config func(t *testing.T) []byte
		want   string
	}{
		{"certificate hash empty", []string{"youtrack-agent-cli", "0.13.0"}, func(t *testing.T) []byte { return shippedConfig(t, false) }, "cert_sha1"},
		{"certificate hash malformed", []string{"youtrack-agent-cli", "0.13.0"}, func(t *testing.T) []byte {
			return bytes.Replace(shippedConfig(t, false), []byte(`"cert_sha1": ""`), []byte(`"cert_sha1": "xyz"`), 1)
		}, "cert_sha1"},
		{"unknown CLI", []string{"other-cli", "0.13.0"}, func(t *testing.T) []byte { return shippedConfig(t, true) }, "no CLI named"},
		{"config is not JSON", []string{"youtrack-agent-cli", "0.13.0"}, func(*testing.T) []byte { return []byte("{") }, "config"},
		{"config has an unknown field", []string{"youtrack-agent-cli", "0.13.0"}, func(t *testing.T) []byte {
			return bytes.Replace(shippedConfig(t, true), []byte(`"repository"`), []byte(`"extra": 1, "repository"`), 1)
		}, "config"},
		{"version with a leading v", []string{"youtrack-agent-cli", "v0.13.0"}, func(t *testing.T) []byte { return shippedConfig(t, true) }, "semantic version"},
		{"version not semantic", []string{"youtrack-agent-cli", "latest"}, func(t *testing.T) []byte { return shippedConfig(t, true) }, "semantic version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.args...)
			h.deps.ConfigJSON = tt.config(t)
			if code := h.run(); code != ExitFailure {
				t.Fatalf("Main() = %d, want %d", code, ExitFailure)
			}
			h.wantNoMachineAccess()
			if !strings.Contains(h.out.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to contain %q", h.out.String(), tt.want)
			}
		})
	}
}

func TestMainUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"youtrack-agent-cli"}, {"youtrack-agent-cli", "0.13.0", "extra"}} {
		h := newHarness(t, args...)
		if code := h.run(); code != ExitUsage {
			t.Fatalf("Main(%q) = %d, want %d", args, code, ExitUsage)
		}
		if !strings.Contains(h.out.String(), "usage: sign-release <cli> <version>") {
			t.Fatalf("stderr = %q, want the usage text", h.out.String())
		}
		h.wantNoMachineAccess()
	}
}

func TestMainRefusesAnUnsafeGH(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(h *harness)
		want   string
	}{
		{"relative LookPath result", func(h *harness) { h.lookPath = "./gh" }, "not an absolute path"},
		{"relative resolved path", func(h *harness) { h.resolved = "bin/gh" }, "clean absolute path"},
		{"unclean resolved path", func(h *harness) { h.resolved = "/opt/test/../bin/gh" }, "clean absolute path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, "youtrack-agent-cli", "0.13.0")
			tt.mutate(h)
			if code := h.run(); code != ExitFailure {
				t.Fatalf("Main() = %d, want %d", code, ExitFailure)
			}
			if h.runners != 0 || h.workdirs != 0 || len(h.rec.calls) != 0 {
				t.Fatalf("runners=%d workdirs=%d calls=%q, want none", h.runners, h.workdirs, h.rec.calls)
			}
			if !strings.Contains(h.out.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to contain %q", h.out.String(), tt.want)
			}
		})
	}
}

func TestMainReportsRunnerFailureBeforeTheWorkDirectory(t *testing.T) {
	h := newHarness(t, "youtrack-agent-cli", "0.13.0")
	h.newRunnerErr = errors.New("program not executable")
	if code := h.run(); code != ExitFailure {
		t.Fatalf("Main() = %d, want %d", code, ExitFailure)
	}
	if h.workdirs != 0 {
		t.Fatalf("a work directory was made after the runner failed")
	}
}

func TestMainMapsAPanicToTheFailureExit(t *testing.T) {
	h := newHarness(t, "youtrack-agent-cli", "0.13.0")
	h.deps.NewRunner = func(int64, []string, ...string) (runner.Runner, error) { panic("boom") }
	if code := h.run(); code != ExitFailure {
		t.Fatalf("Main() = %d, want %d, not the exit 2 of a Go panic", code, ExitFailure)
	}
}

func TestMainRequiresEveryDependency(t *testing.T) {
	h := newHarness(t, "youtrack-agent-cli", "0.13.0")
	h.deps.Environ = nil
	if code := h.run(); code != ExitFailure {
		t.Fatalf("Main() = %d, want %d", code, ExitFailure)
	}
	h.wantNoMachineAccess()
}
