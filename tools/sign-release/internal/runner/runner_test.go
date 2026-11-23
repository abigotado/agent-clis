package runner

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

const helperEnv = "SIGN_RELEASE_RUNNER_HELPER"

// TestMain doubles as the child program: when helperEnv is set the test binary
// behaves as a tiny tool instead of running tests, so the real exec path is
// covered without gh, a shell or any other program.
func TestMain(m *testing.M) {
	mode := os.Getenv(helperEnv)
	if mode == "" && len(os.Args) > 1 && os.Args[1] == "--sign-release-helper-env" {
		mode = "env"
	}
	switch mode {
	case "":
		os.Exit(m.Run())
	case "echo":
		os.Stdout.WriteString(strings.Join(os.Args[1:], "|"))
		os.Stderr.WriteString("diagnostic")
		os.Exit(0)
	case "env":
		env := os.Environ()
		sort.Strings(env)
		os.Stdout.WriteString(strings.Join(env, "\n"))
		os.Exit(0)
	case "fail":
		os.Stdout.WriteString("partial")
		os.Exit(7)
	case "flood":
		buf := make([]byte, 1<<20)
		for range 8 {
			if _, err := os.Stdout.Write(buf); err != nil {
				os.Exit(0)
			}
		}
		os.Exit(0)
	}
	os.Exit(99)
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	return exe
}

func TestExecRun(t *testing.T) {
	exe := self(t)
	tests := []struct {
		name       string
		mode       string
		argv       []string
		max        int64
		wantStdout string
		wantStderr string
		wantCode   int
		wantTooBig bool
		wantErr    string
	}{
		{name: "passes each argv element verbatim with no shell", mode: "echo", argv: []string{exe, "a b", "$HOME", "x;y"}, max: 1 << 10, wantStdout: "a b|$HOME|x;y", wantStderr: "diagnostic"},
		{name: "non-zero exit carries the code and the output", mode: "fail", argv: []string{exe}, max: 1 << 10, wantStdout: "partial", wantCode: 7},
		{name: "stdout over the bound is refused", mode: "flood", argv: []string{exe}, max: 1 << 20, wantTooBig: true},
		{name: "a program that was not allowed is refused", mode: "echo", argv: []string{"/bin/echo", "x"}, max: 1 << 10, wantErr: "not allowed"},
		{name: "empty argv is refused", mode: "echo", argv: nil, max: 1 << 10, wantErr: "empty argv"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewExec(tc.max, []string{helperEnv + "=" + tc.mode}, exe)
			if err != nil {
				t.Fatalf("NewExec() error = %v", err)
			}
			stdout, stderr, err := e.Run(t.Context(), tc.argv, nil)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Run() error = %v, want it to contain %q", err, tc.wantErr)
				}
			case tc.wantTooBig:
				if !errors.Is(err, ErrOutputTooLarge) {
					t.Fatalf("Run() error = %v, want ErrOutputTooLarge", err)
				}
			case tc.wantCode != 0:
				var exit *ExitError
				if !errors.As(err, &exit) || exit.Code != tc.wantCode {
					t.Fatalf("Run() error = %v, want ExitError code %d", err, tc.wantCode)
				}
				if string(stdout) != tc.wantStdout {
					t.Fatalf("stdout = %q, want %q", stdout, tc.wantStdout)
				}
			default:
				if err != nil {
					t.Fatalf("Run() error = %v", err)
				}
				if string(stdout) != tc.wantStdout || string(stderr) != tc.wantStderr {
					t.Fatalf("stdout/stderr = %q/%q, want %q/%q", stdout, stderr, tc.wantStdout, tc.wantStderr)
				}
			}
		})
	}
}

func TestNewExecRefusals(t *testing.T) {
	exe := self(t)
	dir := t.TempDir()
	plain := dir + "/data"
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	tests := []struct {
		name     string
		max      int64
		programs []string
	}{
		{name: "relative path", max: 1, programs: []string{"gh"}},
		{name: "unclean path", max: 1, programs: []string{exe + "/../" + "x"}},
		{name: "missing file", max: 1, programs: []string{dir + "/absent"}},
		{name: "not executable", max: 1, programs: []string{plain}},
		{name: "directory", max: 1, programs: []string{dir}},
		{name: "no program", max: 1},
		{name: "non-positive bound", max: 0, programs: []string{exe}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewExec(tc.max, nil, tc.programs...); err == nil {
				t.Fatal("NewExec() error = nil, want a refusal")
			}
		})
	}
}

func TestMinimalEnv(t *testing.T) {
	tests := []struct {
		name   string
		parent []string
		home   string
		want   []string
	}{
		{name: "keeps what gh needs, sorted", home: "/acct",
			parent: []string{"PATH=/usr/bin", "USER=u", "TMPDIR=/t", "LANG=en_US.UTF-8", "LC_ALL=C", "LC_CTYPE=UTF-8"},
			want:   []string{"HOME=/acct", "LANG=en_US.UTF-8", "LC_ALL=C", "LC_CTYPE=UTF-8", "PATH=/usr/bin", "TMPDIR=/t", "USER=u"}},
		{name: "HOME is the account's, never the parent's", home: "/acct", parent: []string{"HOME=/evil", "HOME=/evil2"}, want: []string{"HOME=/acct"}},
		{name: "config location variables never reach gh", home: "/acct",
			parent: []string{"XDG_CONFIG_HOME=/x", "GH_CONFIG_DIR=/g", "PATH=/p"},
			want:   []string{"HOME=/acct", "PATH=/p"}},
		{name: "drops host, repo, token and output switches", home: "/h",
			parent: []string{"GH_HOST=evil.example", "GH_REPO=a/b", "GH_TOKEN=secret", "GITHUB_TOKEN=secret", "GH_ENTERPRISE_TOKEN=secret", "GITHUB_ENTERPRISE_TOKEN=secret", "GH_FORCE_TTY=1", "CLICOLOR_FORCE=1", "GH_DEBUG=api", "GH_PAGER=cat", "NO_COLOR=1", "HTTPS_PROXY=http://p", "SSH_AUTH_SOCK=/s", "GH_PROMPT_DISABLED=1"},
			want:   []string{"HOME=/h"}},
		{name: "does not match by prefix other than LC_", home: "/h", parent: []string{"HOMEX=1", "XPATH=1", "LANGUAGE=en", "LCX=1", "PATHEXT=1"}, want: []string{"HOME=/h"}},
		{name: "drops malformed entries", home: "/h", parent: []string{"HOME", "=x", "", "PATH=/p"}, want: []string{"HOME=/h", "PATH=/p"}},
		{name: "last duplicate wins", home: "/h", parent: []string{"PATH=/a", "PATH=/b"}, want: []string{"HOME=/h", "PATH=/b"}},
		{name: "empty value is kept", home: "/h", parent: []string{"LANG="}, want: []string{"HOME=/h", "LANG="}},
		{name: "nil parent", home: "/h", parent: nil, want: []string{"HOME=/h"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MinimalEnv(tc.parent, tc.home)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("MinimalEnv() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExecRunsWithExactlyTheGivenEnvironment(t *testing.T) {
	exe := self(t)
	t.Setenv("GH_TOKEN", "secret-from-parent")
	t.Setenv("GH_HOST", "evil.example")
	tests := []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{name: "given variables only", env: []string{helperEnv + "=env", "HOME=/h"}, want: "HOME=/h\n" + helperEnv + "=env"},
		{name: "a nil list is an empty environment, not the inherited one", env: nil, args: []string{"--sign-release-helper-env"}, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewExec(1<<10, tc.env, exe)
			if err != nil {
				t.Fatalf("NewExec() error = %v", err)
			}
			stdout, _, err := e.Run(t.Context(), append([]string{exe}, tc.args...), nil)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if string(stdout) != tc.want {
				t.Fatalf("child environment = %q, want %q (no GH_TOKEN or GH_HOST from the parent)", stdout, tc.want)
			}
		})
	}
}

// TestExecRunsTheResolvedProgram shows the program is fixed when the Exec is
// built: pointing the symbolic link elsewhere afterwards changes nothing.
func TestExecRunsTheResolvedProgram(t *testing.T) {
	exe := self(t)
	link := filepath.Join(t.TempDir(), "gh")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	e, err := NewExec(1<<10, []string{helperEnv + "=echo"}, link)
	if err != nil {
		t.Fatalf("NewExec() error = %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(link), "nowhere"), link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	stdout, _, err := e.Run(t.Context(), []string{link, "x"}, nil)
	if err != nil {
		t.Fatalf("Run() after the link moved error = %v, want the program resolved at construction", err)
	}
	if string(stdout) != "x" {
		t.Fatalf("stdout = %q, want %q", stdout, "x")
	}
}
