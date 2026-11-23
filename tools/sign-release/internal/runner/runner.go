// Package runner is the one seam through which sign-release starts external
// programs. Every command is an argv slice with no shell, so tests substitute a
// recording fake and no test ever runs gh or codesign.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Runner starts one program and returns what it printed. A program that ran and
// exited non-zero returns an *ExitError together with its captured output.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin []byte) (stdout, stderr []byte, err error)
}

// ExitError reports a program that exited with a non-zero status.
type ExitError struct {
	Program string
	Code    int
}

// Error names the program and the status. It never repeats the program's
// output, which can carry text the operator did not mean to log.
func (e *ExitError) Error() string {
	return fmt.Sprintf("%s exited with status %d", e.Program, e.Code)
}

// ErrOutputTooLarge reports a program whose stdout exceeded the capture bound.
var ErrOutputTooLarge = errors.New("program output exceeds the capture limit")

// MaxStderr bounds the stderr kept for a program; the rest is dropped.
const MaxStderr = 64 << 10

const waitDelay = 10 * time.Second

// envKeep is the set of variable names MinimalEnv copies; names starting with
// LC_ are kept as well.
var envKeep = []string{"PATH", "TMPDIR", "USER", "LANG"}

// MinimalEnv builds the environment a gh run gets from the parent's: PATH,
// TMPDIR, USER, LANG and the LC_ variables, plus HOME set to home. home is the
// account's home directory from the account database, never the parent's HOME,
// and it is the only place gh looks for its login: GH_CONFIG_DIR and
// XDG_CONFIG_HOME are dropped with everything else, so the environment cannot
// point gh at another configuration. GH_HOST, GH_REPO, GH_TOKEN, GITHUB_TOKEN,
// the enterprise tokens, GH_DEBUG, GH_PAGER and the colour switches are
// dropped too, so they cannot redirect a call, override the operator's stored
// login or change the output. Malformed entries are dropped; for a repeated
// name the last value wins, as for a process. The result is sorted by name.
func MinimalEnv(parent []string, home string) []string {
	kept := map[string]string{"HOME": home}
	for _, kv := range parent {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if slices.Contains(envKeep, name) || strings.HasPrefix(name, "LC_") {
			kept[name] = value
		}
	}
	out := make([]string, 0, len(kept))
	for name, value := range kept {
		out = append(out, name+"="+value)
	}
	slices.Sort(out)
	return out
}

// Exec runs programs by absolute path with no shell. Only the programs named
// when it was built can run, so a downloaded or extracted file can never be
// started through it. Each runs from the path its symbolic links resolved to
// at construction, so a later change to a link does not change what runs.
type Exec struct {
	programs  map[string]string // requested path to resolved path
	env       []string
	maxStdout int64
}

// NewExec returns an Exec that may start exactly the given programs, with env
// as the environment of every run (use MinimalEnv). Each program must be a
// clean absolute path to an existing executable regular file once its symbolic
// links are resolved; the caller finds gh and passes it in. maxStdout bounds
// the captured stdout of every run.
func NewExec(maxStdout int64, env []string, programs ...string) (*Exec, error) {
	if maxStdout <= 0 {
		return nil, fmt.Errorf("runner: stdout limit %d is not positive", maxStdout)
	}
	if len(programs) == 0 {
		return nil, errors.New("runner: no program allowed")
	}
	allowed := make(map[string]string, len(programs))
	for _, p := range programs {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("runner: program %q is not a clean absolute path", p)
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, fmt.Errorf("runner: resolve program %q: %w", p, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("runner: stat program %q: %w", resolved, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return nil, fmt.Errorf("runner: program %q is not an executable regular file", resolved)
		}
		allowed[p] = resolved
	}
	return &Exec{programs: allowed, env: append([]string{}, env...), maxStdout: maxStdout}, nil
}

// capture is a bounded writer. With fail set an overflow is remembered and
// reported as a write error; otherwise the excess is silently dropped.
type capture struct {
	buf      bytes.Buffer
	max      int64
	fail     bool
	overflow bool
}

func (c *capture) Write(p []byte) (int, error) {
	room := c.max - int64(c.buf.Len())
	if int64(len(p)) <= room {
		return c.buf.Write(p)
	}
	c.overflow = true
	if c.fail {
		return 0, ErrOutputTooLarge
	}
	if room > 0 {
		_, _ = c.buf.Write(p[:room]) // bytes.Buffer.Write never returns an error
	}
	return len(p), nil
}

// Run starts argv[0] with argv[1:]. argv[0] must be one of the allowed programs.
func (e *Exec) Run(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, error) {
	if len(argv) == 0 {
		return nil, nil, errors.New("runner: empty argv")
	}
	program, ok := e.programs[argv[0]]
	if !ok {
		return nil, nil, fmt.Errorf("runner: program %q is not allowed", argv[0])
	}
	cmd := exec.CommandContext(ctx, program, argv[1:]...)
	// A nil Env would mean "inherit the parent environment"; always pass a non-nil
	// slice, even an empty one.
	cmd.Env = append([]string{}, e.env...)
	cmd.WaitDelay = waitDelay
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out := &capture{max: e.maxStdout, fail: true}
	errOut := &capture{max: MaxStderr}
	cmd.Stdout = out
	cmd.Stderr = errOut

	runErr := cmd.Run()
	if out.overflow {
		return nil, errOut.buf.Bytes(), fmt.Errorf("run %s: %w", argv[0], ErrOutputTooLarge)
	}
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			return out.buf.Bytes(), errOut.buf.Bytes(), &ExitError{Program: argv[0], Code: exit.ExitCode()}
		}
		return nil, errOut.buf.Bytes(), fmt.Errorf("run %s: %w", argv[0], runErr)
	}
	return out.buf.Bytes(), errOut.buf.Bytes(), nil
}
