// Package app is the composition of sign-release: it parses the embedded
// configuration, builds the expectation, finds gh, builds the runner and runs
// the release steps. It holds everything the darwin-only main package would
// otherwise carry, so Linux CI tests it. Every seam to the machine (the
// environment, PATH lookup, symbolic links, the runner, the work directory, the
// terminal) is injected through Deps.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/codesign"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/config"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/release"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/usage"
)

// Exit codes of Main.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

// Deps are the machine seams Main uses.
type Deps struct {
	// ConfigJSON is the embedded config.json.
	ConfigJSON []byte
	// Args are the command-line arguments after the program name.
	Args []string
	// Environ returns the parent environment. Main passes it through
	// runner.MinimalEnv and never hands it to a program as it is.
	Environ func() []string
	// LookPath finds a program on PATH.
	LookPath func(file string) (string, error)
	// EvalSymlinks resolves the symbolic links of a path.
	EvalSymlinks func(path string) (string, error)
	// NewRunner builds the runner that may start exactly the given programs.
	NewRunner func(maxStdout int64, env []string, programs ...string) (runner.Runner, error)
	// MkWorkDir makes the new, empty, 0700 work directory.
	MkWorkDir func() (string, error)
	// Stdin carries the operator's two tag answers.
	Stdin io.Reader
	// Stderr receives the prompts, one line per step and the summary.
	Stderr io.Writer
}

func (d Deps) validate() error {
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"ConfigJSON", len(d.ConfigJSON) > 0},
		{"Environ", d.Environ != nil},
		{"LookPath", d.LookPath != nil},
		{"EvalSymlinks", d.EvalSymlinks != nil},
		{"NewRunner", d.NewRunner != nil},
		{"MkWorkDir", d.MkWorkDir != nil},
		{"Stdin", d.Stdin != nil},
		{"Stderr", d.Stderr != nil},
	} {
		if !c.ok {
			return fmt.Errorf("dependency %s is not set", c.name)
		}
	}
	return nil
}

// Main runs sign-release and returns the process exit code. A panic is mapped
// to ExitFailure: Go would exit 2 on its own, which means usage here.
func Main(ctx context.Context, d Deps) (code int) {
	if d.Stderr == nil {
		return ExitFailure
	}
	say := func(format string, args ...any) {
		// stderr is the operator's terminal; a failed write has nowhere to be
		// reported, and the exit code still carries the outcome.
		_, _ = fmt.Fprintf(d.Stderr, format+"\n", args...)
	}
	defer func() {
		if rec := recover(); rec != nil {
			say("sign-release: internal error: %v", rec)
			code = ExitFailure
		}
	}()
	if err := d.validate(); err != nil {
		say("sign-release: %v", err)
		return ExitFailure
	}
	if len(d.Args) != 2 {
		// The usage text is the output; see say above for the write error.
		_, _ = io.WriteString(d.Stderr, usage.Text())
		return ExitUsage
	}
	if err := run(ctx, d, d.Args[0], d.Args[1], say); err != nil {
		say("sign-release: %v", err)
		return ExitFailure
	}
	return ExitOK
}

func run(ctx context.Context, d Deps, cliName, version string, say func(string, ...any)) error {
	// Everything that needs no command runs first: the configuration, the CLI,
	// its readiness to sign (a certificate hash must be set) and the version.
	cfg, err := config.Parse(d.ConfigJSON)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cli, err := cfg.CLI(cliName)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	exp, err := codesign.ExpectationFor(cliName, cli)
	if err != nil {
		return err
	}
	if _, err := config.ExpandName("x-"+config.VersionPlaceholder, version); err != nil {
		return err
	}
	say("config: %s %s, identifier %s, team %s, certificate %s", cliName, version, exp.Identifier, exp.Team, exp.CertSHA1)

	gh, err := resolveGH(d)
	if err != nil {
		return err
	}
	limits := release.DefaultLimits()
	// The stdout bound is the archive bound: gh prints a whole archive.
	r, err := d.NewRunner(limits.MaxArchive, runner.MinimalEnv(d.Environ()), gh, release.CodesignPath)
	if err != nil {
		return fmt.Errorf("build the runner: %w", err)
	}
	dir, err := d.MkWorkDir()
	if err != nil {
		return fmt.Errorf("create the work directory: %w", err)
	}
	say("work directory: %s (kept for inspection; it holds the release files and the signed binaries, and no secrets)", dir)

	params := release.Params{Config: cfg, CLI: cliName, Version: version, GH: gh, WorkDir: dir, Limits: limits}
	res, err := release.Run(ctx, r, params)
	if err != nil {
		return err
	}
	say("resolve, download, checksum, attest: release %d, tag %s, commit %s; both archives and both streams verified", res.ReleaseID, res.Tag, res.Commit)
	say("next: one Keychain prompt per binary; answer Allow, never Always Allow")

	pub, err := release.Finish(ctx, r, params, res, release.Console{In: d.Stdin, Out: d.Stderr})
	if err != nil {
		return err
	}
	say("done: %s published as release %d at commit %s", pub.Tag, pub.ReleaseID, pub.Commit)
	for _, a := range pub.Assets {
		say("  %s  %s", a.SHA256, a.Name)
	}
	return nil
}

// resolveGH finds gh on PATH once and resolves its symbolic links; the result
// is the one program every gh command starts.
func resolveGH(d Deps) (string, error) {
	found, err := d.LookPath("gh")
	if err != nil {
		return "", fmt.Errorf("find gh on PATH: %w", err)
	}
	if !filepath.IsAbs(found) {
		return "", fmt.Errorf("gh was found at %q, which is not an absolute path", found)
	}
	resolved, err := d.EvalSymlinks(found)
	if err != nil {
		return "", fmt.Errorf("resolve gh at %q: %w", found, err)
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errors.New("gh does not resolve to a clean absolute path")
	}
	return resolved, nil
}
