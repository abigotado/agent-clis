//go:build darwin

// Command sign-release signs the darwin archives of a draft release. The
// signing logic lives in untagged packages so Linux CI can test it; this entry
// point only hands the machine's seams to internal/app.
package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/app"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

func main() {
	// The account database, not $HOME: os/user reads it on darwin with or
	// without cgo.
	accountHome := func() (string, error) {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		return u.HomeDir, nil
	}
	seams := app.NewHomeSeams(accountHome)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := app.Main(ctx, app.Deps{
		ConfigJSON:   configJSON,
		Args:         os.Args[1:],
		Environ:      os.Environ,
		HomeDir:      seams.HomeDir,
		Lock:         seams.Lock,
		LookPath:     exec.LookPath,
		EvalSymlinks: filepath.EvalSymlinks,
		NewRunner: func(maxStdout int64, env []string, programs ...string) (runner.Runner, error) {
			r, err := runner.NewExec(maxStdout, env, programs...)
			if err != nil {
				return nil, err
			}
			return r, nil
		},
		MkWorkDir: seams.MkWorkDir,
		Stdin:     os.Stdin,
		Stderr:    os.Stderr,
	})
	stop()
	os.Exit(code)
}
