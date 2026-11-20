//go:build !portable_readonly && !macos_identity_readonly

// Command youtrack-agent-cli reads YouTrack Cloud through a stable machine
// contract.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/cli"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/output"
)

func main() {
	os.Exit(int(run(
		disableCoreDumps,
		func() errx.Code { return cli.Execute(os.Args[1:]) },
		os.Stdout,
	)))
}

// hardeningError carries only the numeric operating-system status of a failed
// hardening step, never operating-system text.
type hardeningError struct{ status int64 }

func (e *hardeningError) Error() string {
	return fmt.Sprintf("hardening failed with status %d", e.status)
}

// run applies the process hardening before any command executes and before any
// secret is read. A hardening failure is fatal and reported as an INTERNAL
// envelope without running the command.
func run(harden func() error, execute func() errx.Code, stdout io.Writer) errx.Code {
	return runWithRecovery(func() errx.Code {
		if err := harden(); err != nil {
			writer := output.New(output.FormatJSON, nil)
			writer.Out = stdout
			message := "the process could not lower its core-dump limit"
			var failure *hardeningError
			if errors.As(err, &failure) && failure.status != 0 {
				message = fmt.Sprintf("%s (status %d)", message, failure.status)
			}
			return writer.Failure(errx.Internal("%s", message).
				WithHint("report this with the error message; do not retry unchanged"))
		}
		return execute()
	}, stdout)
}

func runWithRecovery(execute func() errx.Code, stdout io.Writer) (code errx.Code) {
	defer func() {
		if recover() != nil {
			writer := output.New(output.FormatJSON, nil)
			writer.Out = stdout
			code = writer.Failure(errx.Internal("youtrack-agent-cli stopped after an unexpected internal failure"))
		}
	}()
	return execute()
}
