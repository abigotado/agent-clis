//go:build !portable_readonly && !macos_identity_readonly

// Command youtrack-agent-cli reads YouTrack Cloud through a stable machine
// contract.
package main

import (
	"io"
	"os"

	"github.com/abigotado/youtrack-agent-cli/internal/cli"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
)

func main() {
	os.Exit(int(runWithRecovery(
		func() errx.Code { return cli.Execute(os.Args[1:]) },
		os.Stdout,
	)))
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
