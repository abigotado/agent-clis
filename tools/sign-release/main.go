//go:build darwin

// Command sign-release signs the darwin archives of a draft release. The
// signing logic lives in untagged packages so Linux CI can test it; only this
// entry point is tied to macOS.
package main

import (
	"fmt"
	"os"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/usage"
)

func main() {
	if _, err := fmt.Fprint(os.Stderr, usage.Text()); err != nil {
		os.Exit(1)
	}
	os.Exit(2)
}
