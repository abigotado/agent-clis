package release

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

// maxSnippet bounds the part of a program's stderr repeated in a refusal.
const maxSnippet = 512

// snippet quotes the start of a program's output for a message. The output is
// untrusted text, so it is quoted and bounded.
func snippet(b []byte) string {
	if len(b) > maxSnippet {
		return strconv.Quote(string(b[:maxSnippet])) + "..."
	}
	return strconv.Quote(string(b))
}

// runStep runs one command. A program that ran and exited non-zero is a refusal
// at step; a cancelled run and a command that could not start are plain errors.
func runStep(ctx context.Context, r runner.Runner, step Step, what string, argv []string, stdin []byte) (stdout, stderr []byte, err error) {
	stdout, stderr, err = r.Run(ctx, argv, stdin)
	if err == nil {
		return stdout, stderr, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, nil, fmt.Errorf("%s: %w", what, ctxErr)
	}
	var exit *runner.ExitError
	if errors.As(err, &exit) {
		return stdout, stderr, refuse(step, "%s failed (%v), stderr %s", what, err, snippet(stderr))
	}
	return nil, nil, fmt.Errorf("%s: %w", what, err)
}

// readRegular reads a regular file of at most limit bytes. A symbolic link or
// any other kind of entry is refused.
func readRegular(step Step, path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, refuse(step, "%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, refuse(step, "%s is %d bytes, over the limit %d", path, info.Size(), limit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, refuse(step, "%s is %d bytes, over the limit %d", path, len(data), limit)
	}
	return data, nil
}
