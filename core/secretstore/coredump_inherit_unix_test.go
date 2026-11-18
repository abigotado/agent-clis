//go:build darwin || linux

package secretstore

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func init() {
	platformHelpers["core-dumps-inherited"] = helperCoreDumpsInherited
}

// shellLimitTimeout is a hang guard for the two shell builtins the helper runs.
const shellLimitTimeout = time.Minute

// helperCoreDumpsInherited reads the limit through a second program, not
// through the getrlimit call the helper's own check uses. A program the
// process starts afterwards, such as a browser or a credential helper, inherits
// the limit, so that is the observation that matters.
func helperCoreDumpsInherited() error {
	if err := DisableCoreDumps(); err != nil {
		return fmt.Errorf("DisableCoreDumps: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), shellLimitTimeout)
	defer cancel()
	for _, query := range []struct{ flag, name string }{{"-Sc", "soft"}, {"-Hc", "hard"}} {
		out, err := exec.CommandContext(ctx, "/bin/sh", "-c", "ulimit "+query.flag).Output()
		if err != nil {
			return fmt.Errorf("read the %s core limit in a child shell: %w", query.name, err)
		}
		if got := strings.TrimSpace(string(out)); got != "0" {
			return fmt.Errorf("a child shell sees the %s core limit %q, want 0", query.name, got)
		}
	}
	return nil
}

func TestDisableCoreDumpsIsInherited(t *testing.T) {
	cur, limit, supported, err := readCoreLimit()
	if err != nil {
		t.Fatalf("read core limit: %v", err)
	}
	if supported && cur == 0 && limit == 0 {
		t.Skip("core limit is already 0/0, so the helper cannot show DisableCoreDumps changed anything")
	}
	runHelperProcess(t, "core-dumps-inherited")
}
