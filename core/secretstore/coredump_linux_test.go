//go:build linux

package secretstore

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func init() {
	platformHelpers["core-dumps-proc-limits"] = helperCoreDumpsProcLimits
}

// coreLimitsLine is the row of /proc/self/limits the kernel prints for
// RLIMIT_CORE: soft limit, hard limit and unit.
const coreLimitsLine = "Max core file size"

// helperCoreDumpsProcLimits checks the kernel's own report of the limit, which
// is independent of the getrlimit call DisableCoreDumps is built on.
func helperCoreDumpsProcLimits() error {
	if err := DisableCoreDumps(); err != nil {
		return fmt.Errorf("DisableCoreDumps: %w", err)
	}
	data, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		return fmt.Errorf("read /proc/self/limits: %w", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, coreLimitsLine)
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 || fields[0] != "0" || fields[1] != "0" {
			return fmt.Errorf("the kernel reports the core limit as %q, want soft 0 and hard 0", strings.TrimSpace(rest))
		}
		return nil
	}
	return fmt.Errorf("/proc/self/limits has no %q row", coreLimitsLine)
}

func TestDisableCoreDumpsKernelView(t *testing.T) {
	cur, limit, _, err := readCoreLimit()
	if err != nil {
		t.Fatalf("read core limit: %v", err)
	}
	if cur == 0 && limit == 0 {
		t.Skip("core limit is already 0/0, so the helper cannot show DisableCoreDumps changed anything")
	}
	runHelperProcess(t, "core-dumps-proc-limits")
}
