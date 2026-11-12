package secretstore

import "testing"

// TestHelperProcessesDoNotInheritTheSessionBus sets a bus address and a runtime
// directory in the parent, as a developer's desktop session has them, and
// requires the helper to see neither.
func TestHelperProcessesDoNotInheritTheSessionBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/parent-bus")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	runHelperProcess(t, "isolated-bus-env")
}
