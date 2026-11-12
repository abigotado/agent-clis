package secretstore

import (
	"context"
	"os"
)

// openNative returns the Secret Service store. It reads the session bus
// address from DBUS_SESSION_BUS_ADDRESS and uses nothing else: an empty or
// non-unix address is ErrUnavailable and the bus library never launches a bus.
func openNative(ctx context.Context, opts Options) (Store, error) {
	return openSecretService(ctx, opts, os.Getenv("DBUS_SESSION_BUS_ADDRESS"), dialBus)
}
