package secretstore

import (
	"context"
	"os"
)

// openNative returns the Secret Service store. The session bus address is
// DBUS_SESSION_BUS_ADDRESS, or else $XDG_RUNTIME_DIR/bus under the checks of
// sessionBusAddress. An empty or non-unix address is ErrUnavailable and the
// bus library never launches a bus.
func openNative(ctx context.Context, opts Options) (Store, error) {
	return openSecretService(ctx, opts, sessionBusAddress(os.Getenv, os.Geteuid()), dialBus)
}
