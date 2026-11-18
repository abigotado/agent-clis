// Package secretstore stores one secret per (service, account) pair in the
// operating system's credential store: on macOS the keychains of the user's
// search list (adds go to the default keychain), Credential Manager on
// Windows, and a Secret Service provider on Linux. It never falls back to a
// file.
//
// A Store is opened with Open and addressed by a Key. Failures are *Error
// values whose Kind says what the caller should do next; every Kind has a
// sentinel that errors.Is matches. Error text never contains secret bytes, the
// Service or Account of the key, or text produced by the operating system.
//
// The first Open with valid options fixes the process-wide Interaction mode. A
// later Open with the other mode fails with ErrInvalidArgument, including when
// that first Open itself failed; an Open with invalid options fixes nothing.
//
// On Linux the session bus address is DBUS_SESSION_BUS_ADDRESS when it is set,
// and then only a unix: address is used; any other transport is refused and
// does not fall back. When it is unset or empty the address is
// $XDG_RUNTIME_DIR/bus, as libdbus does, but only if XDG_RUNTIME_DIR is an
// absolute path and bus there is a socket itself, not a symlink, owned by the
// effective user. Otherwise Open fails with ErrUnavailable, and the error never
// names the path. No bus is ever launched.
//
// Callers that save a credential while another process may read or rewrite it
// should hold their own lock around Save and around reads that must be
// consistent with it; the package does not provide cross-process locking.
//
// On macOS the Security framework receives the secret in an immutable CFData
// that is released without being zeroed; only the Go copies are zeroed, on a
// best-effort basis. On Linux the D-Bus library copies the secret into message
// buffers it does not zero, and the Secret Service session encryption, used when
// the provider supports it, only hides the secret from a passive observer of
// the session bus; a provider that does not support it gets the plain
// algorithm, which sends the secret unencrypted over the bus. Only the Go
// copies are zeroed, on a best-effort basis.
//
// Package secretstoretest provides an in-memory fake and a behaviour suite
// that a Store implementation must pass.
package secretstore
