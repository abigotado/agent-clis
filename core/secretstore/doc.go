// Package secretstore stores one secret per (service, account) pair in the
// operating system's credential store: the login keychain on macOS, Credential
// Manager on Windows, and a Secret Service provider on Linux. It never falls
// back to a file.
//
// A Store is opened with Open and addressed by a Key. Failures are *Error
// values whose Kind says what the caller should do next; every Kind has a
// sentinel that errors.Is matches. Error text never contains secret bytes, the
// Service or Account of the key, or text produced by the operating system.
//
// The first Open in a process fixes the process-wide Interaction mode. A later
// Open with the other mode fails with ErrInvalidArgument, including when the
// first Open itself failed.
//
// Callers that save a credential while another process may read or rewrite it
// should hold their own lock around Save and around reads that must be
// consistent with it; the package does not provide cross-process locking.
//
// Package secretstoretest provides an in-memory fake and a behaviour suite
// that a Store implementation must pass.
package secretstore
