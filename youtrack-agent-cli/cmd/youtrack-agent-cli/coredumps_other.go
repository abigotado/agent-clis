//go:build !portable_readonly && !macos_identity_readonly && !(darwin && cgo)

package main

// disableCoreDumps is a no-op where the full edition does not link core, so
// Linux, Windows and cgo-free builds stay free of the secret-store module.
func disableCoreDumps() error { return nil }
