//go:build portable_readonly && macos_identity_readonly

package main

// The portable release and developer-only macOS identity editions must never
// share an executable. Referencing this intentionally undefined identifier
// makes an invalid combined build fail at compile time.
var _ = youtrackAgentCLIPortableAndMacOSIdentityReadonlyAreMutuallyExclusive
