# Changelog

All notable changes to the `core` module are listed here. Tags are
`core/vX.Y.Z`. While the module is `0.x`, a minor release may change the API.

## Unreleased

### v0.1.0

- Add `secretstore`: one secret per (service, account) pair in the operating
  system's credential store, with a typed `Error` whose `Kind` names the
  caller's next move, a closed set of `Reason` values, and a process-wide
  `Interaction` mode fixed by the first `Open`.
- macOS: Keychain through Security.framework (cgo). A save is staged so a
  failed write never destroys the previous value.
- Windows: Credential Manager. A secret is stored as a manifest plus numbered
  chunks, because one credential blob holds at most 2560 bytes.
- Linux: Secret Service over the session bus, with an encrypted session. Only a
  `unix:` bus address is used, and no bus is ever launched.
- `DisableCoreDumps` for the calling process on Unix.
- `secretstoretest`: an in-memory fake and the behaviour suite every backend
  passes.

### Measured facts

- macOS: the flag that forbids keychain prompts
  (`SecKeychainSetUserInteractionAllowed`) is process-scoped, measured from a
  terminal session: one process turning it off does not change what another
  process of the same user reads.
- macOS: a `sandbox-exec` profile that denies file writes makes a keychain
  write fail with OSStatus 100001 while reads still work. Codex's read-only
  sandbox (codex-cli 0.167.1, macOS 26.6.2) differs: it refuses every
  legacy-keychain call with OSStatus -50, reads, unlock and status included.
  Save reports `KindReadOnly` in both cases, through a temporary rule for an
  unclassified status on a write; Load under the Codex sandbox reports
  `KindOther` with -50.

### Notes for the first consumer (M6)

- Map `KindInvalidArgument` to exit code 1: it is a programming error, not a
  flag the caller can fix.
- Adopt `DisableCoreDumps` at process start, before any secret is read.
