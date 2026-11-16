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
  failed write never destroys the previous value. A keychain this process
  cannot use, such as inside Codex's read-only sandbox, is `KindUnavailable`
  with the new `ReasonKeychainUnusable` (`"keychain-unusable"`) and status -50.
  `KindUnavailable` now also covers a store that cannot be used from this
  process, not only a missing backend. It never means the credential is absent:
  a caller must not suggest re-authenticating and must not treat it as not
  found.
- Windows: Credential Manager. A secret is stored as a manifest plus numbered
  chunks, because one credential blob holds at most 2560 bytes.
- Linux: Secret Service over the session bus, with an encrypted session. Only a
  `unix:` bus address is used, and no bus is ever launched.
- `DisableCoreDumps` for the calling process on Unix.
- `secretstoretest`: an in-memory fake and the behaviour suite every backend
  passes.

### Measured facts

- macOS: the flag that forbids keychain prompts
  (`SecKeychainSetUserInteractionAllowed`) is process-scoped, measured in a
  logged-in GUI (Aqua) session on macOS 26.6.2: one process turning it off
  does not change what another process of the same user reads.
- macOS: a `sandbox-exec` profile that denies file writes makes a keychain
  write fail with OSStatus 100001 while reads still work, and the lock probe
  works; Save reports `KindReadOnly` there, through a temporary rule for an
  unclassified status on a write.
- macOS: Codex's read-only sandbox (codex-cli 0.167.1, `:read-only` profile,
  macOS 26.6.2) differs: the add, the unlock and `SecKeychainGetStatus` return
  OSStatus -50 (`errSecParam`), searches find nothing, and the search list
  cannot be read. For the default keychain, the target of a production add,
  `SecKeychainCopyDefault` returns 0 with a non-null reference and
  `SecKeychainGetStatus` then returns -50, so the probe fails at the same step
  as for a scratch keychain (probe run 2026-11-13, search list and default
  keychain equal before and after, interaction flag restored).
- Before the fix, under that sandbox `Load` of a stored secret reported
  `KindNotFound` (-25300), so a stored credential looked absent, and `Delete`
  returned nil without deleting anything. Both now report `KindUnavailable`
  with `ReasonKeychainUnusable` and status -50, as do `Exists` and `Save`
  (`Save` no longer reports `KindReadOnly` there: reads are not allowed, which
  is what that kind promises).
- macOS: only a -50 at the `SecKeychainGetStatus` step counts. A -50 from the
  lookup, the keychain copy or the default-keychain copy keeps its ordinary
  meaning. A scratch keychain whose file was deleted under a live reference
  probes as usable (no failing step, status 0); a reference to a path where no
  keychain exists fails at the get-status step with -25294
  (`errSecNoSuchKeychain`), not -50 (measured by
  `TestKeychainProbeOfAKeychainThatIsNotUsable`). When the item probe fails at
  the lookup or keychain copy, the add-target probe also runs, because the
  search list cannot be read in the sandbox.
- Whether every Codex permission profile makes the probe fail is not claimed:
  the rows run under `SECRETSTORE_CODEX_PROFILE` and branch on what the probe
  measures there. A raw read that bypasses the store's gate must fail wherever
  the probe says unusable; one that succeeds means the rule is too wide.
  Measured 2026-11-16 with codex-cli 0.167.1 on macOS 26.6.2:
  - Under `:read-only` and `:workspace` (the built-in workspace-write profile),
    the item probe and the add-target probe both fail at get-status with -50,
    and the raw read finds nothing (-25300). `Load`, `Save`, `Exists` and
    `Delete` all report unavailable, status -50, keychain-unusable. Under
    `:workspace` the scratch directory is writable, yet the keychain still
    cannot be used.
  - Under a configuration whose default permissions are `:danger-full-access`,
    nothing is sandboxed: the probes pass and every operation behaves normally.
  - No profile showed a -50 probe together with a working read, so the rule
    did not need narrowing.

### Notes for the first consumer (M6)

- Map `KindInvalidArgument` to exit code 1: it is a programming error, not a
  flag the caller can fix.
- Adopt `DisableCoreDumps` at process start, before any secret is read.
- Check the `Reason` before the `Kind`: `KindUnavailable` with
  `ReasonKeychainUnusable` and status -50 means the credential store cannot be
  used from this process, not that the credential is missing or expired. Map it
  to a credential-store-unavailable error with exit code 8 and the hint "run
  outside the sandbox", never to an authentication error (exit code 5, which is
  what a bare `auth.ErrUnsupported` maps to today) and never to not found. The
  adoption PR carries a mapping test: `KindUnavailable` + `ReasonKeychainUnusable`
  + status -50 gives exit 8, not 5. An OAuth refresh pre-check must not redeem
  the refresh token on any Save error, `KindUnavailable` included.
