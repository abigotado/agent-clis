# Threat model: macOS identity-only Cask channel

- Status: **PROPOSED; NOT ACTIVATED**
- Date: 2026-09-21
- Companion decision: [macOS identity-only Cask channel ADR](macos-identity-readonly-adr.md)

This model applies only to the proposed `macos_identity_readonly` identity
edition. It neither changes the portable `v0.1.0` release nor supplies any
authority to the Gate 1A write-capable path.

The first implementation milestone is a Darwin+cgo developer build with only
`version`, `contract`, read-only profile metadata, and Skill installation. It
has no OAuth, Keychain, network, signed artifact, or Cask surface. Its profile
registry is isolated at
`$(os.UserConfigDir)/youtrack-agent-cli-identity-readonly/profiles.json` and
never reads, moves, or merges the source-build registry. The signed-app and
credential controls below are activation requirements for a later published
identity edition, not properties claimed by this developer build.

## Assets and trust boundaries

| Asset or boundary | Required protection |
| --- | --- |
| Signed identity application | Developer ID identity, notarization, literal reviewed Team ID, immutable artifact checksum, and no source rebuild |
| CLI OAuth identity credential | Keychain-only storage under `youtrack-agent-cli.identity-readonly.v1`; never stdout, logs, profiles, exports, or MCP configuration |
| Non-secret profile metadata | Only `list`, `show`, `validate`, `add`, and `remove`; exact `capabilities:["read"]`, exact MCP allowlist, and explicit instance/account binding |
| Remote MCP session | Independent MCP-host OAuth and exact six-tool URL allowlist; not shared with the CLI credential |
| Skill installation | Explicit operator command after install; cgo-enabled macOS extended-ACL inspection for every root/destination; not a Cask hook |
| Write-capable trust root | Disjoint from this channel: no helper, approval key, receipt, journal, or mutation command |

The attacker may control issue text, MCP tool descriptions and outputs, local
shell input, a same-user process, a network origin after DNS resolution, or
distribution/tap content before it is accepted into the reviewed release
manifest. Those values are data, never instructions or authority. A compromise
of the reviewed release-manifest authority or Developer ID signing authority is
outside this channel's client-side guarantees and requires incident response,
not automatic credential preservation. The model does not assume that an OAuth
token is read-only merely because the application does not expose REST issue
commands.

## Threats and required controls

| Threat | Required control | Residual risk / fail-closed response |
| --- | --- | --- |
| A source Formula rebuilds or replaces the executable | Ship only the completed signed/notarized app through a Cask; Cask links its contained CLI | Identity mismatch or missing notarization blocks publication/install; a source Formula is out of scope |
| A Cask hook or alternate asset performs hidden login, migration, network work, or deletion | Install/link only; pin a versioned immutable per-architecture URL and literal SHA-256; policy tests reject hooks, source builds, re-signing, unchecked hashes, alternate assets, and extra publishers | Unsupported installer behavior is a release-policy failure |
| A credential is leaked to an agent, log, or MCP client | Keychain-only storage; redacted diagnostics; never export, print, bridge, or configure it into MCP | Suspected exposure requires operator-led credential revocation; no automatic export/recovery path exists |
| A privileged account makes the CLI accidentally write-capable | Exact CLI allowlist excludes REST issue operations and mutation surfaces; operator configures a least-privilege account/client and exact expected-account binding | `users/me` cannot prove all server permissions; a broad account/client is a deployment-policy failure, not a runtime-detectable read-only claim |
| A bare or mutation-capable MCP endpoint is used for reads | Independent MCP OAuth plus the exact six-tool `tools=` allowlist and host/read-only-account enforcement | `tools=` alone may not reject direct hidden calls; fail closed or use a read-only identity when host enforcement is absent |
| A user assumes CLI OAuth logs in Codex/Claude | Document distinct OAuth sessions and prohibit credential bridging | Agent must start the MCP host's own OAuth flow |
| Migration moves, deletes, or collides with an existing Keychain item | No installer migration; signed old/new spike with explicit operator command and source-collision cases | Any ambiguity, cancellation, interruption, or rollback fails closed without deletion |
| A signed but unreviewed update inherits a credential | Immutable reviewed release manifest binds source commit, tag, digest, code identity, and version; every upgrade needs explicit migration/reauthorization after signed-old/new proof | Missing/changed manifest, unproven transition, or unattended update denies Keychain access; signing/release-authority compromise requires incident response |
| A same-user process impersonates a package or modifies an update | Code-signing/notarization verification, reviewed release manifest, and separate Keychain service; no helper IPC or write authority | Same-user denial of service remains possible; it cannot obtain a credential through the CLI |
| Untrusted YouTrack content steers the agent | Treat every remote string as untrusted data; bounded searches and exact issue reads in the MCP policy | The agent must not execute instructions embedded in issue text |

## Invariants

1. Installation does not authenticate, read or alter Keychain, configure MCP,
   install a Skill, register a helper, or contact a service after download.
2. The identity edition only verifies identity. It never invokes an issue REST
   operation, mutation journal, write policy, confirmation, native helper, or
   guarded-write reconciliation.
3. CLI OAuth and MCP OAuth never share a token, refresh credential, callback,
   or storage namespace.
4. Identity-edition profiles admit only exact read capability and allowlisted
   MCP metadata. The first identity edition accepts OAuth credentials only from
   its own login flow; permanent tokens and all source/legacy credentials are
   rejected rather than migrated. A later signed-old/signed-new migration may
   rebind only a prior identity-edition OAuth item. Least-privilege OAuth
   client/account configuration remains an operator requirement. The
   developer-only metadata build has no credential admission path and fails
   closed when any loaded profile is outside this exact policy.
5. A named instance/account remains explicit. No input, tool output, redirect,
   or profile field may silently switch the selected instance.
6. Failure to prove signing, notarization, accepted release manifest, profile
   binding, credential storage, or migration state denies the operation without
   emitting secret material.
7. Skill installation requires cgo-enabled macOS extended-ACL inspection of
   every root and destination. An unavailable or failed inspection denies the
   operation; neither the Cask nor a fallback installer can bypass it.

## Deferred write requirements

The following requirements are recorded for a later authority-bearing threat
model only. They have **no implementation authority** in this channel:

- expose structured capability availability for `confirm`, `apply`, and
  `reconcile`;
- bind a human-confirmed batch receipt to all ordered plans, then apply once and
  reconcile each result separately;
- derive updates from an exact issue/schema snapshot, including verified custom
  field IDs for `Stage` and card movement;
- return a readable created ID only after confirmed/reconciled application;
- use a visible TDI marker for comment reconciliation;
- return exit `7` / `CONFIRMATION_REQUIRED` immediately in noninteractive
  contexts;
- disclose prospective notifications for Stage changes, and enable suppression
  only after verifying official API behavior; and
- never combine MCP and CLI mutation paths in one operation.

The future write surface remains governed by the separate
[guarded mutation contract](guarded-mutations.md) and the
[Gate 1A topology](gate1a-trust-root.md). Nothing in this document permits a
write, a Keychain migration, or a Cask release.
