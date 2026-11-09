# ADR: macOS identity-only Cask channel

- Status: **PROPOSED; NOT ACTIVATED**
- Date: 2026-09-21
- Scope: a future, disjoint macOS identity-verification distribution channel

This decision remains unactivated as a distribution channel. Its first code
milestone is a developer-only, compile-time `macos_identity_readonly` build;
it is neither a Cask nor a release artifact. It does not create a tap, release
workflow, signed application, OAuth client, Keychain item, or a published
identity-authentication command. It does not alter the Linux portable `v0.1.0`
release or the future write-capable Gate 1A topology in [Gate 1A trust,
storage, and package topology](gate1a-trust-root.md). The companion [threat
model](macos-identity-readonly-threat-model.md) is part of this proposed
decision.

## Context

The portable release deliberately has no local OAuth or Keychain surface. A
future macOS installation may need to verify the identity behind a named
YouTrack profile and retain the resulting credential in the macOS Keychain.
That is a different distribution and trust problem from both the portable
Remote-MCP read plane and the signed native helper needed for guarded writes.

Existing Homebrew layouts in the operator's Jira, Redmine, and related CLI
projects are useful distribution references. They are not authority for this
channel: an ordinary source Formula rebuilds a binary in Homebrew's build
environment and cannot preserve the designated identity needed to bind
Keychain access. It is therefore not a safe delivery mechanism here.

## Proposed decision

### Reserved identifiers

The following literal values are reserved for this channel. They are not
implemented identifiers and must not be treated as installed or trusted before
the prerequisites below are satisfied.

| Purpose | Reserved value |
| --- | --- |
| Bundle identifier | `io.github.abigotado.youtrack-agent.identity` |
| Application bundle | `YouTrackAgentIdentity.app` |
| Keychain service | `youtrack-agent-cli.identity-readonly.v1` |
| Compile-time build tag | `macos_identity_readonly` |
| Release-tag namespace | `identity-v*` |
| Release-artifact prefix | `youtrack-agent-identity` |
| Homebrew Cask token | `youtrack-agent-identity` |

The channel has its own app bundle, code identity, Keychain service, artifact
names, and release tags. It does not reuse `YouTrackAgent.app`, the
write-capable approval-helper bundle ID or Keychain namespace, or portable
release artifacts.

### First developer-only build

The first implementation milestone is available only as a Darwin+cgo
developer build with the `macos_identity_readonly` tag. It is intentionally
not publishable and exposes only:

```text
version
contract
profile list|show|validate|add|remove
skills install|uninstall
```

It has no `auth` command, does not open a browser, does not access Keychain,
does not make a network request, and does not read, move, or merge the normal
source-build registry. Its non-secret registry is separately rooted at
`$(os.UserConfigDir)/youtrack-agent-cli-identity-readonly/profiles.json`.
Every loaded profile must satisfy the identity edition's exact read-only
profile policy before any list, show, validation, replacement, or removal
operation proceeds. A failed validation is a non-secret, fail-closed metadata
error.

### Exact future CLI surface

After a separate OAuth/Keychain design, migration spike, and security review,
the future published identity-only build may extend that developer-only surface
only with:

```text
version
contract
profile list|show|validate|add|remove
auth login
auth status
auth whoami
auth logout
auth migrate-keychain          # only a prior signed identity-edition item
skills
```

`profile` remains non-secret, read-only profile metadata; its only permitted
subcommands are listed above and it must not become an alternate credential
transport. Admission requires exactly `"capabilities": ["read"]`, the
identity channel's exact Remote MCP allowlist, and an explicit expected
instance/account binding. The first identity edition accepts only OAuth
credentials obtained by its own login flow: it never imports or migrates a
source-build or legacy credential, including a permanent token or any profile
with a write capability. A later `auth migrate-keychain` may rebind only an
OAuth item produced by a prior signed identity edition after a signed-old to
signed-new migration proof. The build explicitly excludes `auth
import-token`, `auth allow-projects`, `inspect`, `mutation`, `journal`,
`writepolicy`, every native helper surface, and every issue REST operation.
It therefore cannot create, update, move, assign, comment on, or otherwise
mutate a YouTrack issue.

`skills` is available only in the cgo-enabled macOS identity build and must
run the existing extended-ACL inspection for every Skill root and destination.
If that inspection is unavailable or fails, installation fails closed; a Cask
must not bypass the check or install the Skill itself.

### OAuth and read-plane separation

The CLI OAuth credential is for local identity verification. It is **not
inherently read-only**: the binary can bind it to the configured expected
account through exact `users/me` verification, but cannot infer every server
permission from that response. The configured public client and selected
YouTrack account are therefore an operator-controlled least-privilege
requirement, not a runtime claim. The credential stays in the reserved Keychain
service, is never printed, exported, or bridged to an MCP client, and does not
grant the CLI a REST issue operation.

Remote reads remain a separate MCP-host OAuth session against a named instance
and account. Its only supported endpoint is the official Remote MCP endpoint
with this exact positive tool allowlist:

```text
https://<instance>/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true
```

The documented conflict around predefined MCP tools still applies: a bare
`/mcp` endpoint is not considered read-only. The full read-plane policy is in
the [portable README](../README.md#read-plane); the local identity credential
does not relax the MCP host allowlist or a read-only account requirement.

### Distribution and installer boundary

A future Cask may install the completed signed and notarized
`YouTrackAgentIdentity.app` and link only its contained CLI. It may not build
from source, re-sign, unpack a standalone binary, or run a postflight action.
Specifically, Cask installation performs none of the following:

- OAuth login or browser authorization;
- Keychain read, migration, or deletion;
- Agent Skill installation;
- helper registration or launch;
- network access after artifact download; or
- secret deletion.

The operator must invoke login, Skill installation, or logout explicitly after
installation. The first identity Cask has no migration from a source or legacy
CLI. A future `auth migrate-keychain` is not a Cask concern and may only move a
prior signed identity-edition OAuth item. Before it can exist, a
signed-old/signed-new migration spike must cover first install, reinstall,
upgrade, cancellation, interruption, rollback, uninstall/reinstall, and
source-service collision as an explicit rejection without exposing a
credential.

### Release prerequisites

Activation requires all of the following before a Cask, artifact, or
identity-only command is published:

1. a Developer ID Application signing identity;
2. the literal Apple Team ID supplied as a reviewed immutable release input
   (no placeholder, inferred value, wildcard, or fallback);
3. notarization for the exact shipped application;
4. an owned tap repository with controlled publish access;
5. signing-capable, access-controlled CI that keeps signing material outside
   source and job logs;
6. a versioned immutable application-archive URL and literal SHA-256 for each
   supported architecture (never `sha256 :no_check`);
7. a release-policy test that rejects Cask hooks, source builds, re-signing,
   alternate assets, unchecked hashes, OAuth/Keychain/Skill actions, and any
   publisher outside the reviewed final upload/tap job; and
8. a reviewed immutable release manifest that binds the accepted source commit,
   tag, artifact digest, application code identity, and version. Every
   identity-edition upgrade is deny-by-default: it requires an explicit
   operator migration/reauthorization decision after the signed-old/signed-new
   spike proves the exact transition. No unattended Cask update may gain,
   preserve, or broaden Keychain access.

A private `abigotado/homebrew-tap` is recommended for the first beta but is
not activated or created by this ADR. Public tap publication is a later,
separately reviewed choice.

## Consequences

- macOS identity verification can be designed without weakening the portable
  read-only release or claiming Gate 1A write authority.
- The Cask is a byte-preserving installer/linker, not an identity or secret
  management agent.
- A release is rejected if its Cask does not pin the reviewed immutable asset
  and literal architecture-specific SHA-256 or attempts an installer action.
- A valid Apple signature or checksum alone is not authority to receive an
  earlier build's credential; the accepted release manifest and explicit
  migration/reauthorization decision are required for every upgrade.
- A future operator can intentionally authenticate once the signed app is
  installed, while Codex and Claude Code continue to complete their own MCP
  OAuth flow.
- Any added command, Cask hook, credential migration behavior, source Formula,
  or connection to the write-capable helper requires a new ADR and threat-model
  review.

## Deferred guarded-write appendix

This channel grants no write authority. The following requirements are kept
only as high-level inputs to a later guarded-write ADR; they do not authorize
implementation, release, confirmation, or mutation here:

- a structured `capabilities -o json` result explaining whether `confirm`,
  `apply`, and `reconcile` are available and why not;
- one immutable batch receipt that binds the ordered set of plans, displays the
  complete batch once, applies each one at most once in order, and reconciles
  each result independently;
- snapshot input from an exact issue read, including schema-bound custom-field
  IDs so `Stage` and card movement update the verified custom field rather than
  a guessed standard field;
- a readable created issue ID only after confirmed or reconciled success, never
  guessed from an ambiguous create outcome;
- a visible TDI marker for `comment.add` reconciliation, searched exactly by
  the reconciler;
- noninteractive confirmation that fails immediately with exit `7`, named
  `CONFIRMATION_REQUIRED`, rather than waiting for UI;
- disclosure of prospective Stage-change notifications, with notification
  suppression considered only when the official API semantics are verified;
  and
- explicit separation of MCP and CLI mutation paths: a single operation must
  not mix the two paths.

The existing [guarded mutation contract](guarded-mutations.md) remains the
write-capable design reference. Its Gate requirements, including the native
helper, are not imported into this identity-only channel.
