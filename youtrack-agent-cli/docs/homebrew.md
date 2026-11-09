# Homebrew

## Standard macOS Formula

The standard macOS distribution channel is a published source-built Formula
in the maintained tap.
A merged source change reaches Homebrew only after its own release tag and a
merged tap update; check `version` before
relying on newly documented behavior:

An untagged source checkout reports `devel`. A `devel` build can be used for
development, but it is not a tagged Formula release. The released v0.3.0
supports reads; new operator-write source changes require their own release
and tap update before they appear in an installed binary.

```bash
brew install abigotado/tap/youtrack-agent-cli
youtrack-agent-cli version -o json
```

Like the Jira, Slack, and Confluence CLI Formulae, the Formula
pin a checksummed immutable source release and have Homebrew build it locally
with Go and `CGO_ENABLED=1`. The resulting binary links the native macOS
Security.framework Keychain backend. This Formula is not a downloaded
binary Cask: it needs neither Apple Developer membership nor Developer ID
signing, notarization, or an installer that removes Gatekeeper quarantine.

The Formula carries the standard CLI, including explicit-profile OAuth,
Keychain credential storage, REST reads, local journal operations, and the
Agent Skill installer. The Linux portable Remote-MCP-only release is unchanged:
it remains credential-free and does not gain a macOS archive from this Formula.

The release sequence is deliberately simple: merge the source change, create
the immutable source tag, then open the tap PR that pins that exact archive and
its SHA-256. A Formula update never builds from a mutable branch.

### OAuth error-code transition — historical v0.2.0 design

The following compatibility notes describe the original v0.2.0 transition;
their historical "planned" wording does not mean the standard Formula is
unpublished today. Operator writes have the separate release boundary above.

The planned tagged `v0.2.0` standard CLI changes machine recovery for
authorization-code token exchange failures. The JSON envelope remains `v:1`,
but callers branching on the published `OAUTH_TOKEN_EXCHANGE_FAILED` code
must handle six new categories. Before this classification, the affected
authorization-code exchange failures used that code and exit 5. This is not
true of every *local post-refresh* failure: binding, invalid-token, Keychain,
context, and unknown-store errors formerly crossed different translation
paths. The planned `v0.2.0` CLI collapses them to
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5. See the compact old-to-new local mapping
in the [OAuth recovery guide](oauth-errors.md) and the seven canonical
code/exit/recovery rows in the generated [machine contract](contract.md#oauth-token-errors-standard-macos-cli-planned-v020).

Refresh request failures after an attempt begins keep the published
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5 recovery in this release, including
DNS/TLS failures even if they occurred before wire dispatch. A cancellation or
deadline detected before an attempt remains a normal `CANCELED` or `TIMEOUT`.
The post-attempt category is conservative because dispatch cannot always be
established. Agents must not trigger another refresh after an ambiguous result:
the server may have rotated the old token before the response was lost.
An HTTP 200 token-body read error is also non-retryable for authorization-code
exchange because the server may already have consumed the code.
A durable refresh fence across CLI processes is required before changing that
behavior; this release does not provide one. The CLI makes no repeat attempt
within the same invocation. A failed token request or pre-Save binding
rejection leaves the old credential in place; after a local save error, the
persisted credential state is unknown.
The fixed public hint identifies local repair for each pre-Save validation or
Save failure category: profile/credential binding, token validation, Keychain
interaction or ACL, canceled/interrupted/timed-out save, Keychain availability,
or another local store failure. It never includes the raw cause or OSStatus.
Hints are repair prose, not stable machine IDs; branch on `error.code` and exit.
A later auth-dependent invocation, including `auth status --check` or a read,
may automatically retry the old token. Agents should avoid those commands after
failure and start a fresh interactive login instead.
If the old credential remains present, replacement requires explicit
operator approval (`auth login --profile NAME --yes`); agents must not add
`--yes` automatically. The exchange-specific
failure codes are also listed in the
[machine-error reference](oauth-errors.md).

Only the fixed category and numeric HTTP status appear in an error. The token
endpoint response, OAuth code, verifier, and tokens remain private. Do not
retry a rejected request unchanged. Never replay an invalid-response token
POST, regardless of subsequent configuration changes: check compatibility,
then start a fresh interactive login for a new authorization code. A failed
first login stores no new credential; restarting login starts a fresh browser
authorization.

### Authentication and upgrades

Create or select a named profile, then use the normal browser OAuth flow:

```bash
youtrack-agent-cli auth login --profile work -o json
youtrack-agent-cli auth status --profile work --check -o json
```

Homebrew never reads, copies, deletes, or automatically migrates a credential.
After a Formula Cellar upgrade, macOS may require an existing Keychain item's
ACL to be explicitly rebound to the current executable. Only when the CLI
reports that condition, run:

```bash
youtrack-agent-cli auth migrate-keychain --profile work --yes -o json
```

That command operates on exactly one selected profile and does not expose its
secret. It is deliberately an operator action, never a post-install hook.

## Write boundaries

The new [operator-confirmed lane](operator-writes.md) is source-supported,
not part of the previously released v0.3.0. It requires a new reviewed source
release and tap update; use `capabilities --profile NAME -o json` to check the
installed build and local profile configuration. It supports single custom
field updates and public comment additions with operator-declared confirmation,
not a native receipt. It never activates the separate strict `mutation` lane.

The Formula does not activate native-presence YouTrack writes. `mutation prepare`
remains a network-free local planning operation, while `mutation confirm`,
`mutation apply`, and `mutation reconcile` fail closed until Gate 1A and Gate
1B have passed and a separately authorized write-capable release exists. Do
not use raw REST as a workaround; the lane does not limit MCP tools.

Formula support therefore does not claim a signed native approval helper,
confirmation receipt, or mutation authority. The existing dependency manifest
and `tools/homebrewcheck` provide a dependency-closure and network-free
standard-CLI CGO build rehearsal. They do not validate a Homebrew Formula and
are not proof of native Gate readiness. Formula validation happens in the tap
PR against the pinned release: `brew audit`, a source install, and `brew test`
must all pass there.

## Separate future Cask channels

The [macOS identity-only ADR](macos-identity-readonly-adr.md) describes a
separate, optional, not-yet-activated signed identity Cask. It is not a
precondition for the Formula and is not a write path.

A future Gate 1A write-capable Cask is also a separate proposed channel. It
would carry a completed signed/notarized application and native approval helper
without rebuilding either artifact. Its prerequisites remain the Gate 1A and
Gate 1B evidence, independent review, release-policy update, and the artifact
authorization requirements in [the trust-root topology](gate1a-trust-root.md),
[exact-artifact authorization](gate1a-artifact-authorization.md), and the
[mutation lifecycle](guarded-mutations.md). Neither Cask is required to
install, authenticate with, or use the standard Formula today.
