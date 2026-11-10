# ADR: Gate 1A trust, storage, and package topology

- Status: Safety and isolated-subrun topology specified; native Gate not implemented
- Date: 2026-09-03
- Gate 1A result: **NOT PASSED**
- Production approval adapter: `approval.Unsupported`

[Gate 1B isolated subruns](gate1b-isolated-subruns.md) specifies the separate
authorization, target lifecycle, and parent evidence-aggregation protocol.
Destructive phases never reset or reuse an enrolled unit. That ADR supersedes
Gate 1B single-suite token/context/index assumptions; Gate 1A remains unchanged.
Token issuance requires a reviewed materialized inventory, verified codecs and
validators, and the exact native candidate. The resulting authorized native
runs must then pass before evidence acceptance or successor authority. No
design decision here constitutes a passed Gate or permits activation/publication
by itself.

## Context

The approval protocol verifies a response against an already trusted public
key. A helper response cannot safely choose that key: doing so would turn the
first approval into trust on first use and let a replaced same-user process
enroll itself. A mode-`0600` file is also not an authority boundary against an
agent running as the same user.

The native helper, approval-key registry, code-signing identity, bundle layout,
release-rollover boundary, and future Homebrew artifact therefore form one trust topology.
They must be fixed before native implementation and must fail closed while the
operator-controlled signing identity is unavailable.

Two companion specifications are normative parts of this decision:

- [Gate 1A registry and ceremony protocol](gate1a-registry-protocol.md) freezes
  every authority-bearing ledger and ceremony byte; and
- [Gate artifact authorization](gate1a-artifact-authorization.md) freezes the
  independent exact-code descriptor, per-architecture Gate evidence,
  provisional-to-smoke-to-activation ceremony, and publication binding.

## Decision

### Signed bundle and identifiers

The only production distribution unit for the **write-capable Gate 1A
topology** is one signed and notarized application bundle named
`YouTrackAgent.app`:

```text
YouTrackAgent.app/
  Contents/
    Info.plist
    MacOS/
      youtrack-agent-cli
    Library/LaunchAgents/
      io.github.abigotado.youtrack-agent.approval.plist
    Library/Helpers/
      YouTrackAgentApproval.app/
        Contents/Info.plist
        Contents/embedded.provisionprofile
        Contents/MacOS/YouTrackAgentApproval
```

The delivery archive additionally carries the detached authorization files at
the fixed archive-root paths defined by the artifact-authorization protocol.
They remain outside the sealed application bundle and are installed at fixed
installation-root sibling paths. This detached shape lets the provisional
authorization and activation grant bind the final signed CodeDirectory
identities without a self-reference.

The proposed [macOS identity-only Cask channel](macos-identity-readonly-adr.md)
is a deliberately disjoint future distribution unit. It has a different bundle
identifier, Keychain service, artifact namespace, and no approval helper,
receipt, journal, mutation, or Gate authority. It is not activated and does
not modify this write-capable topology or its first-release claim.

The identifiers are immutable protocol and packaging inputs:

| Code object | Signing identifier |
| --- | --- |
| outer app and CLI authority | `io.github.abigotado.youtrack-agent` |
| approval helper | `io.github.abigotado.youtrack-agent.approval` |
| developer-only Gate runner | `io.github.abigotado.youtrack-agent.gate1a` |

The Gate runner is never embedded in a release, Cask, Formula, archive, or
installed bundle. The CLI path exposed to users is always the executable inside
the installed application bundle. A future Homebrew Cask may install the app
and link that contained executable into Homebrew's binary directory; it may not
rebuild, replace, re-sign, or extract the helper.

The sealed LaunchAgent declaration has the fixed label
`io.github.abigotado.youtrack-agent.approval` and `BundleProgram` equal to
`Contents/Library/Helpers/YouTrackAgentApproval.app/Contents/MacOS/YouTrackAgentApproval`,
relative to the outer application bundle. The operator explicitly registers it
with `SMAppService.agent(plistName:)`, subject to macOS approval. Neither the
Cask nor a post-install hook registers or launches the service. The helper
itself binds the fixed per-user AF_UNIX endpoint defined below; launchd
launches the helper, not a runner-supplied socket. The CLI
connects itself, so `LOCAL_PEERTOKEN` identifies the actual protocol peer;
passing a runner-preconnected descriptor is prohibited.

The parent launch constraint `is-init-proc=true` and fixed job label constrain
the intended lifecycle, not global singleton authority. Ordinary same-UID
`launchctl` operations and alternate bootstrap contexts remain in scope. A
second exact signed helper must be safe: only the unique fixed Keychain
`active` add provides cross-process exclusion, never a launchd label or a
process-local executor guard.

The normative ordinary listener path is exactly
`/private/tmp/ytac-approval-<euid>/approval.sock`. Both peers derive `<euid>`
from the operating system's effective UID and encode it as canonical unsigned
decimal (no leading zero except `0`); it is never read from argv, environment,
runner input, or a profile. The full ASCII pathname plus its terminating NUL
must fit the platform's `sockaddr_un.sun_path` array before any socket call;
there is no truncation or alternate-path fallback.

The immediate parent must be a real directory owned by that effective UID
with mode exactly `0700`. Each peer opens it without following symlinks and
validates its type, owner, and mode from the opened directory descriptor. The
helper verifies the bound entry as a socket under that opened directory, and
the CLI verifies the socket entry under its validated opened directory before
connecting. A replaced parent, symlink, wrong owner/mode/type, or failed
identity check fails closed. Bind collision also fails closed: neither startup
nor connection may unlink an existing entry or delete another listener.
These checks constrain filesystem use, not authority. A same-UID attacker can
replace the directory or socket and deny service; every actual connection
still requires mutual connection-bound audit-token and exact-code validation
before protocol bytes. Neither pathname ownership nor a successful bind proves
peer identity or global singleton status.

The Apple Developer Team ID and positive decimal bundle build number are
required immutable release inputs named `TEAM_ID` and `RELEASE_BUILD`. The
repository has no default or fallback value for either. Empty, wildcard,
non-decimal build, ad-hoc, Apple Development, and locally self-signed inputs
are rejected for production evidence. At the acceptance
date no Developer ID Application identity is installed on the development
machine, so this ADR does not pass Gate 1A.

After substituting the operator-owned `TEAM_ID`, both peers compile and pin the
following Developer ID Application requirements. The exact identifier differs
per peer:

```text
anchor apple generic
and certificate 1[field.1.2.840.113635.100.6.2.6] exists
and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
and certificate leaf[subject.OU] = "${TEAM_ID}"
and identifier "io.github.abigotado.youtrack-agent"
and info[CFBundleVersion] = "${RELEASE_BUILD}"
```

```text
anchor apple generic
and certificate 1[field.1.2.840.113635.100.6.2.6] exists
and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
and certificate leaf[subject.OU] = "${TEAM_ID}"
and identifier "io.github.abigotado.youtrack-agent.approval"
and info[CFBundleVersion] = "${RELEASE_BUILD}"
```

The shipped baseline requirements contain the literal Team ID and build
number; production code never expands an environment variable at runtime.
Those requirements establish publisher and coarse build identity, but they are
not exact-artifact authority. Both sides additionally require the matching
root-signed Gate 1A E1/E2 token with `gate_receipt_context_v1`, or the Gate 1B
isolated unit token with `gate1b_isolated_receipt_context_v1`, inside its
matching authenticated pre-provisional session, or the matching provisional
authorization and smoke or production activation context in those later modes,
from the separately pinned offline Ed25519 root and compare the running self
and connection-bound peer `kSecCodeInfoUnique` / `kSecCodeInfoCdHashes` values
with its exact per-architecture allowlist. The peer is resolved from the audit
token with `SecCodeCopyGuestWithAttributes`; PID and filesystem paths are
diagnostic only. Missing, expired, wrong-domain, wrong-capability,
wrong-artifact, provisional-only, mismatched-context, or differently signed
authority objects fail before protocol bytes or registry state are accepted.
Production, smoke, and post-grant modes reject the Gate context and retained
Gate authority branch; Gate mode rejects the later-mode contexts.

The root public key, key ID, signature domains, canonical sidecar bytes,
safe-read rules, and candidate-to-production lifecycle are fixed in
[Gate artifact authorization](gate1a-artifact-authorization.md). The private
root remains offline and absent from build and Gate hosts. The first release
has no in-band root replacement, revocation, or rollover path.

### Entitlements and Keychain namespace

Both signed nested code objects use the hardened runtime, a secure timestamp,
and no `get-task-allow` or runtime exception entitlement. Only the helper's
provisioning profile authorizes this private data-protection Keychain group:

```text
$(AppIdentifierPrefix)io.github.abigotado.youtrack-agent.approval
```

The outer app and CLI have no entitlement for that group and perform no
Keychain query for approval state. Every helper query sets
`kSecUseDataProtectionKeychain=true` and explicitly names the resolved access
group. The following identifiers are fixed:

| Item | Identifier |
| --- | --- |
| Secure Enclave signing key tag prefix | `io.github.abigotado.youtrack-agent.approval.signing.v1/` |
| approval registry service | `io.github.abigotado.youtrack-agent.approval.registry.v1` |
| approval registry account prefix | `revision/` plus a 20-digit decimal revision |
| apply-authority coordinator service | `io.github.abigotado.youtrack-agent.approval.apply-authority.v1` |
| coordinator accounts | `active`, `permit/<lease-id>`, `closed/<lease-id>` |
| per-user launchd helper job label | `io.github.abigotado.youtrack-agent.approval` |

The signing key is helper-owned P-256 Secure Enclave material. Every generation
uses a fresh 128-bit random key ID encoded as 32 lowercase hexadecimal
characters and the exact application tag formed by appending that ID to the
fixed prefix. The logical generation, key ID, full tag, DER SPKI, and
fingerprint are bound into the registry transition. Its private key
is non-exportable and requires `.privateKeyUsage` together with the accepted
fresh-presence policy. A new `LAContext` with zero reuse is bound to the actual
signing-key lookup only. Its returned `SecKey` is used exactly once with
`SecKeyCreateSignature`, which accepts no context parameter, and the context is
invalidated on every lookup or signature outcome.
Noninteractive existence and orphan-delete queries instead require
`kSecUseAuthenticationUIFail`, carry no `LAContext`, and can never sign. A separate Gate decision
must record whether the release uses `userPresence` or
`biometryCurrentSet`; there is no silent fallback between them.

The helper enumerates at most 64 keys in only that private tag namespace and
never retrieves a key by a reused tag. A candidate created before a failed or
losing registry transition is an orphan and is never eligible for signing
because no committed transition names it. After exact transition
reconciliation, orphaned and retired private keys remain non-authoritative and
are never reused. This design grants no production maintenance authority to
delete them. The orphan-delete query contract applies only to the disjoint
Gate fixture. Live release-stage cleanup is deferred; the trusted external
supervisor destroys the entire disposable host instead.
Retained public verification keys live in the ledger and do not require old
private keys. Orphaned and retired private keys still count toward the 64-key
bound. Hitting that bound fails closed; any operator cleanup requires a future,
separately specified and reviewed authority protocol.

The approval-key registry is not a profile file or one mutable item. It is a
bounded append-only, event-sourced ledger in the helper-private data-protection
Keychain group. Each canonical transition contains its schema version,
monotonic revision, predecessor-record SHA-256, artifact-descriptor SHA-256,
exact old/new key fields, accepted proposal/transcript digests, derived status,
and role-separated signatures. Retained and revoked generations are derived by
replaying the complete gap-free chain; a record never embeds a growing mutable
generation array. The exact JSON field order, grammars, limits, signature
domains, transition table, state derivation, and vectors are normative in
[Gate 1A registry and ceremony protocol](gate1a-registry-protocol.md). The
public CLI surface can request an exact active/retained record through one
bounded, peer-authenticated helper operation but cannot address Keychain items
directly. Only the helper's
challenge-bound enrollment, rotation, revocation, and recovery ceremonies may
mutate the record after trusted UI and fresh user presence.
The registry protocol also freezes every complete Security.framework call
dictionary and bounded result projection for keys, revisions, and coordinator
records. No convenience query, broad delete, legacy-Keychain fallback, or
caller-selected predicate is permitted.

The private group is an authority boundary for key use and registry mutation;
mutual peer validation and a bounded protocol are still required to prevent a
validly signed caller from turning the helper into an arbitrary Keychain
oracle. A same-user process can deny service by interfering with local IPC or
lock files, but cannot acquire the helper's group entitlement. Any entitlement
mismatch, duplicate item, noncanonical record, unexpected revision, rollback,
missing generation, access-group ambiguity, or uncertain Keychain mutation
fails closed.

### Enrollment is a separate authority transition

Ordinary approval can never enroll or replace a key. Enrollment uses a
separate protocol magic/domain and fresh 256-bit challenge, not an approval
frame or approval receipt. It is available only when no valid registry exists
and the operator explicitly starts the enrollment ceremony.

The ceremony is:

1. The CLI validates the connected helper against the pinned helper
   requirement and constructs the canonical enrollment intent without reading
   the registry.
2. The helper validates the CLI against the pinned CLI requirement before
   reading the bounded enrollment request. It acquires the fixed coordinator
   `active` item before any ledger read, including an enrollment that will be
   rejected because the registry already exists. Only under that lease may it
   verify and snapshot the empty registry.
3. Trusted helper UI displays the release identity, Team ID, generation, SPKI
   fingerprint, and the fact that a new trust root is being created.
4. Fresh user presence authorizes generation or use of the helper-only Secure
   Enclave key.
5. The helper returns the exact canonical proposal and key-possession proof
   defined by the registry protocol. They bind the generation, exact DER SPKI,
   fingerprint, challenge, artifact descriptor, expected state, and time.
6. The CLI revalidates helper identity on the same connection, verifies the
   proof and every binding, then returns the canonical challenge-bound
   acceptance message. Acceptance is live peer-authenticated ceremony evidence,
   not a CLI signature, and binds the proposal digest. It has no direct
   registry-write primitive.
7. The helper revalidates the peer and re-reads the exact empty state. It
   includes the acceptance digest in the final transition signing view, signs
   that complete view under the enrollment-activation domain, and creates
   revision 1 with `SecItemAdd` under account
   `revision/00000000000000000001`; `errSecDuplicateItem` is a conflict.
8. The CLI reads the committed record through the helper's bounded read-only
   operation and compares its exact bytes. The uninterrupted owner then
   irrevocably drops every signing/commit capability and queued callback before
   recording durable normal close and releasing its exact active item. Only
   then may it report success.

Failure or uncertain durability leaves enrollment incomplete. Normal approval
continues to fail closed; it never retries enrollment implicitly.

### Rotation, revocation, and recovery

Rotation is a separate fresh-presence ceremony bound to both the old and new
generations. After live CLI acceptance, the old key signs continuity and the
new key signs activation over separate domains and the same complete final
transition view, including the acceptance digest. The next immutable registry
transition commits both signatures and the new active generation.

Old public verification keys remain retained while any unexpired or unresolved
receipt references them. Retention authorizes verification only, never new
approvals. Revocation immediately blocks new approvals from that generation;
already confirmed plans are canceled unless a reviewed policy explicitly
allows their still-valid receipt to proceed. This first implementation chooses
the safer default: rotation or revocation cancels outstanding confirmed plans
and requires fresh preparation and approval.

Key loss has no continuity signature and therefore cannot be rotation.
Recovery is an explicit operator ceremony allowed only over an already valid,
gap-free ledger. It displays the loss of continuity, revalidates the signed
bundle, uses fresh user presence, and admits only the registry protocol's exact
disabled-ledger or `errSecItemNotFound` eligibility evidence. A returned key,
user cancellation, authentication/key-use failure, transient status, or unknown
OSStatus fails closed instead of being treated as loss. Recovery creates a
new generation, revokes all prior generations, and invalidates every existing
confirmed receipt. Recovery never silently reauthorizes a plan. Within the
current signed helper and retained current registry, an older generation
cannot become active without a new recovery ceremony.

This design does not claim cryptographic anti-rollback against an interactive
operator or administrator that installs an older legitimately signed release,
or against an administrator, backup/restore mechanism, or compromised Keychain
service that replaces the ledger with an older complete snapshot. The latter
is undetectable even by the current binary. Team ID and identifier requirements
prove publisher identity, not release or state freshness. Preventing that class
of rollback requires a separately operated monotonic service or an equivalent
external high-water mark and is outside the first release threat model.
Packaging must refuse ordinary downgrade, and Gate 1A must show that an
accidental older-app launch against the retained current registry fails closed;
neither result is described as universal anti-rollback.

### Atomic registry transitions and durable confirmation

The CLI filesystem lock order is:

```text
profile -> policy -> one plan journal
```

Registry transitions do not use a user-owned lock or `SecItemUpdate`. Every
registry commit and mutation apply first acquires the same helper-private
coordinator through a one-shot add to its fixed `active` account. The helper
binds a canonical registry-intent digest available before any ledger/proposal
work; the eventual candidate is validated later under that lease. It
holds it through the registry commit or apply's exact
`confirmed -> in_flight -> one permit -> one send/outcome -> durable close`
sequence; only then may it classify fresh bounded history and remove the active
item if capacity remains. The active, permit, closed,
quarantine, and result-projection codecs are normative in the registry
protocol. CLI filesystem locks never substitute for this cross-process
boundary. Only the original uninterrupted authenticated owner can record
normal close, after irrevocably dropping every sign, permit, send, and commit
capability, including queued callbacks. Any non-owner observing an active item
without its valid durable close returns `AUTHORITY_STATE_QUARANTINED` (exit 1):
no journal CAS, synthesized close, deletion, signing, key generation, permit,
send, or registry commit is allowed. Crash, restart, reboot, expiry, PID loss,
or trusted UI does not release it. Remote reconciliation may read and report
only, never advance its journal. First-release availability is intentionally
lost until a separately reviewed recovery protocol exists.

Strict canonical receipt parsing and low-S DER validation precede hashing or
mutable authority access. Active and closed require `receipt_sha256` for apply
and null for registry commits; each permit repeats the digest of the complete
canonical signed receipt bytes. While holding active, the helper validates ALL
bounded protected permit/closed history independently of enumeration order
before any permit. Any prior receipt digest forbids a fresh permit across
leases, even after a same-user journal restore. The global bound is one permit
per receipt. Normal null-permit aborts burn the receipt; repeated replay-denial
closes may repeat its digest only with null permit and `failed_before_mutation`.
Journal CAS provides crash bookkeeping, not same-user anti-replay protection.
Interrupted closure remains quarantine.

Registry queries allow 256 items / 2,097,152 bytes; coordinator queries separately
allow one active plus 256 permit and 256 closed items / 4,202,496 bytes, with
8,192 bytes per item. The last admitted owner must finish normal close first,
then freshly enumerate complete bounded coordinator history under retained
active. At either 256-record limit it retains its matching valid CLOSED active
as an exhaustion sentinel. Normal and recovery cleanup never delete it, including
after expiry; uncertainty also forbids deletion. This prevents a competing
helper with a stale precheck from acquiring. Capacity cannot prevent the admitted
owner's final close. A valid sentinel reports status `capacity_exhausted`,
`allowed_action=stop`, exit 0; acquire/recover returns
`AUTHORITY_CAPACITY_EXHAUSTED`/exit 1 with message `authority capacity is exhausted`
and hint `stop and request operator investigation; do not retry or delete state`.
Corruption and unclosed quarantine never become capacity success.
Capacity success requires the full validated inventory and matching valid closed
active sentinel; exhausted history with a missing or mismatched sentinel is
corrupt and never recreates a clear state.

This accepts deliberate denial of service and a 256-close lifetime, including
registry ceremonies and denied attempts. The protected access group and signed
helper enforcement are trusted; whole-Keychain rollback is excluded. The
guarantee covers this client's guarded transport, not independent credential use.
No retention, extra signature, presence reuse, or authority cache is introduced.

For an already normally closed lease, an exact lookup returns the attributes,
canonical data, and nonempty CFData persistent reference bounded to 4,096
bytes. Cleanup validates the complete active/permit/closed and terminal-state
bindings and freshly checks full bounded history for capacity, then deletes
only a non-sentinel reference using `kSecMatchItemList`, never an
attributes-only predicate. If A was removed and B acquired after the lookup,
deleting A's stale reference cannot delete B; A's absence is a stale no-op.
Malformed or conflicting evidence quarantines. The helper enumerates registry
revisions only in the fixed registry service and private access group with
match-limit-all, caps the result at 256 revisions, sorts and validates every
canonical account and record, and requires one gap-free hash chain beginning at
revision 1. Missing, duplicate, malformed, forked, out-of-range, or trailing
records fail closed.

To move from revision N to N+1, the helper re-reads that chain, verifies the
expected revision and predecessor digest, then performs exactly one
`SecItemAdd` under account `revision/%020d`. Keychain's unique
service/account/access-group identity makes concurrent candidates contend for
the same new item: one add can win and every different candidate receives
`errSecDuplicateItem`. The helper then reads that exact account and
byte-compares it before reporting success. After an error or crash-ambiguous
add, reconciliation reads once: the exact intended bytes are success, absence
is a failed uncommitted ceremony, and different bytes are a conflict. It never
repeats an add automatically and never mutates or deletes a ledger revision.
These are observations of the add result, not permission for a replacement
actor to close or release an unclosed lease, or to report the whole ceremony
completed while it remains quarantined.
Reaching the 256-record bound fails closed pending a separately reviewed ledger
migration; compaction is not implicit.

Confirmation snapshots the profile, policy, and plan revision under that
order, obtains the exact registry revision and key generation through the
helper, then releases all journal locks before
opening trusted UI. After approval it reacquires the same locks, revalidates
every snapshot and the signed receipt, and performs one revision CAS from
`prepared` to `confirmed`. No UI or remote request runs while a journal lock is
held. Any later registry transition invalidates the receipt at the next helper
validation. No remote executor may be distributed or used outside its
controlled unpublished Gate candidate until Gate 1B selects and proves the
exact coordinator ordering between apply and concurrent enrollment, rotation,
revocation, or recovery; Gate 1A does not claim that cross-boundary guarantee.

The journal stores the complete canonical signed receipt, an exact copy of the
verification SPKI, and one closed stage-tagged authority set with all exact
canonical bytes and digests—not only digest labels. Production and post-grant
sets contain the descriptor, signed provisional authorization, signed
activation grant, and final context. A pre-grant smoke set instead contains the
descriptor, signed provisional authorization, signed smoke token, provisional
context, and smoke receipt context; it contains no grant and any hard-denied
`in_flight` attempt is moved to the non-reconcilable terminal state
`activation_smoke_consumed`. A pre-provisional Gate 1A set instead contains
the exact descriptor, signed Gate token, canonical `gate_receipt_context_v1`,
and complete bounded genesis-to-current registry chain required to derive the
receipt key; it contains no provisional, smoke, grant, final-context, or
production authority. Gate 1B instead retains
`gate1b_isolated_authority_evidence_v1` from the isolated-subrun ADR, including
its unit token, new context and exact unit/host/target/inventory binding as well
as the complete registry chain; it never accepts the old single-suite Gate
object. Confirmation stores the matching set in the same
revision CAS that moves `prepared` to `confirmed`. Apply reopens and fully
revalidates those bytes against the pinned root and current stage context, then
carries the unchanged set through the atomic `confirmed -> in_flight`
transition. The copies are binding evidence, never trust roots. Audit may
reparse every closed branch; ordinary reconciliation accepts only production/
post-grant sets for already `in_flight` ordinary work and never accepts a smoke
or Gate set. Controlled Gate 1B reconciliation accepts its Gate branch only
under the still-authenticated matching runner/session and only for bounded
reads. The verifier applies protocol bounds and rebuilds the matching pinned-
root chain. For Gate, it verifies the signed token/context tuple and replays the
complete retained registry chain to derive the SPKI; a lone final record or
caller-selected SPKI cannot authenticate the receipt. For later modes it
rebuilds either the descriptor/provisional/smoke-token/context or descriptor/
provisional/grant/final-context chain and capability. A Gate token that expired
after the recorded live boundary remains historical evidence, but no
historical result authorizes a new confirmation, permit, send, or network
mutation.

For production/post-grant apply authorization, the signed receipt's registry revision must equal the
current complete ledger revision and its generation, SPKI, and fingerprint
must equal the one current `active` generation. Its authorization-context
digest must equal the currently active provisional-authorization/activation-
grant pair. The current status must explicitly permit apply. Any intervening
registry or activation transition makes a still-confirmed receipt ineligible;
status/apply cancels the plan rather than falling back to retained authority.
The controlled Gate 1B apply path enforces the same current-registry checks but
requires exact `gate1b_isolated_receipt_context_v1`, an unexpired isolated-unit
token and its matching runner session instead of any provisional/grant pair.
The reboot observer segment cannot apply, sign or reconcile remotely; it only
observes local quarantine under its separate scoped token. Gate 1A remains network-free.
Each helper uses a non-reentrant serialized executor only for its own process.
The fixed Keychain active record is the cross-process lock, including against
another exact signed helper in a different user bootstrap context. The owner
retains its local guard and coordinator, revalidates the unexpired embedded
profile
and every authority value, observes the durable `confirmed -> in_flight` CAS,
then creates exactly one request-bound permit. That permit is the sole send
linearization point. A registry transition that acquires first closes before
apply revalidation and cancels the stale receipt; an apply that acquires first
excludes registry commits until it has irreversibly quiesced all send/sign/
commit capabilities and persisted its valid normal closed record. A crash
before close leaves the lease quarantined: permit absence can prove no
mutation was authorized, but does not authorize another actor to terminalize
the journal or release the lease. A crash at or after permit is ambiguous and
never retried. Profile expiry before acquisition closes
`confirmed -> expired`; expiry after acquisition with no permit lets only the
uninterrupted owner burn the receipt and close `failed_before_mutation` with
zero dispatch after quiescence. A replacement actor must quarantine instead.
For normal apply close, `failed_before_mutation` is valid if and only if no
permit exists. After permit issuance, verified success closes `applied`; any
other result, even proven zero-byte denial, closes `ambiguous`. Later eligible
read-only reconciliation may report `resolved_not_applied`, without rewriting
protected history or restoring permit authority.
After the durable `confirmed -> in_flight`
transition, reconciliation verifies
the persisted historical key and authorization context but does not require
either to remain active. Rotation/revocation races before confirmation,
between confirmation and apply, at the in-flight/permit boundary, during send,
and across helper restart are closed Gate 1B cases. A dedicated ABA case uses
independent exact signed helper processes: A is removed and B acquired between
the cleanup lookup and deletion, and deletion by A's persistent reference must
leave B unchanged. A paused unclosed owner is never recovered by the competing
helper. Gate 1B must pass them
before the executor candidate is qualified for any use beyond that controlled
Gate run.

This durable confirmation implementation and the native adapter must exist
before Gate 1A. The current repository remains wired to
`approval.Unsupported`, but the exact signed Gate candidate must wire the
native adapter through `application.NewDefault` and exercise the ordinary
production `mutation confirm` entry point while every remote executor remains
disabled. If either complete Gate pass fails, that candidate is discarded. The
first complete run is E1 evidence only, not production authority. Distinct
runner/session-bound E2 tokens then drive the complete suite again after a
clean reset. E1 and E2 run with fresh tokens on every declared architecture.
Only after both complete evidence sets pass may the offline root sign a
capability-specific provisional authorization, which still denies ordinary
production use. A final network-disabled black-box activation smoke runs under
fresh per-architecture deny-only tokens. Each capability plan begins with one
token/context-limited exact-artifact enrollment from a retained canonical
empty inventory, binds the resulting revision-1/generation-1 registry snapshot
to every later observation and both evidence-index layers, and ends by
retaining terminal and export evidence. The trusted external supervisor then
destroys the entire disposable host. Only its complete passing evidence and
root-bound disposal attestation
set permits the offline root to sign the production activation grant. The
exact artifact then loads that grant and provisional authorization and repeats
the same setup-first, export-and-host-disposal discipline plus the ordinary capability path
on every architecture under separate deny-only post-grant runner tokens. Every
case passes only through a final runner evaluation after all operation and
transcript results exist. Only the publication envelope may bind that later
evidence. The envelope is then packaged with the bound plan and complete
evidence tree; because it does not hash its containing delivery archive, this
creates no hash cycle. The exact sequence and failure quarantine are normative
in
[Gate artifact authorization](gate1a-artifact-authorization.md). No post-Gate
rebuild or wiring change inherits this evidence.

Live `stage_cleanup`, cleanup intent/progress, and ACK-ledger deletion authority
are deferred from the first release. Setup, receipt, and production contexts
grant no deletion privilege. The runner exports only the closed allowlisted
evidence, never mutable Keychain, journal, session, credential, or private-key
state. A trusted supervisor outside the disposable host destroys that entire
host on success or failure and supplies the artifact protocol's root-bound
disposal attestation. Smoke disposal must precede activation-grant signing;
post-grant disposal must precede publication-envelope signing. No missing
attestation, runner self-report, empty-inventory claim, partial cleanup, or
reused host may pass either transition.

The shared Go and Swift receipt contract implements schema v3 as specified in
[Gate 1A approval protocol](gate1a-protocol.md#implemented-schema-v3-delta), with
new cross-language golden vectors and rejection of historical v2 receipts.
Expected revision/context bindings compare claims only; complete registry and
authorization-chain verification, journal v2, durable confirmation, and the
native helper remain unimplemented. These codecs are not activation authority.
No v2 receipt has been released, so there is no compatibility fallback.

### First-release, rollover, rollback, and uninstall

The canonical artifact descriptor binds the outer/helper identifiers, Team ID,
semantic requirements and entitlements, access-group name, item identifiers,
architecture set, version/build number, every architecture's exact Apple code
identity, hashes of both executable files, and the helper's embedded Developer
ID provisioning-profile hash and exact expiry. The profile must authorize the helper App ID,
Team ID, and exact `keychain-access-groups` entitlement. It must be valid for
Developer ID distribution and unexpired at signing and both Gate executions. The
nested helper is signed with the profile at
`Contents/embedded.provisionprofile`; the outer bundle is signed afterward.
The exact application payload is notarized and stapled before descriptor
creation. Executable/resource hashes are evidence; runtime authority comes
from Security.framework validity plus exact signed code identities and the
offline-root authorization.
The descriptor's `helper_profile_expires_at` is an absolute cutoff with no
grace or cached-success exception. Gate token use, grant/envelope signing,
publication, installation, peer acceptance, confirmation, coordinator
acquisition, registry proposal signing, registry final signing, registry
commit, permit issuance, and the final pre-send fence each require the trusted
current time to be strictly earlier. Evidence captured before expiry
cannot authorize an operation at or after it.

The sole exception is launch/peer authentication into an explicitly
recovery-only helper session for bounded startup/status classification. If the
profile is expired and no active record exists, it returns
`HELPER_PROFILE_EXPIRED` with exit 12, never successful `authority_status=clear`,
and closes. This expiry result also precedes ordinary no-active recover denial.
Successful post-expiry status requires a validated already-closed active record;
an exhaustion sentinel advertises `capacity_exhausted`/`stop`, while another
valid closed record advertises only its restricted cleanup path.
Recovery-only classification continues only for the same exact descriptor and
retained evidence. An unclosed active record remains quarantined with no
mutations. A valid already-closed record permits only exact persistent-reference
active cleanup only below capacity; an exhaustion sentinel cannot be deleted.
Recovery cancellation keeps exit 11 and never retries automatically; a later
operator-requested attempt requires fresh presence. The session may not synthesize
close or perform journal CAS. It cannot
enter ordinary confirmation/registry/apply authority, sign, acquire, permit,
construct transport, or send; it closes when classification/cleanup finishes.

The first production release has no supported predecessor and no supported
write-capable in-place upgrade. Exact-build requirements make a current
CLI/helper reject a mixed-version peer. They do not prevent a side-loaded older
matched pair from trusting itself and accessing a stable entitlement group.
Package downgrade refusal is therefore an operational guard, not release
freshness enforcement.

A second write-capable release is prohibited until a separate accepted ADR and
Gate define release rollover for approval keys, registry state, every YouTrack
credential, stale access-token expiry/revocation, side-loaded old binaries, and
crash recovery. A future design may use release-specific entitlement groups and
explicit user-authorized migration or an external monotonic authority; this ADR
does not choose one. Reinstalling the identical first-release artifact is
allowed, but no Cask update may cross to a different build before that rollover
gate passes.

The helper can validate only the complete ledger presented by Keychain;
without an external monotonic authority it cannot detect restoration of an
older complete ledger snapshot, even when the current binary remains installed.
That restoration and execution of a hypothetical older matched signed pair are
explicitly outside the first-release claim. An unsigned, differently signed,
or mixed-build binary/helper replacement breaks peer validation before
approval.

Uninstall removes the application bundle but does not silently delete or
migrate approval keys, registry state, credentials, or journals. Destructive
cleanup is a separate explicit operator action. A Homebrew hook may not grant
new Keychain access or run enrollment.

## Required evidence and activation order

Before Gate 1A can pass, an operator-controlled Developer ID Application
identity must produce an exact hardened-runtime bundle and the offline root
must authorize only a bounded Gate-runner session for that descriptor. A
black-box Gate
harness must launch and drive the CLI contained in that bundle; it never links
the adapter, injects a peer, changes a requirement, or receives Keychain
entitlements. The candidate's normal production factory already wires the
native adapter, and the harness exercises the ordinary `mutation confirm`
entry point while all remote executors remain disabled. A dedicated
non-writing self-test surface may cover additional local faults but is not a
substitute for that production path. Against that exact artifact, the harness
exercises enrollment, approval, durable journal CAS, cancellation, timeout,
process crash, production peer replacement, rotation, revocation, recovery,
the closed first-install/identical-reinstall/rollback/replacement/uninstall
case set, and the closed Keychain-migration cancellation/interruption/partial-
failure case set on a supported clean Mac. The app-only payload archive used by
every install case is produced and retained before descriptor creation and E1;
no install or reinstall case may reconstruct it. A separately signed,
never-shipped old-build fixture with the production IDs proves both current
peers reject mixed-build connections; the report also records that a matched
old pair is not prevented by this first-release topology. The fixture is
created only inside the disposable Gate environment, is not notarized or
archived, and is destroyed with that environment. `codesign`, `spctl`,
notarization, stapling,
entitlements, Team ID, architecture, requirement, Apple CodeDirectory
identities, and embedded-profile CMS/App ID/Team ID/expiry/entitlement checks
all refer to that same artifact. E1 and clean-reset E2 each run the complete
suite with independent fresh runner sessions; neither Gate-only token is valid
for a production peer.

Registry corruption, fork/gap/duplicate parsing, crash-ambiguous `SecItemAdd`,
orphan-key cleanup, and active-key loss require access that the black-box
harness intentionally lacks. Those cases use a separately built and signed
fixture from the same reviewed commit, with bundle IDs, access group, key tags,
registry service, and peer requirements under the disjoint
`io.github.abigotado.youtrack-agent.gate1a.fixture` namespace. Its helper alone
exposes bounded fault operations, accepts only the Gate runner identity, and
stores data only in the disposable fixture group. Fixture code and
entitlements are compile-time absent from the production target; the fixture
is never embedded, notarized, shipped, installed by Cask, or accepted by a
production requirement. Gate reporting labels exact-artifact and fixture
evidence separately and does not present fixture results as production
artifact execution.

The separate Gate runner identity is diagnostic orchestration only and is
never accepted as the production helper's protocol peer. A Gate run uses a
disposable whole host or VM, destroyed by the external supervisor after evidence
export; deleting a user or selected fixture Keychain entries is insufficient.

Gate 1A provisional authorization names only `confirm_only` but enables no
ordinary command by itself. Its content-addressed smoke workflow drives the
ordinary `mutation confirm` command and proves every apply path remains
disabled on every declared architecture. Only the later activation grant makes
confirmation available in production. Gate 1A qualifies only the exact
native-approval candidate. The
current REST
executor stays disabled. A later exact signed candidate must wire the ordinary
production `mutation apply` entry point for only `issue.create` and pass live
Gate 1B through the complete materialized
[isolated-unit inventory](gate1b-isolated-subruns.md), using a distinct disposable
YouTrack 2026.2 project and fresh host for every unit/architecture/pass, with
E2 bound to the complete disposed E1 parent. Because wiring the executor
changes the artifact, that same candidate must first rerun and pass Gate 1A.
Gate 1B then proves exact identity/preconditions, one-shot execution, the
helper-owned coordinator's apply-versus-rotate/revoke/recovery linearization, every
before/after-permit crash boundary, invalid-enrollment contention before any
ledger read, crash after durable outcome but before close, ambiguous close add,
crash after close but before active deletion, ambiguous active deletion,
unclosed-owner quarantine and persistent-reference ABA safety, and bounded ambiguous-outcome
reconciliation. Its content-addressed two-party schedules and traces use exact
barrier events rather than wall-clock sleeps.
After its two complete Gate evidence sets, the root signs only a provisional
`issue_create` authorization. The per-architecture smoke workflow then drives
the ordinary prepare, confirm, and `youtrack-agent-cli --profile work mutation
apply --plan-id <issue-create-plan-id>` path on a network-isolated host. Only
the expected loopback read-only preflight is allowed; an instrumented mutating
dispatch boundary returns the unique post-authorization hard-deny result and
records zero mutating-request bytes. Wrong capability, tampered provisional
authorization, wrong artifact, expired or mismatched smoke token,
`issue.update`, and `comment.add` fail before dispatch. Smoke receipts bind a
disjoint authorization context and cannot be replayed after activation. A
failed candidate is discarded; only the complete smoke evidence set permits a
production activation grant. The exact grant-bound production context then
passes a second per-architecture ordinary-command verification with final-
context receipts and the same safe pre-socket mutation denial. The grant is
cryptographically usable during this bounded step, so the disposable Gate host
and release operator are trusted to quarantine the grant and candidate after
any failure. Every run ends in externally attested destruction of the whole
disposable host; a failed run's output never becomes passing evidence. No
live deletion protocol or empty-inventory proof substitutes for disposal.
A passing candidate is published byte-for-byte with no post-Gate
activation edit.

Public Homebrew distribution is last. The accepted shape is a Cask or private
tap whose literal SHA-256 pins the outer delivery archive containing the
immutable app payload, detached provisional authorization and production
activation grant, root-signed publication envelope, exact post-grant plan, and
complete closed evidence-set tree. The envelope binds the payload, both
authority objects, E1/E2 evidence sets, activation-smoke evidence set, and
complete post-grant verification evidence set; the Cask checksum separately
pins the containing archive bytes without a recursive hash cycle. The Cask
installs those exact bytes under one versioned root and links the contained CLI;
a source Formula cannot rebuild the helper or establish its production code
identity.

## Consequences

- The project can implement durable confirmation and exercise the native
  adapter through a non-writing Gate self-test without granting remote write
  authority.
- A real Team ID is absent from source and cannot be guessed; an unset release
  configuration fails before signing, enrollment, or approval.
- The first release can be evaluated and installed, but publishing a second
  write-capable build is blocked on an explicit key-and-credential rollover
  design.
- Enrollment, rotation, recovery, approval, and mutation execution are distinct
  authority transitions with distinct domains and journal effects.
- The native bundle is macOS-only. Unsupported platforms and unsigned local
  source builds retain the fail-closed adapter.
- An unclosed owner crash can block all further guarded writes indefinitely;
  restart, reboot, and fresh user presence are deliberately not recovery
  authority. Read-only operation remains available.

## Evidence sources

- Apple: [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice), [`agent(plistName:)`](https://developer.apple.com/documentation/servicemanagement/smappservice/agent(plistname:)), and [Updating helper executables from earlier versions of macOS](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)
- Apple: [Defining launch environment and library constraints](https://developer.apple.com/documentation/security/defining-launch-environment-and-library-constraints)
- Apple: [`SecItemDelete`](https://developer.apple.com/documentation/security/secitemdelete(_:)) and [`kSecMatchItemList`](https://developer.apple.com/documentation/security/ksecmatchitemlist)

- Apple: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- Apple: [`errSecDuplicateItem` and Keychain composite primary keys](https://developer.apple.com/documentation/security/errsecduplicateitem)
- Apple: [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- Apple: [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- Apple: [Generating new cryptographic keys](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys)
- Apple: [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- Apple: [TN3127: Inside Code Signing: Requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
- Apple: [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
- Apple: [`kSecCodeInfoUnique`](https://developer.apple.com/documentation/security/kseccodeinfounique) and [`kSecCodeInfoCdHashes`](https://developer.apple.com/documentation/security/kseccodeinfocdhashes)
- Apple: [`SecCodeCopyGuestWithAttributes`](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)) and [guest attribute keys](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys)
- Apple XNU: [`LOCAL_PEERTOKEN` in `sys/un.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h)
- Apple: [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- Homebrew: [Cask Cookbook](https://docs.brew.sh/Cask-Cookbook#stanza-binary)

## Rejected alternatives

- approval-time TOFU or a response-selected verification key;
- plaintext, profile, journal, mode-`0600`, environment, or CLI-argument trust
  roots;
- one shared protocol domain for enrollment and approval;
- an agent-visible `--yes`, stdin, PTY, environment, or browser approval path;
- silent key recovery, Keychain migration, or receipt reauthorization;
- path/PID-only peer trust;
- ad-hoc signing as production evidence;
- a source-built Formula or post-install hook that re-signs the helper.
