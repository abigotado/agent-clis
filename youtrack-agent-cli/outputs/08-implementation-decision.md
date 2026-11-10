# Implementation decision: align with the existing CLI harness without weakening write approval

Scope update: the signed-helper requirements below remain the strict native
`mutation` design. The accepted [operator-write decision](../docs/operator-writes.md)
adds a distinct lower-assurance mode to the standard Formula without claiming
Gate activation. Source support is not an installed release. The ordinary
read-capable Formula is already published.

- Status: Accepted and implemented through the fail-closed first slice
- Date: 2026-09-02
- Target module: `github.com/abigotado/youtrack-agent-cli`
- Target binary: `youtrack-agent-cli`
- Target Agent Skill: `youtrack-agent`

Current mutation boundary: offline `prepare`, local `export`, and local
`status` only. `confirm`, `apply`, and `reconcile` fail closed; native authority
commands and the workflow/state transitions below remain future requirements.

The [isolated-subrun ADR](../docs/gate1b-isolated-subruns.md) specifies the new
Gate 1B topology and supersedes single-suite Gate 1B authority objects. A
quarantined unit never resets into another scenario under the same enrollment;
only its narrowly scoped read-only reboot observer may inspect preserved state.
The full unit inventory, validators, and native evidence remain unimplemented;
Gate token/digest freeze, activation and publication cannot proceed on the
historical coverage catalog alone.

## Reuse baseline

Use the clean `confluence-cli` `main` revision `fea3152` as the canonical source for the provider-neutral harness, JSON v1 envelope, panic recovery, bounded output, direct Security.framework Keychain adapter, atomic registries, lockfiles, embedded skill installer, generated command/contract documentation, and CI. Distribution remains explicitly disabled until Gate 1A passes with the frozen trust/package topology and an audited signed and notarized macOS package; the inherited portable archive and Homebrew paths are not safe defaults for this credential-bearing CLI. Homebrew dependency metadata and validation may be prepared before that gate, but an installable Formula/Cask and every tap publication path remain forbidden.

Use the current `jira-cli` feature branch only as a reviewed source for issue/project modeling, exact project policy, and centralized one-shot HTTP request policy. Do not copy the dirty `trello-cli` worktree.

The official YouTrack Remote MCP remains the routine read plane. Its URL must carry the exact positive `tools=` list, while the host independently restricts the same six names. The bare endpoint is not classified read-only because official YouTrack documentation simultaneously claims predefined tools are read-only and lists mutating tools.

When MCP comments are unavailable, the standard CLI permits one exact-issue
comments page with an explicit profile, limit 1..100 and nonnegative offset.
Bound-account verification precedes one bounded comments page from the fixed
GET endpoint with a limit+1 truncation sentinel; no additional pages are
auto-fetched. Returned comments are untrusted
content and prove neither ordering, currentness, a stable snapshot, complete
history, nor reconciliation evidence. The portable and macOS identity editions
remain MCP-only; this exception does not change the six-tool MCP or guarded-write
boundaries.

## Gate 1A: approval feasibility before remote writes

`LocalAuthentication` can prove a local authentication event, but its short reason string cannot prove that the operator reviewed the complete canonical plan. The existing CLI `--confirm-intent ... --yes` flow is therefore not reused as authority for YouTrack mutations.

Before implementing an enabled `mutation confirm` or `mutation apply`, a macOS feasibility spike must demonstrate all of the following on a supported Mac:

1. A separately signed native helper displays the complete bounded canonical snapshot from one immutable in-memory byte buffer.
2. Only after a fresh LocalAuthentication success, the helper stores the digest of exactly those displayed bytes in `receipt.plan_sha256` and signs the deterministic unsigned receipt from `approval.SigningBytes`, including the exact current approval-registry revision/active key and SHA-256 of the fresh IPC challenge; authentication reuse is disabled.
3. The on-device P-256 private key is non-exportable, has a documented tag and public-key fingerprint, and cannot be used by an unrelated same-user process.
4. Cancellation, timeout, helper crash, binary replacement, key rotation,
   mixed-build peers, and identical reinstall fail closed or preserve the
   first-release boundary. A second write-capable release is blocked on a
   separate rollover design.
5. The CLI verifies the helper code identity, enrolled key, receipt signature,
   signed request challenge, plan digest, TTL, nonce, profile identity, and key
   generation. Exact code identity means Security.framework validity plus the
   offline-root-authorized per-architecture `kSecCodeInfoUnique` /
   `kSecCodeInfoCdHashes` set, not Team ID/build alone.
6. First-install, identical-reinstall, and rollback-refusal paths preserve the
   required code-signing identity and entitlements. Development or ad-hoc
   signing is not accepted as production evidence.

The [registry/ceremony protocol](../docs/gate1a-registry-protocol.md) freezes
every authority-bearing transition byte. The
[artifact-authorization protocol](../docs/gate1a-artifact-authorization.md)
freezes the pinned Ed25519 root, exact descriptor, per-architecture
runner/session-bound E1 and E2 full Gate evidence sets, post-E2 provisional
authorization, pre-grant deny-only smoke, production activation grant, and a
separate per-architecture verification of the real grant-bound production
context before publication. A Gate token or provisional authorization is never
production authority.

## Homebrew activation gate

An ordinary source-built Homebrew Formula cannot establish or preserve the
separately signed native helper's designated requirement and entitlements.
Homebrew therefore remains unavailable before Gate 1A even though the
non-writing CLI surface can be built locally.

The accepted [trust-root topology](../docs/gate1a-trust-root.md) now chooses one
signed/notarized `YouTrackAgent.app` delivered later by Cask or private tap.
Homebrew may link the contained CLI but may not build, replace, extract, or
re-sign the helper. Gate 1A must prove immutable CLI/helper provenance and that
first install, identical reinstall, rollback refusal, and replacement preserve
identity or fail closed. The future Cask pins the exact outer archive SHA-256
and installs the detached descriptor, provisional authorization, activation
grant, root-signed publication envelope, exact post-grant plan, and complete
evidence tree at their fixed support paths. It never fetches verification
assets after extraction and never uses `sha256 :no_check`. The root envelope
binds the security-relevant contents while the Cask separately pins its
containing archive without a recursive hash. It does not authorize a second
write-capable build.

Both activation-smoke capability plans and both post-grant plans are now
setup-first and export-last. A stage token plus derived setup-only context may
perform exactly one revision-1 exact-artifact enrollment after canonical empty
registry/coordinator/key/journal/session inventories pass. The retained
generation/SPKI/fingerprint/descriptor/session snapshot binds every later
observation, per-architecture index, and complete evidence set. Operation
observations carry empty assertion IDs; only the separate case-final runner
evaluation may emit the ordered aggregate after all transcripts exist. Every
failure invalidates the run; the trusted external supervisor destroys the
whole disposable host. Successful exported evidence likewise requires whole-
host destruction before a successor release signature.

Gate 1B independently enrolls each fresh unit host in each E1/E2 pass and
architecture. Its leaf baseline records that unit's provenance; the offline
parent aggregates exact compiled coverage without flattening sessions or
baselines. Planned registry transitions retain their own successor evidence.
Gate 1B does not acquire release-stage cleanup authority.

Live `stage_cleanup`, item-deletion authority, ACK-ledger recovery, and signed
empty-inventory cleanup proofs are deferred. The compiled stage policy is
`external_whole_host_disposal_v1`: export only sanitized evidence, destroy the
entire disposable host through the trusted external supervisor, then retain a
root-signed disposal attestation bound to the descriptor, token digest,
architecture, runner/session, evidence index, and export manifest. The evidence
set references that later attestation; the earlier index does not, avoiding a
hash cycle. Activation-grant signing follows smoke disposal; publication-
envelope signing follows post-grant disposal. Uncertainty permits neither
successor signature nor host reuse. This is an explicit release-operator trust
boundary, not evidence produced by the candidate helper about its own cleanup.

The same gate must test the first Cask install path against the application-
bound Keychain ACL. Install hooks must not silently reauthorize credentials;
the only permitted initial migration is the operator-invoked
`auth migrate-keychain --profile NAME --yes` flow, with cancellation and
partial failure covered. The repository now has committed source and a remote,
but no immutable release tag, signed archive checksum, installed Developer ID
Application identity, pinned-root provisional/activation authority, or
notarization evidence, so it cannot provide release
provenance for an active Cask.

A later write-capable Cask version is prohibited until a separate rollover ADR
and Gate cover side-loaded older matched pairs, approval keys and registry,
credential migration, and stale access-token expiry or revocation.

If Gate 1A cannot be proven without access to an operator-controlled signing identity, the first coherent release includes profile/auth/inspect, the Remote MCP skill/configuration, offline prepare/export/status, and the complete fail-closed journal schema. `confirm` and `apply` return `USER_PRESENCE_UNAVAILABLE`; no PTY, stdin, environment, Keychain-password, or `--yes` fallback exists.

## Compile-time dependency DAG

```text
cmd/youtrack-agent-cli -> cli
cli -> {application, output, errx}

application -> {profile, auth, oauth, writepolicy, intent, mutation,
                approval, journal, skills, youtrack, restexec, reconcile}

mutation -> {intent, errx}
intent -> {endpoint, protocolvalue}
restexec -> {mutation, youtrack, errx}
reconcile -> {mutation, youtrack, errx}
approval -> {intent, protocolvalue, errx}
journal -> {intent, lockfile, errx}
auth -> {profile, lockfile, errx}
oauth -> {endpoint, errx}
youtrack -> {endpoint, errx}
writepolicy -> {profile, lockfile, errx}
profile -> {endpoint, lockfile, errx}
skills -> {assets, lockfile, errx}
output -> errx
endpoint -> protocolvalue
protocolvalue -> standard library only
lockfile -> errx
errx -> standard library only
```

`application` is the only orchestration owner. `cli` parses and renders only. `mutation` owns consumer-defined interfaces whose concrete implementations are injected by `application`:

- `Executor`: preflight plus exactly one typed execute operation;
- `Reconciler`: bounded read-only evidence collection;
- `Approver`: invoke the display/sign boundary for one exact canonical snapshot, with no receipt-verification or journal access;
- `Journal`: compare-and-swap transitions under one transaction API;
- `CredentialProvider` and `PolicyChecker`: minimum operations needed by the application service.

The combined `approval.DecodeAndValidateIPCResponse` decoder is the sole response-acceptance path. Current v2 binds the request challenge, exact snapshot, key generation, and fingerprint and verifies against the expected SPKI. Registry-revision and authorization-context binding require future v3; current codec checks are not native authority evidence. The interfaces contain at most one to three methods. `internal/youtrack` is a fixed-origin transport/model boundary and imports neither profile nor auth. `internal/cli` does not import `net/http`. Architecture tests enumerate allowed internal edges and fail on every unlisted dependency.

## Journal transaction and lock contract

All durable mutation operations use one journal transaction API with revision-based compare-and-swap. When multiple locks are needed, the global order is profile, policy, then one plan/receipt journal lock. Subsets preserve that order. No remote request or approval UI runs while the journal file lock is held.

Native authority requires canonical journal record version 2 with exact authority evidence and raw canonical active/permit/normal-close bytes. Only the uninterrupted owner may persist the normal terminal outcome and close bytes after irrevocably quiescing its send/sign/commit capabilities, including queued callbacks. A replacement process cannot synthesize a close or mutate this journal. A strict atomic migration admits only a valid v1 `prepared` record with zero attempts, no receipt, no outcome, and no evidence—the only safe state actually producible by the shipped fail-closed path. Every other valid v1 state, explicitly including `canceled`, `expired`, and `failed_before_mutation`, is retained unchanged and quarantined with `JOURNAL_V1_AUTHORITY_STATE_QUARANTINED`; a valid v1 `failed_before_mutation` has a receipt, one attempt, and an outcome and is never treated as local zero-attempt state. The current `approval.Unsupported` boundary means no v1 authority state can be legitimate current authority.

`prepare` acquires profile, policy, and journal locks, commits the authoritative canonical plan as `prepared`, then exports a 0600 copy. Export failure does not erase or duplicate the journal record.

`confirm` has two phases. It first snapshots the prepared plan under profile/policy/journal locks and releases all locks. The native helper displays that one immutable snapshot, hashes those exact bytes into the receipt, and signs the deterministic unsigned receipt together with the current registry revision, active key identity, and applicable mode-bound authorization-context digest. The service reacquires the locks in the same order, revalidates unchanged identity, policy, plan hash, state, journal revision, registry revision, active key, descriptor and the complete applicable authority branch and derived context. It then atomically stores the receipt, exact canonical authority objects/context and all digests, and moves to `confirmed`. Concurrent confirmation loses the compare-and-swap and cannot mint a second usable receipt.

`apply` holds the profile and policy locks while it validates the bound credential and remote preconditions. Historical verification with retained key or authority bytes is audit evidence only. Apply authority requires the signed receipt's registry revision and generation/SPKI/fingerprint to equal the current active registry entry and its context digest to equal the currently valid mode-bound authority set. Any intervening registry or activation transition cancels a confirmed plan. After bounded read-only coordinator integrity/capacity classification, and before registry-ledger reads, apply contends on the helper-private fixed-active Keychain account also required by every registry commit. Its unique add is the cross-process mutex; SMAppService registration and a local executor guard do not exclude another same-user helper or bootstrap namespace. The uninterrupted owner retains its lease through exact revalidation, `confirmed -> in_flight`, one exact-request permit, one send/outcome, irreversible capability quiescence, and durable normal close. Registry-first cancels stale confirmation; apply-first excludes registry commits through close. A proven owner abort before permit may close `failed_before_mutation`; a crash without durable close instead quarantines the lease. Uncertainty at/after permit is ambiguous and never retried. Audit-token, helper-session, lease, journal-revision, registry, context, and expiry fences are repeated immediately before send.

`reconcile` verifies retained historical receipt, descriptor, applicable authority branch, context, registry chain, hashes, and capability without making them current authority. While any active lease lacks a valid durable close, reconciliation performs bounded remote reads and reports evidence only: no journal/evidence CAS, terminal transition, signing, or replay. A separately eligible already-closed record may use the normal evidence CAS contract. Terminal states return their existing record without additional network activity unless the operator explicitly requests fresh evidence collection.

Coordinator recovery authenticates exact peers but cannot fence a still-live predecessor. An active lease without a valid durable normal close returns `AUTHORITY_STATE_QUARANTINED` (existing exit 1) with no local mutation, including after restart, reboot, expiry, or fresh user presence. Automated recovery/reset of such a lease is deferred and can leave guarded writes unavailable indefinitely. Cleanup of an already-closed lease validates full active/permit/closed linkage and reads attributes, bytes, and a bounded persistent reference in the same exact query. It deletes only that reference through `kSecMatchItemList`, never the reusable account name. If another helper removes A and acquires B, stale A deletion is a harmless no-op; no journal CAS or close synthesis occurs. Expiry admits only this limited authenticated inspection/closed cleanup, never new authority.

## Complete state table

Protected active and normal-close records bind the exact signed-receipt digest.
Before a new lease can consume a receipt, the helper scans protected history
and rejects its reuse, including a prior null-permit close that burned it.
Restoring journal bytes or winning a journal CAS cannot restore authority.
The complete constraints are in the [registry protocol](../docs/gate1a-registry-protocol.md).

When the last owner reaches 256 permits or closes, it must still durably close
and retain its valid closed active item as the capacity sentinel. Status reports
`capacity_exhausted`, action `stop`, exit 0; acquisition/recovery returns
`AUTHORITY_CAPACITY_EXHAUSTED`, existing exit 1, without deleting that sentinel.

The applicable authority set is mutually exclusive by mode: production and
post-grant use provisional authorization plus activation grant and final context;
Gate 1A uses its E1/E2 token and context; Gate 1B uses the isolated-unit token,
context and authority evidence from the new ADR. Both require their matching
authenticated live session and full registry chain (Gate 1A remains
confirmation-only). Gate 1B's reboot observer cannot resume this authority.
Activation smoke uses its closed provisional/smoke
branch. Confirmation and apply require live authority. Historical validation
reconstructs the retained branch; Gate reconciliation remains confined to its
authenticated runner/session and cannot create a new permit or send.

Every owner transition below requires the original uninterrupted owning
connection. If it is lost before a valid durable normal close, quarantine takes
precedence: preserve all journal bytes and allow only bounded remote reads and
reporting. Neither expiry nor an apparently absent permit proves the old
process has stopped. Reconciliation/operator-resolution CAS rows apply only to
already-closed eligible records, never to quarantined authority.

| From | Event | To | Recovery semantics |
|---|---|---|---|
| none | valid offline prepare committed | `prepared` | Export can be repeated from the journal; no network or credential was used. |
| `prepared` | trusted helper receipt and active authority set committed | `confirmed` | Exactly one receipt/key generation plus the exact canonical descriptor, complete applicable authority branch, derived context, registry chain, and all digests are retained. |
| `prepared` | operator cancellation or expiry | `canceled` / `expired` | Terminal; create a new plan. |
| `confirmed` | coordinator acquired; receipt and unchanged active authority set consumed before permit | `in_flight` | Durable non-replay point; no send authority exists until the one exact-request permit is added. |
| `confirmed` | helper/CLI crashes after coordinator acquisition but before the CAS | unchanged, quarantined | No recovery CAS, close, deletion, or retry; report only. |
| `in_flight` | uninterrupted owner proves definitive failure before permit | `failed_before_mutation` | Quiesce capabilities, persist terminal outcome, durably close; zero dispatch. A crash before that close instead quarantines. |
| `in_flight` | exact permit added | remains `in_flight` | Sole send-authority linearization; every later uncertainty is ambiguous and non-replayable. |
| `confirmed` | operator cancellation before coordinator acquisition | `canceled` | Terminal; no mutation attempt. |
| `confirmed` | receipt TTL expires before coordinator acquisition | `expired` | No lease or permit; expired receipt cannot authorize acquisition. |
| `confirmed` / `in_flight` | receipt TTL expires after acquisition with proven durable permit absence | `failed_before_mutation` | Only the uninterrupted owner may burn the receipt, quiesce capabilities, and durably close; otherwise quarantine without CAS. |
| `in_flight` | receipt TTL expires after durable permit without verified success | `ambiguous` | No send; owner quiesces and closes; absence of request bytes does not establish non-application. |
| `confirmed` | trusted time reaches descriptor `helper_profile_expires_at` before coordinator acquisition | `expired` | Absolute cutoff; Gate/install evidence and cached helper sessions do not extend it. |
| `confirmed` | applicable Gate/smoke/post-grant runner token expires before coordinator acquisition | `expired` | No lease, permit, or dispatch; historical token bytes cannot renew live authority. |
| `confirmed` / `in_flight` | applicable runner token expires after acquisition with proven permit absence | `failed_before_mutation` | Burn receipt and durably close/fence the existing lease with zero dispatch; an already recorded smoke hard-deny `activation_smoke_consumed` remains terminal. |
| `in_flight` | applicable runner token expires at/after permit without a durable outcome | `ambiguous` | No new send or permit; close/fence and use bounded historical reconciliation only. |
| any state with durable outcome | applicable runner token expires | unchanged durable outcome | Expiry never downgrades recorded success/failure or a consumed smoke receipt to ambiguity. |
| `confirmed` | approval registry revision or active generation changed | `canceled` | Retained keys may verify history but never authorize apply. |
| `confirmed` | descriptor, applicable authority token/grant, or context changed | `canceled` | Historical bytes remain audit evidence but never authorize apply. |
| `confirmed` / `in_flight` | trusted time reaches descriptor `helper_profile_expires_at` after coordinator acquisition while no permit exists | `failed_before_mutation` | Only the uninterrupted owner can quiesce, burn, and durably close with zero dispatch. A replacement process quarantines instead. New plans require a newly authorized artifact. |
| `in_flight` | durable permit exists; definitive rejection or known zero bytes sent without verified success | `ambiguous` | Owner quiesces and closes; only later eligible closed reconciliation may establish `resolved_not_applied`. |
| `in_flight` | verified success recorded | `applied` | Non-replayable; proceed to bounded verification. |
| `in_flight` | timeout, reset, unexpected/invalid response, or uncertain send | `ambiguous` | Never retry; reconcile. |
| `in_flight` | process crash or local journal failure after permit without valid durable close | unchanged, quarantined | Restart never sends, closes, deletes, or CASes; bounded reconciliation reports only. |
| `applied` | exact bounded verification matches | `reconciled` | Terminal known-applied. |
| `applied` | verification cannot establish unique state | `operator_resolution_required` | No automatic retry. |
| `ambiguous` | bounded evidence uniquely proves application | `reconciled` | Terminal known-applied. |
| `ambiguous` | bounded evidence proves definitive non-application | `resolved_not_applied` | Terminal; only a new plan may write. |
| `ambiguous` | zero/non-unique/unsupported evidence | `operator_resolution_required` | Not proof of non-application; no automatic retry or fresh plan. |
| `operator_resolution_required` | explicit local operator resolution with evidence digest | `resolved_applied` / `resolved_not_applied` | Terminal audit record; this action never contacts YouTrack. |

A verified remote success followed by stdout or journal-finalization failure emits `WRITE_APPLIED_LOCAL_FAILURE` with do-not-retry guidance. Without a valid durable close, restart preserves the journal bytes and quarantines authority; it never adds a close on behalf of the original owner. Bounded remote reconciliation reports findings without CAS. Gate 1B covers registry/apply ordering, invalid enrollment before ledger read, all pre/post-permit and outcome/close crash boundaries, concurrent exact-code helpers and alternate bootstrap namespaces, owner capability quiescence before close, and active A replaced by B before stale A persistent-reference deletion. Exact Security.framework dictionary/projection vectors and deterministic binary barrier/event traces are required; process-local guard serialization is not a cross-process proof.

The current runtime retains JSON v1 and exits 0..9. The future `mutation authority status` and `mutation authority recover` commands use the [proposed routing](../docs/gate1a-registry-protocol.md), including exits 11/12; the wider coordinator design proposes exits 10..13. Capacity introduces no additional exit number: successful status with action `stop` exits 0, and capacity-exhausted acquire/recover uses existing exit 1, as do corruption and quarantine. These commands remain unimplemented. Their eventual implementation must update `.agents/rules/cli-contract.md`, `internal/errx`, generated references, the tracked Cursor mirror, and embedded skill routing together, then pass sync/compiler gates.

## First implementation slice

1. Scaffold the canonical harness and machine contract.
2. Add the portable embedded skill and safe installer.
3. Implement endpoint/profile/project-policy schemas and architecture tests.
4. Implement Keychain-bound public-client OAuth Authorization Code + PKCE and permanent-token fallback.
5. Implement bounded exact REST inspection and offline intent preparation.
6. Implement the journal state machine and fail-closed approval interfaces.
7. Implement durable two-phase confirmation and its native adapter behind
   dependency injection while the current repository remains disabled.
8. Build an unpublished signed/notarized/stapled candidate whose default
   production factory wires confirmation. Create and retain its exact app-only
   archive, freeze its descriptor, then run complete Gate 1A
   E1 and clean-reset E2 on every declared architecture, then issue the
   confirm-only provisional authorization and pass its ordinary-command
   black-box smoke set. Issue the production activation grant only afterward,
   then verify the exact grant-bound production context through the ordinary
   commands on every architecture under deny-only runner restrictions. Failed
   evidence quarantines the unpublished candidate and grant. No post-Gate
   wiring or rebuild occurs.
9. Implement the typed one-shot `issue.create` engine and reconciliation behind
   the disabled executor boundary together with the helper-owned coordinator,
   exact Security.framework dictionary/projection codecs, permit/closed
   owner quiescence, strict helper-profile expiry checks, and unclosed-crash
   quarantine without any recovery mutation or replay.
10. Build an unpublished exact candidate whose ordinary production factory
    wires only `issue.create`, repeat the two-pass Gate 1A sequence against its
    new descriptor, then run the complete materialized two-pass Gate 1B
    [isolated-unit inventory](../docs/gate1b-isolated-subruns.md), with a fresh
    host and separately allocated and retired disposable YouTrack 2026.2 project
    for every unit/architecture/pass. Bind E2 to the complete disposed E1 parent;
    include the closed apply/registry ordering and every pre/post-permit
    crash/restart variant without target or host reuse. Only after complete E2
    acceptance issue provisional authorization and run the
    exact per-architecture loopback-preflight/hard-deny dispatch smoke; only a
    complete passing smoke evidence set permits the production activation grant.
    The real grant-bound context then passes the separate per-architecture
    ordinary-command verification before publication. There is no post-Gate
    activation edit.
11. Keep `issue.update` and `comment.add` disabled until their separate
    REST-TOCTOU acceptance or strict custom-MCP transaction decision.
12. Complete the non-production pilot and contract, independent security,
    primary, and adversarial review gates before packaging or publication.

The REST executor is always labeled `rest-best-effort`. Strict atomic project enforcement remains a later custom YouTrack MCP executor because a local REST preflight cannot close the concurrent issue-move race.
