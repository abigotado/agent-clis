# Gate 1A approval-helper evidence report

- Status: **NOT PASSED**
- Date opened: 2026-09-02
- Scope completed by this report: protocol-contract spike only
- Production approval adapter: `approval.Unsupported`

Current mutation surface enables offline `prepare`, local `export`, and local
`status` only. `confirm`, `apply`, and `reconcile` fail closed; the native
authority commands and evidence requirements below remain unimplemented.

The [trust-root and package-topology ADR](../docs/gate1a-trust-root.md)
freezes the identifiers, Team ID input, Keychain namespace, enrollment,
rotation/recovery, signed layout, and evidence order. It is a design result,
not Gate evidence.

The separate [isolated-subrun ADR](../docs/gate1b-isolated-subruns.md) specifies
Gate 1B unit authorization and offline parent aggregation without resetting an
enrolled unit. This resolves the topology at design level only: the complete
inventory, validators, and native evidence are still required. The historical
phase catalog cannot authorize Gate tokens, activation or publication by itself.

The normative [registry/ceremony codec](../docs/gate1a-registry-protocol.md)
and [exact-artifact authorization](../docs/gate1a-artifact-authorization.md)
are also design inputs only. Their presence does not advance this report.

This report is deliberately fail-closed. Protocol code, shared Go/Swift golden
vectors, parser tests, and ad-hoc development builds are preparation evidence;
they do not prove the signed native approval boundary required by Gate 1A.

## Slice 1: protocol contract

| Requirement | Status | Evidence |
| --- | --- | --- |
| Pre-Gate v2 canonical receipt/signature byte contract | Passed for slice 1 only | `docs/gate1a-protocol.md` and `testdata/gate1a` |
| Activation-eligible v3 registry/context binding | Not implemented | Required v3 delta in `docs/gate1a-protocol.md` |
| Complete registry/ceremony codec and cross-language vectors | Specified, not implemented | `docs/gate1a-registry-protocol.md` |
| Offline-root exact-artifact descriptor/provisional authorization/activation grant | Specified, not instantiated | `docs/gate1a-artifact-authorization.md`; no production root/signatures exist |
| Strict bounded Go receipt codec | Passed for slice 1 | `go test -race ./internal/approval` |
| Independent Swift parser/encoder agreement | Passed for slice 1 | 39 tests through `swift test` on macOS |
| Reversible inert rendering of every displayed byte | Passed for slice 1 | all-byte, empty, maximum-size, and round-trip Swift tests |
| Production approval helper used by the CLI | Not implemented | `approval.Unsupported` remains the only adapter |

Completion of this slice must not change this report's overall status from
**NOT PASSED**.

## PR A: native-boundary value contract

The accepted boundary ADR freezes the language-neutral ASCII URL grammar,
canonical 128-bit plan ID, binary frame header and payload union, a signed
CSPRNG challenge digest, closed error codes, strict canonical plan parsing,
and a Go verifier requiring the enrolled generation/SPKI/fingerprint. Shared
fixtures cover all three mutation plan kinds plus URL, identifier, request,
success, and error frames. Existing profile and journal reads retain their
legacy URL grammar; new mutation preparation fails early with
`MUTATION_PROFILE_INCOMPATIBLE` when the selected profile cannot be represented
by the narrower approval protocol.

This remains value-codec evidence plus an offline compatibility guard. There is
no production AF_UNIX I/O, process launch, peer audit-token validation, native
key access, approval UI, helper integration, or confirmation orchestration.
Consequently PR A does not advance the overall Gate result beyond **NOT
PASSED**.

## Required later evidence

### Connection-bound process identity

- Accepted AF_UNIX connections expose `LOCAL_PEERTOKEN` audit tokens.
- Each side validates the connection-bound audit token with
  `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` and its pinned
  designated requirement, then matches the running code's Security.framework
  identity with the offline-root-authorized per-architecture set.
- PID and filesystem-path checks are diagnostic only.
- Replacement, exec, PID reuse, malformed framing, timeout, EOF, and trailing
  data all fail before approval.

### Disposable Secure Enclave and UI spike

- Every signing generation is permanent P-256 Secure Enclave material with a
  fresh random key ID/tag in a helper-only data-protection Keychain access
  group; only a committed active registry transition may select it.
- The item uses `kSecAttrAccessControl`; it does not combine that contract with
  legacy `kSecAttrAccess` ACL configuration.
- One new zero-reuse `LAContext` appears only in the exact signing-key lookup.
  The returned `SecKey`, not the context, is used once with
  `SecKeyCreateSignature`; the context is invalidated on every outcome.
  Separate existence/delete queries contain no context, force authentication
  UI to fail, and can never sign.
- The selected `userPresence` password-fallback or `biometryCurrentSet` policy
  is explicit and tested.
- The separately signed UI displays the complete bounded immutable plan through
  the reversible inert renderer without rich text, links, data detectors,
  clipboard actions, or truncation.
- Cancellation, helper crash, key loss/rotation, unrelated-process access, and
  unsupported hardware fail closed without a receipt or network activity.

This spike requires an explicit operator run before it may create disposable
Keychain or Secure Enclave state.

### Production signing and clean-host gate

- An operator-controlled Developer ID Application identity signs the frozen
  helper bundle with hardened runtime, timestamp, exact entitlements, its
  matching embedded Developer ID provisioning profile, and no
  `get-task-allow`.
- The bundle is notarized and stapled; `codesign`, `spctl`, and stapler checks
  pass against the exact designated requirement, Team ID, and architecture set.
- The offline root signs only fresh per-architecture runner/session-bound E1
  and E2 tokens until both complete clean-host evidence sets succeed. It then
  issues only a provisional authorization. Its content-addressed ordinary-
  command branch must pass the mandatory network-disabled smoke on every
  declared architecture before the root may issue a production activation
  grant. The exact artifact must then load that grant, derive the final
  production context, and pass a separate per-architecture ordinary-command
  verification before publication.
- The closed clean-machine Gate 1A set covers first install, identical
  reinstall, accidental rollback, binary/helper replacement, uninstall, and
  Keychain-migration cancellation, interruption, and partial failure. It uses
  the app-only archive retained before descriptor/E1 and a non-secret sentinel;
  any missing case fails Gate. A mixed-build fixture is rejected; a matched
  older pair remains an unsolved rollover case.
- The CLI locally verifies receipt DER signatures against an explicitly
  enrolled public key and stores the full signed receipt only after a
  revision-bound compare-and-swap.

Missing production signing, notarization, Secure Enclave isolation, or
clean-machine evidence is an automatic Gate 1A failure.

Helper-private corruption, key-loss, orphan-cleanup, and ambiguous-Keychain
faults are exercised only by the separately signed Gate fixture defined in the
trust-root ADR. It uses disjoint identifiers, access group, key tags, registry,
and peer requirements and is compile-time absent from the production target.
Reports must distinguish that fixture evidence from black-box execution of the
exact notarized candidate.

## Required candidate product integration

Before Gate 1A runs, a separate reviewed change must add the full signed receipt,
its exact approval-registry revision, and exact verification SPKI to the
journal; revalidate profile/policy/key/revisions after approval; and commit
`prepared -> confirmed` with compare-and-swap. A black-box harness launches the
production CLI from the
exact signed candidate bundle and drives its ordinary `mutation confirm`
entry point; it does not inject an adapter, gain Keychain access, or become an
accepted helper peer. The current repository remains wired to
`approval.Unsupported`, but the unpublished Gate candidate's default factory
must wire the native adapter before signing. Gate success qualifies those exact
Apple code identities only through the descriptor and the post-E2 confirm-only
provisional authorization plus post-smoke activation grant; it is not followed
by a wiring commit or rebuild. `apply` and
`reconcile` remain disabled until a separate exact Gate 1B candidate proves
their one-shot and ambiguous-outcome behavior through the complete isolated-unit
inventory, with a distinct disposable YouTrack project and fresh host for every
unit/architecture/pass under the isolated-subrun ADR.
That candidate must first introduce journal v2; only a valid v1 `prepared`
record migrates atomically, while every other valid v1 state—including
`failed_before_mutation`—remains unchanged and quarantined. It adds exactly `mutation authority status` and
trusted-UI `mutation authority recover`, no plan-ID or force-clear recovery,
and the proposed exits 10..13, with corruption and capacity refusal on existing exit
1, rooted in `internal/errx` and regenerated into both documentation and
embedded-skill references. The implementation change also updates
`.agents/rules/cli-contract.md`, regenerates its tracked Cursor mirror, and
passes rule-sync/provider-compiler checks.
That candidate must implement the fixed-active Keychain coordinator shared by
all registry commits and apply across concurrently valid same-user helpers.
Its protected active/closed records must bind the exact signed-receipt digest;
bounded history rejects new-lease reuse including null-permit burns, independent
of journal CAS. Receipt TTL must distinguish pre-acquisition expiry from an
uninterrupted owner's acquired/pre-permit burn. After durable permit, only
verified success is applied; every other outcome is ambiguous, including
definitive rejection or known zero bytes sent. Later eligible closed
reconciliation may prove `resolved_not_applied`; zero/non-unique matches do not
prove non-application or authorize automatic fresh plans. The last owner at
256 permits/closes must close and retain a valid closed active sentinel:
status `capacity_exhausted`, action `stop`, exit 0; acquire/recover capacity
error uses existing exit 1 with no deletion. See the
[state table](08-implementation-decision.md#complete-state-table) and complete
[registry constraints](../docs/gate1a-registry-protocol.md).
LaunchAgent lifecycle and a process-local guard do not prove global singleton
authority. The lease survives restarts; the owner follows durable
`confirmed -> in_flight`, one exact-request permit, one send/outcome,
irreversible capability quiescence, then durable normal close. Unclosed leases
stay quarantined even after reboot; remote reconciliation only reads/reports
without journal CAS. Gate 1B's closed
plan must exercise both apply-first and registry-first rotation/revocation/recovery,
concurrent invalid enrollment before ledger read, crash before permit, crash
after permit before send, crash after send before outcome, crash after durable
outcome before close, close-add ambiguity, crash after close before active
delete, active-delete ambiguity, replacement active B surviving stale deletion
of A's persistent reference, two valid helpers/alternate bootstrap namespaces,
queued callbacks unable to send after normal close, and exact Security.framework dictionary and
bounded-projection vectors. Those concurrency cases use the signed plan's exact
two-party binary barrier schedule and content-addressed event trace, never
sleeps or scheduler timing. The 26 Gate 1B coverage families expand into atomic
isolated units, each with token-bound enrollment and a baseline scoped to that
unit/architecture/pass. The parent set validates all leaves, their disposal and
coverage; E2 depends on the complete E1 parent. It also exercises exact
authority status/recover JSON v1 shapes with required invocation `meta`, exits
under the proposed routing (including 11/12), closed inherited flags, trusted recovery UI, and
journal v1-to-v2 migration/quarantine interruptions.
Because that wiring changes exact code identities, the same candidate must run
the complete E1/E2 Gate 1A sequence before the two-pass Gate 1B evidence can
qualify it. The final `issue.create` provisional authorization then undergoes
the exact per-architecture CLI/loopback-preflight/hard-deny dispatch smoke with
zero mutating request bytes. Only the complete passing smoke evidence set
permits the production activation grant. A second exact-artifact verification
then exercises the real grant-bound context and schema-v3 receipts on every
architecture under deny-only runner restrictions before publication.
The same descriptor must bind CMS-validated `helper_profile_expires_at`;
the closed 88-vector matrix proves just-before/equality/after/between-checks at
all 22 Gate, publication, install, runtime, peer-authentication, coordinator,
registry-sign/commit, permit, and final pre-send boundaries. Equality and later
fail without grace or evidence carry-forward.

## Homebrew decision

Homebrew remains blocked. The trust-root ADR selects a future Cask/private-tap
shape, but this work does not authorize a Formula, Cask, tap, release workflow,
source rebuild of the helper, or package publication. Gate 1A must prove that
the signed and notarized nested helper retains its identity and entitlements
across first install, identical reinstall, rollback refusal, replacement, and
uninstall. Gate 1B must
then prove the live one-shot YouTrack write path. The existing offline module
manifest and checker cover dependency closure and offline source builds only;
they do not prove Formula/Cask, signing, or native readiness. A non-production
pilot and independent security review must also pass before publication.

The eventual Cask must pin the exact outer archive SHA-256, install the
immutable app payload, detached provisional authorization, activation grant,
root-signed publication envelope, exact post-grant plan, and complete closed
evidence tree without fetching or rewriting them, and reject `sha256
:no_check`. The envelope binds the complete post-grant verification inputs;
the Cask separately pins its containing archive so no recursive hash is needed.
Homebrew checksum validation is
not a substitute for the pinned-root signature or runtime code-identity checks.

The capability-specific activation-smoke plans contain exactly 5 and 6 cases;
the post-grant plans contain exactly 6 for confirm-only and 7 for issue.create,
including its ordinary apply hard-deny dispatch-boundary case. Every plan starts with a stage-
token/setup-context-limited exact-artifact enrollment from a canonical empty
registry/coordinator/key/journal/session inventory, binds the retained
revision-1/generation-1 snapshot to every later observation/index/set, and
ends with terminal/replay-denial evidence and sanitized export. Operation observations have empty assertion
IDs; only a case-final runner evaluation emitted after all transcript results
can pass the case. The external trusted supervisor destroys the whole disposable
host after export, on both success and failure. Root-bound disposal evidence
must precede the activation-grant signature after smoke and the publication-
envelope signature after post-grant verification. Missing or uncertain disposal
blocks every successor signature and host reuse. Live `stage_cleanup`,
deletion ACK-ledger recovery, and helper-produced empty-inventory cleanup
proofs are explicitly deferred; no native cleanup implementation is claimed.

Only the first signed Cask build may follow these gates. A second
write-capable release remains blocked until its separate rollover decision and
evidence cover side-loaded old pairs, approval state, credentials, and stale
access tokens.
