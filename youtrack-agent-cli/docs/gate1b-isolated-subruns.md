# Gate 1B isolated subruns and evidence aggregation

Status: **DESIGN ONLY; NOT PASSED; NOT ACTIVATED**. This decision specifies the
missing execution topology; it does not supply a compiled coverage manifest,
native implementation, signed token, or conformance evidence. Token issuance
requires the reviewed materialized compiler/contracts, cross-language vectors,
and verified native candidate implementation below. Evidence acceptance and
successor authorization additionally require the actual authorized E1/E2 native
runs and their complete independently reviewed evidence; those runs do not
have to exist before their own correctly scoped test tokens can be issued.
`approval.Unsupported` remains the production adapter. Nothing here authorizes
installation, signing, provisioning, a live test, or a production mutation.

Implementation prerequisites: the Go `internal/gatecontract` and Swift
`ApprovalProtocol.IsolatedBinding` / `IsolatedSegmentContract` codecs implement
only the canonical local wire shapes of `gate1b_isolated_binding_v1` and
`gate1b_isolated_segment_contract_v1`, with shared vectors under
`testdata/gate1b-isolated-binding` and `testdata/gate1b-isolated-segment`.
Parsing or hashing either value does not
resolve its references or prove their types, authenticity, semantic agreement,
freshness, or authority. Recursive closure verification, the materialized
inventory/compiler, and native Gate execution remain unimplemented. The segment
codec checks the local numeric domains below, not relationships between counts
or equality to the actual compiled tree, referenced sets, or retained files.

## Scope and precedence

Gate 1B runs independent, root-authorized **units**, not a resettable suite.
Each unit owns one disposable host, one disposable YouTrack project, one
architecture, and one pass. It performs one setup, one atomic scenario/variant,
and final evidence capture. A quarantined unit is never reset or reused.
Crashing a process does not release its unclosed lease. Whole-host disposal
and remote-target retirement belong to the trusted external operator, never
to the candidate's CLI, helper, or Gate-control interface.

This document is authoritative only for Gate 1B orchestration and bindings.
The [shared artifact contract](gate1a-artifact-authorization.md) continues to
define the root key, descriptor, exact code identity, native peer validation,
canonical encoding primitives, setup evidence payloads, operation templates,
assertion/transcript payloads, and required behavioral coverage. The
[registry protocol](gate1a-registry-protocol.md) still controls every authority
operation. No orchestration field grants an operation forbidden there.

Gate 1B rejects legacy `gate_e1`, `gate_e2`, `gate_receipt_context_v1`,
`gate_authority_evidence_v1`, `gate_e1_pass`, `gate_e2_pass`, and legacy Gate
evidence-set objects, even if their `gate_id` says `gate1b`, hashes recompute,
or signatures verify. Their single-suite meaning is not reinterpreted. Gate
1A, activation smoke, post-grant verification, production receipt schema 3,
and JSON output v1 are unchanged. New objects cannot satisfy those modes.

## Canonical object conventions

Every object below is closed compact canonical JSON under the shared strict
decode/re-encode rules. Each row lists **all fields in exact order**. Unless
expressly nullable, a field is required and non-null; empty arrays are allowed
only where specified. Unknown/reordered/duplicate fields, floats, alternate
escaping, trailing data, or cross-type substitution fail before authority work.
All new objects begin with `schema_version` integer `1`, then `object_type`
equal to the row's literal type. This two-field prefix is denoted `H` in tables;
it is expanded, not encoded as a nested field. Types are never inferred by shape.

Primitives: `D` is a lowercase 64-hex SHA-256; `T` is the shared whole-second
UTC time; `N` is canonical unpadded base64url of 32 random bytes; `U` is the
40-hex runner unique value; `A` is `arm64` or `x86_64`; `P` is `e1` or `e2`.
Ordinals are positive canonical JSON integers. A local ID is 1..128 bytes
under the shared identifier grammar, never a pathname. Observer/control
session IDs use `N`. Human/control-plane resource identifiers are printable
ASCII strings of 1..128 bytes without escapes. No identifier is a credential.

New isolated-object reference fields ending in `_sha256` mean `D` over the
complete exact canonical referenced bytes, including a signature where present.
Their required object types and semantic links are verified recursively; an
untyped opaque blob cannot substitute for an object reference. Fields imported
from the shared artifact/registry protocols retain their frozen digest semantics,
including the SPKI-byte `signing_key_fingerprint_sha256`, `registry_chain_sha256`
over its prescribed chain encoding, and shared raw fixture, observation,
transcript and file-byte digests (including `stdout_sha256`, `content_sha256`
and file-manifest `sha256`). These are verified against their prescribed exact
bytes, not decoded as isolated authority objects. The pristine-base artifact
digest has its separate lifecycle verification rule below. Unsigned new objects
use plain SHA-256, no hash-domain prefix. Signed objects append `signature` and
use the existing pinned Ed25519
root and strict signature grammar; signature input is the exact domain below,
including its NUL, followed by the unsigned canonical bytes.

| Signed type | Signature domain | Byte cap including signature |
| --- | --- | ---: |
| `gate1b_isolated_unit_token_v1` | `YTA-GATE1B-ISOLATED-UNIT-V1\0` | 8,192 |
| `gate1b_isolated_observer_token_v1` | `YTA-GATE1B-ISOLATED-OBSERVER-V1\0` | 8,192 |
| `gate1b_isolated_host_disposal_v1` | `YTA-GATE1B-ISOLATED-DISPOSAL-V1\0` | 8,192 |

These domains are disjoint from legacy Gate signatures and from test-only
keys/domains. There is no signature or pass-bit shortcut around closure
validation. All counts, integer arithmetic, byte sums, and products below are
checked before allocation, decoding referenced bodies, or file reads.

## Coverage inventory and unit definition

The compiler materializes every atomic requirement from the shared ordered
26-family catalog and its full coordinator phase/negative-input catalogs.
The 26 family IDs and order are unchanged. Families are **coverage labels**,
not 26 independently reusable mutable suites. The compiler expands both
orders of each rotate/revoke/recovery race, every crash boundary, all close
and delete ambiguity outcomes, every multi-helper and restart/history variant,
and each status, migration, capability, target, receipt, and fail-closed
negative-input variant. A status or migration matrix cannot hide a reset or
an unenumerated loop inside one operation. Variants that leave incompatible
state require separate units; an atomic race may retain its two actors.

| Type | Fields after `H`, in order | Cap |
| --- | --- | ---: |
| `gate1b_isolated_catalog_v1` | `families` | 1 MiB |
| `gate1b_isolated_coverage_inventory_v1` | `descriptor_sha256`, `catalog_sha256`, `architectures`, `minimum_macos_product_build_version`, `unit_definitions`, `family_requirements` | 2 MiB |
| `gate1b_isolated_unit_definition_v1` | `unit_ordinal`, `family_id`, `variant_id`, `segment_count`, `setup_contract_sha256`, `scenario_contract_sha256`, `segment_contracts`, `coverage_requirements` | 1 MiB |
| `gate1b_isolated_segment_contract_v1` | `segment_ordinal`, `mode`, `command_contract_sha256`, `fixture_set_sha256`, `assertion_set_sha256`, `transcript_set_sha256`, `operation_count`, `observation_count`, `transcript_count`, `assertion_count`, `file_count`, `maximum_evidence_bytes` | 4,096 |

For `gate1b_isolated_segment_contract_v1`, all six count/budget fields are
canonical decimal JSON integers in these closed ranges:

| Field | Minimum | Maximum |
| --- | ---: | ---: |
| `operation_count` | 1 | 128 |
| `observation_count` | 1 | 256 |
| `transcript_count` | 1 | 2,048 |
| `assertion_count` | 1 | 256 |
| `file_count` | 1 | 4,096 |
| `maximum_evidence_bytes` | 1 | 268,435,456 |

`transcript_count` and `assertion_count` count entries of the referenced segment
transcript/assertion sets, not result-manifest objects or per-observation copies;
the required one-to-one result-ID coverage is checked during closure
verification. Operation counts exclude final evaluations; observation counts
include operations and case-final evaluations, and segment 1 includes its setup.
`file_count` is the exact number of distinct retained regular-file paths in the
whole segment evidence closure, including its leaf index and the separately
retained private historical-authority branch, but excluding later unit export,
retirement, disposal, and parent objects. `maximum_evidence_bytes` bounds that
same closure's aggregate bytes; it is a ceiling, not a claim that exactly that
many bytes exist. This decision explicitly makes an empty operation sequence
and a zero-byte evidence budget invalid for either mode. Integer syntax and
these local ranges are codec checks. Equality to the compiled tree, count
relationships, referenced-set cardinality, unique result coverage, file
membership, and actual byte totals remain mandatory closure checks and cannot
be established by this codec.

The catalog's `families` array has exactly 26 entries in shared catalog order,
each with fields `family_id`, `variants`. `variants` is empty only for the
setup family; otherwise it is a nonempty ordered array of objects with fields
`variant_id`, `segment_count`, `requirements`. Requirements are a nonempty
ordered array of local IDs; variant IDs are unique within their family.
These are literal reviewed coverage entries, not values inferred from the
units submitted for a run. Their expansion must equal the complete shared
behavioral catalog, including every named negative input and historical phase.

`architectures` exactly equals the descriptor array. `catalog_sha256` names
this canonical catalog under a checked-in verifier literal, not Markdown text
or an operator-chosen digest. The inventory must contain exactly one unit for
every catalog variant in family/variant order, never a self-selected subset.
`unit_definitions` is an ordered array of `D` references to the
complete unit objects, with ordinals exactly `1..n`. `family_id` is one of the
26 literal catalog IDs; `variant_id` is one compiled local ID. `segment_count`
is exactly one, except the single compiled real-reboot variant where it is
two. `segment_contracts` is the exact array of segment-contract objects in
ordinal order. `mode` is `scenario` for segment 1 and `reboot_observer` for
segment 2 only. Setup and scenario contract hashes name closed compiled
operation/case-evaluation trees using the shared payload grammar; the scenario
tree contains one enumerated variant, never a shell, wildcard, or reset loop.

`coverage_requirements` is an ordered nonempty array of closed objects with
fields `family_id`, `requirement_id`, `segment_ordinal`, `assertion_id`.
These are exact selectors into the compiled case-final assertions, not labels
attached after execution. `family_requirements` has exactly 26 objects in
catalog order, each with `family_id`, `requirements`; `requirements` is the
exact ordered nonempty list of that family's compiled local requirement IDs.
All 25 non-setup families are covered exactly once per required variant. The
setup family is evaluated once at parent level by requiring every unit's
setup to pass; repeating setup must not inflate the aggregate coverage count.
There is no stand-alone setup-only unit.

The reviewed compiler must output the **actual complete literal inventory**,
all referenced definitions/contracts, and exact count vectors. Candidate
counts from the old 26-case single-suite table are not executable counts.
Provisional ceilings are 256 units, 128 operations per segment, and 256
observations per segment; each segment's exact compiled counts must be met,
not merely remain below the ceilings. The existing per-leaf 128-byte ID,
fixture/assertion/transcript caps still apply. A required expansion exceeding
any cap blocks contract freeze and requires another reviewed bound decision;
it never truncates coverage, drops a variant, splits a race unsafely, or
silently raises a cap. No literal inventory is supplied by this ADR.

### Required affected-variant selectors

The following mandatory additions/refinements preserve the 26 family IDs.
They are coverage inputs for future tests, not executed conformance evidence
or a complete compiler/inventory. Each listed selector expands to one fresh
unit, `segment_ordinal=1`; its `requirement_id` is the variant ID and its
`assertion_id` is the family ID plus `.` plus variant ID plus `.primary`.
That final assertion verifies every condition in its row. These exact tuples
must occur in both unit coverage and parent source mapping, alongside all
unaffected catalog requirements. Comma-separated variants below each require
their own unit and final assertion, not one combined matrix operation.

| Family ID | Required variant IDs | Final assertion requirements |
| --- | --- | --- |
| `gate1b.coordinator.apply-vs-rotate-linearization` | `apply-first-atomic-contention`, `registry-first-atomic-contention`, `apply-first-ordered-transition`, `registry-first-ordered-transition` | Exact corresponding shared phase; atomic loser exits 10 permanently; ordered second actor begins only after close/deletion; zero overlap; leased registry intent/candidate validation and stale-apply cancellation where applicable. |
| `gate1b.coordinator.apply-vs-revoke-linearization` | `apply-first-atomic-contention`, `registry-first-atomic-contention`, `apply-first-ordered-transition`, `registry-first-ordered-transition` | Same four shared phases with revoke as registry transition and revocation-first cancellation. |
| `gate1b.coordinator.apply-vs-recovery-linearization` | `apply-first-atomic-contention`, `registry-first-atomic-contention`, `apply-first-ordered-transition`, `registry-first-ordered-transition` | Same four shared phases with registry recovery as transition and recovery-first cancellation. |
| `gate1b.receipt.context-and-replay-deny` | `success-restore-confirmed` | Complete successful apply and normal close; restore caller-writable confirmed journal and attempt the same receipt under a fresh lease. Protected permit/closed history denies a second permit/send. |
| `gate1b.receipt.context-and-replay-deny` | `null-permit-abort-restore` | Uninterrupted owner proves no permit, quiesces, terminalizes and durably closes with null permit; exit 13. Restore confirmed journal and retry with fresh lease: protected closed receipt digest denies permit/send. Repeated denied null-permit closes are allowed. |
| `gate1b.receipt.context-and-replay-deny` | `interrupted-abort-quarantine` | Interrupt before durable normal close, restore confirmed journal, then observe through another helper: exit 1 quarantine; no close add, delete, permit or send. |
| `gate1b.receipt.context-and-replay-deny` | `history-order-independent` | Permute returned protected history enumeration order within this unit; identical global receipt-burn decision, accepting repeated denied null-permit closes while rejecting more than one permit for any receipt digest. No mutation or reset between permutations. |
| `gate1b.receipt.context-and-replay-deny` | `post-permit-zero-byte-deny` | Durable permit followed by local pre-send denial yields zero mutating bytes but `ambiguous`, never `failed_before_mutation` or exit 13; normal close burns receipt. Only verified success may close `applied`. |
| `gate1b.authority.status-recover-contract` | `status-live-owner-busy` | Successful status has `busy`, action `wait`, exit 0; status does not emit exit 10. |
| `gate1b.authority.status-recover-contract` | `recover-closed-cancel` | Valid closed cleanup with canceled trusted presence returns exit 11 and preserves bytes. |
| `gate1b.authority.status-recover-contract` | `status-expired-no-active` | Exit 12; no fabricated cleanup work. |
| `gate1b.authority.status-recover-contract` | `recover-expired-closed` | Valid below-capacity durable closed linkage permits only exact-reference cleanup; no new authority. |
| `gate1b.authority.status-recover-contract` | `status-unclosed-quarantine`, `recover-unclosed-quarantine` | Exit 1, unchanged journal/active, zero authority writes. |
| `gate1b.authority.fail-closed-matrix` | `permit-capacity-stale-contender`, `closed-capacity-stale-contender` | Begin below the respective 256-entry bound. Pause contender after its stale precheck; last owner reaches 256 permits or closes, durably closes and retains matching valid closed active sentinel. Resume contender: no new active acquisition. Cleanup cannot delete sentinel. Status is `capacity_exhausted`, action `stop`, exit 0; acquire/recover return `AUTHORITY_CAPACITY_EXHAUSTED`/exit 1. |
| `gate1b.authority.fail-closed-matrix` | `expired-capacity-sentinel` | Valid closed exhaustion sentinel after profile expiry still returns status `capacity_exhausted`/`stop`/0 and recover capacity error/1; no deletion or recovery authority. |

The status/recover family asserts only reachable exits: success 0, quarantine/
corruption/recovery denial/capacity 1, rejected invocation 2, recovery cancel
11, and expiry 12, as applicable to each declared command. Exit 10 is verified
by atomic acquisition contention and invalid-enrollment contention; exit 13
by `null-permit-abort-restore`, never by a status/recover invocation. Existing
status flag, metadata, corruption, absence and migration variants remain
mandatory and must be individually materialized before freeze.

Protected history is searched globally by receipt digest, without dependence
on lease, timestamp, enumeration order or restored local journal state. Any
permit or normal closed receipt digest burns approval. Repeated null-permit
denied closes do not imply corruption; the global permit count per receipt
must remain at most one. A normal pre-permit failure requires proven absence
of a permit. Once a permit exists, close outcome is only `applied` for verified
success or `ambiguous` otherwise, even for proven zero-byte denial.

## Pre-token host and target allocation

Trusted external lifecycle control prepares a genuinely fresh host and target
before requesting a unit token. Creating a new nonce does not make an old
project, disk, snapshot, or host fresh. Allocation/retirement must be observed
through the trusted operator's lifecycle control plane; candidate output and
self-asserted JSON do not prove it. These objects contain no credentials and
confer no target provisioning, reset, or deletion API on the candidate.

| Type | Fields after `H`, in order | Cap |
| --- | --- | ---: |
| `gate1b_isolated_host_provisioning_v1` | `host_instance_id`, `writable_resource_ids`, `pristine_base_sha256`, `provisioned_at`, `observed_at`, `result` | 16,384 |
| `gate1b_isolated_host_inventory_v1` | `descriptor_sha256`, `coverage_inventory_sha256`, `unit_definition_sha256`, `pass`, `architecture`, `disposable_host_id`, `host_instance_id`, `writable_resource_ids`, `provisioning_evidence_sha256`, `created_at` | 16,384 |
| `gate1b_isolated_target_allocation_v1` | `descriptor_sha256`, `coverage_inventory_sha256`, `unit_definition_sha256`, `pass`, `architecture`, `host_inventory_sha256`, `gate_target_sha256`, `allocation_evidence_sha256`, `allocated_at` | 8,192 |
| `gate1b_isolated_binding_v1` | `descriptor_sha256`, `coverage_inventory_sha256`, `unit_definition_sha256`, `pass`, `architecture`, `host_inventory_sha256`, `target_allocation_sha256`, `gate_target_sha256` | 4,096 |

`disposable_host_id` is `N`, diagnostic correlation only. `host_instance_id`
and the byte-sorted unique `writable_resource_ids` array of 1..64 identifiers
are **actually observed** lifecycle identities for the host and every writable
disk/snapshot. `provisioning_evidence_sha256` refers to the new provisioning
object with identical host/resources and `result=fresh`. The trusted external
supervisor verifies that these actual resources were newly created from the
independently accepted immutable pristine base named by `pristine_base_sha256`.
That new artifact-digest field is distinct from isolated-object references:
it hashes the exact pristine-base artifact bytes, independently verified by the
external lifecycle supervisor before provisioning, and is not a recursively
decoded Gate authority object.
Provisioning times use `T` and require `provisioned_at <= observed_at <= created_at`.
This is external lifecycle evidence, not a protected Keychain inspection or
candidate claim of an empty registry. No candidate operation runs before token
authorization. The inventory has no token/session digest and cannot refer to
its future token. Only after unit authentication does setup obtain the shared
`stage_pre_enrollment_empty_inventory` payload before enrollment. The runtime
supervisor binds that observation to the same actual host/resources; it must
prove actual empty Keychain/journal/session state under the shared rules.
Lifecycle freshness never substitutes for this authenticated empty-state check.

`gate_target_sha256` names the unchanged shared 4,096-byte disposable
YouTrack 2026.2 target object, not just an origin string. Its account, exact
project, service/REST/OAuth topology, nonce and expiry are all validated.
`allocation_evidence_sha256` names a canonical object with fields `H` (type
`gate1b_isolated_target_observation_v1`), `service_url`, `project_id`,
`account_id`, `lifecycle_instance_id`, `project_created_at`, `observed_at`,
`result` exactly `fresh`; cap 4,096. URLs/IDs use the shared target grammar;
the lifecycle ID uses the resource grammar and both timestamps use `T`.
The trusted supervisor observes newly allocated empty project state and
verifies exact correspondence to the target, allocation, host, and unit.

Freshness compares normalized **(`service_url`, `project_id`)**, independently
of account aliases, project key, target nonce, host correlation nonce, token,
and session. It also compares actual host-instance/resource identities.
Every unit across both passes and every architecture must have a distinct
target pair, host instance, and writable-resource set with no overlap. The
external supervisor maintains this exclusion set during allocation and the
offline verifier reconstructs it from the complete parents. Distinct aliases
for the same underlying target/host resources are rejected using the trusted
control-plane identity mapping; URL-string variation cannot manufacture
freshness. An uncertain identity or earlier allocation remains unavailable.

## Unit authorization and context

| Type | Fields after `H`, in order | Cap |
| --- | --- | ---: |
| `gate1b_isolated_unit_token_v1` | `authority_key_id`, `binding_sha256`, `prerequisite_gate1a_e2_evidence_set_sha256`, `prior_e1_parent_sha256`, `gate_runner_unique`, `gate_session_id`, `allowed_capability`, `allowed_network`, `issued_at`, `expires_at` | 8,192 signed |
| `gate1b_isolated_setup_context_v1` | `unit_token_sha256`, `binding_sha256`, `gate_runner_unique`, `gate_session_id`, `setup_authorization` | 4,096 |
| `gate1b_isolated_receipt_context_v1` | `unit_token_sha256`, `binding_sha256`, `gate_runner_unique`, `gate_session_id`, `allowed_capability` | 4,096 |
| `gate1b_isolated_authority_evidence_v1` | `descriptor_bytes_base64url`, `descriptor_sha256`, `binding_bytes_base64url`, `binding_sha256`, `unit_token_bytes_base64url`, `unit_token_sha256`, `receipt_context_bytes_base64url`, `receipt_context_sha256`, `registry_chain_records_base64url`, `registry_chain_sha256`, `registry_revision`, `key_generation`, `verification_spki_der_b64u`, `signing_key_fingerprint_sha256` | 1,572,864 |

The binding supplies the token's `pass` (type `P`) and `architecture` (type
`A`); no duplicate independent values can disagree. E1 requires null
`prior_e1_parent_sha256`; E2 requires the complete accepted E1 parent for this
same descriptor/inventory, across **all** units and architectures, with every
target retired and host disposal attested before this E2 token is issued.
`prerequisite_gate1a_e2_evidence_set_sha256` is always required and names the
complete accepted Gate 1A E2 set for the exact descriptor. The signer verifies
these closures before issuing each unit token, never just their supplied hashes.

`allowed_capability` is exactly `issue_create_gate`; `allowed_network` is
exactly `exact_gate_target`. The shared Gate peer/challenge authentication,
native architecture check, profile/descriptor expiry matrix, exact target
sandbox, ordinary user-presence confirmation, and one-shot dispatch checks
remain mandatory. Each token has a fresh `gate_session_id`; runner unique
matches the pinned signed runner. Token lifetime is positive and at most 30
minutes and never extends target/profile validity. All live boundaries must
be inside their applicable validity intervals. Expiry, connection loss, crash,
or reboot cannot renew a token, authorize another unit, or clear quarantine.

The setup context's `setup_authorization` is exactly
`gate1b_first_exact_artifact_enrollment_only`. Its only entry is the unit's
first setup `enroll` operation, after the empty-state check. The ordinary
first-enrollment ceremony creates revision integer `1` and generation string
`YTAG-00000000000000000001`, durably closes and
cleans its own lease, and retains the immutable baseline snapshot. Setup then
ends irreversibly; it cannot sign receipts, send, rotate, recover, or enroll
again. Every scenario uses ordinary registry operations under its unit's
runtime context, not setup authority.

The receipt's existing `authorization_context_sha256` is the plain digest of
the new receipt-context object. Active and permit records bind the same context
digest; active and closed records also carry the receipt digest for apply.
Normal closed evidence binds their exact bytes. The retained authority branch
uses the shared base64url, genesis-to-current chain, SPKI, revision/generation,
signature, and aggregate chain bounds without changing their encodings. It
retains these new exact binding/token/context bytes and verifies their types,
root signature, all hashes, and reconstructed active key before receipt use.
The branch is never accepted as legacy Gate or production evidence. Observer
tokens cannot construct setup, receipt, or retained mutation authority.

## Reboot observer segment

Only the compiled real-reboot quarantine variant has two segments. Segment 1
finishes its scheduled unclosed state and immutable checkpoint while its unit
token/session is valid. The trusted supervisor then performs one real reboot
of **that same preserved host, writable resources, and target**, without
reverting a snapshot, resetting mutable state, or rerunning enrollment. All
other units have exactly one segment; there is no generic continuation mode.

| Type | Fields after `H`, in order | Cap |
| --- | --- | ---: |
| `gate1b_isolated_reboot_checkpoint_v1` | `binding_sha256`, `unit_token_sha256`, `segment_index_sha256`, `registry_snapshot_sha256`, `quarantine_state_sha256`, `host_inventory_sha256`, `finalized_at` | 4,096 |
| `gate1b_isolated_observer_token_v1` | `authority_key_id`, `binding_sha256`, `original_unit_token_sha256`, `checkpoint_sha256`, `reboot_evidence_sha256`, `gate_runner_unique`, `gate_session_id`, `allowed_capability`, `allowed_network`, `issued_at`, `expires_at` | 8,192 signed |

The checkpoint references the finalized segment-1 index, which never references
the future checkpoint, observer token, or parent. `quarantine_state_sha256`
names the shared exact active/permit/closed/journal state projection retained
by the compiled scenario, not a caller claim that the owner died. Reboot
evidence is a closed object with `H` type
`gate1b_isolated_reboot_observation_v1`, then `binding_sha256`,
`checkpoint_sha256`, `host_inventory_sha256`, `before_boot_id`,
`after_boot_id`, `preserved_resource_ids`, `observed_at`; cap 16,384. Boot IDs
use the resource grammar and must differ; resource IDs exactly equal inventory.
The external supervisor observes the real lifecycle event and preserved state;
a fixture, changed PID, local caller flag, or forged identifier is insufficient.

Only after verifying checkpoint and reboot evidence may the root issue the
new observer token to a newly authenticated runner session, with a fresh `N`
different from every scenario/observer session. Its positive lifetime is at
most 30 minutes; issuance checks the current descriptor/profile and the same
binding, original root token, and E1/E2 prerequisites. An expired original
token can be historically verified but is never resumed or accepted live.

Observer capability is exactly `quarantine_status_export_only`; network is
exactly `none`, enforced by the compiled sandbox. Its closed command allowlist
contains only the compiled read-only quarantine-status/state-observation and
sanitized evidence-export operations. No network, remote reconciliation,
setup, enrollment, signing, user-presence authority, permit, send, journal CAS,
close creation, deletion, or reset is available. The second segment proves
unchanged quarantine bytes and zero authority writes, not owner fencing.
Baseline snapshot remains segment 1's retained snapshot. Failure to retain the
checkpoint before reboot invalidates the unit; another authorization cannot
repair it or reconstruct missing live evidence.

## Leaf evidence and binding adapter

Shared observation, case-final aggregate, assertion/transcript result,
operation-template, inventory, snapshot, and state-projection **payloads** keep
their field order and caps. They are accepted only inside the new enclosing
objects below with the following normative binding adapter, not by decoding
an old Gate index/set and changing its meaning.

| Type | Fields after `H`, in order | Cap |
| --- | --- | ---: |
| `gate1b_isolated_leaf_index_v1` | `binding_sha256`, `unit_token_sha256`, `segment_ordinal`, `segment_token_sha256`, `segment_contract_sha256`, `gate_runner_unique`, `gate_session_id`, `macos_product_build_version`, `setup_context_sha256`, `pre_enrollment_inventory_sha256`, `registry_snapshot_sha256`, `started_at`, `finished_at`, `observations`, `result` | 1 MiB |
| `gate1b_isolated_target_retirement_v1` | `binding_sha256`, `target_allocation_sha256`, `gate_target_sha256`, `service_url`, `project_id`, `lifecycle_instance_id`, `retired_at`, `result` | 4,096 |
| `gate1b_isolated_export_v1` | `binding_sha256`, `unit_token_sha256`, `segment_indexes`, `target_retirement_sha256`, `files`, `exported_at`, `result` | 4 MiB |
| `gate1b_isolated_host_destruction_v1` | `binding_sha256`, `host_inventory_sha256`, `export_manifest_sha256`, `host_instance_absent`, `destroyed_resource_ids`, `verified_at`, `result` | 16,384 |
| `gate1b_isolated_host_disposal_v1` | `authority_key_id`, `binding_sha256`, `unit_token_sha256`, `host_inventory_sha256`, `export_manifest_sha256`, `destruction_evidence_sha256`, `exported_at`, `destroyed_at`, `attested_at`, `result` | 8,192 signed |

For segment 1, `segment_token_sha256=unit_token_sha256`; for segment 2 it
names the observer token referencing that original unit token. Index runner,
session, contract and ordinal exactly project their respective token/unit.
Observed native architecture and macOS build meet the descriptor/inventory
requirements, without Rosetta. `result` is exactly `pass`. Observation order,
IDs, scopes, roles, transcripts and final assertions exactly match that
segment's compiled tree, including all setup operations in segment 1.
Counts equal the compiled counts, with no omitted, duplicate or extra entries.

The adapter maps shared setup snapshot and enrollment IPC `stage_type` to `gate1b`,
`stage_token_sha256` to this unit token, and `setup_context_sha256` to the new
setup context. Descriptor/architecture and runner/session fields in all shared
setup payloads equal this binding and segment-1 token; IPC `approved_capability`
is exactly `issue_create_gate`. The selected enrollment transcript remains the
exact setup `/enroll` result with five ordered entries and its reconstructible
IPC projection, never a whole-unit or case-final manifest. Pre-enrollment
inventory has no token field; its authenticated runner/session identify only
the later setup observation. All other shared payload fields remain unchanged.
Before setup snapshot creation, observation
baseline is null exactly where the shared payload requires it. Snapshot and
later observations bind this unit's immutable baseline, including segment 2;
current registry revision/state is separate scenario evidence. Context/token/
binding mismatch, or another unit's otherwise valid snapshot, fails closed.

Shared local IDs are never concatenated with unit/architecture/pass names.
References crossing leaves use a closed tuple with fields `unit_ordinal`,
`architecture`, `segment_ordinal`, `observation_id`, in that order. The parent
determines pass; cross-pass references do not exist. Each tuple resolves one
compiled local ID inside exactly one authenticated leaf. Segment-2 assertions
may additionally inspect only their fixed checkpoint's segment-1 evidence,
not arbitrary prior output or mutable state from another unit.

After scenario execution has stopped and all segments are finalized, the
external operator retires the allocated target permanently and independently
observes that it can no longer accept this unit's writes. Retirement `result`
is exactly `retired`; target/lifecycle fields exactly match allocation. A
nonexistent project claim from the candidate, a new nonce on the same project,
or an inconclusive control-plane response cannot satisfy retirement. There is
no candidate target-reset/delete command and no automatic retry of a mutation.
Retirement failure blocks passing export, disposal attestation, and successors.

Export `segment_indexes` contains the exact ordered `D` references for the
unit's one or two indexes; `result` is exactly `verified`. It includes the
retirement record. `files` reuses the shared sorted path/size/digest grammar
and sanitized immutable closure rules, with at most 8,192 files, 8 MiB per
file, and 512 MiB aggregate for the two-segment maximum. Each individual leaf
still has at most 4,096 files/256 MiB. These are private Gate-evidence bounds,
not the post-grant installed-tree manifest bounds. No live tokens, credentials,
private keys or raw mutable journals/plans/receipts enter exported/installed
trees. Required private historical authority is retained separately in the
access-controlled incident store under the same checked closure limits.

Only after verified export does the external supervisor destroy the entire
host and every inventoried writable resource/snapshot. Destruction evidence
requires `host_instance_absent=true`, resource array exactly the inventory,
and `result=destroyed`, independently observed through lifecycle control.
Disposal attestation uses `result=destroyed` and the new signature domain.
It grants no candidate authority. The shared no-item-cleanup, no-self-disposal
proof and failure-quarantine rules apply unchanged. Ordering is
`finished_at <= retired_at <= exported_at <= destroyed_at <= attested_at`,
with actual lifecycle sequencing required even when whole-second times equal.

## Parent aggregation and freshness

| Type | Fields after `H`, in order | Cap |
| --- | --- | ---: |
| `gate1b_isolated_parent_v1` | `descriptor_sha256`, `coverage_inventory_sha256`, `pass`, `architectures`, `prerequisite_gate1a_e2_evidence_set_sha256`, `prior_e1_parent_sha256`, `units`, `family_results`, `assembled_at`, `result` | 4 MiB |

`units` is the exact Cartesian product of inventory unit order, then descriptor
architecture order. Each tuple has fields `unit_ordinal`, `architecture`,
`binding_sha256`, `unit_token_sha256`, `segment_indexes`,
`export_manifest_sha256`, `host_disposal_attestation_sha256`. Segment indexes
are exact ordinal-ordered digest arrays, not maps. `family_results` contains
exactly 26 objects in catalog order with `family_id`, `requirements`, `result`.
Each requirement has `requirement_id`, `sources`, `result`; `sources` is the
exact compiled nonempty ordered tuple array defined above. Every result is
exactly `pass` only after independently evaluating its retained assertions.
Setup requirements project every unit's setup assertion once per architecture;
other requirements project their single compiled variant per architecture.
The parent verifies derived coverage, never sums raw child pass bits.

The parent and every unit must agree on descriptor, inventory, pass, architecture
membership, Gate 1A prerequisite, and E1 baseline. E1 has null prior parent;
E2 names the complete accepted E1 parent for the same descriptor/inventory.
Every E2 scenario/observer authorization occurs after the entire E1 disposal
closure, not merely its corresponding unit/architecture. No child references
its future parent. The graph is strictly pre-token inventory/allocation ->
binding/token -> setup/observations/index -> retirement/export -> external
disposal -> parent; a reboot checkpoint/observer/index branch fits before
retirement. E1 parent -> E2 tokens is the only cross-pass baseline edge.
Cycles, ancestor-as-child references, missing/extra/reordered/duplicate units,
mixed baselines, self-contained subsets, or cross-context leaves fail even
when every individual signature and content hash is correct.

All required targets, host instances and writable resource IDs must be unique
across this parent and, for E2, its complete E1 parent. Every scenario and
observer token/session is globally unique. The reboot exception preserves
one unit's existing inventory/target across its two segments, never across
units or passes. Uncertain retirement/destruction, reused mutable snapshots,
or replacement UUIDs on old resources fail freshness; E1 state cannot seed E2.

The descriptor has at most two supported architectures, giving at most 512
unit tuples, 1,024 segment references and 4,194,304 file entries per parent;
checked aggregate evidence is at most 256 GiB per parent. These conservative
ceilings derive from unit/export bounds; actual exact compiled counts and
per-leaf caps remain mandatory. Traversal streams bounded manifests/files,
checks arithmetic and content-addressed path safety before reads, and rejects
duplicate manifest entries rather than relying on deduplication to meet caps.
Verification of E2 plus its E1 baseline checks at most two such parent
closures, not an unbounded chain. These are worst-case cost ceilings, not
typical run sizes or performance estimates. Every required referenced body
must still be read, hashed and validated; no hash-only shortcut, supplied pass
bit, or reduced closure can satisfy these bounds. Repeated Gate 1A prerequisites are resolved
once under their own fixed complete-set caps. No Gate 1B parent or private
evidence closure is copied into the post-grant installed tree.

Historical aggregation may occur after child token/profile expiry only when
retained evidence proves validity at **every** applicable live boundary and
all execution/retirement/disposal requirements passed. It cannot issue fresh
authority, restart a session, replay a write, or forgive missing observations.
Any later E2/provisional signature separately requires the current descriptor,
profile, complete accepted prerequisites and ordinary issuance-time checks.
For issue-create provisional authorization, the Gate 1B prerequisite is the
complete accepted E2 parent, never a leaf, legacy set, or mixed-pass subset.
The existing provisional fields `gate1b_e1_evidence_set_sha256` and
`gate1b_e2_evidence_set_sha256` select only the new complete E1 and E2 parents,
respectively, and `gate1b_plan_sha256` selects their identical new coverage
inventory. These are release prerequisite selectors, not permission to decode
a parent as a legacy Gate set or an inventory as an old flat plan. Gate 1A,
confirm-only null rules, smoke and post-grant selectors retain their existing
types and meanings.

## Required conformance vectors

Before freeze, one checked-in canonical vector set must be implemented by the
future independent encoders/verifiers. Positive fixtures contain no secrets;
negative semantic fixtures recompute affected content hashes and valid test
signatures so rejection cannot be attributed merely to corruption. This ADR
does not claim those codec tests or native outcomes already exist.

1. Complete E1 parent with all units/architectures and exact derived coverage.
2. Complete E2 parent bound to the entire disposed E1 parent, with fresh state.
3. One real-reboot unit with finalized checkpoint and observer-only segment.
4. Historical aggregation after expiry with all live boundaries valid.
5. Missing required atomic variant despite otherwise valid family pass bits.
6. Hidden multi-variant/reset operation or uncompiled inventory/contract digest.
7. Missing, duplicated, additional, or reordered unit/architecture/segment tuple.
8. Exceeded expansion/byte/count ceiling; no partial coverage is accepted.
9. Same target pair under different nonce, account alias, or unit token.
10. Reused actual host/disk/snapshot under different correlation UUIDs.
11. Host inventory referring to its future token, reused provisioning resources,
    or a nonempty authenticated pre-enrollment inventory.
12. Cross-unit setup snapshot/context/receipt or concatenated-ID alias.
13. E2 baseline naming a leaf, partial E1 parent, or another descriptor/inventory.
14. E2 issuance before the last required E1 retirement/disposal attestation.
15. Expired child at a live boundary, even if later aggregation is historical.
16. Observer authority attempting network, enrollment, signing, mutation or delete.
17. Reboot with old session/token, missing checkpoint, reset state, or changed target.
18. Forged/uncertain retirement or disposal, or missing private historical closure.
19. Legacy type/domain substitution and a cycle with recomputed valid hashes.
20. Correct child pass bits but incorrect exact assertion-source/coverage mapping.

Native exact-artifact evidence must additionally demonstrate the real reboot,
two independently authenticated helpers, actual target isolation, zero-write
quarantine, and trusted external lifecycle observations. Fake-boundary tests
can validate codecs and decisions, not these OS/remote facts. Until the exact
materialized coverage inventory, bounded contracts, vectors and native
implementations are verified, Gate 1B remains blocked and no successor
authorization, release, or Homebrew write-capable activation follows.
