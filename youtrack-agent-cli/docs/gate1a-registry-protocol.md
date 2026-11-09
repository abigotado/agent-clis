# Gate 1A approval-registry protocol

Status: normative design for Gate 1A; pure offline supplied-history and
supplied-ceremony verification are implemented in Go and Swift, but protected
registry integration is not implemented or production enabled. This document
freezes the helper-private approval-key ledger and the four authority ceremonies
and quarantine-only coordinator recovery.
It does not make `approval.Unsupported` usable.

The [trust-root ADR](gate1a-trust-root.md) owns the Keychain access group,
service, account naming, peer code requirements, and release boundary. This
document owns every authority-bearing byte stored under that service. The
[artifact-authorization contract](gate1a-artifact-authorization.md) owns the
`artifact_descriptor_sha256` value used below.

## Security properties and non-properties

The registry is a bounded, append-only, event-sourced ledger. A valid ledger
proves an unbroken sequence of locally authorized transitions from enrollment
to the current state. A transition is usable only when its complete canonical
record, predecessor, transcript digests, signatures, and state transition all
validate.

The CLI acceptance is not a CLI signature and is not durable independent
evidence of user intent. It is a digest-bound message on the live IPC
connection after both peers have authenticated the connection-bound audit
token. The helper repeats peer authentication immediately before the one-shot
Keychain add. The final old/new Secure Enclave signatures make the accepted
transcript and resulting state durable.

The ledger does not detect restoration of an older, internally complete
ledger snapshot by an administrator, Keychain compromise, or backup service.
That requires an external monotonic high-water mark and remains outside the
first release.

Protected access-group integrity and the exact signed helper's enforcement are
trusted. A same-user attacker may restore user-owned journal files but cannot
alter protected history under this assumption; whole-Keychain rollback is
excluded. These guarantees constrain this client's guarded transport only,
not independent requests made with credentials outside it. Deliberate denial
of service, including consuming the bounded lifetime below, is accepted.

## Primitive encodings

All authority objects are compact UTF-8 JSON objects. They contain no leading
or trailing bytes and no insignificant whitespace. Fields occur in the exact
order listed in this document. Decoders reject duplicate, missing, unknown, or
out-of-order fields; a non-object top level; alternate number, string, or null
encodings; and trailing data. After validation, the decoder re-encodes the
value and requires byte-for-byte equality with the input.

All string values are printable ASCII and contain no JSON escape. Except for
fields explicitly typed `OSStatus`, JSON integers are base-10 digits with no
sign and no leading zero, except the value zero itself. An `OSStatus` is a
canonical signed 32-bit JSON integer in `-2147483648..2147483647`, with token
grammar `^(0|[1-9][0-9]*|-[1-9][0-9]*)$` and an independent range check before
conversion. Positive values have no plus sign; negative zero, leading zeros,
fractions, exponents, strings, and overflow are invalid. This exception applies
only to explicitly declared Security.framework status values; it does not widen
revisions, counts, sizes, enum-valued status fields, or any other integer.
Absence is the numeric status `-25300`, not null. Nullable fields are exactly
JSON `null`, never an empty string.
Booleans are exactly `true` or `false`. Core registry and coordinator authority
objects have no arrays or nested objects.

The common grammar is:

| Name | Exact encoding |
| --- | --- |
| `schema_version` | JSON integer `1` |
| transition | one of `enroll`, `rotate`, `revoke`, `recover` |
| revision | JSON integer `0..256`; stored records use `1..256` |
| OSStatus | canonical signed int32 JSON integer; grammar and range above |
| digest | 64 lowercase hexadecimal characters |
| empty predecessor | 64 ASCII `0` characters |
| challenge | unpadded RFC 4648 base64url of exactly 32 bytes; 43 characters; decode/re-encode equality required |
| time | UTC RFC 3339 whole seconds, `YYYY-MM-DDTHH:MM:SSZ`, four-digit proleptic Gregorian year `0000..9999` |
| key generation | `YTAG-` followed by a 20-digit positive revision; it equals the revision that introduced the key |
| key ID | 32 lowercase hexadecimal characters encoding 128 random bits |
| key tag | `io.github.abigotado.youtrack-agent.approval.signing.v1/` followed by the key ID |
| SPKI | unpadded base64url of the exact 91-byte P-256 DER SubjectPublicKeyInfo; 122 characters |
| SPKI fingerprint | lowercase SHA-256 of those 91 bytes |
| key status | one of `active`, `retained`, `revoked` |
| signature | unpadded base64url of a strict low-S DER ECDSA P-256 signature; at most 96 characters |

The P-256 SPKI and signature rules are exactly those in
[Gate 1A approval protocol](gate1a-protocol.md#signature-and-public-key).
Every decoded public point must be on P-256. Each `(key_generation, key_id,
key_tag, spki, fingerprint)` tuple is internally consistent and unique across
the whole ledger. No generation, key ID, tag, SPKI, or fingerprint may ever be
reused, including after revocation.

The raw-byte caps are checked before parsing, allocation proportional to input,
base64url decoding, signature verification, or display:

| Object | Maximum bytes |
| --- | ---: |
| request | 2,048 |
| signed proposal | 4,096 |
| acceptance | 2,048 |
| final record body | 4,096 |
| complete stored record | 4,352 |
| commit authorization or reconciliation request | 6,144 |
| one Keychain registry item, including metadata returned by Security.framework | 8,192 |
| one coordinator active, permit, or closed item, including metadata | 8,192 |
| complete ledger records | 256 |
| aggregate canonical stored-record bytes | 1,114,112 |
| aggregate bytes returned by the bounded registry query (256 items) | 2,097,152 |
| aggregate bytes returned by the bounded coordinator query (513 items) | 4,202,496 |
| coordinator permit records | 256 |
| coordinator closed records | 256 |

The canonical-record aggregate bound is exactly `256 * 4,352`. Registry and
coordinator query bounds are separate: `256 * 8,192` and `513 * 8,192`.
More than the applicable item count, an item over its bound, an aggregate over its bound, or
Security.framework returning a value of an unexpected type fails before
sorting or cryptographic work.

## Exact Security.framework dictionaries and projections

Every Keychain call below is constructed by the helper from constants and
already validated canonical values. The CLI never supplies a dictionary key,
class, service, access group, match limit, return flag, synchronizable flag, or
accessibility value. A dictionary with a missing, additional, differently
typed, or differently valued entry is a protocol error before the call. All
CFString-to-data conversions below are exact UTF-8 over the already validated
printable-ASCII value, with no NUL or normalization.

The resolved private access group is the one exact value authorized by the
embedded profile and helper entitlement. `SecAccessControlCreateWithFlags`
uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and exactly
`.privateKeyUsage` plus the separately frozen `userPresence` or
`biometryCurrentSet` choice. No second accessibility or authentication policy
is tried.

The `SecKeyCreateRandomKey` attributes are exactly:

| Key | Value |
| --- | --- |
| `kSecAttrKeyType` | `kSecAttrKeyTypeECSECPrimeRandom` |
| `kSecAttrKeySizeInBits` | CFNumber integer `256` |
| `kSecAttrTokenID` | `kSecAttrTokenIDSecureEnclave` |
| `kSecUseDataProtectionKeychain` | `kCFBooleanTrue` |
| `kSecPrivateKeyAttrs` | the exact nested dictionary below |

The private-key dictionary contains exactly
`kSecAttrIsPermanent=true`, `kSecAttrApplicationTag` as CFData of the complete
key tag, `kSecAttrAccessGroup` as the resolved group, and
`kSecAttrAccessControl` as the successfully created access-control object.
Key creation must return one `SecKey` whose copied public key, 91-byte SPKI,
application tag, key type, size, token, and access group all match the proposal
before it can be used.

Signing and existence are different Keychain operations and never share a
query. An exact signing private-key lookup dictionary contains, in this order
in the protocol projection: `kSecClass=kSecClassKey`,
`kSecAttrKeyType=kSecAttrKeyTypeECSECPrimeRandom`,
`kSecAttrApplicationTag` as the exact tag CFData, `kSecAttrAccessGroup`,
`kSecUseDataProtectionKeychain=true`, `kSecMatchLimit=kSecMatchLimitOne`,
`kSecUseAuthenticationContext` as one newly created `LAContext` whose reuse
duration is zero, `kSecUseAuthenticationUI=kSecUseAuthenticationUIAllow`, and
`kSecReturnRef=true`. The context is an input only to that `SecItemCopyMatching`
lookup; `SecKeyCreateSignature` has no authentication-context parameter. On
successful lookup, the returned `SecKey` is passed to exactly one immediately
following `SecKeyCreateSignature`. The context is never reused for a lookup or
treated as a signing argument and is invalidated after lookup/signature success,
cancellation, or every other failure. Success must project to exactly one
`SecKey`; an array, dictionary, data value, or other CFType is malformed. No
retry, context replacement, or UI-policy fallback is allowed.

The noninteractive private-key existence dictionary contains exactly the same
class, key type, exact application tag, access group, data-protection flag, and
match-one entries, followed by
`kSecUseAuthenticationUI=kSecUseAuthenticationUIFail` and
`kSecReturnRef=true`; it contains no `LAContext`. Success projects to exactly
one typed `SecKey` and proves only presence, never signing authority.
`errSecItemNotFound:-25300` proves absence. Interaction-not-allowed, auth
failure, cancellation, wrong CFType, or every other status is neither presence
nor absence and fails closed. No label, generic tag, account, or caller
predicate is added to either lookup. Production key deletion is not provided.

The bounded private-key enumeration dictionary contains exactly
`kSecClass=kSecClassKey`, `kSecAttrKeyType=kSecAttrKeyTypeECSECPrimeRandom`,
`kSecAttrAccessGroup`, `kSecUseDataProtectionKeychain=true`,
`kSecMatchLimit=kSecMatchLimitAll`, and `kSecReturnAttributes=true`. Because
Keychain has no trusted prefix-match operator, the helper caps the returned
array at 64 before allocation proportional to its count, then projects each
dictionary to application-tag CFData, key type, integer key size, token ID,
access group, permanent flag, and synchronizable flag. The tag must decode to
the fixed prefix plus one canonical key ID; type, size, token, group, permanent
and synchronizable values must respectively be EC P-256, Secure Enclave, the
resolved group, true, and false. A non-array success, non-dictionary member,
duplicate tag, missing projected value, wrong CFType, unexpected item in this
private group, or result beyond the bound fails closed. Other OS-returned
diagnostic attributes are neither serialized nor used as authority.

Every registry or coordinator value is stored as a generic-password item.
The exact add dictionary contains `kSecClass=kSecClassGenericPassword`,
`kSecAttrService`, `kSecAttrAccount`, `kSecAttrAccessGroup`,
`kSecAttrAccessible=kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`kSecAttrSynchronizable=false`, `kSecUseDataProtectionKeychain=true`, and
`kSecValueData` as the complete canonical bytes. Registry items use the fixed
registry service and revision account. Coordinator items use the service and
accounts defined below. `SecItemAdd` receives no return flag.

The exact-account read dictionary contains `kSecClassGenericPassword`, exact
service, exact account, resolved access group, `kSecAttrSynchronizable=false`,
`kSecUseDataProtectionKeychain=true`, `kSecMatchLimitOne`,
`kSecReturnAttributes=true`, and `kSecReturnData=true`. Success must be one
dictionary whose projection contains exactly service CFString, account
CFString, access-group CFString, accessibility CFString, synchronizable
CFBoolean, creation/modification CFDates, and value CFData. The first five
must equal the query and fixed policy; both dates must be valid and modification
must not precede creation; value and total projected metadata must respect the
item bound. Authority uses only the exact value bytes. An array, duplicate,
wrong CFType/value, or missing projection field is ambiguous and fails closed.

The bounded service enumeration dictionary is the same except it omits
account and uses `kSecMatchLimitAll`. A success result must be an array of
1..256 dictionaries for the registry or at most one active plus 256 permit and
256 closed dictionaries for the coordinator. The aggregate raw/projection
bound is 2,097,152 bytes for registry and 4,202,496 bytes for coordinator.
Projection occurs before sorting; accounts are then
validated and sorted by canonical revision or record kind/lease ID. A bare
dictionary for match-all, duplicate account, unknown account, unexpected
value, or `errSecSuccess` with an empty collection is malformed. Only
`errSecItemNotFound` represents an empty service.

The coordinator's final pre-send state probe is exactly three sequential
exact-account reads with the dictionary above: `active` must return bytes equal
to the acquired active record, `permit/<lease-id>` must return bytes equal to
the one permit, and `closed/<lease-id>` must return only
`errSecItemNotFound:-25300`. No match-all query, cached result, combined
predicate, reordered call, or extra read can replace this probe. The helper
then repeats peer audit-token/session, profile/token validity, and receipt-TTL
checks without releasing the coordinator. Trusted time must be strictly before
the signed receipt's `expires_at`; equality is expired. Any mismatch,
noncanonical result or expired receipt prevents send. A post-permit denial
is `ambiguous`, never a new send attempt or `failed_before_mutation`.

Registry revisions, coordinator permit/closed records, and approval private
keys are never deleted by this first-release protocol. Disjoint synthetic Gate
fixtures may model deletion outcomes but confer no live deletion authority.
Test hosts are destroyed externally after evidence export; neither ordinary
helper code nor a stage token implements cleanup of their Keychain contents.

The only live deletion is exact cleanup of an already durably closed active
item. Its read uses the exact-account dictionary above with the single added
entry `kSecReturnPersistentRef=true`. One successful result must contain the
same validated attributes and data plus `kSecValuePersistentRef` as nonempty
CFData of at most 4,096 bytes. Attributes, exact active bytes, and persistent
reference must come from that same query result; a second query cannot supply
a missing reference. The reference is an opaque local capability, never a
JSON field, journal value, command argument, diagnostic, or exported artifact.
Wrong type, an empty/oversized reference, malformed metadata, or any uncertain
result prevents deletion. The 8,192-byte projected item cap still applies to
the complete result including that reference.

Before deletion the helper performs the fresh full bounded capacity classification
below; a valid closed exhaustion sentinel is never deleted, and uncertainty
never authorizes deletion. It then validates the complete immutable active/permit/
closed chain and the exact terminal journal or registry candidate/outcome.
A matching durable `closed` is mandatory even when the journal already holds
terminal outcome or normal-closed candidate bytes. The exact delete dictionary
contains only `kSecMatchItemList` as a one-element CFArray containing that
captured persistent-reference CFData, and
`kSecUseDataProtectionKeychain=true`. It contains no class, service, account,
value, match limit, or return flag. There is no attributes-only fallback.
`SecItemDelete` returns only `OSStatus`; no CF result is accepted.

The delete targets item identity rather than the reusable `active` primary
key. If another cleanup process deletes A and an independent helper acquires
B between A's equality read and deletion, A's reference cannot delete B. A
missing old reference (`errSecItemNotFound:-25300`) is successful `stale_noop`,
even when a new exact-account read would return B. Success is `deleted`. Any
other delete status allows one bounded read by the same persistent reference,
with `kSecMatchItemList`, data-protection selector, and return attributes/data
flags only: absence is `already_absent`; a still-present identical A is
`APPLY_COORDINATOR_ACTIVE_DELETE_AMBIGUOUS`; malformed or conflicting result
is `AUTHORITY_STATE_CORRUPT`. No result authorizes a second physical delete in
that invocation. A later explicitly requested cleanup begins with a new exact
account read and complete closed linkage validation, never by reusing an old
reference or deleting the currently named account blindly.

## Domains and hashes

Domain strings below are ASCII including the final NUL byte. Concatenation has
no length prefix because the left operand has fixed bytes and the right operand
is one complete canonical JSON object.

| Purpose | Domain |
| --- | --- |
| request digest | `YTA-REGISTRY-REQUEST-V1\0` |
| proposal signature | `YTA-REGISTRY-PROPOSAL-V1\0` |
| proposal digest | `YTA-REGISTRY-PROPOSAL-DIGEST-V1\0` |
| acceptance digest | `YTA-REGISTRY-ACCEPTANCE-V1\0` |
| recovery evidence digest | `YTA-REGISTRY-RECOVERY-EVIDENCE-V1\0` |
| recovery continuity probe | `YTA-REGISTRY-RECOVERY-CONTINUITY-PROBE-V1\0` |
| registry intent digest | `YTA-REGISTRY-INTENT-V1\0` |
| old-key final signature | `YTA-REGISTRY-RECORD-OLD-V1\0` |
| new-key final signature | `YTA-REGISTRY-RECORD-NEW-V1\0` |
| commit-candidate digest | `YTA-REGISTRY-COMMIT-V1\0` |
| coordinator active digest | `YTA-APPLY-COORDINATOR-ACTIVE-V1\0` |
| coordinator permit digest | `YTA-APPLY-COORDINATOR-PERMIT-V1\0` |
| coordinator closed digest | `YTA-APPLY-COORDINATOR-CLOSED-V1\0` |

`request_sha256`, `proposal_sha256`, `acceptance_sha256`, and
`recovery_evidence_sha256` are lowercase SHA-256 over their respective domain
followed by the complete canonical object. The proposal digest includes its
`proposal_signature`. The record
digest used by commit authorization is SHA-256 over the commit domain followed
by the complete stored record.
A setup context digest is plain SHA-256 of its exact canonical context bytes,
as frozen by the artifact-authorization protocol; it is not a signing domain.

`previous_record_sha256` is deliberately different: it is lowercase SHA-256
over the exact complete prior stored-record bytes, with no domain prefix. The
first record uses the empty-predecessor value. No decoded/reconstructed form
may substitute for those exact prior bytes.

## Ceremony request

The CLI produces one request with these fields in order:

1. `schema_version`
2. `message_type`, exactly `registry_request`
3. `transition_kind`
4. `recovery_mode`, null for other transitions or exactly
   `missing_key_item_or_disabled_registry` for recovery
5. `challenge`
6. `expected_registry_revision`
7. `previous_record_sha256`
8. `artifact_descriptor_sha256`
9. `target_generation`
10. `new_generation`
11. `requested_at`
12. `expires_at`

The challenge is freshly generated for every attempt. `expires_at` is strictly
after `requested_at` and at most five minutes later. Both peers reject a
request outside that closed clock window; tolerated clock skew is at most 30
seconds and never extends `expires_at`.

The exact transition-specific values are:

| Transition | Expected revision | Target generation | New generation |
| --- | ---: | --- | --- |
| enrollment | `0` | `null` | generation for revision 1 |
| rotation | current | current active generation | generation for current + 1 |
| revocation | current | current active generation | `null` |
| recovery | current | current active generation, or `null` when no active key exists | generation for current + 1 |

The previous digest is empty only for enrollment. Otherwise it equals the
SHA-256 of the complete current record. The artifact-descriptor digest equals
the currently authorized exact-artifact descriptor and may not change during
a ceremony.

### Recovery eligibility evidence

Recovery never means “the old signature was inconvenient.” It is eligible only
when the complete existing ledger is valid and either it has no active
generation after an explicit revocation, or the exact active private-key item
is absent from the helper-private Keychain namespace.

For an active generation, after trusted UI and fresh user authentication, the
helper performs exactly one noninteractive existence lookup for the ledger's
exact active tag using the UI-fail dictionary above. Only
`errSecItemNotFound` (OSStatus `-25300`) establishes absence. If a typed key
reference is returned, the helper creates a fresh zero-reuse `LAContext`,
performs exactly one signing lookup with the separate UI-allow dictionary, and
uses only that returned key for exactly one `SecKeyCreateSignature`
continuity-probe signature over
the recovery-continuity-probe domain followed by the exact request bytes:

- a valid signature proves continuity is available, ends recovery with
  `RECOVERY_CONTINUITY_AVAILABLE`, discards the probe, and directs the operator
  to rotation or revocation with a new challenge;
- cancellation, authentication failure, interaction-not-allowed, key-use
  failure, transient/unavailable status, malformed result, or any other error
  ends with `RECOVERY_ELIGIBILITY_UNPROVEN`; and
- none of those errors is reclassified as key loss or retried automatically.

If the existence lookup returns any status other than success with one typed
key reference or `errSecItemNotFound`, or the subsequent signing lookup returns
anything other than one typed key under its exact fresh context, recovery fails with
`RECOVERY_ELIGIBILITY_UNPROVEN`. A disabled valid ledger performs no key query.

An eligible helper constructs this canonical evidence object:

1. `schema_version`
2. `message_type`, exactly `registry_recovery_evidence`
3. `request_sha256`
4. `challenge_sha256`
5. `registry_revision`
6. `previous_record_sha256`
7. `artifact_descriptor_sha256`
8. `target_generation`
9. `target_key_tag`
10. `eligibility`, `active_key_item_not_found` or `registry_disabled`
11. `key_lookup_result`, exactly `errSecItemNotFound:-25300` for the former or
    `not_attempted:registry_disabled` for the latter
12. `continuity_probe_result`, exactly `not_attempted:no_key` or
    `not_attempted:no_active_generation`, respectively
13. `probed_at`

Active-key fields are exact non-null ledger values for
`active_key_item_not_found` and null for `registry_disabled`. The object is
capped at 2,048 bytes. Its domain-separated digest is inserted into every later
recovery message and the final signed record. It is null for every other
transition. Trusted UI displays the eligibility, target generation/fingerprint
when present, and the fact that recovery revokes all prior generations before
the CLI can accept the proposal.

## Signed proposal

After peer validation, ledger validation, trusted UI, and fresh user presence,
the helper returns a proposal. Its unsigned form contains these fields in
order:

1. `schema_version`
2. `message_type`, exactly `registry_proposal`
3. `transition_kind`
4. `request_sha256`
5. `challenge_sha256`
6. `registry_revision`
7. `previous_record_sha256`
8. `artifact_descriptor_sha256`
9. `recovery_evidence_sha256`
10. `target_generation`
11. `target_key_id`
12. `target_key_tag`
13. `target_spki`
14. `target_fingerprint_sha256`
15. `new_generation`
16. `new_key_id`
17. `new_key_tag`
18. `new_spki`
19. `new_fingerprint_sha256`
20. `proposed_at`
21. `expires_at`
22. `proposal_signer_role`

The signed proposal appends `proposal_signature` as field 23. It signs the
proposal domain followed by the exact unsigned proposal bytes.
`challenge_sha256` is SHA-256 over the decoded 32-byte challenge.

Target fields are all non-null for rotation, revocation, and recovery when an
active target exists, and are all null otherwise. New-key fields are all
non-null for enrollment, rotation, and recovery, and all null for revocation.
Partial tuples are invalid. `recovery_evidence_sha256` is required only for
recovery and must match the exact eligible object above; it is null otherwise.
`registry_revision` is the proposed new revision.
The proposal repeats the request expiry; `proposed_at` is not before
`requested_at` and is before expiry.

For enrollment, rotation, and recovery, `proposal_signer_role` is `new` and
the proposed new key signs. For revocation it is `old` and the current active
key signs. Proposal signing uses a fresh zero-reuse authorization context. A
failed signature attempt ends the ceremony; it is not silently retried.

## CLI acceptance

The CLI revalidates the helper on the same connection, parses the proposal,
checks the request digest, challenge, artifact descriptor, revision,
predecessor, all key
bindings, time window, and proposal signature, and then sends this exact
canonical object:

1. `schema_version`
2. `message_type`, exactly `registry_acceptance`
3. `transition_kind`
4. `request_sha256`
5. `proposal_sha256`
6. `challenge_sha256`
7. `registry_revision`
8. `previous_record_sha256`
9. `artifact_descriptor_sha256`
10. `recovery_evidence_sha256`
11. `target_generation`
12. `new_generation`
13. `accepted_at`
14. `expires_at`
15. `accepted`, exactly `true`

`accepted_at` is not before `proposed_at` and is before expiry. An acceptance
received on another connection, after audit-token identity changes, or after
any reauthentication failure is invalid even if its bytes are otherwise
canonical. It conveys no authority outside that authenticated live transcript.

## Final body and stored record

The helper reauthenticates the live CLI, rereads and validates the entire
ledger, and constructs a final body with these fields in order:

1. `schema_version`
2. `record_type`, exactly `approval_registry_transition`
3. `transition_kind`
4. `registry_revision`
5. `previous_record_sha256`
6. `request_sha256`
7. `proposal_sha256`
8. `acceptance_sha256`
9. `challenge_sha256`
10. `artifact_descriptor_sha256`
11. `recovery_evidence_sha256`
12. `requested_at`
13. `accepted_at`
14. `committed_at`
15. `target_generation`
16. `target_key_id`
17. `target_key_tag`
18. `target_spki`
19. `target_fingerprint_sha256`
20. `target_previous_status`
21. `target_new_status`
22. `new_generation`
23. `new_key_id`
24. `new_key_tag`
25. `new_spki`
26. `new_fingerprint_sha256`
27. `new_status`
28. `revokes_all_prior`

The complete stored record appends these fields:

29. `old_signature`
30. `new_signature`

Each non-null signature covers its role-specific record domain followed by the
exact final-body bytes, so both signatures bind the acceptance digest and
every resulting state field. Signatures are produced once; their exact bytes
are retained through commit and reconciliation.

`recovery_evidence_sha256` is the verified eligibility-object digest for
recovery and null for every other transition. Consequently the new-key recovery
signature durably binds the missing-item or disabled-registry basis, the live
CLI acceptance, and the revoke-all result.

The only legal field combinations are:

| Transition | Target status change | New status | Revoke all prior | Old signature | New signature |
| --- | --- | --- | --- | --- | --- |
| enrollment | all target fields `null` | `active` | `false` | `null` | required |
| rotation | `active` to `retained` | `active` | `false` | required | required |
| revocation | `active` to `revoked` | all new fields `null` | `false` | required | `null` |
| recovery | active target to `revoked`, or all target fields `null` | `active` | `true` | `null` | required |

Enrollment is legal only for an empty ledger. Rotation and revocation require
the target tuple to equal the current active entry. Recovery is legal only
after the exact eligibility procedure succeeds; it may name the current active
tuple for display, but it has no old signature. A returned current key, a
successful continuity probe, or any lookup/auth/sign result other than the
exact eligible states above forbids recovery. A reachable old key must use
rotation or revocation with a fresh challenge.

`committed_at` is not before acceptance and is before expiry. The helper must
not alter a proposal tuple while producing the final record. All inapplicable
fields are literal null.

## State derivation

Consumers always replay all records from revision 1. They never trust a cached
snapshot without replaying and byte-comparing the underlying ledger.

The derived state maps every introduced generation to exactly one status and
holds zero or one active generation:

- enrollment introduces one active generation;
- rotation changes the one active generation to retained and introduces a new
  active generation;
- revocation changes the one active generation to revoked and leaves no active
  generation;
- recovery changes every previously active or retained generation to revoked
  and introduces one new active generation.

Revoked is terminal. Retained keys verify historical receipts only. Only the
single current active generation may authorize a new receipt, and the receipt
must carry the current registry revision. Every transition cancels all
outstanding confirmed plans, including a transition that does not change a
receipt's referenced public key.

A valid ledger has exactly one item for every revision from 1 through its
maximum, no other matching account, an empty predecessor only at revision 1,
and an exact predecessor hash thereafter. Every event must be legal for the
state derived immediately before it. Recovery is never allowed to bypass a
gap, fork, malformed predecessor, bad signature, or invalid prior event.

Before any registry ledger read, proposal validation, key generation, presence
request, or signing work, the requesting peer constructs one compact canonical
registry intent capped at 1,024 bytes. Its fields are, in order,
`schema_version` integer `1`, `intent_type` exactly `registry_commit`,
`transition_kind`, `artifact_descriptor_sha256`, `ceremony_nonce`,
`requested_at`, and `expires_at`. The transition is exactly `enroll`,
`rotate`, `revoke`, or `recover`; the nonce is unpadded base64url of 32
fresh random bytes; expiry is after issue and at most five minutes later. Its
digest is SHA-256 of ASCII `YTA-REGISTRY-INTENT-V1` plus NUL followed by the
exact canonical bytes. This `registry_intent_sha256` is available before the
first mutable authority read and is the only registry-operation payload bound
into coordinator acquisition. It expresses intent, not eligibility or a
candidate winner.

Confirmation is not coordinator ownership. Before registry/signing/journal work,
and again immediately before signing or recording a receipt, confirmation
performs bounded read-only coordinator classification. An observed active item
blocks confirmation; an unclosed item is quarantine. These checks are admission
snapshots, not a cross-process lock: another helper may acquire active after a
check. Any resulting receipt still confers no send capability and must pass
fresh serialized apply validation; changed registry/context cancels it. A
helper that has observed quarantine performs no confirmation signature or
journal write. No alternate confirmation endpoint bypasses these checks.

### Offline verification of a supplied history

`approval.VerifySuppliedRegistryHistory(records)` in Go and
`SuppliedRegistryHistory.verify(suppliedRecords:)` in Swift verify only the
caller-supplied complete stored records. They are pure prerequisite code: no
network, Keychain, clock, journal, signing, user interface or authority lookup is
performed. There is no cached-state seed, continuation, append or signing API.

Verification has four global phases: all raw count and per-record bounds;
canonical decoding and exact re-encoding of every record; primitive grammar,
tuple, SPKI, fingerprint and strict low-S DER checks for every record; then
predecessor hashing, ECDSA signatures and genesis-to-tip state replay. A later
encoding or grammar failure therefore precedes an earlier signature failure.
Go takes bounded owned copies after the complete raw preflight and uses only
those copies afterwards; callers must not mutate input buffers during the call.
Swift retains only value-owned data. Invalid input returns no partial history.
Errors identify only a static validation phase, never decoder diagnostics or
caller-controlled strings.

The count cap of 256 and per-record cap of 4,352 jointly enforce the normative
aggregate bound of 1,114,112 bytes before copying or parsing. That aggregate is
a derived invariant, not an independently tighter limit.

Input order is significant and is never sorted. Every supplied record must be
present from revision 1 to the supplied tip, with exact plain-byte predecessor
hashes and no reused key-tuple component. The result exposes only the supplied
tip revision, its plain SHA-256, its descriptor digest claim and the derived key
tuples/statuses in introduction order. Returned Go key slices are copies.
Historical descriptor claims may differ between ceremonies.

An empty input is an internally consistent empty supplied history: revision 0,
the zero predecessor digest, no descriptor and no keys. Every proper valid
prefix also succeeds. **Neither an empty nor a nonempty result establishes
completeness, protected-registry absence or the current protected tip.** An
attacker can supply a self-signed genesis or an older valid prefix. They can
also copy a valid prefix and append a self-signed recovery record introducing
their own key: recovery has no old-key signature, and the supplied evidence
digest does not prove eligibility. Even a supplied tip derived from a genuine
prefix therefore does not establish authorized key continuity. Results
must not seed `ExpectedReceiptBinding`, signing, confirmation, registry commit
or a trusted authority cache. Future protected enumeration, artifact/root
authorization and native integration must independently establish those facts.

Stored records contain only transcript digests, not the original request,
proposal, acceptance, recovery evidence or expiry. Verification checks the
recorded order `requested_at <= accepted_at <= committed_at` and the necessary
whole-second bound `committed_at - requested_at < 300`: the actual request
expires at most 300 seconds after request and commit must precede expiry. This
does not check chronology between different records, reconstruct exact expiry,
establish freshness, check nonce entropy or
nonce/transcript-digest claim uniqueness, or validate the missing transcript
objects. This is not full ceremony validation. Registry calendar grammar retains
year zero, unlike the receipt-specific timestamp grammar. A signed recovery
digest is a declaration, not evidence of native key absence or recovery
eligibility.

### Offline verification of a supplied ceremony

`approval.VerifySuppliedRegistryCeremony(prefixRecords, ceremony)` in Go and
`SuppliedRegistryCeremony.verify(prefixRecords:ceremony:)` in Swift additionally
check a complete supplied ceremony against its supplied genesis-to-tip prefix.
Inputs retain the exact request, optional recovery evidence, unsigned and signed
proposal, acceptance, final body and complete candidate record. This is a pure
consistency check, not an append, signing, protected-storage or admission API.

Verification uses the same global phase order: raw bounds for all objects;
canonical decoding and exact re-encoding for every prefix and ceremony object;
primitive grammar for every object; then prefix replay and ceremony verification.
The prefix plus candidate is bounded to 256 complete records of at most 4,352
bytes each. Request, acceptance and present recovery evidence are nonempty and
at most 2,048 bytes; each proposal and final body is nonempty and at most 4,096
bytes. Absent recovery evidence is distinct from a present empty object. Go
snapshots every input buffer after raw preflight; callers must not mutate them
during the call. Swift inputs are value-owned. Errors disclose only a static
phase and return no partial result.

The check recomputes all transcript digests and proposal/final signatures,
binds revisions, predecessor, descriptor and key tuples across all objects, and
requires the redundant unsigned proposal and final body to equal their exact
signed-object projections. It checks the supplied request's exact lifetime
`0 < expires_at - requested_at <= 300`, repeated timestamps and expiry, and
`requested_at <= proposed_at <= accepted_at <= committed_at`, with proposal,
acceptance and commit strictly before expiry. A recovery probe declaration must
fall between request and proposal and before expiry; its exact eligibility,
lookup and continuity-probe claims must agree with the prefix-derived state.
The candidate is replayed once and the result is a `SuppliedRegistryHistory`.

All supplied-history non-authority restrictions apply unchanged. In particular,
consistent recovery evidence does not establish an actual native lookup or key
absence; accepted transcript bytes do not prove user presence or intent. A
self-signed genesis, self-signed recovery, valid older prefix or expired
historical ceremony can be internally consistent. The result proves neither
protected completeness/current tip, trusted time or freshness, artifact/root
authorization, coordinator ownership nor permission to sign, confirm, commit
or send. It must not seed `ExpectedReceiptBinding` or any trusted authority
cache. No native, journal or command integration is enabled by this verifier.

## Helper-owned apply authority coordinator

The signed helper normally runs as the embedded launchd user agent described
by the trust-root ADR and binds its fixed endpoint itself. Launchd registration,
job labels, parent constraints, and a process-local executor do not prove a
global singleton. The threat model includes another exact signed helper in an
alternate same-UID bootstrap context and a suspended original owner.

Each helper has one non-reentrant serialized authority executor. Its guard
orders that process's callbacks only; it never excludes another process's
Keychain calls. Cross-process exclusion comes solely from the unique fixed
`active` primary key and its successful one-shot `SecItemAdd`. A losing
acquisition cannot read the registry, generate keys, sign, issue a permit,
send, or commit. Bounded coordinator status reads do not acquire authority.

Only the original uninterrupted authenticated owning connection may complete
a lease. Before storing normal `closed`, that owner irreversibly quiesces every
send/sign/permit/registry-commit capability, queued callback, and outstanding
operation that could exercise them. Quiescence must finish before close bytes
are added; the implementation must prove no capability can survive the close.
A disconnected or restarted process cannot inherit or reconstruct ownership.
Any non-owner finding an active item without its valid durable close enters
read-only quarantine. Time, expiry, PID loss, user presence, helper restart,
bootstrap replacement, and reboot do not release that lock. This deliberately
sacrifices write availability after an unclosed crash. Automated recovery or
reset of such a lease requires a separate reviewed protocol and is deferred.

All helper processes therefore serialize registry commits and mutation sends
through one helper-private coordinator service:

```text
io.github.abigotado.youtrack-agent.approval.apply-authority.v1
```

Its only accounts are `active`, `permit/<lease-id>`, and
`closed/<lease-id>`. A lease ID is `YTAL-` followed by uppercase unpadded RFC
4648 Base32 of 16 random bytes; decode/re-encode equality is required. The
fixed `active` account is the crash-durable cross-client mutex: both an apply
attempt and a registry commit must, while holding the authority-executor
guard, successfully create it with one `SecItemAdd` before their first
authority-state read. Every accepted client therefore contends on the same
Keychain primary key rather than an independent process or filesystem lock.
`errSecDuplicateItem` grants no authority; this helper's live-owner contention
is busy, while non-owner unclosed state is quarantine.

The active value is compact canonical JSON capped at 4,096 bytes with fields
in this order: `schema_version`, `record_type` exactly
`apply_coordinator_active`, `lease_id`, `operation_kind` exactly `apply` or
`registry_commit`, `coordinator_session_id`, `cli_audit_token_sha256`,
`artifact_descriptor_sha256`, `authorization_context_sha256`,
`registry_revision`, `plan_id`, `journal_revision`, `receipt_sha256`, `registry_intent_sha256`,
`created_at`, and `expires_at`. The session ID is unpadded base64url of 32
fresh random bytes. The CLI digest is required for both operation kinds.
Apply requires the exact context eligible for its closed mode—canonical
`gate1b_isolated_receipt_context_v1` only in its authenticated Gate 1B unit
session under [isolated subruns](gate1b-isolated-subruns.md), the smoke receipt
context only in activation smoke, or the grant-bound
final context only in production/post-grant verification—plus registry
revision, plan, journal revision, and signed receipt digest, and sets registry intent null. Production,
smoke, and post-grant modes reject the Gate context before active acquisition.
For `operation_kind=apply`, `registry_revision` is an exact JSON integer in
`1..256`, and `plan_id` is `YTAP-` followed by uppercase unpadded RFC 4648
Base32 of exactly 16 decoded bytes; decode/re-encode equality is required.
`journal_revision` is an exact JSON integer, `2` or `3`, claiming the
confirmed v2 journal revision to be validated after active acquisition.
Only these combinations are admitted:

| Prepared v2 origin | Confirmed state at active acquisition | `legacy_v1_record_sha256` | Active `journal_revision` |
| --- | --- | --- | --- |
| fresh `prepared` at revision 1 | `confirmed` at revision 2 | `null` | `2` |
| migrated v1 `prepared` at revision 2 | `confirmed` at revision 3 | non-null digest retained from the validated migration | `3` |

Any other state/revision/provenance combination is ineligible for apply. After
active acquisition, the CLI's apply coordinator validates the complete
confirmed state/revision/provenance combination from its locked journal record
before its `confirmed -> in_flight` CAS. The helper validates the active record's
grammar and protected registry, receipt, context, and coordinator history; it
cannot independently establish journal provenance from the same-user-writable
journal or treat a CLI claim as authority. A claimed revision alone grants no
permit or send. The active and permit `journal_revision` fields both record
the confirmed predecessor: `2` for fresh and `3` for migrated plans. The
closed record's journal-revision set remains deferred until the full v2
transition matrix is frozen.

Registry commit requires the pre-read
registry-intent digest and sets context, registry revision, plan, and journal
revision and signed receipt digest null. Its eventual request/proposal/candidate is constructed and
validated later while the lease is held and must repeat the intent's
transition and descriptor; its `challenge` equals the intent's decoded
`ceremony_nonce` bytes re-encoded by the request codec, and its expiry equals
the intent expiry. It never changes
the acquired active bytes. Expiry is strictly after creation and at most
600 whole seconds later (a lifetime of 1 through 600 seconds inclusive).
Expiry never turns an abandoned record into permission
to delete, steal, or reuse it.

An apply permit is compact canonical JSON capped at 4,096 bytes with fields
`schema_version`, `record_type` exactly `apply_coordinator_permit`, `lease_id`,
`active_sha256`, `coordinator_session_id`, `cli_audit_token_sha256`,
`artifact_descriptor_sha256`, `authorization_context_sha256`,
`registry_revision`, `plan_id`, `journal_revision`, `receipt_sha256`,
`mutation_request_sha256`, `issued_at`, and `expires_at`, in that order. It is
stored once under `permit/<lease-id>`. Every field is non-null. Its shared
binding fields repeat the validated active lease, including the confirmed
predecessor `journal_revision` (`2` or `3`). The receipt digest binds the
exact canonical signed receipt, `mutation_request_sha256` binds the final HTTP
request bytes, and the permit expiry equals the active expiry. A permit is evidence
for at most one send on the still-open authenticated coordinator connection;
it is not a bearer token and is never returned as caller-selectable bytes.

A closed value is compact canonical JSON capped at 4,096 bytes with fields
`schema_version`, `record_type` exactly `apply_coordinator_closed`, `lease_id`,
`active_sha256`, `permit_sha256`, `receipt_sha256`, `operation_kind`, `terminal_outcome`,
`journal_revision`, `registry_record_sha256`, `closed_at`, and `close_mode`, in
that order. `close_mode` is exactly `normal`; recovery actor, recovery reason,
and recovery-close fields are not part of this unimplemented codec. Journal
revision is required for apply and null for registry commit. Registry-record
digest is null for apply. For registry commit it is required for a retained
commit candidate. `registry_record_sha256` is the commit-candidate digest of
the exact complete retained record, not the undomained hash used for predecessor
links; the closed object does not embed the candidate bytes. This field is
otherwise null only for a provably pre-candidate registry abort with
`terminal_outcome=registry_not_committed`. Such an abort retains the
exact intent and owner-produced normal close; the close binds the active digest
and therefore that intent, and no candidate or revision add is inferred.
Registry commit never has a permit and sets `receipt_sha256` null.
Apply requires this digest even when no permit exists; it repeats active and,
when present, permit exactly.
Apply permit digest is null only when the uninterrupted owner proves that no
permit was issued, and required exactly when its permit exists.
`terminal_outcome` is exactly `registry_committed`, `registry_not_committed`,
`failed_before_mutation`, `applied`, or `ambiguous`.
For apply, `failed_before_mutation` is legal if and only if no permit exists.
After a permit, only verified success is `applied`; every other result is
`ambiguous`, including a denied send with proven zero mutation bytes. Later
eligible read-only reconciliation may report `resolved_not_applied`; it cannot
rewrite the immutable close or authorize another permit.

Only the original uninterrupted owner constructs and stores a normal close,
after irreversible capability quiescence. Its exact bytes are durably retained
with the terminal journal outcome or registry candidate/outcome evidence before
the one close add. `closed/<lease-id>` and permit records remain immutable and
are never deleted in this release. The capacity protocol below blocks new work
at either 256-record bound without preventing the admitted owner's normal close.
An outcome or locally retained closed candidate is not a substitute for the
actual durable Keychain closed item.

`receipt_sha256` is lowercase SHA-256 of the exact complete canonical
signed receipt bytes, including its strict low-S signature. Before computing
the digest or touching mutable authority, parse strictly and require canonical
byte-for-byte re-encoding, including low-S DER validation. Under the acquired
active lease, enumerate and validate ALL protected permit and closed history
within the bounds above, independently of enumeration order, before any permit
add. Any prior occurrence of this digest forbids a fresh permit, even after
restoring a user-owned journal to `confirmed` or acquiring a new lease. The
global invariant is at most one permit per signed receipt, across all leases.
Repeated replay-denial closes with the same digest are valid only with null
permit and `failed_before_mutation`; digest uniqueness is not required for
closed records. Every normal pre-permit close burns the receipt, including a
null-permit abort. An interrupted close remains quarantine. Journal CAS is
crash bookkeeping, not same-user anti-replay authority.

### Bounded lifetime and exhaustion sentinel

Before acquisition, bounded read-only classification checks capacity. An
admitted owner must finish its normal close first, then perform a fresh complete
bounded enumeration of protected coordinator history while retaining its active
item. If either permit or closed count reaches 256, it retains that matching
VALID CLOSED active item as the exhaustion sentinel. Capacity must never prevent
this owner's final close. If both counts remain below 256 and all linkage is
valid, exact-reference cleanup may proceed. Uncertain classification never
deletes active. All normal and recovery cleanup follows this same rule.

The retained fixed account prevents a stale precheck in another process from
acquiring after the last admitted owner closes. No cleanup, restart, expiry,
or recovery deletes the sentinel. A valid exhausted history classifies as
`capacity_exhausted` only after validating the full inventory and its matching
valid closed active sentinel, with `allowed_action=stop` and status exit 0; acquire or
recover returns `AUTHORITY_CAPACITY_EXHAUSTED`/exit 1. An expired valid sentinel
remains capacity exhaustion, never recovery work. Corruption or an unclosed
lease remains corruption or quarantine, never capacity success. The limit is
256 lifetime closes, including registry ceremonies and failed/replayed attempts;
an accepted attacker can exhaust this allowance as denial of service. There is
no retention, reset, or implicit migration in this release. Exhausted history
with a missing or mismatched sentinel is `AUTHORITY_STATE_CORRUPT`, never clear
or capacity success; no helper recreates or repairs the sentinel.

For an apply, the schema-3 receipt, active record, permit, and closed record
form one context chain. The receipt, active, and permit repeat the identical
`authorization_context_sha256`; the permit binds `active_sha256`, and the
closed record binds that same active digest plus the permit digest when a
permit exists. In Gate mode that context digest reconstructs the exact
root-signed isolated unit token tuple through the journal's closed
`gate1b_isolated_authority_evidence_v1` branch. Gate 1A remains confirmation-only
and never obtains this apply permit. A changed/missing link, cross-mode context,
or linked object whose bytes reconstruct another Gate token/session is
corruption, never authority.

The active, permit, and closed digests are SHA-256 of their respective domain
followed by their exact canonical bytes. Active, permit, registry-revision, and
each normal-path closed add are one-shot. After their success, error,
cancellation, or ambiguous status, the helper performs at most one
exact-account read: equal bytes mean success, absence means that attempt did
not commit, and different/malformed/duplicate result is a conflict. No permit,
registry-revision, or active acquisition add is retried. A later non-owner may
only read an existing durable close and clean up that
closed active item. It never retries or synthesizes a close add, including when
exact normal closed bytes already exist in a terminal journal.

### Apply linearization and fencing

The uninterrupted apply order is exact:

1. The connected helper authenticates the connected CLI, strictly parses the
   canonical low-S signed receipt and computes its digest without reading
   mutable authority. It requires trusted time strictly before both the
   descriptor expiry and the signed receipt's `expires_at`, as well as the
   applicable live token expiry. Equality or later is expired: the CLI CASes
   `confirmed -> expired` and creates no active item.
   Otherwise it enters the serialized authority executor, takes the executor
   guard, performs fresh complete bounded coordinator integrity/capacity
   classification, and permits an active-add attempt only for a clear,
   below-capacity result. Exhaustion or a missing/mismatched sentinel, corrupt
   history, quarantine, or existing active state follows its classification
   without a new add. This read-only coordinator check is not a ledger read or
   a reservation; a later competing acquisition can still defeat the one add.
   Immediately before that add it rechecks receipt, profile and token expiry.
   It retains the
   guard through step 6 and active cleanup. This successful add is coordinator
   acquisition, not send authority.
2. While retaining the same authenticated connection and excluding every
   registry commit, it validates the complete protected permit/closed history
   and rejects any previously consumed receipt digest before any permit, then
   replays the complete ledger, validates the unexpired
   helper profile and applicable live authority/context (the exact root-signed
   Gate token/context in Gate mode or the existing stage/production chain), and checks the receipt,
   project policy, credential binding, preconditions, and plan. The helper
   checks the active journal-revision grammar and allowed values, while the CLI checks
   the locked journal's complete confirmed state/revision/provenance
   combination; the helper does not infer that provenance from a CLI claim.
   Expiry or another definitive failure after acquisition but before
   permit closes `failed_before_mutation`, burns the receipt, and sends zero
   mutation bytes. An invalid active journal state/revision/provenance
   combination is not such a closeable failure: no valid terminal journal CAS
   is established, so the acquired active remains unclosed quarantine with no
   permit or mutation bytes pending a separately reviewed recovery path.
3. Under its per-plan journal lock, the CLI validates the complete confirmed
   state/revision/provenance combination and durably compare-and-swaps
   `confirmed -> in_flight` with a checked revision increment, storing the
   exact historical registry and authorization evidence. It returns the new
   revision, `3` for a fresh plan or `4` for a migrated plan. This is the local
   crash-bookkeeping point, not same-user anti-replay authority. Failure before
   permit sends zero mutation bytes; it closes as `failed_before_mutation` only
   if a valid terminal journal CAS is possible. A corrupt or impossible stored
   state remains unclosed quarantine, never a synthesized normal close.
4. The helper reauthenticates that same connection, rechecks the unchanged
   ledger/context/profile/token cutoffs, and requires the returned `in_flight`
   revision to equal the active confirmed predecessor plus one (`3` or `4`).
   The connection's expected journal revision advances to that returned value
   only after this check; the permit still records the active predecessor.
   The helper cannot infer migration provenance from this arithmetic. It also
   requires trusted time strictly before the signed receipt's `expires_at`
   immediately before adding exactly one permit. The successful or
   exact-read-reconciled permit add is
   the sole send-authority linearization point.
5. Only the same connection may send the one request whose exact bytes hash to
   `mutation_request_sha256`. The helper keeps the coordinator acquired across
   send and outcome handling, so rotation, revocation, recovery, enrollment,
   and another apply cannot overlap it. Immediately before send it runs the
   exact three-read state probe above and again checks receipt TTL, profile and
   token validity on trusted time. Expiry at or after the receipt deadline
   prevents all request bytes; since a permit exists, the outcome is ambiguous.
   There is no second permit, redirect,
   retry, or resend.
6. The original owner first irreversibly quiesces every send/sign/permit/commit
   capability, including queued callbacks and outstanding operations. Only
   then the CLI constructs exact `close_mode=normal` closed bytes and durably
   compare-and-swaps them together with `applied`, `failed_before_mutation`, or
   `ambiguous` into journal v2. The helper exact-reads that revision and bytes,
   reads `closed/<lease-id>` first, accepts identical bytes as already
   committed, or performs one identical add only when the read was not found.
   Different/malformed bytes fail closed. Only after an identical durable close
   does it perform fresh full bounded capacity classification, retaining the
   valid closed exhaustion sentinel or exact-reading and cleaning up `active`
   under the rules below. Durable
   closed bytes are the close/fencing linearization point; active deletion is
   idempotent cleanup, never proof of closure.

If the normal-path closed add returns ambiguously, its one immediate exact read
maps identical bytes to success, not found to
`AUTHORITY_STATE_QUARANTINED`/exit 1, and
different/malformed/other to `AUTHORITY_STATE_CORRUPT`/exit 1. The normal path
does not issue another add or delete active after either failure.

The authenticated coordinator connection carries the lease ID, active digest,
session ID, and expected journal revision on every message. A reconnect,
different audit token, restarted helper session, stale journal revision,
expired lease, or message after close cannot obtain or exercise a permit. The
network executor accepts request bytes only while that original connection is
open and the helper still holds an equal active item with an equal permit and
no closed item. The CLI cannot bypass this check by invoking a transport
directly; write-capable transport construction remains behind this coordinator
capability.

Registry enrollment, rotation, revocation, and recovery use the same active
account with `operation_kind=registry_commit`. The peer first creates the
canonical registry intent and the helper binds its digest into active; only
after the serialized executor guard, fresh complete bounded coordinator
integrity/capacity classification yielding clear below-capacity state, and a
strict immediately-pre-add profile/token-expiry check may it attempt the active
add. Exhaustion, corrupt or missing sentinel, quarantine, or an existing active
follows its classification without a new add; classification is not a capacity
reservation. At or after expiry it adds nothing. This classification reads only
coordinator state, not the registry ledger. Only
after successful acquisition may the helper read the ledger or validate/build the
request, proposal, or candidate. Under the same lease it rechecks exact peer,
descriptor, intent, ledger, and trusted time strictly before profile expiry
immediately before the proposal signature, again before the final registry
signature, and again before the one revision add. It validates the eventual
candidate against the active intent before commit, reconciles the one revision
add exactly, irreversibly quiesces every capability, durably retains the
exact candidate/outcome and normal close, adds that closed record once, and then performs
fresh bounded capacity classification followed by sentinel retention or
read-first active cleanup. No registry revision can linearize between an
apply's in-flight CAS and durable close. If a registry operation acquires
first, its revision and close are visible before a later apply revalidates, so
the old receipt is canceled without a permit.
An initial enrollment is not an exception: even an invalid or duplicate
enrollment attempt must acquire `active` before its first ledger read or
proposal validation. If this same helper retains the original live owning
apply connection, enrollment returns `APPLY_COORDINATOR_BUSY`. An independent
helper observing that unclosed active item instead returns
`AUTHORITY_STATE_QUARANTINED`. Both paths perform zero ledger reads, key
generation, proposal signing, revision adds, or cleanup deletes and cannot
learn whether the candidate enrollment would otherwise be valid. Gate 1B's
deterministic invalid-enrollment contention case uses the same-helper live
owner; its independent-helper case separately proves quarantine without
mutable authority calls.

### Test-host disposal and deferred cleanup

The first release has no `stage_cleanup` IPC operation, cleanup context,
cleanup intent/progress, delete-attempt marker, ACK ledger, native cleanup
endpoint, signed empty-inventory claim, or live registry/key-deletion tool.
Setup enrollment and its exact signed evidence remain required. Every Gate,
smoke, and post-grant test uses a disposable host/session whose mutable
Keychain, journal, registry, and fixture state is not reused. After bounded
secret-free evidence export, the trusted external supervisor destroys that
whole disposable host before signing any successor authorization. Host
destruction is a trusted lifecycle prerequisite, not a result proved by a
helper response. Failure or uncertainty blocks the successor signature.

### Restart, quarantine, and already-closed cleanup

A helper startup performs bounded read-only coordinator classification before
ordinary authority work. An active item without a matching valid durable close
is `AUTHORITY_STATE_QUARANTINED`, regardless of whether another helper appears
alive. The original authenticated owner may still complete its existing lease;
classification by another process cannot affect that owner's capabilities.
The quarantined process cannot perform a journal CAS, synthesize/add a close,
delete active, sign, generate keys, issue/exercise a permit, send, or commit a
registry revision. It does not create a replacement lease or key and cannot
use UI, expiry, reboot, or a root-signed stage token to widen that subset.

This rule covers every unclosed crash boundary: before in-flight CAS, before
permit, after permit before send, after send, after a durable terminal outcome,
and after an absent or uncertain close add. Absence of a permit can establish
zero send authority for reporting; it cannot fence a paused owner or authorize
terminalization. A durable outcome is preserved byte-for-byte but cannot
license a non-owner's journal CAS or close add. If an immediate exact read
resolves the original owner's one close add to identical durable bytes, normal
closed cleanup is allowed; otherwise absence/uncertainty remains quarantine.

Already-closed cleanup requires a newly authenticated exact peer, the same
artifact descriptor, and complete retained active/permit/closed/outcome linkage.
It also requires fresh full bounded capacity classification; an exhaustion
sentinel is retained and returns capacity exhaustion instead of cleanup.
It requires no old process to be declared dead: the durable normal close proves
that the owner irrevocably dropped its capabilities before publication. The
new connection only reads and performs the exact persistent-reference deletion
above. It neither acquires a lease nor modifies journal, registry, permit, or
closed records. Conflicting/malformed linkage returns
`AUTHORITY_STATE_CORRUPT`; missing proof is quarantine, not inferred closure.
A profile past its expiry may perform this restricted closed cleanup after
fresh trusted presence, but no signature, key generation, permit, or send.

With no active item, every retained permit must link to one valid close and
every close must link to its exact terminal evidence. An unmatched permit,
unknown/duplicate account, malformed record, missing outcome evidence, or
ambiguous query blocks ordinary work; no helper repairs it automatically.
With already-closed A, multiple cleanup helpers may race. If one deletes A and
another helper acquires B, the other cleanup helper's captured A reference can
only delete A or return not found; it never deletes B. Local executor guards
are not evidence that this interleaving cannot occur.

While any lease is quarantined, remote ambiguous-outcome reconciliation is
limited to bounded fixed-origin reads and a transient report. It never changes
the retained journal or authority state and never replays a mutation. A unique
remote match is evidence for the operator, not permission to clear the lease.
Registry key-recovery is a different ceremony: it remains allowed only after
winning a fresh active acquisition against an otherwise valid clear coordinator
and satisfying its existing eligibility/presence requirements. It cannot be
used to recover an unclosed coordinator lease.

### Future authority commands and machine errors

This design intentionally makes an additive command/exit-contract change while
preserving the JSON v1 envelope. It adds exactly two commands:

```text
youtrack-agent-cli --profile NAME mutation authority status
youtrack-agent-cli --profile NAME mutation authority recover
```

Both commands require one explicit, existing `--profile NAME` before helper
contact; missing profile returns the existing `PROFILE_REQUIRED` usage error
and exit 2, and an unknown profile uses the existing not-found contract and
exit 3. Their only accepted inherited flags are `--profile`,
`-o/--output text|json`, the retained hidden `--json` alias, `--timeout`, and
`-v/--verbose` with the existing meanings and conflict rules. They reject
`--yes`, `--dry-run`, `--fields`, and `-o/--output raw` as usage/exit 2;
`status` does not reinterpret dry-run because it is already read-only, and
`recover` never treats dry-run as approval. Neither command defines or accepts
`--plan-id`, a lease ID, `--force`, a cleanup selector, positional arguments,
stdin data, or an environment override; an unknown inherited or local flag is
also usage/exit 2. `status` is bounded and read-only. `recover` operates only
on the exact already-closed active record,
launches trusted native UI that displays profile, operation kind, lease digest,
terminal classification, and proposed cleanup, and requires fresh user
presence. Cancellation changes nothing and must not trigger automatic retry;
a later operator-requested invocation requires fresh presence. The command can run only the closed-
cleanup subset above; it can never force-clear, select/delete an arbitrary
item, or contact YouTrack. A valid exhaustion sentinel returns
`AUTHORITY_CAPACITY_EXHAUSTED`/exit 1 without deletion, including after expiry.
With an expired profile and no active item, `HELPER_PROFILE_EXPIRED`/exit 12
takes precedence. Otherwise no active item at the initial read returns
`AUTHORITY_RECOVERY_DENIED`/exit 1 with zero mutation. An item disappearing
after its valid closed linkage was captured may instead return the successful
stale cleanup result below.

A successful JSON `status` response has exactly the JSON v1 success-envelope
top-level fields `ok` equal to true, `v` equal to integer 1, `data`, and
`meta`, in that order. `meta` is required and has
the existing invocation fields `profile`, `instance`, `account_id`, and
`account_login` in that order, copied from the validated non-secret profile;
it contains no count, cursor, authority state, or credential. `data` has these fields in order: `profile`,
`authority_status`, `artifact_descriptor_sha256`,
`helper_profile_expires_at`, `active`, `permit`, `closed`, `journal`, and
`allowed_action`. Status is `clear`, `busy`, `recovery_required`, or
`expired_recovery_only`, or `capacity_exhausted`; action is respectively `none`,
`wait`, `recover`, `recover`, or `stop`. Every successful status response exits 0. `busy` is possible only
when this helper retains the original live owning connection; non-owner unclosed state
returns `AUTHORITY_STATE_QUARANTINED`/exit 1, never a success status.
`recovery_required` and `expired_recovery_only` require a valid durable close.
An expired profile with no active record returns `HELPER_PROFILE_EXPIRED`/exit
12 rather than inventing cleanup work. Corruption never produces a success
envelope or an `authority_status=corrupt` projection: it uses only
the exact `AUTHORITY_STATE_CORRUPT` failure envelope and exit 1 defined below,
with no `data` or `meta`. `active` is null or contains, in order,
`lease_id`, `operation_kind`, `active_sha256`, `created_at`, `expires_at`,
`historical_cli_audit_token_sha256`, and `historical_helper_session_id`.
`permit` is null or contains `permit_sha256`, `mutation_request_sha256`,
`issued_at`, and `expires_at`. `closed` is null or contains `closed_sha256`,
`terminal_outcome`, `close_mode`, and `closed_at`. `journal` is null or
contains `version`, `revision`, `state`, and `record_sha256`. These projections
contain digests and public metadata only—never receipt bytes, request bytes,
credentials, private keys, Keychain values, or untrusted remote content.

A successful JSON `recover` response uses the same required exact invocation
`meta`; `data` fields are `profile`, `recovery_status`, `lease_id`, `terminal_outcome`, `closed_sha256`,
`active_cleanup`, in that order. Recovery status is `already_closed` or
`stale_active_ignored`; cleanup is `deleted`,
`already_absent`, or `stale_noop`. `terminal_outcome` and `closed_sha256` are
nullable only for `stale_active_ignored`; every other field is non-null. Text
mode is a bounded projection of the same fields. Raw output is unsupported for
both commands.

Every error uses exactly the existing JSON v1 failure shape
`{"ok":false,"v":1,"error":{"code":"CODE","message":"MESSAGE"},"hint":"HINT"}`
with no `data` or `meta`. The following new exit numbers deliberately express
four distinct caller actions for live-owner busy, already-closed cleanup, expiry,
and reconfirmation after a proven uninterrupted pre-permit abort; they must be
added to the public contract rather than disguised as existing exit 9:

| Future exit | Name | Caller action |
| ---: | --- | --- |
| 10 | `AUTHORITY_BUSY` | wait, then call authority status |
| 11 | `AUTHORITY_RECOVERY` | obtain trusted presence and call authority recover |
| 12 | `ARTIFACT_EXPIRED` | install a newly authorized artifact; only recovery cleanup remains available |
| 13 | `RECONFIRM_REQUIRED` | prepare a new plan and obtain a new confirmation |

| Future stable `error.code` | Exit | Exact `message` | Exact `hint` |
| --- | ---: | --- | --- |
| `APPLY_COORDINATOR_BUSY` | 10 | `authority coordinator is busy` | `run mutation authority status and wait` |
| `APPLY_COORDINATOR_RECOVERY_REQUIRED` | 11 | `closed authority cleanup is required` | `run mutation authority recover with trusted user presence` |
| `AUTHORITY_RECOVERY_CANCELED` | 11 | `authority recovery was canceled` | `leave state unchanged or rerun mutation authority recover` |
| `APPLY_COORDINATOR_CLOSE_AMBIGUOUS` | 1 | `authority close is not proven durable` | `stop and request operator investigation; never resend or synthesize close` |
| `APPLY_COORDINATOR_ACTIVE_DELETE_AMBIGUOUS` | 11 | `authority cleanup requires recovery` | `run mutation authority recover; never resend the mutation` |
| `HELPER_PROFILE_EXPIRED` | 12 | `authorized helper profile has expired` | `install a newly authorized artifact; recovery cleanup only` |
| `APPLY_PRE_PERMIT_ABORTED` | 13 | `mutation stopped before permit issuance` | `prepare a new plan and obtain a new confirmation` |
| `AUTHORITY_STATE_QUARANTINED` | 1 | `local authority state is quarantined` | `stop and request operator investigation; do not retry or delete state` |
| `AUTHORITY_CAPACITY_EXHAUSTED` | 1 | `authority capacity is exhausted` | `stop and request operator investigation; do not retry or delete state` |
| `AUTHORITY_STATE_CORRUPT` | 1 | `local authority state is corrupt` | `stop and request operator repair; do not retry or delete state` |
| `JOURNAL_V1_AUTHORITY_STATE_QUARANTINED` | 1 | `legacy authority journal state is quarantined` | `stop and request operator repair; do not migrate or retry it` |
| `AUTHORITY_RECOVERY_DENIED` | 1 | `authority recovery evidence is invalid` | `stop and request operator repair; do not force clear state` |

No new authority command or reason emits exit 9. The existing contract retains
that number for its already published conflict/stale uses;
`WRITE_OUTCOME_UNKNOWN` may still use it to direct read-only remote
reconciliation. It is not reused for coordinator busy, recovery, profile
expiry, reconfirmation, or cleanup corruption. Unknown new exits are nonzero
and fail closed for older callers; the envelope version remains 1 because its
shape is unchanged.

These commands, exits, and reasons are future contract values and are not
implemented by the current disabled slice. The implementation of record must
add the four exit definitions and one authoritative reason registry to
`internal/errx/contract.go`, extend `errx.Describe()` to expose the exact
code/exit/message/hint mapping, and then extend—not assume—the current
`tools/gencontract` renderer. `go generate` from `internal/errx` must update
both `docs/contract.md` and
`assets/skills/youtrack-agent/reference/contract.md`. The Cobra tree must add
only the two commands above; the existing `tools/gencommands` path must then
update `docs/commands.md` and
`assets/skills/youtrack-agent/reference/commands.md`. The authoritative
`.agents/rules/cli-contract.md` must be updated in that implementation change,
its tracked `.cursor/rules` compatibility mirror must be regenerated through
`.agents/scripts/sync-rules.py`, and both the sync check and the machine-local
provider compiler `--check` gate must pass. The embedded skill's
`SKILL.md` and write-policy reference must be updated to route busy/recovery/
expiry/reconfirm/corruption exactly as above, and the installed Codex/Claude
copies must come only from that regenerated embedded skill. This design-only
delta corrects embedded skill guidance; runtime commands, generated contracts,
canonical rules, and tracked mirrors remain unchanged. Capacity adds a proposed
reason on existing exit 1, not another exit number; current exits 0..9 remain
untouched.

## Commit and ambiguous-result reconciliation

Before mutation, the helper sends the complete candidate stored-record bytes
to the CLI. The CLI validates them and retains them durably for this ceremony.
It then sends a compact commit authorization with these fields in order:

1. `schema_version`
2. `message_type`, exactly `registry_commit`
3. `transition_kind`
4. `registry_revision`
5. `record_sha256`
6. `authorized_at`
7. `expires_at`

`record_sha256` uses the commit-candidate digest domain. This authorization is
also connection-bound, not a signature. The helper revalidates the peer,
record digest, expiry, exact current chain, expected revision, and predecessor;
then it performs exactly one `SecItemAdd` for account `revision/%020d` in the
fixed service and access group. It never calls `SecItemUpdate`, never retries
the add, and never deletes a registry revision.

After success, error, cancellation, or a crash-ambiguous response, the only
permitted reconciliation is one exact-account read. On a reconnect the CLI
supplies the retained candidate bytes in this canonical object:

1. `schema_version`
2. `message_type`, exactly `registry_reconcile`
3. `transition_kind`
4. `registry_revision`
5. `record_sha256`
6. `record_base64url`

`record_base64url` is unpadded base64url of the complete candidate and is
bounded by the reconciliation-request cap. The helper decodes/re-encodes it,
validates the complete candidate and all signatures against the preceding
ledger, and confirms its commit digest before reading Keychain once.

- exact stored bytes equal to the candidate mean committed success;
- absence means uncommitted failure and the ceremony ends;
- any different bytes, malformed item, duplicate result, or read ambiguity is
  a conflict and fails closed.

No result authorizes generating new signatures, repeating `SecItemAdd`, or
implicitly starting another ceremony. Only after a valid durable close and exact active cleanup may a new operator
action acquire another lease. It must use a fresh
challenge and, if the prior candidate is absent, a new key ID for every
key-creating transition.

## Cross-language conformance evidence

Protected registry storage, native ceremonies, coordinator integration, durable
confirmation and runtime authority remain blocked until one shared fixture
directory contains Go- and Swift-consumed vectors for each transition. Each
positive vector includes request, signed proposal, acceptance, final body, complete record, every
domain-prefixed signing input, every digest, predecessor chain, DER SPKIs, and
strict low-S signatures. At least one vector must form a multi-event chain
`enroll -> rotate -> revoke -> recover` and derive the exact final state.

The pure offline supplied-history and supplied-ceremony verifiers above are
prerequisite exceptions to this implementation block, not satisfaction of it.
They do not enable confirmation, commit, apply or a write-capable release.

Another positive vector covers recovery from an active valid ledger after the
exact `errSecItemNotFound:-25300` result. Both Go and Swift must decode and
byte-for-byte re-encode status codec vectors for `-2147483648`, `-25300`, `-1`,
`0`, `1`, and `2147483647`. Signed-range acceptance does not classify an unknown
status as success: coordinator result vectors still require the exact failure
or quarantine classification. Negative vectors reject `-2147483649`,
`2147483648`, `-0`, `+1`, `01`, `-01`, `1.0`, `1e0`, and string-valued statuses;
they also reject negative integers in every non-OSStatus integer field.
Status vectors reject null as a substitute for the numeric absence status.
Neither implementation may parse through a floating point value or an unchecked
narrowing conversion.

The same fixture directory contains language-neutral typed projections for
exact key-generation, zero-reuse-context signing, noninteractive key existence,
key enumeration, registry add/enumeration/exact-read, coordinator add/enumeration/
exact-read/pre-send probe, persistent-reference cleanup read, and exact-reference
delete dictionaries. A fixture proves that the opaque nonempty CFData reference
and active attributes/value come from one result, obey their individual and
aggregate caps, and are never serialized or exported. Native dictionaries are
compared by bounded typed projection, not CFDictionary iteration order.

Positive coordinator vectors cover the uninterrupted original owner, normal
close only after irrevocable quiescence, registry-first receipt cancellation,
apply-first registry exclusion, duplicate fixed-active acquisition across two
independent same-UID helper processes, and all unclosed crash boundaries as
read-only quarantine. They retain any existing terminal outcome unchanged.
Already-closed cleanup vectors cover two independent cleanup processes,
A-read/A-delete/B-acquire/stale-A-delete, direct old-reference absence, and an
ambiguous delete followed by an exact-reference read. B always survives. No
vector uses a local guard, PID death, launchd label, user-bootstrap identity,
expiry, trusted UI, or reboot to prove that an unclosed owner was fenced.

Required native anti-replay and capacity vectors extend the existing
[Gate 1B isolated-subrun catalog](gate1b-isolated-subruns.md); they are
requirements for future exact signed native execution, not proof from this
documentation change. They cover restored `confirmed` journals after both a
permit and a normal null-permit abort, a fresh lease with a previously consumed
digest, reordered full history, and repeated replay-denial closes with null
permit. Every schedule must preserve the global one-permit-per-receipt bound.
Parser vectors reject noncanonical/high-S aliases before digest or authority
access. Post-permit zero-byte denial must close ambiguous and allow only later
eligible read-only `resolved_not_applied` reporting.

Capacity vectors cover 255-to-256 closes, registry and denied-apply consumption,
the last admitted owner's final close, a competing helper paused after a stale
precheck, normal and recovery cleanup refusing the retained sentinel, expired
sentinel classification, uncertain enumeration without deletion, and corrupted
or unclosed state remaining failure. Typed projections exercise separate
2,097,152-byte registry and 4,202,496-byte coordinator limits, including the
full 513-item coordinator result. Output vectors pin status exit 0 with
`capacity_exhausted`/`stop`, acquire/recover capacity exit 1, expired/no-active
recover exit 12, and cancellation exit 11 without automatic retry or reused
presence. No vector claims new signatures, retention, or rollback detection.

Setup vectors retain both signed stage-token variants, exact setup enrollment
IPC evidence, its five-entry transcript manifest, and the later setup snapshot.
Their lifecycle evidence requires trusted external destruction of the entire
disposable host before a successor signature. It does not assert a native
cleanup operation or a signed empty inventory. No stage token can enable live
registry, permit, closed-record, or private-key deletion.

Separate negative query vectors delete or substitute
`kSecUseAuthenticationContext`, reuse an `LAContext`, set a nonzero reuse
duration, replace UI allow with fail on signing, add a context or UI allow to
existence, omit UI fail, return a typed key from the wrong query, trigger
unexpected authentication UI, pass any context-like value to the signature
call, reuse the returned signing key for a second signature, or omit context
invalidation on success, cancellation, lookup failure, or signature failure.
Signing vectors require exactly one prompt-capable lookup, one signature made
with only the returned `SecKey`, and one terminal context invalidation;
existence and closed-cleanup Keychain-call vectors require zero Keychain prompt
presentation, zero authentication context, and zero signature. The separate
fresh trusted-presence ceremony for an explicit cleanup request does not alter
those dictionaries or provide a signing capability.

Negative vectors must independently cover:

- a status success envelope containing `authority_status=corrupt`, corruption
  returned with any exit other than 1 or any code other than
  `AUTHORITY_STATE_CORRUPT`, and a corruption failure carrying `data` or `meta`;
- selecting a snapshot, pre-inventory, or final-evaluation transcript manifest
  as setup attribution; missing, extra, reordered, or wrong-kind enroll
  transcript entries; reconstructed enrollment IPC evidence with a substituted
  token, context, tag, registry record, closed record, digest, or byte length;
  and any snapshot/manifest self-reference, all rejected before accepting setup
  evidence;
- every raw and aggregate size boundary, revision 0/257, 256/257 records, and
  overlong base64url before allocation;
- missing, duplicate, unknown, reordered, escaped, whitespace-modified, or
  trailing JSON; noncanonical integer, null, time, base64url, DER, SPKI, point,
  low-S, and digest encodings;
- request/proposal/acceptance splice, wrong signature domain or signer role,
  expired transcript, audit-token change, and artifact-descriptor change;
- recovery while active-key lookup succeeds, continuity-probe success, user
  cancellation, authentication failure, interaction-not-allowed,
  unavailable/transient/unknown OSStatus, missing or substituted recovery
  evidence, and recovery over a malformed/forked/gapped ledger;
- partial key tuples, tuple mismatch, reused generation/key ID/tag/SPKI,
  invalid generation-to-revision binding, and proposal-to-record substitution;
- missing revision, gap, duplicate account, fork, predecessor mismatch,
  invalid status transition, second enrollment, rotation/revocation of a
  non-active key, revoked-key resurrection, and recovery over any invalid
  prefix;
- duplicate-item races, exact-winner reconciliation, different-winner
  conflict, absent ambiguous add, read ambiguity, and any attempted automatic
  add retry;
- a missing/additional/wrong-typed dictionary entry, legacy Keychain selection,
  synchronizable item, wrong accessibility/access group/service/account/class,
  match-limit substitution, unexpected return CFType, match-all bare
  dictionary, duplicate/unknown projected account or key tag, over-bound result,
  broad delete, any live registry revision/permit/closed/key deletion, an
  attributes-only active delete, a missing/wrong/oversized persistent reference,
  or attributes and reference obtained from different reads;
- a missing, additional, reordered, cached, match-all, or differently
  projected pre-send probe; active/permit byte mismatch; closed lookup success;
  or any send after a probe failure; and
- two active leases, permit without the exact active/session/audit token,
  permit before `in_flight`, send without or after permit/close, second permit,
  second send, registry commit overlapping apply, active deletion before close,
  stale reconnect/session/journal fence, restart resumption, crash-state
  downgrade, and treating any post-permit uncertainty as retryable;
- treating a second exact signed helper or alternate same-UID bootstrap context
  as excluded, a local executor guard as cross-process exclusion, a paused
  owner as dead, or PID loss/restart/reboot/expiry as permission to release an
  unclosed lease; a queued callback exercising authority after normal close;
  or a stale persistent reference deleting a replacement active item;
- registry active without an intent, candidate digest substituted for intent,
  intent created after a ledger/proposal read, transition/descriptor/nonce/
  expiry disagreement between intent and request, candidate not validated
  under the same lease, or any proposal/final signature/commit at or after
  profile expiry; and
- coordinator recovery adding a close, changing a journal, acquiring a lease,
  signing, generating a key, issuing a permit, sending, or committing; treating
  a terminal journal outcome without durable close as cleanup authority;
  returning successful recovery for unclosed state; accepting a recovery-close
  codec or substituted normal-close bytes; losing or downgrading retained
  outcome evidence; and permitting mutation replay after any uncertain result;
- any live `stage_cleanup` command, IPC operation, dictionary, ACK-ledger
  authority, empty-inventory proof, or registry/key deletion enabled by a stage
  token; reuse of a disposable host's mutable state, export of private state,
  or successor signing before trusted external host destruction is confirmed.

Go and Swift must parse and re-encode every positive byte identically and
reject every negative vector with the same stable reason class. Gate 1A runs
both implementations against the same immutable fixture hashes.

## Evidence

- Apple defines the dictionary-driven Keychain operations
  [`SecItemAdd`](https://developer.apple.com/documentation/security/secitemadd(_:_:)),
  [`SecItemCopyMatching`](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)),
  and
  [`SecItemDelete`](https://developer.apple.com/documentation/security/secitemdelete(_:)),
  together with the explicit
  [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)
  selector. This protocol narrows those general APIs to the exact dictionaries
  and bounded projections above.
- Apple documents that Keychain duplicate detection uses an item's composite
  primary key in [`errSecDuplicateItem`](https://developer.apple.com/documentation/security/errsecduplicateitem).
- Apple documents CFData persistent references from
  [`kSecReturnPersistentRef`](https://developer.apple.com/documentation/security/ksecreturnpersistentref)
  and their use for exact deletion through
  [`kSecMatchItemList`](https://developer.apple.com/documentation/security/ksecmatchitemlist).
  Apple DTS explains that deleting and re-adding an item changes its persistent
  reference in [SecItem: Pitfalls and Best Practices](https://developer.apple.com/forums/thread/724013).
  This supports item-identity cleanup, not a proof that an unclosed owner died.
- Apple documents private key generation through
  [Generating new cryptographic keys](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys)
  and Secure Enclave protection in
  [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
- The private access-group boundary follows
  [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps).
