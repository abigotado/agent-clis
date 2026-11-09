# Gate 1A exact-artifact authorization

Status: **NOT ACTIVATED**. The authority key is not enrolled, no Gate token is
issued, and no production artifact is activated. `approval.Unsupported`
remains the only production adapter. Gate 1A and Gate 1B are **NOT PASSED**.

Gate 1B's docs-only execution decision is accepted in
[isolated subruns](gate1b-isolated-subruns.md), which is its sole topology and
new-type authority. Token issuance and digest freeze require the reviewed
materialized compiler/contracts/inventory, validated vectors, and native
candidate implementation. After that, separately authorized native E1/E2 runs
must produce the required transport and full-suite evidence before evidence
acceptance or issue-create provisional authorization. Neither implementation
nor those native results exist: Gate 1B remains **NOT PASSED**.

### Gate 1B-only supersession

The isolated-subrun ADR replaces, only for Gate 1B, this document's former
flat plan, single setup/session, E1/E2 token, setup/receipt/retained-authority
context, index, export/disposal, and one-index-per-architecture evidence-set
route. Legacy v1 authority and container codecs below reject
`gate_id=gate1b`, `plan_type=gate1b`, or `stage_type=gate1b`; a valid old
signature or hash does not provide an alternate route. Their Gate 1A,
activation-smoke, and post-grant meanings are unchanged.

The 26 Gate 1B families and 23 coordinator phase rows below are coverage inputs
only. The new compiler must expand every independent phase and negative variant
into an isolated unit with its own setup and final evaluator; status-contract
and legacy-journal quarantine variants are included. Old `reset` labels are
not executable commands. No old flat catalog total establishes the unit,
observation, transcript, or assertion inventory. Shared leaf payloads may be
used only through the ADR's
[typed leaf binding adapter](gate1b-isolated-subruns.md#leaf-evidence-and-binding-adapter),
never by globally reinterpreting their old containing schemas.

Developer ID identity, Team ID, bundle identifiers, and build number establish
publisher and release identity, but they do not distinguish a Gate-tested
binary from a separately rebuilt binary with the same semantic identity. This
contract adds an independent, exact-artifact authorization layer without
placing a self-referential manifest inside the signed app bundle.

## Root of authorization

There is exactly one first-release artifact-authorization root:

- algorithm: Ed25519 as specified by RFC 8032, pure mode, with 32-byte public
  keys and 64-byte signatures;
- key ID: `YTAAK-` followed by lowercase SHA-256 of the exact 32 public-key
  bytes;
- verifier input: one literal key ID and one literal unpadded base64url public
  key compiled into the CLI, helper, Gate runner, and publication verifier;
- custody: the private key is generated and held in an operator-controlled
  offline or hardware-backed signing environment, never exported to a
  developer workstation, CI runner, release archive, Gate fixture, or app;
- use: the signing environment accepts only an already canonical object,
  displays its domain and SHA-256, and emits one signature after explicit
  operator approval. It does not build, edit, test, upload, or install code.

No fallback key, key search, certificate-chain substitution, online key
discovery, environment override, or trust-on-first-use path exists. There is no
root-key rollover in the first write-capable release. Loss, compromise, or any
requested root change blocks production authorization and requires a separate
rollover ADR and a new full Gate. The repository currently contains no
operator root public key; Gate tooling must fail closed until one literal key
and its derived key ID are committed and independently verified. Test keys use
a disjoint `test-only` domain and can never satisfy these domains.

The clean Gate host, its signed runner, and the operator supervising the run
are trusted release inputs. Content addressing makes collected evidence
tamper-evident after capture; it does not prove that a compromised runner or OS
executed a test honestly. The offline signer must require an operator-observed
clean/reverted host and review the complete evidence set, but its signature
does not remove this trust assumption. Compromise or suspected compromise of
the Gate host/runner invalidates the run and all derived E1/E2 evidence.

## Canonical signed objects

All objects are compact UTF-8 JSON with fields in the exact listed order, no
leading/trailing bytes, and no insignificant whitespace. Decoders reject a
non-object top level, missing, duplicate, unknown, or reordered fields,
alternate escaping or number encoding, and trailing data. They re-encode and
require byte equality. Strings are printable ASCII without JSON escapes.
Digests are 64 lowercase hexadecimal characters. Signatures are unpadded
base64url of exactly 64 bytes and are decode/re-encode checked.

Signed bytes are the ASCII domain including its final NUL byte followed by the
complete canonical unsigned object. The signed object appends `signature` as
its final field. Each signed object is capped before parsing or allocation:

| Object | Domain | Maximum bytes |
| --- | --- | ---: |
| Gate 1A E1 token | `YTA-GATE-E1-V1\0` | 4,096 |
| Gate 1A E2 token | `YTA-GATE-E2-V1\0` | 4,096 |
| provisional production authorization | `YTA-PROVISIONAL-PRODUCTION-AUTHORIZATION-V1\0` | 8,192 |
| activation-smoke token | `YTA-ACTIVATION-SMOKE-V1\0` | 4,096 |
| production activation grant | `YTA-PRODUCTION-ACTIVATION-GRANT-V1\0` | 8,192 |
| post-grant verification token | `YTA-POST-GRANT-VERIFICATION-V1\0` | 4,096 |
| publication envelope | `YTA-PUBLICATION-ENVELOPE-V1\0` | 8,192 |
| host-disposal attestation | `YTA-HOST-DISPOSAL-V1\0` | 4,096 |

The descriptor is not itself root-signed. Its exact SHA-256 is the subject of
each signed token or authorization. It is capped at 16,384 bytes and its digest
is SHA-256 over the exact raw canonical descriptor JSON, with no domain prefix.
This permits multiple Gate stages to bind the identical descriptor without
changing signed code.

Unless a field below defines a narrower grammar, every time is exactly UTC
RFC 3339 at whole-second precision (`YYYY-MM-DDTHH:MM:SSZ`), every digest is 64
lowercase hexadecimal characters, and every nullable value is literal JSON
`null`. `authority_key_id` is exactly `YTAAK-` followed by 64 lowercase
hexadecimal characters and must equal the pinned public-key digest.
`gate_runner_unique` is exactly 40 lowercase hexadecimal characters encoding
the 20-byte `kSecCodeInfoUnique` value. `gate_session_id` is canonical unpadded
base64url of exactly 32 bytes (43 characters). Gate plans are capped at their
object-specific limits below and target objects at 4,096 bytes; their
identifiers are SHA-256 of their exact canonical bytes. An evidence index
contains 1..256 observations and references
at most 4,096 regular files, each at most 8 MiB and at most 256 MiB in
aggregate. All counts and byte caps are checked before proportional allocation
or file reads.

The following legacy target payload grammar is descriptive input only; Gate
1B allocation, fresh actual target identity, and target authorization follow
[pre-token allocation](gate1b-isolated-subruns.md#pre-token-host-and-target-allocation).
This payload alone cannot authorize a unit or prove a fresh target.
It is compact canonical JSON capped at 4,096 bytes with
these fields in order: `schema_version` integer `1`, `target_type` exactly
`disposable_youtrack_2026_2`, `service_url`, `rest_url`, `oauth_issuer_url`,
`account_id`, `project_id`, `project_key`, `target_nonce`, and `expires_at`.
URLs use the approval URL grammar; REST is the exact service URL plus `/api`;
the OAuth issuer is the separately pinned HTTPS origin accepted by the Gate
plan. Identifiers use the mutation-plan grammar, and `target_nonce` is
canonical unpadded base64url of 32 random bytes. The target contains no token or
secret. `gate_target_sha256` is SHA-256 of those exact bytes.

## Exact artifact descriptor

The descriptor fields are:

1. `schema_version`, integer `1`
2. `descriptor_type`, exactly `youtrack_agent_exact_artifact`
3. `product_version`, canonical SemVer without build metadata, at most 64 bytes
4. `release_build`, positive decimal string with no leading zero, at most 18 bytes
5. `team_id`, exactly 10 uppercase ASCII letters or digits
6. `outer_identifier`, exactly `io.github.abigotado.youtrack-agent`
7. `helper_identifier`, exactly `io.github.abigotado.youtrack-agent.approval`
8. `minimum_macos`, `major.minor` decimal, at most 16 bytes
9. `architectures`, a JSON array in exact order `arm64`, then `x86_64`, omitting an architecture only when the release does not contain it
10. `code_slices`, ordered JSON array described below
11. `outer_peer_requirement_source_sha256`
12. `helper_peer_requirement_source_sha256`
13. `helper_profile_raw_sha256`
14. `helper_profile_expires_at`, UTC RFC 3339 whole seconds copied from the
    verified profile semantic object
15. `helper_profile_signer_policy_sha256`
16. `helper_profile_cms_evidence_sha256`
17. `outer_code_validation_evidence_sha256`
18. `helper_code_validation_evidence_sha256`
19. `app_payload_archive_sha256`
20. `notary_evidence_sha256`
21. `staple_evidence_sha256`
22. `created_at`, UTC RFC 3339 whole seconds

The structured arrays have no extension points. `architectures` has the order
above. `code_slices` entries are ordered first by role `outer`, `helper`, then
by the descriptor architecture order. Every entry has these fields in order:

1. `role`, `outer` or `helper`
2. `architecture`, `arm64` or `x86_64`
3. `identifier`, the exact matching identifier above
4. `team_id`
5. `release_build`
6. `executable_sha256`
7. `ksec_code_info_unique`, lowercase hex of the exact
   `kSecCodeInfoUnique` bytes returned for that architecture
8. `cdhashes`, an array ordered by ascending Security.framework digest
   algorithm number
9. `entitlements_semantic_sha256`
10. `actual_designated_requirement_data_sha256`

The fixed launchd label equals `helper_identifier`. Static validation requires
the sealed `Contents/Library/LaunchAgents/io.github.abigotado.youtrack-agent.approval.plist`
with its fixed `Label` and bundle-relative `BundleProgram`; it is registered
through `SMAppService.agent(plistName:)` only after explicit operator consent.
The plist is sealed non-executable bundle content, not a third code-slice role.
The helper owns the fixed per-user listener described by the trust-root
protocol. Packaging, parent launch constraints, and SMAppService are lifecycle
controls, not proof that another exact signed helper cannot run. Every
coordinator safety claim must survive two simultaneous valid helpers and
alternate same-UID bootstrap contexts.

Each `cdhashes` entry contains `digest_algorithm` as a JSON integer in
`1..255` and `value` as exactly 40 lowercase hexadecimal characters encoding
the 20-byte cdhash, in that order. Each role/architecture pair occurs exactly
once, so `code_slices` has exactly twice the declared architecture count; each
`cdhashes` array has `1..8` entries. The array contains every value
returned by `kSecCodeInfoCdHashes` paired positionally with
`kSecCodeInfoDigestAlgorithms`; duplicates, omissions, empty arrays, or an
unknown/unrepresentable algorithm fail descriptor creation. No implementation
parses Mach-O or CodeDirectory structures directly to invent these values.

For a universal binary the release tool asks Security.framework for each
declared architecture and records each architecture-specific result. At
runtime, each peer obtains the connection-bound guest from the audit token,
validates its Developer ID requirement, selects the running architecture, and
requires `kSecCodeInfoUnique` and the complete ordered cdhash set to equal the
descriptor entry. Both peers separately verify their own static signed code
against the same descriptor before accepting the connection. They exchange
and compare the descriptor SHA-256 inside the authenticated handshake; any
missing entry, differing digest, mixed descriptor, unsupported architecture,
or Security.framework ambiguity fails closed.

The semantic identifier, Team ID, build, entitlements, provisioning profile,
peer requirements, and actual designated requirements are defense-in-depth
evidence and Gate diagnostics. The Security.framework unique identifiers and
cdhash sets are the runtime exact-code authority. Executable and archive
SHA-256 values bind publication and offline reproduction; they do not replace
runtime code-signing validation.

The descriptor is created only after signing nested code first, signing the
outer app last, notarization, ticket stapling, and final signature validation.
Adding a descriptor inside the app afterward would change its resource seal.
It therefore remains detached.

`helper_profile_expires_at` must equal the profile-semantic `expires_at`
recovered from the CMS-validated embedded profile. There is no grace period,
clock-skew extension, cached-success window, or online refresh. Descriptor
creation, each E1/E2/smoke/post-grant token issuance and observation, activation
grant signing, publication-envelope signing, remote publication verification,
installation validation, helper launch, peer authentication, confirmation,
coordinator acquisition, registry proposal signing, registry final signing,
registry commit, permit issuance, and the final pre-send fence all
require their trusted current UTC instant to be strictly earlier than
this value. A stage that begins before expiry but reaches any listed boundary
at or after expiry fails closed; prior Gate evidence cannot authorize a later
expired install or apply. Replacing the profile changes signed code and starts
again from the app-only archive and descriptor at E1.
Trusted current time is sampled from the host realtime clock at each boundary,
compared as an instant before truncation or display formatting, and is never
accepted from argv, environment, plan, profile, server response, cached prior
check, or Gate fixture. An unavailable or unrepresentable clock result fails
the current operation; administrator/OS clock rollback or compromise remains
outside this local verifier's claim.

The conformance fixture set names the following complete boundary IDs; this is
a closed list for the profile-expiry claim:

| Boundary ID | `.just-before` | `.equal` | `.after` | `.expiry-between-checks` | Side effect forbidden by each denial |
| --- | --- | --- | --- | --- | --- |
| `profile-expiry.descriptor-create` | accept | deny | deny | deny after CMS parse | descriptor canonicalization/signing input acceptance |
| `profile-expiry.gate-e1-token-issue` | accept | deny | deny | deny after descriptor acceptance | E1 token signature |
| `profile-expiry.gate-e1-observation` | accept | deny | deny | deny after token acceptance | next Gate observation |
| `profile-expiry.gate-e2-token-issue` | accept | deny | deny | deny after E1 evidence validation | E2 token signature |
| `profile-expiry.gate-e2-observation` | accept | deny | deny | deny after token acceptance | next Gate observation |
| `profile-expiry.smoke-token-issue` | accept | deny | deny | deny after provisional validation | smoke token signature |
| `profile-expiry.smoke-observation` | accept | deny | deny | deny after token acceptance | next smoke observation |
| `profile-expiry.post-grant-token-issue` | accept | deny | deny | deny after activation-grant validation | post-grant token signature |
| `profile-expiry.post-grant-observation` | accept | deny | deny | deny after token acceptance | next post-grant observation |
| `profile-expiry.activation-grant-sign` | accept | deny | deny | deny after smoke evidence validation | activation-grant signature |
| `profile-expiry.publication-envelope-sign` | accept | deny | deny | deny after post-grant evidence validation | publication-envelope signature |
| `profile-expiry.publication-remote-verify` | accept | deny | deny | deny after envelope validation | release eligibility/publication continuation |
| `profile-expiry.installation-validate` | accept | deny | deny | deny after archive authentication | installation acceptance or link creation |
| `profile-expiry.helper-launch` | accept | deny | deny | deny after installation validation | helper session establishment |
| `profile-expiry.peer-authenticate` | accept | deny | deny | deny after helper launch | peer session authentication or authority read |
| `profile-expiry.mutation-confirm` | accept | deny | deny | deny after peer authentication | user-presence request or signed receipt |
| `profile-expiry.coordinator-acquire` | accept | deny | deny | deny after confirmation validation | coordinator active add |
| `profile-expiry.registry-proposal-sign` | accept | deny | deny | deny after leased ledger/candidate validation | proposal signing lookup or signature |
| `profile-expiry.registry-final-sign` | accept | deny | deny | deny after accepted proposal validation | final registry signing lookup or signature |
| `profile-expiry.registry-commit` | accept | deny | deny | deny after final signature validation | registry revision add |
| `profile-expiry.coordinator-permit` | accept | deny | deny | deny after `in_flight` CAS | permit add |
| `profile-expiry.mutation-pre-send` | accept | deny | deny | deny after permit add | socket creation or mutating request byte |

Every boundary ID has four mandatory vectors, with no sampled-time tolerance:
`.just-before` supplies a trusted instant exactly one nanosecond before expiry
and must accept that boundary; `.equal` supplies the expiry instant and must
reject with reason `HELPER_PROFILE_EXPIRED`; `.after` supplies one nanosecond
after expiry and must reject with the same reason; `.expiry-between-checks`
lets the immediately preceding named check complete one nanosecond before
expiry, then samples this boundary exactly at expiry and must reject before the
side effect in the table. For descriptor creation, the preceding check is CMS
profile parsing. For E1 issue it is descriptor acceptance. The final peer-auth
vector specifically proves a helper launched just before expiry cannot
authenticate a peer at equality. The coordinator-permit and mutation-pre-send
vectors prove that an acquired lease and existing permit respectively cannot
extend authority. The registry-sign/commit vectors prove the same under a
registry lease after proposal construction.
All 88 vector IDs are the 22 boundary IDs plus one of those four suffixes;
the fixture manifest must contain exactly that Cartesian product.
Missing, duplicate, differently rounded, reordered, cached-time, or
caller-controlled-time variants fail both language implementations and every
Gate plan that relies on the expiry claim.

The only post-expiry runtime exception is exact-code-authenticated bounded
authority status and cleanup of an already durably closed lease. An absent
active record with an expired profile returns `HELPER_PROFILE_EXPIRED`/exit 12
and closes. An unclosed active record remains read-only quarantine, even after
owner death, helper restart, reboot, expiry, or user-presence approval. No
journal CAS, closed add, key generation, signing lookup, permit, send, registry
commit, or deletion is authorized by that classification. Bounded historical
remote reconciliation can report results but cannot rewrite the quarantined
journal or replay a mutation. For an already valid normal close, the only
mutation permitted is deletion of the exact captured active persistent
reference under the registry protocol; no replacement active can be deleted.
Its capacity exception remains mandatory: a valid closed exhaustion sentinel
cannot be deleted even after expiry. Status returns `capacity_exhausted`,
action `stop`, exit 0; acquisition/recovery returns
`AUTHORITY_CAPACITY_EXHAUSTED`/exit 1, without cleanup authority.
The ordinary launch/authentication expiry vectors still deny ordinary
authority at equality. Separate recovery-only vectors prove this narrow
status/closed-cleanup exception cannot enter ordinary work.

### Code, entitlement, profile, notary, and staple evidence

The two peer-requirement sources are the exact UTF-8 bytes compiled from the
literal Team ID, identifier, and build requirements in the trust-root ADR.
They end with exactly one LF, contain no CR or NUL, are at most 4,096 bytes,
and are hashed without normalization. The outer source describes the
requirement the helper applies to the CLI; the helper source describes the
requirement the CLI applies to the helper. These hashes do not claim to be the
code objects' designated requirements.

For every role/architecture slice, the release verifier asks
`SecCodeCopySigningInformation` for both `kSecCodeInfoEntitlementsDict` and
the raw `kSecCodeInfoEntitlements` value. Dictionary absence is represented by
an empty dictionary only when the raw value is also absent. Raw-present with a
missing dictionary, dictionary-present with missing raw bytes, parse failure,
or disagreement between their complete semantic values fails closed. The
complete returned dictionary is
converted to compact semantic JSON with recursively sorted ASCII keys; values
may only be boolean, signed 64-bit integer, printable-ASCII string, an array in
the Security.framework order, or another dictionary under the same rules.
Depth is at most 8, each collection has at most 64 members, and canonical bytes
are at most 16,384. Duplicate/non-ASCII keys, data/date/real values, unknown
entitlement keys, or a value outside the exact release allowlist fails closed.
The outer allowlist is empty. The helper allowlist is exactly
`com.apple.application-identifier`, `com.apple.developer.team-identifier`,
`com.apple.security.get-task-allow`, and `keychain-access-groups`;
`com.apple.security.get-task-allow` must be absent or false, and the other
values must equal the fixed Team ID, helper identifier, and one private access
group. Hashing only a selected entitlement subset is forbidden.

Each code-validation evidence object is compact canonical JSON capped at
32,768 bytes with these fields in order: `schema_version` integer `1`,
`evidence_type` exactly `code_validation`, `role`, `architectures`,
`peer_requirement_source_sha256`, `actual_designated_requirements`,
`certificate_chain`, `code_signing_policy_oid`,
`sec_static_code_check_flags`, `sec_static_code_check_status`, and
`validated_at`. `actual_designated_requirements` has one entry per declared
architecture, in descriptor order, containing `architecture` and
`requirement_data_sha256`; the bytes come from
`SecCodeCopyDesignatedRequirement`/`SecRequirementCopyData` and must match the
slice field. `certificate_chain` is the complete leaf-first
`kSecCodeInfoCertificates` array returned with `kSecCSSigningInformation`;
each entry contains its zero-based `position` and SHA-256 of the exact DER
certificate. `code_signing_policy_oid` is the exact UTF-8
value of `kSecPolicyAppleCodeSigning`; the policy is created only with
`SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, null)`. Flags are
the array `kSecCSStrictValidate`, then `kSecCSCheckAllArchitectures`, with no
other entry, and status is exactly the numeric `errSecSuccess` value.

`SecStaticCodeCheckValidityWithErrors` against the compiled peer requirement,
with all architectures and without `kSecCSSkipResourceDirectory`, is the
accept/reject authority. The evidence wrapper and hashes are not substitutes
for that call. The verifier separately validates that every actual designated
requirement is present, canonical Security.framework requirement data and that
the static code satisfies it; this self-designation check cannot substitute
for the stricter peer requirement.

The checked-in first-release profile-signer policy is compact canonical JSON
capped at 32,768 bytes with fields `schema_version` integer `1`, `policy_type`
exactly `apple_developer_id_profile_signer_first_release`, `signer_count`
integer `1`, and `chain`, in that order. `chain` is the exact leaf-to-root
certificate array. Each entry contains, in order, `position`,
`certificate_der_sha256`, `subject_der_sha256`, `issuer_der_sha256`,
`spki_sha256`, `basic_constraints_ca`, `basic_constraints_path_length`,
`key_usage_bits`, `extended_key_usage_oids`, `certificate_policy_oids`,
`subject_key_identifier`, `authority_key_identifier`, `not_before`, and
`not_after`. OID arrays are nonempty sorted canonical dotted-decimal strings;
identifiers are lowercase hex or null; the path length is a nonnegative integer
or null; key usage is the exact nonnegative bit mask. Every value is literal,
not a pattern or caller input. `helper_profile_signer_policy_sha256` is SHA-256
of those exact checked-in bytes and is compiled into both release verifiers.
The current repository has no enrolled first-release policy; its absence fails
closed. Any future certificate, extension, OID, key identifier, or chain change
requires a protocol revision and new Gate, not a policy-file replacement.

`helper_profile_raw_sha256` covers the exact raw
`Contents/embedded.provisionprofile` bytes. Profile CMS evidence is compact
canonical JSON capped at 32,768 bytes with fields in this order:
`schema_version`, `evidence_type` exactly `provisioning_profile_cms`,
`profile_raw_sha256`, `profile_signer_policy_sha256`, `cms_content_sha256`,
`cms_signer_status`,
`cms_certificate_verification_status`, `cms_chain`,
`cms_all_certificates_sha256`, `code_signing_policy_oid`,
`profile_semantic_sha256`, and `validated_at`. The profile is capped at 1 MiB
and the exact call order is
`CMSDecoderCreate`, one `CMSDecoderUpdateMessage` covering all raw bytes,
`CMSDecoderFinalizeMessage`, `CMSDecoderGetNumSigners`,
`CMSDecoderCopyContent`, `CMSDecoderCopyAllCerts`, then
`CMSDecoderCopySignerStatus` for signer index zero with the code-signing policy
and trust evaluation enabled, followed by `SecTrustCopyCertificateChain` on
the returned trust. Exactly one signer and one encapsulated content value must
exist. Every call must succeed; signer status and certificate verification
status must be exactly `kCMSSignerValid` and numeric `errSecSuccess`.
`CMSDecoderCopyAllCerts` must return 1..32 certificates. Each certificate is
exported once with `SecCertificateCopyData`; every DER value is nonempty and
the aggregate DER size is at most 1 MiB. The complete multiset, including
duplicate DER values, is sorted first by the 32 raw digest bytes of
`SHA-256(DER)` and then by the raw DER bytes as a deterministic tie-breaker.
The `cms_all_certificates_sha256` preimage is the ASCII domain
`YTA-CMS-ALL-CERTIFICATES-V1\0`, followed by the certificate count as one
unsigned 32-bit big-endian integer, followed for each sorted multiset entry by
its DER length as one unsigned 32-bit big-endian integer and then its exact DER
bytes. Its value is SHA-256 of that complete byte sequence. No separator,
certificate digest, JSON encoding, deduplication, or platform array order is
part of the preimage. `cms_chain` is the complete
leaf-to-root evaluated chain; each entry carries every field of the checked-in
policy entry and must equal it exactly. Unknown critical extensions, omitted
extension semantics, extra/unordered certificates, policy-digest mismatch, or
time outside any certificate validity interval fails closed. The policy OID
must equal the code-validation evidence. The decoded
plist is the source of a compact profile-semantic object capped at 16,384 bytes
with fields `schema_version` integer `1`, `semantic_type` exactly
`developer_id_profile`, `application_identifier`, `team_identifiers`,
`expires_at`, and `entitlements`, in that order. `team_identifiers` is a
nonempty sorted unique array of 10-character Team IDs. The expiry is converted
from the plist date to UTC whole-second RFC 3339 without rounding.
`entitlements` permits exactly `com.apple.application-identifier`,
`com.apple.developer.team-identifier`, `get-task-allow`, and
`keychain-access-groups`; an unknown entitlement is rejected. Those values,
Team ID, App ID, and expiry must match the descriptor and helper semantic
entitlements. The exact CMS content hash, rather than selected reserialized
metadata, preserves every other Apple-issued profile field.

A typed path token used by release or Gate argv templates is compact canonical
JSON capped at 1,024 bytes with fields `schema_version` integer `1`,
`token_type` exactly `path_argument`, `source`, `fixture_id`,
`content_sha256`, `expected_type`, and `access`, in that order. `source` is
exactly `submitted_artifact_path`, `candidate_app_path`, `gate_profile_path`,
`gate_session_path`, or `fixture_path`. `expected_type` is `regular_file`,
`signed_app_bundle`, or `directory`; access is exactly `read_only`.
`fixture_id` is non-null only for the two fixture-backed sources.
`content_sha256` is required for a submitted artifact or fixture and null for
the signed bundle/session directory, whose descriptor or session identity is
already bound. Source/type/null combinations are closed and compiled into the
consumer. Resolution starts from the already opened trusted root, uses the
one-descriptor path rules above, and substitutes exactly one native path argv
element; no serialized absolute path, environment expansion, tilde, or caller
component is accepted.

Each Apple command-line dependency has one compact canonical tool-capture
object capped at 16,384 bytes. Its fields are `schema_version` integer `1`,
`capture_type` exactly `apple_tool`, `tool_name`, `find_argv`,
`find_exit_code`, `find_stdout_sha256`, `find_stderr_sha256`, `resolved_path`,
`executable_sha256`, `version_probe_argv`, `version_probe_exit_code`,
`version_probe_stdout_sha256`, `version_probe_stderr_sha256`, `version_source`,
`owner_version_argv`, `owner_version_exit_code`,
`owner_version_stdout_sha256`, `owner_version_stderr_sha256`, and `captured_at`,
in that order. All referenced stdout/stderr files are retained exact bytes and
pass secret scanning. Find and owner-version exit codes, when non-null, are
zero. No version-output string is parsed into authority semantics.
A zero version probe requires `version_source` exactly `native_version` and all
four owner-version fields null. A nonzero probe is permitted only for the two
explicit fallback mappings below; every other combination is invalid.

For `notarytool` and `stapler`, `find_argv` is exactly
`/usr/bin/xcrun`, `--find`, then the tool name, and `version_probe_argv` is
exactly `/usr/bin/xcrun`, the tool name, `--version`. `resolved_path` is the sole
printable-ASCII absolute path emitted by `--find`; stdout must be exactly that
path plus LF, stderr must be empty, and `executable_sha256` hashes the regular
file at that resolved path through the same already-opened-descriptor rules.
For `notarytool`, `version_source` is `native_version`, the probe exit is zero,
and all four `owner_version_*` fields are null. For `stapler`, the exact probe
is still executed and all of its bytes and actual `0..255` exit code are
retained. When that captured executable does not support the option,
`version_source` is `xcode_build_fallback`; the nonzero exit and exact usage
output must match the checked-in expected digests for that executable hash,
and `owner_version_argv` is exactly `/usr/bin/xcrun`, `xcodebuild`, `-version`.
An arbitrary failed probe is never treated as a fallback.

The active developer directory is frozen for the ceremony, and xcrun
resolution is repeated after the final tool invocation; any changed path,
executable hash, or output fails the wrapper. For `spctl`, all four `find_*`
fields are null, `resolved_path` is exactly `/usr/sbin/spctl`,
`executable_sha256` hashes that path through an opened descriptor, and
`version_probe_argv` is exactly `/usr/sbin/spctl`, `--version`. If that exact
binary does not support the option, `version_source` is
`macos_build_fallback`; the same pinned-nonzero-probe rule applies and
`owner_version_argv` is exactly `/usr/bin/sw_vers` with no argument. Its exact
output must contain one each of the product name, product version, and build
version keys and match the separately recorded Gate macOS build. An alternate
PATH lookup, shell alias, relative executable, unrecognized failed probe,
failed fallback, or unretained output is invalid.

Notary evidence is one compact canonical wrapper capped at 32,768 bytes with
these fields in order: `schema_version` integer `1`, `evidence_type` exactly
`apple_notary`, `submission_id`, `submitted_artifact_sha256`,
`notarytool_capture_sha256`, `notary_output_schema_sha256`, `submit_argv`, `submit_exit_code`,
`submit_stdout_sha256`, `submit_stderr_sha256`, `log_argv`, `log_exit_code`,
`log_stdout_sha256`, `log_stderr_sha256`, `retained_log_sha256`,
`parsed_submit_id`, `parsed_log_id`, `status` exactly `Accepted`, and
`completed_at`. Both exit codes are exactly zero; all four output files are
retained by digest and must pass secret scanning.

`submit_argv` is exactly `/usr/bin/xcrun`, `notarytool`, `submit`, a typed
`submitted_artifact_path` token carrying `submitted_artifact_sha256`,
`--keychain-profile`, `youtrack-agent-release`, `--wait`, `--output-format`,
`json`. `log_argv` is exactly `/usr/bin/xcrun`, `notarytool`, `log`, a typed
`submission_id` token, `--keychain-profile`, `youtrack-agent-release`,
`--output-format`, `json`. These arrays are direct-process argv values, not
shell text; the typed values are substituted as one argument. The credential
profile name is public, but its Keychain value is never read into evidence.
The submission-ID token is compact canonical JSON with fields `schema_version`
integer `1`, `token_type` exactly `dynamic_scalar`, and `source` exactly
`submission_id`, in that order; it resolves only to the canonical UUID already
present in the wrapper.
The submit JSON and log JSON are strictly parsed under their checked-in,
version-pinned observed-input schema;
their UUID values must both equal `submission_id`, the submit status must be
`Accepted`, and the submitted artifact must pass the same one-descriptor hash
and metadata checks immediately before and after the subprocess.
`notary_output_schema_sha256` is a literal compiled digest of a canonical
manifest containing `schema_version` integer `1`, `schema_type` exactly
`observed_notarytool_json`, `notarytool_capture_sha256`,
`submit_shape_sha256`, and `log_shape_sha256`, in that order. It is a local
allowlist for output observed from the captured tool build, not a claim that
Apple documents or guarantees a stable JSON schema. An unknown field or shape
change fails closed and requires reviewed new observed fixtures, a new literal
digest, and a protocol revision. `retained_log_sha256` exactly equals
`log_stdout_sha256`. A successful exit without those semantic matches is a
failure.

Staple evidence is a non-circular compact wrapper capped at 32,768 bytes with
these fields in order: `schema_version` integer `1`, `evidence_type` exactly
`apple_staple`, `notary_evidence_sha256`, `stapler_capture_sha256`,
`spctl_capture_sha256`, `staple_argv`,
`staple_exit_code`, `staple_stdout_sha256`, `staple_stderr_sha256`,
`validate_argv`, `validate_exit_code`, `validate_stdout_sha256`,
`validate_stderr_sha256`, `spctl_argv`, `spctl_exit_code`,
`spctl_stdout_sha256`, `spctl_stderr_sha256`, `post_staple_code_identities`,
`sec_static_code_check_status`, and `validated_at`. All exit codes and the
Security.framework status are exactly zero; every output is retained by digest
and passes secret scanning.

The three direct argv arrays are exactly `/usr/bin/xcrun`, `stapler`,
`staple`, typed `candidate_app_path`; `/usr/bin/xcrun`, `stapler`, `validate`,
the same typed path; and `/usr/sbin/spctl`, `--assess`, `--type`, `exec`,
`--verbose=4`, the same typed path. No extra flag or alternate executable is
accepted. Stapler validation and `spctl` assessment succeed only by exit code
zero. Their stdout/stderr remain opaque observed evidence: the verifier does
not parse an `accepted` word, source label, app name, or other undocumented
text. The typed path and the subsequent Security.framework validation bind
both invocations to the candidate app. The wrapper contains no descriptor,
authorization, or archive digest; its only predecessor is the already final
notary-evidence digest. The final app is then revalidated through
Security.framework and becomes the app placed in the app-only archive.
`post_staple_code_identities` is an array with exactly one entry for every
descriptor role/architecture pair in descriptor order. Each entry contains
`role`, `architecture`, `ksec_code_info_unique`, and the complete `cdhashes`
array, in that order, and exactly equals the corresponding descriptor slice.
A singular outer identity, native-architecture-only result, missing slice, or
aggregate hash without the canonical array is invalid. This ordering prevents
a descriptor/evidence/archive hash cycle.

## Detached layout and race-free reads

The app-only payload archive contains exactly one top-level
`YouTrackAgent.app/` and excludes every descriptor, token, authorization,
publication envelope, Gate runner, and Gate fixture. The archive format is a
release-packaging choice, not an authority codec. `app_payload_archive_sha256`
is SHA-256 of the exact opaque archive file bytes produced for the candidate;
the file is capped at 1 GiB and retained as evidence. Verifiers never attempt
to reconstruct those bytes from an extracted app.
It is produced exactly once from the final stapled and revalidated app, and its
opaque bytes and digest are retained before the descriptor is canonicalized
and before any E1 token can be issued. No later Gate, smoke, grant, post-grant
verification, or publication step rebuilds or repacks it. After E1 begins, the
only archive created later is the outer delivery archive. The publication
envelope is signed first and then included in that archive at its fixed path.

A production delivery archive contains:

```text
YouTrackAgent.app/
authorization/artifact-descriptor.json
authorization/provisional-production-authorization.json
authorization/production-activation-grant.json
authorization/publication-envelope.json
authorization/post-grant-verification-plan.json
authorization/post-grant-verification-evidence-set/index.json
authorization/post-grant-verification-evidence-set/install-files.json
authorization/post-grant-verification-evidence-set/files/...
```

The descriptor, provisional authorization, and activation grant are outside
the signed app and outside the app-only payload archive. The publication
envelope, exact post-grant plan, canonical complete evidence-set index,
canonical install-evidence manifest, and every file listed by that manifest
are also outside the app-only payload archive but inside the outer delivery
archive at the literal paths above. The `files/` tree is the install-evidence
manifest's closed, relative-path namespace; missing, extra,
duplicate, absolute, dot-segment, symlink, hard-link, or escaping entries fail
closed. The outer archive is an opaque release file capped at 1 GiB and the
Cask pins the SHA-256 of its exact downloaded bytes. The envelope deliberately
does not contain the delivery-archive hash, so including the envelope and its
verification assets creates no recursive hash cycle.

Archive hashes are pre-extraction publication/download evidence only. The
app-only archive hash is verified against the descriptor and retained release
asset; the outer archive hash is a literal Cask checksum verified before
extraction. Neither is runtime authority and neither is recomputed from an
installed tree. Before packaging, the release verifier validates the
app-only archive and the app selected for the outer archive against the same
descriptor, Developer ID signatures, all-architecture code identities,
profile, notarization, and staple evidence. After extraction, installation and
runtime validation use those signed-code checks plus the exact root-signed
sidecar bytes and the envelope-bound post-grant verification assets available
under the same installation root. The code signature's sealed resources, not
a home-grown tree manifest or archive reconstruction, protect the installed
app contents.

For a direct installation, the app and its sibling `authorization/` directory
remain under one installation root. For Homebrew, both remain in the same
versioned Caskroom root and `binary` links only the executable inside the app.
The CLI resolves its executable symlink to the signed app, ascends to that
single versioned root, and accepts no authorization directory outside it.

Every detached file is opened with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW` from an
already opened installation-root directory. Each path component is opened
relative to its parent file descriptor; `..`, empty components, symlinks, hard
links with link count other than one, non-regular files, group/world-writable
files, and owner mismatch are rejected. The verifier applies the raw size cap
to `fstat`, reads to EOF from that one descriptor, repeats `fstat`, and rejects
device/inode, size, mode, owner, or modification-time change. It never validates
one path and reopens another. Gate-only files use the same procedure in a
runner-created mode-`0700` session directory.

Detached files are untrusted until their canonical bytes and root signature
validate. A same-user attacker may replace or replay files, but cannot make a
different code digest satisfy a valid signed authorization.

## Canonical Gate, smoke, and post-grant plans

Gate 1B uses the isolated ADR's coverage inventory and unit compiler, not the
flat v1 plan codec in this section. Its tables below retain behavior coverage,
not a frozen executable contract. The other stages remain unactivated and
their own gates are unchanged.

A Gate plan is data, never a script. Each of the five Gate 1A,
capability-specific activation-smoke, and capability-specific post-grant-
verification plans is capped at 1,048,576 bytes (1 MiB). Their
compact canonical fields are, in order:

1. `schema_version`, integer `1`
2. `plan_type`, exactly `gate1a`, `activation_smoke`, or
   `post_grant_verification`
3. `descriptor_sha256`
4. `approved_capability`, `confirm_only` for Gate 1A; and `confirm_only` or
   `issue_create` for smoke and post-grant verification
5. `architectures`, exactly the descriptor array
6. `fixture_set_sha256`
7. `fixture_executable_manifest_sha256`, required for Gate 1A and null for
   activation smoke and post-grant verification
8. `assertion_set_sha256`
9. `transcript_set_sha256`
10. `command_contract_manifest_sha256`
11. `allowed_network`, exactly `none` for Gate 1A and confirm-only smoke or
    post-grant verification, or `loopback_read_only` for issue-create smoke
    or post-grant verification
12. `sandbox_policy`, exactly `gate1a_deny_v1`,
    `smoke_confirm_deny_v1`, `smoke_issue_loopback_v1`,
    `post_grant_confirm_deny_v1`, or `post_grant_issue_loopback_v1`, matching
    plan type and capability
13. `reset_policy`, exactly `fresh_reverted_host_per_architecture_stage_v1`
14. `minimum_macos_product_build_version`, printable ASCII of 1..32 bytes
15. `architecture_execution_matrix`, the closed array described below
16. `gate_target_sha256`, exactly null
17. `provisional_context_sha256`, null except for activation smoke
18. `authorization_context_sha256`, null except for post-grant verification
19. `stage_setup_policy`, null for Gate 1A or exactly
    `first_exact_artifact_enrollment_v1` for activation smoke and post-grant
    verification
20. `host_disposal_policy`, exactly `external_whole_host_disposal_v1`
21. `cases`, an ordered array

`gate_plan_sha256` always means SHA-256 of these complete exact plan bytes,
including when `plan_type` is `activation_smoke`. No `smoke_plan_sha256` field
or alternate digest exists. The same field and definition apply when plan type
is `post_grant_verification`.

The architecture execution matrix has exactly one entry per descriptor
architecture in descriptor order. Each entry has `architecture`,
`required_native_host` equal to that architecture, `translation_allowed`
exactly false, `fresh_token` exactly true, `fresh_runner_session` exactly true,
and `clean_reset_before_run` exactly true, in that order. The observed macOS
product build and the minimum both match
`^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$`. Comparison parses numeric major, ASCII train
letter, numeric build, then optional seed suffix; an absent suffix sorts after
any suffix for the same first three components. The observed tuple must be at
least the minimum and is recorded byte-for-byte in evidence. A run under
Rosetta, on an undeclared slice, with a reused token/session/host state, or
missing one matrix row fails the whole evidence set.

The five flat-plan sandbox policies are compiled constants, not file paths. They deny
undeclared subprocesses and filesystem access outside the mode-0700 Gate root.
For an `exact_artifact` case they permit only the descriptor-pinned CLI/helper
and the runner/verifier named by its command contract. The sole exception is
the compiled mixed-build rejection substeps of
`gate1a.artifact.runtime-peer-validation`, which may launch the manifest-pinned
`negative_peer_fixture` only as an adversarial connection input. It has no
Keychain, registry, helper, or positive-protocol authority and must be rejected
before protocol bytes. For a
`disjoint_fixture` case they deny execution of the production CLI/helper and
permit only the command-contract-declared `fixture_cli`/`fixture_helper` whose
active slice exactly matches the fixture-executable manifest, plus the same
runner/verifier supervisors. No fixture identity is accepted on an
`exact_artifact` case except the negative peer's bounded adversarial launch,
which is never an accepted protocol peer; no production identity is accepted
on a `disjoint_fixture` case.

Every policy permits the fixed per-user helper-owned `AF_UNIX`
`SOCK_SEQPACKET` listener from the trust-root protocol. The exact outer CLI
connects itself: a connected descriptor created by the runner would
authenticate the runner, not that CLI, and is forbidden for ordinary peer
traffic. The receiver validates `LOCAL_PEERTOKEN` and the exact peer
requirement before any protocol byte, including Team ID, identifier, build,
active-slice unique/cdhash set, descriptor, and authorization context.
Runner session authority arrives on a separately authenticated control
connection and cannot substitute for CLI/helper authentication. Only its
compiled control transport and endpoints are admitted in addition to the
ordinary listener. Disjoint fixtures use their separate fixed
`fixture-ipc/approval.sock` namespace beneath their opened session root and
self-connect there; production identities never gain fixture authority.
The manifest-pinned old-build negative outer self-connects to the ordinary
listener and must be rejected before authority traffic. The negative helper
is contacted only by the compiled rejection probe in its disjoint endpoint;
it is never installed or substituted for the ordinary listener. No runner
preconnected descriptor can stand in for either peer.
Gate 1A and confirm-only smoke deny `AF_INET`,
`AF_INET6`, and every other socket family/type. Gate 1B unit sandbox authority
is defined only by the isolated-subrun ADR; an old `gate1b_target_v1` flat plan
cannot enable network access.
`smoke_issue_loopback_v1` permits only its token's IPv4 loopback origin and
read-only `GET`/`HEAD`; the mutation dispatcher remains a pre-socket hard deny.
The two post-grant policies have the same network restrictions as their smoke
counterparts but require the real grant-bound final authorization context and
the post-grant token's distinct dispatch-denial code.
For the release-stage setup-policy value, `stage_setup_policy` grants no ambient registry
authority: it is usable only by the matching first compiled setup case, only
with the root-signed token and derived setup context for that plan type, and
only to create revision 1 from the proved empty disposable inventory described
below. The context is a bound authorization input to the normal enrollment
ceremony, not a signing credential or standalone signing endpoint; the helper
still performs the ceremony's ordinary proposal and final registry signatures
with its exact enrolled key and fresh user-presence checks. Rotation, recovery,
revocation, a second enrollment, receipt signing, and mutation dispatch are
outside setup authority. No stage grants live per-item deletion authority.
`stage_cleanup` IPC, cleanup contexts, cleanup intents, progress/ACK ledgers,
and cleanup restart authority are absent from the first-release protocol.
Every host is disposable; the trusted external supervisor destroys it after
bounded sanitized evidence export. This lifecycle action is outside the
candidate sandbox and must not be implemented as a helper or CLI operation.
An inherited non-IPC descriptor, alternate Unix path, missing audit-token
check, IPv6/hostname loopback, datagram/raw socket, or undeclared socket attempt
is a Gate failure. Any policy change requires a protocol revision, not a new
caller value.

### Fixture, executable, assertion, and transcript manifests

The fixture and assertion sets are compact canonical JSON, each capped at
65,536 bytes with 1..256 entries and no extensions. The transcript set is
compact canonical JSON capped at 1,048,576 bytes (1 MiB) with 1..2,048 entries
and no extensions. These are independent byte and entry caps, not substitutes
for the exact membership requirements below. A fixture-set manifest has fields
`schema_version` integer `1`, `manifest_type` exactly `fixture_set`, and
`entries`, in that order. Each entry has `fixture_id`, `fixture_kind`,
`content_sha256`, `size`, and `mode`, in that order. Kind is exactly
`canonical_json`, `binary_blob`, `profile_root_archive`, or `expected_output`;
size is `1..8,388,608`; mode is exactly `read_only`. Directory fixtures are
deterministic archives, never caller-supplied paths.

The Gate 1A fixture-executable manifest is a separate compact canonical JSON
object capped at 32,768 bytes. Its fields are `schema_version` integer `1`,
`manifest_type` exactly `fixture_executables`, `descriptor_sha256`,
`fixture_namespace` exactly
`io.github.abigotado.youtrack-agent.gate1a.fixture`, `fixture_set_sha256`,
`architectures`, `fixture_code_slices`, and
`negative_peer_code_slices`, in that order. `architectures` exactly equals the
descriptor array. `fixture_code_slices` is ordered
first by role `fixture_cli`, `fixture_helper`, then by architecture in
descriptor order, with exactly one entry for every pair. Each entry contains,
in order, `role`, `architecture`, `identifier`, `team_id`, `build`,
`executable_sha256`, `ksec_code_info_unique`, `cdhashes`,
`entitlements_semantic_sha256`,
`actual_designated_requirement_data_sha256`, and
`code_validation_evidence_sha256`. `cdhashes` uses the exact descriptor-slice
codec. Identifiers are exactly
`io.github.abigotado.youtrack-agent.gate1a.fixture` and
`io.github.abigotado.youtrack-agent.gate1a.fixture.approval` for their matching
roles. Every other value is obtained and validated by the same per-architecture
Security.framework procedure and grammar as a descriptor code slice.
The resolved fixture access-group suffix is exactly the namespace plus
`.approval`; the key-tag prefix is the namespace plus
`.approval.signing.v1/`; the registry service is the namespace plus
`.approval.registry.v1`; and its peer requirements name only the two fixture
identifiers above. No test, temporary, or caller-selected namespace alias is
accepted.

`negative_peer_code_slices` is ordered by `peer_component` `outer`, `helper`,
then descriptor architecture, with exactly one entry for every pair. Each
entry has `role` exactly `negative_peer_fixture`, then `peer_component`,
`architecture`, `identifier`, `team_id`, `build`, `executable_sha256`,
`ksec_code_info_unique`, `cdhashes`, `entitlements_semantic_sha256`,
`actual_designated_requirement_data_sha256`, and
`code_validation_evidence_sha256`, in that order. Identifier and Team ID equal
the matching production descriptor values, but `build` is one literal positive
decimal build strictly older than `release_build` and is identical in every
negative-peer slice. Its exact signed per-architecture identities and hashes
are manifest data, never a wildcard or semantic-only match.

The disjoint fixture slices must differ from the artifact descriptor in both
identifiers and every role/architecture `ksec_code_info_unique` and
`executable_sha256`. The negative-peer slices deliberately retain production
identifiers but must differ in build, unique identifier, executable hash, and
cdhashes. The negative peer is a separately signed, never-shipped old pair: it
is not notarized, stapled, archived, installed, or accepted as authority, and
is destroyed with the disposable Gate environment. It proves only that the
current exact artifact rejects a mixed-build connection; it does not claim
that this first-release topology prevents a separately run matched old pair.
The manifest is content-addressed by the plan and signed indirectly
by the Gate token; it is never a production descriptor, publication input, or
runtime authority. The checked-in Gate 1A command contract fixes its exact
manifest digest. A missing slice, uncompiled manifest, or fixture binary not
equal to its active signed slice fails before execution. A production
identifier on a disjoint fixture role, or a nonproduction identifier on a
negative-peer component, also fails.

An assertion-set manifest has fields `schema_version` integer `1`,
`manifest_type` exactly `assertion_set`, and `entries`. Each entry has
`assertion_id`, `evaluator`, and `expected_sha256`, in that order. Evaluator is
exactly `json_envelope`, `exit_code`, `filesystem_state`, `keychain_state`,
`code_identity`, `network_transcript`, `byte_equality`, `ui_observation`, or
`archive_state`, or `concurrency_trace`; its expected object is one canonical
fixture in the fixture set. The verifier, not the plan, implements these
evaluators.

A transcript-set manifest has fields `schema_version` integer `1`,
`manifest_type` exactly `transcript_set`, and `entries`. Each entry has
`transcript_id`, `transcript_kind`, `maximum_bytes`, and `redaction_policy`, in
that order. Kind is exactly `stdout`, `stderr`, `ipc`, `network`, `ui`, or
`security_framework`, or `concurrency_trace`; maximum is `1..8,388,608`;
redaction policy is exactly `reject_secret_then_hash`. A detected credential,
token, private key, or unredacted secret fails the run instead of being
replaced.

A command-contract manifest is compact canonical JSON capped at 1,048,576
bytes (1 MiB), for each of the five flat plan types/capabilities.
Its fields are `schema_version` integer `1`, `manifest_type` exactly
`command_contract`, `plan_type`, `approved_capability`,
`fixture_executable_manifest_sha256`, `entries`, and `case_evaluations`, in
that order. The fixture digest follows the same required/null rule as the plan.
Entries are in the
normative case/step order below and contain, in order, `case_id`,
`evidence_scope`, `step_id`, `executable_role`, `executable_component`, `argv`,
`working_directory`, `environment`, `stdin`, `timeout_seconds`, `fixture_ids`,
`assertion_ids`, and `transcript_ids`.
`argv` and `transcript_ids` are nonempty; `assertion_ids` is the exact empty
array on every operation entry. `environment` is the required empty array;
`fixture_ids` may be empty where the compiled contract needs no fixture. The
`argv` field is the exact typed template later resolved by the runner. The
entry fixes each operation's executable, argv template, timeout, and complete
ordered ID lists; a plan never supplies or overrides different values.

`case_evaluations` has exactly one entry per case in normative case order.
The five flat manifests therefore contain exactly 23, 5, 6, 6, and 7
case-evaluation entries for Gate 1A, smoke confirm, smoke issue-create,
post-grant confirm, and post-grant issue-create respectively. Gate 1B unit
evaluators are generated by the new coverage inventory, not these totals.
Each contains, in order, `case_id`, `observation_id` equal to the case ID plus
`/final-evaluation`, `executable_role` and `executable_component` both exactly
`gate_runner`, `assertion_ids`, and `transcript_ids`. Its `assertion_ids` are
the complete ordered IDs obtained from that case row's suffixes. Its
`transcript_ids` are exactly the final evaluator's derived `stdout` then
`stderr` IDs. This is not a candidate subprocess command: it binds the
already authenticated runner's mandatory case-final evaluation after every
operation observation and transcript result exists. A plan case contains
`case_id`, `evidence_scope`, `steps`, and `final_evaluation`, in that order;
the last field is rebuilt from this manifest entry.

The flat-plan release verifier requires five checked-in literal digests named
`GATE1A_COMMAND_CONTRACT_SHA256`,
`SMOKE_CONFIRM_COMMAND_CONTRACT_SHA256`, and
`SMOKE_ISSUE_CREATE_COMMAND_CONTRACT_SHA256`,
`POST_GRANT_CONFIRM_COMMAND_CONTRACT_SHA256`, and
`POST_GRANT_ISSUE_CREATE_COMMAND_CONTRACT_SHA256`. Each is SHA-256 of one complete
manifest whose plan type/capability matches its name. The corresponding plan
field must equal that literal, its fixture-executable field must equal the
manifest field, and its `cases` array must byte-for-byte equal the canonical
case tree rebuilt from all operation and case-evaluation manifest entries,
including scope. A missing literal/manifest,
unregistered digest, empty step, changed command field, or validly hashed but
uncompiled manifest fails before token acceptance. Changing a contract requires
a protocol revision and new Gate.

Case, step, fixture, assertion, and transcript IDs match
`^[a-z0-9][a-z0-9._-]{0,127}$`. Case IDs are unique within a complete plan;
step IDs are unique within their case and may recur in different cases.
Fixture, assertion, and transcript IDs are globally unique by manifest type.
Observation IDs instead are exactly a compiled case ID, one literal `/`, and
that case's compiled step ID or the literal `final-evaluation`; the complete
ID is at most 128 ASCII bytes. Exact membership in the fixed case/step or
case-final contract is mandatory. Extra slashes, path escapes, percent-encoded
separators, and normalization or decoding to obtain a matching ID are rejected.
Only set-like fixture, assertion, and transcript manifest entry
arrays are sorted by increasing unsigned UTF-8 ID bytes and must already be in
that order on input. Order-bearing arrays are never sorted: command-contract
entries and `case_evaluations`, plan `cases`, case `steps`, step `argv`,
case-final `assertion_ids`, `transcript_ids`, observations, evidence scopes,
and concurrency trace events must occur in the exact normative order declared
below. A producer cannot use
map iteration or byte sorting to replace that order. A set digest is SHA-256
over the exact canonical bytes of the explicitly set-like manifest. The plan
validator loads each manifest by digest, rejects missing/extra entries, and
requires every operation and final-evaluation reference to resolve with the
declared kind and evaluator.
An unreferenced manifest entry or a referenced ID absent from the plan is
invalid.

The fixed case tables below derive the following exact cardinalities for each
complete plan, command contract, transcript set, assertion set, and passing
per-architecture evidence index. Every operation contributes one observation;
every case contributes one additional final-evaluation observation, with its
own stdout and stderr transcript IDs. Additional transcript kinds apply to
each operation exactly as declared in its case row. These counts are equality
requirements, not maxima that permit omitted cases or additional authority.

| Plan/capability | Cases / final evaluations | Operations | Observations | Transcript entries | Assertion entries |
| --- | --- | --- | --- | --- | --- |
| Gate 1A | 23 | 78 | 101 | 381 | 69 |
| Activation smoke / confirm-only | 5 | 12 | 17 | 58 | 16 |
| Activation smoke / issue-create | 6 | 15 | 21 | 77 | 18 |
| Post-grant / confirm-only | 6 | 11 | 17 | 59 | 17 |
| Post-grant / issue-create | 7 | 14 | 21 | 78 | 20 |

Gate 1B has no executable flat-count row. Its compiler must materialize all
independent phases and negative variants and derive bounded unit/leaf/parent
counts under the isolated ADR. The legacy catalog's longest local IDs remain
within the 128-byte leaf limit; they do not authorize a single combined index.
The five flat-stage evidence-index codecs use
the same independent 1 MiB object, 256-observation, 4,096-referenced-file,
8 MiB-per-file, and 256 MiB-aggregate limits. Exact membership and ordering
remain mandatory within those limits. Per-observation assertion-result and
transcript-result manifests retain their separate 32,768-byte caps.

Shared bounds do not imply one shared index schema. Gate 1A, smoke and
post-grant indexes deliberately retain their distinct ordered field lists;
the isolated Gate 1B index is another distinct type. The always-null legacy
target/prerequisite/setup fields remain present exactly where listed and
cannot be omitted or moved to normalize the schemas. A proposed compiler may
derive fixed plan policy fields from the selected stage/capability, but those
fields remain authenticated, validated constants in canonical plan bytes,
never caller choices or optional unchecked metadata.

Before freezing any of the five flat literal command-contract digests, the compiler
must materialize and validate every complete checked-in canonical manifest
and plan, including all typed arguments and resolved ID references, against
both its byte and entry budgets. It must also construct each complete
evidence-index/result-manifest skeleton with the maximum encoded lengths of
its permitted runtime fields, enumerate the complete referenced-file closure,
and verify object, count, per-file, and aggregate budgets using checked
arithmetic. This includes the separately scoped post-grant install manifest
across all declared architectures. No digest may be frozen if any budget is
exceeded; cardinalities alone do not prove byte-size feasibility. The budget
report is conformance evidence, not runtime authority or permission to weaken
an object limit. Runtime decoding checks caps before proportional allocation,
parsing, or referenced-file reads even for a pinned digest.

There are no optional fields, user extensions, ignored metadata, default
steps, or wildcard case IDs. `evidence_scope` is exactly `exact_artifact` or
`disjoint_fixture`. The compiled mapping assigns exactly these five cases to
`disjoint_fixture`: `gate1a.registry.corruption-deny`,
`gate1a.registry.fork-gap-duplicate-deny`,
`gate1a.registry.crash-ambiguous-secitemadd`,
`gate1a.registry.orphan-cleanup`, and
`gate1a.registry.active-key-loss`. Every other Gate 1A case, including ordinary
`gate1a.registry.enroll-rotate-revoke-recover` and every
activation-smoke and post-grant-verification case is `exact_artifact`. No caller or plan generator can
change this mapping. The
exact Gate 1A case order is:

1. `gate1a.artifact.static-validation`
2. `gate1a.artifact.runtime-peer-validation`
3. `gate1a.protocol.positive-vectors`
4. `gate1a.protocol.negative-vectors`
5. `gate1a.registry.enroll-rotate-revoke-recover`
6. `gate1a.registry.corruption-deny`
7. `gate1a.registry.fork-gap-duplicate-deny`
8. `gate1a.registry.crash-ambiguous-secitemadd`
9. `gate1a.registry.orphan-cleanup`
10. `gate1a.registry.active-key-loss`
11. `gate1a.confirm.ordinary-success`
12. `gate1a.confirm.cancel-and-expire`
13. `gate1a.confirm.restart-and-replay-deny`
14. `gate1a.confirm.untrusted-display`
15. `gate1a.network.hard-deny`
16. `gate1a.authority.fail-closed-matrix`
17. `gate1a.install.first-install-validation`
18. `gate1a.install.identical-reinstall`
19. `gate1a.install.rollback-and-replacement-deny`
20. `gate1a.install.uninstall-cleanup`
21. `gate1a.migration.cancel`
22. `gate1a.migration.interruption`
23. `gate1a.migration.partial-failure`

This closed Gate 1A list contains exactly 23 cases; the compiled case table
below must contain the same IDs once each in this exact order.

The Gate 1B family order below is coverage input for the
[isolated unit inventory](gate1b-isolated-subruns.md#coverage-inventory-and-unit-definition).
Each expanded unit has independent pre-token host/target allocation, fresh
setup, and final evaluation. The setup family expresses a requirement of
every unit, not one global enrollment followed by 25 state-sharing cases.

1. `gate1b.setup-exact-artifact-enrollment`
2. `gate1b.issue-create.prepare-confirm-apply-success`
3. `gate1b.issue-create.expected-state-conflict`
4. `gate1b.issue-create.timeout-reconcile-created`
5. `gate1b.issue-create.timeout-reconcile-absent`
6. `gate1b.issue-create.timeout-reconcile-conflict`
7. `gate1b.issue-create.one-shot-no-retry`
8. `gate1b.coordinator.apply-vs-rotate-linearization`
9. `gate1b.coordinator.apply-vs-revoke-linearization`
10. `gate1b.coordinator.apply-vs-recovery-linearization`
11. `gate1b.coordinator.invalid-enrollment-contention`
12. `gate1b.coordinator.crash-before-permit`
13. `gate1b.coordinator.crash-after-permit-before-send`
14. `gate1b.coordinator.crash-after-send-before-outcome`
15. `gate1b.coordinator.crash-after-durable-outcome-before-closed-add`
16. `gate1b.coordinator.closed-add-ambiguity`
17. `gate1b.coordinator.crash-after-closed-before-active-delete`
18. `gate1b.coordinator.active-delete-ambiguity`
19. `gate1b.coordinator.active-cleanup-aba-deny`
20. `gate1b.coordinator.multi-helper-unclosed-quarantine`
21. `gate1b.authority.status-recover-contract`
22. `gate1b.journal.v1-v2-migration-and-quarantine`
23. `gate1b.capability.update-comment-other-deny`
24. `gate1b.target.origin-account-project-deny`
25. `gate1b.receipt.context-and-replay-deny`
26. `gate1b.authority.fail-closed-matrix`

This Gate 1B catalog contains exactly 26 coverage families; the coverage table
below must contain the same IDs once each in this order. Neither is a frozen
or executable command contract; only the isolated ADR's materialized unit
inventory can supply that contract.

For activation smoke, `confirm_only` has exactly these cases:

1. `smoke.confirm.setup-exact-artifact-enrollment`
2. `smoke.confirm.prepare-confirm-success`
3. `smoke.confirm.apply-all-deny`
4. `smoke.confirm.receipt-context-ineligible`
5. `smoke.confirm.authority-negatives`

`issue_create` smoke has exactly these cases:

1. `smoke.issue-create.setup-exact-artifact-enrollment`
2. `smoke.issue-create.prepare-confirm-apply-dispatch-deny`
3. `smoke.issue-create.zero-mutating-bytes`
4. `smoke.issue-create.update-comment-other-deny`
5. `smoke.issue-create.receipt-context-ineligible`
6. `smoke.issue-create.authority-negatives`

Post-grant verification for `confirm_only` has exactly these cases:

1. `post-grant.confirm.setup-exact-artifact-enrollment`
2. `post-grant.confirm.prepare-confirm-success`
3. `post-grant.confirm.apply-all-deny`
4. `post-grant.confirm.receipt-terminal-replay-deny`
5. `post-grant.confirm.authority-negatives`
6. `post-grant.confirm.seal-evidence`

Post-grant verification for `issue_create` has exactly these cases:

1. `post-grant.issue-create.setup-exact-artifact-enrollment`
2. `post-grant.issue-create.prepare-confirm-apply-dispatch-deny`
3. `post-grant.issue-create.zero-mutating-bytes`
4. `post-grant.issue-create.update-comment-other-deny`
5. `post-grant.issue-create.receipt-terminal-replay-deny`
6. `post-grant.issue-create.authority-negatives`
7. `post-grant.issue-create.seal-evidence`

The four stage lists therefore contain exactly 5, 6, 6, and 7 cases in the
order shown. Each first case is the only setup-authorized case; each last case
contains or is the final sanitized evidence-export verification. Host disposal
is attested afterward outside the candidate, without an index/attestation cycle.

The verifier compiles the following closed case contracts. Operation step IDs
and case-final assertion suffixes occur in the shown order; a suffix forms the
assertion ID by directly appending it to the case ID. Every operation records
`stdout` and `stderr`; the last column adds required transcript kinds. The
tables do not abbreviate assertion timing: every listed suffix belongs only to
the separate `/final-evaluation` observation, never to an operation
observation.

| Gate 1A case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `gate1a.artifact.static-validation` | `validate` | `.primary`, `.all-architectures`, `.sealed-launchagent-and-fixed-endpoint` | `security_framework` |
| `gate1a.artifact.runtime-peer-validation` | `launch`, `handshake`, `launch-negative-outer`, `reject-negative-outer`, `launch-negative-helper`, `reject-negative-helper` | `.primary`, `.mixed-cli-peer-deny`, `.mixed-helper-peer-deny`, `.negative-peer-no-authority` | `ipc`, `security_framework` |
| `gate1a.protocol.positive-vectors` | `verify` | `.primary` | `ipc` |
| `gate1a.protocol.negative-vectors` | `verify` | `.primary`, `.all-negatives-rejected` | `ipc` |
| `gate1a.registry.enroll-rotate-revoke-recover` | `enroll`, `rotate`, `revoke`, `recover` | `.primary`, `.final-state`, `.coordinator-serialized`, `.all-leases-closed` | `ipc`, `ui`, `security_framework` |
| `gate1a.registry.corruption-deny` | `seed`, `corrupt`, `parse-deny` | `.primary`, `.no-transition` | `ipc`, `security_framework` |
| `gate1a.registry.fork-gap-duplicate-deny` | `seed`, `parse-fork`, `parse-gap`, `parse-duplicate` | `.primary`, `.all-malformed-denied` | `ipc`, `security_framework` |
| `gate1a.registry.crash-ambiguous-secitemadd` | `seed`, `arm-crash`, `secitemadd`, `reconcile` | `.primary`, `.one-shot`, `.ambiguous-reconciled` | `ipc`, `security_framework` |
| `gate1a.registry.orphan-cleanup` | `seed-orphan`, `cleanup`, `verify` | `.primary`, `.only-orphan-removed`, `.delete-ambiguity-code-exit1` | `ipc`, `security_framework` |
| `gate1a.registry.active-key-loss` | `seed`, `remove-active`, `recover`, `verify` | `.primary`, `.recovery-required`, `.final-state` | `ipc`, `ui`, `security_framework` |
| `gate1a.confirm.ordinary-success` | `prepare`, `confirm` | `.primary`, `.receipt-context` | `ipc`, `ui` |
| `gate1a.confirm.cancel-and-expire` | `prepare`, `cancel`, `expire` | `.primary`, `.no-confirmed-plan` | `ipc`, `ui` |
| `gate1a.confirm.restart-and-replay-deny` | `prepare`, `confirm`, `restart`, `replay` | `.primary`, `.replay-denied` | `ipc`, `ui` |
| `gate1a.confirm.untrusted-display` | `prepare`, `confirm` | `.primary`, `.bytes-inert` | `ipc`, `ui` |
| `gate1a.network.hard-deny` | `confirm`, `audit` | `.primary`, `.zero-network-bytes` | `network`, `ipc`, `ui` |
| `gate1a.authority.fail-closed-matrix` | `verify-matrix` | `.primary`, `.all-negatives-rejected`, `.profile-expiry-code-exit12` | `ipc`, `security_framework` |
| `gate1a.install.first-install-validation` | `stage`, `install`, `validate`, `launch` | `.primary`, `.exact-tree`, `.profile-valid`, `.ordinary-launch` | `ipc`, `security_framework` |
| `gate1a.install.identical-reinstall` | `install`, `reinstall-identical`, `validate`, `launch` | `.primary`, `.byte-identical`, `.keychain-preserved`, `.ordinary-launch` | `ipc`, `security_framework` |
| `gate1a.install.rollback-and-replacement-deny` | `install`, `attempt-rollback`, `replace-cli`, `replace-helper`, `validate-denials` | `.primary`, `.rollback-denied`, `.cli-replacement-denied`, `.helper-replacement-denied`, `.zero-authority` | `ipc`, `security_framework` |
| `gate1a.install.uninstall-cleanup` | `install`, `seed-gate-state`, `uninstall`, `audit` | `.primary`, `.app-removed`, `.no-silent-keychain-delete`, `.no-post-uninstall-authority` | `ipc`, `security_framework` |
| `gate1a.migration.cancel` | `seed-legacy-sentinel`, `start-migration`, `cancel-presence`, `verify-source`, `verify-destination-absent` | `.primary`, `.source-intact`, `.destination-absent`, `.no-secret-transcript` | `ipc`, `ui`, `security_framework` |
| `gate1a.migration.interruption` | `seed-legacy-sentinel`, `start-migration`, `interrupt-before-commit`, `restart`, `reconcile`, `verify` | `.primary`, `.source-intact-or-exact-destination`, `.no-duplicate`, `.no-secret-transcript` | `ipc`, `ui`, `security_framework` |
| `gate1a.migration.partial-failure` | `seed-legacy-sentinel`, `arm-destination-write-failure`, `migrate`, `reconcile`, `verify` | `.primary`, `.source-intact`, `.partial-destination-ineligible`, `.no-secret-transcript` | `ipc`, `ui`, `security_framework` |

The seven install/migration cases above are a closed Gate 1A set, not examples.
They run on the clean-reset exact-artifact host in E1 and E2 and use the same
descriptor-bound archive retained before descriptor creation. First install
must reproduce the descriptor's installation tree and profile expiry;
identical reinstall must leave the exact code bytes and every preexisting
Keychain item unchanged. Rollback and either-component replacement must fail
peer/artifact validation before authority access. Uninstall must remove the app
and link while leaving approval, credential, registry, coordinator, and journal
state untouched and unusable until an equal authorized artifact is installed.

Migration uses a Gate-owned non-secret sentinel value generated from a fixed
fixture, never a real credential. It drives the ordinary existing
`auth migrate-keychain --profile gate-migration --yes` command through direct
spawn; `--yes` authorizes only this explicit Gate fixture and is not an
installer hook. Cancellation occurs at the native user-presence prompt before
any destination commit. Interruption terminates the process after destination
staging but before source deletion/commit. Partial failure injects exactly one
destination `SecItemAdd` failure through the authenticated Gate fixture
boundary. In all three cases the source remains intact unless an exact,
readable, byte-equal destination has durably committed; partial destination
state is ineligible, never selected as a credential, and is reconciled without
repeating an ambiguous add. Transcripts contain only item identifiers,
OSStatus/reason classes, digests, and bounded projections—not `kSecValueData`
or the sentinel bytes. Cancellation, interruption at every durable boundary,
source-read failure, destination-add success/error/ambiguity, exact-winner,
different-winner, source-delete success/error/ambiguity, restart, and cleanup
partial failure are mandatory schedule fixtures for these cases. Missing any
one is a Gate failure.

| Gate 1B coverage family | Legacy step/phase labels (not executable) | Required assertion suffixes | Required transcript kinds |
| --- | --- | --- | --- |
| `gate1b.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.gate1b-setup-only-authority`, `.registry-baseline-snapshot` | `ipc`, `ui`, `security_framework` |
| `gate1b.issue-create.prepare-confirm-apply-success` | `prepare`, `confirm`, `apply` | `.primary`, `.one-created-issue` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.expected-state-conflict` | `prepare`, `confirm`, `mutate-fixture`, `apply` | `.primary`, `.zero-create` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.timeout-reconcile-created` | `prepare`, `confirm`, `apply-timeout`, `reconcile` | `.primary`, `.one-created-issue` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.timeout-reconcile-absent` | `prepare`, `confirm`, `apply-timeout`, `reconcile` | `.primary`, `.zero-create` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.timeout-reconcile-conflict` | `prepare`, `confirm`, `apply-timeout`, `reconcile` | `.primary`, `.conflict-closed` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.one-shot-no-retry` | `prepare`, `confirm`, `apply`, `audit` | `.primary`, `.one-mutation-dispatch` | `network`, `ipc`, `ui` |
| `gate1b.coordinator.apply-vs-rotate-linearization` | `apply-first`, `rotate-after-close`, `reset`, `rotate-first`, `apply-after-rotation` | `.primary`, `.pre-read-registry-intent-bound`, `.candidate-validated-under-lease`, `.apply-first-serialized`, `.rotation-first-cancels`, `.zero-overlap` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.apply-vs-revoke-linearization` | `apply-first`, `revoke-after-close`, `reset`, `revoke-first`, `apply-after-revocation` | `.primary`, `.pre-read-registry-intent-bound`, `.candidate-validated-under-lease`, `.apply-first-serialized`, `.revocation-first-cancels`, `.zero-overlap` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.apply-vs-recovery-linearization` | `apply-first`, `recover-after-close`, `reset`, `recover-first`, `apply-after-recovery` | `.primary`, `.pre-read-registry-intent-bound`, `.candidate-validated-under-lease`, `.apply-first-serialized`, `.recovery-first-cancels`, `.zero-overlap` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.invalid-enrollment-contention` | `acquire-apply`, `attempt-enrollment`, `verify-busy-before-ledger-read`, `close-apply` | `.primary`, `.one-losing-active-add`, `.busy-before-enrollment-validation`, `.zero-later-authority-read-or-write`, `.closed-and-fenced`, `.busy-code-exit10` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-before-permit` | `prepare`, `confirm`, `acquire`, `crash-before-in-flight`, `classify-before-in-flight`, `reset`, `prepare-again`, `confirm-again`, `acquire-again`, `mark-in-flight`, `crash-before-permit`, `classify-after-in-flight`, `audit` | `.primary`, `.both-unclosed-states-quarantined`, `.journal-byte-preserved`, `.zero-mutation-dispatch`, `.zero-close-add-or-delete`, `.quarantine-code-exit1` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-permit-before-send` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `crash`, `classify`, `reconcile-read-only`, `audit` | `.primary`, `.unclosed-quarantined-no-retry`, `.zero-mutation-dispatch`, `.zero-state-writes` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-send-before-outcome` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `send`, `crash`, `classify`, `reconcile-read-only`, `audit` | `.primary`, `.unclosed-quarantined-no-retry`, `.at-most-one-created-issue`, `.zero-recovery-state-writes` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-durable-outcome-before-closed-add` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `send`, `record-outcome-and-normal-close-bytes`, `crash`, `classify-unclosed`, `audit` | `.primary`, `.outcome-does-not-authorize-close-add`, `.unclosed-quarantined`, `.no-retry`, `.zero-recovery-state-writes`, `.at-most-one-created-issue` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.closed-add-ambiguity` | `run-equal-winner`, `reset`, `run-not-found-then-quarantine`, `reset-again`, `run-conflicting-winner`, `audit` | `.primary`, `.read-first`, `.equal-reconciled-success`, `.not-found-quarantined-no-add`, `.conflict-code-exit1`, `.no-blind-add`, `.no-resend` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-closed-before-active-delete` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `send`, `record-outcome`, `add-closed`, `crash`, `recover-delete`, `audit` | `.primary`, `.closed-fence-survives`, `.no-resend`, `.single-active-delete`, `.at-most-one-created-issue` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.active-delete-ambiguity` | `run-not-found`, `reset`, `run-equal-active-then-recover`, `reset-again`, `run-different-active`, `reset-third`, `run-malformed-active`, `audit` | `.primary`, `.read-first`, `.not-found-reconciled-success`, `.equal-code-exit11-then-one-matching-delete`, `.different-active-stale-noop`, `.malformed-code-exit1`, `.no-blind-delete`, `.closed-fence-survives`, `.no-resend` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.active-cleanup-aba-deny` | `seed-closed-active`, `capture-active-reference`, `pause-cleaner`, `second-helper-delete-old`, `acquire-replacement`, `resume-stale-delete`, `verify-replacement`, `close-replacement`, `audit` | `.primary`, `.two-valid-helpers`, `.persistent-ref-bound`, `.replacement-survives`, `.old-ref-not-found-stale-noop`, `.no-attribute-delete`, `.fixed-active-lock` | `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.multi-helper-unclosed-quarantine` | `pause-before-permit`, `probe-second-helper`, `reset`, `pause-after-permit`, `probe-alternate-bootstrap`, `reset-again`, `pause-before-close`, `probe-reboot-expiry-ui`, `audit` | `.primary`, `.two-valid-helpers-authenticated`, `.same-uid-bootstrap-in-scope`, `.owner-may-still-run`, `.unclosed-active-preserved`, `.journal-byte-preserved`, `.zero-close-add-delete-or-sign`, `.zero-permit-send-or-commit`, `.no-retry`, `.quarantine-code-exit1` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.authority.status-recover-contract` | `status-clear`, `status-expired-no-active`, `seed-unresolved`, `status-quarantine`, `reject-flags`, `recover-cancel`, `recover-unclosed-deny`, `seed-expired-unresolved`, `recover-expired-unclosed-deny`, `status-after` | `.primary`, `.required-invocation-meta`, `.exact-json-v1-shapes`, `.reachable-status-recover-exits`, `.explicit-profile`, `.closed-inherited-flags`, `.no-plan-id-or-force-clear`, `.expired-no-active-exit12`, `.cancel-no-change`, `.ui-not-fencing-proof`, `.unclosed-byte-preserved`, `.expired-closed-cleanup-only`, `.recovery-only-capabilities`, `.zero-network-bytes` | `network`, `ipc`, `ui`, `security_framework` |
| `gate1b.journal.v1-v2-migration-and-quarantine` | `seed-v1-prepared`, `migrate-prepared`, `seed-v1-canceled`, `quarantine-canceled`, `seed-v1-expired`, `quarantine-expired`, `seed-v1-failed_before_mutation`, `quarantine-failed_before_mutation`, `seed-v1-confirmed`, `quarantine-confirmed`, `seed-v1-in-flight`, `quarantine-in-flight`, `seed-v1-remote-state`, `quarantine-remote-state`, `interrupt-before-rename`, `interrupt-after-rename`, `audit` | `.primary`, `.exact-v2-schema`, `.prepared-only-migration-atomic`, `.all-other-valid-v1-byte-preserved`, `.failed_before_mutation-quarantined`, `.quarantine-code-exit1`, `.ambiguous-write-readback`, `.no-authority-from-v1` | `ipc` |
| `gate1b.capability.update-comment-other-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-mutation-dispatch` | `network`, `ipc` |
| `gate1b.target.origin-account-project-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-target-bytes` | `network`, `ipc` |
| `gate1b.receipt.context-and-replay-deny` | `prepare`, `confirm`, `copy-context`, `replay`; required atomic refinements in isolated ADR | `.primary`, `.zero-mutation-dispatch`, `.protected-receipt-burn`, `.global-one-permit`, `.interrupted-abort-quarantine` | `network`, `ipc`, `ui` |
| `gate1b.authority.fail-closed-matrix` | `verify-matrix` | `.primary`, `.all-negatives-rejected` | `network`, `ipc`, `security_framework` |

The isolated ADR's required affected-variant selector table refines the race,
receipt, status/recover and fail-closed families without adding a family.
Receipt denial's zero-dispatch assertion applies to the denied attempt, not
the successful first apply in `success-restore-confirmed`. Success, normal
null-permit abort and interrupted abort are independently enrolled units.
Protected global receipt history survives restoration of caller-writable
journals; it permits repeated denied null-permit closes but at most one permit
per receipt. Capacity variants retain the last valid closed active sentinel
at 256 permits or closed records, including after expiry; ordinary cleanup
cannot delete it. All selector vectors are future validation requirements,
not evidence of implemented/native outcomes.

| Confirm smoke case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `smoke.confirm.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `smoke.confirm.prepare-confirm-success` | `prepare`, `confirm` | `.primary`, `.smoke-context` | `ipc`, `ui` |
| `smoke.confirm.apply-all-deny` | `apply-negatives` | `.primary`, `.zero-network-bytes` | `network`, `ipc` |
| `smoke.confirm.receipt-context-ineligible` | `consume`, `copy-context`, `replay` | `.primary`, `.terminal-state`, `.ordinary-context-denied` | `ipc` |
| `smoke.confirm.authority-negatives` | `verify-matrix`, `seal-evidence`, `verify-export` | `.primary`, `.all-negatives-rejected`, `.terminal-evidence-retained`, `.sanitized-export`, `.no-live-delete` | `ipc`, `security_framework` |

| Issue-create smoke case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `smoke.issue-create.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `smoke.issue-create.prepare-confirm-apply-dispatch-deny` | `prepare`, `confirm`, `apply` | `.primary`, `.dispatch-deny-code` | `network`, `ipc`, `ui` |
| `smoke.issue-create.zero-mutating-bytes` | `audit` | `.primary`, `.zero-mutation-bytes` | `network` |
| `smoke.issue-create.update-comment-other-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-mutation-dispatch` | `network`, `ipc` |
| `smoke.issue-create.receipt-context-ineligible` | `terminalize`, `copy-context`, `replay` | `.primary`, `.terminal-state`, `.ordinary-context-denied` | `network`, `ipc` |
| `smoke.issue-create.authority-negatives` | `verify-matrix`, `seal-evidence`, `verify-export` | `.primary`, `.all-negatives-rejected`, `.terminal-evidence-retained`, `.sanitized-export`, `.no-live-delete` | `ipc`, `security_framework` |

| Post-grant confirm case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `post-grant.confirm.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `post-grant.confirm.prepare-confirm-success` | `prepare`, `confirm` | `.primary`, `.final-production-context` | `ipc`, `ui` |
| `post-grant.confirm.apply-all-deny` | `apply-negatives` | `.primary`, `.zero-network-bytes` | `network`, `ipc` |
| `post-grant.confirm.receipt-terminal-replay-deny` | `consume`, `replay` | `.primary`, `.terminal-state`, `.replay-denied` | `ipc`, `security_framework` |
| `post-grant.confirm.authority-negatives` | `verify-matrix` | `.primary`, `.all-negatives-rejected` | `ipc`, `security_framework` |
| `post-grant.confirm.seal-evidence` | `seal-evidence`, `verify-export` | `.primary`, `.terminal-evidence-retained`, `.sanitized-export`, `.no-live-delete` | `ipc`, `security_framework` |

| Post-grant issue-create case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `post-grant.issue-create.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `post-grant.issue-create.prepare-confirm-apply-dispatch-deny` | `prepare`, `confirm`, `apply` | `.primary`, `.final-production-context`, `.dispatch-deny-code` | `network`, `ipc`, `ui` |
| `post-grant.issue-create.zero-mutating-bytes` | `audit` | `.primary`, `.zero-mutation-bytes` | `network` |
| `post-grant.issue-create.update-comment-other-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-mutation-dispatch` | `network`, `ipc` |
| `post-grant.issue-create.receipt-terminal-replay-deny` | `terminalize`, `replay` | `.primary`, `.terminal-state`, `.replay-denied` | `network`, `ipc`, `security_framework` |
| `post-grant.issue-create.authority-negatives` | `verify-matrix` | `.primary`, `.all-negatives-rejected` | `network`, `ipc`, `security_framework` |
| `post-grant.issue-create.seal-evidence` | `seal-evidence`, `verify-export` | `.primary`, `.terminal-evidence-retained`, `.sanitized-export`, `.no-live-delete` | `ipc`, `security_framework` |

Gate 1B setup is compiled per isolated unit under the
[new setup and unit authorization contract](gate1b-isolated-subruns.md#unit-authorization-and-context).
The legacy family label `gate1b.setup-exact-artifact-enrollment` cannot select
an old v1 setup context, reuse another unit's enrollment, or defer empty-host
inventory until after token issuance. Each exact CLI self-connects to the
helper-owned fixed ordinary listener; runner control authority never replaces
that peer authentication. Smoke and post-grant setup retain their existing
role, argv, stage-token, and context routing and reject Gate 1B contexts.

The following flat case/step and argv codecs apply unchanged to Gate 1A,
smoke, and post-grant only. Gate 1B uses shared payloads only where the isolated
ADR's typed adapter explicitly admits them; the old family tables and reset
labels cannot be compiled directly by this flat route.

For each step and transcript kind, the transcript ID is the case ID, one dot,
the step ID, one dot, and the kind. Every operation step's `assertion_ids` is
exactly `[]`; its `transcript_ids` equals `stdout`, `stderr`, then the additional
kinds in table order. The case-final evaluation's assertion IDs are the full
IDs derived from that row, and its two transcript IDs use step component
`final-evaluation` and kinds `stdout`, then `stderr`. A case with an empty
operation-step list, an empty case-final assertion list, a changed operation,
evaluation, assertion, or transcript order, or an ID not compiled from this
table is rejected before execution.

Each case object contains only `case_id`, `evidence_scope`, `steps`, and
`final_evaluation`, in that order. Steps are ordered operations and
contain these fields in order: `step_id`, `executable_role`,
`executable_component`, `argv`, `working_directory`, `environment`, `stdin`,
`timeout_seconds`, `fixture_ids`,
`assertion_ids`, and `transcript_ids`. `executable_role` is exactly `cli`,
`helper`, `fixture_cli`, `fixture_helper`, `negative_peer_fixture`,
`gate_runner`, or `release_verifier`; it resolves to the descriptor-, fixture-
manifest-, or Gate-plan-pinned executable and is never an argv value. The two
disjoint fixture roles are valid only in the five compiled
`disjoint_fixture` cases; `cli` and `helper` are valid only in
`exact_artifact` cases. `negative_peer_fixture` is valid only for
`launch-negative-outer` and `launch-negative-helper` in
`gate1a.artifact.runtime-peer-validation`; their corresponding reject steps
run the exact current peer or runner and must prove zero authority or registry
access. `executable_component` is exactly `outer`, `helper`, `fixture_cli`,
`fixture_helper`, `gate_runner`, or `release_verifier`; `cli` maps to `outer`
and every other ordinary role maps to its same-named component;
for `negative_peer_fixture` it selects exactly `outer` or `helper` and matches
the step name. `working_directory`
is always null, `environment` is always an empty array, and `stdin` is exactly
`closed`. `timeout_seconds` is an integer `1..300`. Fixture, assertion, and
transcript IDs are 1..128 printable ASCII bytes, explicitly declared in their
respective manifests, unique in their array, and never pathnames supplied by a
caller.

`final_evaluation` contains exactly the fields frozen by the command-contract
`case_evaluations` entry. The runner may create it only after every operation
has terminated and every declared stdout, stderr, and additional transcript
result has been retained by digest. Its canonical stdout is a bounded
case-evaluation aggregate with fields `schema_version` integer `1`, `case_id`,
`ordered_operation_observation_ids`, `ordered_transcript_results_sha256`,
`ordered_exit_codes`, `assertion_results_sha256`, and `result` exactly `pass`,
in that order; stderr is exactly zero bytes. The three ordered arrays match the
operation-step and per-step transcript order without sorting. Case assertions
evaluate only retained operation, transcript, and state inputs; they never
depend on the final aggregate bytes, its stdout digest, or the final observation
digest. The runner first evaluates those assertions, records their manifest,
then emits the aggregate containing that manifest digest and finally the
case-final observation. A crash, timeout, missing transcript, or failed
assertion produces no passing final observation and therefore no passing case
or evidence index.

`argv` has 1..64 entries and at most 16,384 decoded bytes. Every entry is one
closed typed object using one exact schema:

| Kind | Fields in exact order | Constraint |
| --- | --- | --- |
| literal | `source`, `value` | source exactly `literal`; printable ASCII value |
| path | `schema_version`, `token_type`, `source`, `fixture_id`, `content_sha256`, `expected_type`, `access` | the complete typed path-token codec defined above |
| prior output | `source`, `step_id`, `output_field` | source exactly `step_output`; earlier step; output exactly `plan_id` or `receipt_id` |

No other source or output field exists. Dynamic values are produced by the
same runner after schema validation, never interpolated into a shell string,
and substituted as one argv element. Execution uses direct process spawning
with the declared argv, closed stdin, empty environment, no shell, no current-
directory inheritance, and an independent hard timeout. The runner rejects an
undeclared file access, transcript, assertion, network origin, or subprocess.

### Gate 1B execution decision and remaining freeze

The [isolated-subrun ADR](gate1b-isolated-subruns.md) is the accepted docs-only
decision, superseding the former undefined-topology blocker. It preserves
same-UID adversarial helpers, quarantines unclosed leases, and does not infer
global singleton authority from launchd.

Every independently stateful phase or negative variant runs on a fresh actual
host and target allocation for its architecture and E1/E2 pass. Pre-token
host/target inventory precedes the separately root-signed child token, which
binds pass, architecture, unit, inventory, target, session, and complete Gate
1A E2 prerequisite. E2 additionally binds the complete E1 parent. No host or
actual target is reused by another unit, including across architectures or
passes. Each unit owns its setup, baseline, and final evaluator; the parent
uses typed unit bindings and local leaf IDs, never concatenated global IDs.

A reboot case has at most two segments. Its new token-authorized read-only
observer binds the retained checkpoint and same host/target; it cannot reset,
sign, CAS, delete, or access the network. External target retirement precedes
evidence export and whole-host disposal. These requirements are defined, not
implemented, by the new ADR.

Gate 1B command-contract digest freeze and token issuance remain forbidden
until the accepted compiler and materialized inventory, their validated
conformance vectors, and native candidate implementation exist. Those
prerequisites enable only explicitly authorized native runs; their actual
passing E1/E2 evidence is then required for evidence acceptance and issue-create
provisional authorization. This order does not require a run's evidence before
its own token. Simulation and this documentation do not pass Gate 1B.
Gate 1A remains independently NOT PASSED.

### Deterministic two-party coordinator schedules

This schedule/trace subsection is a coverage catalog routed through the
[isolated unit compiler](gate1b-isolated-subruns.md#coverage-inventory-and-unit-definition),
not an executable flat command contract. Each independent phase and negative
variant becomes its own unit; literal reset labels are not commands. No
schedule digest or token may be frozen before the new execution prerequisites
are satisfied.

Every Gate 1B coordinator case uses a digest-bound schedule fixture. Ordering
comes from release/arrival barriers, never sleeps, scheduler luck, shell
commands, environment values, or caller-selected events. The runner directly
spawns at most two CLI actors per phase; each self-connects to its selected
exact signed helper. Multi-helper phases deliberately run two valid helpers,
including an alternate same-UID bootstrap context. The fixture records each
helper's exact signed identity, PID, audit-token digest, bootstrap-context
identifier, and session. A job label or parent constraint must never collapse
these distinct actors into an assumed global singleton.

The proposed adversarial technique uses only the one fixed ordinary socket
pathname. First CLI A self-connects to helper A and retains that accepted
connection. While A is paused, the trusted external Gate supervisor captures
the exact socket entry's inode, type and path through preopened no-follow
parent descriptors, verifies it is the expected disposable-host socket, and
unlinks only that entry. A's existing accepted connection remains open. Exact
helper B is then launched in the alternate same-UID bootstrap context, binds
the same literal pathname, and CLI B self-connects to B. Both helpers are live,
but there is only one current pathname; no candidate receives another endpoint
or a runner-created connected descriptor. The deletion is a narrowly scoped
adversarial Gate-supervisor action, not a production/helper unlink capability.
Native evidence must show A's old connection survives, B's new connection
authenticates independently, and both exact code identities match. A
pathname/type/inode ambiguity or failure to realize this OS behavior fails
the technique; simulation cannot stand in for that evidence. This technique
is a required native vector under the isolated ADR's
[execution acceptance](gate1b-isolated-subruns.md#required-conformance-vectors).
The design decision does not claim this transport behavior already proven;
failure of that native vector blocks Gate 1B.

The trusted runner creates two anonymous unidirectional pipes per CLI actor
before direct spawn. Only the child's release-read end at descriptor 3 and
arrival-write end at descriptor 4 are inherited; all other unexpected
descriptors are closed. Barrier authority is available only through the
authenticated Gate 1B runner control session, never ordinary production,
Gate 1A, smoke, or post-grant authority. The pipes carry ordering only and are
not substitutes for ordinary helper peer authentication.

Each frame is exactly 16 bytes: bytes 0..7 are ASCII `YTABARR` plus NUL;
byte 8 is version `0x01`; byte 9 is release `0x01` or arrival `0x02`;
byte 10 is actor apply `0x01`, registry `0x02`, or cleanup/status `0x03`;
byte 11 is the event code below; bytes 12..15 are the unsigned big-endian
sequence starting at one. Unknown, short, extra, duplicate, out-of-order, or
unreleased arrivals fail. Each release must receive its matching arrival
within the step timeout before another release. A crash arrival means the
boundary was reached; the runner then kills only that scheduled actor and
requires its exact signal exit before a later probe. Killing one actor is not
evidence that another valid helper or owner has stopped.

| Code | Event | Required durable observation after arrival |
| ---: | --- | --- |
| `0x01` | `apply.acquire` | unique active add won; no permit or close |
| `0x02` | `coordinator.acquire-busy` | acquisition denied busy by existing live local owner or duplicate active add; zero subsequent authority reads/writes |
| `0x03` | `apply.in-flight` | durable in-flight journal; no permit |
| `0x04` | `apply.permit` | exact one permit |
| `0x05` | `apply.send` | at most one mutating request begins |
| `0x06` | `apply.outcome` | response/non-replay decision observed; terminal journal CAS has not run |
| `0x07` | `owner.quiesce` | first irrevocably drop all send/sign/permit/commit capability and queued callbacks, then atomically retain terminal outcome plus exact normal-close candidate; acknowledge only after both |
| `0x08` | `coordinator.close` | owner-only exact normal closed record durable after quiescence |
| `0x09` | `coordinator.capture-reference` | exact active attributes, bytes and bounded CFData persistent reference captured in one lookup; validated normal close links retained |
| `0x0a` | `coordinator.delete-reference` | one delete selects only that persistent reference; no attributes-only fallback |
| `0x0b` | `registry.acquire` | unique active add binds pre-read intent; no prior ledger read |
| `0x0c` | `registry.commit` | candidate matches leased intent; one revision winner or deterministic absence |
| `0x0d` | `apply.cancel-stale` | stale decision observed with zero permit/send; no terminal CAS until owner quiescence |
| `0x0e` | `enrollment.busy-before-ledger` | invalid initial enrollment loses before ledger validation |
| `0x0f` | `process.crash` | exact scheduled actor reaches boundary, then confirmed signal exit |
| `0x10` | `status.unclosed-quarantine` | unclosed active/journal byte-preserved; zero CAS/close/delete/keygen/sign/permit/send/commit |
| `0x11` | `coordinator.close-ambiguous-return` | one owner close add; read-only classify exact equal, absent, or conflict |
| `0x12` | `coordinator.delete-ambiguous-return` | one reference delete; read-only classify that reference, never replacement item |
| `0x13` | `stale.send-probe` | non-owner stale tuple denied before network |
| `0x14` | `helper.restart` | old Unix connection closes; replacement helper authenticates independently, without inferred fencing |
| `0x15` | `coordinator.stale-reference-noop` | captured old reference absent; replacement active unchanged |
| `0x16` | `remote.reconcile-read-only` | bounded remote report; no quarantined journal/coordinator writes and no replay |

The proposed catalog has exactly 22 event codes with no aliases. `A`, `R`, and `H` below
mean apply, registry, and cleanup/status actor. Each arrow is a release/arrival
pair. Reset labels identify a requirement for independently authorized clean
subruns, not permission to revert a host within an existing authenticated
session. Their execution and aggregation remain blocked as specified above.

| Case/phase | Exact released event sequence |
| --- | --- |
| `apply-first-atomic-contention` rotate/revoke/registry-recovery | `A:apply.acquire -> R:coordinator.acquire-busy -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close -> A:coordinator.capture-reference -> A:coordinator.delete-reference` |
| `apply-first-ordered-transition` rotate/revoke/registry-recovery | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close -> A:coordinator.capture-reference -> A:coordinator.delete-reference -> R:registry.acquire -> R:registry.commit -> R:owner.quiesce -> R:coordinator.close -> R:coordinator.capture-reference -> R:coordinator.delete-reference` |
| `registry-first-atomic-contention` rotate/revoke/registry-recovery | `R:registry.acquire -> A:coordinator.acquire-busy -> R:registry.commit -> R:owner.quiesce -> R:coordinator.close -> R:coordinator.capture-reference -> R:coordinator.delete-reference` |
| `registry-first-ordered-transition` rotate/revoke/registry-recovery | `R:registry.acquire -> R:registry.commit -> R:owner.quiesce -> R:coordinator.close -> R:coordinator.capture-reference -> R:coordinator.delete-reference -> A:apply.acquire -> A:apply.cancel-stale -> A:owner.quiesce -> A:coordinator.close -> A:coordinator.capture-reference -> A:coordinator.delete-reference` |
| invalid enrollment contention | `A:apply.acquire -> R:enrollment.busy-before-ledger -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close -> A:coordinator.capture-reference -> A:coordinator.delete-reference` |
| crash confirmed before in-flight | `A:apply.acquire -> A:process.crash -> H:status.unclosed-quarantine` |
| crash in-flight before permit | `A:apply.acquire -> A:apply.in-flight -> A:process.crash -> H:status.unclosed-quarantine` |
| crash after permit before send | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:process.crash -> H:status.unclosed-quarantine -> H:remote.reconcile-read-only` |
| crash after send before outcome | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:process.crash -> H:status.unclosed-quarantine -> H:remote.reconcile-read-only` |
| crash after outcome before close | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:process.crash -> H:status.unclosed-quarantine` |
| close ambiguity / equal | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close-ambiguous-return -> H:coordinator.capture-reference -> H:coordinator.delete-reference` |
| close ambiguity / absent | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close-ambiguous-return -> H:status.unclosed-quarantine` |
| close ambiguity / conflict | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close-ambiguous-return` |
| crash after durable close | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:owner.quiesce -> A:coordinator.close -> A:process.crash -> H:coordinator.capture-reference -> H:coordinator.delete-reference` |
| delete ambiguity / absent old reference | `H:coordinator.capture-reference -> H:coordinator.delete-ambiguous-return -> H:coordinator.stale-reference-noop` |
| delete ambiguity / same reference remains | `H:coordinator.capture-reference -> H:coordinator.delete-ambiguous-return` |
| delete ambiguity / replacement active | `H:coordinator.capture-reference -> H:coordinator.delete-ambiguous-return -> R:registry.acquire -> H:coordinator.stale-reference-noop` |
| delete ambiguity / malformed result | `H:coordinator.capture-reference -> H:coordinator.delete-ambiguous-return` |
| two-helper active replacement ABA | `H:coordinator.capture-reference -> R:coordinator.capture-reference -> R:coordinator.delete-reference -> R:registry.acquire -> H:coordinator.delete-reference -> H:coordinator.stale-reference-noop -> R:registry.commit -> R:owner.quiesce -> R:coordinator.close -> R:coordinator.capture-reference -> R:coordinator.delete-reference` |
| simultaneous helper before permit | `A:apply.acquire -> A:apply.in-flight -> H:status.unclosed-quarantine` |
| alternate-bootstrap helper after permit | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> H:status.unclosed-quarantine -> H:stale.send-probe` |
| simultaneous helper before close | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> H:status.unclosed-quarantine` |
| restart/expiry/UI cannot clear | `A:apply.acquire -> A:helper.restart -> H:status.unclosed-quarantine` |

The table has exactly 23 phase rows. The first four each expand to three named
registry transitions without changing event order. The last phase additionally
has historical state variants for confirmed owner death, reboot, TTL expiry,
profile expiry, and UI acceptance; each still requires identical no-write
quarantine. A real reboot is an external lifecycle action followed by a fresh
authenticated observation, not proof supplied by a PID or caller flag. A
staged historical fixture may test that parser/decision rule but cannot stand
in for required native multi-helper execution.

The ordinary apply-versus-registry and invalid-enrollment contention phases
use the same helper that retains the original uninterrupted owning connection;
their losing acquisition therefore returns `APPLY_COORDINATOR_BUSY`/exit 10.
That result terminates the losing actor; it has no later event or implicit
retry in that unit. Each ordered-transition variant is a separate fresh unit,
with the second actor starting only after the first owner's normal close and
matching active deletion; it has no preceding busy event.
An independent helper observing that same unclosed item instead returns
`AUTHORITY_STATE_QUARANTINED`/exit 1 without later authority work. The
`owner.quiesce` arrival covers a strict internal order: irreversible capability
drop, then terminal journal/normal-close-candidate CAS, then arrival. Merely
observing a response or deciding stale cancellation cannot acknowledge it.
If the actor crashes after this CAS but before the actual normal closed item
is durable, a non-owner still quarantines; retained close-candidate bytes are
not permission to synthesize a close.

A schedule fixture is canonical JSON capped at 32,768 bytes: `schema_version`
integer `1`, `schedule_type` exactly `gate1b_coordinator`, `case_id`,
`phase_id`, `actors`, `events`. Each actor contains `actor`,
`spawn_sequence`, `executable_role`, `executable_component`,
`code_slice_sha256`, `helper_slot` integer 1 or 2, and
`expected_termination` exactly `exit_zero`, `exit_nonzero`, or
`crash_signal`. Slots identify independently authenticated exact helper
sessions, not security rank. Each event contains `sequence`, `actor`,
`event_code`, and `expected_state_sha256`. `actors` is ordered by direct
spawn ordinal and `events` by exact schedule order.

The canonical `concurrency_trace` transcript contains `schema_version`,
`case_id`, `phase_id`, `schedule_fixture_sha256`, `runner_session_id`,
`actor_processes`, `helper_processes`, and `events`. Actor entries contain
`actor`, `spawn_sequence`, `pid`, `audit_token_sha256`,
`executable_sha256`, `ksec_code_info_unique`, `helper_slot`,
`termination_kind`, `exit_status`. Helper entries in slot order contain
`helper_slot`, `pid`, `audit_token_sha256`, `code_slice_sha256`,
`bootstrap_context_id`, `coordinator_session_id`; the bootstrap ID is a
bounded 1..128 printable-ASCII diagnostic label observed by the trusted
supervisor, never helper authority. Each event contains `sequence`,
`actor`, `event_code`, `release_monotonic_ns`, `arrival_monotonic_ns`,
`pre_state_sha256`, `post_state_sha256`, `mutating_request_count`,
`mutating_request_sha256`. PIDs/spawn ordinals are positive integers;
monotonic values are non-negative integers; exit statuses use 0..255, null
until a classified crash where the exact signal is separately in its fixture.
Process IDs are diagnostic and never fences.

Projection to `sequence`, `actor`, `event_code`,
`expected_state_sha256` (the post-state digest) must byte-match the schedule
events. Every pre-state equals the preceding post-state; mutating count never
exceeds one; no registry commit overlaps an active apply; non-owner unclosed
probes never write. Normal close requires prior irreversible owner quiescence.
The ABA phase specifically captures active A's CFData reference (1..4,096
bytes), lets the other helper delete A and acquire B, then invokes the stale
reference delete. B and its unique lock must survive unchanged, even if B's
attributes resemble A's. Absence of A is a successful stale no-op, never an
attributes-only delete of B. Unknown/conflicting results quarantine, and an
ambiguous deletion is never blindly repeated.

The positive issue-create workflow contains three distinct ordered steps:
`prepare`, `confirm`, then `apply`. `confirm` obtains `plan_id` only from the
validated prepare envelope; `apply` obtains that same `plan_id` and the
confirmed `receipt_id` only from validated earlier envelopes. Combining,
omitting, reordering, or replacing a step is a failure. Smoke uses the same
three-step workflow, but its apply step is expected to reach the unique
pre-write dispatch denial rather than a remote mutation.
Post-grant `issue_create` verification also uses those exact three ordinary
steps with real grant-bound authority, but the session token forces its own
pre-socket dispatch denial after read-only loopback preflight.

For every operation step the plan implies exactly one observation ID formed by
the case ID, one slash, and the step ID, followed by the mandatory case ID plus
`/final-evaluation` observation. Evidence observations must equal that complete
derived list byte-for-byte and in order—no missing, duplicate, reordered, early,
or additional entry. The observation scope must equal its case scope. Every
operation observation carries exact `assertion_ids=[]`; only the final
evaluation carries the case row's ordered assertion IDs. The recorded
`command_sha256` covers a compact canonical execution context containing that
scope, executable role and component, the resolved executable's exact canonical descriptor
slice, disjoint-fixture slice, or negative-peer slice digest, resolved argv
array, null working
directory, empty environment, closed stdin, timeout, fixture hashes, assertion
IDs, and transcript IDs. Recording merely a display string or a shell command
is invalid. For a final evaluation, `command_sha256` instead covers its
canonical evaluation context: case ID/scope, pinned runner identity, every
prior operation observation ID and result-manifest digest in order, and the
compiled final assertion/transcript IDs. It cannot be computed before the last
operation result exists.

## E1 Gate authorization

This legacy v1 token is Gate 1A-only and rejects `gate_id=gate1b`.
Gate 1B uses `gate1b_isolated_unit_token_v1` under the
[unit authorization contract](gate1b-isolated-subruns.md#unit-authorization-and-context),
not this token or domain.

E1 permits only the exact descriptor to execute one named Gate suite. Its
unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `gate_e1`
3. `gate_id`, exactly `gate1a`
4. `authority_key_id`
5. `descriptor_sha256`
6. `gate_plan_sha256`
7. `gate_target_sha256`, exactly null
8. `prerequisite_gate1a_e2_evidence_set_sha256`, exactly null
9. `architecture`, exactly one architecture declared by the descriptor
10. `gate_runner_unique`
11. `gate_session_id`
12. `allowed_capability`, exactly `confirm_only`
13. `allowed_network`, exactly `none`
14. `issued_at`
15. `expires_at`

`gate_runner_unique` is lowercase hex of the signed Gate runner's
Security.framework unique identifier. `gate_session_id` is unpadded base64url
of 32 random bytes. E1 validity is at most 30 minutes.

The candidate accepts E1 only over an inherited, already connected local Gate
session descriptor. It validates the runner's connection-bound audit token,
exact runner identifier, Developer ID requirement, unique identifier, and a
challenge response bound to the session ID. A token copied to another process
or session is unusable. E1 cannot be loaded from either production sidecar
path and is never shipped.

Under a Gate 1A E1 token, every `exact_artifact` case runs against the normal
CLI confirmation command and real signed helper/Keychain boundary; this
includes ordinary enroll, rotate, revoke, and recover. The five destructive
registry corruption, malformed-ledger, ambiguous-add, orphan-cleanup, and
active-key-loss cases instead run only the
manifest-pinned disjoint fixture pair in its disjoint Keychain service,
filesystem root, and IPC namespace; they never execute or modify production
registry state. The old-build negative peer may appear only in the exact
runtime mixed-build rejection substeps and must gain no authority. Network
creation is denied by the process sandbox. Gate 1B E1 allocation and issuance
follow the isolated ADR and require the complete Gate 1A E2 prerequisite.
A pass records the
descriptor, Gate ID, token, plan and target digests, fixture hashes and
executable manifest, per-observation scope and executable identity,
OS/architecture, times, and result in immutable evidence.

One distinct E1 token and fresh runner session is required for every declared
architecture. A token is invalid on a different architecture, and passing one
slice cannot stand in for another.

## E2 Gate authorization

This legacy v1 E2 codec is Gate 1A-only and rejects `gate_id=gate1b`.
Gate 1B E2 units use the distinct isolated token and must bind the complete
prior E1 parent, not one prior architecture index.

E2 exists only after a complete E1 pass for the same descriptor, Gate ID, plan,
target, and capability. It permits a clean-reset repetition of that complete
suite solely inside one new Gate runner session. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `gate_e2`
3. `gate_id`, exactly `gate1a`
4. `authority_key_id`
5. `descriptor_sha256`
6. `gate_plan_sha256`
7. `gate_target_sha256`, exactly null as in Gate 1A E1
8. `e1_evidence_sha256`
9. `prerequisite_gate1a_e2_evidence_set_sha256`, exactly matching E1
10. `architecture`, exactly matching its E1 evidence index
11. `gate_runner_unique`
12. `gate_session_id`
13. `allowed_capability`, exactly the matching E1 capability
14. `allowed_network`, exactly the matching E1 network policy
15. `issued_at`
16. `expires_at`

E2 has the same 30-minute maximum and runner/session checks as E1. The run
starts from another clean host or freshly reverted snapshot and repeats every
ordered observation in the same content-addressed Gate plan, including the
exact artifact/fixture scope partition and a fresh disjoint fixture namespace.
Gate 1A remains network-free. No E1 registry, coordinator, signing-key,
journal, or runner-session state is inherited by its E2 run. A partial,
cached, inherited, or smoke-only second pass is invalid. Gate 1B freshness and
target retirement use the distinct per-unit protocol, never this whole-suite
reset path.

Every declared architecture receives its own E2 token after that
architecture's E1 pass, with a new random session ID and a freshly reset host
or snapshot. E1 and E2 session IDs must differ across all Gate IDs,
architectures, and stages.

E1/E2 are capabilities of a signed runner session, not production feature
flags. A Gate 1B token can exist only after the same descriptor's Gate 1A E1
and E2 evidence validate. The ordinary provisional/grant path rejects all Gate
token types and domains. The release binary contains no environment switch
that converts a Gate token into production authority.

### Gate receipt authorization context and retained authority

Before provisional authorization exists, Gate 1A may exercise the ordinary
schema-3 confirmation path inside its exact authenticated E1 or E2 runner
session. This legacy context and its retained-authority branch reject
`gate_id=gate1b`. Gate 1B uses `gate1b_isolated_receipt_context_v1` and
`gate1b_isolated_authority_evidence_v1` from the isolated ADR. Gate 1A peers
derive one compact canonical object capped at 4,096 bytes with fields, in order:

1. `schema_version`, integer `1`
2. `context_type`, exactly `gate_receipt_context_v1`
3. `gate_token_type`, exactly `gate_e1` or `gate_e2`
4. `gate_token_sha256`, SHA-256 of the exact root-signed Gate token bytes
5. `gate_id`, exactly `gate1a`
6. `descriptor_sha256`
7. `gate_plan_sha256`
8. `gate_target_sha256`, exactly null
9. `prerequisite_gate1a_e2_evidence_set_sha256`, exactly null
10. `architecture`
11. `gate_runner_unique`
12. `gate_session_id`
13. `allowed_capability`, exactly `confirm_only`

Every value must exactly equal the descriptor, Gate plan, and signed Gate
token; no field is caller-selected or inferred across tokens. The token digest
is the sole token identifier. `gate_receipt_context_sha256` is plain SHA-256
over these exact canonical bytes, with no domain prefix. A Gate schema-3
receipt places this digest in its existing `authorization_context_sha256`
field. The distinct `context_type` makes this context ineligible for
production, activation smoke, and post-grant verification; those modes reject
it before profile, registry, journal, or network access. Conversely, a Gate
session rejects provisional, smoke, and final-production receipt contexts.

Confirmation atomically retains one closed canonical Gate branch in journal
v2 `authority_evidence`, capped at 1,572,864 bytes. Its fields are, in order,
`schema_version` integer `1`, `evidence_type` exactly
`gate_authority_evidence_v1`, `descriptor_bytes_base64url`,
`descriptor_sha256`, `gate_token_type`, `gate_token_bytes_base64url`,
`gate_token_sha256`, `gate_receipt_context_bytes_base64url`,
`gate_receipt_context_sha256`, `gate_id`, `gate_plan_sha256`,
`gate_target_sha256`, `prerequisite_gate1a_e2_evidence_set_sha256`,
`architecture`, `gate_runner_unique`, `gate_session_id`,
`allowed_capability`, `registry_chain_records_base64url`,
`registry_chain_sha256`, `registry_revision`, `key_generation`,
`verification_spki_der_b64u`, and `signing_key_fingerprint_sha256`.
The first three byte fields are unpadded base64url of the exact canonical
descriptor, exact root-signed Gate token, and exact unsigned Gate
receipt-context bytes. `registry_chain_records_base64url` is the ordered array
of unpadded-base64url exact canonical registry records for every revision from
1 through `registry_revision`, under the existing 256-record and 1,114,112-byte
decoded aggregate bounds. `registry_chain_sha256` is plain SHA-256 of the exact
compact canonical JSON bytes of that complete array. Every
digest is recomputed, every duplicate binding matches the receipt and active
registry generation, and all null rules are the context rules above. This
branch contains no provisional authorization, activation-smoke token,
production activation grant, smoke/final context, or production authority.

The retained exact bytes make the historical chain reconstructible:
verification re-encodes the descriptor and context, verifies the Gate token
under its exact E1/E2 signature domain and pinned root, recomputes every digest,
checks the token/context/session/capability tuple, then replays and verifies the
entire retained genesis-to-current registry chain under the registry protocol.
Only the active generation derived by that replay may select the verification
SPKI/fingerprint; a caller-supplied or lone terminal-record SPKI is never
accepted. The verifier then verifies the receipt signature and matches its
revision, generation, and `authorization_context_sha256`. Live confirmation, coordinator acquisition,
permit, and send require the Gate token to be currently unexpired and the same
Gate runner connection to remain authenticated. Historical validation instead
proves that the token was valid at the recorded live boundaries; later expiry
does not erase an already `in_flight` chain. It never renews authority or
permits another confirmation, permit, or send. Gate 1B historical bounded
read-only reconciliation and the network-free reboot observer use only the
isolated ADR's retained-authority and segment rules, never this legacy branch.

For a Gate apply, the receipt, coordinator active record, permit, and closed
record all bind this same context digest: the receipt and active/permit carry
`authorization_context_sha256` directly, while the closed record carries the
exact active and permit digests. Rebuilding either linked object proves the
same Gate token/context tuple. A missing link, changed context or token digest,
cross-Gate/cross-E1/E2/cross-session substitution, or a closed record whose
linked active/permit bytes do not reconstruct that tuple is invalid. Gate 1A
records the same closed journal authority branch for its confirmation cases;
its network policy remains `none` and the context adds no apply/send
capability.

### Gate 1B first exact-artifact enrollment

Gate 1B enrollment is defined solely by the isolated ADR's
[unit authorization and context](gate1b-isolated-subruns.md#unit-authorization-and-context).
Every expanded unit proves its own pre-token fresh actual host/target
inventory, then receives its bound child token, then performs the ordinary
exact-artifact enrollment and retains an immutable revision-1 baseline. The
old `gate1b_first_exact_artifact_enrollment` context and flat setup policy
are rejected, not accepted as aliases of the new protocol.

Setup permits only the initial enrollment ceremony, with its ordinary fresh
user-presence checks; it cannot sign receipts, rotate, revoke, recover, issue
permits, send, or delete. Runtime operations use that unit's separate receipt
context and retained authority. A later transition may change current registry
state but cannot replace baseline provenance. No mutable state crosses units
or passes. The only continuation is the ADR's bounded read-only reboot
observer, which is not a fresh setup or mutable recovery path.

There is no item-attributed stage cleanup or `stage_cleanup` IPC. The trusted
external supervisor retires the exact target before sanitized export and
whole-host disposal under the isolated ADR. Missing or ambiguous retirement,
export, or destruction blocks the parent; disposal cannot make failed evidence
pass.

## Gate evidence codec

Each Gate 1A run writes immutable content-addressed files and one compact
canonical evidence index. This v1 index and the flat evidence-set below reject
`gate_id=gate1b`. Gate 1B uses `gate1b_isolated_leaf_index_v1` and
`gate1b_isolated_parent_v1`; shared observation/result payloads enter only via
the [typed leaf adapter](gate1b-isolated-subruns.md#leaf-evidence-and-binding-adapter).
They do not make this container valid for Gate 1B.
The Gate 1A index is capped at 1,048,576 bytes (1 MiB). Its fields are:

1. `schema_version`, integer `1`
2. `evidence_type`, exactly `gate_e1_pass` or `gate_e2_pass`
3. `gate_id`, exactly `gate1a`
4. `descriptor_sha256`
5. `gate_token_sha256`
6. `gate_plan_sha256`
7. `gate_target_sha256`, exactly null
8. `allowed_capability`, matching the Gate token
9. `prior_e1_evidence_sha256`, null for E1 and required for E2
10. `prerequisite_gate1a_e2_evidence_set_sha256`, exactly null
11. `gate_runner_unique`
12. `gate_session_id`
13. `macos_product_build_version`, printable ASCII, at most 32 bytes
14. `architecture`, `arm64` or `x86_64`
15. `fixture_set_sha256`
16. `fixture_executable_manifest_sha256`, the Gate 1A plan value
17. `setup_context_sha256`, exactly null
18. `pre_enrollment_inventory_sha256`, exactly null
19. `registry_snapshot_sha256`, exactly null
20. `evidence_scopes`, exactly the ordered unique case scopes in the plan
21. `started_at`
22. `finished_at`
23. `result`, exactly `pass`
24. `observations`, an ordered JSON array

Observation order is the order frozen by the Gate plan. Each entry contains
`observation_id`, `evidence_scope`, `executable_role`, `executable_component`,
`executable_identity_sha256`, `command_sha256`, `stdout_sha256`,
`stderr_sha256`, `exit_code`, `registry_snapshot_sha256`, `assertion_ids`,
`assertion_results_sha256`, and `transcript_results_sha256`, in that order.
`registry_snapshot_sha256` is null for every Gate 1A observation and for
activation-smoke/post-grant setup operations before snapshot creation. It
equals the exact retained post-enrollment snapshot for each release-stage
setup `snapshot` operation, its final evaluation, and every later observation
in that release-stage run. Gate 1B baseline/current-state projection is governed
by the isolated leaf adapter, not a new branch in this v1 index. Scope and role exactly match the compiled case,
step, or case-final evaluation.
`executable_identity_sha256` hashes the complete exact
descriptor code-slice entry (`cli` maps to `outer`, `helper` to `helper`),
fixture-executable slice for `fixture_cli`/`fixture_helper`, negative-peer slice
selected by `executable_component` for `negative_peer_fixture`, or the separately pinned runner or verifier
identity object for a supervisor. A negative-peer identity can occur only in
its compiled rejection observation and never satisfies an exact-artifact
positive identity assertion.
Observation IDs follow the exact case/step grammar and membership rule above;
printable ASCII alone is not sufficient. Digests use the common grammar; exit
codes are JSON integers `0..255`. Secret-bearing output is a Gate
failure and is never made acceptable merely by hashing it.

An assertion-result manifest is compact canonical JSON capped at 32,768 bytes
with fields `schema_version` integer `1`, `manifest_type` exactly
`assertion_results`, `observation_id`, and `entries`, in that order. Each entry
has `assertion_id`, `evaluator`, `expected_sha256`, `actual_sha256`, and
`result` exactly `pass`, in that order. For an operation observation, `entries`
and the observation's `assertion_ids` are both exact empty arrays. For a
case-final evaluation they exactly equal the row's compiled assertion order
and the evaluator/expected digest in the assertion-set manifest. No operation
may claim an assertion pass before the case-final aggregate exists.

A transcript-result manifest has the same cap and fields `schema_version`,
`manifest_type` exactly `transcript_results`, `observation_id`, and `entries`.
Each entry has `transcript_id`, `transcript_kind`, `content_sha256`,
`byte_count`, `redaction_result` exactly `no_secret_detected`, and `result`
exactly `captured`, in that order. Entries exactly equal the compiled
`transcript_ids` order and kind; byte count is within the transcript-set cap and
the retained content file matches its digest.

The final evaluator's stdout is the exact case-evaluation aggregate defined
above. Its assertion-result manifest is created only after every ordered
operation transcript-result manifest has been loaded and matched to the
aggregate; its own transcript-result manifest then captures the final stdout
and empty stderr. This makes assertion suffixes case-final, not aliases for an
arbitrarily early operation result.

The two observation fields hash the exact respective result-manifest bytes.
The runner and offline verifier both require one-to-one equality: every
required ID occurs once, no unrequired ID occurs, all expected and actual
objects are retained by digest, and every result has the required success
literal. The observation's direct stdout/stderr digests must equal the content
digests of its exact stdout/stderr transcript entries. An aggregate success
bit, unordered map, missing result manifest, or
digest referring to a different observation is invalid. In particular, a
nonempty operation `assertion_ids`, an assertion result on a non-final
observation, an evaluation emitted before the final operation transcript, or a
missing/reordered final evaluation invalidates the run; there is no pass bit
that can substitute for it.

Gate 1A observations include every approval-protocol, code-identity, Keychain,
UI-presence, fail-closed, restart, and clean-host test. Gate 1B's independent
unit setup, workflow, and final-evaluation observations are assembled only by
the new leaf/parent protocol. Gate 1A E2 contains the complete repeated
observation set for Gate 1A. Missing,
duplicated, reordered, or additional observations are a failure against the
content-addressed Gate plan.

An evidence digest is lowercase SHA-256 over the exact canonical index bytes.
Every referenced transcript/assertion/file is separately published by its
digest; before signing E2, provisional authorization, or activation grant, the
offline ceremony verifies the entire closed set and recomputes the index. A
detached index with a missing or mismatched referenced file is invalid even if
its own digest is correct.

Passing indexes are collected into one canonical evidence-set manifest,
capped at 16,384 bytes. Its fields are `schema_version` integer `1`,
`evidence_set_type` exactly `gate_e1`, `gate_e2`, or `activation_smoke`,
`gate_id` exactly `gate1a` or `activation_smoke`,
`descriptor_sha256`, `gate_plan_sha256`, `gate_target_sha256`,
`provisional_context_sha256`, `fixture_executable_manifest_sha256`,
`evidence_scopes`, `architectures`, `indexes`, `registry_snapshots`, and
`result` exactly `pass`, in that order. Gate sets use null provisional context,
smoke uses null Gate target, and `registry_snapshots` is null only for Gate 1A.
The fixture-executable digest is required only for Gate 1A. Gate 1A
scope order is exactly `exact_artifact`, then `disjoint_fixture`; smoke
contains only `exact_artifact`. `architectures` exactly equals the
descriptor array.
For Gate 1A sets, `indexes` has one entry per architecture in that same order,
with fields `architecture`, `evidence_index_sha256`, `gate_token_sha256`,
`gate_session_id`, `export_manifest_sha256`, and `host_disposal_attestation_sha256`
in order. For activation smoke, each entry uses the same six-field prefix and appends
`setup_context_sha256`, `pre_enrollment_inventory_sha256`,
`registry_snapshot_sha256`, and `terminal_journal_evidence_sha256`,
in that order. Disposal and export digests name the external objects defined
below and are never fields of the earlier evidence index.
The non-null
`registry_snapshots` array for activation smoke has one entry per
descriptor architecture, in that order, with fields `architecture` and
`registry_snapshot_sha256`; it must exactly project the matching index entries.
Gate 1B has no one-index-per-architecture tuple in this codec. Its parent
requires the complete typed inventory of units for every architecture/pass,
including each unit's retained allocation, setup, segment, retirement, export,
and disposal evidence under the isolated ADR.
For activation smoke, every
tuple must match its canonical index, root-signed token, and retained
setup/export/disposal evidence. All token and session IDs are unique across all sets.

An evidence-set digest is SHA-256 over the exact manifest bytes. A Gate stage
passes only as the complete set; no per-architecture index, subset, combined
session, or architecture copied from another descriptor may satisfy a later
token or authorization.

## Provisional production authorization and pre-grant context

Only after complete E1 and E2 evidence sets exist for every declared
architecture may the offline root sign a provisional production
authorization. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `authorization_type`, exactly `provisional_first_release_production`
3. `authority_key_id`
4. `descriptor_sha256`
5. `gate1a_e1_evidence_set_sha256`
6. `gate1a_e2_evidence_set_sha256`
7. `gate1a_plan_sha256`
8. `gate1a_evidence_scopes`, exactly `exact_artifact`, then
   `disjoint_fixture`
9. `gate1b_e1_evidence_set_sha256`, null for a confirmation-only artifact
10. `gate1b_e2_evidence_set_sha256`, null for a confirmation-only artifact
11. `gate1b_plan_sha256`, null for a confirmation-only artifact
12. `gate1b_evidence_scopes`, null for a confirmation-only artifact or the
    one-element array `exact_artifact`
13. `app_payload_archive_sha256`, exactly the descriptor value
14. `approved_capability`, exactly `confirm_only` or `issue_create`
15. `minimum_registry_schema`, integer `1`
16. `minimum_receipt_schema`, integer `3`
17. `issued_at`
18. `smoke_not_before`

This object is deliberately non-activating. Ordinary `mutation confirm` and
every `mutation apply` fail with `PRODUCTION_ACTIVATION_REQUIRED` when only the
provisional authorization is present. It is accepted solely as an input to a
valid activation-smoke token in a matching Gate runner session. No timestamp,
command flag, environment value, or network state promotes it.
`smoke_not_before` is not before `issued_at`; a smoke token issued earlier is
invalid.

A `confirm_only` provisional authorization requires all Gate 1B fields to be
null. An `issue_create` authorization requires all four Gate 1B fields and
complete `gate1b_isolated_parent_v1` E1/E2 objects: the two evidence-set fields
select their respective exact parent digests, `gate1b_plan_sha256` selects their
identical coverage-inventory digest (not a legacy flat-plan digest), and
`gate1b_evidence_scopes` is exactly `["exact_artifact"]`, as required by the isolated ADR's
[parent verifier](gate1b-isolated-subruns.md#parent-aggregation-and-freshness).
The existing four Gate 1B authorization fields select that new route only;
legacy flat Gate 1B sets or indexes are rejected. E2 binds the complete E1
parent, and every unit binds the complete Gate 1A E2 prerequisite.
Gate 1A's two scope values and Gate 1B's exact-artifact
scope are mandatory and must equal their plans, indexes, and final evidence
sets. The disjoint registry fixture therefore contributes required
corruption, fork/gap/duplicate, ambiguous-add, orphan-cleanup, and active-key-
loss evidence without ever being represented as execution of the production
artifact. Ordinary enroll/rotate/revoke/recover evidence remains exact-
artifact execution. Other operations are never implied.

The provisional context is a compact canonical unsigned object capped at
8,192 bytes. Its fields are `schema_version` integer `1`, `context_type`
exactly `provisional_first_release`, `authority_key_id`, `descriptor_sha256`,
`provisional_authorization_sha256`, `gate1a_e1_evidence_set_sha256`,
`gate1a_e2_evidence_set_sha256`, `gate1a_plan_sha256`,
`gate1a_evidence_scopes`,
`gate1b_e1_evidence_set_sha256`, `gate1b_e2_evidence_set_sha256`,
`gate1b_plan_sha256`, `gate1b_evidence_scopes`,
`app_payload_archive_sha256`, `approved_capability`,
`minimum_registry_schema`, and `minimum_receipt_schema`, in that order. Its
digest is SHA-256 over the exact canonical bytes, with no domain prefix. Every
value must exactly equal the provisional authorization and descriptor. There
are no nullable values beyond the capability-specific four-field Gate 1B
group.
`provisional_context_sha256` names this digest. It is a smoke input only and is
not the context accepted by ordinary peers or production receipts.

### Stage-only first exact-artifact enrollment

Every activation-smoke and post-grant capability plan begins with its compiled
`setup-exact-artifact-enrollment` case on a newly created disposable macOS VM
or physical host. The stage token contains `setup_authorization` exactly
`first_exact_artifact_enrollment_only`. After validating that token, the exact
runner and artifact derive a compact canonical setup context capped at 4,096
bytes with fields, in order, `schema_version` integer `1`, `context_type`
exactly `stage_first_exact_artifact_enrollment`, `stage_type` exactly
`activation_smoke` or `post_grant_verification`, `descriptor_sha256`,
`stage_token_sha256`, `architecture`, `approved_capability`,
`gate_runner_unique`, `gate_session_id`, and `setup_authorization` exactly
`first_exact_artifact_enrollment_only`. `setup_context_sha256` is SHA-256 of
those exact bytes. This context is accepted only for the first case's one
revision-1 enrollment ceremony. It cannot authorize rotation, recovery,
revocation, another enrollment, plan preparation, receipt signing,
confirmation, apply, coordinator permit, or network access. The ordinary smoke
receipt context or final production context, not this setup context, controls
all later workflow authority.

The setup context is not a signing credential or standalone endpoint. The
ordinary enrollment ceremony still uses its newly generated exact signing key
and fresh user presence. No second cleanup context exists in this release.

Before any registry, coordinator, signing-key, journal, plan, receipt, socket,
or loopback state is created, the first case emits a compact canonical
pre-enrollment inventory capped at 8,192 bytes. Its fields are, in order,
`schema_version` integer `1`, `evidence_type` exactly
`stage_pre_enrollment_empty_inventory`, `stage_type`, `descriptor_sha256`,
`architecture`, `gate_runner_unique`, `gate_session_id`, `registry_service`,
`registry_accounts`, `coordinator_service`, `coordinator_accounts`,
`signing_key_tag_prefix`, `signing_key_tags`, `journal_root_inventory_sha256`,
`runner_session_state_sha256`, `observed_at`, and `result` exactly `empty`.
The two services and tag prefix are the fixed production values from the
registry protocol. All three account/tag arrays are exact empty arrays.
`journal_root_inventory_sha256` hashes a compact canonical empty regular-file
inventory, and `runner_session_state_sha256` hashes a compact canonical object
whose `plans`, `receipts`, `sockets`, `loopback_accounts`, and
`temporary_sidecars` arrays, in that order, are all empty. The already
authenticated immutable stage token and its setup context are held outside
this mutable disposable inventory. Bounded exact Keychain enumeration, an
already opened no-follow journal-root descriptor, and runner-owned state
enumeration must all independently prove emptiness; not-found is accepted only
where the exact Security.framework contract declares it.

The single setup enrollment must commit revision integer `1` and generation
string `YTAG-00000000000000000001` and durably
close and remove its coordinator active record before its `snapshot` operation
emits a compact canonical post-enrollment registry snapshot capped at 16,384
bytes. Its fields are, in order, `schema_version` integer `1`, `evidence_type`
exactly `stage_post_enrollment_registry_snapshot`, `stage_type`,
`descriptor_sha256`, `stage_token_sha256`, `setup_context_sha256`,
`pre_enrollment_inventory_sha256`, `architecture`, `gate_runner_unique`,
`gate_session_id`, `registry_service`, `registry_revision` integer `1`,
`registry_record_sha256`, `generation` string `YTAG-00000000000000000001`, `signing_key_tag`,
`signing_key_spki_der_b64u`, `signing_key_fingerprint_sha256`,
`setup_transcript_manifest_sha256`, `generated_key_tags`,
`coordinator_closed_sha256`, and `created_at`. `generated_key_tags` is the
helper-owned creation-order array and contains exactly the snapshot tag at this
boundary. The revision record, generation,
SPKI, fingerprint, descriptor, architecture, runner unique, and session must
equal the enrolled exact artifact and token. `registry_snapshot_sha256` is
SHA-256 of these exact bytes. The snapshot operation, setup final evaluation,
every later observation, the per-architecture evidence index, and its
evidence-set entry all carry this same digest; no later enumeration may silently
substitute current registry state for it.

`setup_transcript_manifest_sha256` selects exactly the existing
`transcript_results` codec, capped at 32,768 bytes, for the first setup case's
`enroll` operation. The applicable setup case is exactly one of
`smoke.confirm.setup-exact-artifact-enrollment`,
`smoke.issue-create.setup-exact-artifact-enrollment`,
`post-grant.confirm.setup-exact-artifact-enrollment`, or
`post-grant.issue-create.setup-exact-artifact-enrollment`, selected by the
validated token's stage and capability and the fixed command contract. Its
`observation_id` is exactly that case ID plus `/enroll`. Its five entries are,
in order, `stdout`, `stderr`, `ipc`, `ui`, and `security_framework`, with
`transcript_id` exactly the case ID plus `.enroll.` plus the corresponding
kind, and all other fields following the existing transcript-result codec.
The selector is plain SHA-256 over these complete canonical manifest bytes.
Every entry's complete content and the manifest itself must be durably
retained outside disposable state before the snapshot is emitted. A
pre-enrollment-inventory, snapshot, final-evaluation, transcript-set, or
whole-run manifest cannot satisfy this selector, even if correctly hashed.

The selected `ipc` transcript content is one closed canonical object capped at
4,096 bytes. Its fields are, in order:

1. `schema_version`, integer `1`
2. `evidence_type`, exactly `stage_setup_enrollment`
3. `stage_type`, exactly `activation_smoke` or
   `post_grant_verification`
4. `stage_token_sha256`
5. `setup_context_sha256`
6. `artifact_descriptor_sha256`
7. `architecture`
8. `approved_capability`, the token's `confirm_only` or `issue_create`
9. `gate_runner_unique`
10. `gate_session_id`
11. `registry_revision`, integer `1`
12. `registry_record_sha256`
13. `generation`, string `YTAG-00000000000000000001`
14. `signing_key_tag`
15. `signing_key_spki_der_b64u`
16. `signing_key_fingerprint_sha256`
17. `generated_key_tags`, exactly the one-element array `[signing_key_tag]`
18. `coordinator_closed_sha256`
19. `result`, exactly `committed`

The exact authenticated helper emits these bytes on the existing enrollment
operation after the registry commit and durable enrollment coordinator close;
the runner retains them as that operation's `ipc` transcript. This creates no
new IPC endpoint. Token/context fields must equal the independently validated
root-signed token and its setup context. Enrollment fields must equal the
valid revision-1 record and its enrollment closed record, including the exact
key identity. The helper can deterministically reconstruct these bytes from
that token/context and the supplied snapshot's enrollment-field projection,
checked against those valid registry/closed records. It compares both the
reconstructed content SHA-256 and byte count to the selected `ipc` entry.
Reconstruction requires no later-stage authority field. The reconstructed
object contains no timestamp, snapshot digest, `setup_transcript_manifest_sha256`,
or other manifest digest. The dependency order is strictly enrollment commit and closed
record, then enrollment IPC content, then the complete durable five-entry
enroll transcript-result manifest, then snapshot, then setup final evaluation.
No object may depend on its own digest or on a later object in this sequence.

As standalone flat-stage inputs these legacy setup payloads apply only to
activation smoke and post-grant verification and reject `stage_type=gate1b`.
Only inside the isolated ADR's typed leaf adapter may their Gate 1B payload
projection use `stage_type=gate1b` and the new unit setup/enrollment/baseline
bindings. This is an explicit enclosing-type route, not a globally accepted
new stage value or acceptance of any old Gate 1B setup context. Their
pre-inventory, context, snapshot, selected enrollment transcript/result
manifest, and failure evidence are retained as immutable content-addressed
files outside the disposable host before proceeding. They never authorize
cleanup, recovery, or a later registry ceremony.

### External whole-host disposal and successor-signature gate

The following flat-stage export/disposal codecs apply to Gate 1A, smoke, and
post-grant only and reject `stage_type=gate1b`. Gate 1B uses the isolated ADR's
per-unit target retirement, export, and host-disposal closure. In particular,
the exact target must be externally retired before export/disposal; an old
single-run host-disposal attestation cannot satisfy a Gate 1B parent.

The first release contains no `stage_cleanup` IPC, per-item stage delete,
cleanup intent/progress/ACK ledger, restart cleanup session, or signed
empty-final-inventory claim. A host-local runner cannot prove disposal of its
own execution environment. The trusted external release supervisor controls a
fresh disposable host for each stage/architecture, exports only the bounded
sanitized evidence closure, stops all test execution, and destroys the entire
host and all writable disks/snapshots belonging to that run. A reused macOS
user or an in-place empty-directory/Keychain probe is not whole-host disposal.
The provisioning inventory must bind the unique host instance and all of its
writable disks/snapshots before the stage starts. Destruction removes the
whole enrolled-key and mutable journal/session environment, not selected
objects, and never invokes candidate cleanup tools.

Each passing run first completes all operation observations and final
evaluations. The final `seal-evidence` and `verify-export` operations are
bounded read-only archive checks, not mutations or disposal commands. Their
compiled `release_verifier` route checks the sanitized retained content by
already opened digest-bound handles; it exports neither signing-key values,
credentials, raw mutable journals/plans/receipts, connected sockets, nor live
test-authority/session tokens. Necessary public receipt/registry projections
and terminal state hashes use the existing explicit evidence codecs. Private
retained authority bytes needed by historical Gate verification remain in the
access-controlled release incident/evidence store and are never installed.

After the immutable index exists, the external verifier emits a canonical
export manifest capped at 2,097,152 bytes with fields in order:
`schema_version` integer `1`, `manifest_type` exactly
`stage_sanitized_evidence_export`, `stage_type` exactly `gate1a`,
`activation_smoke`, or `post_grant_verification`,
`descriptor_sha256`, `stage_token_sha256`, `architecture`,
`gate_runner_unique`, `gate_session_id`, `evidence_index_sha256`,
`files`, `exported_at`, and `result` exactly `verified`.
`files` uses the install-manifest path/size/digest grammar below and is the
complete sorted sanitized closure, including the index but excluding this
manifest and every later attestation/set object. It has 1..4,096 entries,
8 MiB per file and 256 MiB aggregate, checked before allocation/read. Each
entry is exactly `path`, `size`, `sha256`. Missing, extra, linked,
case-colliding, secret-bearing, or mutable-state files fail export. This cap
is a flat-stage export bound and is distinct from the smaller post-grant
installed-tree cap. Gate 1B leaf and aggregate caps follow its isolated ADR.
Export manifests are historical evidence, not authority
loaded by the candidate.

Only after export verification and independently observed complete disposal
does the offline root sign a host-disposal attestation under
`YTA-HOST-DISPOSAL-V1\0`. Its unsigned fields, in exact order, are:

1. `schema_version`, integer `1`
2. `attestation_type`, exactly `external_whole_host_disposal`
3. `authority_key_id`
4. `descriptor_sha256`
5. `stage_type`, matching the export manifest
6. `stage_token_sha256`, the digest only, never embedded session-token bytes
7. `architecture`
8. `gate_runner_unique`
9. `gate_session_id`
10. `evidence_index_sha256`
11. `export_manifest_sha256`
12. `disposable_host_id`, canonical unpadded base64url of 32 random bytes,
    assigned and recorded by the trusted external supervisor before host creation
13. `host_inventory_sha256`
14. `destruction_evidence_sha256`
15. `exported_at`
16. `destroyed_at`
17. `attested_at`
18. `result`, exactly `destroyed`

The signature is the final field and the entire signed object is capped at
4,096 bytes. The inventory and destruction evidence are bounded canonical
supervisor objects, each capped at 16,384 bytes. Inventory fields are
`schema_version` integer `1`, `evidence_type` exactly
`disposable_host_inventory`, `disposable_host_id`, `stage_token_sha256`,
`host_instance_id`, `writable_resource_ids`, and `created_at`.
The host/resource IDs are supervisor-observed 1..128 printable-ASCII strings;
the resource array is byte-sorted, unique, and contains 1..64 identifiers for
every writable disk and snapshot under this run's lifecycle control.
Destruction fields are `schema_version` integer `1`, `evidence_type`
exactly `disposable_host_destroyed`, `disposable_host_id`,
`host_inventory_sha256`, `export_manifest_sha256`,
`host_instance_absent` exactly true, `destroyed_resource_ids` exactly
the inventory array, `verified_at`, and `result` exactly `destroyed`.
The supervisor verifies absence through its trusted host-lifecycle control
plane; candidate success output, an empty local inventory, PID death, or a
disconnected socket cannot satisfy this evidence. OS/supervisor compromise
remains the explicitly trusted release-environment boundary, not a
cryptographic claim supplied by these JSON objects.

The offline ceremony rechecks the complete evidence/export closure,
independently reviews the inventory/destruction record and operator observation,
then signs. Times require `finished_at <= exported_at <= destroyed_at <=
attested_at`; equality is permitted at whole-second resolution, but actual
ceremony sequencing is mandatory. The next E2/provisional signature, smoke
activation-grant signature, or post-grant publication-envelope signature must
occur after that ceremony and not earlier than `attested_at`.
Each complete evidence-set tuple references its index, export manifest, and
attestation digests; none of those earlier objects references the later set.
The attestation is never a candidate runtime capability and grants no signing,
deletion, recovery, or write permission. A missing, invalid, cross-stage,
cross-host, cross-session, or uncertain disposal blocks the successor
signature. Every host is never reused. Failed runs remain invalid; failed
destruction quarantines the host and all successor artifacts until a
separately reviewed operator lifecycle resolution, never an automatic retry
of a candidate mutation.

## Mandatory activation smoke

For each declared architecture, the offline root signs a distinct smoke token
with a fresh runner session. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `activation_smoke`
3. `authority_key_id`
4. `descriptor_sha256`
5. `provisional_authorization_sha256`
6. `provisional_context_sha256`
7. `gate_plan_sha256`
8. `architecture`
9. `approved_capability`, exactly matching the provisional authorization
10. `gate_runner_unique`
11. `gate_session_id`
12. `setup_authorization`, exactly
    `first_exact_artifact_enrollment_only`
13. `host_disposal_policy`, exactly `external_whole_host_disposal_v1`
14. `loopback_origin`, null for `confirm_only` or `http://127.0.0.1:` followed
    by one canonical decimal port in `1..65535` for `issue_create`
15. `dispatch_deny_code`, null for `confirm_only` or exactly
    `GATE_PRODUCTION_MUTATION_DISPATCH_DENIED` for `issue_create`
16. `issued_at`
17. `expires_at`, no more than 30 minutes after issue

The smoke plan's descriptor, capability, architecture set, and provisional
context must match the token and provisional authorization; the plan must begin
with the capability-specific setup case and carry
`stage_setup_policy=first_exact_artifact_enrollment_v1` and
`host_disposal_policy=external_whole_host_disposal_v1`. Smoke tokens and
sessions are unique across architectures and every E1/E2 session. The token
uses its setup field only through the separately derived setup context.
The disposal field imposes an external successor-signature condition, never a
candidate operation. Outside the first setup case it only restricts provisional
authority inside its authenticated runner session.
It cannot activate ordinary use and is never shipped.

Both smoke workflows first run their exact-artifact setup case, retain the
proved-empty pre-inventory and revision-1 registry snapshot, and bind that
snapshot into every later observation. For `confirm_only`, the hard-coded
smoke workflow then prepares and confirms through the ordinary commands on a
clean network-disabled host and proves all apply operations remain disabled.
For `issue_create`, it then uses the hard-coded `prepare -> confirm -> apply`
issue-create workflow. Only the exact
instrumented loopback read-only fixture is reachable. The harness verifies the
ordered preflight reads, then requires the ordinary executor to reach
`GATE_PRODUCTION_MUTATION_DISPATCH_DENIED` at the final transport boundary
before opening or writing a mutating request. No mutating request-line, header,
or body byte may reach a socket. An earlier parse, authority, journal,
capability, or preflight failure cannot satisfy this case.

The smoke token derives a disposable canonical receipt-context object capped
at 4,096 bytes. Its fields are `schema_version` integer `1`, `context_type`
exactly `activation_smoke`, `descriptor_sha256`,
`provisional_authorization_sha256`, `provisional_context_sha256`,
`smoke_token_sha256`, `architecture`, `approved_capability`, and
`gate_session_id`, in that order. Its digest is SHA-256 over those exact bytes.
Every smoke-created plan and schema-v3 receipt carries that value, never the
different `first_release_production` context digest. Smoke uses a runner-created
mode-0700 profile/journal root, a loopback-only account, and no production credential.
The journal atomically stores a stage-tagged historical authority set with the
receipt: `stage_type` exactly `activation_smoke`, the exact descriptor, signed
provisional authorization, signed smoke token, canonical provisional context,
canonical smoke receipt context, and every digest. It contains no activation
grant. For `confirm_only`, the compiled `consume` step moves `confirmed` to the
runner-only terminal state `activation_smoke_consumed` after all apply denials.
For `issue_create`, ordinary apply first persists `in_flight`; after the exact
pre-socket dispatch denial and zero-mutation evidence, `terminalize` moves it
to `activation_smoke_consumed`. That state cannot be reconciled, applied,
confirmed, or returned to an earlier state; replay must return
`RECEIPT_ALREADY_CONSUMED` without UI, preflight, or network access. After
evidence capture the external supervisor destroys the whole disposable host.
Copied, retained, or disposal-failed smoke receipts remain
context-ineligible under the later activation grant and cannot be reconciled
or applied in an ordinary profile.

The terminal transition emits a compact canonical evidence object capped at
8,192 bytes with fields `schema_version` integer `1`, `evidence_type` exactly
`activation_smoke_terminal_journal`, `descriptor_sha256`,
`provisional_authorization_sha256`, `smoke_token_sha256`,
`smoke_receipt_context_sha256`, `architecture`, `gate_session_id`, `plan_id`,
`registry_snapshot_sha256`, `receipt_id`, `receipt_sha256`, `prior_state`, `terminal_state` exactly
`activation_smoke_consumed`, `journal_revision`, and `transitioned_at`, in
that order. `prior_state` is `confirmed` for `confirm_only` and `in_flight` for
`issue_create`. The evidence and replay-denial observation are mandatory; a
smoke `in_flight` record is never eligible for ordinary reconciliation.

The last smoke case verifies the retained terminal/non-replay evidence and
sanitized export inputs. No operation follows except the case-final
evaluation. The immutable index is finalized before the external export
manifest and host-disposal attestation; the complete smoke evidence set binds
all three. No helper deletion or signed empty-inventory proof is produced.

Each architecture produces a canonical smoke evidence index capped at
1,048,576 bytes (1 MiB) with these fields in order: `schema_version` integer
`1`, `evidence_type`
exactly `activation_smoke_pass`, `gate_id` exactly `activation_smoke`,
`descriptor_sha256`, `gate_token_sha256`, `gate_plan_sha256`,
`gate_target_sha256` null, `allowed_capability`,
`prior_e1_evidence_sha256` null,
`prerequisite_gate1a_e2_evidence_set_sha256` null,
`gate_runner_unique`, `gate_session_id`, `macos_product_build_version`,
`architecture`, `fixture_set_sha256`, `fixture_executable_manifest_sha256`
null, `evidence_scopes` exactly the one-element array `exact_artifact`,
`started_at`, `finished_at`, `result` exactly `pass`,
`provisional_authorization_sha256`,
`provisional_context_sha256`, `setup_context_sha256`,
`pre_enrollment_inventory_sha256`, `registry_snapshot_sha256`,
`smoke_receipt_context_sha256`, `terminal_journal_evidence_sha256`,
`observations`.
Observations exactly equal the capability-specific smoke plan, including
the first setup case, case-final evaluations, authority-negative,
receipt-context, sanitized export, ordered preflight, dispatch-deny, and zero-mutating-
byte assertions. The setup `snapshot` observation and every observation after
it carry the index's exact `registry_snapshot_sha256`. The terminal evidence digest resolves to its retained object; the later
export/disposal digests occur only in the complete evidence-set tuple. The per-architecture
indexes form the canonical `activation_smoke` evidence-set manifest defined
above.

## Production activation grant

Only after the complete smoke evidence set and every matching externally
observed whole-host disposal attestation pass may the offline root sign a
production activation grant. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `grant_type`, exactly `first_release_production_activation`
3. `authority_key_id`
4. `descriptor_sha256`
5. `provisional_authorization_sha256`
6. `provisional_context_sha256`
7. `gate1a_e1_evidence_set_sha256`
8. `gate1a_e2_evidence_set_sha256`
9. `gate1a_plan_sha256`
10. `gate1a_evidence_scopes`
11. `gate1b_e1_evidence_set_sha256`
12. `gate1b_e2_evidence_set_sha256`
13. `gate1b_plan_sha256`
14. `gate1b_evidence_scopes`
15. `activation_smoke_gate_plan_sha256`
16. `activation_smoke_evidence_set_sha256`
17. `approved_capability`
18. `minimum_registry_schema`, integer `1`
19. `minimum_receipt_schema`, integer `3`
20. `activated_at`
21. `release_not_before`

All fields match the descriptor, provisional authorization, provisional
context, Gate sets/plans, scopes, and smoke set/plan. The Gate 1B evidence
digests, plan, and scope field follow the
same exact null rule for `confirm_only`; the smoke values are never null. The
grant never contains or signs the final authorization-context digest, avoiding
a circular hash.
`activation_smoke_gate_plan_sha256` must exactly equal `gate_plan_sha256` in
every smoke token, smoke evidence index, and the smoke evidence-set manifest;
there is no second smoke-plan digest or alias.
`release_not_before` is not before `activated_at`; runtime denies authority
before it.

After the complete signed grant bytes exist, both peers derive the final
production authorization context as compact canonical JSON capped at 4,096
bytes. Its fields are `schema_version` integer `1`, `context_type` exactly
`first_release_production`, `authority_key_id`, `descriptor_sha256`,
`provisional_authorization_sha256`, `production_activation_grant_sha256`,
`approved_capability`, `minimum_registry_schema`, and
`minimum_receipt_schema`, in that order. Every value must equal the descriptor,
provisional authorization, and grant. `authorization_context_sha256` is
SHA-256 over those exact bytes, with no domain prefix.

Runtime production authority requires both signed sidecars, valid under their
distinct domains, and exact agreement with the derived final context. Each
peer independently derives and exchanges that digest before any authority
protocol bytes. Two different grants necessarily produce different final
contexts and cannot be silently mixed. The provisional authorization or grant
alone, a mismatched pair, or any missing evidence/context binding denies
confirmation and apply before profile or network access.

Receipt schema 3 adds `authorization_context_sha256` immediately after
`registry_revision` to the unsigned and signed receipt contract. Because v3 is
not implemented or shipped, this is part of its required pre-Gate delta rather
than a new schema version. Production confirmation and apply require it to
equal the final production authorization-context digest. Before provisional
authorization, an exact authenticated Gate E1/E2 session instead requires its
`gate_receipt_context_sha256`; this is Gate execution, not production
authority. The distinct smoke context, Gate context on a non-Gate path, and
every earlier schema are ineligible. This delta must be frozen in the approval-
protocol vectors before Gate begins.

The closed capability matrix is:

| Matching provisional + grant | `mutation confirm` | `mutation apply` for `issue.create` | Apply for `issue.update` / `comment.add` / other |
| --- | --- | --- | --- |
| provisional only | denied before profile access | denied before profile access | denied before profile access |
| grant only | denied before profile access | denied before profile access | denied before profile access |
| mismatched pair/context/evidence | denied before profile access | denied before profile access | denied before profile access |
| peers select different valid grants/final contexts | denied before protocol bytes | denied before protocol bytes | denied before protocol bytes |
| `confirm_only` | allowed with production context | denied before preflight | denied before preflight |
| `issue_create` | allowed with production context | allowed only for a confirmed schema-3 receipt and canonical `issue.create` plan in the same context | denied before preflight |

There is no set union, prefix match, implied wildcard, caller-selected
capability, or Gate-token substitution. Signing provisional authorization,
smoke tokens, and the activation grant changes no executable, bundle, payload
archive, or descriptor byte. Any rebuild, re-sign, re-notarization, restaple,
entitlement/profile change, or archive repack starts again at E1.

## Mandatory post-grant production-path verification

The activation grant is not eligible for packaging or publication until the
exact artifact has completed a separate post-grant verification on every
declared architecture. This stage exists because activation-smoke evidence is
created before the grant exists and therefore cannot test the grant parser,
the final authorization-context derivation, or schema-3 receipts that bind
that final context.

After the grant and final context exist, the offline root signs one distinct
post-grant verification token per declared architecture. Its unsigned fields
are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `post_grant_verification`
3. `authority_key_id`
4. `descriptor_sha256`
5. `provisional_authorization_sha256`
6. `production_activation_grant_sha256`
7. `authorization_context_sha256`
8. `gate_plan_sha256`
9. `architecture`
10. `approved_capability`, exactly matching the grant
11. `gate_runner_unique`
12. `gate_session_id`
13. `setup_authorization`, exactly
    `first_exact_artifact_enrollment_only`
14. `host_disposal_policy`, exactly `external_whole_host_disposal_v1`
15. `loopback_origin`, null for `confirm_only` or `http://127.0.0.1:` followed
    by one canonical decimal port in `1..65535` for `issue_create`
16. `dispatch_deny_code`, null for `confirm_only` or exactly
    `POST_GRANT_PRODUCTION_MUTATION_DISPATCH_DENIED` for `issue_create`
17. `issued_at`
18. `expires_at`, no more than 30 minutes after issue

The signer recomputes all four authority digests from the exact descriptor,
signed provisional authorization, signed activation grant, and derived final
context before signing. The post-grant plan's descriptor, capability,
architecture set, and `authorization_context_sha256` must match the token and
authority pair; the plan begins with the matching setup case and carries
`stage_setup_policy=first_exact_artifact_enrollment_v1` plus
`host_disposal_policy=external_whole_host_disposal_v1`. Tokens and sessions
are fresh and globally distinct from every
E1, E2, and activation-smoke token/session. The candidate accepts the token
only through the same runner-identity, audit-token, native-architecture,
challenge-response, expiry, and mode-0700 session checks as E1. It is never
installed, shipped, or accepted by an ordinary process outside that exact
authenticated session. Its setup field is accepted only through its derived context in the first
case; disposal is an external publication-signature prerequisite. Neither can
substitute for the grant-bound final production context used by the subsequent
workflow.

The runner stages the real detached descriptor, provisional authorization,
and activation grant beside the real signed app under the ordinary installation
layout. It first derives the setup-only context, proves the canonical empty
inventory, performs the one exact-artifact revision-1 enrollment, and retains
the resulting registry snapshot outside disposable state. The CLI and helper
then load that exact authority pair through the ordinary production
validator, independently derive and exchange the final
`authorization_context_sha256`, and use the ordinary production
approval-registry, Secure Enclave/Keychain, and schema-3 receipt codecs against
runner-provisioned state on the clean Gate host. A test root, fixture
executable, provisional context, smoke context, alternate sidecar loader,
synthetic receipt, or prevalidated authority object cannot satisfy a positive
post-grant observation. Every receipt minted in this stage carries the actual
final production context; the runner token restricts where it can be used but
does not replace or alter that context. The setup snapshot observation, its
case-final evaluation, and every later operation/final observation carry the
retained `registry_snapshot_sha256`.

The `confirm_only` plan runs the compiled ordinary `prepare -> confirm`
workflow, proves that the resulting schema-3 receipt names the final context,
and proves every apply operation is denied before preflight or network access.
The `issue_create` plan runs the compiled ordinary
`prepare -> confirm -> apply` workflow. Apply performs only the declared
read-only IPv4-loopback preflight, durably consumes the receipt, and then must
return `POST_GRANT_PRODUCTION_MUTATION_DISPATCH_DENIED` at the final dispatcher
before any mutating request-line, header, or body byte is opened or written.
An earlier validation, authority, journal, preflight, or capability failure
does not satisfy the positive dispatch-denial assertion. Update, comment, and
every other capability remain denied before preflight.

### Non-replayable journal and export evidence

Post-grant verification uses a runner-created mode-0700 profile and journal
root and no production credential. It introduces one compiled, runner-only
terminal transition named `post_grant_verification_consumed`; that transition
is not exposed by the ordinary CLI, skill, environment, or caller-selected
configuration. For `confirm_only`, the compiled `consume` step atomically
changes the positive receipt from `confirmed` to that terminal state after all
apply-denial observations pass. For `issue_create`, ordinary apply first makes
the durable `confirmed -> in_flight` transition, and only after the exact
post-grant dispatch-denial result is captured does the runner atomically change
`in_flight` to the same terminal state. Neither path can return to `prepared`
or `confirmed`. The receipt ID, nonce, plan ID, and journal revision are burned
even if later evidence collection or host disposal fails.

The terminal transition produces one compact canonical journal evidence object
capped at 8,192 bytes. Its fields are, in order: `schema_version` integer `1`,
`evidence_type` exactly `post_grant_terminal_journal`, `descriptor_sha256`,
`provisional_authorization_sha256`, `production_activation_grant_sha256`,
`authorization_context_sha256`, `architecture`, `gate_session_id`, `plan_id`,
`registry_snapshot_sha256`, `receipt_id`, `receipt_sha256`, `nonce_sha256`, `prior_state`,
`terminal_state` exactly `post_grant_verification_consumed`,
`journal_revision`, `transition_reason`, and `transitioned_at`.
`prior_state` is exactly `confirmed` for `confirm_only` and `in_flight` for
`issue_create`; `transition_reason` is respectively
`confirm_only_verification_complete` or
`post_grant_dispatch_denied_before_mutation`. IDs and revisions use the
ordinary schema-3 journal grammar. The hashes cover the exact canonical signed
receipt and its 32-byte nonce. The journal CAS and a repeated ordinary
confirm/apply attempt must both prove the terminal record and return the stable
`RECEIPT_ALREADY_CONSUMED` reason without UI, preflight, or network access.

The final evidence-sealing case runs only after the terminal record,
replay-denial observations, and every authority-negative observation have
been retained by digest. It verifies those public projections and sanitized
archive inputs without deleting or modifying Keychain/journal state. No later
candidate operation may restage a plan, receipt, socket, copied sidecar, or
key. The external supervisor then verifies the final index/export closure,
destroys the entire disposable host, and obtains the separately root-signed
host-disposal attestation before publication can be authorized. The index
cannot contain that later attestation digest: the evidence-set tuple binds
both in dependency order.

Each architecture emits a compact canonical post-grant evidence index capped
at 1,048,576 bytes (1 MiB) with these fields in exact order:

1. `schema_version`, integer `1`
2. `evidence_type`, exactly `post_grant_verification_pass`
3. `gate_id`, exactly `post_grant_verification`
4. `descriptor_sha256`
5. `post_grant_verification_token_sha256`
6. `gate_plan_sha256`
7. `allowed_capability`
8. `provisional_authorization_sha256`
9. `production_activation_grant_sha256`
10. `authorization_context_sha256`
11. `setup_context_sha256`
12. `pre_enrollment_inventory_sha256`
13. `registry_snapshot_sha256`
14. `gate_runner_unique`
15. `gate_session_id`
16. `macos_product_build_version`
17. `architecture`
18. `fixture_set_sha256`
19. `fixture_executable_manifest_sha256`, null
20. `evidence_scopes`, exactly the one-element array `exact_artifact`
21. `started_at`
22. `finished_at`
23. `result`, exactly `pass`
24. `terminal_journal_evidence_sha256`
25. `observations`

The observations exactly equal the capability-specific post-grant plan and use
the Gate evidence observation/result codecs. They begin with exact-artifact
setup and its case-final evaluation; the setup snapshot observation and every
later observation bind the index's retained `registry_snapshot_sha256`. They
include ordinary authority loading, both-peer final-context equality, schema-3 receipt parsing and
signature validation, capability denials, terminal CAS, ordinary replay
denial, sanitized export, runner/session negatives, and, for `issue_create`, the exact
read-only loopback transcript, unique dispatch code, and zero mutating bytes.
The index digest is SHA-256 of those exact bytes. Its setup, pre-inventory,
snapshot, and terminal digests must resolve to the
objects above and agree with their observation result manifests.

The per-architecture indexes form one complete compact canonical evidence-set
manifest capped at 16,384 bytes. Its fields are, in order: `schema_version`
integer `1`, `evidence_set_type` exactly `post_grant_verification`, `gate_id`
exactly `post_grant_verification`, `descriptor_sha256`,
`provisional_authorization_sha256`, `production_activation_grant_sha256`,
`authorization_context_sha256`, `gate_plan_sha256`, `approved_capability`,
`fixture_set_sha256`, `evidence_scopes` exactly the one-element array
`exact_artifact`, `architectures`, `indexes`, `registry_snapshots`,
`install_evidence_manifest_sha256`, and `result` exactly `pass`.
`architectures` exactly equals the descriptor array. `indexes` has one entry
per architecture in that order, with fields `architecture`,
`evidence_index_sha256`, `post_grant_verification_token_sha256`,
`gate_session_id`, `setup_context_sha256`,
`pre_enrollment_inventory_sha256`, `registry_snapshot_sha256`,
`terminal_journal_evidence_sha256`, `export_manifest_sha256`, and
`host_disposal_attestation_sha256`, in that order.
`registry_snapshots` contains one entry per descriptor architecture in that
order, with fields `architecture` and `registry_snapshot_sha256`, exactly
projecting the index tuples. Each export/attestation must match the earlier
index and exact stage/token/architecture/session tuple; each signed
attestation is verified under the pinned root's distinct disposal domain.
No cleanup ledger, intent, progress, marker, final-empty inventory, or
candidate deletion evidence exists in this set.

`install_evidence_manifest_sha256` is SHA-256 of the exact compact canonical
`install-files.json` bytes. That separate object is capped at 2,097,152 bytes
and has fields in exact order: `schema_version` integer `1`, `manifest_type`
exactly `post_grant_install_evidence`, `descriptor_sha256`,
`authorization_context_sha256`, `gate_plan_sha256`, and `files`. Its three
digests exactly equal the complete evidence-set manifest. `files` is the
complete inventory for the archive's
`authorization/post-grant-verification-evidence-set/files/` tree. It is sorted
by the raw ASCII bytes of `path` and contains one entry for every regular file
under that directory, with fields `path`, `size`, and `sha256` in that order.
Across all architectures it contains 1..1,024 entries and names at most 256
MiB of aggregate file bytes; these are independent whole-manifest caps, not
per-index allowances. The counts and aggregate size are checked before any
proportional allocation or file read.
`path` is 1..1,024 printable ASCII bytes without JSON escapes and is a relative
path of slash-separated components. Each component is 1..128 bytes and uses
only ASCII letters, digits, dot, underscore, or hyphen; dot, dot-dot, empty,
backslash, leading-slash, trailing-slash, duplicate, and ASCII-case-fold-
colliding paths are invalid. `size` is a
non-negative JSON integer no greater than the file-type cap, and `sha256` is
the digest of the exact file bytes. The list includes every per-architecture
evidence index and every referenced fixture, transcript, assertion, result
manifest, setup context, pre-enrollment inventory, registry snapshot, terminal
record, export manifest, root-signed host-disposal attestation, and its
supervisor host-inventory/destruction records. Neither
manifest is self-listed: the fixed `index.json` path is authenticated by the
publication envelope's `post_grant_verification_evidence_set_sha256`, and the
fixed `install-files.json` path is authenticated by the evidence-set
manifest's `install_evidence_manifest_sha256`. A missing, additional,
reordered, mismatched, linked, escaping, or secret-bearing file fails the
entire set. `post_grant_verification_evidence_set_sha256` is SHA-256 of the
exact compact evidence-set manifest bytes. The envelope therefore
authenticates the compact evidence-set manifest, which authenticates the
install-evidence manifest, which authenticates every evidence file's installed
path, size, digest, ordering, and multiplicity without exceeding the compact
object's 16,384-byte cap.

Post-grant verification token bytes are deliberately absent from the install-
evidence manifest and from the delivery archive. Before publication,
the Gate and release verifiers validate each root signature, token/session
binding, and expiry and then record its exact digest in both the
per-architecture index and evidence-set manifest. At installation time that
matching digest is an envelope-authenticated historical cross-reference, not
a request to reconstruct or revalidate an expired session token. The installer
must not fetch token bytes. This preserves the rule that a session-bound token
is never installed, shipped, or accepted outside its authenticated Gate
session while still making token substitution in retained evidence detectable.

Until that complete set passes, the app-only archive, canonical descriptor,
provisional authorization, and activation grant remain in trusted
prepublication custody on the clean Gate/release hosts. They must not be put in
a delivery archive, draft release, Cask, ordinary installation root, shared
artifact store, or developer workstation. This custody is a release-process
trust assumption, not a cryptographic revocation mechanism. Any post-grant
failure, timeout, missing architecture, disposal failure/uncertainty, or evidence mismatch
quarantines the descriptor, provisional authorization, grant, tokens, and all
derived artifacts; no publication envelope is signed, no quarantined object is
later reused, and a retry starts from a newly built, signed, notarized, stapled,
archived, and described artifact at E1. The failed evidence is retained only in
the access-controlled release incident record.

## Publication envelope

After the complete post-grant verification set and every matching whole-host
disposal attestation pass, the offline root signs the publication envelope.
The signature occurs after disposal and attestation, never on the live stage host. It has these unsigned fields:

1. `schema_version`, integer `1`
2. `envelope_type`, exactly `youtrack_agent_publication`
3. `authority_key_id`
4. `product_version`
5. `release_build`
6. `git_commit_oid`, `sha1:` followed by the exact 40-character lowercase hexadecimal commit object ID used by the first release repository
7. `descriptor_sha256`
8. `provisional_authorization_sha256`
9. `authorization_context_sha256`
10. `production_activation_grant_sha256`
11. `activation_smoke_evidence_set_sha256`
12. `post_grant_verification_gate_plan_sha256`
13. `post_grant_verification_evidence_set_sha256`
14. `app_payload_archive_sha256`
15. `published_at`, UTC RFC 3339 whole seconds

The two post-grant fields must equal the plan and complete evidence set whose
descriptor, authority pair, final context, capability, architecture order, and
fixture set equal this envelope and its other authority fields. The release
pipeline verifies all contained hashes and signatures, then creates the outer
delivery archive exactly once from the app, descriptor, provisional
authorization, activation grant, signed envelope, exact post-grant plan, and
complete closed evidence-set tree shown above. It records the archive's exact
byte length and SHA-256 in the release record and as literal `url` and `sha256`
values in the reviewed Cask. It uploads that archive plus the descriptor,
authority objects, envelope, Gate/smoke/post-grant plans, Gate 1A fixture-
executable manifest, and complete evidence sets as distinct audit assets to a
draft GitHub release, verifies every remote digest, and only then publishes an
immutable release. The Cask URL names that immutable version/tag and exact
archive filename; it may not use a latest, redirect-selected, mutable, or
replaceable asset. A moved tag, remote digest mismatch, or Cask/archive
checksum mismatch is not eligible for installation.

The Cask uses the literal outer-delivery-archive SHA-256, never `:no_check`,
installs the complete signed app and detached `authorization/` tree without
re-signing, rebuilding, fetching, or rewriting any byte, and links the
contained CLI. Installation validation reads the root-signed publication
envelope, exact post-grant plan, evidence-set index, install-evidence manifest,
and every file listed by that manifest only from their fixed paths under that
same versioned installation root. It must verify the envelope signature,
matching provisional
authorization and
activation grant, authorization context, descriptor, post-grant plan and
complete evidence-set binding, Developer ID signatures, notarization, and
exact app code identities before guarded mutations are enabled. Missing or
extra evidence, a path/link violation, or any digest mismatch disables guarded
mutations. It never reconstructs an archive hash from the installed tree or
retrieves verification material after extraction. Homebrew's checksum is a
download-integrity check, not a substitute for root authorization or runtime
peer verification.

## Cross-language conformance evidence

Implementation is blocked until one language-neutral fixture set is consumed
by the Go release/publication verifier and the Swift native verifier. Positive
vectors contain exact unsigned bytes, domain-prefixed signing bytes, signed
bytes, SHA-256 values, Ed25519 public key/signature, and parsed values for:

- one universal artifact descriptor and one single-architecture descriptor;
- exact Gate 1A, both capability-specific smoke plans, and both
  capability-specific post-grant plans, including every typed argv source,
  scope mapping, canonical operation execution context, empty operation
  assertion array, case-final evaluation contract, and ordered final aggregate;
- all five complete flat command contracts and their fixture/assertion/transcript
  manifests, exact cardinalities from the normative table, maximum-length
  evidence skeletons and complete referenced-file closures, with canonical
  byte/count/file budget reports accepted before their digests are frozen;
- the isolated Gate 1B coverage inventory, all expanded unit/segment contracts,
  exact per-leaf and parent count/budget vectors, and every required semantic
  vector from the isolated ADR; no old flat count or reset route satisfies them;
- the complete Gate 1A fixture-executable manifest with both disjoint fixture
  roles, both negative-peer components, and every architecture-specific signed
  identity/code slice;
- Gate 1A per-architecture E1/E2 tokens, indexes, and complete evidence sets;
  Gate 1B isolated coverage inventory, per-unit E1/E2 tokens and any observer
  tokens, typed leaves, complete parents, target-retirement/export/disposal
  evidence, and per-unit setup
  contexts, empty pre-enrollment inventories, immutable baseline registry
  snapshots, and their exact typed leaf/parent projections;
- all four release-stage setup-case enroll transcript-result manifests with their exact
  observation IDs and ordered five entries, closed `stage_setup_enrollment`
  IPC bytes, and helper reconstruction from the validated token/context and
  snapshot enrollment fields checked against registry/closed records; the
  exact commit/closed-to-IPC-to-manifest-to-snapshot-to-final-evaluation DAG,
  with matching content digests and byte counts in both Go and Swift;
- Gate 1A E1/E2 `gate_receipt_context_v1` objects and digests, and Gate 1B
  per-unit `gate1b_isolated_receipt_context_v1` objects and digests, matching
  schema-3 receipts and their respective complete `gate_authority_evidence_v1`
  or `gate1b_isolated_authority_evidence_v1` journal branches with retained
  descriptor/token/context bytes and genesis-to-current registry chains, and
  the context-bound active/permit/closed linkage plus Gate 1B historical
  read-only reconciliation;
- every exact Security.framework key/registry/coordinator dictionary and
  bounded result projection, including the one-lookup active attributes/data/
  persistent-reference tuple and exact-reference deletion; reference lengths
  1 and 4,096 bytes succeed while zero, 4,097, wrong CF type, absent, or
  conflicting projections deny;
- every fixed coordinator schedule, all 23 phases and their state variants,
  two independently authenticated helpers, same-UID alternate bootstrap,
  unclosed quarantine before/after permit and before close, normal owner
  quiescence before durable close, and the A-to-B persistent-reference ABA
  replacement that leaves B unchanged;
- ordinary owner normal-close and exact already-closed cleanup, ambiguous
  outcomes without automatic resend, read-only remote reconciliation without
  quarantined journal writes, and fixed JSON-v1 status/error shapes;
- code/entitlement, CMS, certificate-chain/policy, notary and staple wrappers,
  exact tool capture, retained output digests and certificate multiset framing;
- both stage-only setup contexts, all canonical pre-enrollment inventories
  and retained registry snapshots, sanitized export manifests, bounded
  supervisor inventories/destruction evidence, root-signed disposal
  attestations, and the acyclic index -> export -> disposal -> set ->
  successor-signature chain;
- provisional authorizations/contexts, both smoke token/index variants,
  terminal non-replay objects, smoke evidence sets, activation grants/final
  contexts, both post-grant token/index variants, complete evidence sets and
  install manifests, publication envelopes and exact archives; and
- all 88 profile-expiry vectors: exactly 22 boundaries times four clock
  positions, plus the separate expired-status/already-closed-cleanup exception.

Both implementations must parse, validate, re-encode, hash, and verify every
positive vector identically. The fixture set evaluates every row of the
capability matrix against confirm and each supported apply operation, including
Gate target/session/architecture restrictions. It runs every hard-coded plan
case and requires exact ordered observation equality. The closed negative set
independently covers:

- every object and field size boundary; missing, duplicate, unknown, reordered,
  escaped, whitespace-modified, noncanonical integer/null/base64url, and
  trailing JSON;
- byte, entry, observation, referenced-file, per-file, and aggregate caps at
  limit-minus-one, limit, and limit-plus-one, subject independently to exact
  membership; checked-count/size addition overflow; truncation or extra entries
  relative to each of the five fixed cardinality rows; and rejection of an
  oversized object before parsing/proportional allocation or an oversized
  referenced-file closure before file reads, including a correctly hashed
  but over-budget candidate at compile time;
- wrong root key ID, public key, signature, domain, object type, descriptor, or
  payload digest, including cross-domain signature substitution;
- absent, duplicate, reordered, unsupported, or mismatched architecture,
  code-slice, digest-algorithm, `kSecCodeInfoUnique`, cdhash, Team ID,
  identifier, build, complete semantic entitlement, peer-requirement source,
  actual designated requirement, certificate chain/policy,
  `SecStaticCodeCheckValidity` result, profile raw/CMS sequence, notarization,
  or staple evidence;
- descriptor/profile expiry mismatch and the exact 88-vector Cartesian product
  of all 22 named profile-expiry boundaries with just-before, equality, after,
  and expiry-between-checks variants—including peer authentication—and exact
  no-side-effect assertions;
- raw-entitlement-present/dictionary-absent, dictionary-present/raw-absent,
  raw/dictionary semantic disagreement, unknown entitlement, and both values
  absent for a helper that requires its fixed entitlements;
- CMS certificate count/aggregate overflow, empty DER, changed count/length
  framing, digest-only or JSON preimage, array-order dependence, duplicate DER
  removal, wrong digest/DER sort order, and trailing certificate bytes;
- sidecar traversal, symlink, hard link, wrong owner/mode/type, oversize,
  truncation, inode/metadata change, mixed descriptor, and reopen races;
- wrong Gate runner, connection audit token, session, nonce, expiry, Gate ID,
  architecture, plan, target, capability, or network policy, plus
  E1/E2/smoke/post-grant replay, session reuse, evidence predecessor mismatch,
  missing architecture, and incomplete evidence set;
- missing, oversized, noncanonical, or changed `gate_receipt_context_v1`;
  wrong Gate token type/digest, Gate ID, descriptor, plan, target/prerequisite
  null rule, architecture, runner, session, or capability; Gate 1A/1B,
  E1/E2, production, smoke, or post-grant context substitution; a live expired
  Gate token accepted for confirmation, acquisition, permit, or send; an old
  Gate context used for a new confirmation/permit/send; historical Gate 1B
  reconciliation without the still-authenticated matching runner session; or
  rejection solely because the retained token expired after the recorded live
  authority boundary;
- missing, oversized, noncanonical, mixed, or digest-only Gate
  `authority_evidence`; any provisional/smoke/grant/final-production object in
  its Gate branch; omitted/reordered/forked/gapped registry-chain records;
  terminal-record-only validation, unchecked SPKI self-selection, receipt/
  context/active/permit/closed link disagreement, or historical validation
  that creates live authority;
- unknown/reordered Gate case, step, typed argv source, fixture, assertion, or
  transcript; shell/cwd/env/stdin inheritance; prepare/confirm/apply reorder;
  dynamic-value injection; observation omission/addition/reorder; and command-
  context digest mismatch;
- observation IDs with extra slashes, escaped or encoded separators,
  normalization-dependent matches, an uncompiled case/step pair, or more than
  128 bytes; a setup selector naming any observation other than the exact
  first-case `enroll`, a wrong manifest codec, missing/extra/reordered entry,
  changed transcript ID/kind, unretained content, or snapshot creation before
  durable retention of all five entries and their result manifest;
- unknown/reordered/oversized `stage_setup_enrollment` fields, wrong stage,
  token, context, capability, tag, SPKI, fingerprint, registry or closed record,
  an extra generated tag, cross-session or cross-token/context splicing, IPC
  content-digest or byte-count disagreement on reconstruction, and any
  timestamp/snapshot/manifest field or dependency cycle in enrollment evidence;
- missing, early, duplicate, or reordered case-final evaluation; nonempty
  `assertion_ids` or an assertion result on any operation observation; empty or
  reordered final assertion IDs; final evaluation before all operation and
  transcript-result digests exist; changed ordered aggregate; or a case/evidence
  pass without its final evaluation;
- changed/missing evidence scope; production-role execution in a disjoint
  case; fixture-role execution in an exact-artifact case; fixture identifier,
  manifest, architecture, unique identifier, executable hash, cdhash, or code-
  validation mismatch; cross-namespace IPC; and fixture evidence mislabeled as
  production execution;
- ordinary lifecycle mislabeled as fixture evidence; any destructive case
  outside the exact five-case disjoint mapping; alternate fixture namespace;
  negative-peer missing/changed component, production identifier, older build,
  architecture, or signed digest; negative-peer use outside the mixed-build
  rejection steps; or any negative-peer helper, Keychain, registry, positive-
  assertion, or protocol authority;
- an empty or modified compiled command contract; assertion/transcript result
  omission, duplication, reorder, wrong expected/actual digest, false success,
  aggregate-only result, and result-manifest/observation substitution;
- alternate or caller-selected ordinary Unix endpoint, missing
  `LOCAL_PEERTOKEN` or exact identity check, runner-preconnected descriptor
  misattributed to a CLI/helper, or unauthenticated control channel; disjoint
  fixture traffic crossing into ordinary authority; `AF_INET`/`AF_INET6`
  under a deny policy, hostname/IPv6 loopback, datagram/raw socket, or
  undeclared socket family/type;
- Gate-token use on the production path, missing Gate 1A prerequisite for Gate
  1B, null/non-null Gate 1B evidence errors, capability widening, and
  `issue.update` / `comment.add` substitution;
- missing, reordered, or additional coordinator cases, schedule fixtures,
  barriers, events, actors or helper identities; sleep-based ordering; treating
  one label, launchd parent, bootstrap namespace, or local executor guard as
  a cross-process singleton/fencing proof; refusing to test two valid helpers;
- normal close before irrevocable owner quiescence, any non-owner close add,
  unclosed recovery CAS/delete/keygen/sign/permit/send/commit, or UI/expiry/
  restart/reboot/PID loss treated as permission to clear an unclosed lease;
- attributes-only active deletion, separately captured reference and value,
  invalid/oversized CFData reference, unknown result fallback, deletion of B
  after capturing A, or mutation on a stale-reference not-found result;
- two active leases, permit before durable `in_flight`, stale session/receipt,
  second permit/send, registry mutation overlapping active apply, automatic
  ambiguous retry, or quarantined remote reconciliation changing local state;
- authority status/recover without explicit profile or required invocation
  `meta`; any plan/lease/force selector, positional input, `--yes`, `--dry-run`,
  `--fields`, raw output, stdin/environment override, or changed accepted-flag
  semantics; corruption or `AUTHORITY_STATE_QUARANTINED` mapped anywhere
  but exit 1; or renumbering existing authority exits 10 through 13;
- migration of any valid v1 state other than `prepared`, especially
  `failed_before_mutation`; mutation/deletion of quarantined source bytes;
  missing quarantine marker attempt; or treating current fail-closed code as
  proof that an unrepresentable v1 authority state is safe;
- provisional-only or grant-only use, mismatched provisional/grant/context,
  two valid grants for one provisional context, peer disagreement on grant or
  final context, smoke-plan or post-grant-plan substitution, smoke receipt
  copied into a production context, post-grant receipt using a provisional or
  synthetic context, wrong post-grant token/grant/context/runner/architecture,
  missing terminal CAS or export/disposal evidence, receipt replay after terminal
  consumption, and pre-dispatch/late-dispatch false positives;
- acceptance of any old flat Gate 1B token, setup/receipt context, retained
  branch, index, evidence set, or export/disposal route; missing isolated
  phase/negative variant, including status and legacy-journal quarantine;
  inherited or relabeled actual host/target identities across units,
  architectures, or passes; wrong unit token, complete E1-parent or Gate 1A
  E2 prerequisite, inventory, target, descriptor, architecture, capability,
  runner, session, or checkpoint binding; use of an old reset label as an
  executable action; missing or late target retirement; reboot observer with
  network, reset, signing, CAS, deletion, or more than two segments; any other
  missing isolated-ADR conformance vector; missing/non-first release-stage setup
  case; setup token/context absent, mismatched, or used for any action except
  the one initial exact-artifact enrollment; nonempty
  pre-enrollment registry service, coordinator service, signing-key namespace,
  journal root, or mutable runner-session inventory; enrollment other than
  revision integer `1`/generation string `YTAG-00000000000000000001`; setup snapshot with wrong revision, generation,
  SPKI, fingerprint, descriptor, architecture, runner, or session; any later
  observation/index/evidence-set entry with a missing or different snapshot;
  a Gate 1B typed leaf/parent with missing, conflicting, or cross-unit
  setup/inventory/snapshot bindings, or a non-null Gate 1A setup or snapshot field; retained setup evidence placed inside disposable state; a
  baseline snapshot treated as current state after an evidenced
  rotate/revoke/recover transition or current state substituted for baseline;
  or a second setup, rotation, recovery, revocation, receipt signature,
  permit, or network action under setup authority;
- any `stage_cleanup` IPC, cleanup intent/progress/ACK/restart authority,
  per-item stage deletion, signed final-empty inventory claim, or candidate
  request treated as a host-destruction instruction;
- missing/invalid/cross-host/cross-stage/cross-session disposal attestations,
  missing supervisor inventory or destruction proof, incomplete writable
  resource removal, host reuse, or activation/publication signed before
  externally verified destruction;
- export with mutable journal/plan/receipt/session state, key values,
  credentials or live test-authority tokens; cyclic index/export/attestation
  references; missing/extra/linked/case-colliding files or any cap violation;
- missing/changed `xcrun --find` output, executable hash, version argv, version
  exit/output digest, active-developer-directory resolution, or wrapper tool-
  capture digest; undocumented `notarytool` JSON shape substitution; and
  `spctl` text accepted despite a nonzero exit;
- app-payload, provisional-authorization, activation-smoke evidence set,
  activation-grant, post-grant plan/evidence set, delivery-archive,
  publication-envelope, remote-asset, and Homebrew checksum mismatch; and
- missing, additional, duplicate, reordered, ASCII-case-fold-colliding, or
  digest/size/path-mismatched install-evidence entries; wrong install-manifest
  context or digest; non-ASCII, escaped, empty-component, dot-segment,
  backslash, or overlong paths; unlisted files; a shipped or post-install-
  fetched post-grant token; and treating a retained token digest as an install-
  time authority object; and
- export sealing before authority-negative/terminal-replay observations,
  restaged mutable objects afterward, successor authorization on an uncertain
  destruction result, or reuse of any invalidated failure output; and
- app-only archive creation or replacement after descriptor canonicalization
  or E1 issuance, quarantined grant reuse, publication before every native
  architecture passes post-grant verification, and a publication envelope
  missing either post-grant digest.

Every negative vector has one stable fail-closed reason class. Gate plans pin
the complete fixture-set digest; adding, removing, or changing a vector
invalidates prior E1/E2 evidence.

## Gate and release invariants

- Gate, smoke, and post-grant plans are closed, canonical, and
  content-addressed. Any case, workflow step, runner, typed argv source,
  fixture, assertion, transcript, entitlement expectation, or command change
  produces a new plan digest and invalidates its tokens and evidence sets.
- Gate 1A E1/E2 receipts bind `gate_receipt_context_v1`; Gate 1B receipts
  bind `gate1b_isolated_receipt_context_v1` and its distinct retained-authority
  branch. Both use the existing schema-3 context field. Live authority requires
  the unexpired token and matching authenticated runner connection. Gate 1B
  historical reads and its network-free reboot observer follow the isolated
  ADR; neither may renew confirmation, permit, or send. Production, smoke,
  and post-grant modes reject both Gate-only context/authority branches.
- Gate 1A exact-artifact cases use the normal confirmation and registry
  lifecycle commands; its five destructive corruption/malformed-ledger/
  ambiguous-add/orphan-cleanup/active-key-loss cases use only the separately
  identified fixture pair and cannot stand in for product execution. Gate 1B
  uses the normal issue creation apply command against only its disposable target. The later
  activation smoke uses that same ordered prepare/confirm/apply workflow
  through exact loopback reads and the unique pre-write dispatch denial. After
  the grant is signed, post-grant verification repeats the ordinary workflow
  with the real sidecar pair, final production context, and schema-3 receipts,
  then irrevocably terminalizes those disposable receipts. Test-only command
  surfaces cannot substitute for either path.
- Every Gate 1B isolated unit, and every smoke or post-grant run, performs
  exactly one setup-only exact-artifact enrollment from its own canonical
  empty inventory. Gate 1B host/target allocation precedes its token and uses
  the new inventory protocol; other stages retain their existing order. The retained
  revision-1/generation-`YTAG-00000000000000000001` snapshot is immutable baseline provenance, not
  current-state authority. E1 state is never inherited by E2. Setup authority
  cannot rotate, recover, revoke, sign receipts, acquire a permit, or send.
- No stage exposes helper/CLI per-item cleanup. Sanitized immutable evidence
  is exported, then the trusted external supervisor destroys the complete
  disposable host and its writable snapshots/disks. The root signs a bounded
  disposal attestation only after independent lifecycle verification; complete
  evidence sets bind it before a successor E2/provisional/grant/publication
  signature. No signed empty-inventory or runner-self-destruction claim exists.
  Failed or uncertain runs remain quarantined and hosts are never reused.
- Assertion suffixes are case-final. Operation observations carry empty
  assertion IDs; only a separate final runner evaluation may aggregate and
  pass them after all ordered operation/transcript results exist. Without that
  observation the case and containing evidence set cannot pass.
- E1, E2, provisional authorization, provisional context, smoke, activation
  grant, final production context, post-grant verification, and publication
  all bind one descriptor digest and complete evidence sets with their exact
  artifact/fixture scope partition. Gate 1B alone requires the isolated typed
  parent across every unit and architecture; a flat per-architecture index
  cannot replace it. The fixture manifest is Gate evidence only
  and is never promoted into production runtime authority. The final context also
  binds the exact grant bytes, so different valid grants cannot share peer or
  receipt authority. Evidence binds the measured exact bytes, descriptor,
  Security.framework unique identifiers and complete cdhash sets. Any mismatch
  fails authorization; a byte-identical reproduction with identical measured
  identity cannot be distinguished by hashes. This is an exact-identity check,
  not proof of which build invocation produced the bytes.
- The helper and CLI must agree on the descriptor digest before any authority
  protocol bytes. The approval registry records that same digest as
  `artifact_descriptor_sha256`; any mismatch or artifact change invalidates the
  ceremony or receipt.
- LaunchAgent packaging and local executor guards are not a global singleton
  proof. The fixed Keychain active unique add is the cross-process mutex.
  Unclosed state remains quarantine even if a process died, a helper restarted,
  the host rebooted, a TTL expired, or UI approved. Only the uninterrupted
  owner may first drop every queued authority capability and then add normal
  close. Below capacity, any helper may subsequently delete only the exact persistent
  reference captured with validated active/close evidence; a replacement active
  is untouched. No recovery actor synthesizes close or mutates a quarantined
  journal. Bounded remote reconciliation reports only and never replays.
- Gate evidence, a provisional authorization, and smoke evidence cannot
  authorize ordinary production. Only a matching, separately domain-separated
  activation grant plus its provisional authorization can do so.
- The app-only payload archive is produced and retained once from the final
  stapled app before descriptor canonicalization and before E1 issuance. No
  Gate, smoke, grant, post-grant, delivery, or publication step may recreate or
  replace it while preserving the descriptor digest.
- A valid activation grant is necessary but not sufficient for publication.
  Every native architecture must pass the grant-bound post-grant plan, reach a
  terminal non-replayable journal state, and complete external host disposal; the
  root-signed publication envelope must bind that exact plan and complete set.
  Failure quarantines the entire candidate and cannot be repaired by rerunning
  only the missing case or by reusing the grant.
- The embedded helper profile expiry is an absolute write cutoff bound by the
  descriptor. Gate or publication evidence created earlier never waives a
  current expiry check, and apply checks it again under the helper coordinator
  immediately before the sole permit and immediately before the sole send.
- No production artifact is activated by this document. The root key, signed
  binaries, complete semantic signing evidence, notarization evidence,
  per-architecture clean-host E1/E2 passes, provisional authorization,
  per-architecture smoke pass, activation grant, per-architecture post-grant
  verification and disposal attestation, publication envelope, and immutable release must
  all exist and validate.

## Evidence

- Apple defines [`kSecCodeInfoUnique`](https://developer.apple.com/documentation/security/kseccodeinfounique)
  as a binary identifier tied to a specific version of signed code and
  [`kSecCodeInfoCdHashes`](https://developer.apple.com/documentation/security/kseccodeinfocdhashes)
  as the unique identifiers for every digest algorithm in the signature.
- Apple recommends Code Signing Services rather than parsing signature internals
  in [TN3127: Inside Code Signing: Requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
  and documents architecture-specific signatures and sealed resources in
  [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes).
- Apple exposes [`kSecCodeAttributeArchitecture`](https://developer.apple.com/documentation/security/kseccodeattributearchitecture)
  for architecture selection and requires
  [`kSecCSCheckAllArchitectures`](https://developer.apple.com/documentation/security/kseccscheckallarchitectures)
  when validating universal code.
- Apple exposes the complete signed entitlement dictionary through
  [`kSecCodeInfoEntitlementsDict`](https://developer.apple.com/documentation/security/kseccodeinfoentitlementsdict)
  and documents
  [`SecCodeCopySigningInformation`](https://developer.apple.com/documentation/security/seccodecopysigninginformation%28_%3A_%3A_%3A%29),
  [`SecCodeCopyDesignatedRequirement`](https://developer.apple.com/documentation/security/seccodecopydesignatedrequirement%28_%3A_%3A_%3A%29),
  and
  [`SecRequirementCopyData`](https://developer.apple.com/documentation/security/secrequirementcopydata%28_%3A_%3A_%3A%29).
  The static-code validity authority is
  [`SecStaticCodeCheckValidityWithErrors`](https://developer.apple.com/documentation/security/secstaticcodecheckvaliditywitherrors(_:_:_:_:)).
- Apple's [Cryptographic Message Syntax Services](https://developer.apple.com/documentation/security/cryptographic-message-syntax-services)
  enumerate the public decoder sequence beginning with
  [`CMSDecoderCreate`](https://developer.apple.com/documentation/security/1392600-cmsdecodercreate)
  and covering update, finalize, content, signer, certificate, and signer-status
  calls used for the profile. Apple separately documents
  [`SecPolicyCreateWithProperties`](https://developer.apple.com/documentation/security/secpolicycreatewithproperties%28_%3A_%3A%29),
  [`SecTrustCopyCertificateChain`](https://developer.apple.com/documentation/security/sectrustcopycertificatechain%28_%3A%29),
  [`SecCertificateCopyData`](https://developer.apple.com/documentation/security/seccertificatecopydata%28_%3A%29),
  and
  [`SecCertificateCopyValues`](https://developer.apple.com/documentation/security/seccertificatecopyvalues%28_%3A_%3A_%3A%29).
  These APIs provide the chain and exact DER/property inputs; the checked-in
  first-release policy remains this protocol's stricter local allowlist.
  Apple's
  [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
  explains the App ID and entitlement allowlist carried by a profile.
- Apple's code-signing guide explains that nested code is signed first and its
  signature is sealed by the outer bundle in
  [Code Signing Tasks](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html).
- Apple's
  [notarization workflow](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
  identifies `notarytool` and `stapler` as the command-line upload and ticket
  tools, while
  [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
  documents manual submission and stapling. Apple's Xcode help gives the exact
  [`xcrun stapler validate` ticket check](https://help.apple.com/xcode/mac/current/en.lproj/dev88332a81e.html).
  Apple also shows `stapler staple` and recommends clean-machine distribution testing in
  [Packaging Mac software for distribution](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution).
- Apple documents `spctl --assess --type exec` as a system-policy assessment in
  [Resolving common notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues)
  and documents exit-status assessment behavior in
  [Code Signing Tasks](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW25).
  Neither source is treated as a stable schema for verbose `spctl` text, so the
  protocol retains that output without parsing it.
- Homebrew requires a downloaded Cask artifact SHA-256 and documents the `app`
  and `binary` artifacts in the
  [Cask Cookbook](https://docs.brew.sh/Cask-Cookbook).
- GitHub documents that
  [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
  lock release tags and assets and generate a cryptographically verifiable
  release attestation over the tag, commit, and assets.
