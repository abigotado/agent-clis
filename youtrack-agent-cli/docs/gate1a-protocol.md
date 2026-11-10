# Gate 1A approval protocol (schema v3, pre-Gate)

Status: frozen cross-language data contract for the feasibility spike. Gate 1A
itself is **not passed**. `approval.Unsupported` remains the only production
adapter, and this document does not enable confirmation, apply, release, or
Homebrew installation.

The Go and Swift protocol libraries implement schema v3. Historical v2 fixtures
remain evidence for the completed feasibility spike and rejection tests, not
accepted candidate receipts. Native authority verification, journal v2, durable
confirmation, and the native helper remain unimplemented.

## Implemented schema v3 delta

Schema v3 retains the v2 message-size limits and canonical encoding rules,
narrows the generation label to exactly 25 bytes, and makes these signed
contract changes:

- `schema_version` is exactly `3`;
- `registry_revision` is inserted immediately after `challenge_sha256` in both
  unsigned and signed canonical JSON;
- `registry_revision` is a JSON integer in `1..256`, matching the bounded
  append-only helper ledger, with no alternate string or floating encoding;
- `authorization_context_sha256` is inserted immediately after
  `registry_revision` in both unsigned and signed canonical JSON. It is the
  lowercase SHA-256 of the exact canonical authorization-context object
  defined by the artifact-authorization protocol: canonical
  `gate_receipt_context_v1` during an authenticated Gate 1A E1/E2 session,
  `gate1b_isolated_receipt_context_v1` during an authorized Gate 1B execution
  unit, smoke receipt context during activation smoke, or grant-bound final
  context during production/post-grant verification;
- `key_generation` is exactly `YTAG-` followed by the 20-digit decimal ledger
  revision that introduced the key (`00000000000000000001` through
  `00000000000000000256`), replacing the broader pre-Gate v2 label grammar.
  That introduction revision must equal the receipt's `registry_revision`:
  enrollment, rotation, and recovery introduce the active key at the current
  revision; revocation leaves no active signer. A historical receipt retains
  its own issuance revision, not the current ledger revision;
- the signature, receipt digest, IPC success response, Go/Swift parsers, and
  golden vectors bind that added field;
- candidate decoders reject schema v2 rather than inferring a revision or
  authorization context.

Both IPC response validators and the Swift receipt factory require an explicit
immutable expected revision/context binding, independently supplied rather than
inferred from the received receipt. This value validates and compares claims
only: it does not authenticate the context, replay the registry, or establish
authority. A matching key and signature are likewise not a closed authority
chain. IPC framing remains version 2; receipt schema and frame versions are
separate. All field positions below describe schema v3.

The native trust boundary, canonical URL/plan-ID grammar, and exact future IPC
frame are specified in [Gate 1A native approval boundary](gate1a-native-boundary.md).
The registry generation and transition authority are specified by the
[Gate 1A registry and ceremony protocol](gate1a-registry-protocol.md), and
`registry_revision` and `authorization_context_sha256` are accepted only with
the descriptor and exact root-signed Gate token/context, provisional/smoke
pair, or provisional/activation pair authorized by
[Gate artifact authorization](gate1a-artifact-authorization.md), with the
Gate 1B-only types and bindings in [isolated subruns](gate1b-isolated-subruns.md). The Gate
branch exists before provisional authorization and is accepted only through
the matching authenticated Gate runner session; production, smoke, and
post-grant modes reject it.
Both authenticated peers agree on that context digest before the helper may
display or sign. Confirmation and the `confirmed -> in_flight` transition
require the same currently active context. Once a request is `in_flight`,
read-only reconciliation verifies the persisted historical context and receipt
but does not require that context to remain active. Before `in_flight`, the
journal atomically retains one closed stage-tagged authority set. An E1/E2
Gate 1A `gate` set contains the exact descriptor, exact root-signed Gate token,
canonical `gate_receipt_context_v1`, complete bounded genesis-to-current
registry chain and digests; it contains no provisional authorization,
smoke token, activation grant, or production authority. Gate 1B instead retains
`gate1b_isolated_authority_evidence_v1`, including the exact isolated unit token,
inventory/unit/target/host binding and new receipt context, as specified by the
isolated-subrun ADR. It cannot accept the old single-suite Gate 1B token or
substitute Gate 1A context bytes. An `activation_smoke`
set contains the exact descriptor, signed provisional
authorization, signed smoke token, provisional context, smoke receipt context,
and digests; it contains no activation grant and a pre-socket hard
denial is terminalized as `activation_smoke_consumed`, never reconciled. A
`production` or `post_grant_verification` set instead contains the exact
descriptor, signed provisional authorization, signed activation grant, final
grant-bound context and digests. In every mode, `receipt` is a sibling of
`authority_evidence` in the [journal v2 record](guarded-mutations.md#future-journal-record-v2-and-migration),
not an additional field inside one of these closed authority objects.
Historical verification rebuilds
the matching pinned-root signature/hash chain and replays the complete retained
registry chain to derive the verification key; a receipt digest, lone terminal
record, or caller-selected SPKI is not sufficient, and fields from different
stage types cannot be mixed. Live Gate confirmation/acquisition/permit/send
requires the matching unexpired Gate 1A token or Gate 1B isolated unit token
and the same authenticated live runner session.
After `in_flight`, later token expiry does not invalidate historical evidence,
but Gate 1B may use it only for bounded read-only reconciliation in that still-
authenticated unit session; it cannot authorize a new permit or send. The
separate reboot observer token admits local read-only quarantine evidence and
export only, with no remote reconciliation or resumption of receipt authority.

Schema v3 apply receipts are consumed only through the helper-owned apply-authority
coordinator defined by the registry protocol. The receipt's revision, active
generation, applicable authorization context, exact request digest, plan ID,
journal revision, and connected CLI audit token are bound through the
active/permit/closed chain using the registry protocol's exact field lists.
The exact signed receipt digest in protected active, permit and closed records
supplies the same-user anti-replay binding. Before any permit, the helper checks
all retained permit/closed history for prior use, including a pre-permit burn;
a restored journal or fresh lease cannot override it. The durable
`confirmed -> in_flight` CAS precedes the sole permit; the permit precedes the
sole send; the helper excludes every registry commit until a durable closed
record exists and the original uninterrupted authenticated owner has
irrevocably quiesced every sign, permit, send, and commit capability, including
queued callbacks. A crash without valid durable close quarantines the lease:
permit absence proves zero authorized mutation, not permission for a new actor
to CAS its journal, manufacture close, or delete active. Any uncertainty
at or after permit is ambiguous and non-replayable. After a permit only verified
success becomes `applied`; other dispatch outcomes, even known zero-byte
denials, become `ambiguous`. `failed_before_mutation` requires no permit.
Quarantined reconciliation is read/report-only without journal CAS; eligible
normally closed evidence follows the journal's bounded reconciliation rules.
Restart, reboot, expiry, PID loss, and trusted UI do not
release unclosed state.
At exhausted capacity, a valid closed active is retained as the non-deletable
`capacity_exhausted` sentinel; it is not recovery work or unclosed quarantine.
Neither a receipt signature nor an `in_flight` state alone authorizes network
I/O. The helper also requires trusted current time strictly before the
descriptor's `helper_profile_expires_at` at confirmation, coordinator
acquisition, permit issuance, and immediately before send.

Expiry of the applicable Gate, smoke, or post-grant runner token has one closed
state rule: before coordinator acquisition a confirmed plan becomes `expired`;
after acquisition with proven permit absence its receipt is burned and the
existing uninterrupted owner may close as `failed_before_mutation` with zero
dispatch only after irrevocable capability quiescence. A replacement actor
must quarantine instead. At or
after permit, an unresolved outcome is `ambiguous` and no new send is allowed.
Existing durable outcomes, including `activation_smoke_consumed`, are preserved,
never downgraded by expiry. The authenticated session may only finish the
existing journal/close fence and allowed historical read-only reconciliation;
this grants no new acquisition, signature, permit, registry commit, or send.
Vectors cover token equality/after at each boundary, both sides of permit,
durable-success preservation, and consumed-smoke preservation.
The registry protocol's future command/exit contract preserves the JSON v1
envelope but deliberately adds exits 10..13 for wait, trusted recovery,
artifact replacement, and reconfirmation; corruption/operator escalation and
`AUTHORITY_STATE_QUARANTINED` use existing exit 1. The future
authority surface never emits exit 9; remote-uncertain reconciliation may
retain it. The four additive exits do not exist in the current disabled
production slice and never authorize retry.

## Authority and limits

Go remains the authority for mutation-plan validation and canonical receipt
semantics. A native implementation must independently enforce this exact
schema before displaying or signing anything. Every numeric length is checked
before allocating, copying, decoding, or rendering the corresponding input.

| Value | Maximum |
| --- | ---: |
| Immutable approval display | 524,288 bytes (512 KiB) |
| Canonical signed receipt JSON | 4,096 bytes |
| Canonical unsigned signing JSON | 3,072 bytes |
| `key_generation` UTF-8/ASCII bytes | exactly 25 bytes |
| DER ECDSA P-256 signature | 72 bytes |
| Unpadded base64url signature text | 96 ASCII bytes |

The display is non-empty and contains the exact bytes returned by
`intent.ApprovalDisplayBytes`. The renderer must represent every byte
reversibly. It must not interpret Markdown, HTML, URLs, terminal escapes, or
other embedded content as active UI.

`intent.MaxCanonicalPlanBytes` owns and enforces the 512 KiB ceiling for every
produced and validated plan; approval code references that invariant rather
than maintaining a second limit. The budget covers the 64 KiB request domain
after the worst-case sixfold `encoding/json` HTML escaping plus the separately
bounded profile, URL, account, policy, and expected-state metadata. Tests keep
escape-heavy maximum plans for every supported mutation kind below the bound.

The frozen escaped renderer emits printable ASCII bytes `0x20...0x7e` unchanged
except that a backslash is emitted as `\\`. Every other byte is emitted as
uppercase `\xHH`. Its decoder accepts only this representation and recovers the
exact original byte sequence. The helper shows both the inert payload and this
escaped representation together with the payload digest.

This slice does not implement the IPC transport, process lifecycle, or helper
discovery specified by the native-boundary ADR. No implementation may infer
live authority from these data fixtures.

Likewise, the release-stage setup context is not an approval receipt-signing
context. Live `stage_cleanup`, cleanup intent/progress, and ACK-ledger deletion
authority are deferred from the first release; no receipt field grants such
authority. Smoke/post-grant terminal and export evidence is followed by
externally attested destruction of the entire disposable host before the
successor root signature. The root-bound disposal attestation is historical
release evidence, never runtime approval or deletion authority.

## Identifiers and time

`receipt_id` and `nonce` respectively use the literal prefixes `YTAR-` and
`YTAN-`, followed by the uppercase RFC 4648 Base32 encoding of exactly 16
bytes, without padding. The encoded payload is exactly 26 characters. A parser
must decode and re-encode it and require byte-for-byte equality, which also
rejects a non-canonical final symbol.

`issued_at` and `expires_at` are exactly UTC RFC 3339 at whole-second
precision: `YYYY-MM-DDTHH:MM:SSZ`. Offsets and fractional seconds are rejected.
Expiry is strictly after issue time, and the interval is no longer than five
minutes.

`key_generation` is exactly `YTAG-` plus the 20-digit revision in `1..256`,
equal to `registry_revision`. Plan, account, project, project-key, and
digest strings retain the canonical constraints of the mutation plan and
project policy. Every SHA-256 value is 64 lowercase hexadecimal characters.

## JSON encodings

The unsigned bytes signed by the helper are compact UTF-8 JSON with these
fields in this exact order:

1. `schema_version`
2. `receipt_id`
3. `nonce`
4. `challenge_sha256`
5. `registry_revision`
6. `authorization_context_sha256`
7. `plan_id`
8. `plan_sha256`
9. `profile_identity_sha256`
10. `account_id`
11. `project_id`
12. `project_key`
13. `schema_sha256`
14. `request_sha256`
15. `expected_sha256`
16. `issued_at`
17. `expires_at`
18. `key_generation`
19. `key_fingerprint_sha256`

`approval.SigningBytes` is the sole Go encoder for that representation. The
`challenge_sha256` is lowercase SHA-256 over the exact 32-byte request
challenge, so an outer-frame challenge splice invalidates the signed receipt.
The signed receipt returned by `approval.ReceiptBytes` appends `signature` as
field 20. `approval.ReceiptDigestSHA256` is lowercase SHA-256 hex over those
complete signed receipt bytes, including the signature text.

`approval.ParseReceiptBytes` accepts only that canonical signed encoding. It
rejects a non-object top level, absent, duplicate, or unknown fields, alternate
field order/escaping/whitespace, malformed values, and all trailing data.

## Signature and public key

Signatures use ECDSA with NIST P-256 and SHA-256. The wire signature is one
strict ASN.1 DER `SEQUENCE` of two minimally encoded positive `INTEGER` values
`r` and `s`, with `1 <= r < P-256.N` and
`1 <= s <= floor(P-256.N/2)`. The low-S rule gives each mathematical ECDSA
signature one receipt encoding. A future helper must normalize signer output
with `s = min(s, N-s)` before base64url encoding and calculating the full
receipt digest. There are no trailing bytes. Receipt JSON carries those DER
bytes as RFC 4648 base64url without `=` padding. Parsers decode and re-encode
both DER and base64url and require exact equality.

The native verifier's bounded internal equivalent-signature compatibility path
is specified in the [native boundary](gate1a-native-boundary.md). It does not
relax this low-S wire grammar or change the signed bytes or expected key.

The public-key interchange form is exactly the 65-byte uncompressed ANSI X9.63
point `0x04 || X || Y`, and the point must lie on P-256. Its DER SubjectPublicKeyInfo
form is exactly the following 26-byte prefix followed by that X9.63 point:

```text
3059301306072a8648ce3d020106082a8648ce3d030107034200
```

The resulting SPKI is exactly 91 bytes. `key_fingerprint_sha256` is lowercase
SHA-256 hex over those exact 91 DER bytes.

## Fixtures

Current receipt-schema-v3 positives and literal revision-boundary vectors live
under [`testdata/gate1a-v3/`](../testdata/gate1a-v3/README.md). Historical receipt-v2
rejection fixtures and unchanged shared plans, keys, signatures, display, and
IPC request/error frames live under [`testdata/gate1a/`](../testdata/gate1a/README.md).
Test callers select the version explicitly; a missing current fixture never
falls back to a historical one. Text fixture files end
with one LF for source-control portability; the JSON values referenced by the
protocol are the file contents without that final fixture LF. Hex files encode
the named binary value in lowercase without separators, again followed by one
fixture LF.

The display vector pairs `display.hex` with `display.escaped.txt` and its
SHA-256 digest. The signature vector intentionally uses `r=1, s=2` to pin DER
and base64url codecs; it is not a signature over `signing.json`.
