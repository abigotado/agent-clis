# Registry transcript core conformance corpus

**Partial prerequisite evidence only. Protected registry integration remains
blocked.** These synthetic vectors do not activate approval, writes, a native
helper, or a release. The [registry protocol](../../docs/gate1a-registry-protocol.md)
is the normative source; this fixture container is not a new authority object.

## Scope

The core covers supplied request, recovery evidence when applicable, unsigned
and signed proposal, acceptance, final body, and stored-record bytes. It retains
domain-prefixed signing inputs, hashes, public SPKIs, signatures, predecessor
records, and explicit expected generation statuses.

The primary scenario is `enroll -> rotate -> revoke -> recover`: revisions 1,
2, 3, and 4. A separate scenario recovers from the active revision-2 state on
the declared missing-key basis. Its revision 3 is an alternative history, not
a fork accepted into the primary ledger. Key uniqueness is enforced within a
history, not across independent fixture scenarios.

Three evidence levels must not be confused:

1. A complete supplied core transcript can establish consistency among its
   canonical bytes, digests, signatures, tuples, times, and resulting state.
2. Supplied stored-record replay verifies signed declarations, predecessor
   linkage and derived state, not protected-helper provenance. Stored records do
   not retain full requests, proposals, acceptances or recovery evidence; their
   digests do not reconstruct those missing objects.
3. Neither test proves actual Keychain absence, trusted user presence, live peer
   authentication, Secure Enclave use, coordinator ownership or quiescence.
   A signed synthetic missing-item declaration is not a native lookup result.

The pure Go and Swift supplied-history verifiers now consume stored-record
fixtures at their production-code boundary, without replacing the independent
test-only transcript oracles. They check only a supplied genesis-to-tip prefix:
even a valid nonempty prefix cannot establish the complete or current protected
registry. The result is not an authority binding or a signing/send capability.
See the [offline verification contract](../../docs/gate1a-registry-protocol.md#offline-verification-of-a-supplied-history).

The pure supplied-ceremony verifiers additionally consume the complete core
transcripts against a supplied prefix, checking proposal signatures, all
transcript bindings, exact request expiry and recovery declarations. The
production-boundary tests retain independent test-only transcript oracles. Their
results remain caller-supplied consistency only, never native lookup evidence,
protected-root continuity, user intent or runtime authority. See the
[supplied-ceremony contract](../../docs/gate1a-registry-protocol.md#offline-verification-of-a-supplied-ceremony).

All times are synthetic historical transcript times. Passing these tests cannot
make an expired transcript live or grant a new confirmation/send capability.

## Reproducibility and independent checks

`generate.go` is a build-ignored test-data generator. Its public fixture scalars
and deterministic signing nonces are deliberately unsafe for real signing.
They are not credentials or an enrolled authorization root. Never use them for
production signatures. The generator imports neither registry parsers nor the
test consumers; generated results are not themselves an oracle.

From the repository root:

```sh
go run ./testdata/gate1a-registry/generate.go
go run ./testdata/gate1a-registry/generate.go -check
go test ./internal/approval -run 'TestSharedRegistry'
go test ./internal/approval -run 'TestSuppliedRegistry'
swift test --package-path native/macos/ApprovalProtocol --filter 'sharedRegistry'
swift test --package-path native/macos/ApprovalProtocol --filter 'suppliedRegistry'
```

Go and Swift independently validate the protocol schemas and recompute exact
signing inputs and digests, using their existing strict P-256 primitives. They
pin the required scenarios and expected states independently of generated
metadata. Domain NUL bytes are preserved in hexadecimal signing-input fields.
The predecessor digest is plain SHA-256 of the exact prior complete record,
not the domain-separated commit-candidate digest.
In each positive manifest, `predecessor_digest` hashes that positive's own
complete record, ready for use as the next record's predecessor value.

The fixture container uses JSON strings for exact embedded object bytes and
has a source-control final LF. Embedded protocol objects have no added LF,
whitespace or escaping. Container arrays and metadata are not protocol fields.

Negatives carry a literal `reason_class` checked identically by both languages:
`canonical_encoding`, `bounds_grammar`, `digest_domain`, `signature`, `temporal`,
`recovery_eligibility`, or `state_transition`. These are test-only categories,
not public CLI errors or exit codes. Negative transcripts must differ from
their named base. Later semantic faults are re-signed and have dependent hashes
recomputed so an earlier accidental signature/digest failure cannot satisfy a
state-transition expectation. Positive manifest comparisons are separate from
negative validation; stale baseline manifest metadata is not a rejection oracle.
These seven categories belong to the independent test-only transcript oracles.
Production verifiers report only static bounds, encoding, grammar or verification
phases; their tests do not impose the oracle's finer composite-fault taxonomy.
All raw caps and canonical/primitive checks run before cryptographic work.
The complete supplied prefix is then validated before the candidate's digest,
signature, temporal, recovery-eligibility and state checks. After prefix
validation, a recovery candidate must supply recovery evidence before candidate
digest checks begin. Only presence is checked at this stage; evidence contents
are checked after signatures and time. Thus missing evidence plus a bad candidate
digest reports `recovery_eligibility`, while an invalid prefix still wins.
A recovery candidate
cannot repair an invalid prefix. Composite faults must not imply a universal
cross-prefix/candidate error priority that the corpus does not test.

OSStatus vectors describe canonical signed-int32 parsing and exact re-encoding,
including numeric absence `-25300`. Their fixture-consistency tests use test-only
reference parsers and independently pinned raw-value sets. There is no production
OSStatus parser here: these tests cannot catch defects in a future implementation
until the vectors are wired to that implementation. They do not classify arbitrary
statuses as success or satisfy the coordinator-result classification requirement.

## Remaining prerequisite inventory

| Surface | Status |
| --- | --- |
| Core transcript bytes, signatures, hashes, history and state | This corpus; synthetic data only |
| Offline supplied stored-history verification | Go and Swift production-code boundary tests; no protected completeness, native provenance or authority |
| Offline supplied complete-ceremony verification | Go and Swift production-code boundary tests; exact transcript bindings and recovery declarations, no native eligibility, freshness or authority |
| OSStatus scalar grammar | Fixture consistency only; no production parser coverage or native status classification |
| Registry intent canonical bytes/hash and supplied intent/request binding | [Supplemental fixture consistency](../gate1a-registry-intent/README.md); no production parser coverage |
| Registry-commit active canonical bytes/hash and supplied active/intent binding | [Supplemental fixture consistency](../gate1a-registry-active/README.md); no acquisition or ownership evidence |
| Registry retained-candidate closed bytes/hash and supplied links | [Supplemental fixture consistency](../gate1a-registry-closed/README.md); not native outcome, quiescence or durable-close evidence |
| Registry timestamp grammar and elapsed seconds | [Shared calendar fixtures](../gate1a-registry-time/README.md); synthetic parsing/arithmetic checks, not trusted time or acquisition evidence |
| Coordinator acquisition binding and actual pre-read intent/runtime ordering | Pending; [state derivation](../../docs/gate1a-registry-protocol.md#state-derivation) |
| Commit authorization and ambiguous-result reconciliation | Pending; [commit contract](../../docs/gate1a-registry-protocol.md#commit-and-ambiguous-result-reconciliation) |
| Typed Security.framework dictionaries/results and persistent-reference provenance | Pending; [native projections](../../docs/gate1a-registry-protocol.md#exact-securityframework-dictionaries-and-projections) |
| Coordinator acquisition, exclusion, quiescence, quarantine, cleanup and classification | Pending; [coordinator contract](../../docs/gate1a-registry-protocol.md#helper-owned-apply-authority-coordinator) |
| Native anti-replay/capacity schedules and signed execution evidence | Pending; [conformance requirements](../../docs/gate1a-registry-protocol.md#cross-language-conformance-evidence) |

This directory does **not** satisfy the complete conformance prerequisite.
Protected registry storage/replay integration, closed authority-evidence
verification, durable journal confirmation, protected native integration,
guarded-write Gates and distribution remain separate work. Pure supplied-history
and supplied-ceremony verification are permitted as prerequisites only; neither
is wired into any command, journal transition or authority consumer. `approval.Unsupported`,
journal v1/v2 behavior, production package dependencies and the CLI contract
are unchanged.

## Native signature compatibility regression

On macOS 26.6.2 / Apple Swift 6.3.3, direct CryptoKit verification rejects the
final new-key signature in `recovery-continuity-success` before the intended
`recovery_eligibility` check. The public verifier now handles this observed
representation-dependent incompatibility, and all 121 core negative vectors
reach their expected rejection classes in both consumers.

Standalone verification outside either test consumer reproduced the disagreement:

| Verifier on the same exact message, public key and DER signature | Result |
| --- | --- |
| Go 1.27.1 `ecdsa.VerifyASN1` | Valid |
| Node / OpenSSL 3.0.16 `crypto.verify` | Valid |
| CryptoKit, both message and SHA-256 digest overloads | Invalid |
| Ruby / system LibreSSL 3.3.6 | Verification error |

The domain-prefixed message is 1,855 bytes and its SHA-256 is
`953be2f28a5e846a47fff27d61cc0514fedb34e7888d1536adea8172974c9ec5`.
CryptoKit's decoded signature scalars match the DER bytes, and its public key
matches the synthetic scalar-3 public key. A fresh CryptoKit signature on that
message verifies. These observations localize an interoperability disagreement;
they do not establish a root cause or a general platform vulnerability.

The same CryptoKit key/message accepts the mathematically equivalent `(r, N-s)`
signature. The public verifier first validates the original strict low-S DER,
then verifies it normally. Only a false result permits one verification of an
ephemeral equivalent representation with the same backend, key and message.
Negating the ECDSA verification point preserves its x-coordinate. The twin is
internal only: it is never accepted as a wire `P256Signature`, stored, returned,
or granted authority. If CryptoKit cannot construct only the alternate signature
after the original verification returned false, the result stays false. Original
input/key construction and internal DER invariant errors retain their closed
error behavior and do not trigger another attempt.

The fixed public scalars and nonce deliberately preserve the known valid-signature
regression. Changing the nonce can avoid this input, but does not repair native
verification of the original signature. Sampling other keys/nonces with no
failures does not prove impossibility for all such keys. The compatibility path
has a fixed ceiling of two verifications even on a non-matching signature.

The original fixture and strict expected reason remain intact. Dedicated
public-API tests pin the exact message hash, key and signature, reject high-S
ingress through both parser and verifier, and reject changed message/key/r/s.
They assert correctness rather than requiring the native defect to persist on
future operating systems. For this earlier public-API regression, the equivalent
representation is checked by CryptoKit again: there is no backend switch,
skipped test, or weakened reason assertion. This compatibility correction does
not complete the remaining production prerequisites above.

The supplied-history/ceremony stress tests construct keys from known public
revision scalars and ask CryptoKit to sign with a fresh nonce for each signature.
Here, fresh key construction creates a new key object with the revision's fixed
public scalar. The scalar-9 native rejection below arose on this exact fresh
signing path before its bytes were frozen as a regression control.

A historical CryptoKit signature capture on 2026-10-05 with macOS 26.6.2 (build
25G83) / Apple Swift 6.3.3 reproduced the same disagreement for public fixture
scalar 9: the exact 1,795-byte message has SHA-256
`0d76c17d481b96dcfb6c8bcf2ff3fae316858e0b0f6af5db7c3519eb655835ba`.
Independent Go verification accepted its original low-S DER and high-S twin,
while CryptoKit and Security rejected the original and accepted the twin,
including in a fresh process. Tests pin CryptoKit's raw scalars to the
independently Go-accepted DER fixture, excluding a DER-decoding mismatch for this
input; the internal cause remains unknown. The test-only control used by the
frozen fixture and fresh-signature paths checks bounded canonical DER, scalar
ranges and the exact public point, then permits one equivalent-twin verification
only after native rejection. Its verification is independent of production
codecs and verdicts, uses the same native backend and has a maximum
of two verification calls per control. A control's mathematical acceptance of
the high-S form does not admit it on the wire. Callers retain production grammar
and verification checks, including strict high-S refusal.

As defined by the [native-boundary ADR](../../docs/gate1a-native-boundary.md#consequences),
Go/Swift disagreement in public wire acceptance/rejection, decoded meaning,
final protocol verdicts or tamper-negative refusals is blocking. Direct native
verification and equivalent-twin outcomes are separate backend-health
diagnostics. An independently valid signature accepted through the bounded
same-backend path does not fail CI solely because the first native call rejected
it. This acceptance criterion does not establish a repaired native backend or
complete Gate 1A.

The public scalar-9 control is frozen verbatim in
[`signature-control.json`](signature-control.json). It is a standalone static
fixture, not generated by `generate.go`; the generator continues to own only
`corpus.json`. Its scalar is deliberately public synthetic test material and
must never be used for production signing. Both the
[Go standard-library oracle](../../internal/approval/registry_signature_control_test.go)
and the
[Swift signature-control tests](../../native/macos/ApprovalProtocol/Tests/ApprovalProtocolTests/RegistrySignatureControlTests.swift)
consume that exact file and independently pin the message length, SHA-256 and
scalar-9 public point. Go verifies both equivalent DER forms directly with
`ecdsa.VerifyASN1`, independently of the production low-S verifier and CryptoKit.
Both consumers check DER/raw-scalar correspondence and reject changed inputs;
Swift also retains twin arithmetic, malformed-input checks and production
high-S refusal.

The same Go oracle's `TestSharedRegistrySignatureControlSwiftScalarThree`
reads the existing `recovery-continuity-success` transcript from
[`corpus.json`](corpus.json) and pins the scalar-3 message, public key and both
DER forms used by the [Swift public-API regression tests](../../native/macos/ApprovalProtocol/Tests/ApprovalProtocolTests/P256CompatibilityTests.swift).
It verifies both mathematical forms directly with `ecdsa.VerifyASN1` and
`ecdsa.Verify`, rejects changed message/key/r/s, and separately requires
production low-S acceptance and high-S refusal. This proof uses existing corpus
bytes; no fixture regeneration is required. The focused Go command below runs
both scalar-3 and scalar-9 controls.

Every successful equivalent result from the Boolean control emits a fixed
`registry_signature_control_fallback` JSON event containing only `schema_version`,
`event` and `outcome: "equivalent"`. Separately, the frozen-fixture test emits two
`registry_signature_control_frozen` JSON rows, one for each low/high-S form,
with the schema version, public scalar 9, actual host OS version, direct native
acceptance Boolean and control outcome. These rows report observations without
requiring either a native rejection or an arbitrary fallback-rate threshold.
The control remains bounded to two calls using the same key, message and native
backend, and changed-input refusals remain mandatory.

The Go checks require at least Go 1.25.13, as declared in
[`go.mod`](../../go.mod). [CI](../../.github/workflows/go.yaml) reads that same
version through `go-version-file`.

From the repository root:

```sh
go test -race ./internal/approval -run '^TestSharedRegistrySignatureControl' -count=1
swift test --package-path native/macos/ApprovalProtocol --filter 'registrySignatureControl'
```

The dated native outcomes above are non-normative observations from that host.
The shared bytes define the regression control; future hosts may accept either
valid representation directly, and no test requires the historical rejection
to persist.
