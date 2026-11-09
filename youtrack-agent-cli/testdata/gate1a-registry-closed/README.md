# Registry closed retained-candidate binding fixtures

Partial, test-only prerequisite evidence. This supplement covers supplied closed
bytes for a registry operation with a retained candidate, not a complete closed
validator, native execution or production authority. Approval remains unsupported.

## Scope

The corpus has 16 positives (five source core scenarios, each with both supplied
registry outcome labels, plus six timestamp-grammar fixtures) and 91 negatives.

The [registry protocol](../../docs/gate1a-registry-protocol.md#helper-owned-apply-authority-coordinator)
defines the twelve ordered fields and 4,096-byte raw cap. This subset requires
`registry_commit`, `normal` close mode, null permit/receipt/journal fields and a
retained candidate digest. The two accepted outcome labels are
`registry_committed` and `registry_not_committed`. They are supplied fixture
labels: no test proves a write happened or that an exact native read found
absence. Neither label grants a send, signature, retry or cleanup capability.

The input is authoritative `raw_hex`, preserving malformed UTF-8 and BOM bytes.
The target raw cap is checked before parsing; canonical bytes require exact
field order, primitive spelling, lossless UTF-8 and byte-for-byte re-encoding.
The malformed 4,096/4,097-byte fixtures test refusal precedence, not a maximum
valid record or native allocation guarantee. Lease IDs reuse the existing
canonical Base32 primitive; body-case vectors preserve the exact `YTAL-` prefix.

Two distinct domains are independently checked:

- Closed digest: SHA-256 of `YTA-APPLY-COORDINATOR-CLOSED-V1`, NUL, exact closed bytes.
- Candidate link: SHA-256 of `YTA-REGISTRY-COMMIT-V1`, NUL, exact complete retained record.

The candidate link is not a plain predecessor hash. Closed bytes do not contain
the candidate record itself. Its identity is derived through the referenced
active → intent → core chain, with no second independently selectable candidate.
Consumers validate that complete supplied chain and its signed prefix before
the target as **offline fixture integrity**, not runtime ordering or permission
to read the registry before acquisition. Broken references produce fixed
fixture errors, not successful negative verdicts or new CLI error codes.

Bindings check the exact lease, validated active digest and candidate digest
within the registry branch. `closed_at` is checked for whole-second UTC grammar
only. Timestamp-grammar fixtures cover years `0000`, `0001` and `9999`, Gregorian
leap days and a date in the historical Gregorian cutover interval. These check
the four-digit proleptic Gregorian grammar, not valid historical closure
chronology. Neither these dates nor the ordinary post-creation fixture dates
define chronology, prove trusted time or establish a live temporal policy.

Sources are hash-linked to the unchanged core, intent and active corpora.
Generator data is deterministic and public, not fresh random or native evidence.
Both consumers independently pin positive bytes/digests and negative IDs/reasons;
generator metadata alone is not the oracle. Negative verdict classes are
test-only `canonical_encoding`, `bounds_grammar`, `digest_domain`, `closed_binding`.

## Reproduction

From the repository root:

```sh
go run ./testdata/gate1a-registry/generate.go -check
go run ./testdata/gate1a-registry-intent/generate.go -check
go run ./testdata/gate1a-registry-active/generate.go -check
go run ./testdata/gate1a-registry-closed/generate.go -check
go test -race ./internal/approval -run RegistryClosed
swift test --package-path native/macos/ApprovalProtocol --filter registryClosed
```

## Not covered

The corpus rejects a null candidate digest with `registry_committed` as
`bounds_grammar`. A null digest with `registry_not_committed` remains outside
this retained-candidate subset; that scope refusal is not proof of a legal abort.
Non-string, non-null candidate values are canonical-encoding refusals even with
an apply operation or unknown close mode, before branch scope or grammar checks.

The legal pre-candidate null-digest abort, registry ambiguous-outcome handling,
apply and permit branches are outside this retained-candidate subset. They are
not asserted to be globally invalid. Separate scope errors in a test helper
mean only that this fixture oracle cannot evaluate that branch.

Actual outcome reconciliation, owner provenance, irreversible quiescence,
durable close publication, native projections, inventory/classification,
acquisition, cleanup, capacity and crash schedules remain pending. No Boolean
fixture declaration substitutes for these proofs. This linked supplement does
not satisfy the complete conformance prerequisite. Production registry codecs,
journal v2, guarded-write activation and distribution remain separate work.
