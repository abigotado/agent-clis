# Registry active and supplied-intent binding fixtures

Partial, test-only prerequisite evidence. These vectors do not exercise a
production registry parser, acquisition, coordinator classifier, native helper,
Keychain, or transport. Production approval remains unsupported.

## Scope

The corpus contains seven named positives with six unique byte sequences and
82 negatives. Five positives are linked core scenarios; `ttl-1s` covers the
lower lifetime boundary. `ttl-600s` is a named alias of `active-enroll1`, not
additional unique coverage: the five linked scenarios already use 600 seconds.

The [registry protocol](../../docs/gate1a-registry-protocol.md#helper-owned-apply-authority-coordinator)
defines the ordered active fields. This supplement covers only the
`registry_commit` branch, not `apply`, permits or closed records. Required
registry fields and exact nullability are validated independently in Go and
Swift. Active lifetime is 1 through 600 whole seconds, inclusive.

`raw_hex` retains the exact input bytes, including malformed UTF-8 and a leading
BOM. Consumers check the 4,096-byte cap before active parsing, preserve the
original UTF-8 bytes and require canonical byte-for-byte re-encoding. The
domain-separated digest is SHA-256 of `YTA-APPLY-COORDINATOR-ACTIVE-V1`, NUL,
then those exact bytes. The malformed 4,096/4,097-byte fixtures test refusal
precedence, not maximum valid objects or native allocation guarantees.

Source hashes bind the unchanged [core](../gate1a-registry/README.md) and
[intent](../gate1a-registry-intent/README.md) corpora. The generator uses only
deterministic public fixture values; they are not fresh random identities or
credentials. Consumers independently pin positive expectations and negative
IDs/reasons rather than accepting generator metadata as their oracle.

Before validating active bytes, the fixture harness resolves and validates the
linked core, prefix and intent. Broken references are fixture-integrity errors.
This offline dependency order is **not** the runtime order: the actual helper
must acquire active before any ledger read or proposal validation.

Supplied binding checks only the validated intent digest and artifact descriptor.
It does not compare the coordinator session to the ceremony nonce, or require
active expiry to equal intent expiry. Positive unequal-expiry data guards against
inventing that extra equality. The CLI audit digest is syntactically validated;
no fixture proves its provenance, live peer authentication or ownership.

Refusals use the test-only classes `canonical_encoding`, `bounds_grammar`,
`temporal`, `digest_domain` and `active_binding`. They are not public CLI errors.

## Reproduction

From the repository root:

```sh
go run ./testdata/gate1a-registry/generate.go -check
go run ./testdata/gate1a-registry-intent/generate.go -check
go run ./testdata/gate1a-registry-active/generate.go -check
go test -race ./internal/approval -run 'Registry(Intent|Active)'
swift test --package-path native/macos/ApprovalProtocol --filter 'registry(Intent|Active)'
```

## Still pending

The [retained-candidate closed supplement](../gate1a-registry-closed/README.md)
checks supplied closed bytes against these validated active fixtures. It does
not establish native ownership, an actual commit outcome or durable closure.

This linked supplemental directory does not satisfy the complete shared
conformance prerequisite by itself. Inventory/classification, typed native
projections, actual acquisition and pre-read ordering, one-shot add outcomes,
uninterrupted ownership, quiescence, quarantine, cleanup and capacity schedules
remain pending. A supplied `clear` flag or synthetic trace is not authority.
Commit/reconciliation, production registry integration, journal v2 and guarded
write activation remain separate work. No live operation is performed here.
