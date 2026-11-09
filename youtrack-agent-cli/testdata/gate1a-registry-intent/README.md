# Registry intent and supplied-core binding fixtures

Test-only prerequisite evidence. These vectors exercise no production registry
codec, coordinator, Keychain operation, signing UI, transport, or authority.
The [registry protocol](../../docs/gate1a-registry-protocol.md#state-derivation)
defines the intent bytes; its coordinator section defines the binding.

## Scope

The corpus contains seven positives (five core-linked scenarios and standalone
1-second/300-second lifetime boundaries) and 52 negatives. Rejection classes are
test-only `canonical_encoding`, `bounds_grammar`, `temporal`, `digest_domain`,
and `intent_binding`; they add no CLI error or authority state.

The authoritative parser input is `raw_hex`, decoded directly to bytes. This
preserves malformed UTF-8 rather than silently replacing it during JSON/string
conversion. A leading UTF-8 BOM is rejected as `canonical_encoding`; decoding
must preserve the original bytes rather than silently stripping the BOM.
Intent parsing enforces the 1,024-byte cap, exact ordered fields,
canonical primitive encodings, and a positive lifetime of at most 300 seconds.
The digest covers `YTA-REGISTRY-INTENT-V1`, a NUL byte, then the exact intent.

Core-linked cases refer to the existing five independently validated transcripts
in [the core corpus](../gate1a-registry/README.md). Consumers validate the referenced
prefix and transcript before checking intent or binding. Unknown or invalid
references are fixture-integrity failures, not new CLI error codes. The original
core corpus and generator are unchanged.

Binding compares only transition, artifact descriptor, decoded nonce/challenge,
and expiry. It does not add a requested-time equality requirement. Existing core
requests use the full 300-second window, so these linked positives share issue
times; an earlier intent would exceed its lifetime. Unequal-issue positive
coverage is deferred until a separately reviewed shorter-window core exists.

Standalone intent cases cover lifetime boundaries without claiming a complete
ceremony. The fixed schema cannot produce a meaningful valid 1,024-byte intent:
same-shape malformed inputs at 1,024 and 1,025 bytes test rejection precedence,
not an allocation guarantee or a fabricated maximum-valid object.

## Reproduction

From the repository root, run the original generator check before the dependent
supplemental check:

```sh
go run ./testdata/gate1a-registry/generate.go -check
go run ./testdata/gate1a-registry-intent/generate.go -check
go test -race ./internal/approval -run RegistryIntent
swift test --package-path native/macos/ApprovalProtocol --filter registryIntent
```

The generator uses only public deterministic test data. Go and Swift consumers
independently pin required IDs, reasons and positive expectations; generated
metadata is not the sole oracle. These checks establish fixture consistency and
test-oracle conformance, not coverage of a future production intent parser.

## Still pending

The [registry-active supplement](../gate1a-registry-active/README.md) checks
supplied active bytes against these validated intent fixtures. This is offline
fixture consistency, not coordinator acquisition or actual execution ordering.

Supplied matching bytes cannot prove random freshness, an intent created before
mutable authority reads, coordinator acquisition, live ownership, uninterrupted
peer authentication, time-of-use checks, or quiescence. Alternative revision-3
core scenarios reuse a synthetic challenge; no nonce uniqueness or freshness
claim is made. Coordinator binding and runtime ordering remain separate work,
as do commit/reconciliation, native projections, journal v2 and guarded-write
Gates. Production approval remains unsupported.
