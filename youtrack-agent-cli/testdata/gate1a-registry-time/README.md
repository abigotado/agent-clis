# Registry timestamp interoperability supplement

This test-only corpus fixes the calendar interpretation used by the registry
oracles: exactly four-digit years `0000`–`9999`, whole-second UTC, and the
proleptic Gregorian calendar, without a historical calendar cutover. Unix
seconds are signed integer scalars. These fixtures do not introduce a
production timestamp API or change receipt timestamp policy.

The corpus contains 27 timestamp cases (10 valid, 17 invalid), 9 exact interval
cases, and 7 complete registry-active fixtures (3 accepted, 4 refused).
Both Go and Swift independently pin IDs, input strings, expected signed seconds,
intervals, and complete active bytes and domain-separated hashes. The generator
stores literal expected seconds; it does not ask either consumer to generate its
own expectations. The full-range interval uses scalar subtraction rather than a
bounded nanosecond duration, which would saturate across 10,000 years.

The active fixtures derive only `created_at` and `expires_at` from the unchanged
`active-enroll1` source, recomputing the exact active-domain hash. They exercise
the existing full supplied-fixture validator and linked intent/core checks,
including Gregorian leap rules, the 1582 calendar gap, and 600/601-second and
reversed intervals. Historical dates are calendar/interval regression evidence,
not claims of valid live chronology, freshness, ownership, or authorization.
Scalar invalid text is tested directly; it need not be a canonical JSON value.

The core, intent, and active source corpus hashes are frozen in the supplement
and independently pinned by the consumers. No prior corpus is regenerated.

From the repository root:

```sh
go run ./testdata/gate1a-registry-time/generate.go
go run ./testdata/gate1a-registry-time/generate.go -check
go test ./internal/approval -run RegistryTime
swift test --package-path native/macos/ApprovalProtocol --filter registryTime
```
