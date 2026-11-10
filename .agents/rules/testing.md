# Testing

Use table-driven tests with named `t.Run` cases and test boundaries rather than
private implementation detail.

- HTTP: `httptest`; never call live YouTrack.
- Secret store and approval: injected fakes; never touch real credentials or UI.
- Filesystem: `t.TempDir()`; never write the developer's home.
- Environment: `t.Setenv()`.

Cover fixed-origin redirect refusal, bounded compressed/decompressed bodies,
non-JSON errors, opaque pagination reconstruction, explicit-profile failures,
exact reads, search limits, untrusted-content inertness, the six-tool MCP
allowlist and mutation-tool refusal, offline prepare with a network trap,
receipt/hash/precondition mismatch, one-shot dispatch, crash recovery, and
ambiguous reconciliation without replay.

Operator tests also prove zero secret/network access on offline prepare or
missing/mismatched confirmation; distinct issue/project/global field IDs; stale
touched-schema refusal; durable exclusive/concurrent claim protection; and
verified-write local/output failures distinct from unknown outcomes. Capabilities
report configuration, never server permission.

Exit codes and envelope shape are contract tests. Before review, inside each
changed module with `GOWORK=off`, run `gofmt -l $(git ls-files '*.go')` (it must
print nothing), `go vet ./...`, and `go test -race ./...`.
