# Architecture

`youtrack-agent-cli` is a single Go binary built for machine callers.

## Package direction

- `cmd/youtrack-agent-cli`: process entry, panic recovery, exit delivery only.
- `internal/cli`: Cobra wiring and output selection; never imports `net/http`.
- `internal/application`: operation orchestration and one-shot write lifecycle.
- `internal/profile`, `internal/auth`, `internal/writepolicy`: non-secret profile,
  credential boundary, and exact project policy respectively.
- `internal/youtrack`: fixed-origin YouTrack reads/writes; never imports auth or
  profile storage.
- `internal/skills`: manifest-owned Codex/Claude skill installation only.
- `internal/output`: compact renderers and JSON v1 envelope.
- `internal/errx`: dependency-free typed error contract.

Dependencies point from CLI/orchestration toward domain boundaries and finally
`errx`; never introduce a storage/client cycle. Every I/O function accepts
`context.Context` first. Remote pagination contributes only an opaque cursor;
the client rebuilds a fixed-origin, fixed-operation URL.

## Streams and mutations

In JSON mode stdout contains exactly one envelope. Logs, warnings, and prompts
use stderr. Text, raw, and explicit help are caller-selected exceptions.

Every network operation resolves a named profile from an explicit flag or an
operator-saved role default on supported commands. Defaults live beside the
user profile registry, never in repository state. Application methods still
take explicit names; saved selection carries an identity guard through context
and rechecks it under the client profile lock before credentials. `inspect` reads
hold that lock shared through a read-only descriptor and take the writable one
only when that cannot serve them, as for a refresh. Reads are bounded. Preparation is
network-free. Native `mutation` requires trusted user presence and remains
closed until its authority gates pass. Separate `operator-write` binds declared
operator confirmation to the exact stored plan, not independently verified
human presence. Its private local attempt ledger is separate from native
authority and prevents cooperating replay. Apply dispatches at most one mutation
per plan. Ambiguous results use bounded reads and are never replayed automatically.
