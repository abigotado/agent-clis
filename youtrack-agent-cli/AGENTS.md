# youtrack-agent-cli agent rules

`youtrack-agent-cli` is a single Go binary that manages YouTrack. Its command
surface is a machine contract. `README.md` here is the product reference. The
shared rules in the root [`AGENTS.md`](../AGENTS.md) apply as well.

## Rule router

| Surface | Required rules |
| --- | --- |
| Package boundaries, a new package, or a dependency change | [architecture](rules/architecture.md) |
| Exit codes, the JSON envelope, flag names, or output format | [architecture](rules/architecture.md), [CLI contract](rules/cli-contract.md) |
| Any Go code | [Go style](../.agents/rules/go-style.md) |
| Any behavior change | [testing](../.agents/rules/testing.md) |
| Credentials, auth, request construction, logging, or error formatting | [secrets](../.agents/rules/secrets.md) |

## Dependency direction

`internal/cli` never calls `net/http`. `internal/youtrack` never formats
user-facing text and never imports `internal/auth`. `internal/errx` imports
nothing from this module. Anything user-facing goes through `internal/output`.
Check this with `go list -deps` or an import grep, not by eye.

The contract's single source is `internal/errx`. `docs/contract.md` and
`assets/skills/youtrack-agent/reference/contract.md` are generated from it.

## Gates

Run these inside this directory, with `GOWORK=off`, for what the change touches:

```bash
export GOWORK=off
gofmt -l $(git ls-files '*.go')
go vet ./...
go test -race ./...
go generate ./...                # the result must be committed
swift test --package-path native/macos/ApprovalProtocol
go run ./testdata/gate1a-registry/generate.go -check   # and the other five fixtures
```

`go vet ./...` skips `testdata/`, so a change to imports needs the fixture
checks. The Homebrew offline build is `go run ./tools/homebrewcheck`. The
release policy guard runs from the repository root.

## Never

- In JSON mode, write to stdout anything but the response envelope. Text, raw,
  and explicit help output are caller-selected exceptions.
- Renumber an exit code or rename an envelope field without treating it as a
  breaking change.
