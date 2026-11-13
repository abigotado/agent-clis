# Contributing

This repository is a monorepo of Go CLIs consumed primarily by agents. Each CLI
is its own module in its own directory, and there is no root module.

For `youtrack-agent-cli`, preserve the JSON v1 envelope, stable exit codes,
explicit profile selection, bounded operations, and one-shot mutation semantics.

Read the root `AGENTS.md`, the matching `.agents/rules/` files, and
`youtrack-agent-cli/AGENTS.md` before editing. Keep package dependencies directed toward `internal/errx`; commands wire behavior but
do not issue HTTP directly. Test HTTP with `httptest`, credentials with a fake
store, and filesystem behavior with `t.TempDir()`.

Generated command and contract references are updated inside the module with:

```bash
GOWORK=off go generate ./...
```

The source Agent Skill lives only under
`youtrack-agent-cli/assets/skills/youtrack-agent/`.
Installation tests must never touch the developer's home directory.

Before review, run inside each changed module:

```bash
export GOWORK=off
gofmt -l $(git ls-files '*.go')
go vet ./...
go test -race ./...
```

For `core`, the same three commands run inside `core/`, plus `go vet` for each
target OS and a cgo-free test run:

```bash
cd core
export GOWORK=off
for os in linux darwin windows; do GOOS=$os go vet ./...; done
CGO_ENABLED=0 go test ./...
```

The real backends have integration tests behind build tags. Each needs its own
operating system, and each fails instead of skipping when its variable is set:

| OS | Tag | Variable |
| --- | --- | --- |
| macOS | `keychainintegration` | `SECRETSTORE_REQUIRE_KEYCHAIN=1` |
| Windows | `credmanintegration` | `SECRETSTORE_REQUIRE_CREDMAN=1` |
| Linux | `secretserviceintegration` | `SECRETSTORE_REQUIRE_SECRET_SERVICE=1` |

```bash
cd core
SECRETSTORE_REQUIRE_KEYCHAIN=1 go test -race -count=1 -timeout 20m -v \
  -tags keychainintegration ./secretstore/...
```

The keychain run needs `-timeout 20m`: it builds and signs helper binaries.
`go vet -tags <tag> ./...` covers the tagged files on their own OS. CI
(`core-macos`, `core-windows`, `core-linux`) runs these with the variables set.
Without the variable a test skips when its environment is missing.

One macOS row is opt-in and local only; CI never runs it. Setting
`SECRETSTORE_CODEX_SANDBOX=/path/to/codex` runs
`TestKeychainSaveInReadOnlySandbox/Save_under_codex_sandbox_read-only_is_read-only`,
which saves under Codex's read-only sandbox. The read-only policy is set on the
command line and no Codex configuration is changed:

```bash
cd core
SECRETSTORE_REQUIRE_KEYCHAIN=1 SECRETSTORE_CODEX_SANDBOX=/path/to/codex \
  go test -race -count=1 -v -tags keychainintegration \
  -run 'TestKeychainSaveInReadOnlySandbox/Save_under_codex_sandbox_read-only_is_read-only' ./secretstore
```

Recorded measurement: the macOS keychain interaction flag is process-scoped. It
was measured in an Aqua GUI session (macOS 26.6.2, 2026-11-13) as well as from a
terminal session.

Before a pull request, run the hygiene check from the repository root. It scans
the tracked files under `core/` and the commit messages that touch it for local
paths, private hosts, token shapes, private keys and assistant attribution:

```bash
.github/scripts/core-hygiene.sh origin/main..HEAD
ruby .github/scripts/core-hygiene_test.rb
```

and at the repository root:

```bash
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

Do not commit `.claude/`, `.codex/`, credentials, generated build output, or
account-specific MCP configuration. Never broaden the fixed REST/MCP surface
through an arbitrary method/path escape hatch.
