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

and at the repository root:

```bash
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

Do not commit `.claude/`, `.codex/`, credentials, generated build output, or
account-specific MCP configuration. Never broaden the fixed REST/MCP surface
through an arbitrary method/path escape hatch.
