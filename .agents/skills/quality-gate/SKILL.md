---
name: quality-gate
description: Run the agent-clis validation gate — formatting, vet, race tests, and the agent-harness checks — and report exactly what passed and what was not run. Use before pushing, before opening a PR, or when asked whether the repository is green.
---

# Run agent-clis Quality Gate

Run in order inside every changed module, and report each result. The CLI's
`AGENTS.md` lists its additional gates.

```bash
export GOWORK=off
gofmt -l $(git ls-files '*.go')
go vet ./...
go build ./...
go test -race ./...
```

Then, at the repository root, the agent harness whenever anything under
`.agents/` or any `<cli>/rules/` changed:

```bash
python3 ~/.agents/compiler.py --source .agents --root . --scope project
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

The compiler is the machine-local global harness, not a vendored copy. If
`~/.agents/compiler.py` is missing, report that rather than skipping the check
silently.

Finally confirm the harness invariants:

- `git status --porcelain` is clean after compiling.
- `git ls-files .claude .codex` returns nothing.

Report the exact command and outcome for each. Name anything you did not run
and say why. Never describe an untouched surface as green, and never report a
gate as passing on the strength of a previous run.

Do not install or uninstall the Git hook — `.githooks/install` mutates local
Git config and is the developer's decision.
