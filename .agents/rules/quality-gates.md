# Quality gates

## Pre-push hook

`.githooks/pre-push` runs, for every tracked `go.mod`: `gofmt -l` over the
module's tracked `.go` files (must be empty), then `go vet ./...`,
`go build ./...` and `go test -race ./...` with `GOWORK=off`. A checkout with no
tracked module fails. It gates each pushed tip, not the working tree: every
distinct tip is checked out into a temporary worktree (checkout hooks disabled)
and gated there, a ref deletion is a no-op, and anything it cannot resolve
fails, as does a tree without `.agents` (or with `.agents` as a symlink) or a harness interpreter that is not a real Python 3.8+ (`AGENT_HARNESS_PYTHON`). The compiler-mirror check reads the real checkout, so a tip whose
`.agents` differs from HEAD's, or a dirty `.agents`, is refused until that
branch is checked out clean. After that it runs the agent-harness checks. It is the
last check before a change leaves the machine.

Install it once per clone:

```bash
.githooks/install
```

This sets `core.hooksPath`. Installing only restores the repository's own gate,
so `.githooks/install` is in `allow` in `.agents/permissions.toml` and an agent
may run it in a new clone or worktree. Uninstalling removes the gate and stays
the developer's decision, never the agent's, which is why
`.githooks/uninstall` sits in `ask`.

A worktree whose config carries an inherited `core.hooksPath` needs
`git config --worktree core.hooksPath .githooks`: `.githooks/install` uses
`--local`, which the worktree value overrides. Without it the worktree can run
another checkout's hook.

`git push --no-verify` and `git config --local core.hooksPath` are denied; the
`--local` spelling stays denied even when it would point at `.githooks`, so the
two ways to restore the hook are `.githooks/install` and the `--worktree` form
above. The
`pre_push_guard` hook in `.agents/hooks.toml` is the real enforcement: prefix
rules cannot cover every spelling, so the guard parses the command. Do not work
around it — if the gate is wrong, fix the gate.

## Before finishing any change

Run the smallest validation that actually covers the touched surface, inside
each changed module:

```bash
export GOWORK=off
gofmt -l $(git ls-files '*.go')
go vet ./...
go test -race ./...
```

A CLI's `AGENTS.md` lists its additional gates. Report what you ran and what you
did not. Never describe an untouched surface as green.

## CI

`.github/workflows/ci.yaml` runs a `changes` job that selects the affected
modules, an always-on `repo` job, and one job per CLI. The single required check
is `ci-ok`, which needs every other job and fails on any failure or
cancellation, so a skipped module job cannot pass by accident.

`.github/scripts/verify-portable-release-policy.rb` takes two required arguments,
the GoReleaser config and the repository root, because a default root once let
it pass while scanning nothing:

```bash
ruby .github/scripts/verify-portable-release-policy.rb youtrack-agent-cli/.goreleaser.yaml .
```

## Harness

The agent harness is compiled, not hand-written. `.claude/` and `.codex/` are
generated and git-ignored; editing them directly is always wrong and the edit
will be pruned on the next compile.

The provider compiler is not vendored in this repository. Use the machine-local
global harness:

```bash
python3 ~/.agents/compiler.py --source .agents --root . --scope project
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

After changing anything under `.agents/` or a `<cli>/rules/` file, run the
compiler and the rule sync, then confirm `git status --porcelain` is clean and
`git ls-files .claude .codex` is empty.

CI cannot run the compiler — a runner has no `~/.agents`. It enforces what it
can: that the generated mirrors stay untracked, that the Cursor mirrors are in
sync, and that the harness tests pass. Compile determinism is a local check, so
run it before pushing a change to `.agents/`.

Every canonical rule file must be registered: shared rules in the `RULES` dict
and per-CLI rules in the `CLI_RULES` dict of `.agents/scripts/sync-rules.py`. An
unregistered or nested rule is a hard error. Per-CLI rules stay out of
`.agents/rules/`, because the compiler loads everything there in every session.
