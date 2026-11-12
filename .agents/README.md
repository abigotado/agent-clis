# Agent harness

Canonical, provider-neutral agent configuration for this repository. Everything
under this directory is committed; the provider-specific output is generated.

## Canonical inputs

| Path | Purpose |
| --- | --- |
| `agents.toml` + `agents/*.md` | agent registry and prompts |
| `rules/*.md` | shared working rules, routed from the root `AGENTS.md` |
| `skills/*/SKILL.md` + `skills/*/agents/openai.yaml` | cross-provider skills |
| `hooks.toml` + `hooks/*` | pre- and post-tool-use hooks |
| `permissions.toml` | explicit allow / ask / deny policy |
| `providers/*.toml` | provider adapter settings |
| `scripts/sync-rules.py` | Cursor rule mirror sync, and the `RULES` / `CLI_RULES` registries |
| `tests/` | harness unit tests |

Per-CLI rules live outside this directory, in `<cli>/rules/`, because the
provider compiler loads everything under `.agents/rules/` in every session. Each
CLI directory has its own `AGENTS.md`, which the root `AGENTS.md` points to and
which routes that CLI's rules. They are registered in the `CLI_RULES` dict of
`scripts/sync-rules.py`.

This directory is the **only** copy of these files in the repository. Nothing
here is duplicated into a committed provider directory.

## Generated outputs

`.claude/` and `.codex/` are compiled and **git-ignored**. Never edit or commit
them — the next compile prunes the edit, and hook commands render with an
absolute path, so committing them would bake one machine's checkout into the
repo. CI enforces this in `.github/workflows/ci.yaml`.

Tracked `.cursor/rules/*.mdc` files are compatibility mirrors rendered from
`rules/*.md` and `<cli>/rules/*.md` (the latter as `<cli>--<name>.mdc`). They are committed because Cursor has no compile step.

## Commands

```bash
# Provider mirrors, via the machine-local global harness (not vendored here):
python3 ~/.agents/compiler.py --source .agents --root . --scope project
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check

# Cursor mirrors, via the one script this repository does carry:
python3 .agents/scripts/sync-rules.py          # rewrite .cursor/rules/*.mdc
python3 .agents/scripts/sync-rules.py --check  # report drift, write nothing

python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

`sync-rules.py` defaults its repository root from its own location, so it takes
no arguments. Both scripts need the standard library only; set
`AGENT_HARNESS_PYTHON` when the first `python3` on PATH is not the interpreter
the hooks should use.

## Why the compiler is not vendored, but the rule sync is

The provider compiler is deliberately **not** committed. The global harness can
vendor it (`vendor.py` writes a byte-identical `.agents/scripts/compiler.py`
plus a `compiler.pin`), which would let CI compile, but every compiler release
would then need a manual re-vendor here, and the generated output this
repository cares about is git-ignored anyway. One machine-local compiler, with
this directory as the single source, is the trade made on purpose.

`scripts/sync-rules.py` **is** committed, for one reason: the global compiler
emits nothing for Cursor, so there is no shared tool to fall back on. Cursor
also has no compile step, which is why `.cursor/rules/*.mdc` is the one
generated artifact the repository tracks.

Two consequences of using the global compiler, worth knowing:

- **CI cannot verify compilation** — a runner has no `~/.agents`. CI checks that
  the mirrors stay untracked, that the Cursor mirrors are in sync, and that the
  harness tests pass. Compile determinism is a local pre-push check.
- **No `.claude/CLAUDE.md` shim.** `providers/claude.toml` sets
  `instruction_shim = false`: the repository tracks its own root `CLAUDE.md`,
  and the shim's relative `@AGENTS.md` would resolve against `.claude/`, where
  no `AGENTS.md` exists. The first compile after the change prunes an older
  shim from that checkout.
If the global compiler is ever out of date and a rename leaves stale generated
files behind, the output is git-ignored, so discarding and rebuilding is always
safe:

```bash
rm -rf .claude .codex
python3 ~/.agents/compiler.py --source .agents --root . --scope project
```

## Hook paths

`hooks.toml` commands use the `{claude_hook_dir}` placeholder rather than
`{root}/.agents/hooks`. The compiler mirrors every canonical hook into the
provider's own hook directory, so referencing `.agents/hooks` directly would
leave those mirrors unreferenced. Available placeholders are `{python}`,
`{compiler}`, `{root}`, `{source}`, and `{claude_hook_dir}`.

`pre_push_guard` sets `on_failure = "block"`: Claude otherwise runs the command
when a `PreToolUse` hook crashes, times out, or cannot find its interpreter.

## Agents and permissions

Every role in `agents.toml` pins `claude_effort` to the level of the operator's
delegation table (the orchestrator and cli-contract-guardian have no row there,
so theirs is a judgement), and none caps its turns: a capped subagent stops
without a report, and a reviewer stopped that way records no review. A pin is a
fixed level, not a floor, and a value passed at spawn overrides it either way: a
plan under the plan gate, a security or auth change, or a contract migration
passes `effort: xhigh`, and a re-review after a fix passes `model: sonnet` with
`effort: medium`.
`reviewer` and `adversarial-review` close with `Reviewed commit: <sha>` and a
verdict line, which is what the review record is keyed to.

`providers/claude.toml` sets `validation = "strict"`, so the compile refuses a
duplicate rule, a `Write(...)` deny (Claude folds Write into Edit, so such a
rule matches nothing; the `Edit(...)` denies cover it), and a Bash rule that
would mean something different in the Codex policy.

Settings ownership stays `merge` and hook paths stay absolute: those
project-scope options protect committed provider output, and this repository's
output is git-ignored. `providers/codex.toml` does not set `sandbox = "off"`,
so Codex keeps the compiler's default workspace permission profile, where the
global harness turns the sandbox off; its `sandbox_mode = "workspace-write"` is
only the compiler's migration assertion, not the switch. The deny list above
treats the sandbox as part of the boundary. Its known cost is that a sandboxed
Codex session cannot write `<git common dir>/agent-review`, where the review
record lives (verified from a linked worktree), or the CLI's own state
directory; record a Codex review from the session that started the job, or run
that step outside the sandbox.

## Adding a rule

1. Write `rules/<name>.md` for a shared rule, or `<cli>/rules/<name>.md` for a
   rule specific to one CLI. It must be flat — the sync script rejects nesting.
2. Register it in the `RULES` dict (shared) or under its CLI in the `CLI_RULES`
   dict (per-CLI) in `scripts/sync-rules.py` with a description, `always_apply`,
   and `globs`. An unregistered rule, or a `rules/` directory under a top-level
   directory that is not a `CLI_RULES` key, is a hard error, not a warning.
3. Add a row to the router table in the root `AGENTS.md` (shared) or in the
   CLI's own `AGENTS.md` (per-CLI).
4. Run the compiler and the rule sync, then confirm `git status --porcelain` is
   clean.
