#!/usr/bin/env bash
# Tests .githooks/pre-push against a scratch repository with two Go modules.
# `go` is a shim that logs each invocation and reads stdin, so a gate that let a
# command swallow stdin would skip the second module or the later refs.
set -euo pipefail

hook="$(cd "$(dirname "$0")/../.." && pwd)/.githooks/pre-push"
work="$(mktemp -d "${TMPDIR:-/tmp}/pre-push-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
failures=0

check() { # name, expected exit, actual exit
  if [ "$2" -eq "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want exit $2, got $3" >&2; failures=$((failures + 1)); fi
}
contains() { # name, file, needle
  if grep -Fq -- "$3" "$2"; then echo "ok   $1"; else echo "FAIL $1: missing '$3'" >&2; failures=$((failures + 1)); fi
}
lacks() {
  if grep -Fq -- "$3" "$2"; then echo "FAIL $1: unexpected '$3'" >&2; failures=$((failures + 1)); else echo "ok   $1"; fi
}

mkdir -p "$work/bin" "$work/repo" "$work/tmp"
cat >"$work/bin/go" <<'SHIM'
#!/usr/bin/env bash
cat >/dev/null
echo "$PWD $*" >>"$GO_LOG"
SHIM
chmod +x "$work/bin/go"
export GO_LOG="$work/go.log"
export PATH="$work/bin:$PATH"
# A real interpreter for the version probe; the harness scripts the fixture does
# not have run as no-ops.
cat >"$work/bin/fakepy" <<'PY'
#!/usr/bin/env bash
if [ "$1" = -c ]; then exec python3 "$@"; fi
exit 0
PY
chmod +x "$work/bin/fakepy"
export AGENT_HARNESS_PYTHON="$work/bin/fakepy"
# A Python 3.7 stand-in: real interpreter, but it reports an old version.
cat >"$work/bin/oldpy" <<'PY'
#!/usr/bin/env bash
if [ "$1" = -c ]; then
  exec python3 -c 'import sys; sys.version_info = (3, 7, 0, "final", 0); exec(sys.argv[1])' "$2"
fi
exit 0
PY
chmod +x "$work/bin/oldpy"

cd "$work/repo"
git init -q -b main
git config user.email t@example.invalid
git config user.name t
mkdir -p .githooks mod_a mod_b .agents
echo one >.agents/r.md
cp "$hook" .githooks/pre-push
for module in mod_a mod_b; do
  printf 'module example.invalid/%s\n\ngo 1.22\n' "$module" >"$module/go.mod"
  printf 'package %s\n' "$module" >"$module/x.go"
done
git add -A
git commit -qm good
good=$(git rev-parse HEAD)
zero=0000000000000000000000000000000000000000

run() { # refs on stdin; output to $work/out
  : >"$GO_LOG"
  set +e
  TMPDIR="$work/tmp" bash .githooks/pre-push origin url >"$work/out" 2>&1
  status=$?
  set -e
}

run <<<"refs/heads/x $good refs/heads/x $zero"
check "good commit passes" 0 "$status"
contains "module a vetted" "$GO_LOG" "mod_a vet"
contains "module b vetted despite stdin-reading go" "$GO_LOG" "mod_b test"

run <<<"refs/heads/x $good refs/heads/x $zero
refs/heads/y $good refs/heads/y $zero"
check "duplicate tips are gated once" 0 "$status"
test "$(grep -c 'mod_a vet' "$GO_LOG")" -eq 1 && echo "ok   gated once" || { echo "FAIL gated once" >&2; failures=$((failures + 1)); }

git commit -q --allow-empty -m second
second=$(git rev-parse HEAD)
run <<<"refs/heads/x $good refs/heads/x $zero
refs/heads/y $second refs/heads/y $zero"
check "two distinct tips pass" 0 "$status"
test "$(grep -c 'mod_a vet' "$GO_LOG")" -eq 2 && echo "ok   every tip gated" || { echo "FAIL every tip gated" >&2; failures=$((failures + 1)); }
git reset -q --hard "$good"

run <<<"(delete) $zero refs/heads/x $good"
check "deleting a ref is a no-op" 0 "$status"
test ! -s "$GO_LOG" && echo "ok   delete ran nothing" || { echo "FAIL delete ran go" >&2; failures=$((failures + 1)); }

# A deletion needs neither Go nor scratch space.
set +e
PATH="/usr/bin:/bin" TMPDIR=/nonexistent bash .githooks/pre-push origin url <<<"(delete) $zero refs/heads/x $good" >"$work/out" 2>&1
status=$?
set -e
if PATH="/usr/bin:/bin" command -v go >/dev/null 2>&1; then echo "skip delete-without-go (go in /usr/bin)"; else check "deletion needs no go or tmp" 0 "$status"; fi

# A pushed commit must not run its own checkout hooks.
mkdir -p "$work/hooks-evil"
printf '#!/bin/sh\necho evil >mod_a/evil.txt\n' >"$work/hooks-evil/post-checkout"
chmod +x "$work/hooks-evil/post-checkout"
git config core.hooksPath "$work/hooks-evil"
run <<<"refs/heads/x $good refs/heads/x $zero"
check "checkout hooks do not run" 0 "$status"
git config --unset core.hooksPath
rm -rf "$work/hooks-evil"

run <<<"refs/heads/x $(printf 'f%.0s' {1..40}) refs/heads/x $zero"
check "unresolvable sha fails closed" 1 "$status"

run <<<"garbage"
check "malformed ref line fails closed" 1 "$status"

# The pushed commit is unformatted while the working tree is clean: the gate must
# read the commit.
printf 'package   mod_a\n' >mod_a/x.go
git commit -qam bad
bad=$(git rev-parse HEAD)
git checkout -q "$good" -- mod_a/x.go
git status --porcelain | grep -q . && git commit -qm restore
run <<<"refs/heads/x $bad refs/heads/x $zero"
check "unformatted pushed commit fails" 1 "$status"
contains "gofmt names the file" "$work/out" "x.go"

# The working tree is dirty and unformatted, but the pushed commit is clean.
printf 'package   mod_a\n' >mod_a/x.go
run <<<"refs/heads/x $good refs/heads/x $zero"
check "dirty working tree does not fail a clean pushed commit" 0 "$status"
git checkout -q -- mod_a/x.go

# Provider-mirror branch: the compiler is absent here (HOME is a scratch dir).
export HOME="$work/home"; mkdir -p "$HOME"
agents1=$good
echo two >.agents/r.md && git commit -qam agents2
run <<<"refs/heads/x $agents1 refs/heads/x $zero"
check "a tip whose .agents differs from HEAD fails closed" 1 "$status"
contains "mirror refusal is explained" "$work/out" ".agents differs from the checked-out HEAD"
run <<<"refs/heads/x $(git rev-parse HEAD) refs/heads/x $zero"
check "HEAD with matching .agents passes" 0 "$status"
echo three >.agents/r.md
run <<<"refs/heads/x $(git rev-parse HEAD) refs/heads/x $zero"
check "uncommitted .agents changes fail closed" 1 "$status"
git checkout -q -- .agents/r.md
AGENT_HARNESS_PYTHON=true run <<<"refs/heads/x $(git rev-parse HEAD) refs/heads/x $zero"
check "a command that merely exits 0 is not a harness python" 1 "$status"
AGENT_HARNESS_PYTHON=false run <<<"refs/heads/x $(git rev-parse HEAD) refs/heads/x $zero"
check "a failing harness python fails closed" 1 "$status"
PYTHONOPTIMIZE=1 AGENT_HARNESS_PYTHON="$work/bin/oldpy" run <<<"refs/heads/x $(git rev-parse HEAD) refs/heads/x $zero"
check "python 3.7 is refused even with assertions stripped" 1 "$status"
AGENT_HARNESS_PYTHON="$work/bin/oldpy" run <<<"refs/heads/x $(git rev-parse HEAD) refs/heads/x $zero"
check "python 3.7 is refused" 1 "$status"
with_agents=$(git rev-parse HEAD)
git rm -rq .agents && git commit -qm noagents
without_agents=$(git rev-parse HEAD)
git checkout -q "$with_agents"
run <<<"refs/heads/x $without_agents refs/heads/x $zero"
check "a tip dropping .agents fails closed" 1 "$status"
git checkout -q main
git reset -q --hard "$without_agents"
run <<<"refs/heads/x $without_agents refs/heads/x $zero"
check "pushing a HEAD with no .agents fails closed" 1 "$status"
contains "missing harness is explained" "$work/out" "has no .agents"
git reset -q --hard "$with_agents"

# A symlinked .agents is not the pushed harness: it resolves outside the tree.
mkdir -p "$work/external-agents"
git rm -rq .agents
ln -s "$work/external-agents" .agents
git add .agents && git commit -qm symlinked-agents
symlinked=$(git rev-parse HEAD)
run <<<"refs/heads/x $symlinked refs/heads/x $zero"
check "a symlinked .agents fails closed" 1 "$status"
contains "symlinked harness is explained" "$work/out" "symlink"
git reset -q --hard "$with_agents"

# Cleanup must not prune worktrees the hook does not own.
git worktree add -q --detach "$work/other" HEAD
mv "$work/other" "$work/other-moved"
run <<<"refs/heads/x $good refs/heads/x $zero"
git worktree list | grep -q 'other' && echo "ok   foreign worktree entry kept" || { echo "FAIL foreign worktree pruned" >&2; failures=$((failures + 1)); }
mv "$work/other-moved" "$work/other"
git worktree remove --force "$work/other"

leftover=$(git worktree list | wc -l | tr -d ' ')
test "$leftover" -eq 1 && echo "ok   no temporary worktree left" || { echo "FAIL $leftover worktrees left" >&2; failures=$((failures + 1)); }
ls "$work"/tmp/pre-push.* >/dev/null 2>&1 && { echo "FAIL temp dir left" >&2; failures=$((failures + 1)); } || echo "ok   no temp dir left"

[ "$failures" -eq 0 ] || { echo "$failures failure(s)" >&2; exit 1; }
echo "pre-push tests ok"
