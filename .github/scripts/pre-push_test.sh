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

mkdir -p "$work/bin" "$work/repo"
cat >"$work/bin/go" <<'SHIM'
#!/usr/bin/env bash
cat >/dev/null
echo "$PWD $*" >>"$GO_LOG"
SHIM
chmod +x "$work/bin/go"
export GO_LOG="$work/go.log"
export PATH="$work/bin:$PATH"
export AGENT_HARNESS_PYTHON=false

cd "$work/repo"
git init -q -b main
git config user.email t@example.invalid
git config user.name t
mkdir -p .githooks mod_a mod_b
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
  bash .githooks/pre-push origin url >"$work/out" 2>&1
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

run <<<"(delete) $zero refs/heads/x $good"
check "deleting a ref is a no-op" 0 "$status"
test ! -s "$GO_LOG" && echo "ok   delete ran nothing" || { echo "FAIL delete ran go" >&2; failures=$((failures + 1)); }

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

leftover=$(git worktree list | wc -l | tr -d ' ')
test "$leftover" -eq 1 && echo "ok   no temporary worktree left" || { echo "FAIL $leftover worktrees left" >&2; failures=$((failures + 1)); }
ls "${TMPDIR:-/tmp}"/pre-push.* >/dev/null 2>&1 && { echo "FAIL temp dir left" >&2; failures=$((failures + 1)); } || echo "ok   no temp dir left"

[ "$failures" -eq 0 ] || { echo "$failures failure(s)" >&2; exit 1; }
echo "pre-push tests ok"
