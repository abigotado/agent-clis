#!/usr/bin/env bash
# Scan the tracked files under core/ and the commit messages that touch core/ for
# what must never be published: local paths, private hosts, token shapes, private
# keys, assistant attribution, a committed go.work, and imports of a CLI module.
# Findings name the file or commit, the line and the rule, never the matched text,
# so the log cannot itself leak what it found.
#
# Usage: core-hygiene.sh [RANGE]
#   RANGE is a git revision range for the commit-message scan. Without it the
#   script uses origin/$GITHUB_BASE_REF..HEAD on a pull request and the last
#   commit otherwise. Run it from inside the repository.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "${root}"

failures=0

# name<TAB>extended regex. Applied to file contents and to commit messages.
# Rules are literal fragments, so the data stays out of every file this script
# does not scan (it lives outside core/).
common_rules="home path (macOS)	/Users/[A-Za-z0-9._-]+/
home path (Linux)	/home/[A-Za-z0-9._-]+/
home path (Windows)	[A-Za-z]:\\\\+Users\\\\+[A-Za-z0-9._-]+
agent worktree path	\.claude/worktrees
YouTrack service host	[A-Za-z0-9-]+\.(youtrack\.cloud|myjetbrains\.com)
Apple team identifier	(TeamIdentifier|DEVELOPMENT_TEAM|team[ _-]?id)[\"' =:]+[A-Z0-9]{10}([^A-Za-z0-9]|$)
YouTrack permanent token	perm[:-][A-Za-z0-9._=-]{8,}
GitHub token	(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})
AWS access key	AKIA[0-9A-Z]{16}
Slack token	xox[abprs]-[A-Za-z0-9-]{10,}
JWT	eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}
bearer credential	[Bb]earer[ ]+[A-Za-z0-9._~+/=-]{24,}
private key block	-----BEGIN [A-Z ]*PRIVATE KEY-----"

# Extra rules for files: core is a leaf and must not import a CLI.
file_rules="CLI module import	agent-clis/youtrack-agent-cli"

# Extra rules for commit messages: no assistant stamped as author.
message_rules="co-author trailer	^[Cc]o-[Aa]uthored-[Bb]y:
assistant byline	(Generated|Fixed|Addressed|Handled|Written)[ ]+(with|by)[ ]+(Claude|Codex|Cursor|Copilot|ChatGPT|Gemini)
assistant marker	(sent with|Generated with)[ ]+(Claude|Codex|Cursor)
robot emoji byline	🤖"

report() {
  echo "::error::core hygiene: $1"
  failures=$((failures + 1))
}

# scan_stream LABEL RULES: read stdin, report each rule that matches a line.
scan_stream() {
  local label="$1" rules="$2" name pattern lines
  local data
  data="$(cat)"
  while IFS=$'\t' read -r name pattern; do
    [ -n "${name}" ] || continue
    if lines="$(printf '%s\n' "${data}" | grep -nE -- "${pattern}" | cut -d: -f1 | paste -sd, -)" && [ -n "${lines}" ]; then
      report "${label}: ${name} (line ${lines})"
    fi
  done <<<"${rules}"
}

# Files: tracked content only, so build output and untracked scratch are ignored.
files_seen=0
while IFS= read -r -d '' file; do
  [ -f "${file}" ] || continue
  files_seen=$((files_seen + 1))
  case "$(basename "${file}")" in
    go.work | go.work.sum) report "${file}: go.work must not be committed" ;;
  esac
  # Binary files are skipped by name of the check, not by luck: -I treats them
  # as non-matching.
  if grep -qI . "${file}" 2>/dev/null; then
    scan_stream "${file}" "${common_rules}
${file_rules}" <"${file}"
  fi
done < <(git ls-files -z -- core/)

if [ "${files_seen}" -eq 0 ]; then
  echo "::error::core hygiene: no tracked files under core/; the scan would pass while checking nothing"
  exit 1
fi

# A go.work anywhere in the tree breaks the GOWORK=off rule, not just in core/.
while IFS= read -r -d '' file; do
  report "${file}: go.work must not be committed"
done < <(git ls-files -z -- 'go.work' '*/go.work' 'go.work.sum' '*/go.work.sum')

# Commit messages: only commits that touch core/.
range="${1:-}"
if [ -z "${range}" ]; then
  if [ -n "${GITHUB_BASE_REF:-}" ]; then
    range="origin/${GITHUB_BASE_REF}..HEAD"
  else
    range="HEAD~1..HEAD"
    git rev-parse --verify --quiet HEAD~1 >/dev/null || range="HEAD"
  fi
fi

commits=0
while IFS= read -r sha; do
  [ -n "${sha}" ] || continue
  commits=$((commits + 1))
  # Not a pipe: a pipeline subshell would lose the failure count.
  scan_stream "commit ${sha:0:12}" "${common_rules}
${message_rules}" < <(git log -1 --format=%B "${sha}")
done < <(git log --format=%H "${range}" -- core/)

if [ "${failures}" -ne 0 ]; then
  echo "core hygiene: ${failures} finding(s) in ${files_seen} file(s) and ${commits} commit(s)" >&2
  exit 1
fi
echo "core hygiene: ${files_seen} file(s) and ${commits} commit(s) clean"
