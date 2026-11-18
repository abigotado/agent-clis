#!/usr/bin/env bash
# Decide which CI jobs a change needs and write the result to GITHUB_OUTPUT.
# Any doubt selects every job: skipping a needed check is the failure to avoid.
#
# Outputs, always all four and written once:
#   youtrack  the youtrack-agent-cli jobs are needed because of its own paths
#   core      core/ changed (its job always runs; the flag feeds later jobs)
#   clis      JSON array of the registered CLI modules (every module but core)
#   all       something shared changed or the diff is uncertain: run everything
set -euo pipefail

# A new module must be added here and given jobs before it can land, otherwise
# nothing would ever select it. The list is sorted, as git ls-files prints it.
registered_modules="core/go.mod
youtrack-agent-cli/go.mod"

youtrack=false
core=false
all=false

clis_json() {
  local out="" module dir
  while IFS= read -r module; do
    dir="${module%/go.mod}"
    [ "${dir}" = core ] && continue
    out+="${out:+,}\"${dir}\""
  done <<<"${registered_modules}"
  printf '[%s]' "${out}"
}

emit_and_exit() {
  printf 'youtrack=%s\ncore=%s\nclis=%s\nall=%s\n' \
    "${youtrack}" "${core}" "$(clis_json)" "${all}" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
  exit 0
}

run_everything() {
  echo "ci-changes: selecting every job: $1" >&2
  youtrack=false
  core=false
  all=true
  emit_and_exit
}

tracked_modules="$(git ls-files -- go.mod '*/go.mod')"
if [ "${tracked_modules}" != "${registered_modules}" ]; then
  echo "::error::tracked go.mod files differ from the registered list: ${tracked_modules}"
  exit 1
fi

[ "${EVENT_NAME:-}" = pull_request ] || run_everything "event ${EVENT_NAME:-unset}"

for sha in "${BASE_SHA:-}" "${HEAD_SHA:-}"; do
  if [[ "${sha}" =~ ^0*$ ]]; then
    run_everything "empty or zero revision"
  fi
  git rev-parse --verify --quiet "${sha}^{commit}" >/dev/null \
    || run_everything "unknown revision ${sha}"
done

# --no-renames so a move into a module directory also reports its source path.
changed="$(git diff --no-renames --name-only "${BASE_SHA}...${HEAD_SHA}")" \
  || run_everything "diff failed"
[ -n "${changed}" ] || run_everything "empty diff"

while IFS= read -r path; do
  case "${path}" in
    youtrack-agent-cli/*) youtrack=true ;;
    core/*) core=true ;;
    *) run_everything "shared path ${path}" ;;
  esac
done <<<"${changed}"

emit_and_exit
