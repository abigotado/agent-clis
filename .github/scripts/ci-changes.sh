#!/usr/bin/env bash
# Decide which CI jobs a change needs and write the result to GITHUB_OUTPUT.
# Any doubt selects every job: skipping a needed check is the failure to avoid.
set -euo pipefail

emit() {
  printf 'youtrack=%s\nall=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
  exit 0
}

run_everything() {
  echo "ci-changes: selecting every job: $1" >&2
  emit false true
}

# A new module must be added here and given jobs before it can land, otherwise
# nothing would ever select it.
registered_modules="youtrack-agent-cli/go.mod"
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

youtrack=false
while IFS= read -r path; do
  case "${path}" in
    youtrack-agent-cli/*) youtrack=true ;;
    *) run_everything "shared path ${path}" ;;
  esac
done <<<"${changed}"

emit "${youtrack}" false
