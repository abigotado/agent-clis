#!/usr/bin/env ruby

require "pathname"
require "yaml"

ALLOWED_ACTIONS = %w[actions/checkout actions/setup-go actions/setup-python].freeze
READONLY_TAG = "portable_readonly"
MODULE_PREFIX = "github.com/abigotado/agent-clis/youtrack-agent-cli"
CHECKOUT_STEP = {
  "name" => "Git checkout",
  "uses" => "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "with" => { "fetch-depth" => 0, "persist-credentials" => false },
}.freeze
# Release builds must not restore mutable caches.
SETUP_GO_STEP = {
  "name" => "Set up Go",
  "uses" => "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
  "with" => {
    "go-version-file" => "youtrack-agent-cli/go.mod",
    "cache" => false,
    "cache-dependency-path" => "youtrack-agent-cli/go.sum",
  },
}.freeze
VERIFY_TAG_RUN = <<~'SH'
  set -euo pipefail
  test "${GITHUB_REF_TYPE}" = tag
  printf '%s' "${GITHUB_REF_NAME}" | grep -Eq '^youtrack-agent-cli/v0\.[0-9]+\.[0-9]+$'
  release_commit="$(git rev-parse "${GITHUB_SHA}^{commit}")"
  git fetch origin main:refs/remotes/origin/main
  git merge-base --is-ancestor "${release_commit}" origin/main
  git tag --points-at "${release_commit}" | grep -Fxq "${GITHUB_REF_NAME}"
SH
VERIFY_BOUNDARY_RUN = <<~'SH'
  set -euo pipefail
  go test -race ./...
  go test -tags portable_readonly ./...
  test -z "$(go list -tags portable_readonly -deps ./cmd/youtrack-agent-cli | grep -E '/internal/(auth|application|journal|mutation|operatorwrite|youtrack)$' || true)"
  go build -tags portable_readonly -o "${RUNNER_TEMP}/portable-readonly" ./cmd/youtrack-agent-cli
  "${RUNNER_TEMP}/portable-readonly" --help | grep -Eq '^  profile +Manage non-secret read-only Remote MCP profiles$'
  ! "${RUNNER_TEMP}/portable-readonly" --help | grep -Eiq 'auth|inspect|mutation|operator-write'
SH
VERIFY_POLICY_RUN = <<~'SH'
  set -euo pipefail
  go install github.com/goreleaser/goreleaser/v2@v2.17.1
  (cd youtrack-agent-cli && goreleaser check --config .goreleaser.yaml)
  ruby .github/scripts/verify-portable-release-policy_test.rb
  ruby .github/scripts/verify-portable-release-policy.rb youtrack-agent-cli/.goreleaser.yaml .
SH
BUILD_RUN = <<~'SH'
  set -euo pipefail
  test -z "$(git status --porcelain)"
  export CLI_VERSION="${GITHUB_REF_NAME#youtrack-agent-cli/v}"
  goreleaser release --config .goreleaser.yaml --snapshot --clean
  binary="$(ls -d dist/portable-readonly_linux_amd64*/)youtrack-agent-cli"
  report="$("${binary}" version -o json)"
  test "$(jq -r '.data.version' <<<"${report}")" = "${CLI_VERSION}"
  test "$(jq -r '.data.commit' <<<"${report}")" = "$(git rev-parse "${GITHUB_REF}^{commit}")"
  for arch in amd64 arm64; do
    test "$(tar -tzf "dist/youtrack-agent-cli_${CLI_VERSION}_linux_${arch}.tar.gz" | LC_ALL=C sort | tr '\n' ' ')" = "LICENSE README.md youtrack-agent-cli "
  done
SH
UPLOAD_PATHS = <<~'PATHS'
  youtrack-agent-cli/dist/youtrack-agent-cli_*_linux_amd64.tar.gz
  youtrack-agent-cli/dist/youtrack-agent-cli_*_linux_arm64.tar.gz
  youtrack-agent-cli/dist/checksums.txt
PATHS
REVERIFY_DRAFT_RUN = <<~'SH'
  set -euo pipefail
  test "${GITHUB_REF_TYPE}" = tag
  printf '%s' "${GITHUB_REF_NAME}" | grep -Eq '^youtrack-agent-cli/v0\.[0-9]+\.[0-9]+$'
  object="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}" --jq '.object.type + " " + .object.sha')"
  if [ "${object%% *}" = tag ]; then
    object="$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/${object##* }" --jq '.object.type + " " + .object.sha')"
  fi
  test "${object%% *}" = commit
  commit="${object##* }"
  test "${commit}" = "${GITHUB_SHA}"
  status="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${commit}...main" --jq '.status')"
  [ "${status}" = ahead ] || [ "${status}" = identical ]
  {
    echo "COMMIT=${commit}"
    echo "CLI_VERSION=${GITHUB_REF_NAME#youtrack-agent-cli/v}"
  } >> "${GITHUB_ENV}"
SH
VERIFY_FILES_RUN = <<~'SH'
  set -euo pipefail
  archives="$(printf '%s\n' "youtrack-agent-cli_${CLI_VERSION}_linux_amd64.tar.gz" "youtrack-agent-cli_${CLI_VERSION}_linux_arm64.tar.gz" | LC_ALL=C sort)"
  test "$(find . -mindepth 1 -not -name checksums.txt -printf '%P\n' | LC_ALL=C sort)" = "${archives}"
  test "$(awk '{print $2}' checksums.txt | LC_ALL=C sort)" = "${archives}"
  sha256sum --check --strict checksums.txt
SH
CREATE_DRAFT_RUN = <<~'SH'
  set -euo pipefail
  existing="$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases" --jq '.[].tag_name')"
  if grep -Fxq "${GITHUB_REF_NAME}" <<<"${existing}"; then
    echo "a release already exists for ${GITHUB_REF_NAME}" >&2
    exit 1
  fi
  printf '%s\n' "Portable read-only archives of youtrack-agent-cli ${CLI_VERSION}. The operator publishes this draft after checking it." > "${RUNNER_TEMP}/notes.md"
  gh release create "${GITHUB_REF_NAME}" \
    "artifacts/youtrack-agent-cli_${CLI_VERSION}_linux_amd64.tar.gz" \
    "artifacts/youtrack-agent-cli_${CLI_VERSION}_linux_arm64.tar.gz" \
    artifacts/checksums.txt \
    --draft --verify-tag --target "${COMMIT}" \
    --title "youtrack-agent-cli v${CLI_VERSION}" \
    --notes-file "${RUNNER_TEMP}/notes.md"
  object="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}" --jq '.object.type + " " + .object.sha')"
  if [ "${object%% *}" = tag ]; then
    object="$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/${object##* }" --jq '.object.type + " " + .object.sha')"
  fi
  if [ "${object%% *}" != commit ] || [ "${object##* }" != "${COMMIT}" ]; then
    echo "::error::tag ${GITHUB_REF_NAME} no longer resolves to ${COMMIT}; it moved during the job. The operator must delete the draft release before retrying."
    exit 1
  fi
SH
GH_ENV = { "GH_REPO" => "${{ github.repository }}", "GH_TOKEN" => "${{ github.token }}" }.freeze
EXPECTED_RELEASE_WORKFLOW = {
  "name" => "release-youtrack-agent-cli",
  true => { "push" => { "tags" => ["youtrack-agent-cli/v0.*"] } },
  "permissions" => { "contents" => "read" },
  "env" => { "GOWORK" => "off" },
  "concurrency" => { "group" => "release-${{ github.ref }}", "cancel-in-progress" => false },
  "jobs" => {
    "verify" => {
      "name" => "Verify portable Remote-MCP read-only release", "runs-on" => "ubuntu-latest",
      "steps" => [
        CHECKOUT_STEP, SETUP_GO_STEP,
        { "name" => "Verify release tag is on main", "run" => VERIFY_TAG_RUN },
        { "name" => "Verify portable read-only boundary", "working-directory" => "youtrack-agent-cli", "run" => VERIFY_BOUNDARY_RUN },
        { "name" => "Verify release policy and config", "env" => { "GOTOOLCHAIN" => "auto" }, "run" => VERIFY_POLICY_RUN },
      ],
    },
    "build" => {
      "name" => "Build checksummed portable archives", "needs" => "verify", "runs-on" => "ubuntu-latest",
      "steps" => [
        CHECKOUT_STEP, SETUP_GO_STEP,
        { "name" => "Reverify release tag is on main", "run" => VERIFY_TAG_RUN },
        { "name" => "Install pinned GoReleaser", "env" => { "GOTOOLCHAIN" => "auto" }, "run" => "go install github.com/goreleaser/goreleaser/v2@v2.17.1" },
        { "name" => "Build and check the archives", "working-directory" => "youtrack-agent-cli", "run" => BUILD_RUN },
        {
          "name" => "Upload the archives",
          "uses" => "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
          "with" => { "name" => "portable-archives", "path" => UPLOAD_PATHS, "if-no-files-found" => "error" },
        },
      ],
    },
    "draft" => {
      "name" => "Create the draft release", "needs" => %w[verify build],
      "permissions" => { "contents" => "write" }, "runs-on" => "ubuntu-latest",
      "steps" => [
        { "name" => "Reverify the tag against main", "env" => GH_ENV, "run" => REVERIFY_DRAFT_RUN },
        {
          "name" => "Download the archives",
          "uses" => "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
          "with" => { "name" => "portable-archives", "path" => "artifacts" },
        },
        { "name" => "Verify the exact files and checksums", "working-directory" => "artifacts", "run" => VERIFY_FILES_RUN },
        { "name" => "Create the draft", "env" => GH_ENV, "run" => CREATE_DRAFT_RUN },
      ],
    },
  },
}.freeze
# Workflows allowed to publish, each pinned to its approved content.
PUBLISHERS = { ".github/workflows/release.yaml" => EXPECTED_RELEASE_WORKFLOW }.freeze
# The tap publisher needs signing and its Environment, so nothing may occupy its
# path until it is added to PUBLISHERS.
RESERVED = %w[.github/workflows/tap.yaml .github/workflows/tap.yml].freeze
CI_WORKFLOW = ".github/workflows/ci.yaml"
CI_GATE = "ci-ok"

unless ARGV.length == 2
  warn "usage: verify-portable-release-policy.rb GORELEASER_CONFIG REPOSITORY_ROOT"
  exit 2
end
path = ARGV.fetch(0)
root = File.expand_path(ARGV.fetch(1))

begin
  config = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
rescue Errno::ENOENT, Psych::Exception => error
  warn "portable read-only release policy: cannot read config: #{error.message}"
  exit 1
end

relative_to_root = ->(candidate) { Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s }

errors = []
unless config.is_a?(Hash) && config["version"] == 2 && config["project_name"] == "youtrack-agent-cli"
  errors << "release config must identify the v2 youtrack-agent-cli project"
end
errors << "release config contains an unapproved top-level section" unless (config.keys - %w[version project_name builds archives checksum snapshot release]).empty?

builds = config.fetch("builds", [])
unless builds.length == 1
  errors << "release config must contain exactly one portable read-only build"
else
  build = builds.first
  expected = {
    "id" => "portable-readonly", "main" => "./cmd/youtrack-agent-cli", "binary" => "youtrack-agent-cli",
    "tags" => [READONLY_TAG], "env" => ["CGO_ENABLED=0"], "flags" => ["-trimpath"],
    "goos" => ["linux"], "goarch" => %w[amd64 arm64],
  }
  expected.each { |key, value| errors << "portable build has invalid #{key}" unless build[key] == value }
  errors << "portable build contains an unapproved setting" unless (build.keys - (expected.keys + ["ldflags"])).empty?
  expected_ldflags = [
    "-s -w",
    "-X #{MODULE_PREFIX}/internal/readonlycli.releaseVersion={{ .Version }}",
    "-X #{MODULE_PREFIX}/internal/readonlycli.releaseCommit={{ .FullCommit }}",
    "-X #{MODULE_PREFIX}/internal/readonlycli.releaseCommitTime={{ .CommitDate }}",
  ]
  errors << "portable build has invalid provenance ldflags" unless build["ldflags"] == expected_ldflags
end

archives = config.fetch("archives", [])
expected_archive = {
  "id" => "portable-readonly", "ids" => ["portable-readonly"], "formats" => ["tar.gz"],
  "name_template" => "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}",
}
unless archives == [expected_archive]
  errors << "release config must publish only portable read-only tar.gz archives"
end
errors << "release config must publish only the approved checksum" unless config["checksum"] == { "name_template" => "checksums.txt" }
errors << "release config must take its version from CLI_VERSION" unless config["snapshot"] == { "version_template" => "{{ .Env.CLI_VERSION }}" }
errors << "release config must leave publication to the release workflow" unless config["release"] == { "disable" => true }
%w[homebrew homebrew_casks nfpms docks brews blobs uploads universal_binaries].each do |key|
  errors << "portable release config must not define #{key}" if config.key?(key)
end

Dir.glob(File.join(root, "{,*/}{Formula,Cask,Casks}/**/*.rb")).each do |candidate|
  errors << "Homebrew Formula/Cask is forbidden: #{relative_to_root.call(candidate)}"
end

# The trailing /**/* matters: a trailing /** does not recurse in Ruby and would
# scan nothing.
surface = [File.join(root, ".github/workflows/**/*"), File.join(root, "{,*/}{packaging,scripts}/**/*")].flat_map { |glob| Dir.glob(glob) }.uniq
surface.each do |candidate|
  next unless File.file?(candidate)
  relative = relative_to_root.call(candidate)
  next if PUBLISHERS.key?(relative)
  content = File.binread(candidate).force_encoding(Encoding::UTF_8).scrub
  errors << "#{relative} contains a Homebrew or quarantine bypass" if content.match?(/(?:\bbrew\s+(?:tap|tap-new|create|bump)|\bxattr\b|com\.apple\.quarantine|spctl\s+--master-disable)/i)
  errors << "#{relative} contains a publication action" if content.match?(/(?:\bgoreleaser\s+release\b|\bgh\s+(?:api|release)\b|action-gh-release|\/upload-artifact@)/i)
  # Without --config, GoReleaser prefers .config/goreleaser.y*ml or .goreleaser.yml
  # over the checked config if one appears.
  content.scan(/(?:^|[;&|(]|\brun:)[ \t]*goreleaser[ \t]+(?:check|build|release)\b[^\n]*/i).each do |call|
    errors << "#{relative} runs GoReleaser without --config .goreleaser.yaml: #{call.strip}" unless call.include?("--config .goreleaser.yaml")
  end
end

workflows = Dir.glob(File.join(root, ".github/workflows/*.{yaml,yml}"))
errors << "no workflows found under .github/workflows" if workflows.empty?
present = workflows.map { |candidate| relative_to_root.call(candidate) }
PUBLISHERS.each_key { |publisher| errors << "missing publishing workflow #{publisher}" unless present.include?(publisher) }
(RESERVED & present).each { |reserved| errors << "#{reserved} is reserved for a publisher that is not approved yet" }
errors << "missing #{CI_WORKFLOW}" unless present.include?(CI_WORKFLOW)

workflows.each do |candidate|
  relative = relative_to_root.call(candidate)
  begin
    workflow = YAML.safe_load(File.read(candidate), permitted_classes: [], aliases: false)
  rescue Psych::Exception => error
    errors << "#{relative} is invalid YAML: #{error.message}"
    next
  end
  unless workflow.is_a?(Hash)
    errors << "#{relative} must be a mapping"
    next
  end
  checkouts = lambda do |value|
    case value
    when Hash
      value.each do |key, item|
        if key.to_s == "uses" && item.to_s.start_with?("actions/checkout@")
          step_with = value["with"]
          unless step_with.is_a?(Hash) && step_with["persist-credentials"] == false
            errors << "#{relative} has an actions/checkout step without persist-credentials: false"
          end
        end
        checkouts.call(item)
      end
    when Array then value.each { |item| checkouts.call(item) }
    end
  end
  checkouts.call(workflow)
  if PUBLISHERS.key?(relative)
    errors << "#{relative} must equal the approved publisher" unless workflow == PUBLISHERS.fetch(relative)
    next
  end
  errors << "#{relative} must set read-only permissions" unless workflow["permissions"] == { "contents" => "read" }
  if relative == CI_WORKFLOW
    jobs = workflow["jobs"].is_a?(Hash) ? workflow["jobs"] : {}
    gate = jobs[CI_GATE]
    if gate.is_a?(Hash)
      errors << "#{CI_GATE} must keep its job id as its name" unless gate["name"] == CI_GATE
      errors << "#{CI_GATE} must need every other job" unless Array(gate["needs"]).sort == (jobs.keys - [CI_GATE]).sort
      errors << "#{CI_GATE} must run with if: always()" unless gate["if"] == "always()"
      gate_envs = Array(gate["steps"]).map { |step| step.is_a?(Hash) ? step["env"] : nil }
      unless gate_envs.any? { |env| env.is_a?(Hash) && env["NEEDS"] == "${{ toJSON(needs) }}" }
        errors << "#{CI_GATE} must pass NEEDS: ${{ toJSON(needs) }} to its verification step"
      end
    else
      errors << "#{relative} has no #{CI_GATE} job"
    end
    forgiving = lambda do |value|
      case value
      when Hash then value.any? { |key, item| key.to_s == "continue-on-error" || forgiving.call(item) }
      when Array then value.any? { |item| forgiving.call(item) }
      else false
      end
    end
    errors << "#{relative} must not use continue-on-error" if forgiving.call(jobs)
  end
  walk = lambda do |value, nested_permissions = false|
    case value
    when Hash
      value.each do |key, item|
        if key.to_s == "permissions" && nested_permissions
          errors << "#{relative} has nested workflow permissions"
        end
        if key.to_s == "uses"
          action, revision = item.to_s.split("@", 2)
          errors << "#{relative} uses unapproved action #{action.inspect}" unless ALLOWED_ACTIONS.include?(action)
          errors << "#{relative} uses an unpinned action" unless revision&.match?(/\A[0-9a-f]{40}\z/)
        end
        walk.call(item, nested_permissions || key.to_s == "jobs")
      end
    when Array
      value.each { |item| walk.call(item, nested_permissions) }
    when String
      errors << "#{relative} references forbidden secrets context" if value.match?(/\$\{\{.*\bsecrets\b/im)
    end
  end
  walk.call(workflow)
end

if errors.empty?
  puts "portable read-only release policy ok"
  exit 0
end
errors.each { |error| warn "portable read-only release policy: #{error}" }
exit 1
