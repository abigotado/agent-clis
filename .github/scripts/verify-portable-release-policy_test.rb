#!/usr/bin/env ruby

require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"
require "yaml"

class VerifyPortableReadOnlyReleasePolicyTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  VERIFIER = File.join(__dir__, "verify-portable-release-policy.rb")
  CONFIG_PATH = "youtrack-agent-cli/.goreleaser.yaml"
  CONFIG = YAML.safe_load(File.read(File.join(ROOT, CONFIG_PATH)), permitted_classes: [], aliases: false)
  RELEASE = File.read(File.join(ROOT, ".github/workflows/release.yaml"))
  MINIMAL_CI = <<~YAML
    name: ci
    on: pull_request
    permissions:
      contents: read
    jobs:
      changes:
        runs-on: ubuntu-latest
        steps:
          - run: "true"
      ci-ok:
        name: ci-ok
        if: always()
        needs: [changes]
        runs-on: ubuntu-latest
        steps:
          - env:
              NEEDS: ${{ toJSON(needs) }}
            run: "true"
  YAML

  def verify(config = CONFIG, files = {}, release: RELEASE, ci: MINIMAL_CI)
    Dir.mktmpdir("portable-release-policy") do |root|
      config_path = File.join(root, CONFIG_PATH)
      FileUtils.mkdir_p(File.dirname(config_path))
      File.write(config_path, YAML.dump(config))
      if ci
        FileUtils.mkdir_p(File.join(root, ".github/workflows"))
        File.write(File.join(root, ".github/workflows/ci.yaml"), ci)
      end
      files.each do |relative, content|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        File.write(target, content)
      end
      FileUtils.mkdir_p(File.join(root, ".github/workflows"))
      File.write(File.join(root, ".github/workflows/release.yaml"), release) if release
      _stdout, stderr, status = Open3.capture3("ruby", VERIFIER, config_path, root)
      [status.success?, stderr]
    end
  end

  def workflow_using(step)
    <<~YAML
      name: other
      on: pull_request
      permissions:
        contents: read
      jobs:
        check:
          runs-on: ubuntu-latest
          steps:
            - #{step}
    YAML
  end

  def test_current_configuration_passes
    success, stderr = verify
    assert success, stderr
  end

  def test_requires_the_repository_root_argument
    _stdout, stderr, status = Open3.capture3("ruby", VERIFIER, File.join(ROOT, CONFIG_PATH))
    assert_equal 2, status.exitstatus
    assert_includes stderr, "usage:"
  end

  def test_rejects_an_empty_workflows_directory
    success, stderr = verify(CONFIG, {}, release: nil, ci: nil)
    refute success
    assert_includes stderr, "no workflows found"
  end

  def test_rejects_a_missing_release_workflow
    success, stderr = verify(CONFIG, { ".github/workflows/other.yaml" => workflow_using("run: true") }, release: nil)
    refute success
    assert_includes stderr, "missing publishing workflow .github/workflows/release.yaml"
  end

  def test_rejects_a_missing_ci_workflow
    success, stderr = verify(CONFIG, {}, ci: nil)
    refute success
    assert_includes stderr, "missing .github/workflows/ci.yaml"
  end

  def test_rejects_a_ci_workflow_without_the_gate
    success, stderr = verify(CONFIG, {}, ci: MINIMAL_CI.sub("  ci-ok:\n", "  other:\n"))
    refute success
    assert_includes stderr, "has no ci-ok job"
  end

  def test_rejects_a_gate_that_misses_a_job
    extra_job = "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: \"true\"\n"
    success, stderr = verify(CONFIG, {}, ci: MINIMAL_CI + extra_job)
    refute success
    assert_includes stderr, "must need every other job"
  end

  def test_rejects_a_gate_that_does_not_always_run
    success, stderr = verify(CONFIG, {}, ci: MINIMAL_CI.sub("if: always()", "if: success()"))
    refute success
    assert_includes stderr, "if: always()"
  end

  def test_rejects_a_gate_without_the_needs_context
    changed = MINIMAL_CI.sub("NEEDS: ${{ toJSON(needs) }}", "NEEDS: ${{ needs.changes.result }}")
    refute_equal MINIMAL_CI, changed
    success, stderr = verify(CONFIG, {}, ci: changed)
    refute success
    assert_includes stderr, "must pass NEEDS"
  end

  def test_rejects_a_release_workflow_without_the_goreleaser_config_flag
    changed = RELEASE.gsub(" --config .goreleaser.yaml", "")
    refute_equal RELEASE, changed
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end

  def with_run_block(*lines)
    block = lines.map { |line| "          #{line}\n" }.join
    changed = MINIMAL_CI.sub("- run: \"true\"\n", "- run: \"true\"\n      - run: |\n#{block}")
    refute_equal MINIMAL_CI, changed
    changed
  end

  def test_rejects_goreleaser_outside_the_approved_lines
    [
      ["goreleaser check"],
      ["(cd x && goreleaser build --snapshot --clean)"],
      ["goreleaser \\", "  build --snapshot --clean"],
      ["command goreleaser build --config .goreleaser.yaml --snapshot --clean --id portable-readonly"],
      ["if goreleaser check --config .goreleaser.yaml; then true; fi"],
      ["goreleaser build # --config .goreleaser.yaml"],
      ["goreleaser check --config .goreleaser.yaml; goreleaser build --snapshot"],
      ["goreleaser build --config=.goreleaser.yaml --snapshot --clean --id portable-readonly"],
    ].each do |lines|
      success, stderr = verify(CONFIG, {}, ci: with_run_block(*lines))
      refute success, lines.join(" / ")
      assert_includes stderr, "outside the approved lines"
    end
  end

  REAL_CI = File.read(File.join(ROOT, ".github/workflows/ci.yaml"), encoding: "UTF-8")
  REHEARSAL_NAME = "      - name: goreleaser check and portable build rehearsal\n"

  def test_accepts_the_real_ci_workflow
    success, stderr = verify(CONFIG, {}, ci: REAL_CI)
    assert success, stderr
  end

  def test_rejects_approved_lines_outside_the_pinned_steps
    success, stderr = verify(CONFIG, {}, ci: with_run_block(
      "go install github.com/goreleaser/goreleaser/v2@v2.17.1",
      "goreleaser check --config .goreleaser.yaml",
    ))
    refute success
    assert_includes stderr, "not the pinned step"
  end

  def test_rejects_the_rehearsal_in_another_working_directory
    step_level = REAL_CI.sub(REHEARSAL_NAME, "#{REHEARSAL_NAME}        working-directory: alternate\n")
    job_level = REAL_CI.sub("        working-directory: youtrack-agent-cli\n", "        working-directory: alternate\n")
    [step_level, job_level].each do |ci|
      refute_equal REAL_CI, ci
      success, stderr = verify(CONFIG, {}, ci: ci)
      refute success
      assert_match(/not the pinned step|must keep defaults/, stderr)
    end
  end

  def test_rejects_the_rehearsal_copied_into_another_job
    rehearsal = REAL_CI[/#{Regexp.escape(REHEARSAL_NAME)}.*?\n\n/m]
    refute_nil rehearsal
    extra_job = "  other:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: alternate\n    steps:\n#{rehearsal}"
    ci = REAL_CI.sub("  ci-ok:\n", "#{extra_job}  ci-ok:\n").sub("needs: [changes, repo, youtrack, youtrack-windows]", "needs: [changes, repo, youtrack, youtrack-windows, other]")
    success, stderr = verify(CONFIG, {}, ci: ci)
    refute success
    assert_includes stderr, "job other has a GoReleaser step that is not the pinned step"
  end

  def test_rejects_goreleaser_outside_ci_yaml
    success, stderr = verify(CONFIG, { "youtrack-agent-cli/packaging/build.sh" => "goreleaser check --config .goreleaser.yaml\n" })
    refute success
    assert_includes stderr, "packaging/build.sh:1 mentions GoReleaser outside the approved lines"
  end

  def test_every_approved_goreleaser_line_is_used
    real_ci = File.read(File.join(ROOT, ".github/workflows/ci.yaml"), encoding: "UTF-8").lines.map(&:strip)
    source = File.read(VERIFIER, encoding: "UTF-8")
    approved = source[/GORELEASER_LINES = \[\n(.*?)\n\]\.freeze/m, 1]
    refute_nil approved
    approved.scan(/^\s+"(.*)",$/).flatten.each do |line|
      assert_includes real_ci, line.gsub('\\"', '"')
    end
  end

  def test_rejects_a_release_workflow_that_restores_the_go_cache
    changed = RELEASE.gsub("cache: false", "cache: true")
    refute_equal RELEASE, changed
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end

  def test_rejects_a_release_draft_that_does_not_recheck_the_tag
    changed = RELEASE.sub("no longer resolves to", "still resolves to")
    refute_equal RELEASE, changed
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end

  def test_rejects_a_checkout_that_persists_credentials_in_any_workflow
    bare = "uses: actions/checkout@#{'a' * 40}"
    kept = "uses: actions/checkout@#{'a' * 40}\n        with:\n          persist-credentials: true"
    [bare, kept].each do |step|
      success, stderr = verify(CONFIG, { ".github/workflows/other.yaml" => workflow_using(step) })
      refute success, step
      assert_includes stderr, "without persist-credentials: false"
    end
    success, stderr = verify(CONFIG, {}, release: RELEASE.sub("persist-credentials: false", "persist-credentials: true"))
    refute success
    assert_includes stderr, "without persist-credentials: false"
  end

  def test_rejects_a_checkout_of_other_code_in_any_workflow
    checkout = "        with:\n          persist-credentials: false\n"
    youtrack_checkout = REAL_CI.index(checkout, REAL_CI.index("  youtrack:\n"))
    refute_nil youtrack_checkout
    %w[repository path ref].each do |input|
      line = "          #{input}: alternate\n"
      ci = REAL_CI.dup.insert(youtrack_checkout + checkout.length, line)
      success, stderr = verify(CONFIG, {}, ci: ci)
      refute success, input
      assert_includes stderr, "ci.yaml has an actions/checkout step with unapproved inputs: #{input}"
      success, stderr = verify(CONFIG, {}, release: RELEASE.sub("          persist-credentials: false\n", "          persist-credentials: false\n#{line}"))
      refute success, input
      assert_includes stderr, "release.yaml has an actions/checkout step with unapproved inputs: #{input}"
    end
  end

  def test_rejects_continue_on_error_at_any_depth
    job_level = MINIMAL_CI.sub("  changes:\n", "  changes:\n    continue-on-error: true\n")
    step_level = MINIMAL_CI.sub('- run: "true"', "- run: \"true\"\n        continue-on-error: true")
    [job_level, step_level].each do |ci|
      refute_equal MINIMAL_CI, ci
      success, stderr = verify(CONFIG, {}, ci: ci)
      refute success
      assert_includes stderr, "must not use continue-on-error"
    end
  end

  def test_rejects_a_workflow_at_the_reserved_tap_path
    %w[tap.yaml tap.yml].each do |name|
      success, stderr = verify(CONFIG, { ".github/workflows/#{name}" => workflow_using("run: true") })
      refute success, name
      assert_includes stderr, ".github/workflows/#{name} is reserved"
    end
  end

  def test_release_config_selects_only_portable_readonly_build
    build = CONFIG.fetch("builds").fetch(0)
    assert_equal ["portable_readonly"], build.fetch("tags")
    assert_equal ["CGO_ENABLED=0"], build.fetch("env")
    assert_equal ["linux"], build.fetch("goos")
    assert_equal %w[amd64 arm64], build.fetch("goarch")
    assert_equal ["tar.gz"], CONFIG.fetch("archives").fetch(0).fetch("formats")
    refute CONFIG.key?("homebrew")
    refute CONFIG.key?("homebrew_casks")
  end

  def test_rejects_a_nonportable_build_tag
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("builds").fetch(0)["tags"] = ["ordinary"]
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "invalid tags"
  end

  def test_rejects_cgo_or_windows_portable_build
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("builds").fetch(0)["env"] = ["CGO_ENABLED=1"]
    changed.fetch("builds").fetch(0)["goos"] << "windows"
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "invalid env"
    assert_includes stderr, "invalid goos"
  end

  def test_rejects_the_old_ldflags_prefix
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("builds").fetch(0)["ldflags"] = changed.fetch("builds").fetch(0).fetch("ldflags").map { |flag| flag.sub("agent-clis/", "") }
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "invalid provenance ldflags"
  end

  def test_rejects_release_config_hooks_or_extra_archive_files
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed["before"] = { "hooks" => ["curl https://example.invalid"] }
    changed.fetch("archives").fetch(0)["files"] = ["private/*"]
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "unapproved top-level section"
    assert_includes stderr, "must publish only portable read-only tar.gz archives"
  end

  def test_rejects_enabled_release_or_checksum_settings
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed["release"] = { "github" => { "owner" => "abigotado", "name" => "agent-clis" } }
    changed.fetch("checksum")["algorithm"] = "sha512"
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "leave publication to the release workflow"
    assert_includes stderr, "only the approved checksum"
  end

  def test_rejects_a_changed_snapshot_version
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed["snapshot"] = { "version_template" => "{{ .Tag }}" }
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "version from CLI_VERSION"
  end

  def test_rejects_homebrew_and_quarantine_workarounds
    ["Formula/youtrack-agent-cli.rb", "youtrack-agent-cli/Formula/youtrack-agent-cli.rb"].each do |formula|
      success, stderr = verify(CONFIG, { formula => "class YoutrackAgentCli < Formula; end\n" })
      refute success, formula
      assert_includes stderr, "Homebrew Formula/Cask"
    end

    ["packaging/install.sh", "youtrack-agent-cli/packaging/homebrew/x.sh", "youtrack-agent-cli/scripts/deep/x.sh"].each do |script|
      success, stderr = verify(CONFIG, { script => "xattr -dr com.apple.quarantine binary\n" })
      refute success, script
      assert_includes stderr, "quarantine bypass"
    end
  end

  def test_rejects_unrelated_publisher
    workflow = <<~YAML
      name: upload
      on:
        push:
          tags: ["v*"]
      permissions:
        contents: write
      jobs:
        publish:
          runs-on: ubuntu-latest
          steps:
            - run: gh release create v0.1.0
    YAML
    success, stderr = verify(CONFIG, { ".github/workflows/other.yaml" => workflow })
    refute success
    assert_includes stderr, "must set read-only permissions"
    assert_includes stderr, "publication action"
  end

  def test_rejects_unpinned_or_unapproved_actions
    success, stderr = verify(CONFIG, { ".github/workflows/other.yaml" => workflow_using("uses: actions/checkout@v7") })
    refute success
    assert_includes stderr, "unpinned action"

    success, stderr = verify(CONFIG, { ".github/workflows/other.yaml" => workflow_using("uses: actions/upload-artifact@#{'a' * 40}") })
    refute success
    assert_includes stderr, "unapproved action"
  end

  def test_rejects_secrets_outside_the_publisher
    success, stderr = verify(CONFIG, { ".github/workflows/ci.yaml" => workflow_using("run: echo ${{ secrets.TOKEN }}") })
    refute success
    assert_includes stderr, "forbidden secrets context"
  end

  def test_release_workflow_is_prefixed_tag_only_and_scoped
    workflow = YAML.safe_load(RELEASE, permitted_classes: [], aliases: false)
    assert_equal({ "contents" => "read" }, workflow.fetch("permissions"))
    assert_equal({ "push" => { "tags" => ["youtrack-agent-cli/v0.*"] } }, workflow.fetch(true))
    assert_equal "verify", workflow.fetch("jobs").fetch("build").fetch("needs")
    assert_equal %w[verify build], workflow.fetch("jobs").fetch("draft").fetch("needs")
    assert_equal({ "contents" => "write" }, workflow.fetch("jobs").fetch("draft").fetch("permissions"))
    refute workflow.fetch("jobs").fetch("build").key?("permissions")
    assert_equal 2, RELEASE.scan("persist-credentials: false").length
    refute_match(/homebrew|xattr|secrets\./i, RELEASE)
    assert_includes RELEASE, "-tags portable_readonly"
    assert_includes RELEASE, "--draft --verify-tag"
  end

  def test_rejects_a_root_tag_trigger
    changed = RELEASE.sub('"youtrack-agent-cli/v0.*"', '"v0.*"')
    refute_equal RELEASE, changed
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end

  def test_rejects_a_second_upload_path_in_release_workflow
    changed = "#{RELEASE}      - run: curl -T artifact https://example.invalid\n"
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end

  def test_rejects_publishing_the_draft
    changed = RELEASE.sub("--draft --verify-tag", "--verify-tag")
    refute_equal RELEASE, changed
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end

  def test_rejects_removing_operator_write_dependency_guard
    changed = RELEASE.sub("auth|application|journal|mutation|operatorwrite|youtrack", "auth|application|journal|mutation|youtrack")
    refute_equal RELEASE, changed
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved publisher"
  end
end
