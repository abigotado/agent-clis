#!/usr/bin/env ruby

require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"

class CiChangesTest < Minitest::Test
  SCRIPT = File.join(__dir__, "ci-changes.sh")
  ALL = { "youtrack" => "false", "all" => "true" }.freeze
  YOUTRACK_ONLY = { "youtrack" => "true", "all" => "false" }.freeze

  def git(repo, *args)
    stdout, stderr, status = Open3.capture3("git", "-C", repo, *args)
    assert status.success?, "git #{args.join(' ')}: #{stderr}"
    stdout.strip
  end

  def write(repo, relative, content = "content\n")
    target = File.join(repo, relative)
    FileUtils.mkdir_p(File.dirname(target))
    File.write(target, content)
  end

  # Builds a repository with a base commit, applies the change, commits it, and
  # runs the script against that range.
  def select(event: "pull_request", base: :base, head: :head)
    Dir.mktmpdir("ci-changes") do |dir|
      repo = File.join(dir, "repo")
      FileUtils.mkdir_p(repo)
      git(repo, "init", "-q", "-b", "main")
      git(repo, "config", "user.email", "test@example.invalid")
      git(repo, "config", "user.name", "test")
      write(repo, "youtrack-agent-cli/go.mod", "module example\n")
      write(repo, "top.txt")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "base")
      base_sha = git(repo, "rev-parse", "HEAD")
      yield repo
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "--allow-empty", "-m", "head")
      head_sha = git(repo, "rev-parse", "HEAD")

      output = File.join(dir, "output")
      env = {
        "EVENT_NAME" => event,
        "BASE_SHA" => base == :base ? base_sha : base,
        "HEAD_SHA" => head == :head ? head_sha : head,
        "GITHUB_OUTPUT" => output,
      }
      combined, status = Open3.capture2e(env, SCRIPT, chdir: repo)
      pairs = File.exist?(output) ? File.readlines(output, chomp: true).to_h { |line| line.split("=", 2) } : nil
      [status.success?, pairs, combined]
    end
  end

  def test_only_cli_paths_select_only_that_cli
    success, pairs, stderr = select { |repo| write(repo, "youtrack-agent-cli/internal/a.go") }
    assert success, stderr
    assert_equal YOUTRACK_ONLY, pairs
  end

  def test_shared_paths_select_everything
    [".agents/rules/x.md", ".github/workflows/x.yaml", ".githooks/pre-push", "tools/x", "README.md", "unknown/x"].each do |path|
      success, pairs, stderr = select { |repo| write(repo, path) }
      assert success, stderr
      assert_equal ALL, pairs, path
    end
  end

  def test_a_cli_path_with_a_shared_path_selects_everything
    success, pairs, stderr = select do |repo|
      write(repo, "youtrack-agent-cli/internal/a.go")
      write(repo, ".agents/rules/x.md")
    end
    assert success, stderr
    assert_equal ALL, pairs
  end

  def test_a_rename_into_the_cli_directory_selects_everything
    success, pairs, stderr = select { |repo| git(repo, "mv", "top.txt", "youtrack-agent-cli/top.txt") }
    assert success, stderr
    assert_equal ALL, pairs
  end

  def test_a_push_selects_everything
    success, pairs, stderr = select(event: "push") { |repo| write(repo, "youtrack-agent-cli/internal/a.go") }
    assert success, stderr
    assert_equal ALL, pairs
  end

  def test_an_unusable_base_selects_everything
    ["", "0" * 40, "1" * 40].each do |base|
      success, pairs, stderr = select(base: base) { |repo| write(repo, "youtrack-agent-cli/internal/a.go") }
      assert success, stderr
      assert_equal ALL, pairs, base
    end
  end

  def test_an_empty_diff_selects_everything
    success, pairs, stderr = select { |_repo| nil }
    assert success, stderr
    assert_equal ALL, pairs
  end

  def test_an_unregistered_module_fails
    ["go.mod", "foo/go.mod"].each do |path|
      success, pairs, stderr = select { |repo| write(repo, path, "module example\n") }
      refute success, path
      assert_nil pairs
      assert_includes stderr, "registered list"
    end
  end
end
