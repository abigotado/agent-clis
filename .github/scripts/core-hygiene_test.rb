#!/usr/bin/env ruby

require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"

class CoreHygieneTest < Minitest::Test
  SCRIPT = File.join(__dir__, "core-hygiene.sh")

  def git(repo, *args)
    stdout, stderr, status = Open3.capture3(
      "git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args
    )
    assert status.success?, "git #{args.join(' ')}: #{stderr}"
    stdout.strip
  end

  def write(repo, relative, content)
    target = File.join(repo, relative)
    FileUtils.mkdir_p(File.dirname(target))
    File.write(target, content)
  end

  # Commits a clean base, then one change with the given message, and runs the
  # script over that change. Returns [stdout+stderr, success?].
  def run_scan(files: {}, message: "feat(core): add a thing", range: true)
    Dir.mktmpdir do |repo|
      git(repo, "init", "-q")
      write(repo, "core/clean.go", "package core\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "chore: base")
      files.each { |path, content| write(repo, path, content) }
      write(repo, "core/touch.go", "package core\n// #{rand(1 << 30)}\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", message)
      args = range ? ["HEAD~1..HEAD"] : []
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, *args, chdir: repo)
      [out, status.success?]
    end
  end

  def assert_flags(rule, **opts)
    out, ok = run_scan(**opts)
    refute ok, "expected a finding for #{rule}"
    assert_includes out, rule
    out
  end

  def test_clean_change_passes
    out, ok = run_scan
    assert ok, out
    assert_includes out, "clean"
  end

  def test_files_flag_each_rule_without_echoing_the_match
    {
      "home path (macOS)" => "x := \"/Users/someone/project\"\n",
      "home path (Linux)" => "x := \"/home/someone/project\"\n",
      "home path (Windows)" => "x := `C:\\Users\\someone`\n",
      "agent worktree path" => "// see .claude/worktrees/abc\n",
      "YouTrack service host" => "// https://acme.youtrack.cloud/api\n",
      "Apple team identifier" => "// TeamIdentifier=ABCDE12345\n",
      "YouTrack permanent token" => "// perm:abcdefgh12345678\n",
      "GitHub token" => "// ghp_#{'a' * 36}\n",
      "AWS access key" => "// AKIA#{'A' * 16}\n",
      "private key block" => "// -----BEGIN RSA PRIVATE KEY-----\n",
      "CLI module import" => "import _ \"github.com/abigotado/agent-clis/youtrack-agent-cli/internal/x\"\n"
    }.each do |rule, content|
      out = assert_flags(rule, files: { "core/bad.go" => content })
      assert_includes out, "core/bad.go", rule
      refute_includes out, "someone", rule
      refute_includes out, "abcdefgh12345678", rule
    end
  end

  def test_go_work_is_refused_in_core_and_at_the_root
    assert_flags("go.work must not be committed", files: { "core/go.work" => "go 1.26\n" })
    assert_flags("go.work must not be committed", files: { "go.work" => "go 1.26\n" })
  end

  def test_files_outside_core_are_not_scanned
    out, ok = run_scan(files: { "docs/note.md" => "/Users/someone/x\n" })
    assert ok, out
  end

  def test_commit_message_rules
    [
      ["co-author trailer", "feat: x\n\nCo-Authored-By: Someone <a@example.invalid>"],
      ["assistant byline", "feat: x\n\nGenerated with Claude Code"],
      ["home path (macOS)", "feat: x\n\nsee /Users/someone/x"]
    ].each do |rule, message|
      out = assert_flags(rule, message: message)
      assert_includes out, "commit "
    end
  end

  def test_commits_not_touching_core_are_not_scanned
    Dir.mktmpdir do |repo|
      git(repo, "init", "-q")
      write(repo, "core/clean.go", "package core\n")
      write(repo, "other/a.txt", "a\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "chore: base")
      write(repo, "other/a.txt", "b\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "docs: x\n\nCo-Authored-By: Someone <a@example.invalid>")
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, "HEAD~1..HEAD", chdir: repo)
      assert status.success?, out
    end
  end

  def test_no_core_files_fails_instead_of_passing_vacuously
    Dir.mktmpdir do |repo|
      git(repo, "init", "-q")
      write(repo, "other/a.txt", "a\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "chore: base")
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, chdir: repo)
      refute status.success?
      assert_includes out, "no tracked files under core/"
    end
  end

  def test_default_range_is_the_last_commit
    out, ok = run_scan(message: "feat: x\n\nCo-Authored-By: Someone <a@example.invalid>", range: false)
    refute ok
    assert_includes out, "co-author trailer"
  end
end
