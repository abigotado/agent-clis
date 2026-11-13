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
    [
      ["home path (macOS)", "x := \"/Users/someone/project\"\n"],
      ["home path (Linux)", "x := \"/home/someone/project\"\n"],
      ["home path (macOS)", "x := \"/Users/someone\"\n"],
      ["home path (Linux)", "// /home/someone\n"],
      ["home path (Windows)", "x := `C:\\Users\\someone`\n"],
      ["agent worktree path", "// see .claude/worktrees/abc\n"],
      ["YouTrack service host", "// https://acme.youtrack.cloud/api\n"],
      ["Apple team identifier", "// TeamIdentifier=ABCDE12345\n"],
      ["Apple team identifier", "// Team ID: ABCDE12345\n"],
      ["Slack token", "// xoxb-#{'1' * 12}\n"],
      ["JWT", "// eyJ#{'a' * 12}.eyJ#{'b' * 12}\n"],
      ["bearer credential", "// Authorization: Bearer #{'z' * 30}\n"],
      ["co-author trailer", "Co-Authored-By: Someone <a@example.invalid>\n"],
      ["assistant byline", "// Generated with Claude Code\n"],
      ["assistant marker", "// sent with Cursor\n"],
      ["robot emoji byline", "// \u{1F916} made this\n"],
      ["YouTrack permanent token", "// perm:abcdefgh12345678\n"],
      ["GitHub token", "// ghp_#{'a' * 36}\n"],
      ["AWS access key", "// AKIA#{'A' * 16}\n"],
      ["private key block", "// -----BEGIN RSA PRIVATE KEY-----\n"],
      ["CLI module import", "import _ \"github.com/example/agent-clis/youtrack-agent-cli/internal/x\"\n"]
    ].each do |rule, content|
      out = assert_flags(rule, files: { "core/bad.go" => content })
      assert_includes out, "core/bad.go", rule
      %w[someone abcdefgh12345678 ABCDE12345 Bearer].each { |text| refute_includes out, text, rule }
    end
  end

  def test_old_module_path_import_is_flagged
    assert_flags("CLI module import",
                 files: { "core/bad.go" => "import _ \"github.com/example/youtrack-agent-cli/internal/x\"\n" })
  end

  def test_home_path_followed_by_a_non_path_character_is_flagged
    assert_flags("home path (macOS)", files: { "core/bad.go" => "// (/Users/someone)\n" })
    assert_flags("home path (Linux)", files: { "core/bad.go" => "// /home/someone, ok\n" })
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
      ["assistant marker", "feat: x\n\nsent with Cursor"],
      ["robot emoji byline", "feat: x\n\n\u{1F916} done"],
      ["JWT", "feat: x\n\neyJ#{'a' * 12}.eyJ#{'b' * 12}"],
      ["home path (macOS)", "feat: x\n\nsee /Users/someone/x"]
    ].each do |rule, message|
      out = assert_flags(rule, message: message)
      assert_includes out, "commit "
      %w[someone Cursor Claude].each { |text| refute_includes out, text, rule }
    end
  end

  def test_unresolvable_range_fails_instead_of_passing
    Dir.mktmpdir do |repo|
      git(repo, "init", "-q")
      write(repo, "core/clean.go", "package core\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "chore: base")
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, "origin/nonexistent..HEAD", chdir: repo)
      refute status.success?, out
      assert_includes out, "cannot resolve revision range"
      refute_includes out, "clean"
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => "nonexistent" }, SCRIPT, chdir: repo)
      refute status.success?, out
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, "--all", chdir: repo)
      refute status.success?, out
      assert_includes out, "must not start with '-'"
    end
  end

  def test_empty_valid_range_passes
    Dir.mktmpdir do |repo|
      git(repo, "init", "-q")
      write(repo, "core/clean.go", "package core\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "chore: base")
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, "HEAD..HEAD", chdir: repo)
      assert status.success?, out
      assert_includes out, "0 commit(s) clean"
    end
  end

  # A side branch that touched core/ is dropped by a merge that keeps the first
  # parent's tree; the range's net change to core/ is zero but the message of the
  # side commit still has to be scanned.
  def test_message_is_scanned_when_the_net_change_to_core_is_zero
    Dir.mktmpdir do |repo|
      git(repo, "init", "-q", "-b", "main")
      write(repo, "core/clean.go", "package core\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "chore: base")
      base = git(repo, "rev-parse", "HEAD")
      git(repo, "checkout", "-q", "-b", "side")
      write(repo, "core/side.go", "package core\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "feat: x\n\nCo-Authored-By: Someone <a@example.invalid>")
      git(repo, "checkout", "-q", "main")
      write(repo, "other/a.txt", "a\n")
      git(repo, "add", "-A")
      git(repo, "commit", "-q", "-m", "docs: x")
      git(repo, "merge", "-q", "-s", "ours", "--no-edit", "side")
      out, status = Open3.capture2e({ "GITHUB_BASE_REF" => nil }, SCRIPT, "#{base}..HEAD", chdir: repo)
      refute status.success?, out
      assert_includes out, "co-author trailer"
    end
  end

  # grep exits 2 when a pattern does not compile; that must fail the script.
  def test_grep_error_fails_instead_of_counting_as_no_match
    real_grep = Open3.capture2("sh", "-c", "command -v grep").first.strip
    Dir.mktmpdir do |bin|
      File.write(File.join(bin, "grep"), "#!/bin/sh\ncase \"$*\" in *-nE*) exit 2 ;; esac\nexec #{real_grep} \"$@\"\n")
      File.chmod(0o755, File.join(bin, "grep"))
      Dir.mktmpdir do |repo|
        git(repo, "init", "-q")
        write(repo, "core/clean.go", "package core\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "chore: base")
        env = { "GITHUB_BASE_REF" => nil, "PATH" => "#{bin}:#{ENV.fetch('PATH')}" }
        out, status = Open3.capture2e(env, SCRIPT, "HEAD", chdir: repo)
        refute status.success?, out
        assert_includes out, "failed to run"
      end
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
