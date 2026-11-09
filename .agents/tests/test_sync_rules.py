from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync-rules.py"
SPEC = importlib.util.spec_from_file_location("youtrack_cli_sync_rules", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SYNC_RULES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SYNC_RULES
SPEC.loader.exec_module(SYNC_RULES)


class SyncRulesTest(unittest.TestCase):
    def _repo(self, temporary: str) -> Path:
        repo = Path(temporary) / "repo"
        canonical = repo / ".agents" / "rules"
        cursor = repo / ".cursor" / "rules"
        canonical.mkdir(parents=True)
        cursor.mkdir(parents=True)
        for name in SYNC_RULES.RULES:
            (canonical / f"{name}.md").write_text(
                f"# {name}\n\nCanonical {name} rule.\n",
                encoding="utf-8",
            )
        for cli, rules in SYNC_RULES.CLI_RULES.items():
            rules_root = repo / cli / "rules"
            rules_root.mkdir(parents=True)
            for name in rules:
                (rules_root / f"{name}.md").write_text(
                    f"# {name}\n\nCanonical {cli} {name} rule.\n",
                    encoding="utf-8",
                )
        return repo

    def test_extra_rule_is_detected_and_removed_by_sync(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            SYNC_RULES.synchronize(repo, check=False)
            stale = repo / ".cursor" / "rules" / "stale.mdc"
            stale.write_text("stale\n", encoding="utf-8")

            with self.assertRaisesRegex(
                SYNC_RULES.RuleDriftError,
                r"unexpected Cursor rule: \.cursor/rules/stale\.mdc",
            ):
                SYNC_RULES.synchronize(repo, check=True)

            result = SYNC_RULES.synchronize(repo, check=False)

            self.assertEqual(result.removed, (stale.resolve(),))
            self.assertFalse(stale.exists())
            SYNC_RULES.synchronize(repo, check=True)

    def test_undeclared_canonical_rule_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            SYNC_RULES.synchronize(repo, check=False)
            (repo / ".agents" / "rules" / "undeclared.md").write_text(
                "# undeclared\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                SYNC_RULES.RuleSyncError,
                r"unexpected canonical rule: \.agents/rules/undeclared\.md",
            ):
                SYNC_RULES.synchronize(repo, check=True)

    def test_undeclared_cli_rule_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            (repo / "youtrack-agent-cli" / "rules" / "undeclared.md").write_text(
                "# undeclared\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                SYNC_RULES.RuleSyncError,
                r"unexpected canonical rule: youtrack-agent-cli/rules/undeclared\.md",
            ):
                SYNC_RULES.synchronize(repo, check=False)

    def test_nested_rules_are_rejected(self) -> None:
        for directory in (".agents", "youtrack-agent-cli"):
            with self.subTest(directory=directory):
                with tempfile.TemporaryDirectory() as temporary:
                    repo = self._repo(temporary)
                    nested = repo / directory / "rules" / "nested"
                    nested.mkdir()
                    (nested / "rule.md").write_text("# nested\n", encoding="utf-8")

                    with self.assertRaisesRegex(
                        SYNC_RULES.RuleSyncError,
                        rf"unexpected canonical rule: {directory}/rules/nested/rule\.md",
                    ):
                        SYNC_RULES.synchronize(repo, check=False)

    def test_cli_mirror_is_prefixed_and_scoped_to_its_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            SYNC_RULES.synchronize(repo, check=False)
            mirror = (
                repo / ".cursor" / "rules" / "youtrack-agent-cli--cli-contract.mdc"
            ).read_text(encoding="utf-8")
            _, frontmatter, _ = mirror.split("---\n", 2)
            globs = frontmatter.split('globs: "', 1)[1].split('"', 1)[0].split(",")

            self.assertIn("alwaysApply: false", frontmatter)
            self.assertEqual(len(globs), 3)
            for glob in globs:
                self.assertTrue(glob.startswith("youtrack-agent-cli/"), glob)

    def test_rendered_mirror_keeps_canonical_body_after_frontmatter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            SYNC_RULES.synchronize(repo, check=False)
            name = "testing"
            canonical = (repo / ".agents" / "rules" / f"{name}.md").read_text(
                encoding="utf-8"
            )
            mirror = (repo / ".cursor" / "rules" / f"{name}.mdc").read_text(
                encoding="utf-8"
            )
            _, frontmatter, body = mirror.split("---\n", 2)

            self.assertIn(f"description: {SYNC_RULES.RULES[name]['description']}", frontmatter)
            self.assertIn("alwaysApply: false", frontmatter)
            self.assertIn(f'globs: "{SYNC_RULES.RULES[name]["globs"]}"', frontmatter)
            self.assertEqual(body, "\n" + canonical)

    def test_symlink_escape_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            SYNC_RULES.synchronize(repo, check=False)
            outside = Path(temporary) / "outside.mdc"
            outside.write_text("outside\n", encoding="utf-8")
            escape = repo / ".cursor" / "rules" / "escape.mdc"
            escape.symlink_to(outside)

            with self.assertRaisesRegex(
                SYNC_RULES.RuleSyncError,
                r"must not contain symlinks",
            ):
                SYNC_RULES.synchronize(repo, check=False)

            self.assertTrue(escape.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")


class RealRepositoryInventoryTest(unittest.TestCase):
    """Guard the declared inventory against the files actually committed.

    The synthetic tests build their fixture from RULES, so they stay green when
    a new canonical rule is added without declaring it. These assert the real
    tree instead.
    """

    def test_declared_rules_match_committed_canonical_files(self) -> None:
        committed = {path.stem for path in (REPO / ".agents" / "rules").glob("*.md")}

        self.assertEqual(committed, set(SYNC_RULES.RULES))

    def test_declared_cli_rules_match_committed_files(self) -> None:
        for cli, rules in SYNC_RULES.CLI_RULES.items():
            committed = {path.stem for path in (REPO / cli / "rules").glob("*.md")}

            self.assertEqual(committed, set(rules))

    def test_committed_mirrors_match_declared_rules(self) -> None:
        mirrors = {path.stem for path in (REPO / ".cursor" / "rules").glob("*.mdc")}
        declared = set(SYNC_RULES.RULES) | {
            f"{cli}--{name}"
            for cli, rules in SYNC_RULES.CLI_RULES.items()
            for name in rules
        }

        self.assertEqual(mirrors, declared)

    def test_committed_mirrors_are_in_sync(self) -> None:
        SYNC_RULES.synchronize(REPO, check=True)


if __name__ == "__main__":
    unittest.main()
