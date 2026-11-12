from __future__ import annotations

import re
import unittest
from pathlib import Path


HOOKS = Path(__file__).resolve().parents[1] / "hooks.toml"


def _hook_tables(text: str) -> dict[str, str]:
    """Each `[[hooks]]` table's body, keyed by its id.

    Parsed by text rather than tomllib: the harness interpreter may be a
    Python older than 3.11 (`AGENT_HARNESS_PYTHON`, see quality-gates.md).
    """
    tables: dict[str, str] = {}
    for body in re.split(r"^\[\[hooks\]\]\s*$", text, flags=re.MULTILINE)[1:]:
        match = re.search(r'^id\s*=\s*"([^"]+)"\s*$', body, flags=re.MULTILINE)
        if match is None:
            raise AssertionError(f"hook table without an id: {body!r}")
        tables[match.group(1)] = body
    return tables


class HooksManifestTest(unittest.TestCase):
    def test_pre_push_guard_blocks_when_it_cannot_run(self) -> None:
        tables = _hook_tables(HOOKS.read_text(encoding="utf-8"))
        self.assertIn("pre_push_guard", tables)
        self.assertRegex(
            tables["pre_push_guard"],
            re.compile(r'^on_failure\s*=\s*"block"\s*$', re.MULTILINE),
            "a crashed or timed-out pre_push_guard must refuse the command, "
            "not let the push through",
        )


if __name__ == "__main__":
    unittest.main()
