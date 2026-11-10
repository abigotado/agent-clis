#!/usr/bin/env python3
"""Synchronize canonical .agents rules to tracked Cursor compatibility files."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


RULES = {
    "architecture": {
        "description": "Monorepo layout, module boundaries, and tag conventions.",
        "always_apply": True,
        "globs": None,
    },
    "go-style": {
        "description": "Go conventions: errors, context, resources, naming.",
        "always_apply": False,
        "globs": "**/*.go",
    },
    "testing": {
        "description": "Table-driven tests and boundary mocking conventions.",
        "always_apply": False,
        "globs": "**/*_test.go",
    },
    # Always applied: credential handling is a property of the whole binary,
    # and the failure mode is leaking a token, not a localized bug.
    "secrets": {
        "description": "Credential storage, redaction, and logging rules.",
        "always_apply": True,
        "globs": None,
    },
    # Always applied: the gate is a property of pushing any change, so there is
    # no file glob that usefully scopes it.
    "quality-gates": {
        "description": "Git hook installation, the pre-push gate, and CI.",
        "always_apply": True,
        "globs": None,
    },
}

# Per-CLI rules live in <cli>/rules/, outside .agents/, because the provider
# compiler loads everything under .agents/rules/ in every session. Globs are
# repository-relative and comma-joined, since a mirror holds one list.
CLI_RULES = {
    "youtrack-agent-cli": {
        "architecture": {
            "description": "youtrack-agent-cli package boundaries and dependency direction.",
            "always_apply": False,
            "globs": "youtrack-agent-cli/**",
        },
        # The machine contract is the CLI's public API. Scoped to the packages
        # that define and render it, not to every .go file, so unrelated work
        # does not pull the whole contract into context.
        "cli-contract": {
            "description": "youtrack-agent-cli JSON envelope, exit codes, and flag naming contract.",
            "always_apply": False,
            "globs": (
                "youtrack-agent-cli/internal/cli/**/*.go,"
                "youtrack-agent-cli/internal/errx/**/*.go,"
                "youtrack-agent-cli/internal/output/**/*.go"
            ),
        },
    },
}


class RuleSyncError(RuntimeError):
    """Raised when repository layout cannot be synchronized safely."""


class RuleDriftError(RuleSyncError):
    """Raised when check mode finds missing, changed, or unexpected mirrors."""


@dataclass(frozen=True)
class SyncResult:
    updated: int
    removed: tuple[Path, ...]


def _render(source: Path, metadata: dict[str, object]) -> str:
    body = source.read_text(encoding="utf-8").rstrip() + "\n"
    lines = [
        "---",
        f"description: {metadata['description']}",
        f"alwaysApply: {str(metadata['always_apply']).lower()}",
    ]
    globs = metadata["globs"]
    if globs is not None:
        lines.append(f'globs: "{globs}"')
    lines.extend(["---", "", body])
    return "\n".join(lines)


def _assert_real_directory(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise RuleSyncError(f"{label} must be a real directory: {path}")
    return path.resolve()


def _assert_contained(path: Path, root: Path, *, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuleSyncError(f"{label} escapes {root}: {path}") from exc
    return resolved


def _validate_tree(root: Path, *, label: str) -> tuple[Path, ...]:
    resolved_root = _assert_real_directory(root, label=label)
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuleSyncError(f"{label} must not contain symlinks: {path}")
        _assert_contained(path, resolved_root, label=label)
        if path.suffix == ".mdc":
            if not path.is_file():
                raise RuleSyncError(f"{label} .mdc entry must be a file: {path}")
            files.append(path)
    return tuple(files)


def _check_inventory(root: Path, names: dict[str, object], repo: Path) -> None:
    """Fail unless root holds exactly the declared rules, none of them nested."""
    _assert_real_directory(root, label="canonical rules")
    expected = {root / f"{name}.md" for name in names}
    actual = set(root.rglob("*.md"))
    details = [
        *(f"unexpected canonical rule: {path.relative_to(repo)}" for path in sorted(actual - expected)),
        *(f"missing canonical rule: {path.relative_to(repo)}" for path in sorted(expected - actual)),
    ]
    if details:
        raise RuleSyncError("\n".join(details))
    for path in sorted(expected):
        if path.is_symlink() or not path.is_file():
            raise RuleSyncError(f"missing real canonical rule: {path}")
        _assert_contained(path, root.resolve(), label="canonical rule")


def _check_unregistered_cli_rules(repo: Path) -> None:
    """Fail on rules under a top-level <dir>/rules/ whose <dir> is not in CLI_RULES."""
    details = [
        f"unexpected canonical rule: {path.relative_to(repo)}"
        for top in sorted(repo.glob("*/"))
        if top.is_dir() and not top.name.startswith(".") and top.name not in CLI_RULES
        for path in sorted(top.glob("rules/**/*.md"))
    ]
    if details:
        raise RuleSyncError("\n".join(details) + "\nregister the directory in CLI_RULES")


def _declared_rules(repo: Path) -> dict[str, tuple[Path, dict[str, object]]]:
    """Map each mirror name to its validated canonical source and metadata."""
    canonical_root = repo / ".agents" / "rules"
    _check_inventory(canonical_root, RULES, repo)
    _check_unregistered_cli_rules(repo)
    declared = {name: (canonical_root / f"{name}.md", metadata) for name, metadata in RULES.items()}
    for cli, rules in CLI_RULES.items():
        rules_root = repo / cli / "rules"
        _check_inventory(rules_root, rules, repo)
        for name, metadata in rules.items():
            declared[f"{cli}--{name}"] = (rules_root / f"{name}.md", metadata)
    return declared


def synchronize(repo: Path, *, check: bool) -> SyncResult:
    """Check or update the exact declared Cursor mirror inventory."""
    repo = repo.resolve()
    agents_root = repo / ".agents"
    cursor_parent = repo / ".cursor"
    _assert_real_directory(agents_root, label=".agents")
    _assert_real_directory(cursor_parent, label=".cursor")

    cursor_root = cursor_parent / "rules"
    existing_cursor_files = _validate_tree(cursor_root, label="Cursor rules")

    expected = {
        cursor_root / f"{name}.mdc": _render(source, metadata)
        for name, (source, metadata) in _declared_rules(repo).items()
    }

    existing = set(existing_cursor_files)
    expected_paths = set(expected)
    extras = sorted(existing - expected_paths)
    drift = sorted(
        path
        for path, content in expected.items()
        if not path.is_file()
        or path.is_symlink()
        or path.read_text(encoding="utf-8") != content
    )

    if check and (extras or drift):
        details = [
            *(f"unexpected Cursor rule: {path.relative_to(repo)}" for path in extras),
            *(f"out of sync: {path.relative_to(repo)}" for path in drift),
        ]
        raise RuleDriftError("\n".join(details))

    if check:
        return SyncResult(updated=0, removed=())

    # The complete tree was validated before this point. Remove only stale,
    # contained, real .mdc files; never unlink a symlink or directory.
    for path in extras:
        if path.is_symlink() or not path.is_file():
            raise RuleSyncError(f"refusing to remove unsafe Cursor rule: {path}")
        _assert_contained(path, cursor_root.resolve(), label="stale Cursor rule")
    for path in extras:
        path.unlink()

    for path, content in expected.items():
        path.write_text(content, encoding="utf-8")
    return SyncResult(updated=len(expected), removed=tuple(extras))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without writing compatibility mirrors",
    )
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    try:
        result = synchronize(repo, check=args.check)
    except RuleDriftError as error:
        print(error, file=sys.stderr)
        return 1
    except (OSError, UnicodeError, RuleSyncError) as error:
        print(error, file=sys.stderr)
        return 2

    if args.check:
        mirrors = len(RULES) + sum(len(rules) for rules in CLI_RULES.values())
        print(f"Cursor rule mirrors are in sync ({mirrors} files).")
    else:
        for path in result.removed:
            print(f"Removed stale Cursor rule: {path.relative_to(repo)}")
        print(f"Updated {result.updated} Cursor rule mirrors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
