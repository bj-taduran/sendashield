"""Asserts the CI gates actually cover the code, per CLAUDE.md invariant 12.

A gate can fail in two ways. It can be wrong about what it inspects, which shows up as a
red build and gets fixed. Or it can inspect nothing, which shows up as a green build and
does not get fixed — it gets trusted. Only the second kind is dangerous, and only the
second kind is what happened here: the `mypy` step ran against `src/sendashield/detect` and
`src/sendashield/policy`, both empty scaffolding, and reported success over zero lines for
the entire life of the project while `normalise.py` and `ical.py` went unchecked.

These tests are cheap and read the workflow file directly, so the gate's *scope* is now
itself under test. Parsed textually rather than with PyYAML: CLAUDE.md asks before adding a
dependency, and the shape needed here is one command line.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SOURCE_ROOT = REPO_ROOT / "src" / "sendashield"


def _run_commands() -> list[str]:
    """Every `run:` command in the workflow, single-line form."""
    text = WORKFLOW.read_text(encoding="utf-8")
    return [
        match.group(1).strip() for match in re.finditer(r"^\s*run:\s*(.+)$", text, re.MULTILINE)
    ]


def _command_containing(tool: str) -> str:
    matches = [c for c in _run_commands() if re.search(rf"\b{tool}\b", c)]
    assert matches, f"no CI step runs {tool} — the gate is absent, not merely narrow"
    assert len(matches) == 1, f"expected exactly one {tool} step, found {len(matches)}: {matches}"
    return matches[0]


def _paths_in(command: str) -> list[Path]:
    """Positional path arguments of a command, ignoring the tool name and any flags."""
    tokens = command.split()
    return [
        (REPO_ROOT / token).resolve()
        for token in tokens
        if not token.startswith("-") and (REPO_ROOT / token).exists()
    ]


def test_workflow_file_exists() -> None:
    # Everything below silently passes if the path is wrong, which would make this module
    # the very thing it was written to prevent.
    assert WORKFLOW.is_file(), f"CI workflow not found at {WORKFLOW}"
    assert _run_commands(), "no run: commands parsed from the workflow — parser is broken"


def test_mypy_step_covers_every_source_file() -> None:
    """The regression that motivated this file.

    Not "does CI run mypy" — it did — but "does what it runs reach this file". Asserted per
    file, so pointing the step at a subpackage that happens to be empty fails here instead
    of passing quietly.
    """
    targets = _paths_in(_command_containing("mypy"))
    assert targets, "the mypy step has no path arguments at all"

    uncovered = [
        path.relative_to(REPO_ROOT)
        for path in sorted(SOURCE_ROOT.rglob("*.py"))
        if not any(path.is_relative_to(target) for target in targets)
    ]
    assert not uncovered, (
        f"CI's mypy step does not cover {len(uncovered)} source file(s): {uncovered}. "
        f"A type gate that skips the code it is meant to guard reports success over "
        f"nothing — see CLAUDE.md invariant 12."
    )


def test_mypy_step_covers_the_tests_themselves() -> None:
    targets = _paths_in(_command_containing("mypy"))
    tests_dir = (REPO_ROOT / "tests").resolve()
    assert any(tests_dir.is_relative_to(target) or target == tests_dir for target in targets), (
        "CI's mypy step does not cover tests/ — test code is where fixture wiring and "
        "assertion helpers live, and a type error there weakens the suite silently"
    )


@pytest.mark.parametrize("tool", ["ruff check", "ruff format", "pytest"])
def test_other_gates_are_still_wired(tool: str) -> None:
    # Cheap presence check. It would not catch a narrowed scope the way the mypy test
    # above does, but it does catch a step being deleted or renamed away.
    assert any(tool in command for command in _run_commands()), f"no CI step runs `{tool}`"
