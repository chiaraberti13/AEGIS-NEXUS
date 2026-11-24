from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff not installed")
def test_high_signal_lint_gate_is_clean():
    # Gate: the ruff rule set configured in pyproject [tool.ruff.lint]
    # (pyflakes/syntax/bugbear — correctness, not style) must stay clean.
    result = subprocess.run(
        ["ruff", "check", "src", "tests", "scripts"],
        cwd=_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, f"ruff lint gate failed:\n{result.stdout}\n{result.stderr}"
