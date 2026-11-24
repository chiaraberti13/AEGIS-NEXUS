from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def test_core_modules_pass_mypy_gate():
    # Regression gate: the curated core module set (configured in pyproject
    # [tool.mypy] files) must type-check cleanly. Skipped if mypy is absent.
    pytest.importorskip("mypy")
    result = subprocess.run(
        [sys.executable, "-m", "mypy"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"mypy gate failed:\n{result.stdout}\n{result.stderr}"
