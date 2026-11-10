"""Every file the wheel ships as package data is tracked by git (audit D).

The package check builds the wheel from the working tree, so a data file that a broad
.gitignore rule hides (the D.8 word list matched both `data/` and `*.txt`) is present here
and missing from every clean clone, CI run and release. This fails while one is untracked."""
from __future__ import annotations

import subprocess

from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")   # Python 3.11+; 3.10 is covered by the other versions

ROOT = Path(__file__).resolve().parents[1]


def _tracked() -> set[str]:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "src/kratos"], capture_output=True, text=True,
                             timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("not a git checkout")
    return set(out.splitlines())


def test_every_package_data_file_is_tracked_by_git():
    tracked = _tracked()
    if not tracked:
        pytest.skip("not a git checkout")
    spec = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]["package-data"]
    pkg = ROOT / "src" / "kratos"
    untracked = []
    for pattern in spec.get("kratos", []):
        for f in pkg.glob(pattern):
            if f.is_file() and "__pycache__" not in f.parts:
                rel = str(f.relative_to(ROOT))
                if rel not in tracked:
                    untracked.append(rel)
    assert not untracked, f"shipped as package data but not in git (check .gitignore): {untracked}"
