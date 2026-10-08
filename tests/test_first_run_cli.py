"""What a first-time user sees from the command line."""
from __future__ import annotations

import os
import subprocess
import sys


def _kratos(tmp_path, *args, columns=80):
    env = {**os.environ, "KRATOS_HOME": str(tmp_path), "COLUMNS": str(columns), "NO_COLOR": "1"}
    return subprocess.run([sys.executable, "-m", "kratos.cli.app", *args], capture_output=True, text=True,
                          env=env, timeout=120)


def test_help_fits_one_screen_and_cuts_nothing_off(tmp_path):
    out = _kratos(tmp_path, "--help").stdout
    lines = out.rstrip("\n").splitlines()
    assert len(lines) <= 24
    assert "Open the full-screen app" in out          # bare `kratos` is the starting point
    assert not any(line.rstrip("│ ").endswith("...") for line in lines)
    assert "ReAct" not in out


def test_help_all_wraps_instead_of_cutting(tmp_path):
    out = _kratos(tmp_path, "--help", "--all").stdout
    assert "read-only checks" in out.replace("\n", " ").replace("│", " ").replace("  ", " ") or "read-only" in out
    assert not any(line.rstrip("│ ").endswith("...") for line in out.splitlines())


def test_chat_with_nothing_to_explain_says_what_to_do(tmp_path):
    proc = _kratos(tmp_path, "chat", "-q", "hi")
    assert proc.returncode == 1
    assert "Nothing to explain yet" in proc.stderr and "kratos run" in proc.stderr
    assert "bundle" not in (proc.stdout + proc.stderr)
