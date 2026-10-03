"""nmap's human-readable report must never reach an inherited file descriptor:
fd 1 is the JSON-RPC channel under `kratos mcp-serve`, and inside the TUI
Textual's stderr stand-in has fileno() == -1, which subprocess reads as
"don't redirect" -- the report then landed on the real terminal over the UI."""
from __future__ import annotations

import io
import os
import stat
import sys
from pathlib import Path

import pytest

from kratos.adapters import nmap_scan

FAKE_NMAP = """#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-oX" ]; then out="$2"; shift; fi
  shift
done
echo "Starting Nmap 7.94 ( https://nmap.org )"
echo "Nmap done: 1 IP address (1 host up)"
echo "a warning on stderr" >&2
printf '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/></host></nmaprun>' > "$out"
[ -n "$FAIL" ] && { echo "boom: something broke" >&2; exit 3; }
exit 0
"""


class _TextualLikeStderr(io.StringIO):
    def fileno(self) -> int:  # what Textual's _PrintCapture returns
        return -1


@pytest.fixture
def fake_nmap(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "nmap"
    exe.write_text(FAKE_NMAP)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return tmp_path


def _scan(data_dir: Path):
    return nmap_scan.run_nmap_scan(data_dir, "192.0.2.5")


def test_report_goes_through_python_stderr_never_a_raw_fd(fake_nmap, monkeypatch, capfd):
    fake_err = _TextualLikeStderr()
    monkeypatch.setattr(sys, "stderr", fake_err)
    out = _scan(fake_nmap / "data")
    raw = capfd.readouterr()
    assert "Nmap done" not in raw.out and "Nmap done" not in raw.err  # nothing on fd 1 or fd 2
    assert "Nmap done" in fake_err.getvalue() and "a warning on stderr" in fake_err.getvalue()
    assert Path(out).exists()


def test_a_failure_carries_nmaps_own_reason(fake_nmap, monkeypatch, capfd):
    monkeypatch.setenv("FAIL", "1")
    monkeypatch.setattr(sys, "stderr", _TextualLikeStderr())
    with pytest.raises(RuntimeError, match="exit code 3: boom: something broke"):
        _scan(fake_nmap / "data")
    raw = capfd.readouterr()
    assert "boom" not in raw.out and "boom" not in raw.err
