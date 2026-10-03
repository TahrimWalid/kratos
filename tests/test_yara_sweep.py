"""run_yara_scan's default sweep (eval A4): the REAL generated script runs locally under
bash against temp directories with a stub `yara`, so path skipping, the silent-skip
readability accounting (yara exits 0 on unreadable dirs) and marker parsing are exercised
end to end without SSH."""
from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

from kratos.adapters import ssh_remote as S
from kratos.agent import tools

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="unreadable-dir checks need a non-root user")


@pytest.fixture
def local_remote(tmp_path, monkeypatch):
    """run_remote_script -> bash locally, with a stub yara first on PATH that
    'matches' any file whose name contains 'eicar' (like the real rule)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "yara"
    stub.write_text(textwrap.dedent("""\
        #!/bin/sh
        # yara -r -s RULES PATH
        find "$4" -type f -name '*eicar*' 2>/dev/null | while read -r f; do
          printf 'eicar %s\\n0x0:$eicar: X5O!P\\n' "$f"
        done
        exit 0
        """))
    stub.chmod(0o755)

    def run(script, timeout=None, shell="bash"):
        r = subprocess.run([shell, "-s"], input=script, capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"})
        return S.SSHResult(ok=r.returncode == 0, returncode=r.returncode, stdout=r.stdout, stderr=r.stderr)

    monkeypatch.setattr(S, "run_remote_script", run)
    return tmp_path


def test_sweep_finds_matches_and_accounts_for_what_it_could_not_read(local_remote):
    home, locked, partly = local_remote / "home", local_remote / "locked", local_remote / "partly"
    (home / "ubuntu").mkdir(parents=True)
    (home / "ubuntu" / "eicar.com").write_text("x")
    locked.mkdir()
    (partly / "secret").mkdir(parents=True)
    (partly / "secret" / "eicar.bin").write_text("x")
    (partly / "ok.txt").write_text("x")
    locked.chmod(0)
    (partly / "secret").chmod(0)
    try:
        out = S.fetch_yara_sweep((str(home), str(locked), str(partly), str(local_remote / "absent")), "rule r {}")
    finally:
        locked.chmod(0o755)
        (partly / "secret").chmod(0o755)
    assert [m["file"] if "file" in m else m.get("path") for m in out["matches"]] == [str(home / "ubuntu" / "eicar.com")]
    assert out["scanned"] == [str(home), str(partly)]
    assert out["unreadable_paths"] == [str(locked)]
    assert out["partially_unreadable"] == {str(partly): {"unreadable_dirs": 1, "unreadable_files": 0}}


def test_tool_default_sweep_reports_coverage(local_remote, monkeypatch):
    (local_remote / "h").mkdir()
    (local_remote / "h" / "eicar.com").write_text("x")
    monkeypatch.setattr(tools, "_DEFAULT_YARA_SWEEP_PATHS", (str(local_remote / "h"), "/nonexistent-kratos"))
    monkeypatch.setattr(tools, "_ssh_target_label", lambda: "ubuntu@10.0.0.5")
    monkeypatch.setattr(tools, "_fetch_yara_sweep", S.fetch_yara_sweep)
    res = tools.tool_run_yara_scan()
    assert res["status"] == "ok" and res["match_count"] == 1
    assert res["not_present_on_target"] == ["/nonexistent-kratos"] and "coverage_note" not in res


def test_missing_yara_is_an_error_not_a_clean_sweep(monkeypatch):
    monkeypatch.setattr(S, "run_remote_script", lambda script, **kw: S.SSHResult(
        ok=False, returncode=4, stdout="", stderr="yara is not installed on the target"))
    monkeypatch.setattr(tools, "_fetch_yara_sweep", S.fetch_yara_sweep)
    res = tools.tool_run_yara_scan()
    assert res["status"] == "error" and "not installed" in res["observation"]


def test_default_paths_never_include_the_filesystem_root():
    assert "/" not in S.DEFAULT_YARA_SWEEP_PATHS and "/home" in S.DEFAULT_YARA_SWEEP_PATHS


def test_scan_path_is_optional_in_the_registry():
    p = tools.TOOL_REGISTRY["run_yara_scan"].parameters["scan_path"]
    assert p.get("default", "<required>") is None
