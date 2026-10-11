"""Helpers for the 0.3 log-source tests: a fake machine tree and a sandboxed shell.

`make_root` builds /etc/os-release, /etc/timezone and log files under a temp
directory; `run_sh` runs a generated script with PATH limited to a bin dir that
holds the chosen awk (mawk / gawk / busybox), the standard tools the scripts use,
a fake `date` (fixed clock, so syslog year inference is deterministic) and,
optionally, a fake `journalctl`."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "logsources"

OS_RELEASE = {
    "debian": 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\n',
    "rhel": 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.8"\n',
    "alpine": 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.22.5\n',
}
TOOLS = ("sh", "sed", "tr", "cat", "readlink", "head", "mktemp", "rm", "stat", "grep", "sha256sum", "cut", "base64",
         "tail", "basename", "dirname", "sort", "wc", "echo", "printf", "mkdir", "true", "ls", "su")


def awks() -> list[str]:
    out = [a for a in ("mawk", "gawk") if shutil.which(a)]
    bb = os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox")
    if bb:
        out.append("busybox")
    return out


def make_root(tmp_path: Path, family: str, files: dict[str, str | bytes] | None = None,
              tz: str | None = "Etc/UTC") -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc/os-release").write_text(OS_RELEASE[family])
    if tz:
        (root / "etc/timezone").write_text(tz + "\n")
    for dest, content in (files or {}).items():
        p = root / dest.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        elif content.startswith("@"):
            shutil.copy(FIX / content[1:], p)
        else:
            p.write_text(content)
    return root


FAKE_DATE = textwrap.dedent(f"""\
    #!{sys.executable}
    import os, sys, time
    now = float(os.environ.get("FAKE_NOW", time.time()))
    off = os.environ.get("FAKE_TZOFF", "+0000")
    fmt = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith("+") else "+%a %b %d %H:%M:%S %Y"
    sign = -1 if off[0] == "-" else 1
    t = time.gmtime(now + sign * (int(off[1:3]) * 3600 + int(off[3:5]) * 60))
    out = fmt[1:].replace("%z", off).replace("%s", str(int(now)))
    print(time.strftime(out, t))
    """)


def bindir(tmp_path: Path, awk: str, journalctl: str | None = None, extra: dict[str, str] | None = None) -> Path:
    b = tmp_path / f"bin_{awk}"
    if b.exists():
        return b
    b.mkdir()
    for tool in TOOLS:
        src = shutil.which(tool)
        if src:
            os.symlink(src, b / tool)
    if awk == "busybox":
        os.symlink(os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox"), b / "awk")
    else:
        os.symlink(shutil.which(awk), b / "awk")
    (b / "date").write_text(FAKE_DATE)
    (b / "date").chmod(0o755)
    if journalctl:
        (b / "journalctl").write_text(journalctl)
        (b / "journalctl").chmod(0o755)
    for name, text in (extra or {}).items():
        (b / name).write_text(text)
        (b / name).chmod(0o755)
    return b


def run_sh(script: str, b: Path, *, now: float, tzoff: str = "+0000", env: dict[str, str] | None = None,
           timeout: float = 60) -> subprocess.CompletedProcess:
    e = {"PATH": str(b), "HOME": str(b), "FAKE_NOW": str(now), "FAKE_TZOFF": tzoff, "LC_ALL": "C", **(env or {})}
    return subprocess.run([str(b / "sh"), "-s"], input=script, capture_output=True, text=True, env=e,
                          timeout=timeout)
