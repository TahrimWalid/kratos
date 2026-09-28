"""Classic syslog + fail2ban sources in the measurement engine (docs/time_window_design.md
§2E; validated live as E16-E21). The REAL generated script runs against real files --
rotated, gzipped, dateext-named, in RFC3164 / BusyBox / RFC3339 formats -- with the
target's journal absent or present (fake journalctl)."""
from __future__ import annotations

import gzip
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.timewin.measure import build_script, parse_output

AWK = shutil.which("mawk") or shutil.which("gawk")
pytestmark = pytest.mark.skipif(AWK is None, reason="no awk available")
UTC = timezone.utc
TOOLS = ("awk", "sort", "cut", "head", "tail", "date", "rm", "cat", "gzip", "stat", "sed", "readlink", "mktemp", "timeout", "grep")


def _epoch(y, mo, d, h=0, mi=0, s=0) -> float:
    return datetime(y, mo, d, h, mi, s, tzinfo=UTC).timestamp()


def _bin(tmp: Path, journal_lines: list[str] | None) -> Path:
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    for t in TOOLS:
        real = AWK if t == "awk" else shutil.which(t)
        if real and not (b / t).exists():
            (b / t).symlink_to(real)
    if journal_lines is not None:
        data = tmp / "journal.txt"
        data.write_text("\n".join(journal_lines) + "\n")
        fj = b / "journalctl"
        fj.write_text(textwrap.dedent(f"""\
            #!{sys.executable}
            import sys
            args = sys.argv[1:]
            lines = [l for l in open({str(data)!r}).read().splitlines() if l.strip()]
            if "--list-boots" in args: sys.exit(0)
            comms = [a.split("=", 1)[1] for a in args if a.startswith("_COMM=")]
            since = next((float(args[i + 1][1:]) for i, a in enumerate(args) if a == "--since"), None)
            n = next((int(args[i + 1]) for i, a in enumerate(args) if a == "-n"), None)
            out = [l for l in lines if (not comms or l.split()[2].split("[")[0].rstrip(":") in comms)
                   and (since is None or float(l.split()[0]) >= since)]
            if n is not None: out = out[-n:]
            print("\\n".join(out))
            """))
        fj.chmod(fj.stat().st_mode | stat.S_IEXEC)
    return b


def _run(tmp: Path, script: str, journal_lines=None) -> str:
    b = _bin(tmp, journal_lines)
    r = subprocess.run(["/bin/sh", "-c", script], env={"PATH": str(b), "SSH_CONNECTION": ""},
                       capture_output=True, text=True, timeout=120)
    assert "awk:" not in r.stderr, r.stderr[-1500:]
    return r.stdout


def _write(path: Path, lines: list[str], mtime: float, gz: bool = False) -> None:
    data = ("\n".join(lines) + "\n").encode()
    if gz:
        path.write_bytes(gzip.compress(data))
    else:
        path.write_bytes(data)
    os.utime(path, (mtime, mtime))


def _inv(ts: str, n: int, ip: str = "203.0.113.5") -> str:
    return f"{ts} web1 sshd[{100 + n}]: Invalid user x{n} from {ip} port 5{n:03d}"


def test_year_rollover_across_rotated_and_gzipped_files(tmp_path):
    logs = tmp_path / "log"
    logs.mkdir()
    _write(logs / "auth.log.2.gz", [_inv("Dec 30 22:10:00", 1), _inv("Dec 31 23:58:00", 2)],
           _epoch(2025, 12, 31, 23, 58, 30), gz=True)
    _write(logs / "auth.log.1", [_inv("Dec 31 23:59:10", 3), _inv("Jan  1 00:00:20", 4), _inv("Jan  2 09:00:00", 5)],
           _epoch(2026, 1, 2, 9, 0, 30))
    _write(logs / "auth.log", [_inv("Jan  3 10:00:00", 6)], _epoch(2026, 1, 3, 10, 0, 30))
    start, end = _epoch(2025, 12, 30), _epoch(2026, 1, 4)
    script = build_script(start, end, journalctl_prefix="", classic_globs=(f"{logs}/auth.log*",),
                          fail2ban_glob=f"{logs}/nofail2ban*")
    m = parse_output(_run(tmp_path, script), start, end, 0.0)
    assert m.journald == "absent" and m.classic_status == "used"
    assert m.counts == {"ssh_failed_login": 6}
    first = m.by_ip["203.0.113.5"]["first"]
    assert datetime.fromtimestamp(first, UTC).year == 2025  # a naive current-year parse would say 2026
    cov = m.coverage()
    assert cov["percent"] < 100 and "classic syslog files" in cov["sources"]


def test_classic_lines_only_fill_the_time_before_the_journal_starts(tmp_path):
    logs = tmp_path / "log"
    logs.mkdir()
    t0 = _epoch(2026, 9, 1, 10, 0)
    head = t0 + 3600  # journal begins one hour in
    classic = [_inv(datetime.fromtimestamp(t0 + i * 600, UTC).strftime("%b %e %H:%M:%S").replace("  ", "  "), i)
               for i in range(12)]  # 2 hours, every 10 minutes: 6 before head, 6 after
    _write(logs / "auth.log", classic, t0 + 7200)
    journal = [f"{t0 + 3600 + i * 600:.6f} web1 sshd[{200 + i}]: Invalid user x{i + 6} from 203.0.113.5 port 5{i:03d}"
               for i in range(6)]
    start, end = t0, t0 + 7200
    script = build_script(start, end, journalctl_prefix="", classic_globs=(f"{logs}/auth.log*",),
                          fail2ban_glob=f"{logs}/none*")
    m = parse_output(_run(tmp_path, script, journal), start, end, 0.0)
    assert m.journal_head == pytest.approx(head)
    assert m.counts["ssh_failed_login"] == 12  # 6 journald + 6 classic -- NOT 18 (no double count)
    assert m.coverage()["percent"] == pytest.approx(100.0, abs=0.5)


def test_busybox_rfc3339_and_dateext_formats(tmp_path):
    logs = tmp_path / "log"
    logs.mkdir()
    _write(logs / "messages", ["Sep 27 22:12:54 alp auth.info sshd-session[863]: Invalid user ttprobe from 10.136.28.52 port 34150"],
           _epoch(2026, 9, 27, 22, 13))
    _write(logs / "secure-20260927", ["2026-09-27T18:12:53.123456-04:00 rhel sshd-session[519]: Invalid user ttprobe from 10.136.28.52 port 1"],
           _epoch(2026, 9, 27, 22, 14))
    start, end = _epoch(2026, 9, 27, 22), _epoch(2026, 9, 27, 23)
    script = build_script(start, end, journalctl_prefix="", classic_globs=(f"{logs}/secure*", f"{logs}/messages*"),
                          fail2ban_glob=f"{logs}/none*")
    m = parse_output(_run(tmp_path, script), start, end, 0.0)
    assert m.counts == {"ssh_failed_login": 2}
    times = sorted(datetime.fromtimestamp(d, UTC).strftime("%H:%M") for d in (m.by_ip["10.136.28.52"]["first"], m.by_ip["10.136.28.52"]["last"]))
    assert times[0] == "22:12"  # the RFC3339 line's explicit -04:00 offset was honoured


def test_fail2ban_bans_are_counted(tmp_path):
    logs = tmp_path / "log"
    logs.mkdir()
    _write(logs / "fail2ban.log", [
        "2026-09-27 22:12:55,123 fail2ban.actions        [123]: NOTICE  [sshd] Ban 10.136.28.52",
        "2026-09-27 22:22:55,123 fail2ban.actions        [123]: NOTICE  [sshd] Unban 10.136.28.52",
        "2026-09-27 22:23:00,000 fail2ban.filter         [123]: INFO    [sshd] Found 10.136.28.52",
    ], _epoch(2026, 9, 27, 22, 30))
    start, end = _epoch(2026, 9, 27, 22), _epoch(2026, 9, 27, 23)
    script = build_script(start, end, journalctl_prefix="", classic_globs=(f"{logs}/nothing*",),
                          fail2ban_glob=f"{logs}/fail2ban.log*")
    m = parse_output(_run(tmp_path, script), start, end, 0.0)
    assert [(e["action"], e["ip"], e["jail"]) for e in m.fail2ban] == [("ban", "10.136.28.52", "sshd"),
                                                                       ("unban", "10.136.28.52", "sshd")]


def test_calibration_detects_a_log_daemon_writing_a_different_timezone():
    """E16: rsyslog kept writing in an OLD zone. The newest classic lines are matched
    to identical journal lines; a 4-hour disagreement with the target's zone is used and
    disclosed instead of silently shifting every classic event by 4 hours."""
    e = _epoch(2026, 9, 27, 22, 12, 52)
    local_edt = e - 4 * 3600
    out = "\n".join([
        "META\tjournald\tpresent", f"META\tjournal_head\t{e - 60}", "META\ttz_name\tEtc/UTC",
        f"JT\t{e}\tInvalid user ttprobe from 10.136.28.52 port 34150",
        f"CFILE\t/var/log/auth.log\t{e}\t0\t2026",
        f"CT\t/var/log/auth.log\t{int(local_edt)}\tInvalid user ttprobe from 10.136.28.52 port 34150",
        f"CM\tL\t{int(local_edt - 3600) // 60 * 60}\t0\tssh_failed_login\t10.136.28.52\t3",
        f"CDONE\t/var/log/auth.log\t4\t{int(local_edt - 3600)}\t{int(local_edt)}",
        "DONE\t1\t1\t1",
    ])
    m = parse_output(out, e - 7200, e + 60, 0.0)
    assert m.classic_offset_note and "UTC-4h" in m.classic_offset_note
    # the classic burst an hour before the journal began is placed at the right UTC hour
    t = m.by_ip["10.136.28.52"]["first"]
    assert datetime.fromtimestamp(t, UTC).strftime("%H:%M") == "21:12"
    assert m.counts["ssh_failed_login"] == 3


def test_local_time_conversion_is_dst_correct():
    """A classic line written at 01:30 local on the US fall-back day is converted with the
    zone's rules (earlier instant), not a fixed offset."""
    # 2026-11-01 01:30 America/New_York (first occurrence, EDT) = 05:30 UTC
    pseudo = int(datetime(2026, 11, 1, 1, 30).replace(tzinfo=UTC).timestamp())  # wall clock as if UTC
    out = "\n".join(["META\tjournald\tabsent", "META\ttz_name\tAmerica/New_York",
                     f"CM\tL\t{pseudo}\t0\tssh_failed_login\t198.51.100.9\t1",
                     f"CDONE\tmessages\t1\t{pseudo}\t{pseudo}"])
    start, end = _epoch(2026, 11, 1), _epoch(2026, 11, 2)
    m = parse_output(out, start, end, 0.0)
    assert datetime.fromtimestamp(m.by_ip["198.51.100.9"]["first"], UTC).strftime("%H:%M") == "05:30"
