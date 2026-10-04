"""Target-side measurement (docs/time_window_design.md §2F): the REAL generated sh script
runs locally against a fake `journalctl` (serving fixture lines, honouring --since/
--until/_COMM/-n/-r/--list-boots) under each available awk (mawk = Debian/Ubuntu default,
gawk = RHEL). Its counts must equal auth_log_parse.classify_auth_message over the same
lines, and its bursts must equal auth_log_patterns._detect_bursts -- one definition of
"a failed login" / "a burst", whichever path produced the numbers."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import textwrap
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.adapters.auth_log_patterns import _detect_bursts
from kratos.timewin.measure import build_script, parse_output

FIX = Path(__file__).parent / "fixtures" / "timewin"
CORPUS = [FIX / "auth_corpus.short_unix.txt", FIX / "auth_edge_cases.short_unix.txt"]
AWKS = [a for a in ("mawk", "gawk") if shutil.which(a)]

FAKE_JOURNALCTL = textwrap.dedent(f"""\
    #!{sys.executable}
    import os, sys
    args = sys.argv[1:]
    lines = []
    for path in os.environ["FAKE_JOURNAL"].split(os.pathsep):
        lines += [l.rstrip("\\n") for l in open(path) if l.strip()]
    lines.sort(key=lambda l: float(l.split(" ", 1)[0]))
    if "--list-boots" in args:
        for i, b in enumerate(os.environ.get("FAKE_BOOTS", "").split(",")):
            if b:
                print(f"{{i - len(os.environ['FAKE_BOOTS'].split(',')) + 1}} bootid{{i}} x")
        sys.exit(0)
    comms = [a.split("=", 1)[1] for a in args if a.startswith("_COMM=")]
    since = until = n = None
    rev = "-r" in args or "--reverse" in args
    for i, a in enumerate(args):
        if a == "--since": since = float(args[i + 1].lstrip("@"))
        if a == "--until": until = float(args[i + 1].lstrip("@"))
        if a == "-n": n = int(args[i + 1])
    def prog(l):
        p = l.split(" ")[2]
        return p.split("[")[0].rstrip(":")
    out = [l for l in lines
           if (not comms or prog(l) in comms)
           and (since is None or float(l.split(" ")[0]) >= since)
           and (until is None or float(l.split(" ")[0]) <= until)]
    if rev: out.reverse()
    if n is not None: out = out[:n] if rev else out[-n:]
    print("\\n".join(out))
    """)


def _bin_dir(tmp_path: Path, awk: str, with_timeout=True, with_mktemp=True) -> Path:
    b = tmp_path / f"bin_{awk}"
    b.mkdir(exist_ok=True)
    fj = b / "journalctl"
    fj.write_text(FAKE_JOURNALCTL)
    fj.chmod(fj.stat().st_mode | stat.S_IEXEC)
    for tool, real in (("awk", shutil.which(awk)), ("sort", shutil.which("sort")), ("cut", shutil.which("cut")),
                       ("head", shutil.which("head")), ("tail", shutil.which("tail")), ("date", shutil.which("date")),
                       ("rm", shutil.which("rm")), ("mkdir", shutil.which("mkdir")), ("cat", shutil.which("cat")),
                       ("grep", shutil.which("grep")),
                       ("sed", shutil.which("sed")), ("readlink", shutil.which("readlink")),
                       ("timeout", shutil.which("timeout") if with_timeout else None),
                       ("mktemp", shutil.which("mktemp") if with_mktemp else None)):
        if real:
            (b / tool).symlink_to(real)
    return b


def _run(tmp_path: Path, awk: str, script: str, journal_files, boots: str = "", **bin_kw) -> str:
    b = _bin_dir(tmp_path, awk, **bin_kw)
    env = {"PATH": str(b), "FAKE_JOURNAL": os.pathsep.join(str(p) for p in journal_files),
           "FAKE_BOOTS": boots, "SSH_CONNECTION": os.environ.get("TEST_SSH_CONNECTION", "")}
    r = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, text=True, timeout=120)
    assert "awk:" not in r.stderr, r.stderr[-2000:]
    return r.stdout


def _python_counts(paths) -> Counter:
    c: Counter = Counter()
    for path in paths:
        for line in path.read_text().splitlines():
            parts = line.split(" ", 3)
            if len(parts) < 4:
                continue
            prog = parts[2]
            prog_name = prog.split("[")[0].rstrip(":")
            msg = parts[3]
            ev = classify_auth_message("t", parts[1], prog_name, msg, line)
            c[(ev.event_type, ev.source_ip or "-", ev.user or "-")] += 1
    return c


def _awk_counts(stdout: str) -> Counter:
    c: Counter = Counter()
    for line in stdout.splitlines():
        p = line.split("\t")
        if p[0] == "CNT":
            c[(p[1], p[2], p[3])] += int(p[4])
    return c


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
@pytest.mark.parametrize("awk", AWKS)
def test_awk_classifier_matches_python_classifier_exactly(tmp_path, awk):
    out = _run(tmp_path, awk, build_script(0, None, journalctl_prefix=""), CORPUS)
    got, want = _awk_counts(out), _python_counts(CORPUS)
    assert sum(want.values()) > 6000
    diff = {k: (got.get(k), want.get(k)) for k in set(got) | set(want) if got.get(k) != want.get(k)}
    assert diff == {}, list(diff.items())[:15]


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
@pytest.mark.parametrize("awk", AWKS)
def test_window_bounds_are_honoured(tmp_path, awk):
    edge = [FIX / "auth_edge_cases.short_unix.txt"]
    out = _run(tmp_path, awk, build_script(1790000004, 1790000009, journalctl_prefix=""), edge)
    m = parse_output(out, 1790000004, 1790000009, 0.0)
    assert m.lines == 6  # 1790000004 .. 1790000009 inclusive (until bound +1s)


def _synthetic(tmp_path: Path, events: list[tuple[float, str, str, str]]) -> Path:
    """events: (epoch, prog, ip, user) -> journal lines of failed logins / sudo failures."""
    p = tmp_path / "synthetic.txt"
    lines = []
    for t, prog, ip, user in events:
        if prog == "sshd":
            lines.append(f"{t:.6f} h sshd[1]: Failed password for {user} from {ip} port 1 ssh2")
        else:
            lines.append(f"{t:.6f} h sudo[1]:   {user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/x")
    p.write_text("\n".join(lines) + "\n")
    return p


def _python_bursts(events):
    evs = []
    for t, prog, ip, user in events:
        et = "ssh_failed_login" if prog == "sshd" else "sudo_auth_failure"
        evs.append({"event_type": et, "timestamp": datetime.fromtimestamp(t, timezone.utc).isoformat(),
                    "source_ip": ip if prog == "sshd" else None, "user": user})
    from datetime import timedelta
    out = []
    for et in ("sudo_pam_auth_failure", "sudo_auth_failure", "ssh_failed_login"):
        out += _detect_bursts(evs, et, timedelta(minutes=5), 3)
    return out


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
@pytest.mark.parametrize("awk", AWKS)
def test_bursts_match_the_correlation_engines_algorithm(tmp_path, awk):
    t0 = 1_790_000_000.0
    events = (
        [(t0 + i * 20, "sshd", "203.0.113.9", "root") for i in range(4)]            # burst A
        + [(t0 + 200 + i * 10, "sshd", "203.0.113.7", f"u{i}") for i in range(3)]   # overlaps A -> merged
        + [(t0 + 2000 + i * 200, "sshd", "198.51.100.1", "x") for i in range(3)]    # too slow: 400s span? no burst
        + [(t0 + 5000 + i, "sshd", "198.51.100.2", "y") for i in range(2)]           # only 2: no burst
        + [(t0 + 9000 + i * 30, "sudo", "-", "alice") for i in range(3)]             # sudo burst
    )
    out = _run(tmp_path, awk, build_script(0, None, journalctl_prefix=""), [_synthetic(tmp_path, events)])
    got = parse_output(out, 0, t0 + 10000, 0.0).bursts
    want = _python_bursts(events)
    norm = lambda bs: sorted((b["event_type"], b["start"][:19], b["end"][:19], b["count"],
                              sorted((d.get("ip") or d.get("user"), d["count"]) for d in b["top_source_ips"]),
                              sorted((d["user"], d["count"]) for d in b["top_users"])) for b in bs)
    assert norm(got) == norm(want)


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
def test_kratos_own_sessions_excluded_but_its_failures_never_hidden(tmp_path, monkeypatch):
    p = tmp_path / "self.txt"
    p.write_text(
        "1790000001.0 h sshd[1]: Accepted publickey for ubuntu from 10.9.9.9 port 1 ssh2: ED25519 x\n"
        "1790000002.0 h sshd[1]: Disconnected from 10.9.9.9 port 1\n"
        "1790000003.0 h sshd[1]: Failed password for ubuntu from 10.9.9.9 port 1 ssh2\n"
        "1790000004.0 h sudo[1]:   ubuntu : TTY=unknown ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/journalctl -n 1\n"
        "1790000005.0 h sudo[1]:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt install x\n"
    )
    monkeypatch.setenv("TEST_SSH_CONNECTION", "10.9.9.9 5555 10.0.0.2 22")
    out = _run(tmp_path, AWKS[0], build_script(0, None, journalctl_prefix="", kratos_user="ubuntu"), [p])
    m = parse_output(out, 0, 1790000010, 0.0)
    assert m.kratos_ip == "10.9.9.9"
    assert m.self_excluded == {"ssh_success_login": 1, "ssh_disconnect": 1, "sudo_command": 1}
    assert m.counts == {"ssh_failed_login": 1, "sudo_command": 1}  # failure kept; apt kept


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
def test_clock_jump_detected_and_reported_in_coverage(tmp_path):
    p = tmp_path / "jump.txt"
    # fake journal sorts by time, so emulate the jump with the raw awk stage instead
    p.write_text("1790001000.0 h sshd[1]: Invalid user a from 203.0.113.1 port 1\n"
                 "1790000400.0 h sshd[1]: Invalid user b from 203.0.113.1 port 1\n")
    from kratos.timewin import measure as M
    awk = shutil.which(AWKS[0])
    r = subprocess.run([awk, "-v", "kip=", "-v", "kuser=", "-v", "selfcmd=x", "-v", f"ffile={tmp_path / 'f'}",
                        "-v", "nsample=5", "-v", "maxfirst=5", M._CLASSIFY_AWK, str(p)], capture_output=True, text=True)
    m = M.parse_output("META\tjournald\tpresent\n" + r.stdout, 1790000000, 1790002000, 0.0)
    assert m.clock_jumps and any("jumped backwards" in x for x in m.coverage()["problems"])


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
def test_runs_without_timeout_and_mktemp_like_stock_alpine(tmp_path):
    edge = [FIX / "auth_edge_cases.short_unix.txt"]
    out = _run(tmp_path, AWKS[0], build_script(0, None, journalctl_prefix=""), edge,
               with_timeout=False, with_mktemp=False)
    m = parse_output(out, 0, 1790000100, 0.0)
    assert m.budget_unavailable and m.lines == 26 and m.counts["ssh_failed_login"] > 0


def test_coverage_reports_retention_and_boot_gaps_and_clock_offset():
    out = "\n".join([
        "META\tjournald\tpresent", "META\tjournal_head\t1790003000", "META\trc\t0",
        "BOOT\t-1\t1790003000\t1790004000", "BOOT\t0\t1790005000\t1790009000",
        "CNT\tssh_failed_login\t203.0.113.1\troot\t5\t1790006000\t1790006100",
        "DONE\t5\t1790006000\t1790006100",
    ])
    m = parse_output(out, 1790000000, 1790010000, clock_offset=-300.0)
    cov = m.coverage()
    # journal starts 1790003000 target clock = 1790003300 Kratos clock; boot gap 1000s
    assert cov["percent"] == pytest.approx(100 * (10000 - 3300 - 1000) / 10000, abs=0.1)
    assert any("retention" in p for p in cov["problems"]) and any("rebooting" in p for p in cov["problems"])
    assert m.by_ip["203.0.113.1"]["first"] == 1790006300  # converted to Kratos clock


def test_journald_absent_is_zero_coverage_not_zero_events():
    m = parse_output("META\tjournald\tabsent\n", 0, 100, 0.0)
    cov = m.coverage()
    assert cov["percent"] == 0.0 and "absent" in cov["problems"][0]


def test_auth_stats_and_patterns_have_the_shape_correlate_findings_reads():
    out = "\n".join([
        "META\tjournald\tpresent", "CNT\tssh_failed_login\t203.0.113.1\troot\t7\t1\t2",
        "CNT\tsudo_session_open\t-\t-\t2\t1\t2",
        "BURST\tssh_failed_login\t1790000000.0\t1790000060.0\t7\t203.0.113.1:7\troot:7", "DONE\t9\t1\t2",
    ])
    m = parse_output(out, 0, 1790001000, 0.0)
    stats, pats = m.as_auth_stats(), m.as_auth_patterns()
    assert stats["events_by_type"] == {"ssh_failed_login": 7, "sudo_session_open": 2}
    assert stats["top_failed_login_ips"] == [{"ip": "203.0.113.1", "count": 7}]
    assert pats["bursts"][0]["top_source_ips"] == [{"ip": "203.0.113.1", "count": 7}]


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
@pytest.mark.parametrize("awk", AWKS)
def test_event_times_keep_full_precision(tmp_path, awk):
    """Live bug: awk's default "%.6g" printed 1790547006.8 as 1.79055e+09, so every
    first/last-seen time came back ~an hour off. Times must survive to the second."""
    p = tmp_path / "t.txt"
    p.write_text("1790547006.812345 h sshd[1]: Invalid user a from 203.0.113.1 port 1\n"
                 "1790547123.500000 h sshd[1]: Invalid user a from 203.0.113.1 port 2\n")
    out = _run(tmp_path, awk, build_script(0, None, journalctl_prefix=""), [p])
    m = parse_output(out, 0, 1790550000, 0.0)
    d = m.by_ip["203.0.113.1"]
    assert d["first"] == pytest.approx(1790547006.812345, abs=1e-3)
    assert d["last"] == pytest.approx(1790547123.5, abs=1e-3)
    assert m.samples[0]["time"] == "2026-09-27T22:12:03+00:00"


_FILE_ORDER_JOURNAL = textwrap.dedent(f"""\
    #!{sys.executable}
    # A journal whose FILE ORDER is not time order (after a backwards clock jump), with a
    # seek that behaves like systemd's: --since returns everything from the first line (in
    # file order) at/after the bound; --until stops at the first line past it.
    import os, sys
    args = sys.argv[1:]
    lines = [l.rstrip("\\n") for l in open(os.environ["FAKE_JOURNAL"]) if l.strip()]
    if "--list-boots" in args: sys.exit(0)
    since = next((float(args[i + 1][1:]) for i, a in enumerate(args) if a == "--since"), None)
    until = next((float(args[i + 1][1:]) for i, a in enumerate(args) if a == "--until"), None)
    n = next((int(args[i + 1]) for i, a in enumerate(args) if a == "-n"), None)
    out = lines
    if since is not None:
        k = next((i for i, l in enumerate(lines) if float(l.split()[0]) >= since), len(lines))
        out = lines[k:]
    if until is not None:
        k = next((i for i, l in enumerate(out) if float(l.split()[0]) > until), len(out))
        out = out[:k]
    if n is not None: out = out[-n:] if "-r" not in args else list(reversed(out))[:n]
    print("\\n".join(out))
    """)


@pytest.mark.skipif(not AWKS, reason="no mawk/gawk available")
def test_time_travelled_journal_counts_exactly_and_rescans(tmp_path):
    """Live E25b: after the target's clock was set back, journalctl's time seek returned
    out-of-window lines (counts 52 and 130 where the truth was 40 and 89) and the first
    journal line was not the earliest. Every event is now filtered by its own time and a
    detected jump forces a full rescan."""
    base = 1_790_000_000
    day = 86400
    file_order = (  # boot at base+2d, then the clock was set back to base, base+1d
        [f"{base + 2 * day + i:.6f} h sshd[1]: Accepted publickey for u from 10.0.0.1 port 1 ssh2: K x" for i in range(3)]
        + [f"{base + 60 * i:.6f} h sshd[1]: Invalid user a{i} from 203.0.113.1 port 1" for i in range(5)]
        + [f"{base + day + 60 * i:.6f} h sshd[1]: Invalid user b{i} from 203.0.113.2 port 1" for i in range(4)]
        + [f"{base + 2 * day + 100 + 60 * i:.6f} h sshd[1]: Invalid user c{i} from 203.0.113.3 port 1" for i in range(7)]
    )
    jf = tmp_path / "journal.txt"
    jf.write_text("\n".join(file_order) + "\n")
    b = _bin_dir(tmp_path, AWKS[0])
    (b / "journalctl").write_text(_FILE_ORDER_JOURNAL)
    (b / "journalctl").chmod(0o755)
    env = {"PATH": str(b), "FAKE_JOURNAL": str(jf), "FAKE_BOOTS": "", "SSH_CONNECTION": ""}
    start, end = base + day, base + 2 * day  # "the middle day": truth = 4
    script = build_script(start, end, journalctl_prefix="", classic_globs=(str(tmp_path / "none*"),),
                          fail2ban_glob=str(tmp_path / "none*"))
    out = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, text=True, timeout=60).stdout
    m = parse_output(out, start, end, 0.0)
    assert m.counts.get("ssh_failed_login") == 4
    assert m.journal_rescanned and m.clock_jumps
    assert m.journal_head == pytest.approx(base)  # the true earliest, not the first line


def test_without_mktemp_the_scratch_folder_is_private_and_removed(tmp_path):
    """The no-mktemp path makes its own folder with mkdir -m 700 (never a
    predictable file name an attacker could pre-create as a symlink)."""
    edge = [FIX / "auth_edge_cases.short_unix.txt"]
    script = build_script(0, None, journalctl_prefix="")
    _run(tmp_path, AWKS[0] if AWKS else "awk", script, edge, with_timeout=False, with_mktemp=False)
    import glob

    assert not [p for p in glob.glob("/tmp/kratos.*") if p.startswith("/tmp/kratos.")
                and os.stat(p).st_uid == os.getuid() and os.path.isdir(p)]
