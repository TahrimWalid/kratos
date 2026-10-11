"""The 0.3 file extractor (kratos.logsources.logread): one awk program, run under
mawk, gawk and BusyBox awk, must give the same records for every format fixture
(real lines from the lab hosts), honour the window exactly, cap and flag
truncation, and say which files it read, couldn't read or skipped."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.logsources import catalog, logread
from tests._logsources_util import FIX, awks, bindir, make_root, run_sh

AWKS = awks()
pytestmark = pytest.mark.skipif(not AWKS, reason="no awk available")
NOW = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc).timestamp()
WIDE = (datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp(), NOW)


def _read(tmp_path: Path, awk: str, source: str, family: str, files: dict, since=WIDE[0], until=WIDE[1],
          tz: str | None = "Etc/UTC", tzoff: str = "+0000", **kw) -> logread.LogRead:
    root = make_root(tmp_path, family, files, tz=tz)
    script = logread.build_script(source, since, until, journal_prefix="", root=str(root), **kw)
    r = run_sh(script, bindir(tmp_path, awk), now=NOW, tzoff=tzoff)
    assert r.returncode == 0, r.stderr
    assert "syntax error" not in r.stderr and "awk:" not in r.stderr, r.stderr
    return logread.parse_output(source, r.stdout, since, until, max_lines=kw.get("max_lines", logread.DEFAULT_MAX_LINES))


def _summary(lr: logread.LogRead) -> list[tuple]:
    return [(round(r.ts, 3), r.path.rsplit("/", 1)[-1] if r.path else None, r.text) for r in lr.records]


CASES = [
    # (source, family, {dest: fixture}, expected record count, (one line's text start, its UTC time))
    ("web", "debian", {"/var/log/nginx/access.log": "@nginx_access.log", "/var/log/nginx/error.log": "@nginx_error.log"},
     6, ('10.136.28.52 - - [11/Oct/2026:17:12:05 +0000] "GET /admin', "2026-10-11T17:12:05")),
    ("firewall", "alpine", {"/var/log/messages": "@ufw.log"}, 6, ("Oct 11 17:12:10 kratos-tt-skew kernel:", "2026-10-11T17:12:10")),
    ("packages", "debian", {"/var/log/dpkg.log": "@dpkg.log", "/var/log/apt/history.log": "@apt_history.log"},
     None, ("2026-10-11 17:17:54 install sl:amd64", "2026-10-11T17:17:54")),
    ("packages", "rhel", {"/var/log/dnf.rpm.log": "@dnf.rpm.log", "/var/log/dnf.log": "@dnf.log"},
     None, ("2026-10-11T17:19:25+0000 SUBDEBUG Installed: tree", "2026-10-11T17:19:25")),
    ("cron", "rhel", {"/var/log/cron": "@rhel_cron.log"}, 12, ("Oct 11 17:01:01 kratos-tt-rhel CROND[13876]", "2026-10-11T17:01:01")),
    ("cron", "alpine", {"/var/log/messages": "@alpine_messages.log"}, None,
     ("Oct 11 17:15:00 kratos-tt-alpine cron.info crond[320]", "2026-10-11T17:15:00")),
    ("auditd", "debian", {"/var/log/audit/audit.log": "@audit.log.sample"}, 40,
     ("type=DAEMON_START msg=audit(1791738707.063:9127)", "2026-10-11T17:11:47")),
    ("sudo", "debian", {"/var/log/sudo.log": "@sudo.log"}, 2,
     ("Oct 11 17:17:24 : ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/ls\x1f/root", "2026-10-11T17:17:24")),
]


def _expected_count(source: str, family: str, files: dict) -> int:
    n = 0
    for spec in catalog.SOURCES[source].files.get(family, ()):
        fx = files.get(spec.path)
        if not fx:
            continue
        lines = (FIX / fx[1:]).read_text().splitlines()
        if spec.fmt == "apt_history":
            n += sum(1 for ln in lines if ln.startswith("Start-Date:"))
        else:
            n += sum(1 for ln in lines if (not spec.keep or re.search(spec.keep, ln)))
    return n


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("source, family, files, count, probe", CASES, ids=[f"{c[0]}-{c[1]}" for c in CASES])
def test_every_format_fixture_reads_the_same_under_each_awk(tmp_path, awk, source, family, files, count, probe):
    lr = _read(tmp_path, awk, source, family, files)
    expected = count if count is not None else _expected_count(source, family, files)
    assert len(lr.records) == expected
    assert lr.family == family
    hit = [r for r in lr.records if r.text.startswith(probe[0])]
    assert hit, f"no record starts with {probe[0]!r}"
    assert datetime.fromtimestamp(hit[0].ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") == probe[1]
    assert [r.ts for r in lr.records] == sorted((r.ts for r in lr.records), reverse=True)  # newest first
    assert not lr.truncated


@pytest.mark.parametrize("source, family, files, count, probe", CASES, ids=[f"{c[0]}-{c[1]}" for c in CASES])
def test_all_awks_agree(tmp_path, source, family, files, count, probe):
    if len(AWKS) < 2:
        pytest.skip("needs two awks")
    results = []
    for awk in AWKS:
        sub = tmp_path / awk
        sub.mkdir()
        results.append(_summary(_read(sub, awk, source, family, files)))
    assert all(r == results[0] for r in results[1:])


@pytest.mark.parametrize("awk", AWKS)
def test_window_is_inclusive_to_the_second_and_exact_for_zoned_and_zoneless_times(tmp_path, awk):
    # access.log has exact times (+0000); ufw.log (syslog) has none -- both filter exactly.
    t = datetime(2026, 10, 11, 17, 12, 6, tzinfo=timezone.utc).timestamp()
    lr = _read(tmp_path, awk, "web", "debian", {"/var/log/nginx/access.log": "@nginx_access.log"}, since=t, until=t)
    assert [r.text.split('"')[1] for r in lr.records] == ["GET /x.php HTTP/1.1"]
    t2 = datetime(2026, 10, 11, 17, 12, 10, tzinfo=timezone.utc).timestamp()
    lr2 = _read(tmp_path / "b", awk, "firewall", "alpine", {"/var/log/messages": "@ufw.log"}, since=t2, until=t2 + 1)
    assert {datetime.fromtimestamp(r.ts, timezone.utc).second for r in lr2.records} == {10, 11}


@pytest.mark.parametrize("awk", AWKS)
def test_zoneless_lines_are_read_in_the_machines_zone(tmp_path, awk):
    # The same wall-clock line on a machine in Europe/Helsinki (UTC+3 in October) is 3 hours earlier in UTC.
    lr = _read(tmp_path, awk, "cron", "rhel", {"/var/log/cron": "@rhel_cron.log"}, tz="Europe/Helsinki", tzoff="+0300")
    newest = lr.records[0]
    assert datetime.fromtimestamp(newest.ts, timezone.utc).strftime("%H:%M") == "14:01"
    assert not newest.zone_assumed


@pytest.mark.parametrize("awk", AWKS)
def test_unknown_zone_name_falls_back_to_the_reported_offset_then_utc(tmp_path, awk):
    lr = _read(tmp_path, awk, "cron", "rhel", {"/var/log/cron": "@rhel_cron.log"}, tz=None, tzoff="+0200")
    assert datetime.fromtimestamp(lr.records[0].ts, timezone.utc).strftime("%H:%M") == "15:01"


def test_syslog_year_rollover_december_line_read_in_january(tmp_path):
    jan = datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc).timestamp()
    root = make_root(tmp_path, "rhel", {"/var/log/cron": "Dec 31 23:59:01 h CROND[1]: (root) CMD (x)\n"
                                                         "Jan  1 00:01:01 h CROND[2]: (root) CMD (y)\n"})
    since = datetime(2026, 12, 31, tzinfo=timezone.utc).timestamp()
    script = logread.build_script("cron", since, jan, journal_prefix="", root=str(root))
    r = run_sh(script, bindir(tmp_path, AWKS[0]), now=jan)
    lr = logread.parse_output("cron", r.stdout, since, jan)
    years = sorted(datetime.fromtimestamp(x.ts, timezone.utc).strftime("%Y-%m-%d") for x in lr.records)
    assert years == ["2026-12-31", "2027-01-01"]


@pytest.mark.parametrize("awk", AWKS)
def test_line_cap_keeps_the_newest_and_flags_truncation(tmp_path, awk):
    lines = "".join(f"2026-10-11 10:{i // 60:02d}:{i % 60:02d} install pkg{i}:amd64 <none> 1.0\n" for i in range(300))
    lr = _read(tmp_path, awk, "packages", "debian", {"/var/log/dpkg.log": lines}, max_lines=50)
    assert len(lr.records) == 50
    assert lr.truncated
    assert lr.records[0].text.split()[3] == "pkg299:amd64"   # newest kept
    assert lr.files[0].matched == 300 and lr.files[0].emitted == 50


@pytest.mark.parametrize("awk", AWKS)
def test_byte_cap_flags_truncation(tmp_path, awk):
    lines = "".join(f"2026-10-11 10:00:{i % 60:02d} install p{'x' * 200}{i}:amd64 <none> 1.0\n" for i in range(100))
    lr = _read(tmp_path, awk, "packages", "debian", {"/var/log/dpkg.log": lines}, max_bytes=4096)
    assert 0 < len(lr.records) < 100
    assert lr.truncated


@pytest.mark.parametrize("awk", AWKS)
def test_long_lines_are_cut_and_tabs_kept_out_of_the_format(tmp_path, awk):
    line = "Oct 11 17:00:00 h CROND[1]: (root) CMD (" + "a\tb" * 2000 + ")\n"
    lr = _read(tmp_path, awk, "cron", "rhel", {"/var/log/cron": line})
    assert len(lr.records) == 1
    assert len(lr.records[0].text) <= logread.LINE_MAX_BYTES and "\t" not in lr.records[0].text
    assert lr.files[0].cut_lines == 1


@pytest.mark.parametrize("awk", AWKS)
def test_reads_the_first_rotation_and_lists_the_rest_as_not_read(tmp_path, awk):
    files = {"/var/log/cron": "Oct 11 17:00:00 h CROND[1]: (root) CMD (now)\n",
             "/var/log/cron-20261004": "Oct  3 12:00:00 h CROND[1]: (root) CMD (old)\n",
             "/var/log/cron-20261011": "Oct 10 12:00:00 h CROND[1]: (root) CMD (prev)\n",
             "/var/log/cron-20260927.gz": b"\x1f\x8b"}
    lr = _read(tmp_path, awk, "cron", "rhel", files)
    assert [r.text.rsplit("(", 1)[1] for r in lr.records] == ["now)", "prev)"]
    assert [f.path.rsplit("/", 1)[1] for f in lr.files if f.status == "read"] == ["cron", "cron-20261011"]
    assert [p.rsplit("/", 1)[1] for p in lr.skipped] == ["cron-20260927.gz", "cron-20261004"]


@pytest.mark.parametrize("awk", AWKS)
def test_busybox_rotation_dot_zero_is_preferred(tmp_path, awk):
    files = {"/var/log/messages": "Oct 11 17:00:00 h cron.info crond[1]: USER root pid 2 cmd now\n",
             "/var/log/messages.0": "Oct 10 17:00:00 h cron.info crond[1]: USER root pid 2 cmd prev\n"}
    lr = _read(tmp_path, awk, "cron", "alpine", files)
    assert len(lr.records) == 2
    assert lr.files[1].path.endswith("messages.0")


@pytest.mark.parametrize("awk", AWKS)
def test_missing_unreadable_and_link_files_are_reported_not_read(tmp_path, awk):
    root = make_root(tmp_path, "debian", {"/var/log/nginx/access.log": "@nginx_access.log"})
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$secret:19000:0:99999:7:::\n")
    (root / "var/log/nginx/error.log").symlink_to(shadow)
    (root / "var/log/apache2").mkdir(parents=True)
    import os

    os.link(shadow, root / "var/log/apache2/access.log")
    script = logread.build_script("web", *WIDE, journal_prefix="", root=str(root))
    r = run_sh(script, bindir(tmp_path, awk), now=NOW)
    lr = logread.parse_output("web", r.stdout, *WIDE)
    status = {f.path.rsplit("/", 2)[-2] + "/" + f.path.rsplit("/", 1)[1]: f.status for f in lr.files}
    assert status == {"nginx/access.log": "read", "nginx/error.log": "symlink", "apache2/access.log": "hardlink",
                      "apache2/error.log": "missing"}
    assert "$6$secret" not in r.stdout   # the planted shadow content never crossed


@pytest.mark.parametrize("awk", AWKS)
def test_no_journal_fallback_file_is_read_only_without_journalctl(tmp_path, awk):
    lr = _read(tmp_path, awk, "firewall", "debian", {"/var/log/ufw.log": "@ufw.log"})
    assert len(lr.records) == 6           # no journalctl in the sandbox -> ufw.log read
    assert lr.journal_errors == {"kernel": "no journalctl on this machine"}


def test_journal_part_with_a_fake_journalctl_and_dedupe_against_the_file(tmp_path):
    import json

    entries = [json.loads(ln) for ln in (FIX / "journal_cron.jsonl").read_text().splitlines()]
    fake = (f"#!{__import__('sys').executable}\nimport json,sys\n"
            f"E={json.dumps(entries)!r}\n"
            "args=sys.argv[1:]\n"
            "assert '--reverse' in args and any(a.startswith('--output-fields=') for a in args)\n"
            "for e in reversed(json.loads(E)): print(json.dumps(e))\n")
    root = make_root(tmp_path, "rhel", {"/var/log/cron": "\n".join(
        f"Oct 11 {datetime.fromtimestamp(int(e['__REALTIME_TIMESTAMP']) / 1e6, timezone.utc):%H:%M:%S} "
        f"kratos-target CRON[{e['_PID']}]: {e['MESSAGE']}" for e in entries) + "\n"})
    since, until = WIDE
    script = logread.build_script("cron", since, until, journal_prefix="", root=str(root))
    r = run_sh(script, bindir(tmp_path, AWKS[0], journalctl=fake), now=NOW)
    assert r.returncode == 0, r.stderr
    lr = logread.parse_output("cron", r.stdout, since, until)
    assert lr.has_journal
    assert lr.journal_counts == {"cron": len(entries)}
    assert all(rec.kind == "journal" for rec in lr.records)   # the file copies were dropped as duplicates


def test_gap_text_for_a_family_with_nothing_to_read(tmp_path):
    lr = _read(tmp_path, AWKS[0], "packages", "alpine", {})
    assert lr.records == [] and lr.gaps == ["apk keeps no install history log on Alpine"]


def test_script_is_built_only_from_constants_and_checked_values():
    with pytest.raises(ValueError):
        logread.build_script("cron", None, None, journal_prefix="sudo -n; rm -rf /")
    with pytest.raises(ValueError):
        logread.build_script("cron", None, None, root="/tmp/x'; reboot #")
    with pytest.raises(KeyError):
        logread.build_script("/etc/shadow", None, None)


def test_previous_rotation_matches_the_shell_choice():
    assert logread.previous_rotation("messages", ["messages", "messages.0", "messages.1"]) == "messages.0"
    assert logread.previous_rotation("auth.log", ["auth.log.1", "auth.log.2.gz"]) == "auth.log.1"
    assert logread.previous_rotation("cron", ["cron-20261004", "cron-20261011", "cron-20260927.gz"]) == "cron-20261011"
    assert logread.previous_rotation("cron", ["cron.gz"]) is None
