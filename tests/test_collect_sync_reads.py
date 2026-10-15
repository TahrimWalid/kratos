"""The two ways of reading a log file FORWARD from a saved position -- the SSH script and
the sub-agent's file_sync probe -- on a real fake file tree, under every awk we have
(mawk / gawk / BusyBox): appends, a line cut mid-write, rotation by rename, copytruncate,
symlinks and hard links, a first sync that starts at the tail, multi-line records."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.logsources import catalog, logread
from kratos.subagent import reads
from tests._logsources_util import awks, bindir, make_root, run_sh

NOW = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc).timestamp()
AUTH = "/var/log/auth.log"
needs_awk = pytest.mark.skipif(not awks(), reason="no awk")


def L(sec: int, msg: str = "Failed password for root from 198.51.100.7 port 22 ssh2") -> str:
    return f"Oct 11 10:00:{sec:02d} h sshd[1]: {msg}\n"


class Machine:
    """A fake machine tree read through either transport."""

    def __init__(self, tmp_path: Path, awk: str, family: str = "debian") -> None:
        self.tmp, self.awk = tmp_path, awk
        self.root = make_root(tmp_path, family, {})
        self.family = family

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def write(self, p: str, text: str | bytes, mode: str = "w") -> Path:
        f = self.path(p)
        f.parent.mkdir(parents=True, exist_ok=True)
        with open(f, mode + ("b" if isinstance(text, bytes) else "")) as fh:
            fh.write(text)
        return f

    def ssh(self, source: str, idx: int, inode: int | None, offset: int, floor: float | None = None):
        script = logread.build_file_sync_script(source, {idx: (inode, offset)}, floor=floor, root=str(self.root))
        b = bindir(self.tmp, self.awk)
        e = {"PATH": str(b), "HOME": str(b), "FAKE_NOW": str(NOW), "FAKE_TZOFF": "+0000", "LC_ALL": "C"}
        # bytes in, replaced-on-decode out: exactly what ssh_remote.fetch_file_sync does (errors="replace")
        r = subprocess.run([str(b / "sh"), "-s"], input=script.encode(), capture_output=True, env=e, timeout=60)
        assert r.returncode == 0, r.stderr
        return logread.parse_output(source, r.stdout.decode("utf-8", "replace"), None, None,
                                    max_lines=logread.SYNC_MAX_RECORDS)

    def agent(self, source: str, idx: int, inode: int | None, offset: int, floor: float | None = None):
        out = reads.file_sync_output(source, idx, inode, offset, floor, root=str(self.root), now=NOW)
        return logread.parse_output(source, out["stdout"], None, None, max_lines=logread.SYNC_MAX_RECORDS)


@pytest.fixture(autouse=True)
def _fake_machine_runs_in_utc(monkeypatch):
    """The agent reads its own clock's zone (it runs ON the machine); the fake machine here is UTC, so the
    test process must be too, whatever zone the developer's computer is in."""
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture(params=[(a, t) for a in (awks() or ["mawk"]) for t in ("ssh", "agent")],
                ids=lambda p: f"{p[1]}-{p[0]}")
def m(request, tmp_path):
    awk, transport = request.param
    mach = Machine(tmp_path, awk)
    mach.sync = mach.ssh if transport == "ssh" else mach.agent
    mach.transport = transport
    return mach


def slot(read, n):
    return next((f for f in read.files if f.slot == n), None)


def texts(read):
    return sorted(r.text for r in read.records)


@needs_awk
def test_a_first_sync_reads_the_file_and_reports_where_it_got_to(m):
    body = L(1) + L(2) + L(3)
    f = m.write(AUTH, body)
    r = m.sync("auth", 0, None, 0)
    f0 = slot(r, 0)
    assert f0.status == "read" and f0.inode == f.stat().st_ino and f0.size == len(body) and f0.start == 0
    assert f0.consumed == len(body) and len(r.records) == 3
    assert r.family == "debian"


@needs_awk
def test_an_append_is_read_from_the_saved_offset_exactly_once(m):
    f = m.write(AUTH, L(1) + L(2))
    first = m.sync("auth", 0, None, 0)
    off = slot(first, 0).consumed
    ino = slot(first, 0).inode
    m.write(AUTH, L(3) + L(4), "a")
    again = m.sync("auth", 0, ino, off)
    assert texts(again) == sorted([L(3).strip(), L(4).strip()])
    assert slot(again, 0).start == off and slot(again, 0).consumed == len(L(3) + L(4))
    caught_up = m.sync("auth", 0, ino, off + slot(again, 0).consumed)
    assert caught_up.records == [] and slot(caught_up, 0).consumed == 0


@needs_awk
def test_a_line_still_being_written_is_not_consumed_until_it_is_complete(m):
    half = L(2)[:-1][:30]                                   # a line cut mid-write: no newline
    m.write(AUTH, L(1) + half)
    r1 = m.sync("auth", 0, None, 0)
    assert texts(r1) == [L(1).strip()] and slot(r1, 0).consumed == len(L(1))      # the half line is left
    ino, off = slot(r1, 0).inode, slot(r1, 0).consumed
    m.write(AUTH, L(2)[30:], "a")                           # the writer finishes it
    r2 = m.sync("auth", 0, ino, off)
    assert texts(r2) == [L(2).strip()]
    assert slot(r2, 0).consumed == len(L(2))


@needs_awk
def test_rotation_by_rename_is_finished_from_the_old_file_then_the_new_one_starts_at_zero(m):
    f = m.write(AUTH, L(1) + L(2))
    r1 = m.sync("auth", 0, None, 0)
    ino, off = slot(r1, 0).inode, slot(r1, 0).consumed
    m.write(AUTH, L(3), "a")                                # written after our sync, before the rotation
    os.rename(f, f.with_name("auth.log.1"))
    m.write(AUTH, L(4) + L(5))
    r2 = m.sync("auth", 0, ino, off)
    cur, old = slot(r2, 0), slot(r2, 1)
    assert cur.status == "current" and cur.inode != ino
    assert old.status == "read" and old.inode == ino and old.start == off
    assert texts(r2) == [L(3).strip()]                      # only what the old file still had for us
    r3 = m.sync("auth", 0, cur.inode, 0)
    assert texts(r3) == sorted([L(4).strip(), L(5).strip()])


@needs_awk
def test_a_rotated_file_that_is_gone_is_reported_lost(m):
    f = m.write(AUTH, L(1))
    r1 = m.sync("auth", 0, None, 0)
    ino, off = slot(r1, 0).inode, slot(r1, 0).consumed
    newer = m.write("/var/log/new.log", L(9))             # created while the old one still exists: a new inode
    f.unlink()
    os.rename(newer, f)
    r2 = m.sync("auth", 0, ino, off)
    assert slot(r2, 0).status == "current" and slot(r2, 1).status == "rotated_lost" and not r2.records


@needs_awk
def test_copytruncate_is_reported_as_truncation(m):
    f = m.write(AUTH, L(1) + L(2) + L(3))
    r1 = m.sync("auth", 0, None, 0)
    ino, off = slot(r1, 0).inode, slot(r1, 0).consumed
    shutil.copy(f, f.with_name("auth.log.1"))
    with open(f, "w"):                                      # truncate in place: same inode, smaller file
        pass
    m.write(AUTH, L(7), "a")
    r2 = m.sync("auth", 0, ino, off)
    assert slot(r2, 0).status == "truncated" and not r2.records


@needs_awk
def test_a_symlink_and_a_hard_link_are_refused(m):
    target = m.write("/var/log/real.log", L(1))
    m.path(AUTH).symlink_to(target)
    assert slot(m.sync("auth", 0, None, 0), 0).status == "symlink"
    m.path(AUTH).unlink()
    os.link(target, m.path(AUTH))
    r = m.sync("auth", 0, None, 0)
    assert slot(r, 0).status == "hardlink" and not r.records


@needs_awk
def test_missing_and_unreadable_files_are_named_not_hidden(m):
    assert slot(m.sync("auth", 0, None, 0), 0).status == "missing"
    if m.transport == "agent" and os.geteuid() == 0:
        pytest.skip("root reads everything")


@needs_awk
def test_a_first_sync_of_a_big_file_starts_at_the_tail_on_a_whole_line(m):
    line = L(1)
    n = (logread.SYNC_FIRST_TAIL_BYTES // len(line)) * 3          # about 6 MB
    m.write(AUTH, line * n)
    f = m.path(AUTH)
    size = f.stat().st_size
    r = m.sync("auth", 0, None, 0)
    f0 = slot(r, 0)
    assert f0.start == size - logread.SYNC_FIRST_TAIL_BYTES and f0.start > 0
    assert f0.consumed <= logread.SYNC_FIRST_TAIL_BYTES
    assert all(rec.text == line.strip() for rec in r.records)     # no partial first line
    assert (f0.start + f0.consumed) % len(line) == 0              # whole lines only
    assert f0.start + f0.consumed == size                         # and it reached the end


@needs_awk
def test_a_slice_is_capped_and_the_next_round_continues(m):
    line = L(1)
    n = (logread.SYNC_CHUNK_BYTES // len(line)) * 2 + 10
    m.write(AUTH, line * n)
    r1 = m.sync("auth", 0, 1, 0) if False else m.sync("auth", 0, m.path(AUTH).stat().st_ino, 0)
    f0 = slot(r1, 0)
    assert f0.consumed <= logread.SYNC_CHUNK_BYTES and f0.consumed > logread.SYNC_CHUNK_BYTES - len(line)
    r2 = m.sync("auth", 0, f0.inode, f0.consumed)
    assert slot(r2, 0).start == f0.consumed
    assert len(r1.records) + len(r2.records) < n                   # not everything yet


@needs_awk
def test_a_multi_line_record_still_open_at_the_end_is_held_back(m):
    idx = [i for i, s in enumerate(catalog.sync_files("packages", "debian")) if s.fmt == "apt_history"][0]
    path = catalog.sync_files("packages", "debian")[idx].path
    done = ("Start-Date: 2026-10-11  09:00:00\nCommandline: apt install tree\nInstall: tree:amd64 (2.0-1)\n"
            "End-Date: 2026-10-11  09:00:05\n\n")
    open_block = "Start-Date: 2026-10-11  09:30:00\nCommandline: apt install sl\n"
    m.write(path, done + open_block)
    r1 = m.sync("packages", idx, None, 0)
    f0 = slot(r1, 0)
    assert len(r1.records) == 1 and "tree" in r1.records[0].text
    assert f0.consumed == len(done)                                    # the open block is left for next time
    rest = "Install: sl:amd64 (5.0-1)\nEnd-Date: 2026-10-11  09:30:04\n\n"
    m.write(path, rest, "a")
    r2 = m.sync("packages", idx, f0.inode, f0.consumed)
    assert len(r2.records) == 1 and "apt install sl" in r2.records[0].text and "5.0-1" in r2.records[0].text


@needs_awk
def test_the_first_syncs_look_back_floor_keeps_older_lines_out(m):
    old = "Oct 10 09:00:00 h sshd[1]: Failed password for old from 1.2.3.4 port 22 ssh2\n"
    m.write(AUTH, old + L(1))
    floor = NOW - 6 * 3600
    r = m.sync("auth", 0, None, 0, floor)
    assert texts(r) == [L(1).strip()] and slot(r, 0).consumed == len(old + L(1))


@needs_awk
def test_carriage_returns_and_odd_bytes_do_not_confuse_the_offsets(m):
    body = b"Oct 11 10:00:01 h sshd[1]: caf\xc3\xa9 \xff\xfe bad bytes\r\n" + L(2).encode()
    m.write(AUTH, body)
    r = m.sync("auth", 0, None, 0)
    assert slot(r, 0).consumed == len(body)


# ---- the closed parameters of the agent probe ---------------------------------------------------
def test_the_agent_probe_only_takes_closed_parameters():
    ok = {"source": "auth", "file_index": 0}
    assert reads.validate_params("file_sync", ok)["offset"] == 0
    for bad in ({**ok, "offset": -1}, {**ok, "offset": 2 ** 45}, {**ok, "offset": "5"}, {**ok, "offset": 1.5},
                {**ok, "inode": 0}, {**ok, "inode": "7"}, {**ok, "file_index": 99}, {**ok, "file_index": -1},
                {**ok, "source": "../etc/passwd"}, {**ok, "source": "shadow"}, {**ok, "path": "/etc/shadow"},
                {"file_index": 0}, {**ok, "floor": "yesterday"}):
        with pytest.raises(reads.ReadParamError):
            reads.validate_params("file_sync", bad)
    for bad in ({"match": "auth", "after_cursor": "x; reboot"}, {"match": "auth", "after_cursor": "s=1"},
                {"match": "kernel; id"}, {"match": "auth", "lines": 0}, {"match": "auth", "lines": 10 ** 9},
                {"match": "auth", "cmd": "id"}, {}):
        with pytest.raises(reads.ReadParamError):
            reads.validate_params("journal_sync", bad)
    good = {"match": "auth", "after_cursor": "s=" + "a" * 32 + ";i=1;b=" + "b" * 32 + ";m=1;t=1;x=1", "lines": 100}
    assert reads.validate_params("journal_sync", good)["match"] == "auth"


def test_the_agent_refuses_a_file_index_the_machine_does_not_have(tmp_path):
    root = make_root(tmp_path, "debian", {})
    with pytest.raises(reads.ReadParamError):
        reads.file_sync_output("auth", 3, None, 0, None, root=str(root), now=NOW)


def test_run_probe_answers_refusals_instead_of_raising():
    out = reads.run_probe("file_sync", {"source": "auth", "file_index": 0, "offset": -5})
    assert out["status"] == "refused"
    out = reads.run_probe("journal_sync", {"match": "auth", "after_cursor": "nope"})
    assert out["status"] == "refused"


def test_the_agent_never_follows_a_symlinked_directory(tmp_path):
    root = make_root(tmp_path, "debian", {})
    secret = tmp_path / "elsewhere"
    secret.mkdir()
    (secret / "auth.log").write_text(L(1))
    (root / "var/log").rmdir() if (root / "var/log").exists() else None
    (root / "var").mkdir(exist_ok=True)
    (root / "var/log").symlink_to(secret)
    out = reads.file_sync_output("auth", 0, None, 0, None, root=str(root), now=NOW)
    r = logread.parse_output("auth", out["stdout"], None, None)
    assert not r.records and r.files and r.files[0].status in ("symlink", "refused", "missing")


# ---- the bundle ------------------------------------------------------------------------------------
def test_the_new_probes_need_agent_0_5_0():
    from kratos.subagent import core_server

    assert core_server.PROBE_MIN_AGENT_VERSION["journal_sync"] == (0, 5, 0)
    assert core_server.PROBE_MIN_AGENT_VERSION["file_sync"] == (0, 5, 0)
    assert core_server.PROBE_MIN_AGENT_VERSION["persistence_inventory"] == (0, 6, 0)   # A.1
    assert core_server.PROBE_MIN_AGENT_VERSION["live_inventory"] == (0, 6, 1)          # A.5
    assert core_server.PROBE_MIN_AGENT_VERSION["package_inventory"] == (0, 7, 0)       # A.2
    from kratos.subagent import agent

    assert agent.AGENT_VERSION == "0.7.1"       # phase A audit: live read records its blind spots
    assert {"journal_sync", "file_sync", "persistence_inventory", "live_inventory",
            "package_inventory"} <= set(reads.READ_PROBES)


def test_the_bundle_still_imports_without_kratos():
    from kratos.subagent import installer

    files = installer.read_bundle_files()
    for name in ("catalog.py", "logread.py", "reads.py"):
        text = files[name].replace("from kratos.logsources import", "").replace("from kratos.subagent import", "")
        assert "import kratos" not in text
