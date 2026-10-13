"""Incremental log sync: cursors, coverage spans, gaps, events -- with scripted reads
(no machine). The shell script and the agent's file read are exercised on a real fake
file tree in tests/test_collect_sync_reads.py."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from kratos.collect import sync
from kratos.collect.sync import cursors, engine
from kratos.events.store import EventStore
from kratos.logsources import catalog, logread
from kratos.logsources.logread import FileRead, JournalSync, LogRead, Record
from kratos.target_key import target_key

TARGET = "10.7.7.7"
TKEY = target_key(TARGET)
BOOT = "b" * 32
SEQ_A = "a" * 32
SEQ_B = "c" * 32
NOW = 1_800_000_000.0


def cursor(i: int, ts: float, seq: str = SEQ_A) -> str:
    return f"s={seq};i={i:x};b={BOOT};m={i:x};t={int(ts * 1_000_000):x};x={i:x}"


def entry(i: int, ts: float, msg: str = "Failed password for root from 198.51.100.7 port 22 ssh2",
          ident: str = "sshd", seq: str = SEQ_A) -> dict[str, Any]:
    return {"__CURSOR": cursor(i, ts, seq), "__REALTIME_TIMESTAMP": str(int(ts * 1_000_000)), "MESSAGE": msg,
            "SYSLOG_IDENTIFIER": ident, "_COMM": ident, "_PID": "100"}


class FakeJournal:
    """Scripted journal for one match: answers like journalctl --after-cursor, forward."""

    def __init__(self, entries: list[dict[str, Any]], oldest: float | None = None, now: float = NOW) -> None:
        self.entries = entries
        self.oldest = oldest if oldest is not None else (_ts(entries[0]) if entries else None)
        self.now = now
        self.calls: list[tuple] = []
        self.refuse_cursor = False
        self.have_journal = True

    def __call__(self, match: str, after: str | None, since: float | None, lines: int) -> JournalSync:
        self.calls.append((match, after, since, lines))
        out = JournalSync(have_journal=self.have_journal, now=self.now, oldest_ts=self.oldest)
        if after is not None and self.refuse_cursor:
            out.errors = ["Failed to seek to cursor: Invalid argument"]
            return out
        pool = self.entries
        if after is not None:
            pool = [e for e in pool if e["__CURSOR"] > after and _ts(e) >= _cursor_ts(after) - 1] \
                if False else _after(pool, after)
        elif since is not None:
            pool = [e for e in pool if _ts(e) >= since]
        out.entries = list(pool[: lines + 1])
        return out


def _ts(e: dict[str, Any]) -> float:
    return int(e["__REALTIME_TIMESTAMP"]) / 1_000_000


def _cursor_ts(c: str) -> float:
    return logread.cursor_realtime(c) or 0.0


def _after(pool: list[dict[str, Any]], after: str) -> list[dict[str, Any]]:
    seen = False
    out = []
    for e in pool:
        if seen:
            out.append(e)
        if e["__CURSOR"] == after:
            seen = True
    if not seen:                               # a cursor the journal no longer holds: from that time on
        return [e for e in pool if _ts(e) > _cursor_ts(after)]
    return out


def fetchers(journal=None, file=None) -> engine.Fetchers:
    def no_file(*a: Any, **k: Any) -> Any:
        raise AssertionError("no file read expected")

    def no_journal(*a: Any, **k: Any) -> Any:
        raise AssertionError("no journal read expected")

    return engine.Fetchers(journal=journal or no_journal, file=file or no_file)


def run(tmp_path: Path, fetch: engine.Fetchers, source: str = "auth", now: float = NOW, **kw: Any) -> engine.SourceReport:
    kw.setdefault("initial_hours", 24)
    kw.setdefault("max_lines", 1000)
    kw.setdefault("deadline", time.monotonic() + 60)
    return engine.sync_source(tmp_path, TARGET, source, fetchers=fetch, now=now, **kw)


def stored(tmp_path: Path) -> int:
    return EventStore(tmp_path / "kratos.db").count(TARGET)


# ----------------------------------------------------------------------------- cursor format
def test_cursor_format_accepts_real_cursors_and_refuses_junk():
    real = "s=182f9da338364125bd028c867e8289c2;i=3138;b=9759ea4124464ffd94ed7add450a5099;m=40934241338;t=65db10c6adad2;x=5d0783fdfe98bcec"
    assert logread.valid_cursor(real)
    for junk in ("", "garbage", real + ";rm -rf /", real + " ", "$(id)", real.replace("s=", "S="), "s=1;i=2", None, 5,
                 real + "\n", real[:-1] + "g", "--" + real):
        assert not logread.valid_cursor(junk), junk


def test_no_command_for_a_junk_cursor_is_ever_built():
    with pytest.raises(ValueError):
        logread.journal_sync_argv("auth", "x; reboot", None)
    with pytest.raises(ValueError):
        logread.build_journal_sync_script("auth", "$(id)", None, 10)
    with pytest.raises(KeyError):                      # the match is a closed table
        logread.journal_sync_argv("anything-else", None, 1.0)


def test_the_journal_script_never_writes_on_the_machine():
    script = logread.build_journal_sync_script("auth", cursor(5, NOW), None, 100)
    only_quieting = (script.replace("2>/dev/null", "").replace("2>&1", "").replace(">/dev/null", "")
                     .replace("(b > cap)", ""))                      # the awk byte-cap comparison
    assert ">" not in only_quieting                                              # no redirect into a file
    files = logread.build_file_sync_script("auth", {0: (None, 0)}, floor=None)
    for banned in ("tee ", "mktemp", "touch ", " dd ", "> /", ">>"):
        assert banned not in script + files, banned
    assert "cursor-file" not in script
    first = logread.build_journal_sync_script("cron", None, NOW - 3600, 100)
    assert "--since @" in first and "--after-cursor" not in first


# ----------------------------------------------------------------------------- journal sync
def test_first_sync_reads_from_the_look_back_then_forward_from_the_cursor(tmp_path):
    es = [entry(i, NOW - 3600 + i * 10) for i in range(1, 6)]
    j = FakeJournal(es)
    rep = run(tmp_path, fetchers(journal=j))
    assert rep.status == "ok" and rep.lines_read == 5 and rep.new_events == 5 and not rep.behind
    match, after, since, lines = j.calls[0]
    assert match == "auth" and after is None and since == NOW - 24 * 3600 and lines == 1000
    cur = cursors.get_cursor(tmp_path, TKEY, "auth", "journal")
    assert cur.position == es[-1]["__CURSOR"] and cur.seqnum_id == SEQ_A
    # the next sync starts AFTER that cursor, and finds the 2 new lines
    es2 = es + [entry(6, NOW + 10), entry(7, NOW + 20)]
    j2 = FakeJournal(es2, now=NOW + 60)
    rep2 = run(tmp_path, fetchers(journal=j2), now=NOW + 60)
    assert j2.calls[0][1] == es[-1]["__CURSOR"] and j2.calls[0][2] is None
    assert rep2.lines_read == 2 and rep2.new_events == 2 and stored(tmp_path) == 7


def test_a_source_that_is_cut_at_the_cap_continues_next_round(tmp_path):
    es = [entry(i, NOW - 600 + i) for i in range(1, 8)]
    j = FakeJournal(es)
    rep = run(tmp_path, fetchers(journal=j), max_lines=3)
    # three rounds of 3,3,1 within one sync (MAX_ROUNDS) -> caught up
    assert rep.lines_read == 7 and not rep.behind and len(j.calls) == 3
    assert stored(tmp_path) == 7


def test_behind_is_reported_when_the_rounds_run_out(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_ROUNDS", 1)
    es = [entry(i, NOW - 600 + i) for i in range(1, 10)]
    rep = run(tmp_path, fetchers(journal=FakeJournal(es)), max_lines=3)
    assert rep.behind and rep.lines_read == 3
    assert cursors.get_cursor(tmp_path, TKEY, "auth", "journal").behind
    assert not cursors.covered(tmp_path, TKEY, "auth", NOW - 600, NOW)          # only part of it is in


def test_the_synced_span_is_complete_and_adjacent_syncs_merge(tmp_path):
    es = [entry(i, NOW - 3000 + i) for i in range(1, 4)]
    run(tmp_path, fetchers(journal=FakeJournal(es, now=NOW - 2000)), now=NOW - 2000)
    run(tmp_path, fetchers(journal=FakeJournal(es, now=NOW)), now=NOW)
    sp = [s for _src, s in cursors.spans(tmp_path, TKEY, "auth") if s.complete]
    assert len(sp) == 1 and sp[0].end == NOW                                     # merged into one
    assert cursors.covered(tmp_path, TKEY, "auth", NOW - 1500, NOW - 10)
    assert not cursors.covered(tmp_path, TKEY, "auth", NOW - 2 * 24 * 3600, NOW)  # before the first sync's reach


def test_a_quiet_source_still_advances_its_coverage(tmp_path):
    run(tmp_path, fetchers(journal=FakeJournal([], now=NOW)), now=NOW)
    run(tmp_path, fetchers(journal=FakeJournal([], now=NOW + 900)), now=NOW + 900)
    assert cursors.covered(tmp_path, TKEY, "auth", NOW - 600, NOW + 800)


def test_a_cursor_the_journal_refuses_restarts_by_time_and_records_a_gap(tmp_path):
    es = [entry(i, NOW - 1000 + i) for i in range(1, 4)]
    run(tmp_path, fetchers(journal=FakeJournal(es, now=NOW - 900)), now=NOW - 900)
    j = FakeJournal(es + [entry(9, NOW + 5)], now=NOW + 60)
    j.refuse_cursor = True
    rep = run(tmp_path, fetchers(journal=j), now=NOW + 60)
    assert j.calls[0][1] is not None and j.calls[1][1] is None and j.calls[1][2] is not None   # then by time
    assert any("restarted by time" in g for g in rep.gaps)
    gaps = [s for _src, s in cursors.spans(tmp_path, TKEY, "auth") if not s.complete]
    assert gaps and "no longer accepted" in gaps[0].note
    # no false "complete": the window around the restart is not covered
    assert not cursors.covered(tmp_path, TKEY, "auth", NOW - 1000, NOW + 50)


def test_a_vacuumed_hole_is_a_gap_not_complete_coverage(tmp_path):
    es = [entry(i, NOW - 5000 + i) for i in range(1, 4)]
    run(tmp_path, fetchers(journal=FakeJournal(es, now=NOW - 4000)), now=NOW - 4000)
    # later: entries up to NOW-1000 were vacuumed; the oldest the journal still holds is newer than our position
    kept = [entry(50, NOW - 500), entry(51, NOW - 400)]
    rep = run(tmp_path, fetchers(journal=FakeJournal(kept, oldest=NOW - 500, now=NOW)), now=NOW)
    assert any("no longer holds entries between" in g for g in rep.gaps)
    assert not cursors.covered(tmp_path, TKEY, "auth", NOW - 4000, NOW)
    assert cursors.covered(tmp_path, TKEY, "auth", NOW - 400, NOW - 10)           # what came after the hole is complete
    assert stored(tmp_path) == 5


def test_a_new_journal_seqnum_id_with_a_hole_is_recorded_too(tmp_path):
    es = [entry(i, NOW - 3000 + i) for i in range(1, 3)]
    run(tmp_path, fetchers(journal=FakeJournal(es, now=NOW - 2900)), now=NOW - 2900)
    fresh = [entry(1, NOW - 100, seq=SEQ_B), entry(2, NOW - 90, seq=SEQ_B)]      # journal recreated
    rep = run(tmp_path, fetchers(journal=FakeJournal(fresh, oldest=NOW - 100, now=NOW)), now=NOW)
    assert rep.gaps and not cursors.covered(tmp_path, TKEY, "auth", NOW - 3000, NOW)
    assert cursors.get_cursor(tmp_path, TKEY, "auth", "journal").seqnum_id == SEQ_B


def test_re_reading_overlapping_lines_stores_each_event_once(tmp_path):
    es = [entry(i, NOW - 600 + i) for i in range(1, 6)]
    run(tmp_path, fetchers(journal=FakeJournal(es)))
    cursors.delete_cursors(tmp_path, TKEY, "auth")                  # as if the position were lost
    rep = run(tmp_path, fetchers(journal=FakeJournal(es)))
    assert rep.lines_read == 5 and rep.new_events == 0 and stored(tmp_path) == 5


def test_entries_with_a_junk_cursor_are_dropped_never_saved_as_a_position(tmp_path):
    es = [entry(1, NOW - 100), {**entry(2, NOW - 90), "__CURSOR": "x; reboot"}]
    rep = run(tmp_path, fetchers(journal=FakeJournal(es)))
    assert rep.lines_read == 1
    assert cursors.get_cursor(tmp_path, TKEY, "auth", "journal").position == es[0]["__CURSOR"]


def test_the_position_does_not_move_when_the_event_store_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_store", lambda *a, **k: None)
    rep = run(tmp_path, fetchers(journal=FakeJournal([entry(1, NOW - 100)])))
    assert rep.status == "failed"
    assert cursors.get_cursor(tmp_path, TKEY, "auth", "journal") is None
    assert not cursors.covered(tmp_path, TKEY, "auth", NOW - 200, NOW)


def test_a_failed_read_is_reported_not_raised(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult

    bad = lambda *a: SSHResult(ok=False, returncode=255, stdout="", stderr="ssh: connect timed out")  # noqa: E731
    rep = run(tmp_path, fetchers(journal=bad))
    assert rep.status == "failed" and not rep.old_agent


def test_an_old_agent_yields_an_update_message_not_a_crash(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult

    old = lambda *a: SSHResult(ok=False, returncode=-1, stdout="", via="subagent", stderr=(  # noqa: E731
        "via the sub-agent: this box runs sub-agent 0.4.0; the journal_sync read needs 0.5.0 or newer -- "
        "update the agent (`g` in /subagent, select the box). Nothing was read for this part."))
    rep = run(tmp_path, fetchers(journal=old))
    assert rep.status == "failed" and rep.old_agent and "update it" in rep.message


def test_a_machine_without_a_journal_falls_back_to_the_files(tmp_path):
    j = FakeJournal([])
    j.have_journal = False
    files = FakeFiles()
    files.add_family("debian", 1)
    rep = run(tmp_path, fetchers(journal=j, file=files))
    assert rep.mode == "files" and files.calls and files.calls[0][0] == "auth"


def test_a_source_with_no_journal_and_no_files_is_not_supported(tmp_path):
    j = FakeJournal([])
    j.have_journal = False
    rep = run(tmp_path, fetchers(journal=j), source="systemd")
    assert rep.status == "not_supported"


# ----------------------------------------------------------------------------- file sync
class FakeFiles:
    """Scripted file reads: each call pops the next prepared LogRead."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.queue: list[LogRead] = []
        self.families: dict[int, str] = {}

    def add_family(self, family: str, n: int) -> None:
        self.queue.append(read(family, [], now=NOW))

    def __call__(self, source: str, idx: int, inode: int | None, offset: int, floor: float | None) -> LogRead:
        self.calls.append((source, idx, inode, offset, floor))
        if not self.queue:
            raise AssertionError("no more scripted file reads")
        return self.queue.pop(0)


def read(family: str, files: list[FileRead], records: list[Record] | None = None, now: float = NOW) -> LogRead:
    r = LogRead(source="packages", family=family, tz_name="UTC", tz_offset="+0000", now=now, files=files)
    r.records = records or []
    return r


def fr(slot: int, status: str, path: str = "/var/log/dpkg.log", **kw: Any) -> FileRead:
    return FileRead(index=0, slot=slot, path=path, status=status, **kw)


def line(ts: float, text: str = "2026-10-12 10:00:00 install tree:amd64 <none> 2.0-1", path: str = "/var/log/dpkg.log") -> Record:
    return Record(kind="file", ts=ts, text=text, path=path)


DPKG1 = "2026-10-12 10:00:00 install tree:amd64 <none> 2.0-1"


def pkg_files(n_second_file: bool = True) -> int:
    return len(catalog.sync_files("packages", "debian"))


def test_file_sync_moves_the_offset_by_exactly_what_was_consumed(tmp_path):
    ff = FakeFiles()
    recs = [line(NOW - 100, DPKG1)]
    ff.queue = [
        read("debian", [fr(0, "read", size=1000, inode=77, start=0, consumed=60, first=NOW - 100, last=NOW - 100)], recs),
        read("debian", [fr(0, "missing", "/var/log/apt/history.log")]),
    ]
    rep = run(tmp_path, fetchers(file=ff), source="packages")
    assert rep.mode == "files" and rep.lines_read == 1 and rep.new_events == 1
    cur = cursors.get_cursor(tmp_path, TKEY, "packages", "file:0")
    assert cur.offset == 60 and cur.inode == 77
    # the first call had no saved position; the next sync passes (inode, offset) back
    assert ff.calls[0][2:4] == (None, 0)
    ff.queue = [read("debian", [fr(0, "read", size=1000, inode=77, start=60, consumed=0)]),
                read("debian", [fr(0, "missing", "/var/log/apt/history.log")])]
    run(tmp_path, fetchers(file=ff), source="packages", now=NOW + 60)
    assert ff.calls[2][2:4] == (77, 60)


def test_a_file_that_is_behind_is_followed_up_in_the_same_sync(tmp_path):
    ff = FakeFiles()
    big = logread.SYNC_CHUNK_BYTES * 3
    ff.queue = [
        read("debian", [fr(0, "read", size=big, inode=5, start=0, consumed=logread.SYNC_CHUNK_BYTES, first=NOW - 900,
                           last=NOW - 800)], [line(NOW - 900)]),
        read("debian", [fr(0, "read", size=big, inode=5, start=logread.SYNC_CHUNK_BYTES,
                           consumed=logread.SYNC_CHUNK_BYTES, first=NOW - 700, last=NOW - 600)], [line(NOW - 700, DPKG1 + "x")]),
        read("debian", [fr(0, "read", size=big, inode=5, start=2 * logread.SYNC_CHUNK_BYTES,
                           consumed=logread.SYNC_CHUNK_BYTES, first=NOW - 500, last=NOW - 400)], [line(NOW - 500, DPKG1 + "y")]),
        read("debian", [fr(0, "missing", "/var/log/apt/history.log")]),
    ]
    rep = run(tmp_path, fetchers(file=ff), source="packages")
    assert rep.lines_read == 3 and not rep.behind
    assert [c[3] for c in ff.calls[:3]] == [0, logread.SYNC_CHUNK_BYTES, 2 * logread.SYNC_CHUNK_BYTES]


def test_a_rotated_file_is_finished_from_its_old_inode_then_the_new_file_starts_at_zero(tmp_path):
    cursors.put_cursor(tmp_path, TKEY, "packages", "file:0", position="500", inode=11, last_ts=NOW - 1000)
    ff = FakeFiles()
    old = "/var/log/dpkg.log.1"
    ff.queue = [
        # the path now holds inode 22; the file we followed (inode 11) is dpkg.log.1
        read("debian", [fr(0, "current", size=100, inode=22),
                        fr(1, "read", old, size=800, inode=11, start=500, consumed=300, first=NOW - 900, last=NOW - 800)],
             [line(NOW - 900, DPKG1, old)]),
        read("debian", [fr(0, "read", size=100, inode=22, start=0, consumed=100, first=NOW - 500, last=NOW - 400)],
             [line(NOW - 500, DPKG1 + "z")]),
        read("debian", [fr(0, "missing", "/var/log/apt/history.log")]),
    ]
    rep = run(tmp_path, fetchers(file=ff), source="packages")
    assert rep.lines_read == 2 and stored(tmp_path) == 2
    assert ff.calls[0][2:4] == (11, 500)                       # asked to look for inode 11
    assert ff.calls[1][2:4] == (22, 0)                         # then the new file from the start
    cur = cursors.get_cursor(tmp_path, TKEY, "packages", "file:0")
    assert (cur.inode, cur.offset) == (22, 100)


def test_a_rotated_file_that_cannot_be_found_is_a_gap(tmp_path):
    cursors.put_cursor(tmp_path, TKEY, "packages", "file:0", position="500", inode=11, last_ts=NOW - 1000)
    ff = FakeFiles()
    ff.queue = [read("debian", [fr(0, "current", size=100, inode=22), fr(1, "rotated_lost")]),
                read("debian", [fr(0, "read", size=100, inode=22, start=0, consumed=100)], []),
                read("debian", [fr(0, "missing", "/var/log/apt/history.log")])]
    rep = run(tmp_path, fetchers(file=ff), source="packages")
    assert any("rotated and the previous file is gone" in g for g in rep.gaps)
    assert [s for _src, s in cursors.spans(tmp_path, TKEY, "packages") if not s.complete]
    assert not cursors.covered(tmp_path, TKEY, "packages", NOW - 1000, NOW)


def test_a_truncated_file_is_a_gap_and_restarts_at_zero(tmp_path):
    cursors.put_cursor(tmp_path, TKEY, "packages", "file:0", position="5000", inode=11, last_ts=NOW - 1000)
    ff = FakeFiles()
    ff.queue = [read("debian", [fr(0, "truncated", size=40, inode=11)]),
                read("debian", [fr(0, "read", size=40, inode=11, start=0, consumed=40, first=NOW - 5, last=NOW - 4)],
                     [line(NOW - 5)]),
                read("debian", [fr(0, "missing", "/var/log/apt/history.log")])]
    rep = run(tmp_path, fetchers(file=ff), source="packages")
    assert any("was cut short" in g for g in rep.gaps)
    assert ff.calls[1][2:4] == (11, 0)
    assert not cursors.covered(tmp_path, TKEY, "packages", NOW - 1000, NOW)


def test_unreadable_symlink_and_hardlink_files_are_reported_not_read(tmp_path):
    for status in ("unreadable", "symlink", "hardlink"):
        ff = FakeFiles()
        ff.queue = [read("debian", [fr(0, status)]), read("debian", [fr(0, "missing", "/var/log/apt/history.log")])]
        rep = run(tmp_path, fetchers(file=ff), source="packages")
        assert rep.lines_read == 0 and rep.status == "partial" and rep.gaps, status
        assert cursors.get_cursor(tmp_path, TKEY, "packages", "file:0") is None


def test_a_file_read_that_raced_a_rotation_changes_nothing(tmp_path):
    ff = FakeFiles()
    ff.queue = [read("debian", [fr(0, "changed")]), read("debian", [fr(0, "missing", "/var/log/apt/history.log")])]
    rep = run(tmp_path, fetchers(file=ff), source="packages")
    assert rep.status == "partial" and cursors.get_cursor(tmp_path, TKEY, "packages", "file:0") is None


# ----------------------------------------------------------------------------- coverage
def test_covered_is_true_only_without_a_hole(tmp_path):
    cursors.add_span(tmp_path, TKEY, "x", 100, 200, complete=True)
    cursors.add_span(tmp_path, TKEY, "x", 200, 300, complete=True)
    cursors.add_span(tmp_path, TKEY, "x", 300, 340, complete=False, note="gap")
    cursors.add_span(tmp_path, TKEY, "x", 340, 400, complete=True)
    assert cursors.covered(tmp_path, TKEY, "x", 110, 290)
    assert not cursors.covered(tmp_path, TKEY, "x", 110, 390)           # the gap splits it
    assert cursors.covered(tmp_path, TKEY, "x", 350, 399)
    assert not cursors.covered(tmp_path, TKEY, "x", 50, 150)
    assert not cursors.covered(tmp_path, TKEY, "other", 110, 190)
    assert not cursors.covered(tmp_path, "other-machine", "x", 110, 190)
    spans = cursors.spans(tmp_path, TKEY, "x")
    assert [s.complete for _s, s in spans] == [True, False, True]        # the two before the gap merged


# ----------------------------------------------------------------------------- events + settings
def test_synced_lines_become_events_with_the_right_labels(tmp_path):
    from kratos.run_context import run_scope

    es = [entry(1, NOW - 100)]
    with run_scope("schedule", target=TARGET) as rc:
        run(tmp_path, fetchers(journal=FakeJournal(es)))
    ev = EventStore(tmp_path / "kratos.db").query(TARGET)[0]
    assert ev.dataset == "kratos.auth" and ev.action == "ssh_failed_login" and ev.source_ip == "198.51.100.7"
    assert ev.run_id == rc.run_id
    assert ev.transport == "ssh" and "log_sync.auth" in str(ev.read)


def test_sources_and_settings(tmp_path):
    from kratos import settings_store
    from kratos.collect.sync import settings as ss

    assert settings_store.get(ss.SOURCES, data_dir=tmp_path) == list(catalog.DEFAULT_SYNC_SOURCES)
    assert "web" not in catalog.DEFAULT_SYNC_SOURCES                        # off by default: can be huge
    settings_store.set(ss.SOURCES, "auth, web", data_dir=tmp_path, actor="test")
    assert settings_store.get(ss.SOURCES, data_dir=tmp_path) == ["auth", "web"]
    with pytest.raises(settings_store.SettingError):
        settings_store.set(ss.SOURCES, "auth, bogus", data_dir=tmp_path, actor="test")


def test_sync_logs_runs_every_selected_source_and_isolates_failures(tmp_path):
    def journal(match, after, since, lines):
        if match == "cron":
            raise RuntimeError("boom")
        return JournalSync(have_journal=True, now=NOW, entries=[entry(1, NOW - 50, ident="CRON" if False else "sshd")])

    rep = sync.sync_logs(TARGET, tmp_path, sources=("auth", "cron", "systemd"), fetchers=fetchers(journal=journal),
                         now=NOW)
    by = {s.source: s for s in rep.sources}
    assert by["cron"].status == "failed" and by["auth"].status == "ok" and by["systemd"].status == "ok"


def test_out_of_time_sources_are_left_for_next_time(tmp_path):
    rep = sync.sync_logs(TARGET, tmp_path, sources=("auth", "cron"), fetchers=fetchers(journal=FakeJournal([])),
                         now=NOW, deadline=time.monotonic() - 1)
    assert all(s.status == "skipped" and s.behind for s in rep.sources)
