"""The four reads produce events; their tool results don't change (spec §5.8, §3.4)."""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from kratos import kratos_config
from kratos.adapters import privileged_accounts as PA
from kratos.adapters.ssh_remote import JournalWindow
from kratos.agent import tools
from kratos.events import recording
from kratos.events.store import EventStore
from kratos.run_context import run_scope

TARGET = "10.136.28.168"
T = 1_790_538_000.0  # 2026-09-28

AUTH_ENTRIES = [
    (f"2026-09-28T{h:02d}:00:0{h % 10}+00:00", "sshd", f"Invalid user u{h} from 10.136.28.52 port {4000 + h}")
    for h in range(4)
] + [("2026-09-28T05:00:00+00:00", "sudo",
      "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=nobody ; COMMAND=/usr/bin/true")]
JOURNAL_ENTRIES = [
    {"timestamp": "2026-09-28T06:00:00+00:00", "unit": "cron.service", "message": "(root) CMD (run-parts)",
     "priority": "6"},
    {"timestamp": "2026-09-28T06:01:00+00:00", "unit": "kernel", "message": "eth0: link up", "priority": "5"},
]
PRIV_STDOUT = "\n".join([
    "GROUP\tsudo:x:27:ubuntu,bob",
    "PASSWD\tbob\t1001\t1001\t/bin/bash",
    "EVTSRC\tjournal",
    f"EVT\t{T + 10:.1f} kratos-target usermod[4242]: add 'bob' to group 'sudo'",
    f"EVT\t{T + 5:.1f} kratos-target useradd[4240]: new user: name=bob, UID=1001, GID=1001, home=/home/bob",
])


@pytest.fixture
def fakes(monkeypatch):
    """The target reads, faked at the fetchers; `via` says which transport they used."""
    kratos_config.set_active_target(f"ubuntu@{TARGET}")
    state = {"via": "ssh"}

    def auth(**kw):
        via = state["via"]
        windows = {"sshd": JournalWindow(kw.get("since_epoch"), kw.get("until_epoch"), 500, 4, False,
                                         AUTH_ENTRIES[0][0], AUTH_ENTRIES[3][0], via=via),
                   "sudo": JournalWindow(kw.get("since_epoch"), kw.get("until_epoch"), 500, 1, True,
                                         AUTH_ENTRIES[4][0], AUTH_ENTRIES[4][0], via=via)}
        return list(AUTH_ENTRIES), [], windows

    def journal(unit, since, lines, until_epoch=None):
        return list(JOURNAL_ENTRIES), JournalWindow(since, until_epoch, lines, 2, False,
                                                    JOURNAL_ENTRIES[0]["timestamp"],
                                                    JOURNAL_ENTRIES[1]["timestamp"], via=state["via"])

    monkeypatch.setattr(tools, "_fetch_journalctl_auth_entries", auth)
    monkeypatch.setattr(tools, "_fetch_journalctl_entries", journal)
    monkeypatch.setattr(tools, "_measure_target_clock_offset", lambda: 0.0)
    monkeypatch.setattr(tools, "_fetch_privileged_accounts", lambda days: (PA.parse_output(PRIV_STDOUT), int(T)))
    monkeypatch.setattr(tools, "_last_privileged_accounts_via", lambda: state["via"])
    return state


def _auth_log(tmp_path) -> Path:
    log = tmp_path / "auth.log"
    log.write_text(
        "Oct  9 13:01:02 kratos-target sshd[812]: Failed password for root from 10.136.28.52 port 4000 ssh2\n"
        "Oct  9 13:01:03 kratos-target sshd[812]: Failed password for root from 10.136.28.52 port 4001 ssh2\n"
        "Oct  9 13:01:04 kratos-target sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; "
        "COMMAND=/usr/bin/mysql -pS3cretPw\n", encoding="utf-8")
    return log


CALLS = {
    "parse_auth_log": lambda d, log: tools.tool_parse_auth_log(d, log_path=str(log), source="file"),
    "read_journalctl": lambda d, log: tools.tool_read_journalctl(d, since="2026-09-28 00:00", until="2026-09-28 12:00", lines=50),
    "list_privileged_accounts": lambda d, log: tools.tool_list_privileged_accounts(d, lookback_days=30),
}


def _normalised(result, data_dir: Path) -> str:
    text = json.dumps(result, sort_keys=True, default=str).replace(str(data_dir), "<DATA>")
    text = re.sub(r"\d{8}_\d{6}(_\d+)?", "<TS>", text)                       # file names carry the time
    text = re.sub(r'"checked_at": "[^"]*"', '"checked_at": "<NOW>"', text)  # so does this
    text = re.sub(r'"(since|until)_utc": "[^"]*"', r'"\1_utc": "<T>"', text)
    return text


@pytest.mark.parametrize("name", sorted(CALLS))
def test_tool_results_identical_with_events_on_and_off(name, tmp_path, fakes, monkeypatch):
    log = _auth_log(tmp_path)
    on_dir, off_dir = tmp_path / "on", tmp_path / "off"
    on = CALLS[name](on_dir, log)
    with monkeypatch.context() as m:
        for fn in ("record_local_auth_log", "record_target_auth", "record_journal", "record_privileged_changes"):
            m.setattr(recording, fn, lambda *a, **k: None)
        off = CALLS[name](off_dir, log)
    assert _normalised(on, on_dir) == _normalised(off, off_dir)
    assert EventStore(on_dir / "kratos.db").targets(), "events were recorded"
    assert not (off_dir / "kratos.db").exists() or not EventStore(off_dir / "kratos.db").targets()


@pytest.mark.parametrize("name", sorted(CALLS))
def test_a_failing_store_changes_nothing(name, tmp_path, fakes, monkeypatch, caplog):
    log = _auth_log(tmp_path)
    good = CALLS[name](tmp_path / "good", log)

    def boom(self, events):
        raise OSError("disk full")
    monkeypatch.setattr(EventStore, "add", boom)
    bad = CALLS[name](tmp_path / "bad", log)
    assert _normalised(good, tmp_path / "good") == _normalised(bad, tmp_path / "bad")


def test_a_failing_converter_changes_nothing(tmp_path, fakes, monkeypatch):
    from kratos.events import converters

    monkeypatch.setattr(converters, "from_journal_entry", lambda *a, **k: 1 / 0)
    out = tools.tool_read_journalctl(tmp_path, lines=50)
    assert out["status"] == "ok" and out["count"] == 2


def _store(d):
    return EventStore(Path(d) / "kratos.db")


def test_read_journalctl_records_auth_and_journal_events(tmp_path, fakes):
    with run_scope("cli") as run:
        tools.tool_read_journalctl(tmp_path, since="2 hours ago", lines=50)
    s = _store(tmp_path)
    fails = s.query(TARGET, action="ssh_failed_login", newest_first=False)
    assert [e.source_ip for e in fails] == ["10.136.28.52"] * 4
    e = fails[0]
    assert (e.category, e.type, e.outcome) == (("authentication",), ("start",), "failure")
    assert e.transport == "ssh" and e.read == "journal_auth" and e.run_id == run.run_id
    assert e.coverage == "complete" and e.window[0] is not None
    sudo = s.query(TARGET, action="sudo_command")[0]
    assert sudo.user_effective_name == "nobody" and sudo.coverage == "truncated"
    assert s.count(TARGET, dataset="kratos.journal") == 2
    # The same read again: nothing new (overlapping windows dedupe).
    before = s.count(TARGET)
    tools.tool_read_journalctl(tmp_path, since="2 hours ago", lines=50)
    assert s.count(TARGET) == before


def test_reads_through_the_sub_agent_say_so(tmp_path, fakes):
    fakes["via"] = "subagent"
    tools.tool_read_journalctl(tmp_path, lines=50)
    tools.tool_list_privileged_accounts(tmp_path)
    transports = {e.transport for e in _store(tmp_path).query(TARGET)}
    assert transports == {"agent"}


def test_privileged_changes_recorded(tmp_path, fakes):
    tools.tool_list_privileged_accounts(tmp_path)
    events = _store(tmp_path).query(TARGET, dataset="kratos.privileged_accounts", newest_first=False)
    assert [(e.action, e.user_target_name, e.group_name) for e in events] == [
        ("user_created", "bob", None), ("added_to_group", "bob", "sudo")]
    assert events[0].window == (float(int(T)), None)


def test_local_auth_log_recorded_masked_and_flagged(tmp_path, fakes):
    tools.tool_parse_auth_log(tmp_path, log_path=str(_auth_log(tmp_path)), source="file")
    events = _store(tmp_path).query("127.0.0.1", newest_first=False)
    assert len(events) == 3 and {e.transport for e in events} == {"local"}
    assert all(e.time_zone_assumed for e in events)  # a file at another path: zone unknown
    assert events[0].log_file_path.endswith("auth.log") and events[0].process_pid == 812
    sudo = events[2]
    assert "S3cretPw" not in json.dumps(sudo.to_ecs()) and sudo.redacted
    # ...and the raw text in the DB row too
    import sqlite3
    with sqlite3.connect(tmp_path / "kratos.db") as c:
        assert "S3cretPw" not in "".join(r[0] for r in c.execute("SELECT doc FROM host_events"))


def test_through_execute_tool_call_events_carry_the_run(tmp_path, fakes):
    from kratos.agent.loop import execute_tool_call

    with run_scope("schedule") as run:
        res = execute_tool_call("read_journalctl", {"lines": 20}, tmp_path)
    assert res["status"] == "ok"
    assert {e.run_id for e in _store(tmp_path).query(TARGET)} == {run.run_id}


def test_tui_use_stores_events_with_the_session_run(tmp_path, fakes, monkeypatch):
    """Across Textual's worker thread: the tool runs there, and so does recording."""
    from textual.app import App

    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session([TARGET], "m")
    screen = SessionScreen(store, tmp_path, sid, [TARGET], "")

    class Host(App):
        def on_mount(self):
            self.push_screen(screen)

    async def run():
        async with Host().run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash('/use read_journalctl {"lines": 20}')
            for _ in range(300):
                await pilot.pause()
                if _store(tmp_path).targets() and not screen._busy:
                    break
    asyncio.run(run())
    events = _store(tmp_path).query(TARGET)
    assert events and len({e.run_id for e in events}) == 1 and events[0].run_id is not None


def test_auth_coverage_report_keeps_its_keys(tmp_path, fakes):
    out = tools.tool_read_journalctl(tmp_path, lines=50)
    assert set(out["auth_correlation_data"]["coverage"]["sshd"]) == {
        "since_epoch", "until_epoch", "requested", "returned", "truncated", "oldest_returned", "newest_returned"}
