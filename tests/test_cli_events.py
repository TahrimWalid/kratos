"""`kratos events`: a read-only dump of stored events."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.cli import app
from kratos.events import converters as C
from kratos.events.model import Event
from kratos.events.store import EventStore


def _seed(tmp_path, n=3, minutes_ago=10):
    now = datetime.now(timezone.utc)
    events = []
    for i in range(n):
        ts = (now - timedelta(minutes=minutes_ago - i)).isoformat()
        msg = f"Invalid user u{i} from 10.136.28.52 port {4000 + i}"
        ctx = C.ReadContext(target="10.136.28.168", transport="ssh", read=C.READ_JOURNAL_AUTH, run_id="run1")
        events.append(C.from_auth_event(classify_auth_message(ts, "t", "sshd", msg, msg), ctx=ctx))
    EventStore(tmp_path / "kratos.db").add(events)
    return events


def _run(tmp_path, monkeypatch, *argv):
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    return app.main(["--data-dir", str(tmp_path), "events", *argv])


def test_plain_listing(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    assert _run(tmp_path, monkeypatch, "--target", "ubuntu@10.136.28.168", "--since", "1 hour ago") == 0
    out = capsys.readouterr().out
    assert out.count("ssh_failed_login") == 3 and "from=10.136.28.52" in out and "3 events for 10.136.28.168" in out


def test_json_is_one_ecs_document_per_line(tmp_path, monkeypatch, capsys):
    seeded = _seed(tmp_path)
    assert _run(tmp_path, monkeypatch, "--target", "10.136.28.168", "--json", "--oldest-first") == 0
    docs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [Event.from_ecs(d) for d in docs] == seeded
    assert docs[0]["kratos"]["transport"] == "ssh" and docs[0]["event"]["category"] == ["authentication"]


def test_filters_and_limit(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, n=5)
    _run(tmp_path, monkeypatch, "--target", "10.136.28.168", "--limit", "2", "--user", "u3")
    out = capsys.readouterr().out
    assert "user=u3" in out and "user=u2" not in out
    _run(tmp_path, monkeypatch, "--target", "10.136.28.168", "--limit", "2")
    assert "2 of 5 events" in capsys.readouterr().out


def test_nothing_stored_says_which_machines_have_events(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    assert _run(tmp_path, monkeypatch, "--target", "10.9.9.9") == 0
    assert "Machines with events: 10.136.28.168" in capsys.readouterr().out


def test_bad_time_is_a_clear_error(tmp_path, monkeypatch, capsys):
    assert _run(tmp_path, monkeypatch, "--target", "x", "--since", "next tuesday") == 1
    assert "[KRATOS]" in capsys.readouterr().err
