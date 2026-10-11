"""Event: validation and the to_ecs/from_ecs round trip (spec §5.2)."""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

import jsonschema
import pytest

from kratos.adapters import privileged_accounts
from kratos.adapters.auth_log_parse import classify_auth_message, iter_auth_events
from kratos.events import converters as C
from kratos.events.fields import json_schema
from kratos.events.model import Event, EventError

UTC = timezone.utc
NOW = datetime(2026, 10, 9, 13, 30, 0, 250000, tzinfo=UTC)
VALIDATOR = jsonschema.Draft202012Validator(json_schema(), format_checker=jsonschema.FormatChecker())


def _ctx(read, transport="ssh", **kw):
    return C.ReadContext(target="10.136.28.168", transport=transport, read=read, created=NOW,
                         run_id="ab" * 16, **kw)


def fixtures() -> list[Event]:
    """At least one event of every dataset, with most fields set."""
    auth = [C.from_auth_event(classify_auth_message("2026-10-09T13:01:02.000001+00:00", "t", ident, msg, msg),
                              ctx=_ctx(C.READ_JOURNAL_AUTH, window=(1790000000.5, 1790003600.0),
                                       coverage="complete"))
            for ident, msg in [
                ("sshd", "Failed password for invalid user admin from 10.136.28.52 port 51234 ssh2"),
                ("sudo", "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=nobody ; COMMAND=/usr/bin/true"),
                ("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)"),
                ("sshd", "Accepted publickey for ubuntu from 2001:db8::7 port 50000 ssh2"),
            ]]
    local = [C.from_auth_event(e, ctx=_ctx(C.READ_AUTH_LOG, transport="local", log_file_path="/var/log/auth.log"))
             for e in iter_auth_events([
                 "Oct  9 13:01:02 kratos-target sshd[812]: Failed password for root from 10.0.0.9 port 4000 ssh2",
                 "unparsed noise"])]
    journal = [C.from_journal_entry({"timestamp": "2026-10-09T12:00:00+00:00", "unit": "cron.service",
                                     "message": "x " * 3000, "priority": "6"},
                                    ctx=_ctx(C.READ_JOURNAL_FETCH, transport="agent", coverage="truncated"))]
    priv = [C.from_privileged_event(privileged_accounts.parse_event(line), ctx=_ctx(C.READ_PRIVILEGED))
            for line in ["1790538495.5 h usermod[1]: add 'bob' to group 'sudo'",
                         "1790538496 h useradd[2]: new user: name=eve, UID=1002, GID=1002, home=/home/eve"]]
    return auth + local + journal + priv


@pytest.mark.parametrize("event", fixtures(), ids=lambda e: f"{e.dataset}:{e.action}")
def test_round_trip_and_schema(event):
    doc = event.to_ecs()
    assert Event.from_ecs(doc) == event
    assert Event.from_ecs(json.loads(json.dumps(doc))) == event   # through JSON, as stored
    VALIDATOR.validate(doc)
    assert doc["ecs"]["version"] == "9.5.0" and doc["kratos"]["schema_version"] == 1


def test_fixtures_cover_every_dataset():
    assert {e.dataset for e in fixtures()} == {"kratos.auth", "kratos.journal", "kratos.privileged_accounts"}


def test_long_message_is_capped_and_flagged():
    journal = [e for e in fixtures() if e.dataset == "kratos.journal"][0]
    assert journal.truncated and len(journal.message.encode()) <= 4096


def _base(**over):
    e = fixtures()[0]
    return dataclasses.replace(e, **over) if over else e


@pytest.mark.parametrize("over", [
    {"category": ("authentication", "not-a-category")},
    {"type": ("begin",)},
    {"kind": "log"},
    {"outcome": "ok"},
    {"transport": "carrier-pigeon"},
    {"coverage": "most"},
    {"source_ip": "10.0.0.999"},
    {"timestamp": datetime(2026, 1, 1)},                                  # naive
    {"timestamp": datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2)))},  # not UTC
    {"source_port": "22"},
    {"redacted": 1},
    {"host_name": ""},
    {"category": ("authentication", "authentication")},
    {"message": "x" * 5000},
    {"window": (1, 2, 3)},
])
def test_invalid_values_rejected(over):
    with pytest.raises(EventError):
        _base(**over)


def test_from_ecs_rejects_unknown_and_missing_fields():
    doc = _base().to_ecs()
    with pytest.raises(EventError):
        Event.from_ecs({**doc, "made": {"up": 1}})
    doc.pop("@timestamp")
    with pytest.raises(EventError):
        Event.from_ecs(doc)


def test_unset_fields_are_left_out_of_the_document():
    doc = [e for e in fixtures() if e.dataset == "kratos.privileged_accounts"][0].to_ecs()
    assert "source" not in doc and "redacted" not in doc["kratos"]
    assert doc["event"]["category"] == ["iam"]
