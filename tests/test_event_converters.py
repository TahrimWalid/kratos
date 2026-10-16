"""Converters: existing parser outputs -> ECS events (spec §5.3, §5.5)."""
from __future__ import annotations

import ast
import inspect
import re
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from kratos.adapters import auth_log_parse, privileged_accounts
from kratos.adapters.auth_log_parse import classify_auth_message, iter_auth_events
from kratos.events import converters as C
from kratos.events.model import Event

UTC = timezone.utc
NOW = datetime(2026, 10, 9, 13, 30, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures" / "timewin"


def _ctx(read=C.READ_JOURNAL_AUTH, **kw):
    kw.setdefault("created", NOW)
    return C.ReadContext(target=kw.pop("target", "ubuntu@10.136.28.168"),
                         transport=kw.pop("transport", "ssh"), read=read, **kw)


def _journal_auth(ident, msg, ts="2026-10-09T13:01:02.123456+00:00"):
    return C.from_auth_event(classify_auth_message(ts, "10.136.28.168", ident, msg, msg), ctx=_ctx())


# ---------------------------------------------------------------------------
# The event-type table
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ident, msg, action, category, etype, outcome", [
    ("sshd", "Failed password for invalid user admin from 10.136.28.52 port 51234 ssh2",
     "ssh_failed_login", ("authentication",), ("start",), "failure"),
    ("sshd-session", "Invalid user oracle from 10.136.28.52 port 40000",
     "ssh_failed_login", ("authentication",), ("start",), "failure"),
    ("sshd", "Accepted publickey for ubuntu from 10.136.28.1 port 50000 ssh2: ED25519 SHA256:abc",
     "ssh_success_login", ("authentication",), ("start",), "success"),
    ("sshd", "Disconnected from 10.136.28.52 port 51234", "ssh_disconnect", ("session",), ("end",), "unknown"),
    ("sudo", "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=nobody ; COMMAND=/usr/bin/true",
     "sudo_command", ("process",), ("start",), "success"),
    ("sudo", "ubuntu : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls",
     "sudo_auth_failure", ("authentication",), ("start",), "failure"),
    ("sudo", "pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 euid=0 tty=/dev/pts/0 ruser=ubuntu rhost=  user=ubuntu",
     "sudo_pam_auth_failure", ("authentication",), ("start",), "failure"),
    ("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)",
     "sudo_other", (), ("info",), "unknown"),
    ("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
     "sudo_session_open", ("session",), ("start",), "success"),
    ("sudo", "pam_unix(sudo:session): session closed for user root", "sudo_session_close",
     ("session",), ("end",), "success"),
    ("sshd", "Server listening on 0.0.0.0 port 22.", "ssh_other", (), ("info",), "unknown"),
])
def test_auth_table(ident, msg, action, category, etype, outcome):
    e = _journal_auth(ident, msg)
    assert (e.action, e.category, e.type, e.outcome) == (action, category, etype, outcome)
    assert e.dataset == "kratos.auth" and e.kind == "event" and e.host_name == "10.136.28.168"
    assert e.transport == "ssh" and e.read == "journal_auth" and e.parser == "auth_log/1"
    assert e.message == msg and e.original is None


def test_ssh_failure_fields():
    e = _journal_auth("sshd", "Failed password for invalid user admin from 10.136.28.52 port 51234 ssh2")
    assert e.source_ip == "10.136.28.52" and e.source_port == 51234
    assert e.user_name == "admin" and e.related_ip == ("10.136.28.52",) and e.related_user == ("admin",)
    assert e.process_name == "sshd" and e.provider == "sshd"
    assert e.timestamp == datetime(2026, 10, 9, 13, 1, 2, 123456, tzinfo=UTC)
    assert not e.time_zone_assumed


def test_sudo_command_fields():
    e = _journal_auth("sudo", "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=nobody ; COMMAND=/usr/bin/true")
    assert e.user_name == "ubuntu" and e.user_effective_name == "nobody"
    assert e.process_command_line == "/usr/bin/true" and e.related_user == ("ubuntu", "nobody")
    # ECS: the process event is about the command started; sudo logged it.
    assert e.process_executable == "/usr/bin/true" and e.process_name == "true" and e.provider == "sudo"


def test_local_sudo_line_puts_sudos_pid_as_the_parent():
    e = _local("Oct  9 13:01:04 h sudo[777]:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id -u")
    assert e.process_parent_pid == 777 and e.process_pid is None
    assert e.process_executable == "/usr/bin/id" and e.process_command_line == "/usr/bin/id -u"


def test_sudo_command_line_is_masked():
    e = _journal_auth("sudo", "ubuntu : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/mysql -uroot -pTopSecret1")
    assert "TopSecret1" not in (e.process_command_line + e.message) and e.redacted


def test_sudo_session_open_records_who_and_as_whom():
    e = _journal_auth("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)")
    assert e.user_effective_name == "root" and e.user_id == "1000"


# ---------------------------------------------------------------------------
# Completeness: every type the parsers can produce has a mapping
# ---------------------------------------------------------------------------
def _auth_types_in_source() -> set[str]:
    """Every event_type literal passed to AuthEvent(...) anywhere in auth_log_parse."""
    types = set()
    for node in ast.walk(ast.parse(inspect.getsource(auth_log_parse))):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "AuthEvent":
            for arg in node.args[3:4]:
                if isinstance(arg, ast.Constant):
                    types.add(arg.value)
            for kw in node.keywords:
                if kw.arg == "event_type" and isinstance(kw.value, ast.Constant):
                    types.add(kw.value.value)
    return types


def test_every_auth_event_type_is_mapped():
    found = _auth_types_in_source()
    assert {"ssh_failed_login", "sudo_command", "unparsed_auth_line", "auth_other"} <= found  # the scan works
    assert found - set(C.AUTH_EVENT_TYPES) == set()


def test_every_privileged_action_is_mapped():
    actions = {a for a, _rx in privileged_accounts._EVENT_PATTERNS}
    assert actions and actions - set(C.PRIVILEGED_ACTIONS) == set()


def test_every_mapped_value_is_ecs_allowed_and_consistent():
    import json

    ref = json.loads((Path(__file__).parent / "fixtures" / "ecs" / "ecs_9.5.0_subset.json").read_text())["fields"]
    expected = ref["event.category"]["expected_event_types"]
    for cats, types, *_ in list(C.AUTH_EVENT_TYPES.values()) + list(C.PRIVILEGED_ACTIONS.values()):
        for c in cats:
            assert set(types) <= set(expected[c]), (c, types)


# ---------------------------------------------------------------------------
# Local auth.log lines: zone-less times
# ---------------------------------------------------------------------------
def _local(line, zone=None, now=NOW):
    ev = iter_auth_events([line])[0]
    return C.from_auth_event(ev, ctx=_ctx(read=C.READ_AUTH_LOG, target="127.0.0.1", transport="local",
                                          time_zone=zone, created=now, log_file_path="/var/log/auth.log"))


def test_syslog_line_in_utc_is_flagged_assumed():
    e = _local("Oct  9 13:01:02 kratos-target sshd[812]: Failed password for root from 10.136.28.52 port 4000 ssh2")
    assert e.timestamp == datetime(2026, 10, 9, 13, 1, 2, tzinfo=UTC) and e.time_zone_assumed
    assert e.host_name == "loopback" and e.process_pid == 812 and e.log_file_path == "/var/log/auth.log"
    assert e.original.startswith("Oct  9 13:01:02 kratos-target sshd[812]:")
    assert e.message.startswith("Failed password for root")


def test_syslog_line_in_the_targets_zone():
    # Target in UTC+3, Kratos host in UTC: 13:01 local there is 10:01 UTC.
    e = _local("Oct  9 13:01:02 tz-box sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2",
               zone=ZoneInfo("Europe/Moscow"))
    assert e.timestamp == datetime(2026, 10, 9, 10, 1, 2, tzinfo=UTC) and not e.time_zone_assumed


def test_december_line_read_on_new_years_day_is_last_year():
    jan1 = datetime(2027, 1, 1, 0, 5, tzinfo=UTC)
    e = _local("Dec 31 23:59:58 h sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2", now=jan1)
    assert e.timestamp == datetime(2026, 12, 31, 23, 59, 58, tzinfo=UTC)
    # ...but tomorrow's line (clock skew) stays this year.
    e2 = _local("Jan  1 23:00:00 h sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2", now=jan1)
    assert e2.timestamp.year == 2027


def test_dst_change_day():
    hel = ZoneInfo("Europe/Helsinki")  # 2026-03-29 03:00 EET -> 04:00 EEST
    now = datetime(2026, 3, 30, tzinfo=UTC)
    before = _local("Mar 29 02:30:00 h sshd[1]: Failed password for a from 10.0.0.9 port 1 ssh2", zone=hel, now=now)
    after = _local("Mar 29 05:30:00 h sshd[1]: Failed password for a from 10.0.0.9 port 1 ssh2", zone=hel, now=now)
    assert before.timestamp == datetime(2026, 3, 29, 0, 30, tzinfo=UTC)   # UTC+2
    assert after.timestamp == datetime(2026, 3, 29, 2, 30, tzinfo=UTC)    # UTC+3


def test_feb_29_goes_back_to_the_last_leap_year():
    e = _local("Feb 29 10:00:00 h sshd[1]: Failed password for a from 10.0.0.9 port 1 ssh2",
               now=datetime(2026, 10, 9, tzinfo=UTC))
    assert e.timestamp == datetime(2024, 2, 29, 10, 0, tzinfo=UTC)


def test_iso_prefixed_line_keeps_its_own_offset():
    e = _local("2026-02-01T18:56:57.976846+02:00 OPTIMUS sudo: pam_unix(sudo:session): session closed for user root")
    assert e.timestamp == datetime(2026, 2, 1, 16, 56, 57, 976846, tzinfo=UTC) and not e.time_zone_assumed


def test_unparsed_line_is_stamped_when_received():
    e = _local("garbage with no time at all")
    assert e.action == "unparsed_auth_line" and e.timestamp == NOW and e.message == "garbage with no time at all"


# ---------------------------------------------------------------------------
# Journal entries and privileged-account changes
# ---------------------------------------------------------------------------
def test_journal_entry_with_a_unit():
    e = C.from_journal_entry({"timestamp": "2026-10-09T13:00:00+00:00", "unit": "cron.service",
                              "message": "(root) CMD (run-parts)", "priority": "6"},
                             ctx=_ctx(read=C.READ_JOURNAL_FETCH, transport="agent", coverage="truncated",
                                      window=(1790000000.0, None)))
    assert e.dataset == "kratos.journal" and e.service_name == "cron.service" and e.provider is None
    assert e.log_syslog_priority == 6 and e.transport == "agent" and e.coverage == "truncated"
    assert e.window == (1790000000.0, None) and e.type == ("info",)


def test_journal_entry_with_an_identifier_and_odd_values():
    e = C.from_journal_entry({"timestamp": None, "unit": "kernel", "message": [104, 105], "priority": "x"},
                             ctx=_ctx(read=C.READ_JOURNAL_FETCH))
    assert e.provider == "kernel" and e.process_name == "kernel" and e.service_name is None
    assert e.message == "hi" and e.log_syslog_priority is None and e.timestamp == NOW


def test_privileged_event():
    ev = privileged_accounts.parse_event(
        "1790538495.5 kratos-target usermod[4242]: add 'bob' to group 'sudo'")
    e = C.from_privileged_event(ev, ctx=_ctx(read=C.READ_PRIVILEGED))
    assert (e.category, e.type, e.action) == (("iam",), ("group", "change"), "added_to_group")
    assert e.user_target_name == "bob" and e.group_name == "sudo" and e.provider == "usermod"
    assert e.timestamp == datetime.fromtimestamp(1790538495.5, UTC)


def test_same_line_twice_same_id_different_line_different_id():
    a = _journal_auth("sshd", "Invalid user x from 10.0.0.9 port 1")
    b = _journal_auth("sshd", "Invalid user x from 10.0.0.9 port 1")
    c = _journal_auth("sshd", "Invalid user y from 10.0.0.9 port 1")
    d = _journal_auth("sshd", "Invalid user x from 10.0.0.9 port 1", ts="2026-10-09T13:01:02.123457+00:00")
    assert a.event_id == b.event_id and len({a.event_id, c.event_id, d.event_id}) == 3
    assert re.fullmatch(r"[0-9a-f]{32}", a.event_id)


def test_run_id_comes_from_the_run_context():
    from kratos.run_context import run_scope

    with run_scope("cli") as run:
        e = _journal_auth("sshd", "Invalid user x from 10.0.0.9 port 1")
    assert e.run_id == run.run_id
    assert _journal_auth("sshd", "Invalid user x from 10.0.0.9 port 1").run_id is None


def test_whole_fixture_corpus_converts():
    """Every line of the real lab corpus converts to a valid event."""
    events = []
    for line in (FIXTURES / "auth_corpus.short_unix.txt").read_text().splitlines():
        m = re.match(r"^(\S+) \S+ ([\w.-]+)(?:\[\d+\])?:\s*(.*)$", line)
        if not m:
            continue
        ts = datetime.fromtimestamp(float(m[1]), UTC).isoformat()
        events.append(_journal_auth(m[2], m[3], ts=ts))
    assert len(events) > 50
    assert all(isinstance(e, Event) for e in events)
    assert {"ssh_failed_login", "sudo_session_open"} <= {e.action for e in events}


def test_feb_29_line_no_longer_breaks_the_auth_log_parse():
    # Pre-existing bug: strptime raised for Feb 29 in a non-leap year, failing
    # iter_auth_events (and with it parse_auth_log) for the whole file.
    events = iter_auth_events([
        "Feb 29 10:00:00 h sshd[1]: Failed password for a from 10.0.0.9 port 1 ssh2",
        "Mar  1 10:00:00 h sshd[1]: Failed password for a from 10.0.0.9 port 1 ssh2",
    ])
    assert [e.event_type for e in events] == ["ssh_failed_login", "ssh_failed_login"]
    assert auth_log_parse._parse_syslog_timestamp("Feb", "29", "10:00:00", year=2026) == "2024-02-29T10:00:00"
    assert auth_log_parse._parse_syslog_timestamp("Mar", "1", "10:00:00", year=2026) == "2026-03-01T10:00:00"
