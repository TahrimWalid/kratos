"""0.3 parsers -> events: each source's real fixture lines, run through the real
extractor and parser, become the right events (fields, masking, IDs), malformed
lines are skipped, and every action a parser can emit has an ECS mapping."""
from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.events import converters as C
from kratos.events.model import Event
from kratos.logsources import catalog, logread
from kratos.logsources.logread import LogRead, Record
from kratos.logsources.parsers import Parsed, auditd, parse_read, web
from tests._logsources_util import FIX, awks, bindir, make_root, run_sh

NOW = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc).timestamp()
SINCE = datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()
PARSERS_DIR = Path(__file__).parents[1] / "src" / "kratos" / "logsources" / "parsers"


def _read_files(tmp_path, source, family, files) -> LogRead:
    root = make_root(tmp_path, family, files)
    script = logread.build_script(source, SINCE, NOW, journal_prefix="", root=str(root))
    r = run_sh(script, bindir(tmp_path, awks()[0]), now=NOW)
    assert r.returncode == 0, r.stderr
    return logread.parse_output(source, r.stdout, SINCE, NOW)


def _journal_read(source, fixture) -> LogRead:
    recs = []
    for line in (FIX / fixture).read_text().splitlines():
        e = json.loads(line)
        recs.append(Record(kind="journal", ts=int(e["__REALTIME_TIMESTAMP"]) / 1e6, entry=e, match="x"))
    recs.sort(key=lambda r: r.ts, reverse=True)
    return LogRead(source=source, records=recs, since=SINCE, until=NOW)


def _events(read: LogRead, target="10.136.28.102") -> list[Event]:
    ctx = C.ReadContext(target=target, transport="ssh", read=f"log_read.{read.source}", window=(SINCE, NOW),
                        coverage="complete")
    items = parse_read(read, target)
    if read.source == "sudo":
        return [C.from_auth_event(i, ctx=ctx) for i in items]
    return [C.from_parsed(p, ctx=ctx, dataset=catalog.SOURCES[read.source].dataset) for p in items]


needs_awk = pytest.mark.skipif(not awks(), reason="no awk")


@needs_awk
def test_auditd_groups_records_into_events_and_decodes_hex(tmp_path):
    read = _read_files(tmp_path, "auditd", "debian", {"/var/log/audit/audit.log": "@audit_session.log.sample"})
    evs = _events(read)
    curl = next(e for e in evs if e.process_executable == "/usr/bin/curl")
    assert curl.action == "process_started" and curl.outcome == "success"
    assert curl.category == ("process",) and curl.type == ("start",)
    assert curl.user_id == "1000" and curl.user_name == "ubuntu"
    assert curl.process_working_directory == "/home/ubuntu"
    assert curl.process_command_line.startswith("curl -s -o /dev/null http://127.0.0.1/?token=")
    assert "abc123secret" not in json.dumps(curl.to_ecs()) and curl.redacted
    assert curl.sequence == 278 and curl.dataset == "kratos.auditd"
    grp = next(e for e in evs if e.action == "group_added")
    assert grp.group_name == "kratostest03" and grp.category == ("iam",)
    hexed = next(e for e in evs if e.process_executable == "/usr/lib/systemd/systemd-user-runtime-dir")
    assert hexed.process_command_line == "/lib/systemd/systemd-user-runtime-dir start 1000"
    assert len({e.event_id for e in evs}) == len(evs)


def test_auditd_config_change_daemon_and_split_hex_args():
    lines = [
        'type=CONFIG_CHANGE msg=audit(1791738800.000:10): auid=1000 ses=3 op=remove_rule key="k" list=4 res=1',
        'type=CONFIG_CHANGE msg=audit(1791738801.000:11): op=set audit_enabled=0 old=1 auid=1000 ses=3 res=1',
        'type=DAEMON_END msg=audit(1791738802.000:12): op=terminate auid=0 uid=0 ses=4294967295 pid=1 res=success',
        'type=SYSCALL msg=audit(1791738803.000:13): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=5 '
        'auid=1000 uid=0 comm="bash" exe="/usr/bin/bash"',
        'type=EXECVE msg=audit(1791738803.000:13): argc=2 a0="bash" a1_len=10 a1[0]=2D63206563 a1[1]=686F206869',
        'type=PROCTITLE msg=audit(1791738803.000:13): proctitle=62617368002D63',
        'garbage that is not an audit line',
        'type=SYSCALL msg=audit(notanumber:1): x=1',
    ]
    recs = [Record(kind="file", ts=0, text=t, path="/var/log/audit/audit.log") for t in reversed(lines)]
    evs = _events(LogRead(source="auditd", records=recs))
    by_action = {e.action: e for e in evs}
    assert set(by_action) == {"audit_rule_removed", "audit_disabled", "auditd_stopped", "process_started"}
    assert by_action["process_started"].process_command_line == "bash -c echo hi"
    assert by_action["auditd_stopped"].category == ("configuration",)


@needs_awk
def test_cron_from_debian_journal_rhel_file_and_busybox(tmp_path):
    deb = _events(_journal_read("cron", "journal_cron.jsonl"), target="10.136.28.168")
    cmd = next(e for e in deb if e.action == "cron_command")
    assert cmd.user_name == "root" and cmd.process_command_line == "/bin/true # kratos-0.3-test"
    assert {e.action for e in deb} >= {"cron_session_opened", "cron_session_closed"}
    # journal events are keyed by the entry's own cursor
    from kratos.events.model import cursor_event_id

    entry = json.loads((FIX / "journal_cron.jsonl").read_text().splitlines()[0])
    assert cursor_event_id("10.136.28.168", entry["__CURSOR"]) in {e.event_id for e in deb}
    rhel = _events(_read_files(tmp_path, "cron", "rhel", {"/var/log/cron": "@rhel_cron.log"}))
    assert {e.action for e in rhel} >= {"cron_command", "cron_command_ended"}
    assert all(e.user_name == "root" for e in rhel if e.action == "cron_command")
    alp = _events(_read_files(tmp_path / "a", "cron", "alpine", {"/var/log/messages": "@alpine_messages.log"}))
    job = next(e for e in alp if e.action == "cron_command")
    assert job.process_command_line.startswith("run-parts /etc/periodic/") and job.process_pid


def test_systemd_unit_activity():
    evs = _events(_journal_read("systemd", "journal_systemd.jsonl"), target="10.136.28.168")
    started = [e for e in evs if e.action == "unit_started"]
    assert started and all(e.service_name for e in started)
    cron = [e for e in evs if e.service_name == "cron.service"]
    assert {e.action for e in cron} >= {"unit_started", "unit_stopped"}


@needs_awk
def test_firewall_lines_from_journal_and_ufw_log(tmp_path):
    jr = _events(_journal_read("firewall", "journal_kernel_ufw.jsonl"))
    assert jr and all(e.action == "blocked" for e in jr)
    e = jr[0]
    assert (e.source_ip, e.destination_ip, e.destination_port, e.network_transport) == \
           ("10.136.28.52", "10.136.28.102", 2222, "tcp")
    assert e.category == ("network",) and e.type == ("connection", "denied") and e.outcome == "failure"
    fr = _events(_read_files(tmp_path, "firewall", "alpine", {"/var/log/messages": "@ufw.log"}))
    assert len(fr) == 6 and all(x.destination_port == 2222 for x in fr)


@needs_awk
def test_packages_dpkg_apt_and_dnf(tmp_path):
    deb = _events(_read_files(tmp_path, "packages", "debian", {"/var/log/dpkg.log": "@dpkg.log",
                                                                "/var/log/apt/history.log": "@apt_history.log"}))
    sl = next(e for e in deb if e.action == "package_installed" and e.package_name == "sl")
    assert sl.package_version == "5.02-1" and sl.category == ("package",) and sl.type == ("installation",)
    tx = next(e for e in deb if e.action == "package_transaction" and e.package_name == "sl")
    assert tx.process_command_line == "apt-get install -y -q sl"
    rhel = _events(_read_files(tmp_path / "r", "packages", "rhel", {"/var/log/dnf.rpm.log": "@dnf.rpm.log",
                                                                    "/var/log/dnf.log": "@dnf.log"}))
    tree = next(e for e in rhel if e.package_name == "tree")
    assert tree.action == "package_installed" and tree.package_version == "1.8.0-10.el9"
    assert any(e.action == "package_command" and e.process_command_line == "yum -y --allowerasing makecache"
               for e in rhel)


@needs_awk
def test_web_access_and_error_logs_mask_query_credentials(tmp_path):
    files = {"/var/log/nginx/access.log": "@nginx_access.log", "/var/log/nginx/error.log": "@nginx_error.log",
             "/var/log/apache2/error.log": "[Sun Oct 11 17:30:01.123456 2026] [core:error] [pid 42] "
                                           "[client 10.136.28.52:51234] AH00126: Invalid URI in request\n"}
    evs = _events(_read_files(tmp_path, "web", "debian", files))
    login = next(e for e in evs if e.url_original and e.url_original.startswith("/login"))
    assert login.url_original == "/login?user=bob&password=[REDACTED]"
    doc = json.dumps(login.to_ecs())
    assert "hunter2" not in doc and login.redacted
    assert (login.http_request_method, login.http_response_status_code, login.outcome) == ("GET", 404, "failure")
    assert login.user_agent_original == "Mozilla/5.0 test" and login.source_ip == "10.136.28.52"
    errs = [e for e in evs if e.action == "web_error"]
    assert {e.provider for e in errs} == {"nginx", "apache"}
    assert next(e for e in errs if e.provider == "apache").source_ip == "10.136.28.52"


def test_mask_url_leaves_ordinary_queries_alone():
    assert web.mask_url("/search?q=password+reset&page=2") == ("/search?q=password+reset&page=2", False)
    assert web.mask_url("/x?api_key=abc&id=7")[0] == "/x?api_key=[REDACTED]&id=7"
    assert web.mask_url("http://u:pw@h/p")[0] == "http://u:[REDACTED]@h/p"


@needs_awk
def test_sudo_logfile_continuation_and_journal_share_the_auth_classifier(tmp_path):
    evs = _events(_read_files(tmp_path, "sudo", "debian", {"/var/log/sudo.log": "@sudo.log"}))
    assert {e.dataset for e in evs} == {"kratos.auth"}
    ls = next(e for e in evs if e.process_command_line and "/usr/bin/ls" in e.process_command_line)
    assert ls.action == "sudo_command" and ls.user_name == "ubuntu" and ls.user_effective_name == "root"
    assert ls.process_command_line == "/usr/bin/ls /root"


def test_malformed_lines_are_skipped_not_fatal():
    junk = [Record(kind="file", ts=NOW, text=t, path="/x") for t in ("", "\x00\x01", "Oct 11 nonsense", "[[[")]
    for source in ("auditd", "cron", "firewall", "packages", "web"):
        assert _events(LogRead(source=source, records=junk)) == []


def test_parsed_rejects_fields_that_are_not_event_fields():
    with pytest.raises(ValueError):
        Parsed(ts=0, action="x", fields={"not_a_field": 1})


def _emitted_actions() -> set[str]:
    """Every action string a parser module can return: `action=`/`action =`
    literals, the values of *ACTIONS/*_OPS dicts and the action slot of _RULES."""
    found: set[str] = set()
    for path in PARSERS_DIR.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "action" and isinstance(node.value, ast.Constant):
                found.add(node.value.value)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    names = [t] if isinstance(t, ast.Name) else (list(t.elts) if isinstance(t, ast.Tuple) else [])
                    for i, n in enumerate(names):
                        if not isinstance(n, ast.Name):
                            continue
                        if n.id == "action":
                            val = node.value.elts[i] if isinstance(node.value, ast.Tuple) else node.value
                            if isinstance(val, ast.Constant):
                                found.add(val.value)
                            if isinstance(val, ast.IfExp):
                                found |= {v.value for v in (val.body, val.orelse) if isinstance(v, ast.Constant)}
                        if (n.id.endswith("ACTIONS") or n.id.endswith("_OPS")) and isinstance(node.value, ast.Dict):
                            found |= {v.value for v in node.value.values if isinstance(v, ast.Constant)}
                        if n.id == "_RULES" and isinstance(node.value, ast.Tuple):
                            found |= {e.elts[1].value for e in node.value.elts if isinstance(e, ast.Tuple)}
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "get" and node.args:
                if isinstance(getattr(node.func, "value", None), ast.Name) and node.func.value.id in ("ACTIONS", "_ACTIONS"):
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        found.add(node.args[1].value)
    return {a for a in found if isinstance(a, str)}


def test_every_parser_action_has_an_ecs_mapping_and_no_mapping_is_dead():
    emitted = _emitted_actions()
    assert emitted, "the scan found no actions -- it is broken"
    assert emitted - set(C.LOG_ACTIONS) == set(), "parser actions without an ECS mapping"
    assert set(C.LOG_ACTIONS) - emitted == set(), "mappings no parser emits"
    from kratos.events import fields as F

    for cat, typ, outcome in C.LOG_ACTIONS.values():
        assert set(cat) <= set(F.CATEGORY_VALUES) and set(typ) <= set(F.TYPE_VALUES)
        assert outcome in (None, *F.OUTCOME_VALUES)


def test_every_source_has_a_parser_and_dataset():
    assert set(catalog.SOURCE_NAMES) == {"auditd", "sudo", "cron", "systemd", "firewall", "packages", "web"}
    for s in catalog.SOURCES.values():
        assert s.dataset.startswith("kratos.") and s.doc
        assert set(s.journal) | set(s.files) | set(s.gaps) == set(catalog.FAMILIES), s.name


def test_read_journalctl_keys_events_by_cursor_but_never_shows_it_to_the_model(tmp_path, monkeypatch):
    from kratos import kratos_config
    from kratos.adapters.ssh_remote import JournalWindow
    from kratos.agent import tools
    from kratos.events.model import cursor_event_id
    from kratos.events.store import EventStore

    kratos_config.set_active_target("ubuntu@10.136.28.168")
    entries = [{"timestamp": "2026-09-28T06:00:00+00:00", "unit": "cron.service", "message": "same line",
                "priority": "6", "cursor": f"s=abc;i={i}"} for i in (1, 2)]   # identical text, same time
    monkeypatch.setattr(tools, "_fetch_journalctl_auth_entries", lambda **kw: ([], [], {}))
    monkeypatch.setattr(tools, "_fetch_journalctl_entries",
                        lambda unit, since, lines, until_epoch=None: (
                            [dict(e) for e in entries],
                            JournalWindow(since, until_epoch, lines, 2, False, entries[0]["timestamp"],
                                          entries[1]["timestamp"])))
    monkeypatch.setattr(tools, "_measure_target_clock_offset", lambda: 0.0)
    result = tools.tool_read_journalctl(tmp_path, since="2026-09-28 00:00", until="2026-09-28 12:00")
    assert all("cursor" not in e for e in result["entries"])
    stored = EventStore(tmp_path / "kratos.db").query("10.136.28.168", dataset="kratos.journal")
    assert sorted(e.event_id for e in stored) == sorted(cursor_event_id("10.136.28.168", e["cursor"]) for e in entries)
