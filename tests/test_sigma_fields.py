"""The Sigma -> Kratos table (events/sigma_fields.py) is current for the log sources
Kratos feeds (0.3's parsers) and checked against their REAL output: every mapped
field is one the parsers fill, and every log source's condition selects the events
it should. Rules under tests/fixtures/sigma/ are SigmaHQ's, DRL 1.1 (see the LICENSE
there)."""
from __future__ import annotations

from pathlib import Path

import pytest

from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.detect.flat import flat
from kratos.events import converters as C
from kratos.events import fields as F
from kratos.events import sigma_fields as SF
from kratos.logsources import catalog
from kratos.subagent import detect as D
from kratos.logsources import logread
from tests._logsources_util import awks, bindir, make_root, run_sh
from tests.test_logsources_parsers import _events

RULES = sorted((Path(__file__).parent / "fixtures" / "sigma").glob("*.yml"))
KNOWN_DATASETS = {s.dataset for s in catalog.SOURCES.values()} | {
    "kratos.auth", "kratos.journal", "kratos.privileged_accounts"}
needs_awk = pytest.mark.skipif(not awks(), reason="no awk")
SINCE, NOW = 1790000000.0, 1793000000.0     # 2026-09-21 .. 2026-10-26: covers every fixture used here


def _read_files(tmp_path, source, family, files):
    root = make_root(tmp_path, family, files)
    script = logread.build_script(source, SINCE, NOW, journal_prefix="", root=str(root))
    r = run_sh(script, bindir(tmp_path, awks()[0]), now=NOW)
    assert r.returncode == 0, r.stderr
    return logread.parse_output(source, r.stdout, SINCE, NOW)


def test_mapped_targets_are_fields_events_carry_and_rules_may_name():
    for ls in SF.LOGSOURCES.values():
        for sigma, target in ls.fields.items():
            assert target in F.BY_NAME, f"{ls.key}: {sigma} -> {target}, which events don't have"
            assert target in D.FIELDS, f"{ls.key}: {sigma} -> {target}, which the evaluator won't accept"
        for kw in SF.KEYWORD_FIELDS:
            assert kw in F.BY_NAME and kw in D.FIELDS
        assert set(ls.datasets) <= KNOWN_DATASETS and set(ls.datasets) <= D.DATASETS, ls.key
        assert ls.label and ls.needs


def test_the_evaluator_field_list_is_a_subset_of_the_event_table():
    assert D.FIELDS <= set(F.BY_NAME)
    assert D.ORDERED_FIELDS == {f.name for f in F.FIELDS if f.ordered}
    assert D.DATASETS <= KNOWN_DATASETS
    assert D.GROUPABLE <= D.FIELDS


def test_log_source_conditions_are_valid_evaluator_nodes():
    for ls in SF.LOGSOURCES.values():
        if ls.where is not None:
            D._validate_node(ls.where, str(ls.key), 1, D._Counter())


def test_auditd_arguments_map_to_argv_positions_only_on_the_audit_log():
    auditd = SF.LOGSOURCES[("linux", "auditd", None)]
    assert SF.map_field(auditd, "a0") == ("process.args", 0)
    assert SF.map_field(auditd, "a7") == ("process.args", 7)
    assert SF.map_field(auditd, "a64") is None and SF.map_field(auditd, "arch") is None
    proc = SF.LOGSOURCES[("linux", None, "process_creation")]
    assert SF.map_field(proc, "a0") is None
    assert SF.map_field(proc, "Image") == ("process.executable", None)


def test_unsupported_and_unmapped_reasons_are_stated():
    assert not set(SF.UNSUPPORTED) & set(SF.LOGSOURCES)
    for reasons in (SF.UNSUPPORTED.values(), SF.UNMAPPED.values()):
        assert all(r.strip() for r in reasons)
    for ls in SF.LOGSOURCES.values():
        assert not set(ls.fields) & set(SF.UNMAPPED), ls.key


# ---------------------------------------------------------------------------- against the real parsers
def _applies(key, event) -> bool:
    ls = SF.LOGSOURCES[key]
    ev = flat(event)
    return ev.get("event.dataset") in ls.datasets and (ls.where is None or D._Node(ls.where).test(ev))


@needs_awk
def test_audit_log_events_carry_every_mapped_auditd_field(tmp_path):
    evs = _events(_read_files(tmp_path, "auditd", "debian", {"/var/log/audit/audit.log": "@audit_c1.log.sample"}))
    evs += _events(_read_files(tmp_path / "b", "auditd", "debian",
                               {"/var/log/audit/audit.log": "@audit.log.sample"}))
    auditd = SF.LOGSOURCES[("linux", "auditd", None)]
    flats = [flat(e) for e in evs]
    for sigma, target in auditd.fields.items():
        assert any(target in f for f in flats), f"no real audit event fills {target} (Sigma {sigma})"
    assert all(_applies(("linux", "auditd", None), e) for e in evs)
    chattr = next(e for e in evs if e.process_executable == "/usr/bin/chattr")
    assert chattr.process_args == ("chattr", "-i", "/etc/hostname")
    assert chattr.audit_syscall == "execve" and chattr.audit_key == "kratos_exec"
    assert {"SYSCALL", "EXECVE", "PATH"} <= set(chattr.audit_types) and chattr.user_effective_id == "0"


@needs_awk
def test_process_starts_are_auditd_execs_and_sudo_commands(tmp_path):
    audit = _events(_read_files(tmp_path, "auditd", "debian", {"/var/log/audit/audit.log": "@audit_c1.log.sample"}))
    sudo = _events(_read_files(tmp_path / "s", "sudo", "debian", {"/var/log/sudo.log": "@sudo.log"}))
    key = ("linux", None, "process_creation")
    execs = [e for e in audit if _applies(key, e)]
    assert execs and all(e.action == "process_started" for e in execs)
    assert any(e.process_executable == "/usr/bin/whoami" for e in execs)
    cmds = [e for e in sudo if _applies(key, e)]
    assert cmds and all(e.action == "sudo_command" and e.process_command_line for e in cmds)
    # a config change or a file write is not a program start
    assert not any(_applies(key, e) for e in audit if e.action != "process_started")


@needs_awk
def test_file_creation_is_audit_paths_recorded_as_created(tmp_path):
    evs = _events(_read_files(tmp_path, "auditd", "debian", {"/var/log/audit/audit.log": "@audit_c1.log.sample"}))
    key = ("linux", None, "file_event")
    created = [e for e in evs if _applies(key, e)]
    names = {p for e in created for p in e.audit_created_paths}
    assert {"/etc/cron.d/kratos_c1_fixture", "/etc/profile.d/kratos_c1.sh"} <= names
    # the rm of the same files is a PATH record with nametype=DELETE, not a creation
    assert all(e.process_executable != "/usr/bin/rm" for e in created)


def _auth(prog: str, msg: str):
    ev = classify_auth_message("2026-10-21T09:00:00+00:00", "203.0.113.5", prog, msg, msg)
    ctx = C.ReadContext(target="203.0.113.5", transport="ssh", read="journal_auth")
    return C.from_auth_event(ev, ctx=ctx)


def test_sshd_and_sudo_sources_select_their_programs():
    sshd = _auth("sshd", "Failed password for invalid user alice from 192.0.2.10 port 4242 ssh2")
    sudo = _auth("sudo", "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id")
    assert _applies(("linux", "sshd", None), sshd) and not _applies(("linux", "sshd", None), sudo)
    assert _applies(("linux", "sudo", None), sudo) and not _applies(("linux", "sudo", None), sshd)
    for key in (("linux", None, None), ("linux", "auth", None), ("linux", "syslog", None)):
        assert _applies(key, sshd) and _applies(key, sudo)


# ---------------------------------------------------------------------------- vendored SigmaHQ rules
sigma_collection = pytest.importorskip("sigma.collection")
from sigma.rule import SigmaDetection  # noqa: E402


def _items(det):
    for d in det.detection_items:
        if isinstance(d, SigmaDetection):
            yield from _items(d)
        else:
            yield d


def _rules():
    for path in RULES:
        for rule in sigma_collection.SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules:
            yield path.name, rule


def test_enough_real_rules_vendored_with_attribution():
    assert len(RULES) >= 10
    assert (RULES[0].parent / "LICENSE").read_text().startswith("# Detection Rule License (DRL) 1.1")
    for path in RULES:
        head = path.read_text(encoding="utf-8")
        assert head.startswith("# From SigmaHQ (https://github.com/SigmaHQ/sigma), rules/linux/")
        assert "\nid: " in head and "\nauthor: " in head


def test_every_vendored_rule_is_fed_or_explained_field_by_field():
    seen: set[str] = set()
    for name, rule in _rules():
        ls_key = (rule.logsource.product, rule.logsource.service, rule.logsource.category)
        assert ls_key in SF.LOGSOURCES or ls_key in SF.UNSUPPORTED, f"{name}: logsource {ls_key} unaccounted for"
        ls = SF.LOGSOURCES.get(ls_key)
        for det in rule.detection.detections.values():
            for it in _items(det):
                field = it.field or SF.KEYWORDS
                seen.add(field)
                ok = field == SF.KEYWORDS or field in SF.UNMAPPED or (ls is not None and SF.map_field(ls, field))
                assert ok, f"{name}: Sigma field {field!r} unaccounted for"
    assert {"keywords", "Image", "CommandLine"} <= seen and {"ParentImage", "CurrentDirectory"} <= seen
