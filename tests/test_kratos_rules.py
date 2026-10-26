"""Kratos's own detection rules (Phase C audit). Continuous watching ran only the Sigma
pack, which has no counting rules and nothing for account-change lines -- on a machine
without auditd an SSH brute force or a new sudo account raised no live detection. These
tests prove: account-change lines are read and classified, the kratos-linux pack is valid
and current, its counting rules count the way people expect, and the same lines raise
the same detections on the agent's side and on Kratos's."""
from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from kratos.adapters import auth_log_parse as ALP
from kratos.detect import ids
from kratos.detect import pack as P
from kratos.events import assemble as A
from kratos.logsources import catalog
from kratos.logsources.parsers import auth as lp_auth
from kratos.subagent import detect as D
from kratos.subagent import watch as W

from tests._watch_fakes import journal_entry

ROOT = Path(__file__).resolve().parents[1]
MACHINE = "198.51.100.30"


def _classify(program: str, msg: str):
    return ALP.classify_auth_message("2026-10-26T12:00:00+00:00", MACHINE, program, msg, msg)


def _values(ev):
    return A.flat(A.auth_values(ev, host=MACHINE, line_prefix=False, time_zone=None,
                                created=datetime.now(timezone.utc)))


# ---------------------------------------------------------------------------- reading account changes
def test_account_change_lines_are_classified_with_user_group_and_uid():
    cases = [
        ("useradd", "new user: name=carol, UID=1002, GID=1002, home=/home/carol, shell=/bin/sh, from=none",
         "account_created", "carol", {"user.id": "1002"}),
        ("useradd", "add 'carol' to group 'sudo'", "account_added_to_group", "carol", {"group.name": "sudo"}),
        ("useradd", "add 'carol' to shadow group 'sudo'", "account_added_to_group", "carol", {"group.name": "sudo"}),
        ("usermod", "add 'dave' to group 'docker'", "account_added_to_group", "dave", {"group.name": "docker"}),
        ("gpasswd", "user erin added by root to group wheel", "account_added_to_group", "erin", {"group.name": "wheel"}),
        ("usermod", "change user 'frank' UID from '1003' to '0'", "account_changed", "frank", {"user.id": "0"}),
        ("userdel", "delete user 'carol'", "account_deleted", "carol", {}),
        ("passwd", "pam_unix(passwd:chauthtok): password changed for carol", "account_password_changed", "carol", {}),
        ("groupadd", "new group: name=ops, GID=1005", "account_group_created", None, {"group.name": "ops"}),
    ]
    for program, msg, etype, user, fields in cases:
        ev = _classify(program, msg)
        assert ev.event_type == etype and ev.user == user, (program, msg, ev)
        flat = _values(ev)
        assert flat["event.action"] == etype and flat["event.category"] == ["iam"]
        for k, v in fields.items():
            assert flat.get(k) == v, (msg, k, flat.get(k))


def test_ssh_and_sudo_classification_is_unchanged():
    assert _classify("sshd", "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2").event_type \
        == "ssh_failed_login"
    assert _classify("sudo", "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls").event_type == "sudo_command"
    assert _classify("cron", "anything").event_type == "auth_other"


def test_the_auth_journal_match_follows_account_tools_by_process_name():
    """journalctl ORs matches on the same field and ANDs different fields: every match in
    the auth set must be _COMM=, or account lines (and sshd/sudo) would match nothing."""
    match = catalog.JOURNAL_MATCHES["auth"]
    assert all(m.startswith("_COMM=") for m in match)
    comms = {m.split("=", 1)[1] for m in match}
    assert ALP.ACCOUNT_PROGRAMS <= comms and {"sshd", "sshd-session", "sudo"} <= comms
    assert all(len(c) <= 15 for c in comms)                 # _COMM is the kernel's 15-character name
    assert W._AUTH_COMMS == comms and ALP.ACCOUNT_PROGRAMS <= lp_auth.AUTH_PROGRAMS


# ---------------------------------------------------------------------------- the pack
def test_the_kratos_pack_is_shipped_valid_current_and_passes_its_samples():
    own = P.kratos_pack()
    assert own is not None and own.pack_id == "kratos-linux"
    assert D.check_samples(own.pack) == []
    assert [lp.pack_id for lp in P.load(None).loaded][:2] == ["sigma-linux", "kratos-linux"]
    r = subprocess.run([sys.executable, str(ROOT / "scripts/dev/build_kratos_pack.py"), "--check"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


def test_every_kratos_rule_is_a_detection_rule_with_a_lifecycle_class_and_labels():
    from kratos.attack import mapping
    from kratos.lifecycle.rules import rule_info

    for rule in P.kratos_pack().pack.rules:
        assert ids.is_detection_rule(rule.id) and not ids.is_sigma(rule.id)
        assert rule_info(rule.id).kind == "occurrence"
        assert mapping.labels(rule.id), rule.id
        assert rule.meta["author"] == "Kratos" and rule.meta["license"] == "MIT"


def test_a_kratos_finding_names_no_sigma_licence():
    from kratos.detect.findings import credit_line

    assert credit_line({"detection_rule": {"author": "Kratos", "license": "MIT", "matches": 2}}) is None
    assert "DRL" in credit_line({"detection_rule": {"author": "Someone", "license": "DRL-1.1"}})


# ---------------------------------------------------------------------------- counting rules
def _failed(i: int, ip: str, ts: float) -> dict:
    return {"event.id": f"e{i}", "event.dataset": "kratos.auth", "event.action": "ssh_failed_login",
            "source.ip": ip, "user.name": "admin"}


def test_ten_failed_logins_from_one_address_in_five_minutes_is_one_brute_force():
    ev = D.Evaluator(P.kratos_pack().pack)
    t0 = 1_800_000_000.0
    hits = []
    for i in range(12):
        hits += [m for m in ev.evaluate(_failed(i, "203.0.113.9", t0 + i), t0 + i) if m.rule_id == "KRATOS-SSH-BRUTEFORCE"]
    assert len(hits) >= 1 and hits[0].group == "203.0.113.9"
    # nine from one address, or ten spread over ten addresses: nothing
    ev2 = D.Evaluator(P.kratos_pack().pack)
    quiet = [m for i in range(9) for m in ev2.evaluate(_failed(i, "203.0.113.10", t0 + i), t0 + i)]
    quiet += [m for i in range(10) for m in ev2.evaluate(_failed(100 + i, f"203.0.113.{20 + i}", t0 + i), t0 + i)]
    assert not [m for m in quiet if m.rule_id == "KRATOS-SSH-BRUTEFORCE"]


# ---------------------------------------------------------------------------- end to end, the agent's own code
def test_real_account_lines_raise_the_privileged_group_and_new_account_rules():
    """The lines a new sudo account writes (as seen on the lab target), through the
    watcher's journal handling and both shipped packs."""
    now = time.time()
    lines = [("useradd", "new user: name=auditc2, UID=1002, GID=1002, home=/home/auditc2, shell=/bin/sh, from=none"),
             ("useradd", "add 'auditc2' to group 'sudo'"), ("useradd", "add 'auditc2' to shadow group 'sudo'")]
    evaluators = [D.Evaluator(lp.pack) for lp in P.load(None).loaded]     # one per pack, as the agent runs them
    found: set[str] = set()
    for i, (comm, msg) in enumerate(lines):
        entry = journal_entry(i + 1, now, msg, comm=comm)
        values = W.journal_values(entry, MACHINE)
        assert values is not None, msg
        flat = A.flat(values)
        for evaluator in evaluators:
            found |= {m.rule_id for m in evaluator.evaluate(flat, values["timestamp"].timestamp())}
    assert {"KRATOS-ACCOUNT-CREATED", "KRATOS-ACCOUNT-PRIVILEGED-GROUP"} <= found


# ---------------------------------------------------------------------------- the finding names the group
def test_a_privileged_group_finding_names_the_account_and_the_group(tmp_path):
    """The group is what makes it serious: the finding names it (scheduled pass; the live
    path copies the same field -- watch._IDENTITY_FIELDS and live.matched_event)."""
    from kratos.detect import run as R
    from kratos.detect.findings import summarize
    from kratos.events import converters as C
    from kratos.events.store import EventStore

    now = time.time()
    iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 60))
    ctx = C.ReadContext(target=MACHINE, transport="ssh", read="test", coverage="complete")
    msg = "add 'carol' to group 'sudo'"
    EventStore(tmp_path / "kratos.db").add([C.from_auth_event(ALP.classify_auth_message(iso, MACHINE, "useradd", msg, msg),
                                                              ctx=ctx)])
    rep = R.run_pass(MACHINE, tmp_path, now=now)
    assert [m["rule_id"] for m in rep.matches] == ["KRATOS-ACCOUNT-PRIVILEGED-GROUP"]
    [g] = summarize(tmp_path, MACHINE, now=now, loaded=P.load(tmp_path))
    assert g["subject"] == "carol" and {"carol", "sudo"} <= set(g["entities"])
    assert "group.name" in W._IDENTITY_FIELDS


def test_findings_show_and_list_present_a_kratos_rule_cleanly(tmp_path, monkeypatch, capsys):
    """`findings show` says "Kratos's own rule" (no author/licence/blank URL) and names the
    group; `findings list` keeps its columns lined up for the long KRATOS-... ids."""
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.cli import app
    from kratos.detect import run as R
    from kratos.events import converters as C
    from kratos.events.store import EventStore
    from kratos.lifecycle import query as Q
    from kratos.run_context import run_scope

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: MACHINE)
    now = time.time()
    ctx = C.ReadContext(target=MACHINE, transport="ssh", read="test", coverage="complete")
    events = []
    for i, (prog, msg) in enumerate([("useradd", "new user: name=carol, UID=1002, GID=1002, home=/home/carol, "
                                                 "shell=/bin/sh, from=none"),
                                     ("useradd", "add 'carol' to group 'sudo'")]):
        iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 60 + i))
        events.append(C.from_auth_event(ALP.classify_auth_message(iso, MACHINE, prog, msg, msg), ctx=ctx))
    EventStore(tmp_path / "kratos.db").add(events)
    with run_scope("cli", target=MACHINE):
        R.run_pass(MACHINE, tmp_path)
        FE.write_findings_report(data_dir=tmp_path)
    rows = {r["rule_id"]: r for r in Q.list_findings(tmp_path, target=MACHINE, state="all")}
    assert {"KRATOS-ACCOUNT-CREATED", "KRATOS-ACCOUNT-PRIVILEGED-GROUP"} <= set(rows)
    capsys.readouterr()
    assert app.main(["--data-dir", str(tmp_path), "findings", "show",
                     rows["KRATOS-ACCOUNT-PRIVILEGED-GROUP"]["finding_key"]]) == 0
    out = capsys.readouterr().out
    assert "rule: Account added to a privileged group (Kratos's own rule)" in out
    assert " by Kratos -- " not in out and "sudo" in out
    assert app.main(["--data-dir", str(tmp_path), "findings", "list", "--target", MACHINE]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if MACHINE in ln]
    assert len({ln.index(MACHINE) for ln in lines}) == 1, lines        # one column, whatever the id length


# ---------------------------------------------------------------------------- Kratos's own root logins
FP = "SHA256:" + "A" * 43                      # a made-up key fingerprint (Kratos's, in these tests)
OTHER_FP = "SHA256:" + "B" * 43


def _root_login(fp: str) -> str:
    return f"Accepted publickey for root from 198.51.100.7 port 50022 ssh2: ED25519 {fp}"


def test_a_root_login_fires_unless_it_is_kratos_logging_in_with_its_own_key(tmp_path, monkeypatch):
    """Kratos's SSH user may be root (discouraged, supported): its own logins must not
    raise "Root logged in over SSH" on every collection -- on schedule or live."""
    from kratos.detect import own as own_mod
    from kratos.detect import run as R
    from kratos.events import converters as C
    from kratos.events.store import EventStore

    monkeypatch.setattr(own_mod, "kratos_fingerprint", lambda: FP)
    now = time.time()
    ctx = C.ReadContext(target=MACHINE, transport="ssh", read="test", coverage="complete")
    evs = []
    for i, fp in enumerate((FP, OTHER_FP)):
        iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 60 + i))
        msg = _root_login(fp)
        evs.append(C.from_auth_event(ALP.classify_auth_message(iso, MACHINE, "sshd", msg, msg), ctx=ctx))
    EventStore(tmp_path / "kratos.db").add(evs)
    rep = R.run_pass(MACHINE, tmp_path, now=now)
    root = [m for m in rep.matches if m["rule_id"] == "KRATOS-SSH-ROOT-LOGIN"]
    assert len(root) == 1 and root[0]["event_id"] == evs[1].event_id     # someone else's key fires
    assert rep.own_events == 1                                            # Kratos's own login, set aside once

