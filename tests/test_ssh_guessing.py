"""SSH brute force rated by whether guessing can succeed (owner decision 2026-11-01), SSH
reachability from the machine's own evidence, and CORR-SSH-002: a successful login from an
address that had been guessing passwords."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.adapters import findings_engine as FE
from kratos.adapters import ssh_guessing as G
from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.events import converters as C
from kratos.events.store import EventStore
from kratos.sshguess import detect as D
from kratos.sshguess import findings as SF
from kratos.sshguess import record as SR
from kratos.subagent import reads

HOST = "10.0.0.5"


def _audit(**status):
    return {"checks": [{"check": k, "status": v, "detail": f"{k} detail"} for k, v in status.items()]}


CLOSED = _audit(ssh_password_auth="PASS", ssh_kbd_interactive="PASS", ssh_match_password="PASS")


# ---------------------------------------------------------------- can guessing succeed?
def test_key_only_is_closed_and_low():
    a = G.assess(CLOSED)
    assert a.state == "closed" and a.severity == "low" and "can't succeed" in a.reasons[0]


@pytest.mark.parametrize("row", ["ssh_password_auth", "ssh_kbd_interactive", "ssh_match_password", "ssh_auth_methods"])
def test_any_open_path_is_open_and_high(row):
    checks = {**{c["check"]: c["status"] for c in CLOSED["checks"]}, row: "WARN"}
    a = G.assess(_audit(**checks))
    assert a.state == "open" and a.severity == "high" and a.reasons


def test_auth_methods_requiring_a_key_closes_it_even_with_passwords_listed():
    a = G.assess(_audit(ssh_password_auth="UNKNOWN", ssh_auth_methods="PASS", ssh_match_password="PASS"))
    assert a.state == "closed" and "needs a key" in a.reasons[0]


def test_unreadable_or_missing_settings_are_unknown_and_medium_with_the_reason():
    a = G.assess(_audit(ssh_password_auth="PASS", ssh_kbd_interactive="PASS", ssh_match_password="UNKNOWN"))
    assert a.state == "unknown" and a.severity == "medium" and "Match blocks" in a.gaps[0]
    assert G.assess(None).state == "unknown"


def test_an_older_agent_without_the_new_rows_says_update_it():
    a = G.assess({"via": "agent", "checks": [{"check": "ssh_password_auth", "status": "PASS", "detail": ""}]})
    assert a.state == "unknown" and any("update it with `g`" in g for g in a.gaps)


def test_snapshot_round_trip_and_freshness(tmp_path):
    path = G.save_snapshot(tmp_path, HOST, CLOSED["checks"], via="ssh", now=time.time())
    assert G.assess(G.load_recent(path)).state == "closed"
    old = G.save_snapshot(tmp_path, HOST, CLOSED["checks"], now=time.time() - 25 * 3600)
    assert G.load_recent(old) is None
    assert FE.find_latest_inputs(tmp_path, HOST)["config_audit"] is not None


# ---------------------------------------------------------------- reachability
def test_reachability_from_the_machine_itself():
    assert G.exposure(["203.0.113.9"]).scope == "internet"
    assert G.exposure(["10.1.2.3"]).scope == "network"
    assert not G.exposure(["127.0.0.1"]).exposed
    listening = [{"port": 22, "proto": "tcp", "seen": True, "exe": "/usr/sbin/sshd", "address": "0.0.0.0"}]
    loop = [{"port": 22, "proto": "tcp", "seen": True, "exe": "/usr/sbin/sshd", "address": "127.0.0.1"}]
    assert G.exposure([], listeners=listening).exposed and not G.exposure([], listeners=loop).exposed


# ---------------------------------------------------------------- the finding
_BURST = {"event_type": "ssh_failed_login", "count": 40, "start": "2026-10-04T08:55:24+00:00",
          "end": "2026-10-04T08:59:25+00:00",
          "top_source_ips": [{"ip": "203.0.113.52", "count": 20}, {"ip": "198.51.100.7", "count": 20}]}


def _corr(config_audit, nmap=None):
    out = FE.generate_findings(nmap, None, {"bursts": [_BURST]}, None, config_audit=config_audit)
    return next((f for f in out if f.id == "CORR-SSH-001"), None)


def test_a_sub_agent_machine_without_a_scan_still_gets_the_finding():
    """devserver3's case: 1,115 failures from 68 addresses read as info, because only an nmap
    scan (impossible over the sub-agent) could say SSH was exposed."""
    f = _corr(CLOSED, nmap=None)
    assert f is not None and f.severity == "low"
    assert any("reachable from the internet" in e for e in f.evidence)
    assert "can't succeed" in f.title


def test_severity_follows_the_judgement():
    assert _corr(_audit(ssh_password_auth="WARN")).severity == "high"
    assert _corr(None).severity == "medium"
    f = _corr(None)
    assert any(e.startswith("Not known:") for e in f.evidence)


# ---------------------------------------------------------------- CORR-SSH-002
def _t(minutes: float) -> float:
    return datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc).timestamp() + minutes * 60


def test_guessing_then_a_password_login_is_critical():
    fails = {"203.0.113.9": [D.Failure(_t(-10 + i), "203.0.113.9", "admin", "Failed password for admin from x")
                             for i in range(4)]}
    hits = D.judge([D.Login(_t(0), "203.0.113.9", "admin", "Accepted password for admin from x")], fails)
    assert len(hits) == 1 and hits[0].severity == "critical" and hits[0].failures == 4


def test_a_key_login_after_guessing_is_high():
    fails = {"203.0.113.9": [D.Failure(_t(-5), "203.0.113.9", "x", "Invalid user x from 203.0.113.9")] * 3}
    hits = D.judge([D.Login(_t(0), "203.0.113.9", "bob", "Accepted publickey for bob from x")], fails)
    assert hits[0].severity == "high"


def test_trying_several_keys_is_not_guessing():
    """An admin's client offers each of its keys: Failed publickey lines, then success."""
    fails = {"198.51.100.7": [D.Failure(_t(-1), "198.51.100.7", "bob", "Failed publickey for bob from x")] * 5}
    assert D.judge([D.Login(_t(0), "198.51.100.7", "bob", "Accepted publickey for bob from x")], fails) == []


def test_old_failures_and_too_few_failures_dont_count():
    old = {"203.0.113.9": [D.Failure(_t(-25 * 60), "203.0.113.9", "a", "Failed password for a")] * 5}
    few = {"203.0.113.9": [D.Failure(_t(-1), "203.0.113.9", "a", "Failed password for a")] * 2}
    login = [D.Login(_t(0), "203.0.113.9", "a", "Accepted password for a")]
    assert D.judge(login, old) == [] and D.judge(login, few) == []


def _store(tmp_path: Path, lines: list[tuple[float, str]]):
    ctx = C.ReadContext(target=HOST, transport="ssh", read="log_sync")
    events = []
    for ts, msg in lines:
        iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
        ev = classify_auth_message(iso, HOST, "sshd", msg, msg)
        events.append(C.from_auth_event(ev, ctx=ctx))
    EventStore(tmp_path / "kratos.db").add(events)


def test_end_to_end_from_stored_events_with_kratos_own_login_set_aside(tmp_path):
    now = time.time()
    lines = [(now - 600 + i, f"Failed password for alice from 203.0.113.9 port {4000 + i} ssh2") for i in range(5)]
    lines.append((now - 60, "Accepted password for alice from 203.0.113.9 port 5000 ssh2"))
    # Kratos's own login (its key's fingerprint) after failures from the same address: set aside
    lines += [(now - 500 + i, f"Failed password for root from 192.0.2.10 port {6000 + i} ssh2") for i in range(5)]
    lines.append((now - 30, "Accepted publickey for ubuntu from 192.0.2.10 port 7000 ssh2: ED25519 SHA256:" + "k" * 43))
    _store(tmp_path, lines)
    doc = SR.run(tmp_path, HOST, now=now, fingerprint="SHA256:" + "k" * 43)
    assert [h["ip"] for h in doc["hits"]] == ["203.0.113.9"] and doc["complete"]
    [f] = SF.build(SF.load_recent(Path(doc["file"])))
    assert f.id == "CORR-SSH-002" and f.severity == "critical" and f.subject == "203.0.113.9"
    assert "kratos hunt 203.0.113.9" in " ".join(f.evidence)


def test_no_stored_sign_ins_is_a_stated_gap(tmp_path):
    doc = SR.run(tmp_path, HOST, now=time.time(), fingerprint=None)
    assert not doc["complete"] and doc["coverage_gaps"] and doc["hits"] == []


# ---------------------------------------------------------------- the script's new rows
def _fake_sshd(tmp_path: Path, settings: str) -> dict:
    b = tmp_path / "bin"
    b.mkdir()
    for tool in ("awk", "cat", "printf", "grep", "head", "sh"):
        real = shutil.which(tool)
        if real:
            os.symlink(real, b / tool)
    sshd = b / "sshd"
    sshd.write_text("#!/bin/sh\ncat <<'EOF'\n" + settings + "\nEOF\n")
    sshd.chmod(sshd.stat().st_mode | stat.S_IEXEC)
    return {"PATH": str(b), "LC_ALL": "C"}


@pytest.mark.parametrize("settings,want", [
    ("passwordauthentication no\nkbdinteractiveauthentication yes\nusepam yes",
     {"ssh_kbd_interactive": "WARN"}),
    ("passwordauthentication no\nkbdinteractiveauthentication yes",            # no PAM in this build
     {"ssh_kbd_interactive": "PASS"}),
    ("passwordauthentication yes\nchallengeresponseauthentication no\nusepam yes\n"
     "authenticationmethods publickey,password publickey,keyboard-interactive",
     {"ssh_password_auth": "WARN", "ssh_kbd_interactive": "PASS", "ssh_auth_methods": "PASS"}),
    ("passwordauthentication no\nkbdinteractiveauthentication no\nauthenticationmethods password",
     {"ssh_auth_methods": "WARN"}),
])
def test_the_audit_script_reads_the_new_settings(tmp_path, settings, want):
    out = subprocess.run(["sh", "-s"], input=reads.config_audit_script(""), capture_output=True, text=True,
                         env=_fake_sshd(tmp_path, settings), timeout=30)
    rows = {c["check"]: c["status"] for c in reads.parse_check_lines(out.stdout)}
    for check, status in want.items():
        assert rows.get(check) == status, (check, rows)
    if "authenticationmethods" not in settings:
        assert "ssh_auth_methods" not in rows                                  # default "any": no row
