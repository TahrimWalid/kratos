"""A small incident in a scratch data folder, for the export tests (D.6).

Neutral values only: RFC 5737 addresses, `.test` names, alice/bob/mallory. Two machines;
recorded evidence files, one file from before the evidence ledger, stored events, a
privileged-account read (the account list masking uses), findings with history.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from kratos import evidence
from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.events import converters as C
from kratos.events.store import EventStore
from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import Coverage
from kratos.run_context import RunContext

M1 = "192.0.2.10"
M2 = "192.0.2.20"
ATTACKER = "203.0.113.9"
OTHER_IP = "198.51.100.7"
HOST1 = "web-01.test"
ACCOUNTS = ("alice", "bob", "mallory")
ALL = Coverage(inputs={k: None for k in ("nmap_parsed", "auth_stats", "auth_patterns", "system_context",
                                          "auth_trends", "file_integrity", "privileged_accounts", "vuln_scan")})


def _write(d: Path, rel: str, obj) -> Path:
    p = d / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2) if not isinstance(obj, str) else obj, encoding="utf-8")
    return p


def _events(machine: str, now: float, n: int = 12):
    created = datetime.fromtimestamp(now, timezone.utc)
    ctx = C.ReadContext(target=machine, transport="ssh", read=C.READ_JOURNAL_AUTH, created=created, run_id="r1")
    out = []
    for i in range(n):
        ts = datetime.fromtimestamp(now - 3600 + i * 60, timezone.utc).isoformat()
        user = "mallory" if i % 3 else "bob"
        msg = f"Failed password for invalid user {user} from {ATTACKER} port {40000 + i} ssh2"
        out.append(C.from_auth_event(classify_auth_message(ts, machine, "sshd", msg, msg), ctx=ctx))
    msg = f"Accepted publickey for alice from {OTHER_IP} port 50000 ssh2"
    ts = datetime.fromtimestamp(now - 60, timezone.utc).isoformat()
    out.append(C.from_auth_event(classify_auth_message(ts, machine, "sshd", msg, msg), ctx=ctx))
    return out


def build(d: Path, *, now: float | None = None) -> dict:
    """The incident. Returns the instant used and the paths written."""
    now = now or time.time()
    d.mkdir(parents=True, exist_ok=True)
    written = {}
    # a file from before the ledger (no row): a system context of M1
    old = _write(d, "context/system_context_20260101_000000.json",
                 {"target": M1, "collected_at": datetime.fromtimestamp(now - 7200, timezone.utc).isoformat(),
                  "hostname": HOST1, "users": list(ACCOUNTS)})
    written["pre_ledger"] = old
    # recorded evidence: privileged accounts (the account list), persistence, a findings report
    priv = _write(d, f"context/privileged_accounts_{uuid.uuid4().hex[:8]}.json",
                  {"target": M1, "collected_at": datetime.fromtimestamp(now - 1800, timezone.utc).isoformat(),
                   "privileged": ["alice"], "local_accounts": {"alice": 1000, "bob": 1001, "mallory": 1002},
                   "accounts": {"alice": {"uid": 1000}}})
    evidence.record(priv, data_dir=d, category="privileged_accounts", machine=M1, read="list_privileged_accounts",
                    transport="ssh", now=now - 1800)
    pers = _write(d, f"persistence/persistence_{uuid.uuid4().hex[:8]}.json",
                  {"target": M1, "signals": [{"path": "/home/mallory/.ssh/authorized_keys", "owner": "mallory",
                                              "note": f"key added from {ATTACKER}"}]})
    evidence.record(pers, data_dir=d, category="persistence", machine=M1, read="persistence_inventory",
                    transport="agent", now=now - 1500)
    rep = _write(d, f"reports/findings_{uuid.uuid4().hex[:8]}.json",
                 {"target": M1, "findings": [{"id": "CORR-SSH-001", "evidence": [f"12 failures from {ATTACKER}"]}]})
    evidence.record(rep, data_dir=d, category="findings_report", machine=M1, read="correlate_findings",
                    transport="local", now=now - 1200)
    pers2 = _write(d, f"persistence/persistence_{uuid.uuid4().hex[:8]}.json", {"target": M2, "signals": []})
    evidence.record(pers2, data_dir=d, category="persistence", machine=M2, read="persistence_inventory",
                    transport="ssh", now=now - 1000)
    written.update(priv=priv, pers=pers, rep=rep, pers2=pers2)
    # events
    EventStore(d / "kratos.db").add(_events(M1, now))
    EventStore(d / "kratos.db").add(_events(M2, now, n=3))
    # findings with a history
    for m in (M1, M2):
        run = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=m, session_id=None,
                         started_at=now - 900)
        A.apply_run([{"id": "CORR-SSH-001", "title": f"SSH brute force from {ATTACKER}", "severity": "high",
                      "evidence": [f"12 failed logins from {ATTACKER} for mallory and bob"], "subject": "",
                      "entities": [ATTACKER]},
                     {"id": "PERSIST-003", "title": "new SSH key for mallory", "severity": "medium",
                      "evidence": ["/home/mallory/.ssh/authorized_keys added"], "subject": "/home/mallory/.ssh",
                      "entities": ["/home/mallory/.ssh/authorized_keys"]}],
                    target=m, coverage=ALL, run=run, data_dir=d, now=now - 900)
    return {"now": now, **written}


REAL_VALUES = (M1, M2, ATTACKER, OTHER_IP, HOST1, "web-01", *ACCOUNTS)
