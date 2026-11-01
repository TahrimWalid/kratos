"""Read the stored auth events for one machine, judge them, keep one snapshot per machine
(`sshguess/sshguess_<machine-hash>.json`, replaced in place).

Logins of the last LOGIN_LOOKBACK_DAYS are looked at on every run, so a day without a
collection doesn't hide one; Kratos's own logins (its key's fingerprint in sshd's
"Accepted" line) are set aside.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos.sshguess import detect as D
from kratos.target_key import target_key

FOLDER = "sshguess"
PATTERN = "sshguess_*.json"
LOGIN_LOOKBACK_DAYS = 30
MAX_LOGINS = 5000
MAX_FAILURES_PER_IP = 20000


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def run(data_dir: Path, target: str, *, now: float | None = None, fingerprint: str | None = None) -> dict[str, Any]:
    from kratos.detect import own
    from kratos.events.store import EventStore

    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    key = target_key(target)
    fp = fingerprint if fingerprint is not None else own.kratos_fingerprint()
    gaps: list[str] = []
    hits: list[dict[str, Any]] = []
    db = data_dir / "kratos.db"
    if not db.exists():
        gaps.append("no sign-in events are stored for this machine yet (log sync stores them)")
    else:
        store = EventStore(db)
        if store.count(key, dataset="kratos.auth", start=now - 24 * 3600) == 0:
            gaps.append("no sign-in events from this machine were stored in the last 24 hours, so a login after "
                        "guessing couldn't be checked (is log sync reading its auth log?)")
        logins = []
        for e in store.query(key, action="ssh_success_login", start=now - LOGIN_LOOKBACK_DAYS * 86400,
                             limit=MAX_LOGINS, newest_first=True):
            if not e.source_ip or own.is_own_login("ssh_success_login", e.message, fp):
                continue
            logins.append(D.Login(ts=e.timestamp.timestamp(), ip=str(e.source_ip), user=str(e.user_name or ""),
                                  message=str(e.message or ""), event_id=str(e.event_id or "")))
        failures: dict[str, list[D.Failure]] = {}
        for ip in sorted({x.ip for x in logins}):
            first = min(x.ts for x in logins if x.ip == ip) - D.LOOKBACK_SECONDS
            failures[ip] = [D.Failure(ts=f.timestamp.timestamp(), ip=ip, user=str(f.user_name or ""),
                                      message=str(f.message or ""))
                            for f in store.query(key, action="ssh_failed_login", source_ip=ip, start=first,
                                                 limit=MAX_FAILURES_PER_IP, newest_first=False)]
        hits = [D.as_dict(h) for h in D.judge(logins, failures)]
    doc = {"target": key, "checked_at": _iso(now), "checked_at_epoch": now, "complete": not gaps,
           "coverage_gaps": gaps, "hits": hits[:500]}
    out = data_dir / FOLDER
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"sshguess_{hashlib.sha256(key.encode()).hexdigest()[:8]}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return {**doc, "file": str(path)}


def summary_line(doc: dict[str, Any]) -> str:
    hits = doc.get("hits") or []
    if not hits:
        return "no login from an address that was guessing passwords"
    worst = "critical" if any(h.get("severity") == "critical" for h in hits) else "high"
    return f"{len(hits)} login(s) from an address that was guessing passwords ({worst})"
