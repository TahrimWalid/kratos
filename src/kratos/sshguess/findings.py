"""CORR-SSH-002 from the saved snapshot (kratos.sshguess.record), as a snapshot source."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos.sshguess import record

CATEGORY = "ssh_guess"
MAX_AGE_HOURS = 24
TITLE = "A login succeeded from an address that had been guessing passwords"


def load_recent(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("hits"), list):
        return None
    if time.time() - float(doc.get("checked_at_epoch") or 0) > MAX_AGE_HOURS * 3600:
        return None
    return doc


def _when(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError):
        return "an unknown time"


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding, normalise_entities

    by_ip: dict[str, list[dict[str, Any]]] = {}
    for h in doc.get("hits") or []:
        if isinstance(h, dict) and h.get("ip"):
            by_ip.setdefault(str(h["ip"]), []).append(h)
    out: list[Any] = []
    for ip, hits in sorted(by_ip.items()):
        hits.sort(key=lambda h: float(h.get("login_ts") or 0), reverse=True)
        severity = "critical" if any(h.get("severity") == "critical" for h in hits) else "high"
        evidence = []
        for h in hits[:5]:
            evidence.append(
                f"{_when(h.get('login_ts'))}: '{h.get('user') or '?'}' logged in with {h.get('method')} from {ip}, "
                f"after {h.get('failures')} guessed login(s) from the same address between "
                f"{_when(h.get('first_failure_ts'))} and {_when(h.get('last_failure_ts'))}"
                + (f" (names tried: {', '.join(h.get('users_tried') or [])})" if h.get("users_tried") else ""))
        if len(hits) > 5:
            evidence.append(f"... and {len(hits) - 5} earlier login(s) from this address")
        evidence.append("From the sign-in events Kratos stored for this machine (log sync); Kratos's own logins "
                        "are set aside.")
        evidence.append(f"Look at everything this address did: kratos hunt {ip} --machine {doc.get('target')}")
        out.append(Finding(
            id="CORR-SSH-002", title=TITLE, severity=severity, evidence=evidence,
            recommendation=[
                "Treat the account as possibly taken over until you know otherwise: check what the session did "
                "(the hunt above, `last`, the shell history), and look for new keys, cron jobs, services or "
                "accounts from that time (Kratos's persistence and running-process checks).",
                "If the login wasn't you: change the account's password, remove any key added to it, and block "
                "the address.",
                "Turn password logins off for SSH (PasswordAuthentication no, KbdInteractiveAuthentication no).",
            ],
            subject=ip,
            entities=normalise_entities("text", [f"{h.get('user')}@{ip}@{int(float(h.get('login_ts') or 0))}"
                                                 for h in hits]),
            source_ips=[ip]))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    return False          # a past login stays true; a person decides on it


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=record.FOLDER, pattern=record.PATTERN,
                                            rule_prefix="CORR-SSH-002", load=load_recent, build=build,
                                            closes_findings=closes_findings))
