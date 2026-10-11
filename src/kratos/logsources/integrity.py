"""check_log_integrity: run every tamper check on the active machine, remember
what was seen, and save the result for the rule engine (0.3).

Reads go through kratos.adapters.ssh_remote (SSH, or the machine's sub-agent
when it is linked to one), so both transports run the same checks. A read that
fails makes that check "unknown" with the reason -- never "ok". State is only
remembered from reads that succeeded.

The saved file `data_dir/integrity/log_integrity_<time>.json` says which
machine it describes (`target`) and what each check covered; correlate_findings
picks it up (findings_engine.find_latest_inputs, category `log_integrity`).
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos.logsources import state_store, tamper
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

INTEGRITY_DIR = "integrity"
FILE_GLOB = "log_integrity_*.json"
_AUDIT_EVENT_ACTIONS = ("auditd_stopped", "auditd_aborted", "audit_rule_removed", "audit_disabled")


class Reader:
    """The real reads (SSH or sub-agent). Tests pass their own."""

    def file_states(self) -> Any:
        from kratos.adapters.ssh_remote import fetch_log_file_states

        return fetch_log_file_states()

    def journal_headers(self) -> Any:
        from kratos.adapters.ssh_remote import fetch_journal_headers

        return fetch_journal_headers()

    def boot_history(self) -> Any:
        from kratos.adapters.ssh_remote import fetch_boot_history

        return fetch_boot_history()

    def utmp(self, name: str) -> Any:
        from kratos.adapters.ssh_remote import fetch_utmp

        return fetch_utmp(name)

    def audit_status(self) -> Any:
        from kratos.adapters.ssh_remote import fetch_audit_status

        return fetch_audit_status()


def _failed(result: Any) -> str | None:
    """The failure text of a failed read (an SSHResult), or None."""
    if isinstance(result, dict) or result is None:
        return None if isinstance(result, dict) else "no result"
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def _unknown(check_id: str, why: str) -> dict[str, Any]:
    return {"id": check_id, "status": "unknown", "evidence": [], "items": [], "coverage": f"not checked: {why}"}


def _audit_events_since(data_dir: Path, target: str, since: float | None) -> list[Any]:
    try:
        from kratos.events.store import EventStore

        store = EventStore(Path(data_dir) / "kratos.db")
        out = []
        for action in _AUDIT_EVENT_ACTIONS:
            out += store.query(target_key(target), action=action, start=since, dataset="kratos.auditd", limit=20)
        return sorted(out, key=lambda e: e.ts)[-10:]
    except Exception:  # noqa: BLE001 -- extra evidence only
        return []


def run(data_dir: Path, target: str, *, reader: Reader | None = None, now: float | None = None) -> dict[str, Any]:
    """Run the checks, remember state, write the integrity file. Returns the saved
    document plus `file` (its path)."""
    data_dir = Path(data_dir)
    reader = reader or Reader()
    now = time.time() if now is None else now
    checks: dict[str, dict[str, Any]] = {}
    via: set[str] = set()

    fs = reader.file_states()
    if (why := _failed(fs)) is not None:
        checks["file_state"] = _unknown("file_state", why)
    else:
        via.add(fs.get("via") or "ssh")
        previous = state_store.file_states(data_dir, target)
        lr_before = state_store.get_extra(data_dir, target, "logrotate") or {}
        lr_before.pop("_checked_at", None)
        result, rows = tamper.check_file_states(fs, previous, lr_before)
        checks["file_state"] = result
        state_store.save_file_states(data_dir, target, rows, checked_at=now)
        state_store.put_extra(data_dir, target, "logrotate", dict(fs.get("logrotate") or {}))

    jh = reader.journal_headers()
    checks["journal"] = _unknown("journal", why) if (why := _failed(jh)) is not None else tamper.check_journal(jh)

    bh = reader.boot_history()
    checks["boots"] = _unknown("boots", why) if (why := _failed(bh)) is not None else tamper.check_boots(bh, now=now)

    utmp_reads: dict[str, Any] = {}
    for name in tamper.UTMP_NAMES:
        r = reader.utmp(name)
        utmp_reads[name] = None if _failed(r) is not None else r
    checks["login_records"] = tamper.check_login_records(utmp_reads)

    au = reader.audit_status()
    if (why := _failed(au)) is not None:
        checks["auditd"] = _unknown("auditd", why)
    else:
        previous_audit = state_store.get_extra(data_dir, target, "auditd")
        events = _audit_events_since(data_dir, target, (previous_audit or {}).get("_checked_at"))
        result, state = tamper.check_auditd(au, previous_audit, events)
        checks["auditd"] = result
        if state is not None:
            state_store.put_extra(data_dir, target, "auditd", state)

    seal = None
    try:
        from kratos.logsources import seal as _seal

        seal = _seal.latest_summary(data_dir, target)
    except Exception:  # noqa: BLE001 -- sealing is optional; its absence is not a failure here
        seal = None

    doc: dict[str, Any] = {
        "target": target,
        "checked_at": epoch_to_utc_iso(now),
        "checked_at_epoch": now,
        "checks": checks,
        "seal": seal,
        "via": sorted(via) or None,
    }
    out_dir = data_dir / INTEGRITY_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"log_integrity_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return {**doc, "file": str(path)}


def summary_for_model(doc: dict[str, Any]) -> dict[str, Any]:
    """What check_log_integrity returns: per check its status, evidence and
    coverage; a coverage_gap naming every check that couldn't be done."""
    out: dict[str, Any] = {"target": doc.get("target"), "checked_at": doc.get("checked_at")}
    suspicious, unknown = [], []
    for cid, c in doc["checks"].items():
        out[cid] = {"status": c["status"], "evidence": c["evidence"][:8], "coverage": c["coverage"]}
        if c["status"] == "suspicious":
            suspicious.append(cid)
        elif c["status"] == "unknown":
            unknown.append(f"{cid} ({c['coverage']})")
    seal = doc.get("seal")
    out["sealing"] = seal or {"status": "not set up", "note": "journal sealing is not configured for this machine "
                                                                "(recommended: /target seal)"}
    out["suspicious_checks"] = suspicious
    if unknown:
        out["coverage_gap"] = "log tampering was not fully checked: " + "; ".join(unknown)
    out["next_step"] = "run correlate_findings to turn these results into findings (LOG-*/SEAL-*)"
    return out
