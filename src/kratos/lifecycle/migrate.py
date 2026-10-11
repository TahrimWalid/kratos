"""One-time import of the findings reports written before the lifecycle existed.

`data_dir/reports/findings_*.json` are walked oldest -> newest; each file is
recorded in `finding_imports` (name + sha256) so it is imported once. Report
files are only read -- never changed or deleted (owner decision 5).

Which machine an old report was about, in order:
1. its own `target` field (reports written by this version have one);
2. the machine its input files describe (findings_engine.input_hosts), if they
   still exist;
3. the session whose saved transcript names this report file;
4. "unknown" -- still imported, never dropped.

Imported findings become records with first/last seen from the report times:
`open` if in the newest imported report for that machine, else
`inactive`/`mitigated` with reason "from history import". No coverage claim is
invented (`last_checked` stays empty). Reports written by this version (they
carry `lifecycle`) are already accounted for and only recorded.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos.adapters.findings_engine import input_hosts
from kratos.lifecycle import store as S
from kratos.lifecycle.keys import finding_key, normalise_subject
from kratos.lifecycle.rules import rule_info
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

UNKNOWN = "unknown"
_INPUT_DIRS = {"nmap_parsed": "scans", "vuln_scan": "scans", "auth_stats": "logs", "auth_patterns": "logs",
               "system_context": "context", "privileged_accounts": "context", "auth_trends": "reports",
               "file_integrity": "baseline"}
_imported: set[str] = set()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _epoch(value: Any, fallback: float) -> float:
    """A report's generated_at as epoch seconds (very old reports wrote naive local
    times, which timestamp() reads as local -- what they were)."""
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return fallback


def record_written_report(data_dir: Path, report: Path, target: str | None) -> None:
    """A report written with lifecycle data: mark it accounted for."""
    report = Path(report)
    with S.opened(data_dir) as conn:
        S.record_import(conn, report.name, _sha256(report), time.time(), target)


def _hosts_from_inputs(data_dir: Path, inputs: dict[str, Any]) -> str | None:
    hosts: set[str] = set()
    context_only = False
    for category, name in (inputs or {}).items():
        if not name or category not in _INPUT_DIRS:
            continue
        path = Path(data_dir) / _INPUT_DIRS[category] / Path(str(name)).name
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        found = input_hosts(category, data)
        if not found:
            continue
        if category == "system_context":
            context_only = True
            continue
        hosts |= found
    if len(hosts) == 1:
        return next(iter(hosts))
    if not hosts and context_only:
        return "loopback"
    return None


def _session_index(data_dir: Path) -> dict[str, str]:
    """report file name -> the target of the session whose transcript produced it."""
    sessions = Path(data_dir) / "sessions"
    if not sessions.is_dir():
        return {}
    targets: dict[str, list[str]] = {}
    try:
        conn = sqlite3.connect(f"file:{S.db_path(data_dir)}?mode=ro", uri=True)
        try:
            for sid, raw in conn.execute("SELECT session_id, targets FROM sessions"):
                try:
                    targets[sid] = list(json.loads(raw) or [])
                except ValueError:
                    pass
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    index: dict[str, str] = {}
    for path in sessions.glob("*_turn*.json"):
        sid = path.name.split("_turn", 1)[0]
        tgts = targets.get(sid) or []
        if len(tgts) != 1:
            continue
        try:
            steps = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for step in steps if isinstance(steps, list) else []:
            if not isinstance(step, dict) or step.get("tool") != "correlate_findings":
                continue
            obs = step.get("observation")
            result = obs.get("result") if isinstance(obs, dict) and isinstance(obs.get("result"), dict) else obs
            name = Path(str((result or {}).get("findings_json_file") or "")).name if isinstance(result, dict) else ""
            if name:
                index.setdefault(name, target_key(tgts[0]))
    return index


def _attribute(data_dir: Path, report: dict[str, Any], name: str,
               sessions: dict[str, str] | None) -> tuple[str, str, dict[str, str] | None]:
    if report.get("target"):
        return target_key(report["target"]), "report", sessions
    host = _hosts_from_inputs(data_dir, report.get("inputs") or {})
    if host:
        return host, "inputs", sessions
    if sessions is None:
        sessions = _session_index(data_dir)
    if name in sessions:
        return sessions[name], "session", sessions
    return UNKNOWN, "unknown", sessions


def import_reports(data_dir: Path, *, now: float | None = None) -> dict[str, Any]:
    """Import every report not yet in finding_imports. Returns counts:
    {imported, skipped_lifecycle, malformed, records_created, by_source: {...}, targets: {...}}."""
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    stats: dict[str, Any] = {"imported": 0, "skipped_lifecycle": 0, "malformed": 0, "records_created": 0,
                             "by_source": {}, "targets": {}}
    reports_dir = data_dir / "reports"
    files = sorted(reports_dir.glob("findings_*.json")) if reports_dir.is_dir() else []
    if not files:
        return stats
    with S.opened(data_dir) as conn, S.immediate(conn):
        done = {r[0] for r in conn.execute("SELECT report_name FROM finding_imports")}
        todo = [p for p in files if p.name not in done]
        loaded: list[tuple[float, str, Path, dict[str, Any], str]] = []
        for path in todo:
            try:
                sha = _sha256(path)
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
                    raise ValueError("not a findings report")
            except (OSError, ValueError, UnicodeDecodeError) as e:
                logger.warning("skipping malformed findings report %s: %s", path.name, e)
                stats["malformed"] += 1
                try:
                    S.record_import(conn, path.name, _sha256(path), now, None)
                except OSError:
                    pass
                continue
            if "lifecycle" in data or "lifecycle_error" in data:
                S.record_import(conn, path.name, sha, now, target_key(data.get("target")) or None)
                stats["skipped_lifecycle"] += 1
                continue
            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = now
            loaded.append((_epoch(data.get("generated_at"), mtime), path.name, path, data, sha))
        loaded.sort(key=lambda x: (x[0], x[1]))

        sessions: dict[str, str] | None = None
        per_target: dict[str, dict[str, Any]] = {}
        for at, name, _path, data, sha in loaded:
            target, source, sessions = _attribute(data_dir, data, name, sessions)
            stats["by_source"][source] = stats["by_source"].get(source, 0) + 1
            stats["targets"][target] = stats["targets"].get(target, 0) + 1
            t = per_target.setdefault(target, {"records": {}, "newest": None, "source": source})
            keys_here: set[str] = set()
            for f in data["findings"]:
                if not isinstance(f, dict) or not f.get("id"):
                    continue
                rid = str(f["id"])
                info = rule_info(rid)
                if info is not None and info.kind == "run_note":
                    continue
                key = finding_key(rid, target, normalise_subject(f.get("subject")))
                keys_here.add(key)
                rec = t["records"].setdefault(key, {"rule_id": rid, "kind": info.kind if info else "condition",
                                                    "first": at, "last": at, "times": 0, "finding": f,
                                                    "subject": normalise_subject(f.get("subject")),
                                                    "source": source})
                rec["first"], rec["last"] = min(rec["first"], at), max(rec["last"], at)
                rec["times"] += 1
                if at >= rec["last"]:
                    rec["finding"] = f
            t["newest"] = keys_here
            S.record_import(conn, name, sha, now, target)
            stats["imported"] += 1

        for target, t in per_target.items():
            for key, rec in t["records"].items():
                f = rec["finding"]
                existing = S.get_record(conn, key)
                if existing is not None:
                    conn.execute("UPDATE finding_records SET first_seen = MIN(first_seen, ?), "
                                 "times_seen = times_seen + ? WHERE finding_key = ?", (rec["first"], rec["times"], key))
                    continue
                in_newest = key in (t["newest"] or set())
                state = "open" if in_newest else ("inactive" if rec["kind"] == "occurrence" else "mitigated")
                entities = sorted({str(e) for e in f.get("entities") or []})
                conn.execute(
                    "INSERT INTO finding_records (finding_key, rule_id, target, subject, kind, state, severity, "
                    "title, entities, latest, first_seen, last_seen, last_checked, last_run_id, times_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                    (key, rec["rule_id"], target, rec["subject"], rec["kind"], state,
                     str(f.get("severity") or "info").lower(), str(f.get("title") or ""), json.dumps(entities),
                     json.dumps(f, sort_keys=True, default=str), rec["first"], rec["last"], rec["times"]),
                )
                S.add_event(conn, key, at=now, kind="imported", actor="kratos", to_state=state,
                            interface="migration",
                            reason="from history import" + ("" if in_newest else " (absent from the newest report)"),
                            details={"target_source": rec["source"], "reports": rec["times"]})
                stats["records_created"] += 1
    return stats


def ensure_imported(data_dir: Path) -> None:
    """Import old reports once per process per data folder (cheap afterwards)."""
    key = os.path.realpath(str(data_dir))
    if key in _imported:
        return
    try:
        result = import_reports(Path(data_dir))
    except Exception as e:  # noqa: BLE001 -- history import must never block a new report
        logger.warning("could not import old findings reports (%s); will retry next start", e)
        return
    _imported.add(key)
    if result["imported"] or result["malformed"]:
        logger.info("imported findings history: %s", result)
