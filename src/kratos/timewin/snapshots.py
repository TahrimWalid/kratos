"""
Snapshot time index, "state as of" lookups, and retention (docs/time_window_design.md §7,
§17).

Logs can't answer "was port 8080 open last month?" or "who was in sudo last week?" --
only Kratos's own saved observations can. This module indexes those files by the moment
they were CAPTURED (read from the file's own content where it records it -- parsed_at,
collected_at, generated_at, created_at, checked_at, the nmap run's start attribute --
falling back to the filename stamp, then mtime, and always saying which it used). Filename
sorting is never used for "latest": the regression check found `scan-summary` reading an
August scan because 'nmap_kratos_...' sorts after 'nmap_10...' (E-fix below).

Retention only ever touches Kratos's own local files, never the target, and is PLAN-FIRST:
`plan_retention` lists what the tiered policy would remove; nothing is deleted unless a
caller explicitly applies the plan (`kratos snapshots prune --apply`). Pinned files --
named integrity baselines, anything a findings report or baseline lists as an input, and
the newest snapshot of each category per target -- are never removed.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from kratos.utils.timeutil import detect_local_tz

UTC = timezone.utc

# category -> (subdir, glob, excluded-name regex or None)
CATEGORIES: dict[str, tuple[str, str, str | None]] = {
    "open_ports": ("scans", "parsed_*.json", None),
    "nmap_scan": ("scans", "nmap_*.xml", None),
    "vuln_scan": ("scans", "vulscan_*.xml", None),
    "system_context": ("context", "system_context_*.json", None),
    "baseline": ("baseline", "baseline_*.json", None),
    "integrity_check": ("baseline", "file_integrity_diff_*.json", None),
    "integrity_baseline": ("baseline", "file_integrity_*.json", r"^file_integrity_diff_"),
    "auth_stats": ("logs", "auth_stats_*.json", None),
    "findings": ("reports", "findings_*.json", None),
}
DESCRIPTIONS = {
    "open_ports": "open ports/services seen by an nmap scan of the target",
    "nmap_scan": "raw nmap scan output",
    "vuln_scan": "vulnerability scan output",
    "system_context": "system state snapshot (users, services, SSH config)",
    "baseline": "security baseline (sudo members, open ports, services)",
    "integrity_check": "file-integrity check result (changed/added/removed files)",
    "integrity_baseline": "named file-integrity reference baseline",
    "auth_stats": "authentication activity counts",
    "findings": "correlated findings report",
}
_STAMP_RE = re.compile(r"(\d{8})_(\d{6})")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Retention policy (defaults; all configurable by callers)
KEEP_ALL_DAYS = 30
DAILY_UNTIL_DAYS = 90
WEEKLY_UNTIL_DAYS = 365
SIZE_CAP_BYTES = 2 * 1024 ** 3


@dataclass
class Snapshot:
    path: str
    category: str
    target: str | None
    captured_at: float
    captured_source: str
    bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "file": Path(self.path).name, "category": self.category, "target": self.target,
                "captured_at": datetime.fromtimestamp(self.captured_at, UTC).isoformat(timespec="seconds"),
                "captured_source": self.captured_source}


# ---------------------------------------------------------------------------
# capture-time and target extraction
# ---------------------------------------------------------------------------
def _parse_iso(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:  # legacy naive value = Kratos host local time (timeutil's convention)
        dt = dt.replace(tzinfo=detect_local_tz() or UTC)
    return dt.timestamp()


def _captured(path: Path, category: str) -> tuple[float, str, str | None]:
    """(epoch, source, target) for one file."""
    target = None
    if path.suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            for key in ("parsed_at", "collected_at", "generated_at", "created_at", "checked_at"):
                t = _parse_iso(data.get(key))
                if t is not None:
                    target = _json_target(data)
                    return t, f"content:{key}", target
            target = _json_target(data)
    elif path.suffix == ".xml":
        try:
            head = path.open("r", encoding="utf-8", errors="replace").read(4096)
        except OSError:
            head = ""
        m = re.search(r'\bstart="(\d{9,})"', head)
        ips = _IP_RE.findall(re.search(r'args="([^"]*)"', head).group(1)) if 'args="' in head else []
        target = ips[-1] if ips else None
        if m:
            return float(m.group(1)), "content:nmap start", target
    m = _STAMP_RE.search(path.name)
    if m:
        naive = datetime.strptime("".join(m.groups()), "%Y%m%d%H%M%S")
        return naive.replace(tzinfo=detect_local_tz() or UTC).timestamp(), "filename (host local time)", target
    return path.stat().st_mtime, "file mtime", target


def _json_target(d: dict[str, Any]) -> str | None:
    t = d.get("target")
    if isinstance(t, str) and t:
        return t.split("@")[-1]
    src = d.get("source")
    if isinstance(src, str) and ":" in src:
        return src.rsplit(":", 1)[-1].split("@")[-1]
    hosts = d.get("hosts")
    if isinstance(hosts, list) and hosts and isinstance(hosts[0], dict) and hosts[0].get("ip"):
        return str(hosts[0]["ip"])
    return None


# ---------------------------------------------------------------------------
# index (SQLite, in the data dir's kratos.db)
# ---------------------------------------------------------------------------
def _db(data_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(Path(data_dir) / "kratos.db"), timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS snapshots (
        path TEXT PRIMARY KEY, category TEXT NOT NULL, target TEXT, captured_at REAL NOT NULL,
        captured_source TEXT NOT NULL, bytes INTEGER NOT NULL, mtime REAL NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_cat_time ON snapshots(category, captured_at)")
    return conn


def _files(data_dir: Path) -> Iterable[tuple[str, Path]]:
    for cat, (sub, pattern, exclude) in CATEGORIES.items():
        for p in sorted((Path(data_dir) / sub).glob(pattern)):
            if exclude and re.search(exclude, p.name):
                continue
            if p.is_file():
                yield cat, p


def reindex(data_dir: Path) -> dict[str, int]:
    """Bring the index in line with the files on disk (cheap: unchanged files are skipped
    by mtime). Returns {category: count}."""
    conn = _db(data_dir)
    try:
        known = {row[0]: row[1] for row in conn.execute("SELECT path, mtime FROM snapshots")}
        seen: set[str] = set()
        for cat, p in _files(data_dir):
            key = str(p.resolve())
            seen.add(key)
            st = p.stat()
            if known.get(key) == st.st_mtime:
                continue
            t, src, target = _captured(p, cat)
            conn.execute("INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?,?,?,?)",
                         (key, cat, target, t, src, st.st_size, st.st_mtime))
        for gone in set(known) - seen:
            conn.execute("DELETE FROM snapshots WHERE path = ?", (gone,))
        conn.commit()
        return {c: n for c, n in conn.execute("SELECT category, COUNT(*) FROM snapshots GROUP BY category")}
    finally:
        conn.close()


def _rows(data_dir: Path, sql: str, args: tuple) -> list[Snapshot]:
    conn = _db(data_dir)
    try:
        return [Snapshot(*r) for r in conn.execute(
            "SELECT path, category, target, captured_at, captured_source, bytes FROM snapshots " + sql, args)]
    finally:
        conn.close()


def _target_clause(target: str | None) -> tuple[str, tuple]:
    # a snapshot with no recorded target can't be ruled out, so it stays in (and is flagged)
    return ("AND (target = ? OR target IS NULL)", (target,)) if target else ("", ())


def latest(data_dir: Path, category: str, target: str | None = None) -> Snapshot | None:
    reindex(data_dir)
    clause, args = _target_clause(target)
    rows = _rows(data_dir, f"WHERE category = ? {clause} ORDER BY captured_at DESC LIMIT 1", (category, *args))
    return rows[0] if rows else None


def as_of(data_dir: Path, category: str, at: float, target: str | None = None) -> Snapshot | None:
    reindex(data_dir)
    clause, args = _target_clause(target)
    rows = _rows(data_dir, f"WHERE category = ? AND captured_at <= ? {clause} ORDER BY captured_at DESC LIMIT 1",
                 (category, at, *args))
    return rows[0] if rows else None


def within(data_dir: Path, category: str, start: float, end: float, target: str | None = None) -> list[Snapshot]:
    reindex(data_dir)
    clause, args = _target_clause(target)
    return _rows(data_dir, f"WHERE category = ? AND captured_at >= ? AND captured_at < ? {clause} ORDER BY captured_at",
                 (category, start, end, *args))


def horizon(data_dir: Path) -> dict[str, dict[str, Any]]:
    """Oldest/newest capture per category -- the limit of what 'state as of' can answer."""
    reindex(data_dir)
    conn = _db(data_dir)
    try:
        out = {}
        for cat, lo, hi, n in conn.execute(
                "SELECT category, MIN(captured_at), MAX(captured_at), COUNT(*) FROM snapshots GROUP BY category"):
            out[cat] = {"oldest": datetime.fromtimestamp(lo, UTC).isoformat(timespec="seconds"),
                        "newest": datetime.fromtimestamp(hi, UTC).isoformat(timespec="seconds"), "count": n}
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# summaries for the agent
# ---------------------------------------------------------------------------
def summarize(s: Snapshot) -> dict[str, Any]:
    p = Path(s.path)
    try:
        if s.category == "nmap_scan":
            from kratos.adapters.nmap_parse import parse_nmap_xml_to_dict

            d = parse_nmap_xml_to_dict(p)
            return {"hosts": [{"ip": h.get("ip"), "open_ports": [f"{o.get('port')}/{o.get('protocol')} {o.get('service', '')}".strip()
                                                               for o in h.get("open_ports", [])]} for h in d.get("hosts", [])]}
        if p.suffix != ".json":
            return {"file": p.name}
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001 -- a damaged snapshot is reported, not fatal
        return {"error": f"could not read snapshot: {e}"}
    if s.category == "open_ports":
        return {"hosts": [{"ip": h.get("ip"), "open_ports": [f"{o.get('port')}/{o.get('protocol')} {o.get('service', '')}".strip()
                                                           for o in h.get("open_ports", [])]} for h in d.get("hosts", [])]}
    if s.category == "baseline":
        return {k: d.get(k) for k in ("sudo_members", "open_ports", "environment")} | {
            "active_services_count": len(d.get("active_services") or [])}
    if s.category == "system_context":
        return {"scope": d.get("scope"), "ssh": d.get("ssh"), "users": (d.get("users") or {}).get("total_users"),
                "critical_services": (d.get("critical_services") or {}).get("detected")}
    if s.category == "integrity_check":
        diff = d.get("diff") or {}
        return {"baseline_name": d.get("baseline_name"), "changed": diff.get("changed"), "added": diff.get("added"),
                "removed": diff.get("removed")}
    if s.category == "findings":
        return {"findings": [{"id": f.get("id"), "severity": f.get("severity"), "title": f.get("title")}
                             for f in d.get("findings", [])]}
    if s.category == "auth_stats":
        return {"events_by_type": d.get("events_by_type"), "top_failed_login_ips": d.get("top_failed_login_ips"),
                "window": d.get("since")}
    return {"keys": sorted(d)[:12]}


# ---------------------------------------------------------------------------
# retention (plan first; apply only on request)
# ---------------------------------------------------------------------------
def _pinned(data_dir: Path, snaps: list[Snapshot]) -> set[str]:
    pinned: set[str] = set()
    names_referenced: set[str] = set()
    for s in snaps:
        if s.category == "integrity_baseline":
            pinned.add(s.path)
        if s.category in ("findings", "baseline"):
            try:
                inputs = json.loads(Path(s.path).read_text(encoding="utf-8", errors="replace")).get("inputs") or {}
            except (OSError, json.JSONDecodeError, AttributeError):
                inputs = {}
            names_referenced |= {Path(v).name for v in inputs.values() if isinstance(v, str)}
    newest: dict[tuple[str, str | None], Snapshot] = {}
    for s in snaps:
        k = (s.category, s.target)
        if k not in newest or s.captured_at > newest[k].captured_at:
            newest[k] = s
    pinned |= {s.path for s in newest.values()}
    pinned |= {s.path for s in snaps if Path(s.path).name in names_referenced}
    return pinned


def plan_retention(data_dir: Path, now: float | None = None, *, keep_all_days: int = KEEP_ALL_DAYS,
                   daily_until_days: int = DAILY_UNTIL_DAYS, weekly_until_days: int = WEEKLY_UNTIL_DAYS,
                   size_cap_bytes: int = SIZE_CAP_BYTES) -> dict[str, Any]:
    reindex(data_dir)
    now = now if now is not None else time.time()
    snaps = _rows(data_dir, "ORDER BY captured_at DESC", ())
    pinned = _pinned(data_dir, snaps)
    kept_bucket: set[tuple] = set()
    delete: list[Snapshot] = []
    for s in snaps:  # newest first: the first file seen in each bucket is the one kept
        age_days = (now - s.captured_at) / 86400
        if s.path in pinned or age_days <= keep_all_days:
            continue
        d = datetime.fromtimestamp(s.captured_at, UTC)
        if age_days <= daily_until_days:
            bucket = ("d", s.category, s.target, d.date())
        elif age_days <= weekly_until_days:
            bucket = ("w", s.category, s.target, d.isocalendar()[:2])
        else:
            bucket = ("m", s.category, s.target, (d.year, d.month))
        if bucket in kept_bucket:
            delete.append(s)
        else:
            kept_bucket.add(bucket)
    total = sum(s.bytes for s in snaps) - sum(s.bytes for s in delete)
    dropping = {s.path for s in delete}
    for s in sorted(snaps, key=lambda x: x.captured_at):  # size cap: thin oldest non-pinned first
        if total <= size_cap_bytes:
            break
        if s.path in pinned or s.path in dropping or (now - s.captured_at) / 86400 <= keep_all_days:
            continue
        delete.append(s)
        dropping.add(s.path)
        total -= s.bytes
    return {"delete": [s.as_dict() | {"bytes": s.bytes} for s in delete],
            "delete_bytes": sum(s.bytes for s in delete), "kept": len(snaps) - len(delete),
            "pinned": len(pinned), "policy": {"keep_all_days": keep_all_days, "daily_until_days": daily_until_days,
                                              "weekly_until_days": weekly_until_days, "size_cap_bytes": size_cap_bytes}}


def apply_retention(data_dir: Path, plan: dict[str, Any]) -> int:
    """Delete exactly the files a plan listed (and only if they still exist and are still
    Kratos snapshot files under data_dir). Returns how many were removed."""
    root = Path(data_dir).resolve()
    removed = 0
    for item in plan.get("delete", []):
        p = Path(item["path"]).resolve()
        if root not in p.parents or not p.is_file():
            continue
        p.unlink()
        removed += 1
    reindex(data_dir)
    return removed
