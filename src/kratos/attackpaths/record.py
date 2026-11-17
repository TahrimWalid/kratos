"""Attack-path runs on record (E.1 §5.1): ``kratos.db`` tables and the per-run snapshot.

Per run, never edited: ``path_runs`` (one row -- the group, who built it, when, machine
count, coverage, cost 0), ``path_nodes`` / ``path_edges`` (the graph as drawn, each with
its evidence), ``path_results`` (the ranked entries, paths and chokepoints). The per-run
snapshot ``data_dir/paths/paths_<group-hash>_<run>.json`` holds the whole result for export
(D.6) and the PATH finding payloads build.py applies.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "attack_paths"
FOLDER = "paths"


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS path_runs (
          run_id TEXT PRIMARY KEY,
          group_ref TEXT NOT NULL,
          actor TEXT NOT NULL, interface TEXT NOT NULL, source TEXT NOT NULL,
          status TEXT NOT NULL,                -- running | done | incomplete
          machines INTEGER NOT NULL DEFAULT 0,
          outside_scope INTEGER NOT NULL DEFAULT 0,
          coverage TEXT,                       -- JSON (CoverageNumbers)
          nodes INTEGER NOT NULL DEFAULT 0, edges INTEGER NOT NULL DEFAULT 0,
          entries INTEGER NOT NULL DEFAULT 0, paths INTEGER NOT NULL DEFAULT 0,
          chokepoints INTEGER NOT NULL DEFAULT 0,
          caps_hit TEXT,                       -- JSON list
          cost_usd REAL NOT NULL DEFAULT 0.0,  -- always 0: a build never reaches the model
          snapshot_file TEXT,
          trace_id TEXT,
          built_at REAL NOT NULL, finished_at REAL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS path_runs_built ON path_runs(built_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS path_runs_group ON path_runs(group_ref, built_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS path_nodes (
          run_id TEXT NOT NULL, node_key TEXT NOT NULL,
          kind TEXT NOT NULL, target_key TEXT NOT NULL DEFAULT '',
          label TEXT, attrs TEXT, evidence TEXT,
          PRIMARY KEY (run_id, node_key)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS path_edges (
          run_id TEXT NOT NULL, edge_key TEXT NOT NULL,
          kind TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
          confidence TEXT NOT NULL, reason TEXT, evidence TEXT, attrs TEXT,
          PRIMARY KEY (run_id, edge_key)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS path_results (
          run_id TEXT NOT NULL, kind TEXT NOT NULL,      -- entry | path | chokepoint
          rank INTEGER NOT NULL, payload TEXT NOT NULL,
          PRIMARY KEY (run_id, kind, rank)
        )
        """
    )


STEPS = (_step_1,)


def _db(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


@contextlib.contextmanager
def opened(data_dir: Path | str) -> Iterator[sqlite3.Connection]:
    path = _db(data_dir)
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
        yield conn
    finally:
        conn.close()


def group_hash(group_ref: str) -> str:
    return hashlib.sha256(group_ref.encode("utf-8")).hexdigest()[:10]


def start(data_dir: Path | str, *, run_id: str, group_ref: str, actor: Any, source: str,
          machines: int, outside_scope: int, trace_id: str | None) -> None:
    with opened(data_dir) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO path_runs (run_id, group_ref, actor, interface, source, status, machines, "
            "outside_scope, trace_id, built_at) VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)",
            (run_id, group_ref[:200], str(getattr(actor, "user", actor))[:120],
             str(getattr(actor, "interface", "")), source, int(machines), int(outside_scope), trace_id, time.time()))


def finish(data_dir: Path | str, run_id: str, *, graph: Any, entries: list[Any], paths: list[Any],
           chokepoints: list[Any], coverage: Any, snapshot_file: str, status: str = "done") -> None:

    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE path_runs SET status = ?, coverage = ?, nodes = ?, edges = ?, entries = ?, paths = ?, "
                "chokepoints = ?, caps_hit = ?, snapshot_file = ?, finished_at = ? WHERE run_id = ?",
                (status, json.dumps(coverage.as_dict(), default=str), len(graph.nodes), len(graph.edges),
                 len(entries), len(paths), len(chokepoints), json.dumps(sorted(graph.caps_hit)),
                 snapshot_file, time.time(), run_id))
            for n in graph.all_nodes():
                conn.execute(
                    "INSERT OR REPLACE INTO path_nodes (run_id, node_key, kind, target_key, label, attrs, evidence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (run_id, n.node_key, n.kind, n.target_key, n.label[:300],
                     json.dumps(n.attrs, default=str)[:8000], json.dumps(n.evidence)[:4000]))
            for e in graph.all_edges():
                conn.execute(
                    "INSERT OR REPLACE INTO path_edges (run_id, edge_key, kind, src, dst, confidence, reason, "
                    "evidence, attrs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, e.edge_key, e.kind, e.src, e.dst, e.confidence, (e.reason or "")[:500],
                     json.dumps(e.evidence)[:2000], json.dumps(e.attrs, default=str)[:4000]))
            for i, en in enumerate(entries):
                conn.execute("INSERT OR REPLACE INTO path_results (run_id, kind, rank, payload) VALUES (?, ?, ?, ?)",
                             (run_id, "entry", i, json.dumps(_entry_payload(graph, en), default=str)))
            for i, p in enumerate(paths):
                conn.execute("INSERT OR REPLACE INTO path_results (run_id, kind, rank, payload) VALUES (?, ?, ?, ?)",
                             (run_id, "path", i, json.dumps(_path_payload(graph, p), default=str)))
            for i, c in enumerate(chokepoints):
                conn.execute("INSERT OR REPLACE INTO path_results (run_id, kind, rank, payload) VALUES (?, ?, ?, ?)",
                             (run_id, "chokepoint", i, json.dumps(c.__dict__, default=str)))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def _entry_payload(graph: Any, en: Any) -> dict[str, Any]:
    return {"target_key": en.target_key, "node_key": en.target_node_key, "label": en.target_label,
            "tier": en.tier, "severity": en.severity, "rank_index": en.rank_index,
            "grants_foothold": en.grants_foothold, "reason": en.edge.reason, "evidence": en.edge.evidence}


def _path_payload(graph: Any, p: Any) -> dict[str, Any]:
    return {"crown_jewel": p.crown_jewel, "criticality": p.crown_criticality, "length": p.length,
            "assumed_hops": p.assumed_hops, "fully_observed": p.fully_observed,
            "hops": [{"kind": e.kind, "src": e.src, "dst": e.dst, "confidence": e.confidence,
                      "reason": e.reason, "evidence": e.evidence} for e in p.edges]}


def write_snapshot(data_dir: Path | str, *, run_id: str, group_ref: str, graph: Any, entries: list[Any],
                   paths: list[Any], chokepoints: list[Any], coverage: Any, findings: list[Any],
                   built_at: float) -> str:
    from kratos import evidence as _evidence
    from kratos.utils.timeutil import epoch_to_utc_iso

    out_dir = Path(data_dir) / FOLDER
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "run_id": run_id, "group": group_ref, "built_at": epoch_to_utc_iso(built_at),
        "built_at_epoch": built_at,
        "coverage": coverage.as_dict(),
        "caps_hit": sorted(graph.caps_hit),
        "nodes": [n.to_dict() for n in graph.all_nodes()],
        "edges": [e.to_dict() for e in graph.all_edges()],
        "entries": [_entry_payload(graph, en) for en in entries],
        "paths": [_path_payload(graph, p) for p in paths],
        "chokepoints": [c.__dict__ for c in chokepoints],
        "findings": findings,     # [{target_key, id, title, severity, ...}] for the lifecycle
    }
    name = f"paths_{group_hash(group_ref)}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    path = out_dir / name
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    _evidence.record(path, data_dir=data_dir, category="attack_paths", machine="",
                     read="attack_path_build", transport="synthesis")
    return str(path)


def recent(data_dir: Path | str, limit: int = 20, *, group_ref: str | None = None) -> list[dict[str, Any]]:
    if not _db(data_dir).exists():
        return []
    with opened(data_dir) as conn:
        if group_ref:
            rows = conn.execute("SELECT * FROM path_runs WHERE group_ref = ? ORDER BY built_at DESC LIMIT ?",
                                (group_ref, int(limit)))
        else:
            rows = conn.execute("SELECT * FROM path_runs ORDER BY built_at DESC LIMIT ?", (int(limit),))
        return [dict(r) for r in rows]


def latest(data_dir: Path | str, group_ref: str) -> dict[str, Any] | None:
    rows = recent(data_dir, 1, group_ref=group_ref)
    return rows[0] if rows else None


def results(data_dir: Path | str, run_id: str, kind: str) -> list[dict[str, Any]]:
    if not _db(data_dir).exists():
        return []
    with opened(data_dir) as conn:
        rows = conn.execute("SELECT payload FROM path_results WHERE run_id = ? AND kind = ? ORDER BY rank",
                            (run_id, kind)).fetchall()
    out = []
    for r in rows:
        try:
            out.append(json.loads(r[0]))
        except (TypeError, ValueError):
            continue
    return out


def load_snapshot(path: str | Path) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
