"""Reading run records back (`kratos trace list/show`, `/trace`, prune). Read-only."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos.trace.recorder import PARTIAL_SUFFIX, TRACES_DIR


def trace_files(data_dir: Path) -> list[Path]:
    """Every run record (finished `.json` and unfinished `.json.partial`), oldest folder first."""
    root = Path(data_dir) / TRACES_DIR
    if not root.is_dir():
        return []
    out: list[Path] = []
    for day in sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink()):
        for p in sorted(day.iterdir()):
            if p.is_symlink() or not p.is_file() or p.name.startswith("."):
                continue
            if p.name.endswith(".json") or p.name.endswith(".json" + PARTIAL_SUFFIX):
                out.append(p)
    return out


def trace_id_of(path: Path) -> str:
    name = path.name
    if name.endswith(PARTIAL_SUFFIX):
        name = name[: -len(PARTIAL_SUFFIX)]
    return name[:-5] if name.endswith(".json") else name


@dataclass
class TraceInfo:
    path: Path
    trace_id: str
    partial: bool
    data: dict[str, Any] | None
    error: str | None = None

    @property
    def started(self) -> str:
        return str((self.data or {}).get("started") or "")


def load(path: Path) -> TraceInfo:
    partial = path.name.endswith(PARTIAL_SUFFIX)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict):
            raise ValueError("not a run record")
        return TraceInfo(path, trace_id_of(path), partial, data)
    except (OSError, ValueError) as e:
        return TraceInfo(path, trace_id_of(path), partial, None, f"{type(e).__name__}: {e}")


def list_traces(data_dir: Path, *, target: str | None = None, since: float | None = None,
                session_id: str | None = None, limit: int | None = None) -> list[TraceInfo]:
    """Newest first. A finished record hides the `.partial` of the same run."""
    from kratos.utils.timeutil import epoch_of as to_epoch
    from kratos.target_key import target_key

    files = trace_files(data_dir)
    finished = {trace_id_of(p) for p in files if not p.name.endswith(PARTIAL_SUFFIX)}
    want_target = target_key(target) if target else None
    out: list[TraceInfo] = []
    for p in reversed(files):
        if p.name.endswith(PARTIAL_SUFFIX) and trace_id_of(p) in finished:
            continue
        info = load(p)
        d = info.data or {}
        if want_target and d.get("target") != want_target:
            continue
        if session_id and d.get("session_id") != session_id:
            continue
        if since is not None:
            started = to_epoch(d.get("started"))
            if started is None or started < since:
                continue
        out.append(info)
    out.sort(key=lambda i: i.started, reverse=True)
    return out[:limit] if limit else out


class AmbiguousTrace(LookupError):
    def __init__(self, prefix: str, matches: list[str]) -> None:
        self.matches = matches
        super().__init__(f"{prefix!r} matches {len(matches)} run records: {', '.join(matches[:8])}")


def find(data_dir: Path, ref: str) -> TraceInfo | None:
    """A run record by id or unique prefix (the finished one wins over its .partial)."""
    ref = (ref or "").strip()
    if not ref:
        return None
    files = trace_files(data_dir)
    exact = [p for p in files if trace_id_of(p) == ref]
    if exact:
        exact.sort(key=lambda p: p.name.endswith(PARTIAL_SUFFIX))
        return load(exact[0])
    hits: dict[str, Path] = {}
    for p in files:
        tid = trace_id_of(p)
        if tid.startswith(ref) and (tid not in hits or hits[tid].name.endswith(PARTIAL_SUFFIX)):
            hits[tid] = p
    if not hits:
        return None
    if len(hits) > 1:
        raise AmbiguousTrace(ref, sorted(hits))
    return load(next(iter(hits.values())))


def children_of(data_dir: Path, run_id: str) -> list[TraceInfo]:
    return [i for i in list_traces(data_dir) if (i.data or {}).get("parent_run_id") == run_id]
