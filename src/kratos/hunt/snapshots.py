"""Hunting in saved snapshots (C.3 §5.1): persistence reads (A.1), running-process
reads (A.5), installed-package lists (A.2) -- and the small `hunt_index` those
reads now save so a later hunt can find a full SHA-256, a program that ran, or an
address a process was talking to.

`hunt_index` is bounded (caps below) and holds only identities -- paths, hashes,
program names, account names, remote addresses -- never file contents or command
lines. A snapshot saved before this existed is still searched through its findings'
entities and evidence (where a persistence item keeps the first 12 hex digits of its
hash: such a match is reported as a prefix match).
"""
from __future__ import annotations

import ipaddress
import json
import posixpath
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from kratos.hunt.indicators import Indicator
from kratos.target_key import target_key

MAX_FILES = 2000
MAX_KEYS = 500
MAX_PROCESSES = 2000
MAX_ADDRS = 2000
MAX_TEMP = 500

KINDS = {"persistence": ("persistence", "persistence_*.json", "persistence read"),
         "live_response": ("live", "live_response_*.json", "running-process read")}


# --------------------------------------------------------------------------- what reads save
def persistence_index(inv: dict[str, Any]) -> dict[str, Any]:
    files = []
    for path, it in sorted((inv.get("items") or {}).items()):
        sha = str(it.get("sha256") or "").lower()
        if len(sha) == 64 and not it.get("package"):
            files.append([path, sha])
        if len(files) >= MAX_FILES:
            break
    keys = [[str(k.get("user") or ""), str(k.get("fingerprint") or ""), str(k.get("path") or "")]
            for k in (inv.get("keys") or [])[:MAX_KEYS]]
    return {"files": files, "keys": keys, "capped": len(files) >= MAX_FILES}


def _public(addr: Any) -> str | None:
    try:
        a = ipaddress.ip_address(str(addr))
    except ValueError:
        return None
    if a.is_unspecified or a.is_loopback:
        return None
    return a.compressed


def live_index(inv: dict[str, Any]) -> dict[str, Any]:
    procs, seen = [], set()
    for it in (inv.get("procs") or {}).values():
        row = (str(it.get("exe") or ""), str(it.get("comm") or ""), str(it.get("user") or ""))
        if row != ("", "", "") and row not in seen:
            seen.add(row)
            procs.append(list(row))
        if len(procs) >= MAX_PROCESSES:
            break
    addrs = sorted({a for s in (inv.get("sockets") or []) if s.get("remote_port")
                    for a in [_public(s.get("remote_addr"))] if a})[:MAX_ADDRS]
    temp = [[p, str(it.get("sha256") or "")] for p, it in sorted((inv.get("temp_files") or {}).items())][:MAX_TEMP]
    return {"processes": procs, "remote_addrs": addrs, "temp_files": temp}


# --------------------------------------------------------------------------- searching
@dataclass
class SnapHit:
    machine: str
    kind: str              # persistence | live_response | packages
    label: str
    ts: float
    file: str
    where: str             # what matched, in plain words
    value: str             # the matched value (validated identity)
    prefix_only: bool = False


def _files(data_dir: Path, kind: str, limit: int) -> tuple[list[Path], int]:
    folder, pattern, _ = KINDS[kind]
    paths = sorted((Path(data_dir) / folder).glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return paths[:limit], len(paths)


def _ip_in(ind: Indicator, value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)) in ind.network
    except (ValueError, TypeError):
        return False


def _path_hit(ind: Indicator, path: str) -> bool:
    return path == ind.value or (ind.value != "/" and path.startswith(ind.value.rstrip("/") + "/")) \
        or ind.value == "/"


def _word_in(value: str, text: str) -> bool:
    return re.search(r"(?<![\w.@/-])" + re.escape(value) + r"(?![\w@-])", text) is not None


def _entities(doc: dict[str, Any]) -> Iterator[tuple[str, str, str]]:
    """(rule, entity, first evidence line) of a snapshot's findings."""
    for s in doc.get("signals") or []:
        if not isinstance(s, dict):
            continue
        ev = " ".join(str(x) for x in (s.get("evidence") or [])[:6])
        for e in s.get("entities") or []:
            yield str(s.get("rule") or ""), str(e), ev
        if not s.get("entities"):
            yield str(s.get("rule") or ""), "", ev


def _match_doc(kind: str, doc: dict[str, Any], ind: Indicator) -> list[tuple[str, str, bool]]:
    """[(where, value, prefix_only)] in one snapshot."""
    out: list[tuple[str, str, bool]] = []
    idx = doc.get("hunt_index") or {}
    v = ind.value
    if kind == "persistence":
        for path, sha in idx.get("files") or []:
            if ind.kind == "sha256" and sha == v:
                out.append((f"file {path} (no package owns it) had this hash", path, False))
            elif ind.kind == "path" and _path_hit(ind, path):
                out.append((f"file {path} was a persistence item (hash {sha[:12]}…)", path, False))
        for user, fp, kpath in idx.get("keys") or []:
            if ind.kind == "account" and user == v:
                out.append((f"an SSH key of {user} in {kpath} ({fp or 'no fingerprint'})", user, False))
            elif ind.kind == "path" and _path_hit(ind, kpath):
                out.append((f"SSH key file {kpath} ({user})", kpath, False))
    if kind == "live_response":
        for exe, comm, user in idx.get("processes") or []:
            real = exe.split(" (deleted)")[0]
            if ind.kind == "program" and (comm == v or posixpath.basename(real) == v):
                where = real or "its program file could not be read by this read"
                out.append((f"program {comm or real} was running ({where}, user {user or '?'})", comm or real, False))
            elif ind.kind == "path" and real.startswith("/") and _path_hit(ind, real):
                out.append((f"{real} was running (user {user or '?'})", real, False))
            elif ind.kind == "account" and user == v:
                out.append((f"{user} was running {comm or real or 'a process'}", user, False))
        for addr in idx.get("remote_addrs") or []:
            if ind.kind == "ip" and _ip_in(ind, addr):
                out.append((f"a process had a connection with {addr}", addr, False))
        for path, sha in idx.get("temp_files") or []:
            if ind.kind == "sha256" and sha == v:
                out.append((f"temporary-folder file {path} had this hash", path, False))
            elif ind.kind == "path" and _path_hit(ind, path):
                out.append((f"temporary-folder file {path} was present", path, False))
        for lst in doc.get("listeners") or []:
            exe = str(lst.get("exe") or "")
            if exe and ((ind.kind == "path" and _path_hit(ind, exe)) or
                        (ind.kind == "program" and posixpath.basename(exe) == v)):
                out.append((f"{exe} was listening on port {lst.get('port')}/{lst.get('proto')}", exe, False))
    # the findings in the snapshot -- for snapshots older than hunt_index too
    for rule, ent, ev in _entities(doc):
        path, _, frag = ent.partition("#")
        if ind.kind == "sha256" and frag and len(frag) >= 12 and v.startswith(frag.lower()) \
                and not any(item[1] == path and not item[2] for item in out):     # a full match says it already
            out.append((f"{rule}: {path} -- hash starting {frag} (Kratos kept only the first {len(frag)} "
                        "digits for this item)", path, True))
        elif ind.kind == "path" and path.startswith("/") and _path_hit(ind, path.split("|")[0]):
            out.append((f"{rule}: {path.split('|')[0]}", path.split("|")[0], False))
        elif ind.kind in ("ip", "account", "program", "domain") and not ind.is_cidr and ev and _word_in(v, ev):
            out.append((f"{rule} mentions it", v, False))
    seen, uniq = set(), []
    for item in out:
        if item[:2] not in seen:
            seen.add(item[:2])
            uniq.append(item)
    return uniq


@dataclass
class Loaded:
    """One machine's snapshots in the hunt window, read once per hunt."""
    docs: list[tuple[str, float, str, dict[str, Any]]]     # (kind, ts, file name, doc)
    stats: dict[str, dict[str, Any]]
    packages: list[tuple[float, float, list[dict[str, Any]]]] | None = None


def load(data_dir: Path | str, machine: str, *, start: float | None, end: float | None,
         max_files: int) -> Loaded:
    data_dir = Path(data_dir)
    key = target_key(machine)
    docs: list[tuple[str, float, str, dict[str, Any]]] = []
    stats: dict[str, dict[str, Any]] = {}
    for kind, (_folder, _pattern, label) in KINDS.items():
        files, total = _files(data_dir, kind, max_files * 4)
        st = {"count": 0, "first": None, "last": None, "total_files": total, "capped": False, "label": label}
        for path in files:
            if st["count"] >= max_files:
                st["capped"] = True
                break
            try:
                doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict) or target_key(str(doc.get("target") or "")) != key:
                continue
            ts = float(doc.get("checked_at_epoch") or path.stat().st_mtime)
            if (start is not None and ts < start) or (end is not None and ts >= end):
                continue
            st["count"] += 1
            st["first"] = ts if st["first"] is None else min(st["first"], ts)
            st["last"] = ts if st["last"] is None else max(st["last"], ts)
            docs.append((kind, ts, path.name, doc))
        stats[kind] = st
    return Loaded(docs, stats)


def match(loaded: Loaded, data_dir: Path | str, machine: str, ind: Indicator, *, start: float | None,
          end: float | None) -> list[SnapHit]:
    key = target_key(machine)
    hits: list[SnapHit] = []
    for kind, ts, name, doc in loaded.docs:
        for where, value, prefix in _match_doc(kind, doc, ind):
            hits.append(SnapHit(key, kind, KINDS[kind][2], ts, name, where, value, prefix))
    if ind.kind == "program":
        if loaded.packages is None:
            loaded.packages, loaded.stats["packages"] = _load_packages(Path(data_dir), key, start, end)
        for taken, last, pkgs in loaded.packages:
            for p in pkgs:
                if isinstance(p, dict) and str(p.get("name") or "") == ind.value:
                    hits.append(SnapHit(key, "packages", "installed-package list", float(last), "pkg_inventory",
                                        f"package {ind.value} {p.get('version') or ''} was installed "
                                        f"(lists from {_d(taken)} to {_d(last)})", ind.value))
                    break
    return hits


def search(data_dir: Path | str, machine: str, ind: Indicator, *, start: float | None, end: float | None,
           max_files: int) -> tuple[list[SnapHit], dict[str, dict[str, Any]]]:
    """(hits, per kind {count, first, last, ...}) for one machine and one indicator."""
    loaded = load(data_dir, machine, start=start, end=end, max_files=max_files)
    return match(loaded, data_dir, machine, ind, start=start, end=end), loaded.stats


def _load_packages(data_dir: Path, key: str, start: float | None,
                   end: float | None) -> tuple[list[tuple[float, float, list[dict[str, Any]]]], dict[str, Any]]:
    """Installed-package lists (pkg_inventory) in the window: a program name may be a package."""
    from kratos.storage.sqlite_files import connect_store

    st: dict[str, Any] = {"count": 0, "first": None, "last": None, "label": "installed-package list"}
    out: list[tuple[float, float, list[dict[str, Any]]]] = []
    db = data_dir / "kratos.db"
    if not db.exists():
        return out, st
    conn = connect_store(db)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_schema WHERE name='pkg_inventory'").fetchone():
            return out, st
        rows = conn.execute("SELECT taken_at, last_seen_at, packages_json FROM pkg_inventory WHERE target = ? "
                            "ORDER BY taken_at DESC LIMIT 200", (key,)).fetchall()
    finally:
        conn.close()
    for taken, last, blob in rows:
        if (end is not None and taken >= end) or (start is not None and last < start):
            continue
        st["count"] += 1
        st["first"] = taken if st["first"] is None else min(st["first"], taken)
        st["last"] = last if st["last"] is None else max(st["last"], last)
        try:
            pkgs = json.loads(zlib.decompress(blob))
        except (zlib.error, ValueError, TypeError):
            continue
        out.append((float(taken), float(last), pkgs if isinstance(pkgs, list) else []))
    return out, st


def _d(ts: float) -> str:
    from kratos.hunt.coverage import fmt

    return fmt(ts)
