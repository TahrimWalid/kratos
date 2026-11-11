"""Which files get a reputation: candidates from Kratos's own snapshots only (E.4 §3.5).

The persistence read (A.1) and the running-process read (A.5) save a bounded
`hash_candidates` list with their snapshot (`from_persistence` / `from_live`): the
executables and libraries they found -- SUID/SGID files, programs a startup line names
(cron, systemd ExecStart=, rc.local, udev RUN+=, shell startup, ld.so.preload), loaded
kernel modules, running programs no package owns and deleted or memory-only ones,
executables dropped in temporary folders. Nothing else is ever a candidate: not a path
the model names, not a path from the wire. Container image layers never are (the
persistence read already prunes them; D.5 judges containers).

`select()` merges the newest snapshots of one machine (each at most a day old, as the
findings engine loads them), orders them most suspicious first -- already known-bad by
the hash the snapshot saw, then running, then setuid, then dropped, then the rest --
and caps them at `hashdb.max_files`. What is left over is a stated gap, never silence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MAX_SAVED = 2000            # per snapshot
_SO_SUFFIXES = (".so", ".ko", ".ko.xz", ".ko.zst", ".ko.gz")


def _is_exec(perm: str) -> bool:
    try:
        return bool(int(perm, 8) & 0o6111)
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------- what reads save
def from_persistence(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """The executables/libraries a persistence inventory found, as saved candidates."""
    items = inv.get("items") or {}
    verify = inv.get("verify") or {}
    changed = {p for p, i in (verify.get("changed") or {}).items() if isinstance(i, dict) and i.get("content_changed")}
    out: dict[str, dict[str, Any]] = {}

    def add(path: str, use: str, *, package: Any = None, sha256: Any = None, suid: bool = False,
            item: dict[str, Any] | None = None) -> None:
        if not isinstance(path, str) or not path.startswith("/"):
            return
        c = out.setdefault(path, {"path": path, "uses": [], "package": None, "sha256": None, "suid": False,
                                  "source": "persistence"})
        if use not in c["uses"]:
            c["uses"].append(use)
        c["package"] = c["package"] or package
        c["sha256"] = c["sha256"] or (str(sha256).lower() if sha256 else None)
        c["suid"] = c["suid"] or suid
        if item is not None:
            c["perm"] = item.get("perm")
            c["uid"] = item.get("uid")
        if path in changed:
            c["package_verify"] = "changed"
        elif verify.get("done") and c["package"]:
            c["package_verify"] = c.get("package_verify") or "unchanged"

    for path, it in sorted(items.items()):
        typ = str(it.get("type") or "")
        if typ and not typ.startswith("regular"):
            continue
        if it.get("suid_bits"):
            perm = str(it.get("perm") or "")
            what = "setuid program" if perm[:1] in "4567" else "setgid program"
            add(path, what, package=it.get("package"), sha256=it.get("sha256"), suid=True, item=it)
        elif _is_exec(str(it.get("perm") or "")) or path.endswith(_SO_SUFFIXES):
            add(path, f"a program in a startup location ({it.get('area') or 'persistence'})",
                package=it.get("package"), sha256=it.get("sha256"), item=it)
    for ref, pkg in sorted((inv.get("refs") or {}).items()):
        add(ref, "named by a line that starts programs (cron, a unit, a boot or startup script)", package=pkg)
    for m in (inv.get("modules") or {}).values():
        if m.get("path"):
            add(str(m["path"]), f"loaded kernel module {m.get('name')}", package=m.get("package"))
    return list(out.values())[:MAX_SAVED]


def from_live(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """Running programs no package owns, deleted or memory-only running programs, and
    executables dropped in temporary folders, as saved candidates."""
    from kratos.adapters import live_response as _L

    out: dict[str, dict[str, Any]] = {}
    reader = inv.get("reader_uid")
    for pid, it in sorted((inv.get("procs") or {}).items()):
        exe = str(it.get("exe") or "")
        if not exe:
            continue                      # kernel thread, or unreadable
        base, marker = _L._split_marker(exe)
        real = _L._exe_real_path(exe)
        gone = bool(marker) or "memfd:" in base
        if not gone and it.get("exe_package"):
            continue                      # a packaged program running normally: not a candidate
        # a deleted/memory-only image is read through /proc/<pid>/exe (the agent can; over
        # SSH only for the login's own processes)
        path = f"/proc/{int(pid)}/exe" if gone else real
        if not path:
            continue
        c = out.setdefault(path, {"path": path, "uses": [], "package": None if gone else it.get("exe_package"),
                                  "sha256": None, "running": [], "source": "live"})
        c["running"].append(int(pid))
        c["uses"] = [f"running (pid {', '.join(str(p) for p in c['running'][:5])})"]
        if gone:
            c["image_of"] = base or exe
            c["proc_uid"] = it.get("uid")
            c["reader_uid"] = reader
    for path, it in sorted((inv.get("temp_files") or {}).items()):
        if str(it.get("header") or "") not in ("elf", "script"):
            continue
        c = out.setdefault(path, {"path": path, "uses": [], "package": None, "sha256": None, "running": [],
                                  "source": "live"})
        c["uses"].append("dropped in a temporary folder")
        c["dropped"] = True
        if it.get("sha256"):
            c["sha256"] = str(it["sha256"]).lower()
    return list(out.values())[:MAX_SAVED]


# --------------------------------------------------------------------------- choosing
@dataclass
class Selection:
    chosen: list[dict[str, Any]] = field(default_factory=list)
    over_cap: list[dict[str, Any]] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)    # snapshot kind -> its checked_at
    missing: list[str] = field(default_factory=list)         # snapshot kinds with no recent read
    snapshot_paths: frozenset[str] = frozenset()             # every path a recent snapshot listed


def _rank(c: dict[str, Any], known_bad: Callable[[str], bool]) -> tuple[int, str]:
    if c.get("sha256") and known_bad(c["sha256"]):
        tier = 0
    elif c.get("running"):
        tier = 1
    elif c.get("suid"):
        tier = 2
    elif c.get("dropped"):
        tier = 3
    else:
        tier = 4
    # within a tier: files no package owns first
    return (tier * 2 + (1 if c.get("package") else 0), c["path"])


def merge(docs: dict[str, dict[str, Any] | None]) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[str]]:
    merged: dict[str, dict[str, Any]] = {}
    sources: dict[str, str] = {}
    missing: list[str] = []
    for kind in ("persistence", "live_response"):
        doc = docs.get(kind)
        if not doc:
            missing.append(kind)
            continue
        sources[kind] = str(doc.get("checked_at") or "")
        for c in doc.get("hash_candidates") or []:
            if not isinstance(c, dict) or not str(c.get("path") or "").startswith("/"):
                continue
            m = merged.setdefault(c["path"], {"path": c["path"], "uses": [], "package": None, "sha256": None,
                                              "running": [], "seen_at": doc.get("checked_at")})
            for u in c.get("uses") or []:
                if u not in m["uses"]:
                    m["uses"].append(str(u))
            for k in ("package", "sha256", "suid", "dropped", "perm", "uid", "image_of", "proc_uid", "reader_uid",
                      "package_verify"):
                if c.get(k) and not m.get(k):
                    m[k] = c[k]
            m["running"] = sorted(set(m.get("running") or []) | set(c.get("running") or []))
    return merged, sources, missing


def select(docs: dict[str, dict[str, Any] | None], *, max_files: int,
           known_bad: Callable[[str], bool] = lambda _h: False) -> Selection:
    merged, sources, missing = merge(docs)
    ordered = sorted(merged.values(), key=lambda c: _rank(c, known_bad))
    return Selection(ordered[:max_files], ordered[max_files:], sources, missing, frozenset(merged))


def load_docs(data_dir: Path, target: str) -> dict[str, dict[str, Any] | None]:
    """The machine's newest persistence and live-response snapshots, each only when the
    findings engine would still use it (at most a day old, this machine's)."""
    from kratos.adapters import findings_engine as FE

    found = FE.find_latest_inputs(Path(data_dir), target)
    out: dict[str, dict[str, Any] | None] = {}
    for kind in ("persistence", "live_response"):
        src = FE.SNAPSHOT_SOURCES.get(kind)
        path = found.get(kind)
        out[kind] = src.load(path) if (src and path) else None
    return out
