"""Run the live-response read, judge it, and save what the rule engine reads (A.5).

One call: read ``/proc`` (over SSH as the SSH user, or through the machine's
sub-agent as root -- ``ssh_remote.fetch_live_response`` routes it), judge it
(``judge``), and write ``data_dir/live/live_response_<time>.json``.
``correlate_findings`` picks that file up like any other input
(``findings_engine.find_latest_inputs``, category ``live_response``) and turns its
``signals`` into LIVE-* findings.

Live-response findings are point-in-time, so there is no baseline: the read
describes what is running at the moment it ran. Nothing is written on the
monitored machine, and nothing here calls a model.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from kratos.live.judge import judge
from kratos.utils.timeutil import epoch_to_utc_iso

LIVE_DIR = "live"
FILE_GLOB = "live_response_*.json"

Reader = Callable[[], Any]


def _default_reader() -> Any:
    from kratos.adapters.ssh_remote import fetch_live_response

    return fetch_live_response()


def _failure_text(result: Any) -> str:
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def _counts(inv: dict[str, Any]) -> dict[str, int]:
    procs = inv.get("procs") or {}
    socks = inv.get("sockets") or []
    temp = inv.get("temp_files") or {}
    return {
        "processes": len(procs),
        "listening": sum(1 for s in socks if str(s.get("state") or "").upper() == "0A"),
        "temp_executables": sum(1 for it in temp.values() if str(it.get("header") or "") in ("elf", "script")),
        "deleted": sum(1 for it in procs.values() if str(it.get("exe") or "").endswith(" (deleted)")),
    }


def run(data_dir: Path, target: str, *, reader: Reader | None = None,
        now: float | None = None, run_id: str | None = None) -> dict[str, Any]:
    """Read, judge, save. Returns the saved document plus `file` (its path), or
    `{"status": "error", ...}` when the read itself failed (nothing is saved -- a
    failed read must never become "nothing running")."""
    data_dir = Path(data_dir)
    reader = reader or _default_reader
    when = time.time() if now is None else now
    result = reader()
    if not isinstance(result, dict):
        return {"status": "error", "target": target, "observation": _failure_text(result)}

    inv = result
    judged = judge(inv)
    coverage_gaps: list[str] = []
    for s in judged.signals:
        if s.rule == "LIVE-007":
            coverage_gaps = [ln.strip() for ln in s.evidence]
    doc: dict[str, Any] = {
        "target": target,
        "checked_at": epoch_to_utc_iso(when),
        "checked_at_epoch": when,
        "via": inv.get("via") or "ssh",
        "family": inv.get("family"),
        "reader_uid": inv.get("reader_uid"),
        "complete": bool(inv.get("complete")) and not inv.get("truncated_output"),
        "ownership": inv.get("ownership") or {},
        "counts": _counts(inv),
        "coverage_gaps": coverage_gaps,
        "answer_gaps": list(getattr(judged, "answer_gaps", [])),
        "signals": [s.as_dict() for s in judged.signals],
        "blind": blind_spots(inv),
        "listeners": listeners(inv),
        "hunt_index": _hunt_index(inv),      # C.3: programs, users, remote addresses a later hunt can find
    }
    out_dir = data_dir / LIVE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"live_response_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return {**doc, "status": "ok", "file": str(path)}


def _hunt_index(inv: dict[str, Any]) -> dict[str, Any]:
    from kratos.hunt.snapshots import live_index

    return live_index(inv)


MAX_BLIND_ITEMS = 5000
MAX_LISTENERS = 500


def listeners(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """Each listening socket with the program behind it, when this read could see it:
    {port, proto, seen, exe, package}. `seen` is False when the owning process is not
    known (another user's socket over SSH); `package` is None for a program no package
    owns (or one running from memory/a deleted file). Used by the package cross-check
    (kratos.pkgvuln.crosscheck.listener_doubts)."""
    from kratos.adapters import live_response as _L

    procs = inv.get("procs") or {}
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for sock in inv.get("sockets") or []:
        proto = str(sock.get("proto") or "")
        state = str(sock.get("state") or "").upper()
        listening = state == "0A" if proto.startswith("tcp") else state == "07" and not sock.get("remote_port")
        port = sock.get("local_port")
        if not listening or not isinstance(port, int) or (proto, port) in seen:
            continue
        seen.add((proto, port))
        it = procs.get(sock.get("pid")) or {}
        seen_exe = bool(it.get("exe"))       # the process and its program link were readable
        exe = _L._exe_real_path(str(it.get("exe") or "")) if seen_exe else None
        out.append({"port": port, "proto": proto.rstrip("6"), "seen": seen_exe,
                    "exe": exe or (str(it.get("exe")) if seen_exe else None),
                    "package": it.get("exe_package") if exe else None})
        if len(out) >= MAX_LISTENERS:
            break
    return out


def blind_spots(inv: dict[str, Any]) -> dict[str, Any]:
    """What this read could not look at, saved with the snapshot so the finding
    lifecycle doesn't take "not seen" for "gone" (entity_blind)."""
    procs = inv.get("procs") or {}
    unseen = []
    for pid in sorted(inv.get("proc_gap_pids") or {}):
        start = (procs.get(pid) or {}).get("starttime")
        unseen.append(f"{pid}|{start if start is not None else '*'}")
    return {
        "reader_root": inv.get("reader_uid") == 0,
        "hidepid": bool(inv.get("hidepid")),
        "unseen_processes": unseen[:MAX_BLIND_ITEMS],
        "unseen_processes_capped": len(unseen) > MAX_BLIND_ITEMS,
        "unopened_dirs": sorted(set(inv.get("temp_denied") or []) | set(inv.get("temp_timeouts") or []))[:MAX_BLIND_ITEMS],
        "temp_list_capped": any(t.get("what") == "temp files" for t in inv.get("truncated") or []),
    }


def _under(path: str, folders: list[str]) -> str | None:
    for d in folders:
        d = d.rstrip("/") or "/"
        if path == d or path.startswith(d + "/"):
            return d
    return None


def entity_blind(doc: dict[str, Any]) -> Callable[[str, str], str | None] | None:
    """For a saved snapshot: (rule, entity) -> why this read could not have seen it, or None.
    Entities are `exe|pid|starttime` (a process) and `path#sha256` (a dropped file).
    A snapshot saved before blind spots were recorded has none (None)."""
    blind = doc.get("blind")
    if not isinstance(blind, dict):
        return None
    root = bool(blind.get("reader_root"))
    hidden = bool(blind.get("hidepid")) and not root
    unseen = set(blind.get("unseen_processes") or [])
    capped = bool(blind.get("unseen_processes_capped"))
    dirs = [str(d) for d in blind.get("unopened_dirs") or []]
    temp_capped = bool(blind.get("temp_list_capped"))

    def why(_rule: str, entity: str) -> str | None:
        parts = entity.rsplit("|", 2)
        if len(parts) == 3 and parts[1].isdigit():
            pid, start = parts[1], parts[2]
            if hidden:
                return "/proc hides other users' processes from this login"
            if f"{pid}|{start}" in unseen or f"{pid}|*" in unseen:
                return "the process is still there but this login could not read it"
            if capped:
                return "too many processes could not be read to tell"
            return None
        path = entity.split("#", 1)[0]
        if path.startswith("/"):
            d = _under(path, dirs)
            if d:
                return f"this login could not open {d}"
            if temp_capped:
                return "more temp files than the read looks at"
        return None
    return why


def summary_line(doc: dict[str, Any]) -> str:
    """The one plain line the collection digest shows (Kratos's own words)."""
    counts = doc.get("counts") or {}
    procs = int(counts.get("processes") or 0)
    signals = [s for s in doc.get("signals") or [] if str(s.get("rule")) != "LIVE-007"]
    head = f"{procs} running process(es) checked"
    if signals:
        worst = ", ".join(sorted({str(s.get("rule")) for s in signals}))
        return f"{head}; something to look at ({worst})"
    return f"{head}; nothing unusual"
