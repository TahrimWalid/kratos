"""What every surface shows about a machine's code folders (E.7a §3.12): candidates with why,
confirmed folders with their git state, drift counts, dependencies and secret kinds, and the
files of one folder. Read-only; machine text (paths, why) is cleaned where it is shown."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kratos.code import record as REC
from kratos.code import store as S
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso


class ViewError(ValueError):
    """Refused, or nothing to show; the message is plain words."""


def resolve_code_reader(data_dir: Path | str, actor: Any, machine: str | None) -> tuple[str, Any]:
    """(target_key, scope) after `code.read` for this machine; refused outside scope. Only a
    person at the Kratos host gets the default machine implicitly (a network door names one
    of its machines -- naming the default in a refusal would tell an outsider it exists)."""
    from kratos import authz

    if not machine:
        if getattr(actor, "interface", None) not in ("tui", "cli"):
            raise ViewError("which machine? (name one of your machines)")
        from kratos.kratos_config import get_active_target

        machine = get_active_target()
    if not machine:
        raise ViewError("which machine?")
    try:
        p = authz.require(actor, authz.P.CODE_READ, machine, data_dir=data_dir, obj="code view")
    except authz.Denied as e:
        raise ViewError(str(e)) from None
    return target_key(machine), p.scope


def _load(path: Path) -> dict[str, Any]:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def view(data_dir: Path | str, machine: str) -> dict[str, Any]:
    data_dir = Path(data_dir)
    tk = target_key(machine)
    doc = _load(REC.result_path(data_dir, tk))
    rdoc = _load(REC.roots_path(data_dir, tk))
    results = {r.get("path"): r for r in doc.get("roots") or []}
    out: dict[str, Any] = {"machine": tk, "checked_at": doc.get("checked_at"), "roots_checked_at": rdoc.get("checked_at"),
                           "roots": [], "notes": list(doc.get("coverage_gaps") or []),
                           "discovery_notes": list(rdoc.get("notes") or [])}
    for r in S.roots(data_dir, tk):
        res = results.get(r["path"]) or {}
        git = res.get("git") or {}
        deps = res.get("deps") or {}
        sev: dict[str, int] = {}
        for s in doc.get("signals") or []:
            if str(s.get("subject") or "").split("|", 1)[0] == r["path"]:
                sev[s["rule"]] = sev.get(s["rule"], 0) + 1
        out["roots"].append({
            "id": r["id"], "path": r["path"], "status": r["status"], "source": r["source"],
            "why": [w.get("detail") for w in r.get("why") or []][:8],
            "decided_by": r.get("decided_by"), "decided_at": epoch_to_utc_iso(r["decided_at"]) if r.get("decided_at") else None,
            "accepted_at": epoch_to_utc_iso(r["accepted_at"]) if r.get("accepted_at") else None,
            "gone": r.get("gone_since") is not None,
            "read": res.get("status"), "via": res.get("via"),
            "git": ({"commit": (git.get("head") or {}).get("commit"), "ref": (git.get("head") or {}).get("ref"),
                     "counts": git.get("counts") or {}, "usable": not git.get("unusable")} if git else None),
            "no_git": res.get("baseline") is not None,
            "files": (res.get("counts") or {}).get("files"),
            "dependencies": deps.get("count"), "ecosystems": deps.get("ecosystems") or [],
            "vulnerable_dependencies": len(deps.get("hits") or []),
            "secrets": len(res.get("secrets") or []), "findings": sev,
        })
    return out


def files(data_dir: Path | str, machine: str, root_path: str, limit: int = 500) -> list[dict[str, Any]]:
    tk = target_key(machine)
    root = next((r for r in S.roots(data_dir, tk) if r["path"] == root_path), None)
    if root is None:
        raise ViewError("Kratos doesn't know that folder for this machine")
    rows = sorted(S.files(data_dir, root["id"], "current").values(),
                  key=lambda f: (f.get("git_status") in ("tracked", "-"), f["relpath"]))
    return [{k: f.get(k) for k in ("relpath", "size", "mode", "sha256", "git_status")} for f in rows[:limit]]


def to_text(v: dict[str, Any]) -> str:
    lines = [f"Code folders on {v['machine']}" + (f" (last code check {v['checked_at']})" if v.get("checked_at") else "")]
    if not v["roots"]:
        lines.append("  none found yet -- run `kratos collect --target <machine> --force`, or add one: "
                     "`kratos code add <machine> <folder>`")
    for r in v["roots"]:
        head = f"  [{r['status']}] {r['path']}" + ("  (no longer there)" if r["gone"] else "")
        lines.append(head)
        for w in r["why"][:4]:
            lines.append(f"      why: {w}")
        if r["status"] != "confirmed":
            continue
        if r["git"]:
            g = r["git"]
            c = g["counts"]
            lines.append(f"      git: {g.get('ref') or 'detached'} @ {str(g.get('commit') or '?')[:12]}; "
                         + ", ".join(f"{n} {k}" for k, n in sorted(c.items()) if k != "ignored") or "no drift")
        elif r["no_git"]:
            lines.append(f"      no git: compared with the state accepted {r['accepted_at'] or 'at the first read'}")
        if r["read"]:
            lines.append(f"      read: {r['read']} via {r['via']}; {r['files'] or 0} files; {r['dependencies'] or 0} "
                         f"dependencies ({', '.join(r['ecosystems']) or 'none'}), {r['vulnerable_dependencies']} "
                         f"vulnerable; {r['secrets']} secret(s)")
        if r["findings"]:
            lines.append("      findings: " + ", ".join(f"{k} x{n}" for k, n in sorted(r["findings"].items())))
    for n in v["notes"][:20]:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def compact(v: dict[str, Any]) -> dict[str, Any]:
    """For MCP and chat: the same facts, without the per-file list."""
    return {"machine": v["machine"], "checked_at": v.get("checked_at"),
            "roots": [{k: r[k] for k in ("path", "status", "why", "git", "no_git", "read", "files", "dependencies",
                                         "vulnerable_dependencies", "secrets", "findings", "gone")} for r in v["roots"]],
            "notes": v["notes"][:20]}
