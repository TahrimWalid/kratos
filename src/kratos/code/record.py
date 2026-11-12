"""Run the deployed-code checks for one machine and save what the rule engine reads (E.7a).

Two calls, one per collection check:

- ``run_roots`` (check `code_roots`, quick): the configuration read + the newest running-process
  and container snapshots -> candidate code roots with why (kratos.code.roots), recorded in
  ``code_roots``; writes ``data_dir/code/roots_<machine>.json`` (the parsed web-server rules,
  never the raw configuration text).
- ``run_code`` (check `code`, slow): for each CONFIRMED root, the bounded inventory, git
  drift (parsed, never run), the no-git baseline comparison, dependencies matched offline,
  secrets (kind, line, fingerprint), web-shell YARA -> CODE-001..006; writes
  ``data_dir/code/code_<machine>.json`` (one per machine, replaced in place, evidence-recorded).

File contents are read into memory for parsing and scanning and dropped there: what is saved
is paths, sizes, modes, hashes, git states, dependency names/versions and findings.
Nothing here runs anything on the machine or calls a model.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from kratos.adapters import code_facts as CF
from kratos.code import judge as J
from kratos.code import reads as R
from kratos.code import roots as RT
from kratos.code import secrets as SEC
from kratos.code import settings as CS
from kratos.code import store as S
from kratos.code import webconf as W
from kratos.code import yara as Y
from kratos.code.deps import match as DM
from kratos.code.deps import parsers as DP
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

from kratos.code.findings import FOLDER  # noqa: E402  (one definition)
ROOTS_PATTERN = "roots_*.json"
MAX_FILES_SAVED = 5000


def _mh(target: str) -> str:
    return hashlib.sha256(target_key(target).encode()).hexdigest()[:8]


def result_path(data_dir: Path, target: str) -> Path:
    return Path(data_dir) / FOLDER / f"code_{_mh(target)}.json"


def roots_path(data_dir: Path, target: str) -> Path:
    return Path(data_dir) / FOLDER / f"roots_{_mh(target)}.json"


def _write(path: Path, doc: dict[str, Any], data_dir: Path, target: str, read: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    from kratos import evidence as _evidence

    _evidence.record(path, data_dir=data_dir, category="code", machine=target, read=read, transport=doc.get("via"))


def _failure(res: Any) -> str:
    text = (getattr(res, "stderr", "") or getattr(res, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def _old_agent(text: str) -> bool:
    return "update the agent" in text or "can't do the 'code_" in text or "no 'code_" in text


def _load(path: Path) -> dict[str, Any] | None:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def _live(data_dir: Path, target: str) -> dict[str, Any] | None:
    from kratos.hashdb.candidates import load_docs

    return load_docs(data_dir, target).get("live_response")


# =========================================================================== roots
def run_roots(data_dir: Path, target: str, *, fetch: R.Fetcher | None = None, now: float | None = None,
              live: dict[str, Any] | None = None, containers: dict[str, Any] | None = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    tk = target_key(target)
    facts = R.fetch_facts(fetch)
    notes: list[str] = []
    via = None
    if isinstance(facts, dict):
        via = facts.get("via")
        cfg = W.parse(facts.get("configs") or {})
        if facts.get("truncated_output"):
            notes.append("the configuration read was cut off: some web-server files may be missing")
    else:
        err = _failure(facts)
        via = getattr(facts, "via", None)
        notes.append(("the machine's sub-agent is too old to read web-server configurations -- update the agent "
                      "(`g` in /subagent)" if _old_agent(err) else f"the configuration read failed: {err}"))
        facts, cfg = {}, W.Config()
    if live is None:
        live = _live(data_dir, target)
    if containers is None:
        from kratos.containers import record as _crec

        containers = _crec.load(data_dir, target)
    if live is None:
        notes.append("no recent running-process read: folders of listening programs not looked at yet")
    cands, cnotes = RT.candidates(live, facts, cfg, containers)
    notes += cnotes
    rows = S.offer(data_dir, tk, cands, now=when)
    doc = {"target": tk, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when, "via": via or "ssh",
           "complete": isinstance(facts, dict) and bool(facts.get("complete")) and not facts.get("truncated_output"),
           "webconf": W.to_json(cfg), "candidates": [{"path": c["path"], "why": c["why"]} for c in cands],
           "notes": notes, "units": len((facts or {}).get("units") or {}),
           "configs_read": sum(1 for c in ((facts or {}).get("configs") or {}).values() if c.get("status") == "ok")}
    _write(roots_path(data_dir, target), doc, data_dir, target, "code_roots_facts")
    return {**doc, "status": "ok", "roots": rows, "file": str(roots_path(data_dir, target))}


def summary_roots(doc: dict[str, Any]) -> str:
    roots = doc.get("roots") or []
    conf = sum(1 for r in roots if r["status"] == "confirmed")
    cand = sum(1 for r in roots if r["status"] == "candidate")
    if not roots:
        return "none found"
    return f"{conf} confirmed, {cand} to confirm"


# =========================================================================== code
def _baseline_compare(data_dir: Path, root: dict[str, Any], current: dict[str, dict[str, Any]],
                      complete: bool) -> dict[str, Any]:
    base = S.files(data_dir, root["id"], "baseline")
    if not base:
        if complete:
            S.replace_files(data_dir, root["id"], "baseline", list(current.values()))
        return {"first": True, "added": [], "changed": [], "removed": []}
    added = sorted(k for k in current if k not in base)
    changed = sorted(k for k in current if k in base and current[k].get("sha256") and base[k].get("sha256")
                     and current[k]["sha256"] != base[k]["sha256"])
    removed = sorted(k for k in base if k not in current) if complete else []
    return {"first": False, "added": added, "changed": changed, "removed": removed}


def _git_state(data_dir: Path, path: str, inv: dict[str, Any], budget: int, fetch: R.Fetcher | None,
               notes: list[str]) -> tuple[dict[str, Any] | None, int]:
    if inv.get("git") == "file":
        notes.append(f"{path}: its .git is a file pointing to git metadata outside this folder (a linked worktree "
                     "or submodule) -- not read; compared with Kratos's own hash baseline instead")
        return None, 0
    if inv.get("git") != "dir":
        return None, 0
    used = 0
    gs = inv.get("git_state")
    if gs is None:            # over SSH: fetch the repository's files, compare on Kratos
        recs, used = R.git_records(path, inv, budget=budget, max_files=int(CS.get(CS.MAX_FILES, data_dir)),
                                   fetch=fetch)
        gs = CF.parse_inventory("\n".join(recs) + "\nEND\n").get("git_state") or {}
    reasons = gs.get("reasons") or {}
    for k, why in reasons.items():
        notes.append(f"{path}: git {k}: {why}")
    unusable = "index" in reasons or ("head" in reasons and not gs.get("head"))
    if gs.get("extra", {}).get("tracked_in_skipped"):
        notes.append(f"{path}: {gs['extra']['tracked_in_skipped']} tracked file(s) inside skipped dependency "
                     "folders were not compared (code.skip_folders)")
    if gs.get("extra", {}).get("drift_capped"):
        notes.append(f"{path}: more git differences than Kratos lists; the first {CF.MAX_DRIFT_RECORDS} are judged")
    return {"head": gs.get("head"), "drift": gs.get("drift") or [], "ignored": gs.get("ignored") or [],
            "counts": gs.get("counts") or {}, "conflicts": gs.get("conflicts") or [], "reasons": reasons,
            "unusable": unusable}, used


def _deps(data_dir: Path, path: str, inv: dict[str, Any], budget: int, fetch: R.Fetcher | None,
          notes: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    files = inv.get("files") or {}
    wanted = [rel for rel in sorted(files) if DP.kind_of(rel) and files[rel].get("status") == "ok"]
    have_gomod = {os.path.dirname(r) for r in wanted if r.endswith("go.mod")}
    wanted = [r for r in wanted if not (r.endswith("go.sum") and os.path.dirname(r) in have_gomod)]
    parsed = DP.Parsed()
    used = 0
    if wanted:
        got, info = R.read_contents(path, "deps", inv, wanted, budget=budget, fetch=fetch)
        used += int(info.get("used") or 0)
        for rel in wanted:
            item = got.get(rel) or {}
            if item.get("status") == "ok":
                DP.parse(rel, item["data"], parsed)
            else:
                notes.append(f"{path}: {rel} not read ({item.get('status')})")
        includes = [i for i in dict.fromkeys(parsed.includes) if i in files and i not in wanted]
        missing = [i for i in dict.fromkeys(parsed.includes) if i not in files]
        for i in missing:
            notes.append(f"{path}: a requirements include ({i}) is not in the folder")
        if includes and budget - used > 0:
            got2, info2 = R.read_contents(path, "deps", inv, includes, budget=budget - used, fetch=fetch)
            used += int(info2.get("used") or 0)
            for rel in includes:
                if (got2.get(rel) or {}).get("status") == "ok":
                    DP.requirements(got2[rel]["data"], rel, parsed)
        del got
    notes += [f"{path}: {n}" for n in parsed.notes]
    deps, mismatch = DP.reconcile(parsed.deps)
    notes += [f"{path}: {m}" for m in mismatch[:20]]
    from kratos.pkgvuln import settings as PS

    try:
        epss_high = float(PS.get(PS.EPSS_HIGH, data_dir))
    except Exception:  # noqa: BLE001
        epss_high = 0.1
    m = DM.match(data_dir, deps, epss_high=epss_high)
    for eco in m.missing_ecosystems:
        notes.append(f"{path}: {eco} advisories not downloaded: `kratos vulndb-update --for-roots`")
    rows = [{"ecosystem": d.ecosystem, "package": d.package, "version": d.version, "source_file": d.source_file,
             "installed": d.installed} for d in deps]
    hits = [{"ecosystem": h.ecosystem, "package": h.package, "version": h.version, "source_files": h.source_files,
             "installed": h.installed,
             "advisories": [{"osv_id": a.osv_id, "cves": a.cves, "fixed_in": a.fixed_in, "severity": a.severity,
                             "rating": a.rating, "kev": a.kev, "epss": a.epss, "cvss": a.cvss,
                             "ssvc_inputs": a.ssvc_inputs} for a in h.advisories]} for h in m.hits]
    return ({"hits": hits, "checked": m.checked, "uncomparable": m.uncomparable, "unpinned": parsed.unpinned,
             "missing_ecosystems": m.missing_ecosystems, "count": len(deps),
             "ecosystems": sorted({d.ecosystem for d in deps})}, rows, used)


def _secrets(data_dir: Path, path: str, inv: dict[str, Any], budget: int, fetch: R.Fetcher | None,
             notes: list[str]) -> tuple[list[dict[str, Any]], int]:
    files = inv.get("files") or {}
    hits = [h.__dict__ for h in SEC.key_files(files)]
    want, skipped = SEC.candidates(files)
    if skipped:
        notes.append(f"{path}: {skipped} large or minified file(s) not scanned for secrets")
    used = 0
    if want and budget > 0:
        key = SEC._key(data_dir)
        got, info = R.read_contents(path, "secrets", inv, want, budget=budget, fetch=fetch)
        used = int(info.get("used") or 0)
        if info.get("budget_hit"):
            notes.append(f"{path}: {info['budget_hit']} file(s) not scanned for secrets (code.max_read_mb reached)")
        for rel in want:
            item = got.pop(rel, None) or {}
            if item.get("status") == "ok":
                hits += [h.__dict__ for h in SEC.scan_text(rel, item["data"], key)]
            item.clear()
        del got
    return hits, used


def _known_bad(data_dir: Path, shas: set[str]) -> set[str]:
    from kratos.hashdb import store as HS

    out: set[str] = set()
    for sha in shas:
        try:
            if any(r.get("verdict") == "known_bad" for r in HS.lookup(data_dir, sha)):
                out.add(sha)
        except Exception:  # noqa: BLE001 -- a reputation is an annotation
            continue
    return out


def _check_root(data_dir: Path, target: str, root: dict[str, Any], cfg: W.Config, budget: int,
                fetch_inv: R.Fetcher | None, fetch_read: R.Fetcher | None, scanner: Y.Scanner | None,
                notes: list[str], when: float) -> tuple[dict[str, Any], int]:
    path = root["path"]
    res: dict[str, Any] = {"path": path, "root_id": root["id"], "status": "failed", "complete": False,
                           "accepted_at": epoch_to_utc_iso(root["accepted_at"]) if root.get("accepted_at") else None,
                           "serving": list(root.get("serving") or [])[:20],
                           "app_served": any((w or {}).get("kind") in ("listener", "systemd", "container")
                                             for w in root.get("why") or [])}
    inv = R.inventory(data_dir, path, fetch=fetch_inv)
    if not isinstance(inv, dict):
        err = _failure(inv)
        res["status"] = "old_agent" if _old_agent(err) else "failed"
        notes.append(f"{path}: " + ("this machine's sub-agent is too old for code checks -- update the agent (`g` in "
                                    "/subagent)" if _old_agent(err) else f"the read failed: {err}"))
        return res, 0
    res["via"] = inv.get("via")
    rstatus = (inv.get("root") or {}).get("status")
    if rstatus in ("missing", "not_dir"):
        S.mark_gone(data_dir, root, True, now=when)
        res["status"] = "gone"
        notes.append(f"{path}: the folder is no longer there (deleted or moved) -- confirm its new place with "
                     "`kratos code add`")
        return res, 0
    if rstatus in ("unreadable", "symlink"):
        res["status"] = rstatus
        notes.append(f"{path}: " + ("this login can't read the folder -- the sub-agent can, or grant this login read "
                                    "access" if rstatus == "unreadable" else "the folder is a symbolic link (or "
                                    "inside one) -- confirm the real folder instead"))
        return res, 0
    S.mark_gone(data_dir, root, False, now=when)
    complete = bool(inv.get("complete"))
    res["complete"] = complete
    totals = inv.get("totals") or {}
    if totals.get("capped") == "1":
        notes.append(f"{path}: more than {CS.get(CS.MAX_FILES, data_dir)} files -- the rest were not listed "
                     "(code.max_files)")
    if totals.get("timed_out") == "1":
        notes.append(f"{path}: the listing took longer than code.inventory_seconds and stopped part-way")
    if totals.get("depth_capped") == "1":
        notes.append(f"{path}: folders deeper than code.max_depth were not listed")
    unread = [k for k, f in (inv.get("files") or {}).items() if f.get("status") not in ("ok",)]
    if unread:
        notes.append(f"{path}: {len(unread)} file(s) could not be hashed (changed while read, hard-linked, too large "
                     "or unreadable)")
    for s in inv.get("skipped") or []:
        if s["reason"] == "other_device":
            notes.append(f"{path}: {s['path']} is another filesystem -- not walked")
    used = 0
    git, u = _git_state(data_dir, path, inv, budget, fetch_read, notes)
    used += u
    res["git"] = git
    status_of: dict[str, str] = {}
    if git and not git.get("unusable"):
        for d in git["drift"]:
            status_of[d["path"]] = d["class"]
        for p in git["ignored"]:
            status_of[p] = "ignored"
    rows = []
    for rel, f in (inv.get("files") or {}).items():
        rows.append({"relpath": rel, "size": f.get("size"), "mode": f.get("mode"), "sha256": f.get("sha256"),
                     "blob": f.get("blob"), "mtime": f.get("mtime"),
                     "git_status": status_of.get(rel, "tracked" if git and not git.get("unusable") else "-")})
    current = {r["relpath"]: r for r in rows}
    if complete:
        S.replace_files(data_dir, root["id"], "current", rows, at=when)
    if not git or git.get("unusable"):
        res["baseline"] = _baseline_compare(data_dir, root, current, complete)
    res["files"] = {r["relpath"]: {"sha256": r["sha256"], "size": r["size"], "mode": r["mode"]} for r in rows}
    deps, dep_rows, u = _deps(data_dir, path, inv, max(0, budget - used), fetch_read, notes)
    used += u
    res["deps"] = deps
    if complete:
        S.replace_deps(data_dir, root["id"], dep_rows, at=when)
    sec, u = _secrets(data_dir, path, inv, max(0, budget - used), fetch_read, notes)
    used += u
    res["secrets"] = sec
    yara, why = Y.scan(path, scanner)
    if why:
        notes.append(f"{path}: {why}")
    res["yara"] = yara
    counts = {"files": len(rows), "bytes": sum(int(r.get("size") or 0) for r in rows),
              "skipped_folders": len(inv.get("skipped") or []),
              "skipped_files": sum(int(s.get("count") or 0) for s in inv.get("skipped") or []),
              "links": len(inv.get("links") or {})}
    if git and git.get("counts"):
        counts["git"] = git["counts"]
    res["counts"] = counts
    res["status"] = "ok" if complete else "partial"
    return res, used


def run_code(data_dir: Path, target: str, *, fetch_inv: R.Fetcher | None = None, fetch_read: R.Fetcher | None = None,
             scanner: Y.Scanner | None = None, now: float | None = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    tk = target_key(target)
    all_roots = S.roots(data_dir, tk)
    confirmed = [r for r in all_roots if r["status"] == "confirmed"][:int(CS.get(CS.MAX_ROOTS, data_dir))]
    cand = [r for r in all_roots if r["status"] == "candidate"]
    rdoc = _load(roots_path(data_dir, target)) or {}
    cfg = W.from_json(rdoc.get("webconf"))
    notes: list[str] = []
    if cand:
        notes.append(f"{len(cand)} folder(s) look like served code but no person has confirmed them, so they were not "
                     f"read: {', '.join(r['path'] for r in cand[:5])}" + (" ..." if len(cand) > 5 else "")
                     + " (`/code` or `kratos code confirm`)")
    notes += [n for n in rdoc.get("notes") or [] if "partly read" in n or "variable" in n]
    budget = int(CS.get(CS.MAX_READ_MB, data_dir)) * 1024 * 1024
    results: list[dict[str, Any]] = []
    vias: set[str] = set()
    for root in confirmed:
        res, used = _check_root(data_dir, target, root, cfg, budget, fetch_inv, fetch_read, scanner, notes, when)
        budget = max(0, budget - used)
        results.append(res)
        if res.get("via"):
            vias.add(str(res["via"]))
    shas = {f["sha256"] for r in results for rel, f in (r.get("files") or {}).items() if f.get("sha256")
            and (any(d["path"] == rel for d in (r.get("git") or {}).get("drift") or [])
                 or rel in ((r.get("baseline") or {}).get("added") or []) + ((r.get("baseline") or {}).get("changed")
                                                                              or []))}
    bad = _known_bad(data_dir, shas)
    signals: list[dict[str, Any]] = []
    group_after = int(CS.get(CS.GROUP_AFTER, data_dir))
    for res in results:
        if res.get("status") in ("ok", "partial"):
            signals += J.judge_root(res, cfg, known_bad=bad, group_after=group_after)
    note = J.run_note(tk, notes)
    if note:
        signals.append(note)
    for res in results:          # what is saved: no file list beyond the cap, never contents
        files = res.get("files") or {}
        if len(files) > MAX_FILES_SAVED:
            res["files_saved"] = MAX_FILES_SAVED
            res["files"] = dict(sorted(files.items())[:MAX_FILES_SAVED])
    doc = {"target": tk, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when,
           "via": ",".join(sorted(vias)) or "ssh",
           "complete": bool(confirmed) and all(r.get("status") == "ok" for r in results),
           "roots": results, "candidates": [r["path"] for r in cand], "signals": signals, "coverage_gaps": notes,
           "answer_gaps": notes[:2], "read_bytes": int(CS.get(CS.MAX_READ_MB, data_dir)) * 1024 * 1024 - budget}
    _write(result_path(data_dir, target), doc, data_dir, target, "code_inventory")
    return {**doc, "status": "ok", "file": str(result_path(data_dir, target))}


def summary_code(doc: dict[str, Any]) -> str:
    roots = doc.get("roots") or []
    if not roots:
        n = len(doc.get("candidates") or [])
        return (f"no confirmed code folders ({n} waiting for a person to confirm in /code)" if n
                else "no confirmed code folders")
    worst = sorted({str(s.get("rule")) for s in doc.get("signals") or [] if s.get("rule") != "CODE-006"})
    lead = f"something to look at ({', '.join(worst)})" if worst else "no drift, vulnerable dependency or secret found"
    files = sum(int((r.get("counts") or {}).get("files") or 0) for r in roots)
    waiting = len(doc.get("candidates") or [])
    return (f"{lead}; {len(roots)} code folder(s), {files} file(s) checked"
            + (f", {waiting} more to confirm" if waiting else ""))
