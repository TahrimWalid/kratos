"""The core side of the deployed-code reads (E.7a §3.2, §3.3, §3.6).

- ``inventory(root)``: the bounded walk of one confirmed root (paged through the sub-agent).
- ``read_contents(root, purpose, inventory, rels, budget)``: file contents for one closed
  purpose -- only files the root's LATEST inventory listed (refused before sending
  otherwise; the agent checks its own walk again), in batches that fit one agent reply,
  within a byte budget. Contents are returned to the caller in memory; nothing here writes
  them anywhere.
- ``git_records(root, inventory, budget)``: over SSH, fetch the repository's own files and
  compute the drift on Kratos with the same code the agent runs (kratos.code.gitread).
- ``read_for_review(...)``: the ``review`` purpose, for a person-started E.7b prepare only.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, Callable

from kratos import settings_store
from kratos.adapters import code_facts as CF
from kratos.code import gitread as G
from kratos.code import settings as CS

BATCH_BYTES = CF.AGENT_READ_MB * 1024 * 1024
REVIEW_EXTS_BASE = (".py",)
REVIEW_EXTS_EXTRA = (".php", ".js", ".mjs", ".ts")


class NotInInventory(ValueError):
    """A path the root's latest inventory didn't list: never sent."""


class ReviewRefused(PermissionError):
    """The review purpose was asked for by something other than a person-started prepare."""


Fetcher = Callable[..., Any]


def _ssh() -> Any:
    from kratos.adapters import ssh_remote

    return ssh_remote


def fetch_facts(fetch: Fetcher | None = None) -> Any:
    return (fetch or _ssh().fetch_code_roots_facts)()


def inventory(data_dir: Path, root: str, *, fetch: Fetcher | None = None) -> Any:
    raw = os.fsencode(root)
    CF.check_root(raw)
    return (fetch or _ssh().fetch_code_inventory)(
        raw, max_files=int(CS.get(CS.MAX_FILES, data_dir)), max_depth=int(CS.get(CS.MAX_DEPTH, data_dir)),
        seconds=int(CS.get(CS.SECONDS, data_dir)), skip=CS.skip_folders(data_dir),
        max_pack_mb=int(CS.get(CS.MAX_PACK_MB, data_dir)))


def _listed_size(inv: dict[str, Any], rel: str) -> int | None:
    f = (inv.get("files") or {}).get(rel)
    if f is not None:
        return int(f.get("size") or 0)
    if rel.startswith(".git/"):
        g = (inv.get("gitfiles") or {}).get(rel[5:])
        if g is not None or rel[5:] in (inv.get("gitfiles") or {}):
            return int(g or 0)
    return None


def read_contents(root: str, purpose: str, inv: dict[str, Any], rels: list[str], *, budget: int,
                  fetch: Fetcher | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """({rel: {status, size, sha256, data}}, info {via, used, budget_hit, error}). Every rel
    must be in `inv` (the root's latest inventory); a file whose purpose doesn't allow it, or
    that would pass the budget, is skipped with its reason."""
    fetch = fetch or _ssh().fetch_code_read
    raw_root = os.fsencode(root)
    out: dict[str, dict[str, Any]] = {}
    info: dict[str, Any] = {"via": None, "used": 0, "budget_hit": 0, "error": "", "uid": None}
    batch: list[tuple[str, int]] = []
    batch_bytes = 0
    planned = 0

    def flush() -> None:
        nonlocal batch, batch_bytes
        if not batch:
            return
        res = fetch(raw_root, purpose, [os.fsencode(r) for r, _s in batch], budget_bytes=max(1, batch_bytes))
        if not isinstance(res, dict):
            err = (getattr(res, "stderr", "") or getattr(res, "stdout", "") or "the read failed").strip()
            info["error"] = " ".join(err.split())[:300]
            info["via"] = getattr(res, "via", None) or info["via"]
            for r, _s in batch:
                out[r] = {"status": "read_failed", "size": None, "sha256": None, "data": None}
        else:
            info["via"] = res.get("via") or info["via"]
            info["uid"] = res.get("uid", info["uid"])
            for i, (r, _s) in enumerate(batch):
                item = (res.get("files") or {}).get(i) or {"status": "read_failed", "size": None, "sha256": None,
                                                           "data": None}
                out[r] = item
                if item.get("status") == "ok":
                    info["used"] += len(item.get("data") or b"")
        batch, batch_bytes = [], 0

    for rel in rels:
        size = _listed_size(inv, rel)
        if size is None:
            raise NotInInventory(f"{rel!r} is not in this root's latest inventory")
        why = CF.purpose_allows(purpose, os.fsencode(rel), size)
        if why is not None:
            out[rel] = {"status": "too_large" if why == "too_large" else "refused", "size": size, "sha256": None,
                        "data": None, "why": why}
            continue
        if planned + size > budget:
            out[rel] = {"status": "budget", "size": size, "sha256": None, "data": None}
            info["budget_hit"] += 1
            continue
        planned += size
        if batch and (batch_bytes + size > BATCH_BYTES or len(batch) >= 2000):
            flush()
        batch.append((rel, size))
        batch_bytes += size
    flush()
    return out, info


# --------------------------------------------------------------------------- git over SSH
_GIT_TOP = ("HEAD", "config", "index", "packed-refs", "info/exclude")
MAX_LOOSE_OBJECTS = 5000      # over SSH each fetched file costs; a repository with more is compared by index


def git_wanted(inv: dict[str, Any], budget: int) -> tuple[list[str], str]:
    """The repository files to fetch for a drift comparison, smallest-first within the
    budget, and why the HEAD tree can't be compared (empty when it can)."""
    gf: dict[str, int | None] = inv.get("gitfiles") or {}
    meta = [k for k in gf if k in _GIT_TOP or k.startswith("refs/") or k.startswith("sharedindex.")
            or k == "objects/info/alternates"]
    objects = [k for k in gf if k.startswith("objects/") and k not in meta]
    want = [f".git/{k}" for k in sorted(meta)]
    used = sum(int(gf.get(k) or 0) for k in meta)
    reason = ""
    if "objects/info/alternates" in gf:
        reason = "HEAD comparison skipped: the objects are stored outside this folder (alternates); index comparison done"
        return want, reason
    obj_bytes = sum(int(gf.get(k) or 0) for k in objects)
    loose = sum(1 for k in objects if not k.startswith("objects/pack/"))
    if loose > MAX_LOOSE_OBJECTS:
        reason = (f"HEAD comparison skipped: {loose} loose objects (more than {MAX_LOOSE_OBJECTS} fetched over SSH; "
                  "the sub-agent compares them on the machine); index comparison done")
    elif used + obj_bytes > budget:
        reason = "HEAD comparison skipped: pack too large; index comparison done"
    else:
        want += [f".git/{k}" for k in sorted(objects)]
    return want, reason


def git_records(root: str, inv: dict[str, Any], *, budget: int, max_files: int,
                fetch: Fetcher | None = None) -> tuple[list[str], int]:
    """Over SSH: fetch the repository's files and the work tree's .gitignore/.gitattributes
    (purpose `git`), run the same comparison the agent runs, return (records, bytes used)."""
    want, reason = git_wanted(inv, budget)
    ignore_rels = [r for r in (inv.get("files") or {}) if r.rsplit("/", 1)[-1] in (".gitignore", ".gitattributes")]
    got, info = read_contents(root, "git", inv, want + ignore_rels[:G.MAX_IGNORE_FILES], budget=budget, fetch=fetch)
    files = {k[5:]: v["data"] for k, v in got.items() if k.startswith(".git/") and v.get("status") == "ok"}
    if reason:
        files = {k: v for k, v in files.items() if not k.startswith("objects/")}
    ignores = {k: v["data"].decode("utf-8", "replace") for k, v in got.items()
               if k.rsplit("/", 1)[-1] == ".gitignore" and v.get("status") == "ok"}
    attrs = {k: v["data"].decode("utf-8", "replace") for k, v in got.items()
             if k.rsplit("/", 1)[-1] == ".gitattributes" and v.get("status") == "ok"}
    work: dict[str, tuple[int, str]] = {}
    for rel, f in (inv.get("files") or {}).items():
        if f.get("blob") and f.get("mode"):
            try:
                work[rel] = (G.work_mode(int(f["mode"], 8), False), f["blob"])
            except ValueError:
                continue
    for rel, target in (inv.get("links") or {}).items():
        work[rel] = (G.MODE_LINK, G.blob_id(os.fsencode(target), inv.get("format") or "sha1"))
    skipped = [s["path"] for s in inv.get("skipped") or []]
    src = G.DictSource(files)
    complete = not any((inv.get("totals") or {}).get(k) == "1" for k in ("capped", "timed_out"))
    unread = [k for k, v in got.items() if v.get("status") not in ("ok",) and k.startswith(".git/")
              and not k.startswith(".git/objects/")]
    recs = CF.compute_git(src, work, ignores, attrs, skipped, complete_walk=complete, max_files=max_files,
                          max_pack_bytes=budget)
    if reason:
        recs.append(f"GR\ttree\t{reason}")
    if unread:
        recs.append(f"GR\tfiles\t{len(unread)} git file(s) could not be read")
    if info.get("error"):
        recs.append(f"GR\tfiles\tthe git read failed: {CF._clean(info['error'])}")
    return recs, int(info.get("used") or 0)


# --------------------------------------------------------------------------- E.7b's review purpose
def review_extensions() -> tuple[str, ...]:
    """`.py` always; PHP / JS / TS only when the E.7b `review` extra (tree-sitter) is installed."""
    if importlib.util.find_spec("tree_sitter") is not None:
        return REVIEW_EXTS_BASE + REVIEW_EXTS_EXTRA
    return REVIEW_EXTS_BASE


def read_for_review(data_dir: Path, machine: str, root: str, rels: list[str], *, actor: Any,
                    fetch: Fetcher | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Source files of one CONFIRMED root for a person-started E.7b review prepare: only the
    root's latest inventory, only the review extensions, at most `review.max_read_mb`. Refused
    for anything but a person at the Kratos host with `code.review_start` -- never a tool call,
    schedule, MCP, chat or model step."""
    from kratos import authz
    from kratos.code import store as S
    from kratos.lifecycle.decide import Actor
    from kratos.target_key import target_key

    tool = settings_store.in_tool_call()
    if tool is not None:
        raise ReviewRefused(f"agent tools may not read source for a review (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in ("tui", "cli"):
        raise ReviewRefused("a review read needs a person at the Kratos computer (TUI or CLI)")
    try:
        authz.require(actor, authz.P.CODE_REVIEW_START, machine, data_dir=data_dir, obj=f"code root {root}")
    except authz.Denied as e:
        raise ReviewRefused(str(e)) from None
    tk = target_key(machine)
    rec = next((r for r in S.roots(data_dir, tk, status="confirmed") if r["path"] == root), None)
    if rec is None:
        raise ReviewRefused("only a confirmed code folder can be read for a review")
    exts = review_extensions()
    current = S.files(data_dir, rec["id"], "current")
    inv = {"files": {k: {"size": v.get("size")} for k, v in current.items()}, "gitfiles": {}}
    bad = [r for r in rels if not r.lower().endswith(exts)]
    if bad:
        raise ReviewRefused(f"{len(bad)} file(s) don't have a source extension a review reads ({', '.join(exts)})")
    budget = int(CS.get(CS.REVIEW_MAX_READ_MB, data_dir)) * 1024 * 1024
    return read_contents(root, "review", inv, rels, budget=budget, fetch=fetch)
