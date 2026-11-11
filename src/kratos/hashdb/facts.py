"""The core side of the `file_facts` read (E.4 §3.8): build the request from a candidate
selection, refuse anything a recent snapshot of this machine didn't list, send it, and
map each record back to its candidate.

The read itself (both transports, one parser) is kratos.adapters.file_facts.
"""
from __future__ import annotations

import os
from typing import Any, Callable

from kratos.adapters import file_facts as F


class NotFromSnapshot(ValueError):
    """A path no recent snapshot of this machine listed: never sent."""


def to_bytes(path: str) -> bytes | None:
    """The raw bytes of a snapshot path, or None when they can't be recovered exactly
    (an SSH read replaced undecodable bytes with U+FFFD)."""
    if "�" in path:
        return None
    try:
        raw = os.fsencode(path)
        return F.check_path(raw)
    except (F.RequestError, UnicodeError, ValueError):
        return None


def build_request(chosen: list[dict[str, Any]], snapshot_paths: frozenset[str]) -> tuple[list[bytes], list[int],
                                                                                         dict[int, str]]:
    """(raw paths to send, the candidate index of each, {candidate index: why not sent}).
    Raises NotFromSnapshot for any candidate whose path no snapshot listed -- the caller
    built the selection from snapshots, so this only fires on a bug or a tampered list."""
    paths: list[bytes] = []
    which: list[int] = []
    skipped: dict[int, str] = {}
    for i, c in enumerate(chosen):
        path = str(c.get("path") or "")
        if path not in snapshot_paths:
            raise NotFromSnapshot(f"{path!r} was not listed by a recent snapshot of this machine")
        raw = to_bytes(path)
        if raw is None:
            skipped[i] = "name"
            continue
        paths.append(raw)
        which.append(i)
    return paths, which, skipped


Fetcher = Callable[..., Any]


def default_fetcher(paths: list[bytes], **limits: int) -> Any:
    from kratos.adapters.ssh_remote import fetch_file_facts

    return fetch_file_facts(paths, **limits)


def read(chosen: list[dict[str, Any]], snapshot_paths: frozenset[str], *, limits: dict[str, int],
         fetch: Fetcher | None = None) -> tuple[dict[int, dict[str, Any]], dict[int, str], dict[str, Any]]:
    """({candidate index: fact}, {candidate index: not-read reason}, read info {via,
    reader_uid, complete, error}). A failed read leaves every candidate unread with the
    failure's reason ("old_agent" for an agent too old for file_facts)."""
    paths, which, skipped = build_request(chosen, snapshot_paths)
    info: dict[str, Any] = {"via": None, "reader_uid": None, "complete": False, "error": ""}
    facts: dict[int, dict[str, Any]] = {}
    if not paths:
        info["complete"] = True
        return facts, skipped, info
    result = (fetch or default_fetcher)(paths, **limits)
    if not isinstance(result, dict):
        err = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "the read failed").strip()
        info["error"] = " ".join(err.split())[:300]
        info["via"] = getattr(result, "via", None)
        why = "old_agent" if ("update the agent" in err or "can't do the 'file_facts' read" in err or
                              "no 'file_facts' read" in err) else "read_failed"
        for i in which:
            skipped[i] = why
        return facts, skipped, info
    info.update({"via": result.get("via") or "ssh", "reader_uid": result.get("reader_uid"),
                 "complete": bool(result.get("complete")) and not result.get("truncated_output"),
                 "ownership": result.get("ownership") or {}})
    root_reader = result.get("reader_uid") == 0
    for pos, i in enumerate(which):
        fact = (result.get("files") or {}).get(pos)
        if fact is None:
            skipped[i] = "read_failed"
            continue
        status = fact.get("status")
        if status == "unreadable" and not root_reader:
            skipped[i] = "proc_ssh" if str(chosen[i].get("path", "")).startswith("/proc/") else "unreadable_ssh"
        facts[i] = fact
    return facts, skipped, info
