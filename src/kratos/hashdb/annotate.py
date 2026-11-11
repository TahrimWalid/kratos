"""Reputation lines on findings (E.4 §3.6, §3.11) -- an ANNOTATION, never a state.

After the findings engine builds a report, every finding that names a file the machine's
latest reputation check looked up (a `path#sha256` entity, a running process's program,
a HASH-* finding's own file) gets a `reputation` list: [{path, sha256, verdict, label,
note, sources, checked_at}]. Nothing here touches a finding's severity, title, state or
entities: a known-good `bash` copied setuid into /tmp stays PERSIST-003 high, with
"probably known-good -- a known program in an unusual place is still a risk" beside it.
A test runs every rule id through this and fails if anything but `reputation` changes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kratos.hashdb import reputation as R

_RANK = {"known_bad": 0, "package_modified": 1, "unknown": 2, "not_checked": 3, "known_good": 4, "package": 5}


def _entity_path(entity: str) -> tuple[str, str]:
    """(path, sha256 prefix or '') of a finding entity, ('', '') when it names no file."""
    e = str(entity or "")
    if "|" in e:                          # a process: exe|pid|starttime
        exe = e.rsplit("|", 2)[0]
        if exe.endswith(" (deleted)"):
            exe = exe[: -len(" (deleted)")]
        return (exe, "") if exe.startswith("/") else ("", "")
    path, _, frag = e.partition("#")
    return (path, frag.lower()) if path.startswith("/") else ("", "")


def index(doc: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for f in (doc or {}).get("files") or []:
        if isinstance(f, dict) and str(f.get("path") or "").startswith("/"):
            out.setdefault(str(f["path"]), f)
    return out


def lines_for(entities: list[str], files: dict[str, dict[str, Any]], checked_at: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ent in entities or []:
        path, frag = _entity_path(ent)
        f = files.get(path)
        if not f or path in seen:
            continue
        seen.add(path)
        sha = str(f.get("sha256") or "")
        note = str(f.get("note") or "")
        if frag and sha and not sha.startswith(frag):
            note = (note + "; " if note else "") + "the file's content has changed since this finding saw it"
        out.append({"path": path, "sha256": sha or None, "verdict": f.get("verdict"),
                    "label": R.short_tag(f), "note": note, "sources": f.get("sources") or [],
                    "checked_at": checked_at})
    out.sort(key=lambda x: (_RANK.get(str(x["verdict"]), 9), x["path"]))
    return out


def attach(findings: list[Any], doc: dict[str, Any] | None) -> None:
    """Set `reputation` on each finding (objects with .entities/.subject/.reputation)."""
    files = index(doc)
    if not files:
        return
    when = str((doc or {}).get("checked_at") or "")
    for f in findings:
        ents = list(getattr(f, "entities", None) or [])
        subj = str(getattr(f, "subject", "") or "")
        if subj.startswith("/"):
            ents.append(subj)
        rep = lines_for(ents, files, when)
        if rep:
            f.reputation = rep


def text_lines(reps: list[dict[str, Any]] | None) -> list[str]:
    """Plain lines for the CLI ("reputation of /tmp/.b: known-bad (MalwareBazaar) -- note")."""
    out = []
    for r in reps or []:
        src = ", ".join(str(s.get("source")) + (f" {s.get('date')}" if s.get("date") else "")
                        for s in r.get("sources") or [])
        out.append(f"reputation of {r.get('path')}: {r.get('label')}" + (f" ({src})" if src else "")
                   + (f" -- {r.get('note')}" if r.get("note") else ""))
    return out


def worst_tag(finding: dict[str, Any]) -> str:
    """The one short tag the digest and lists show ('' when none)."""
    reps = finding.get("reputation") or []
    return str(reps[0].get("label") or "") if reps else ""


def load_doc(data_dir: Path, snapshots: dict[str, Any] | None) -> dict[str, Any] | None:
    return (snapshots or {}).get("hash_reputation")
