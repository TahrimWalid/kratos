"""B.1 verifier for the AI-review findings (E.7b §3.12).

REVIEW-001/002 are conditions tied to a slice's function. Their re-check re-reads **E.7a's stored
inventory hash** for the slice's file -- no new review read, no model call: unchanged -> the stored
verdict stands ("code unchanged since review"); changed or gone -> "the code changed, review it
again" (a person's `/retest` prepares a review of that slice, with the normal consent). Never a
`NoVerifier`.
"""
from __future__ import annotations

import re
from typing import Any

from kratos.triage.context import VerifyContext
from kratos.triage.registry import Verifier, register_verifier
from kratos.triage.verdict import Verdict, VerifyCheck

_SHA_PREFIX = re.compile(r"^[0-9a-f]{12,64}$")
_ENTITY = re.compile(r"^(?P<rel>.+):(?P<func>[^:]+):(?P<cls>[^:]+)$")


def _parse_entities(entities: list[str]) -> tuple[str | None, str | None]:
    """(relpath, slice-sha-prefix) from a REVIEW finding's entities (`rel:function:class` and a
    16-char slice sha prefix)."""
    rel = sha = None
    for e in entities or []:
        s = str(e)
        if _SHA_PREFIX.match(s):
            sha = s
        else:
            m = _ENTITY.match(s)
            if m:
                rel = m.group("rel")
    return rel, sha


def _current_inventory_sha(data_dir: Any, machine_key: str, root: str, relpath: str) -> str | None:
    """E.7a's stored inventory hash for `relpath` in the confirmed root, or None when the file
    (or the root) is no longer there. A stored read -- no SSH, no model."""
    from kratos.code import store as CS
    rec = next((r for r in CS.roots(data_dir, machine_key, status="confirmed") if r["path"] == root), None)
    if rec is None:
        return None
    files = CS.files(data_dir, rec["id"], "current")
    f = files.get(relpath)
    return (f.get("sha256") or None) if f else None


def _verify(ctx: VerifyContext) -> Verdict:
    from kratos.review import store as RST

    check = (VerifyCheck("code inventory", "local"),)
    rel, prefix = _parse_entities(ctx.finding.get("entities") or [])
    row = RST.latest_slice_by_prefix(ctx.data_dir, prefix or "") if prefix else None
    if row is None or not rel:
        return Verdict("couldnt_check", "No stored review slice to re-check this against -- review the folder again.",
                       detail="no stored review slice", checks=check)
    reviewed_sha = str(row.get("file_sha") or "")
    current = _current_inventory_sha(ctx.data_dir, str(row.get("target_key") or ctx.target_key),
                                     str(row.get("run_root") or ""), str(row.get("file") or rel))
    if current is None:
        return Verdict("couldnt_check",
                       "The file is gone from the code folder's inventory (removed, moved or not read) -- "
                       "review the folder again (/retest).", detail="file gone or not in the inventory", checks=check)
    if not reviewed_sha:
        return Verdict("couldnt_check", "The review didn't record this file's hash, so it can't be compared -- "
                       "review the folder again.", detail="no recorded hash", checks=check)
    if current == reviewed_sha:
        return Verdict("reproduced", "The code at this path is unchanged since the review (same file hash), so the "
                       "finding stands.",
                       evidence=(f"{rel}: file hash unchanged since the review",), checks=check)
    return Verdict("couldnt_check", "The code changed since the review -- review it again to see if the weakness is "
                   "still there (press t in /findings, or `kratos review start`).",
                   detail="code changed since review", checks=check)


register_verifier(Verifier(rules=("REVIEW-001", "REVIEW-002"), cost="quick", verify=_verify,
                           label="a re-read of the code folder's stored file hash"))
