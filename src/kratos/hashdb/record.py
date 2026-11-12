"""Run the file-reputation check for one machine and save what the rule engine reads (E.4 §3.9).

One call: pick the candidates from the machine's newest snapshots (kratos.hashdb
.candidates), read their facts (`file_facts`, SSH or the sub-agent), decide each file's
reputation from local data only (kratos.hashdb.reputation), judge HASH-001/002/003, write
`data_dir/hashdb/results/hash_<machine>.json` (one per machine, replaced in place,
evidence-recorded) and update `hash_reputation`.

Nothing here calls a model or sends a hash anywhere; the datasets are read on this
computer. A failed read is never "nothing found": every candidate it covered is
not_checked with the reason.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from kratos.hashdb import candidates as C
from kratos.hashdb import facts as FX
from kratos.hashdb import judge as J
from kratos.hashdb import reputation as R
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

FOLDER = "hashdb/results"
PATTERN = "hash_*.json"
MAX_FILES_SAVED = 2000


def result_path(data_dir: Path, target: str) -> Path:
    key = target_key(target)
    return Path(data_dir) / FOLDER / f"hash_{hashlib.sha256(key.encode()).hexdigest()[:8]}.json"


def _datasets_note(mb: Any, circl: Any) -> str:
    missing = []
    if circl is None:
        missing.append("the CIRCL known-good filter (`kratos hashdb-update --circl`)")
    if mb is None:
        missing.append("the MalwareBazaar known-bad set (needs a free abuse.ch key: `kratos hashdb-key set "
                       "malwarebazaar`, then `kratos hashdb-update --malwarebazaar`)")
    return ("Not set up: " + " and ".join(missing) + ". Until then, reputations come from package checks only."
            if missing else "")


def _open_sets(data_dir: Path) -> tuple[Any, Any, str, str]:
    from kratos.hashdb import circl, malwarebazaar

    mb = malwarebazaar.Reader(data_dir)
    cr = circl.Reader(data_dir)
    mb_date = mb.row.version if mb.row else ""
    cr_date = cr.row.version if cr.row else ""
    return (mb if mb.conn is not None else None), (cr if cr.bf is not None else None), mb_date, cr_date


def run(data_dir: Path, target: str, *, fetch: FX.Fetcher | None = None, now: float | None = None,
        docs: dict[str, Any] | None = None) -> dict[str, Any]:
    from kratos.hashdb import settings as S
    from kratos.hashdb import store

    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    key = target_key(target)
    docs = C.load_docs(data_dir, target) if docs is None else docs
    mb, cr, mb_date, cr_date = _open_sets(data_dir)
    try:
        sel = C.select(docs, max_files=int(S.get(S.MAX_FILES, data_dir)),
                       known_bad=(lambda h: mb.get(h) is not None) if mb else (lambda _h: False))
        limits = {"max_file_mb": int(S.get(S.MAX_FILE_MB, data_dir)), "run_mb": int(S.get(S.MAX_RUN_MB, data_dir)),
                  "seconds": int(S.get(S.SECONDS, data_dir))}
        facts, skipped, info = FX.read(sel.chosen, sel.snapshot_paths, limits=limits, fetch=fetch)
        threshold = float(S.get(S.ENTROPY, data_dir))
        reps: list[R.Reputation] = []
        for i, c in enumerate(sel.chosen):
            fact = facts.get(i)
            if fact and fact.get("status") == "ok" and c.get("sha256") and fact.get("sha256") != c["sha256"]:
                c["changed_since_snapshot"] = True
            reps.append(R.decide(fact if i not in skipped else None, c, known_bad=mb, known_good=cr,
                                 entropy_threshold=threshold, mb_date=mb_date, circl_date=cr_date,
                                 not_read=skipped.get(i, "")))
    finally:
        if mb is not None:
            mb.close()
        if cr is not None:
            cr.close()
    note = _datasets_note(mb, cr)
    signals = J.judge(sel.chosen, facts, reps, over_cap=len(sel.over_cap), target=key, via=info.get("via"),
                      datasets_note=note)
    files = []
    for i, (c, rep) in enumerate(zip(sel.chosen, reps)):
        fact = facts.get(i) or {}
        files.append({"path": c.get("image_of") or c["path"], "read_path": c["path"],
                      "sha256": fact.get("sha256") or (c.get("sha256") if rep.verdict == "known_bad" else None),
                      "sha1": fact.get("sha1"), "size": fact.get("size"), "uses": c.get("uses") or [],
                      "running": c.get("running") or [], **rep.as_dict(),
                      "changed_since_snapshot": bool(c.get("changed_since_snapshot"))})
    counts = {v: sum(1 for r in reps if r.verdict == v) for v in R.VERDICTS}
    counts["over_cap"] = len(sel.over_cap)
    gaps: list[str] = []
    if sel.missing:
        gaps.append("no recent " + " or ".join({"persistence": "persistence read", "live_response":
                                                "running-process read"}[k] for k in sel.missing)
                    + " to take candidates from")
    if info.get("error"):
        gaps.append(f"the file read failed: {info['error']}")
    nc = counts["not_checked"] + counts["over_cap"]
    if nc:
        gaps.append(f"{nc} file(s) not checked (HASH-003 says why)")
    doc = {
        "target": key, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when,
        "via": info.get("via") or "ssh",
        "reader_uid": info.get("reader_uid"),
        "complete": bool(info.get("complete")) and not sel.missing and not info.get("error"),
        "snapshots": sel.sources,
        "datasets": {"malwarebazaar": mb_date or None, "circl": cr_date or None},
        "counts": counts, "files": files[:MAX_FILES_SAVED], "signals": signals,
        "coverage_gaps": gaps, "answer_gaps": gaps[:2],
    }
    store.put_many(data_dir, key, [{"sha256": f["sha256"], "sha1": f.get("sha1"), "verdict": f["verdict"],
                                    "sources": f.get("sources"), "path": f["path"], "note": f.get("note")}
                                   for f in files if f.get("sha256")], at=when)
    out = result_path(data_dir, key)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, out)
    from kratos import evidence as _evidence

    _evidence.record(out, data_dir=data_dir, category="hash_reputation", machine=target, read="file_facts",
                     transport=doc.get("via"))
    return {**doc, "status": "ok", "file": str(out)}


def summary_line(doc: dict[str, Any]) -> str:
    c = doc.get("counts") or {}
    looked = sum(int(c.get(v) or 0) for v in R.VERDICTS)
    if not looked:
        return "no programs to look up yet (needs a recent persistence and running-process read)"
    bits = [f"{int(c.get('package') or 0)} from packages"]
    for v, word in (("known_bad", "KNOWN-BAD"), ("package_modified", "changed since installed"),
                    ("known_good", "known-good"), ("unknown", "unknown"), ("not_checked", "not checked")):
        if c.get(v):
            bits.append(f"{c[v]} {word}")
    counted = f"{looked} program(s) looked up: " + ", ".join(bits)
    worst = sorted({str(s.get("rule")) for s in doc.get("signals") or [] if s.get("rule") != "HASH-003"})
    lead = f"something to look at ({', '.join(worst)})" if worst else "nothing known to be bad"
    return f"{lead}; {counted}"

