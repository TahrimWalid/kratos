"""Make an incident bundle: plan -> copy -> report -> CASE/UCO -> manifest -> sign -> sums
-> archive -> record.

A person's action only: refused inside a tool call (no model tool can export), and every
export records who made it (``Actor``). The bundle goes to ``data_dir/exports/<id>/``
(and ``<id>.tar.gz`` beside it). The finished manifest is an evidence-ledger entry whose
detail is the export record: who, when, scope, variant, manifest and archive hashes,
signing-key fingerprint (``kratos export list`` reads them back).
"""
from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from kratos import evidence, paths, signing
from kratos.evidence import ledger as L
from kratos.export import archive, case_uco, manifest as M, report_html, sshsig
from kratos.export import bundle as B
from kratos.export.collect import BundleFile, collect
from kratos.export.redact import redactor_for
from kratos.export.scope import ExportError, ExportRequest, Plan, _iso, plan as make_plan

EXPORTS_DIR = "exports"
Progress = Callable[[str], None]


@dataclass
class ExportResult:
    export_id: str
    bundle: Path
    archive: Path | None
    archive_sha256: str | None
    manifest_sha256: str
    fingerprint: str
    files: int
    events: int
    bytes: int
    seconds: float
    warnings: list[str] = field(default_factory=list)
    narrative: dict[str, Any] | None = None

    def verify_commands(self) -> list[str]:
        return [f"cd {self.bundle}", *M.VERIFY_COMMANDS]


def exports_dir(data_dir: Path | str) -> Path:
    return Path(data_dir) / EXPORTS_DIR


def _refuse_in_tool() -> None:
    from kratos import settings_store

    tool = settings_store.in_tool_call()
    if tool:
        raise ExportError(f"an export is a person's action; refused inside the tool call {tool!r}")


def create(data_dir: Path | str, req: ExportRequest, actor: Any, *, progress: Progress | None = None,
           narrative_chat: Callable[[str, str], str | None] | None = None, now: float | None = None,
           plan: Plan | None = None) -> ExportResult:
    from kratos.export import narrative as N
    from kratos.export import settings as ES

    _refuse_in_tool()
    if actor is None or not getattr(actor, "user", None):
        raise ExportError("an export needs a person (actor)")
    say = progress or (lambda _m: None)
    data_dir = Path(data_dir)
    t0 = time.monotonic()
    p = plan or make_plan(data_dir, req, now=now)
    req = p.request
    say("checking the evidence ledger")
    chain = L.verify_chain(data_dir, check_files=False)
    key = signing.load_key(data_dir)
    assert key is not None
    pub = signing.public_key_openssh(data_dir)
    fp = signing.fingerprint_of(key.public_key())

    root = paths.ensure_private_dir(exports_dir(data_dir))
    out = root / p.export_id
    if out.exists():
        raise ExportError(f"{out} already exists")
    tmp = root / f".{p.export_id}.building"
    if tmp.exists():
        shutil.rmtree(tmp)   # a crashed export's unfinished folder from this same id (never another's)
    tmp.mkdir(mode=0o700)
    try:
        red = redactor_for(req.variant, data_dir, p.export_id, req.machines, people=(str(actor.user),))
        say("copying evidence")
        col = collect(data_dir, p, tmp, red, progress=say)
        files: list[BundleFile] = list(col.files)

        # the ledger excerpt: from the first exported file's row to the head
        seqs = {f.ledger_seq for f in files if f.ledger_seq}
        excerpt: list[dict[str, Any]] = []
        if seqs:
            excerpt = M.ledger_excerpt(data_dir, first_seq=min(seqs), head_seq=p.ledger_head[0],
                                       full_seqs=seqs, redacted=red.active)
            d, n = B.write_text(tmp, M.LEDGER, "".join(json.dumps(r, sort_keys=True) + "\n" for r in excerpt))
            files.append(BundleFile(M.LEDGER, d, n, "ledger", hashed_at="generated"))

        narrative = None
        if req.narrative:
            say("writing the summary (a model with no tools)")
            from kratos import run_context

            with run_context.run_scope("cli"):
                narrative = N.write_summary(col.findings, col.coverage, data_dir=data_dir, chat=narrative_chat,
                                    max_usd=float(ES.get(ES.NARRATIVE_MAX_USD, data_dir)), run_tag=p.export_id[-8:])
            md = narrative.markdown()
            if md:
                d, n = B.write_text(tmp, "narrative.md", md)
                files.append(BundleFile("narrative.md", d, n, "report", hashed_at="generated"))

        created_at = _iso(p.taken_at)
        man: dict[str, Any] = {
            "format": M.FORMAT, "export_id": p.export_id, "created_at": created_at,
            "created_by": {"user": red.text(str(actor.user)) if red.active else actor.user,
                           "interface": actor.interface},
            "kratos_build": _build(), "variant": req.variant,
            "redaction": red.stats() or None,
            "scope": {**req.as_dict(), "machines": [col.machine_names[m] for m in req.machines],
                      "group": (red.text(req.group) if red.active and req.group else req.group)},
            "signing_key": {"fingerprint": fp, "public_key": pub, "algorithm": "ssh-ed25519",
                            "namespace": sshsig.NAMESPACE, "principal": sshsig.PRINCIPAL},
            "ledger": {"head_seq": p.ledger_head[0], "head_hash": p.ledger_head[1], "chain_verified": chain.chain_ok,
                       "problems": chain.problems[:50], "excerpt": M.LEDGER if excerpt else None,
                       "first_seq": min(seqs) if seqs else None},
            "events_upto_row": p.events_upto_row,
            "machines": [{"shown": col.machine_names[m],
                          "files": sum(1 for f in files if f.machine == col.machine_names[m] and f.kind == "evidence"),
                          "events": sum(f.events or 0 for f in files if f.machine == col.machine_names[m]),
                          "findings": len(col.findings.get(col.machine_names[m], [])),
                          "gaps": (col.coverage.get(col.machine_names[m]) or {}).get("gaps") or []}
                         for m in req.machines],
            "cuts": p.cuts(), "unattributed_files_left_out": p.unattributed,
            "warnings": col.warnings, "files": [],
        }
        man["files"] = [f.as_dict() for f in files]
        say("writing the report")
        html = report_html.render(man, col, narrative=narrative.as_dict() if narrative else None,
                                  timeline_rows=int(ES.get(ES.TIMELINE_ROWS, data_dir)))
        d, n = B.write_text(tmp, "report.html", html)
        files.append(BundleFile("report.html", d, n, "report", hashed_at="generated"))
        man["files"] = [f.as_dict() for f in files]
        graph = case_uco.dumps(case_uco.build(man))
        d, n = B.write_text(tmp, "case.jsonld", graph)
        files.append(BundleFile("case.jsonld", d, n, "report", hashed_at="generated",
                                category=f"CASE {case_uco.CASE_VERSION} / UCO {case_uco.UCO_VERSION}"))
        man["files"] = sorted((f.as_dict() for f in files), key=lambda f: f["path"])

        say("signing")
        man_bytes = M.dumps(man)
        man_sha, _ = B.write_bytes(tmp, M.MANIFEST, man_bytes)
        B.write_text(tmp, M.SIGNATURE, sshsig.sign(man_bytes, key))
        B.write_text(tmp, M.SIGNERS, sshsig.allowed_signers_line(pub))
        B.write_text(tmp, M.VERIFY, M.verify_text(fp, p.export_id))
        sums = M.sums_text(tmp)
        B.write_text(tmp, M.SUMS, sums)
        B.write_text(tmp, M.SUMS_SIG, sshsig.sign(sums.encode("utf-8"), key))
        tmp.rename(out)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    arc_path = arc_sha = None
    if req.archive:
        say("packing the .tar.gz")
        arc_path = root / f"{p.export_id}.tar.gz"
        arc_sha = archive.write(out, arc_path, mtime=int(p.taken_at))
    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    evidence.record(out / M.MANIFEST, data_dir=data_dir, category="export", machine=None, read="export",
                    transport="local", detail={
                        "export_id": p.export_id, "by": actor.user, "interface": actor.interface,
                        "scope": req.as_dict(), "variant": req.variant, "manifest_sha256": man_sha,
                        "archive": arc_path.name if arc_path else None, "archive_sha256": arc_sha,
                        "fingerprint": fp, "files": len(man["files"]),
                        "events": sum(f.events or 0 for f in files), "bytes": size,
                    })
    return ExportResult(p.export_id, out, arc_path, arc_sha, man_sha, fp, len(man["files"]),
                        sum(f.events or 0 for f in files), size, time.monotonic() - t0, col.warnings,
                        narrative.as_dict() if narrative else None)


def _build() -> str | None:
    try:
        from kratos.utils.build_info import RUNNING_BUILD

        return RUNNING_BUILD
    except Exception:  # noqa: BLE001
        return None


def list_exports(data_dir: Path | str) -> list[dict[str, Any]]:
    """Every export Kratos made here, from the evidence ledger (newest first)."""
    out = []
    for e in L.entries(data_dir):
        if e.category == "export" and e.detail:
            out.append({**e.detail, "at": _iso(e.written_at), "ledger_seq": e.seq, "path": e.path,
                        "bundle_present": (Path(data_dir) / (e.path or "")).is_file()})
    return list(reversed(out))


def when(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
