"""Running verifiers: one finding on request (/verify), the serious ones
automatically after correlation (the auto budget), and a scoped retest after a fix.

Nothing here decides anything. A verdict is recorded (triage.store) and attached to
the finding dict as `finding["verdict"]` so every surface that already reads the
finding (the answer block, the digest, /findings, the report, MCP, notifications)
shows it. Auto-verification is bounded by `triage.auto_seconds`; whatever doesn't
finish in time is marked "verifying…" and completed in the background, the same way
a slow collection check is folded in later.
"""
from __future__ import annotations

import contextvars
import logging
import threading
import time
from pathlib import Path
from typing import Any

from kratos import finding_facts, settings_store
from kratos.triage import settings as _triage_settings
from kratos.triage import store as _store
from kratos.triage.context import VerifyContext
from kratos.triage.registry import NoVerifier, Verifier, verifier_for
from kratos.triage.verdict import Verdict, from_this_run

logger = logging.getLogger(__name__)

# What `finding["verdict"]` holds while a background verification is still running.
PENDING = {"verdict": "verifying", "tag": "verifying…", "sentence": "Kratos is re-checking this…",
           "detail": "", "checks": [], "evidence": [], "pending": True}


def _no_read_verdict(entry: NoVerifier | None) -> Verdict:
    if entry is None:
        return Verdict("couldnt_check", "Kratos has no re-check for this kind of finding yet.",
                       detail="no verifier registered")
    return Verdict("couldnt_check", "Kratos does not re-check this kind of finding by itself.",
                   detail=entry.reason)


def verify_finding(finding: dict[str, Any], *, data_dir: Path, target: str, run: Any = None,
                   deadline: float | None = None, dispatch: Any = None, recollect: Any = None,
                   now: float | None = None, record: bool = True, reuse: bool = False,
                   report: Any = None) -> Verdict:
    """Re-check one finding and return (and, by default, store) the verdict. `reuse`
    with `report` judges against a collection Kratos just ran (the automatic pass) instead
    of issuing a fresh read."""
    now = time.time() if now is None else now
    entry = verifier_for(str(finding.get("id") or ""))
    key = str(finding.get("finding_key") or "")
    if not key and target:                           # a stored finding dict may not carry its key
        from kratos.lifecycle.keys import finding_key as _fk
        from kratos.target_key import target_key as _tk
        key = _fk(str(finding.get("id") or ""), _tk(target), finding.get("subject") or "")
    started = time.monotonic()
    if not isinstance(entry, Verifier):
        verdict = _no_read_verdict(entry if isinstance(entry, NoVerifier) else None)
        label = "none"
    else:
        from kratos.triage.context import _default_dispatch, _default_recollect

        # Resolve the real reads here (inside the caller's run_scope), not in the context.
        if dispatch is None:
            dispatch = _default_dispatch(Path(data_dir))
        if recollect is None:
            recollect = _default_recollect(target, Path(data_dir))
        ctx = VerifyContext(finding=finding, target=target, data_dir=Path(data_dir), run=run,
                            deadline=deadline or 0.0, now=now, dispatch=dispatch, recollect=recollect,
                            reuse=reuse, report=report)
        label = entry.label or entry.verify.__name__
        try:
            verdict = entry.verify(ctx)
        except Exception as e:  # noqa: BLE001 -- a verifier crash is "couldn't check", never a failed run
            logger.warning("triage: verifier for %s failed", finding.get("id"), exc_info=True)
            verdict = Verdict("couldnt_check", "The re-check hit an error.",
                              detail=f"{type(e).__name__}: {str(e)[:120]}")
        if reuse:
            # Judged against the read that raised the finding -- not a second look, so
            # it never says "reproduced" (it says "seen in this run's read").
            verdict = from_this_run(verdict)
    duration = time.monotonic() - started
    if record and key:
        try:
            _store.record_verdict(Path(data_dir), finding_key=key, verdict=verdict,
                                  verifier=label, cost=getattr(entry, "cost", "quick"),
                                  run_id=getattr(run, "run_id", None), duration=duration, now=now)
        except Exception:  # noqa: BLE001 -- storing a verdict must never fail a run
            logger.debug("triage: could not store verdict for %s", finding.get("id"), exc_info=True)
    finding["verdict"] = verdict.as_dict()
    return verdict


class _ReuseReport:
    """The collection Kratos just ran, viewed for reuse-mode verification: its checks
    and transport, but the findings as they stand now (post re-correlation)."""
    def __init__(self, report: Any, findings: list[dict[str, Any]] | None):
        self.findings = list(findings or [])
        self.checks = list(getattr(report, "checks", None) or [])
        self.transport = getattr(report, "transport", "") or ""
        self.disabled_reason = getattr(report, "disabled_reason", None)


def _reuse_report(report: Any, findings: list[dict[str, Any]] | None) -> "_ReuseReport":
    return _ReuseReport(report, findings)


def _eligible(finding: dict[str, Any]) -> bool:
    """A finding auto-verification should re-check: serious (HIGH/CRITICAL), open, and
    new/reopened/recurred this run (not one already verified on an earlier run)."""
    if not finding_facts.serious([finding]):
        return False
    change = str(finding.get("change") or "")
    return change in ("", "new", "reopened", "recurred")


def auto_verify(findings: list[dict[str, Any]] | None, *, data_dir: Path, target: str, run: Any = None,
                budget_seconds: float | None = None, quick_only: bool = True, dispatch: Any = None,
                recollect: Any = None, now: float | None = None, report: Any = None) -> dict[str, Verdict]:
    """Re-check the serious new/reopened findings by code, inside the auto budget.
    Quick verifiers only (decision 4); whatever doesn't finish is left "verifying…"
    and completed in a background thread. Mutates each verified finding's dict
    (`finding["verdict"]`) and returns the verdicts produced in time, by key.

    `report` (a CollectionReport Kratos just ran): the verifiers judge against it rather
    than issuing a second read -- the automatic pass after an investigation / scheduled run
    re-uses the fresh collection (reuse mode) instead of doubling the load on the target."""
    data_dir = Path(data_dir)
    if budget_seconds is None:
        budget_seconds = float(settings_store.get(_triage_settings.AUTO_SECONDS, data_dir=data_dir))
    out: dict[str, Verdict] = {}
    if budget_seconds <= 0 or not findings or not (target or "").strip():
        return out
    todo: list[dict[str, Any]] = []
    for f in findings:
        if not _eligible(f):
            continue
        done = f.get("verdict")                       # already verified this run (idempotent re-call)
        if isinstance(done, dict) and not done.get("pending"):
            continue
        entry = verifier_for(str(f.get("id") or ""))
        if quick_only and isinstance(entry, Verifier) and entry.cost == "slow":
            continue
        todo.append(f)
    if not todo:
        return out
    deadline = time.monotonic() + budget_seconds
    now = time.time() if now is None else now
    # In reuse mode the "fresh read" IS the collection Kratos just ran. Judge presence
    # against the findings as they stand now (a re-correlation may have refreshed them
    # after collection), while keeping the collection's checks/transport for display and
    # the completeness test. That read is the one that raised the finding, so a finding
    # currently present is "seen in this run's read -- not re-checked yet", never
    # "reproduced": only a genuine second read (recheck, retest, the slow verifiers) may
    # say reproduced / not reproduced.
    reuse_report = _reuse_report(report, findings) if report is not None else None
    leftover: list[dict[str, Any]] = []
    for i, f in enumerate(todo):
        if time.monotonic() >= deadline:
            leftover = todo[i:]
            break
        key = str(f.get("finding_key") or "")
        verdict = verify_finding(f, data_dir=data_dir, target=target, run=run, deadline=deadline,
                                 dispatch=dispatch, recollect=recollect, now=now,
                                 reuse=reuse_report is not None, report=reuse_report)
        if key:
            out[key] = verdict
    for f in leftover:
        f.setdefault("verdict", dict(PENDING))
    if leftover:
        _finish_in_background(leftover, data_dir=data_dir, target=target, run=run, dispatch=dispatch,
                              recollect=recollect, report=reuse_report)
    return out


def _finish_in_background(findings: list[dict[str, Any]], *, data_dir: Path, target: str, run: Any,
                          dispatch: Any, recollect: Any, report: Any = None) -> None:
    """Finish the remaining quick verifiers after the answer has gone out, so their
    verdicts are on record for /findings and the next run (like a late collection
    check). A hard cap keeps a stuck read from running forever."""
    def finish() -> None:
        deadline = time.monotonic() + 60.0
        for f in findings:
            if time.monotonic() >= deadline:
                break
            try:
                verify_finding(f, data_dir=data_dir, target=target, run=run, deadline=deadline,
                               dispatch=dispatch, recollect=recollect, reuse=report is not None, report=report)
            except Exception:  # noqa: BLE001 -- background bookkeeping must never raise
                logger.debug("triage: background verify of %s failed", f.get("id"), exc_info=True)

    threading.Thread(target=contextvars.copy_context().run, args=(finish,),
                     name="triage-verify-finish", daemon=True).start()


# --------------------------------------------------------------------------- display helpers
def verdict_tag_of(finding: dict[str, Any]) -> str | None:
    """The short verdict tag to show next to a finding, from `finding["verdict"]`."""
    v = finding.get("verdict")
    if not isinstance(v, dict):
        return None
    return str(v.get("tag") or "") or None


def attach_stored_verdicts(findings: list[dict[str, Any]] | None, data_dir: Path) -> None:
    """Attach each finding's latest stored verdict (if any) to its dict, for a surface
    that reads findings straight from the engine without running a verification."""
    if not findings:
        return
    keys = [str(f.get("finding_key") or "") for f in findings if f.get("finding_key")]
    stored = _store.latest_verdicts(Path(data_dir), keys)
    for f in findings:
        key = str(f.get("finding_key") or "")
        if key in stored and "verdict" not in f:
            f["verdict"] = stored[key].verdict.as_dict()


def enrich_rows(rows: list[dict[str, Any]], data_dir: Path) -> list[dict[str, Any]]:
    """Add `verdict` and `suggestions` to lifecycle query rows (for /findings, CLI, MCP)."""
    if not rows:
        return rows
    keys = [str(r.get("finding_key") or "") for r in rows if r.get("finding_key")]
    stored = _store.latest_verdicts(Path(data_dir), keys)
    for r in rows:
        key = str(r.get("finding_key") or "")
        vr = stored.get(key)
        r["verdict"] = vr.verdict.as_dict() if vr is not None else None
        if key:
            r["suggestions"] = _store.suggestions_for(Path(data_dir), key, state="new")
    return rows


# --------------------------------------------------------------------------- retest
def retest(finding_key: str, *, data_dir: Path, target: str | None = None,
           run: Any = None) -> dict[str, Any]:
    """`/retest`: force-run the collection checks that cover this finding's rule, run
    one correlation and the lifecycle update, then this finding's verifier. Returns
    before/after state and the verdict, in plain data. No model call (decision 8)."""
    from kratos.lifecycle import query as _q
    from kratos.lifecycle import store as _lc

    data_dir = Path(data_dir)
    with _lc.opened(data_dir) as conn:
        full = _lc.resolve_key(conn, finding_key)
        rec = _lc.get_record(conn, full)
        before_state = rec["state"]
        rule_id, rec_target = rec["rule_id"], rec["target"]
    tgt = machine_of(rec_target, target)
    check_names = _covering_check_names(rule_id)
    report = _recollect(tgt, data_dir, check_names, run=run) if check_names else None
    # The forced collection + correlation already ran the lifecycle update (write_findings_report
    # -> apply_run), so re-read this finding's state now.
    row, latest, _events = _q.get_finding(data_dir, full)
    after_state = row["state"]
    latest.setdefault("first_seen", row.get("first_seen"))   # occurrence re-measure uses the real window
    verdict = verify_finding(latest, data_dir=data_dir, target=tgt, run=run)
    incomplete = _retest_incomplete(report, check_names)
    return {
        "finding_key": full, "rule_id": rule_id, "target": row["target"],
        "before_state": before_state, "after_state": after_state,
        "rechecked": check_names, "incomplete": incomplete,
        "verdict": verdict.as_dict(),
        "fixed": after_state in ("mitigated", "inactive"),
    }


def machine_of(rec_target: str, wanted: str | None = None) -> str:
    """The machine a finding is re-checked on: always its OWN machine. `wanted` (the
    caller's active or chosen machine) is used only when it names that same machine (its
    spelling may carry more, e.g. a host name's case) -- a finding on one machine is never
    judged against another machine's reads (Phase B audit: /findings lists every machine,
    and k/t on another machine's row re-read the active one)."""
    from kratos.target_key import target_key

    if wanted and target_key(wanted) == target_key(rec_target):
        return str(wanted).strip()
    return rec_target


def _covering_check_names(rule_id: str) -> list[str]:
    from kratos.adapters.findings_engine import rule_inputs
    from kratos.collect import checks as _checks  # noqa: F401
    from kratos.collect.registry import checks as registered_checks
    from kratos.lifecycle.rules import rule_info

    info = rule_info(rule_id)
    needed = set(info.covering_inputs if info else rule_inputs(rule_id))
    return [c.name for c in registered_checks() if needed & set(c.inputs)]


def _recollect(target: str, data_dir: Path, check_names: list[str], *, run: Any) -> Any:
    from kratos import kratos_config
    from kratos.collect import runner as _runner

    with kratos_config.pinned_target(target):
        return _runner.prepare(target, data_dir, classes=("quick", "slow"), only=tuple(check_names),
                               force=True, correlate=True, background=False)


def _retest_incomplete(report: Any, check_names: list[str]) -> str | None:
    if report is None:
        return "nothing was re-collected"
    if getattr(report, "disabled_reason", None):
        return str(report.disabled_reason)
    bad = [o for o in (getattr(report, "checks", None) or []) if o.name in check_names and o.status != "ok"]
    if bad:
        return "; ".join(dict.fromkeys(o.reason or o.summary or o.name for o in bad))
    return None
