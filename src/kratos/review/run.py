"""The one front door for a review (E.7b §5.1 `run.py`): prepare locally, then -- on an explicit
yes with an agreed amount -- send, decide every verdict by code, and keep every verdict reached
if the run stops.

`prepare_review` and `start_review` are **people-only, admin, local** (via E.7a's
`read_for_review`, which refuses any tool/schedule/MCP/chat/model/fleet step). `start_review`
opens a B.5 run record and a budget run scope, raises the per-run call/token caps to the agreed
estimate for the review scope only (gate answer 2), and stops cleanly at the agreed amount, on a
0.4 budget cap, on an endpoint error, or on the person's Stop -- keeping partial verdicts and the
real cost. Verdicts are set by `verdict.decide` from code-produced facts; a model's words never
set one.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos.review import cache as CACHE
from kratos.review import cost as COST
from kratos.review import plan as PLAN
from kratos.review import reproduce as REPRO
from kratos.review import rules as RULES
from kratos.review import settings as RS
from kratos.review import store as ST
from kratos.review import verdict as V
from kratos.review.plan import Plan, PlanError
from kratos.review.profiles import ReviewProfile, UnknownProfile, resolve

Progress = Callable[[str, dict[str, Any]], None]
Stop = Callable[[], bool]

_ROOT_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


class ReviewRefused(PermissionError):
    pass


def _root_lock(tk: str, root: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _ROOT_LOCKS.setdefault((tk, root), threading.Lock())


# --------------------------------------------------------------------------- gathering E.7a data
def _gather(data_dir: Path, machine: str, root: str) -> dict[str, Any]:
    """Everything a prepare needs from E.7a: the root id, the inventory hashes and sizes, the
    git drift status per file, the serving config, the open CODE-003 advisories, the serving
    listeners and the machine's own addresses."""
    from kratos.code import store as CS
    from kratos.code import record as CR
    from kratos.target_key import target_key

    tk = target_key(machine)
    rec = next((r for r in CS.roots(data_dir, tk, status="confirmed") if r["path"] == root), None)
    if rec is None:
        raise PlanError("confirm the root first (`/code`)")
    files = CS.files(data_dir, rec["id"], "current")
    file_hashes = {rel: (f.get("sha256") or "") for rel, f in files.items()}
    all_sizes = {rel: int(f.get("size") or 0) for rel, f in files.items()}
    git_status = {rel: str(f.get("git_status") or "") for rel, f in files.items()}

    rdoc = CR._load(CR.roots_path(data_dir, machine)) or {}
    serving_cfg = None
    try:
        from kratos.code import webconf as W
        serving_cfg = W.from_json(rdoc.get("webconf"))
    except Exception:  # noqa: BLE001
        serving_cfg = None

    code_doc = CR._load(CR.result_path(data_dir, machine)) or {}
    open_advisories: list[dict[str, Any]] = []
    for r in code_doc.get("roots") or []:
        if r.get("path") == root:
            open_advisories = list((r.get("deps") or {}).get("hits") or [])
            break
    root_serving = list(rec.get("serving") or [])
    local_addresses = _machine_addresses(data_dir, machine)
    return {"root_id": rec["id"], "tk": tk, "file_hashes": file_hashes, "all_sizes": all_sizes,
            "git_status": git_status, "serving_cfg": serving_cfg, "open_advisories": open_advisories,
            "root_serving": root_serving, "local_addresses": local_addresses}


def _machine_addresses(data_dir: Path, machine: str) -> list[str]:
    """The machine's own addresses from the newest A.5 live snapshot (for wildcard exposure)."""
    try:
        from kratos.live import record as LR
        doc = LR.load_recent(data_dir, machine) if hasattr(LR, "load_recent") else None
        if isinstance(doc, dict):
            return [a for a in (doc.get("own_addresses") or []) if isinstance(a, str)]
    except Exception:  # noqa: BLE001
        pass
    return []


def _window_tokens() -> int:
    try:
        from kratos.llm_interface import get_context_window_tokens
        w = int(get_context_window_tokens() or 0)
        return w if w >= 2000 else 32000
    except Exception:  # noqa: BLE001
        return 32000


# --------------------------------------------------------------------------- prepare
def prepare_review(data_dir: Path | str, actor: Any, machine: str, root: str, *,
                   profile_name: str | None = None, verifier_name: str | None = None,
                   fresh: bool = False) -> Plan:
    """Read the root's source (E.7a `review` purpose), slice it, and return a Plan with the
    consent summary. Refused for anything but a person at the Kratos host."""
    data_dir = Path(data_dir)
    REPRO.sweep(data_dir)
    profile = _resolve_profile(profile_name, data_dir)
    verifier = _resolve_verifier(verifier_name, profile, data_dir)
    info = _gather(data_dir, machine, root)

    from kratos.code.reads import read_for_review, review_extensions
    exts = review_extensions()
    rels = [r for r in info["all_sizes"] if r.lower().endswith(exts)]
    try:
        files, read_info = read_for_review(data_dir, machine, root, rels, actor=actor)
    except Exception as e:  # ReviewRefused / transport errors
        from kratos.code.reads import ReviewRefused as RR
        if isinstance(e, RR):
            raise ReviewRefused(str(e)) from None
        raise PlanError(f"can't read the code now: {e}") from None

    mask_mode = _mask_mode(data_dir, profile)
    reproduction = REPRO.reproduction_enabled(data_dir)
    plan = PLAN.build_plan(
        data_dir, machine=machine, target_key=info["tk"], root=root, root_id=info["root_id"],
        files=files, read_info=read_info, file_hashes=info["file_hashes"], all_sizes=info["all_sizes"],
        git_status=info["git_status"], serving_cfg=info["serving_cfg"], open_advisories=info["open_advisories"],
        local_addresses=info["local_addresses"], root_serving=info["root_serving"], profile=profile,
        verifier=verifier, mask_mode=mask_mode, reproduction=reproduction, window_tokens=_window_tokens(),
        fresh=fresh)
    return plan


def _resolve_profile(name: str | None, data_dir: Path) -> ReviewProfile:
    want = name if name is not None else RS.get(RS.LLM_PROFILE, data_dir)
    try:
        return resolve(want)
    except UnknownProfile as e:
        raise ReviewRefused(str(e)) from None


def _resolve_verifier(name: str | None, profile: ReviewProfile, data_dir: Path) -> ReviewProfile | None:
    want = name if name is not None else RS.get(RS.VERIFIER_LLM_PROFILE, data_dir)
    if not str(want or "").strip():
        return None
    try:
        v = resolve(want)
    except UnknownProfile as e:
        raise ReviewRefused(str(e)) from None
    return v if v.name != profile.name else None


def _mask_mode(data_dir: Path, profile: ReviewProfile) -> str:
    try:
        from kratos.privacy import mode as PM
        return PM.resolve_for(local=profile.local, data_dir=data_dir) if hasattr(PM, "resolve_for") else PM.resolve(data_dir)
    except Exception:  # noqa: BLE001
        return "off" if profile.local else "standard"


# --------------------------------------------------------------------------- start
@dataclass
class RunResult:
    run_id: int
    state: str
    stop_reason: str = ""
    actual_usd: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, Any] = field(default_factory=dict)


def start_review(data_dir: Path | str, actor: Any, plan_id: str, *, agreed_usd: float,
                 on_progress: Progress | None = None, should_stop: Stop | None = None,
                 raised_by: str = "", raised_to: float | None = None) -> RunResult:
    """Send the plan's slices, decide every verdict by code, store and publish findings. Only
    reachable with a plan id from `prepare_review` (person-started)."""
    from kratos.run_context import run_scope
    from kratos.trace import recorder as trace

    data_dir = Path(data_dir)
    plan = PLAN.get_plan(plan_id)
    if plan is None:
        raise PlanError("the plan expired or was never prepared -- prepare it again")
    _require_person(actor, data_dir, plan.machine, plan.root)

    lock = _root_lock(plan.target_key, plan.root)
    if not lock.acquire(blocking=False):
        raise ReviewRefused("a review of this root is running")
    source = "interactive" if getattr(actor, "interface", "") == "tui" else "cli"
    try:
        with run_scope(source, target=plan.machine) as ctx:
            with trace.run_trace("review", data_dir, name=f"review {plan.root}"):
                return _run(data_dir, actor, plan, agreed_usd=agreed_usd, run_ctx=ctx,
                            on_progress=on_progress or (lambda *a: None),
                            should_stop=should_stop or (lambda: False),
                            raised_by=raised_by, raised_to=raised_to)
    finally:
        lock.release()
        PLAN.drop_plan(plan_id)


def _require_person(actor: Any, data_dir: Path, machine: str, root: str) -> None:
    from kratos import authz
    from kratos.lifecycle.decide import Actor
    from kratos.settings_store import in_tool_call
    if in_tool_call() is not None:
        raise ReviewRefused("a review can't be started from a tool call")
    if not isinstance(actor, Actor) or getattr(actor, "interface", "") not in ("tui", "cli"):
        raise ReviewRefused("a review needs a person at the Kratos computer (TUI or CLI)")
    try:
        authz.require(actor, authz.P.CODE_REVIEW_START, machine, data_dir=data_dir, obj=f"code root {root}")
    except authz.Denied as e:
        raise ReviewRefused(str(e)) from None


def _run(data_dir: Path, actor: Any, plan: Plan, *, agreed_usd: float, run_ctx: Any,
         on_progress: Progress, should_stop: Stop, raised_by: str, raised_to: float | None) -> RunResult:
    from kratos.budget.ledger import BudgetLedger
    from kratos.review import hunt as HUNT
    from kratos.review.modelcall import ReviewModelError

    hunter = plan.profile
    verifier = plan.verifier or plan.profile
    run_id_db = ST.create_run(
        data_dir, target_key=plan.target_key, machine=plan.machine, root=plan.root, profile=hunter.name,
        verifier_profile=verifier.name, destination=hunter.destination, mask_mode=plan.mask_mode,
        estimate_usd=plan.estimate.usd, agreed_usd=agreed_usd, est_calls=plan.estimate.calls,
        est_tokens=plan.estimate.tokens, reproduction=plan.reproduction, logic_version=plan.logic_version,
        actor=actor, raised_by=raised_by, raised_to=raised_to)
    _authorize_run_caps(data_dir, run_ctx, hunter)

    # Re-check hashes at send: drop slices whose file changed since the person agreed.
    cur_hashes = _current_hashes(data_dir, plan)
    to_review, changed = PLAN.recheck_hashes(plan, cur_hashes)
    counts: dict[str, Any] = {"cached": len(plan.cached), "dropped_by_cap": plan.dropped_by_cap,
                              "changed_since_consent": changed, "too_large": plan.stats.too_large,
                              "leads_dropped": {"outside": 0, "over_cap_call": 0, "over_cap_run": 0},
                              "incomplete_languages": dict(plan.stats.other_language),
                              "reviewed": 0, "reproduced": 0}
    slice_rows = [_slice_row(sl, ledger_state="looked_at", file_sha=plan.file_hashes.get(sl.rel, ""))
                  for sl in to_review]
    slice_rows += [_slice_row(c["slice"], ledger_state="verdict_reached",
                              file_sha=plan.file_hashes.get(c["slice"].rel, "")) for c in plan.cached]
    ST.add_slices(data_dir, run_id_db, plan.target_key, slice_rows)

    findings_data: list[dict[str, Any]] = []
    # Cached verdicts become findings with no send.
    for c in plan.cached:
        findings_data.append(_verdict_to_finding(c["slice"], _row_verdict(c["verdict"]), c["verdict"]))

    ledger = BudgetLedger(data_dir)
    stop_reason = ""
    state = "done"

    def spent() -> float:
        try:
            return float(ledger.totals_for_run(run_ctx.run_id).cost_usd or 0.0)
        except Exception:  # noqa: BLE001
            return 0.0

    per_call_reserve = (plan.estimate.usd / plan.estimate.calls) if plan.estimate.calls else 0.0

    def budget_blocks() -> bool:
        return plan.estimate.priced and COST.would_exceed(spent(), per_call_reserve, agreed_usd)

    try:
        batches = HUNT.build_batches(to_review, run_id=f"run{run_id_db}", window_tokens=_window_tokens())
        slice_by_sha = {sl.sha256: sl for sl in to_review}
        leads_seen: set[tuple[str, int, str]] = set()
        total_leads = 0
        max_leads = int(RS.get(RS.MAX_LEADS, data_dir))
        max_leads_per_call = int(RS.get(RS.MAX_LEADS_PER_CALL, data_dir))
        for b in batches:
            if should_stop():
                state, stop_reason = "stopped", "you stopped the review"
                break
            if budget_blocks():
                state, stop_reason = "stopped", "reached the agreed amount"
                break
            on_progress("hunting", {"class": b.cls, "slices": len(b.slices)})
            hr = HUNT.hunt(hunter, [b], max_leads_per_call=max_leads_per_call,
                           max_leads=max(0, max_leads - total_leads))
            for k in ("outside", "over_cap_call", "over_cap_run"):
                counts["leads_dropped"][k] += hr.drops.get(k, 0)
            for lead in hr.leads:
                key = (lead.file, lead.line, lead.cls)
                if key in leads_seen:
                    continue
                leads_seen.add(key)
                total_leads += 1
                sl = slice_by_sha.get(lead.slice_sha) or _slice_for_lead(to_review, lead)
                if sl is None:
                    continue
                ST.add_candidate(data_dir, run_id_db, slice_sha=sl.sha256, cls=lead.cls, file=lead.file,
                                 line=lead.line, reason=lead.reason, call_ids=[b.call_id])
                ST.set_ledger_state(data_dir, run_id_db, sl.sha256, sl.cls, "lead_raised")
                if should_stop() or budget_blocks():
                    state, stop_reason = "stopped", ("you stopped the review" if should_stop()
                                                     else "reached the agreed amount")
                    raise _Stop()
                vd, fd = _decide_lead(data_dir, plan, sl, lead, hunter, verifier, run_id_db,
                                     budget_blocks, should_stop)
                counts["reviewed"] += 1
                if vd.strength == V.REPRODUCED:
                    counts["reproduced"] += 1
                ST.set_ledger_state(data_dir, run_id_db, sl.sha256, sl.cls, "verdict_reached")
                if fd is not None:
                    findings_data.append(fd)
        # Slices with no lead still reached a code verdict? No -- a slice with no lead is
        # "looked at" with nothing found; its cell stays looked_at (incomplete coverage shows it).
    except _Stop:
        pass
    except ReviewModelError as e:
        state, stop_reason = "stopped", f"the model endpoint failed: {e}"
    except Exception as e:  # noqa: BLE001 -- 0.4 budget cap or anything else: stop cleanly, keep partial
        from kratos.budget.guard import BudgetExceeded
        if isinstance(e, BudgetExceeded):
            state, stop_reason = "stopped", "daily budget"
        else:
            state, stop_reason = "error", f"{type(e).__name__}: {str(e)[:200]}"

    actual = spent()
    counts["coverage"] = _coverage_counts(data_dir, run_id_db)
    ST.finish_run(data_dir, run_id_db, state=state, stop_reason=stop_reason, actual_usd=actual, counts=counts)
    try:
        findings = _publish(data_dir, plan, findings_data, run_id_db, counts, actual, agreed_usd)
    except Exception:  # noqa: BLE001 -- never let publishing fail the run's own completion
        findings = findings_data
    return RunResult(run_id=run_id_db, state=state, stop_reason=stop_reason, actual_usd=actual,
                     findings=findings, counts=counts)


class _Stop(Exception):
    pass


def _authorize_run_caps(data_dir: Path, run_ctx: Any, profile: ReviewProfile) -> None:
    """Raise 0.4's per-run call/token caps for THIS review run only (gate answer 2): the agreed
    dollar amount is the real limit for a review, not the default 40 calls / 300k tokens."""
    from kratos.budget.ledger import BudgetLedger, OVERRIDE
    from kratos.budget import limits as L
    import json as _json
    try:
        ledger = BudgetLedger(data_dir)
        now = time.time()
        with ledger.transaction() as conn:
            day = _day(now, data_dir)
            for scope in (L.SCOPE_RUN_CALLS, L.SCOPE_RUN_TOKENS):
                ledger.insert(conn, at=now, day=day, status=OVERRIDE,
                              source="interactive", model=profile.model, local=profile.local,
                              run_id=run_ctx.run_id, note=_json.dumps({"scope": scope, "review": True}))
    except Exception:  # noqa: BLE001 -- the review's own agreed-amount stop still bounds it
        pass


def _day(now: float, data_dir: Path) -> str:
    from kratos.budget.guard import local_day
    return local_day(now, data_dir)


def _decide_lead(data_dir: Path, plan: Plan, sl: Any, lead: Any, hunter: ReviewProfile,
                 verifier: ReviewProfile, run_id_db: int, budget_blocks, should_stop) -> tuple[V.Verdict, dict | None]:
    from kratos.review import verify as VERIFY
    from kratos.review import fix as FIX
    rule = RULES.direct(plan.index, sl)
    disproof = None
    if not (budget_blocks() or should_stop()):
        disproof = VERIFY.verify(verifier, lead, sl, run_id=f"run{run_id_db}")
    repro = REPRO.reproduce(sl, plan.index, data_dir=data_dir, run_id=f"run{run_id_db}-{sl.id}",
                            enabled=plan.reproduction)
    vd = V.decide(sl.cls, rule, repro, disproof)

    fix_words = fix_added = fix_check = ""
    if vd.kind in (V.CONFIRMED, V.NEEDS_VALIDATION) and not (budget_blocks() or should_stop()):
        try:
            proposal = FIX.propose(hunter, sl, sl.cls, run_id=f"run{run_id_db}")
            fix_words, fix_added = proposal.words, proposal.added
            if vd.strength == V.REPRODUCED and fix_added:
                fix_check = REPRO.fix_recheck(sl, plan.index, fix_added, data_dir=data_dir,
                                              run_id=f"run{run_id_db}-{sl.id}", enabled=plan.reproduction)
        except Exception:  # noqa: BLE001 -- a failed fix proposal never fails the verdict
            pass

    hv = hunter.model if vd.from_verifier else ""
    vv = verifier.model if vd.from_verifier else ""
    CACHE.store_verdict(data_dir, vd, slice_sha=sl.sha256, context_sha=sl.context_sha256, cls=sl.cls,
                        hunter_model=hunter.model, verifier_model=verifier.model, fix_words=fix_words,
                        fix_added=fix_added, fix_check=fix_check)
    fd = None
    if vd.kind != V.REJECTED:
        fd = _verdict_to_finding(sl, vd, {"fix_words": fix_words, "fix_added": fix_added, "fix_check": fix_check})
    return vd, fd


# --------------------------------------------------------------------------- helpers
def _current_hashes(data_dir: Path, plan: Plan) -> dict[str, str]:
    from kratos.code import store as CS
    files = CS.files(data_dir, plan.root_id, "current")
    return {rel: (f.get("sha256") or "") for rel, f in files.items()}


def _slice_row(sl: Any, *, ledger_state: str, file_sha: str = "") -> dict[str, Any]:
    return {"slice_sha": sl.sha256, "context_sha": sl.context_sha256, "file": sl.rel, "span": sl.span,
            "function": sl.function, "class": sl.cls, "exposure": sl.exposure, "drift": sl.drift,
            "served": sl.served, "part": sl.part, "nbytes": sl.nbytes, "language": sl.language,
            "ledger_state": ledger_state, "file_sha": file_sha}


def _slice_for_lead(slices: list[Any], lead: Any) -> Any | None:
    for sl in slices:
        if any(rel == lead.file and a <= lead.line <= b for rel, a, b in sl.segments) and sl.cls == lead.cls:
            return sl
    return next((sl for sl in slices if sl.cls == lead.cls), None)


def _row_verdict(row: dict[str, Any]) -> V.Verdict:
    return V.Verdict(kind=row.get("verdict", ""), strength=row.get("strength", ""),
                     evidence=row.get("evidence", ""), question=row.get("question", ""),
                     from_verifier=bool(row.get("hunter_model")))


def _verdict_to_finding(sl: Any, vd: V.Verdict, extra: dict[str, Any]) -> dict[str, Any]:
    line = sl.calls[0].line if sl.calls else sl.span[0]
    return {"slice_sha": sl.sha256, "rel": sl.rel, "function": sl.function, "cls": sl.cls, "line": line,
            "root": sl.root, "exposure": sl.exposure, "served": sl.served, "drift": sl.drift,
            "route": sl.route, "verdict": vd.kind, "strength": vd.strength, "evidence": vd.evidence,
            "question": vd.question, "fix_words": extra.get("fix_words", ""),
            "fix_added": extra.get("fix_added", ""), "fix_check": extra.get("fix_check", "")}


def _coverage_counts(data_dir: Path, run_id_db: int) -> dict[str, Any]:
    from kratos.review import ledger as LED
    rows = ST.slices(data_dir, run_id_db)
    cov = LED.coverage(rows)
    return {"overall_pct": LED.overall_pct(rows),
            "incomplete": [{"class": c.cls, "pct": c.pct, "reached": c.reached, "total": c.total}
                           for c in LED.incomplete_classes(rows)]}


def _publish(data_dir: Path, plan: Plan, findings_data: list[dict[str, Any]], run_id_db: int,
             counts: dict[str, Any], actual: float, agreed: float) -> list[dict[str, Any]]:
    """Write the review snapshot and publish findings through the engine (lifecycle/triage)."""
    from kratos.review import judge
    run = ST.get_run(data_dir, run_id_db) or {}
    doc = judge.build_doc(plan, findings_data, run, counts, actual, agreed)
    judge.write_snapshot(data_dir, plan.machine, doc)
    judge.publish(data_dir, plan.machine)
    return findings_data
