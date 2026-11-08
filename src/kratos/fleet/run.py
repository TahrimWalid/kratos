"""The one front door for a question (or an audit) about a group of machines (D.2).

Every surface -- the TUI, ``kratos fleet ask``, the chat server, MCP, schedules -- calls
:func:`run_fleet`. It resolves the group within the caller's scope, builds the cost
estimate (and, for an unattended run, refuses BEFORE any read when the estimate would
exceed what is left of the unattended cap), opens the run scope and its one run record,
collects every machine in parallel (``fleet.collect``), answers once (``fleet.answer``)
or -- for an audit -- builds the report by code, records the run, and sends at most ONE
grouped notification. The fix channel is never reachable from here.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from kratos import kratos_config
from kratos.fleet import groups as fleet_groups
from kratos.fleet import settings as fleet_settings
from kratos.lifecycle.decide import Actor

logger = logging.getLogger(__name__)

KINDS = ("question", "audit")
RUN_INTERFACES = ("tui", "cli", "serve", "mcp", "schedule")
# Rough sizes for the estimate (measured on the lab, D.2 Handoff): what one machine's
# block costs in the digest, the prompt around it, and one answer.
_BLOCK_CHARS = 4500        # 5 lab machines: ~24k characters of blocks (D.2 Handoff)
_PROMPT_CHARS = 4000
_ANSWER_TOKENS = 250       # per machine in the reply
_CHARS_PER_TOKEN = 4

FIX_CHANNEL_REFUSAL = ("Not in a fleet answer: Kratos never runs a fix on several machines at once. Open one "
                       "machine (/look <machine>) and use /run-fix there.")


class FleetError(ValueError):
    """The question can't run as asked (no such group, nothing visible, no person)."""


@dataclass
class Estimate:
    machines: int
    model_calls: int            # expected (an answer); worst case is max_calls
    max_calls: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float | None      # None: no price on file (local model, or unknown)
    model: str

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def text(self) -> str:
        if self.model_calls == 0:
            return f"{self.machines} machine(s), collected by Kratos only -- no model call."
        cost = f", about ${self.cost_usd:.3f}" if self.cost_usd is not None else ""
        return (f"{self.machines} machine(s) collected by Kratos, then one model call for the whole group "
                f"(≈{self.tokens:,} tokens{cost}; at most {self.max_calls} calls with extra reads and corrections).")

    def as_dict(self) -> dict[str, Any]:
        return {"machines": self.machines, "model_calls": self.model_calls, "max_calls": self.max_calls,
                "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens,
                "cost_usd": self.cost_usd, "model": self.model}


def estimate(n_machines: int, data_dir: Path | str, *, kind: str = "question") -> Estimate:
    from kratos.budget import pricing
    from kratos.fleet.answer import MAX_ROUNDS
    from kratos.llm_config import _active_backend_is_local, get_active_llm_model

    data_dir = Path(data_dir)
    model = get_active_llm_model()
    if kind == "audit":
        return Estimate(n_machines, 0, 0, 0, 0, 0.0, model)
    cap = fleet_settings.get(fleet_settings.DIGEST_CHARS, data_dir)
    extra = fleet_settings.get(fleet_settings.EXTRA_READS, data_dir)
    chars = min(cap, n_machines * _BLOCK_CHARS) + _PROMPT_CHARS
    prompt = chars // _CHARS_PER_TOKEN
    completion = n_machines * _ANSWER_TOKENS
    rate = None if _active_backend_is_local() else pricing.rate_for(model, data_dir)
    cost = pricing.tokens_cost(rate, prompt, completion) if rate is not None else None
    return Estimate(n_machines, 1, min(MAX_ROUNDS, 2 + extra), prompt, completion, cost, model)


@dataclass
class FleetRequest:
    question: str
    group: str | list[str]                 # '@web' / 'web' / '@all', or a list of machines
    data_dir: Path
    actor: Actor
    source: str = "interactive"            # a run_context source
    kind: str = "question"                 # question | audit
    scope: Iterable[str] | None = None     # the caller's visible machines (None = all)
    slow: bool = False                     # also run the slow checks (vulnerability scan, YARA, ...)
    timezone: str | None = None
    notify: bool = False                   # one grouped notification for the run
    notifier: Callable[[str, str], Any] | None = None
    on_progress: Callable[[str], None] | None = None
    should_stop: Callable[[], bool] | None = None
    confirm: Callable[[Estimate], bool] | None = None   # interactive: shown the estimate first
    name: str = ""                         # a schedule's or trigger's name, for the record


@dataclass
class FleetOutcome:
    status: str                            # final_answer | fallback | audit | refused_by_budget | cancelled | ...
    text: str
    run_id: str | None = None
    group_label: str = ""
    estimate: Estimate | None = None
    answer: Any = None                     # fleet.answer.FleetAnswer
    results: list[Any] = field(default_factory=list)
    resolved: Any = None
    refusal: str | None = None
    notified: bool = False
    token_usage: dict[str, Any] | None = None

    def machine_ids(self) -> list[str]:
        return [r.machine for r in self.results]


def _check_actor(actor: Actor) -> None:
    if not isinstance(actor, Actor) or actor.interface not in RUN_INTERFACES or not str(actor.user or "").strip():
        raise FleetError("a fleet run needs an actor (who asked, and through which interface)")


def _unattended_refusal(est: Estimate, data_dir: Path, source: str) -> str | None:
    """Before any read: the unattended day cap and the per-run caps, against the estimate."""
    from kratos.budget import guard, limits as L
    from kratos.budget.ledger import BudgetLedger
    from kratos.run_context import UNATTENDED

    refusal = guard.precheck(source, data_dir_=data_dir)
    if refusal is not None:
        return refusal.user_message()
    if est.model_calls == 0:
        return None
    lim = L.read(data_dir)
    if est.tokens > lim.run_tokens:
        return (f"Not started: this question is estimated at {est.tokens:,} tokens, over the per-run limit of "
                f"{lim.run_tokens:,} (Settings -> Budget). Ask about a smaller group.")
    if est.max_calls > lim.run_model_calls and est.model_calls > lim.run_model_calls:
        return f"Not started: the per-run model-call limit ({lim.run_model_calls}) is below what one answer needs."
    if source in UNATTENDED and est.cost_usd is not None:
        totals = BudgetLedger(data_dir).totals_for_day(guard.local_day(time.time(), data_dir))
        left = lim.unattended_daily_cost_usd - totals.unattended_cost_usd
        if est.cost_usd > left:
            return (f"Not started: this unattended question about {est.machines} machines is estimated at "
                    f"${est.cost_usd:.3f}, more than the ${max(0.0, left):.3f} left of today's unattended "
                    "limit (Settings -> Budget).")
    return None


def _run_cost(data_dir: Path, run_id: str | None) -> tuple[int | None, float | None]:
    if not run_id:
        return None, None
    try:
        from kratos.budget.ledger import BudgetLedger

        rows = BudgetLedger(data_dir).rows(run_id=run_id)
    except Exception:  # noqa: BLE001 -- bookkeeping only
        return None, None
    tokens = sum(int(r.get("total_tokens") or 0) for r in rows if r.get("status") == "settled")
    costs = [r.get("cost_usd") for r in rows if r.get("status") == "settled"]
    cost = sum(float(c) for c in costs if c is not None) if any(c is not None for c in costs) else None
    return tokens, cost


def run_fleet(req: FleetRequest) -> FleetOutcome:
    """Run one fleet question or audit. Raises FleetError only for a request that can't
    start (no group, nothing visible); everything else is a FleetOutcome in plain words."""
    from kratos import run_context
    from kratos.fleet import record
    from kratos.fleet.answer import answer_fleet
    from kratos.fleet.collect import collect_fleet
    from kratos.trace import recorder as _trace

    _check_actor(req.actor)
    if req.kind not in KINDS:
        raise FleetError(f"unknown fleet run kind {req.kind!r}")
    data_dir = Path(req.data_dir)
    if kratos_config.get_active_data_dir() is None:
        kratos_config.set_active_data_dir(data_dir)
    try:
        resolved = fleet_groups.resolve(data_dir, req.group, scope=req.scope)
    except fleet_groups.GroupError as e:
        raise FleetError(str(e)) from None
    label = resolved.label
    est = estimate(len(resolved.machines), data_dir, kind=req.kind)
    if req.confirm is not None and not req.confirm(est):
        return FleetOutcome("cancelled", "Not started.", group_label=label, estimate=est, resolved=resolved)
    question = " ".join(str(req.question or "").split())
    if req.kind == "question" and not question:
        raise FleetError("what should Kratos ask about these machines?")
    if req.kind == "audit" and not question:
        question = f"standard audit of {label}"

    with run_context.run_scope(req.source, target=None):
        refusal = _unattended_refusal(est, data_dir, req.source) if est.model_calls else None
        if refusal:
            return FleetOutcome("refused_by_budget", refusal, group_label=label, estimate=est,
                                resolved=resolved, refusal=refusal)
        with _trace.run_trace("fleet", data_dir, name=label, fleet_kind=req.kind, machines=len(resolved.machines),
                              outside_scope=resolved.outside_scope) as tr:
            run_id = tr.trace_id if tr is not None else (run_context.current().run_id if run_context.current() else None)
            time_ctx, time_block, now = _time_context(question, data_dir, req)
            record.start(data_dir, run_id=run_id or "", kind=req.kind, question=question, group_ref=label,
                         window=_window_record(time_ctx), actor=req.actor, source=req.source,
                         estimate=est.as_dict(), machines=len(resolved.machines),
                         outside_scope=resolved.outside_scope, trace_id=run_id)

            def make_ctx() -> Any:
                if req.kind != "question" or time_ctx is None:
                    return None
                from kratos.timewin.agentwin import prepare_time_context

                return prepare_time_context(question, data_dir, timezone_name=req.timezone, now=now)[0]

            classes = ("quick", "slow") if (req.slow or req.kind == "audit") else ("quick",)
            results = collect_fleet(resolved.machines, data_dir, classes=classes, force=req.kind == "audit",
                                    make_time_ctx=make_ctx, on_progress=req.on_progress,
                                    should_stop=req.should_stop)
            if req.kind == "audit":
                answer = _audit_answer(results)
            else:
                answer = answer_fleet(question, results, data_dir, time_block=time_block,
                                      extra_reads=fleet_settings.get(fleet_settings.EXTRA_READS, data_dir),
                                      digest_cap=fleet_settings.get(fleet_settings.DIGEST_CHARS, data_dir),
                                      outside_scope=resolved.outside_scope, on_progress=req.on_progress,
                                      should_stop=req.should_stop)
            if resolved.outside_scope:
                answer.summary += f" · {resolved.outside_scope} machine(s) in this group are outside your access"
            if resolved.duplicates:
                answer.summary += " · " + "; ".join(f"{a} is {b} (counted once)" for a, b in resolved.duplicates[:4])
            tokens, cost = _run_cost(data_dir, run_context.current().run_id if run_context.current() else None)
            passed = {m.machine: (m.passed if not m.kratos_text else None) for m in answer.machines}
            record.finish(data_dir, run_id or "", status=answer.status, summary=answer.summary, results=results,
                          passed=passed, tokens=tokens, cost_usd=cost, extra_reads=answer.extra_reads)
            _trace.set_result(status=answer.status, machines=len(results),
                              not_checked=sum(1 for r in results if not r.collected))
            notified = False
            if req.notify:
                from kratos.agent.scheduled_run import _sent

                res = _grouped_notification(req, label, results, answer, data_dir)
                notified = _sent(res) or (isinstance(res, dict) and res.get("status") == "queued")
            return FleetOutcome(answer.status, answer.render(), run_id=run_id, group_label=label, estimate=est,
                                answer=answer, results=results, resolved=resolved, notified=notified,
                                token_usage={"total_tokens": tokens, "cost_usd": cost})


def _time_context(question: str, data_dir: Path, req: FleetRequest) -> tuple[Any, str, float]:
    now = time.time()
    if req.kind != "question":
        return None, "", now
    try:
        from kratos.timewin.agentwin import prepare_time_context, render_time_block

        ctx, _log = prepare_time_context(question, data_dir, timezone_name=req.timezone, now=now)
    except Exception as e:  # noqa: BLE001 -- an unreadable period is said, not a crash
        logger.info("fleet: no time context: %s", e)
        return None, "", now
    return ctx, (render_time_block(ctx) if ctx.goal_ids else ""), now


def _window_record(ctx: Any) -> Any:
    if ctx is None or not getattr(ctx, "goal_ids", None):
        return None
    try:
        return [{"id": i, "label": ctx.windows[i].label, "start_utc": ctx.windows[i].start_utc,
                 "end_utc": ctx.windows[i].end_utc, "tz": ctx.tz_name} for i in ctx.goal_ids if i in ctx.windows]
    except Exception:  # noqa: BLE001
        return None


def _audit_answer(results: list[Any]) -> Any:
    """The standard audit's report: Kratos's own findings per machine, no model."""
    from kratos import finding_facts
    from kratos.fleet.answer import FleetAnswer, MachineAnswer, code_summary
    from kratos.fleet.digest import assign_ids, counts_line

    ans = FleetAnswer(status="audit", summary=code_summary(results))
    for mid, m in assign_ids(results).items():
        r = next(x for x in results if x.machine == m)
        ma = MachineAnswer(mid=mid, machine=r.machine, label=r.label, outcome=r.outcome, reason=r.reason)
        if not r.collected:
            ma.kratos_text = f"Not checked by Kratos in this run ({r.status_text})."
        else:
            ma.block = finding_facts.answer_block(r.findings, "")
            gaps = r.gaps
            ma.notes = (f"Kratos's own reading: {counts_line(r)}, {r.outcome_words}."
                        + (f" Not read: {'; '.join(g.rstrip(' .') for g in gaps[:5])}." if gaps else "") + "\n")
        ans.machines.append(ma)
    return ans


def _grouped_notification(req: FleetRequest, label: str, results: list[Any], answer: Any, data_dir: Path,
                          extra_lines: list[str] | None = None) -> dict[str, Any] | None:
    """ONE notification for the run: worst severity, the group, the machines with open
    serious findings or Act decisions, the ones not checked. No accounts, addresses
    of attackers or paths (it may cross a public ntfy server); machine names only."""
    from kratos import finding_facts
    from kratos.fleet.digest import _open

    notifier = req.notifier
    if notifier is None:
        from kratos.outbox.alerts import OutboxNotifier

        notifier = OutboxNotifier(data_dir=data_dir, source="fleet", name=req.name)
    serious = [r for r in results if finding_facts.serious(r.findings)]
    act = [r for r in results if any(str((f.get("ssvc") or {}).get("outcome") or "") == "act" for f in _open(r.findings))]
    missing = [r for r in results if not r.collected]
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    sevs = [str(f.get("severity") or "info").lower() for r in results for f in _open(r.findings)]
    worst = max(sevs, key=lambda s: rank.get(s, 0), default="info")
    worst = worst if worst in rank else "info"
    lines = [f"{worst.upper()} on {label}: {answer.summary}"]
    for r in serious[:5]:
        ids = ", ".join(sorted({str(f.get('id')) for f in finding_facts.serious(r.findings)})[:4])
        lines.append(f"- {r.label or r.machine}: {ids}")
    for r in act[:5]:
        if r not in serious:
            lines.append(f"- {r.label or r.machine}: an Act decision")
    for r in missing[:5]:
        lines.append(f"- {r.label or r.machine}: not checked ({r.outcome_words})")
    lines.extend((extra_lines or [])[:5])
    lines.append("Next: open Kratos and type /fleet")
    if req.name:
        lines.append(f"({req.name})")
    sev = "critical" if worst in ("critical", "high") else "warning" if worst == "medium" or missing else "info"
    try:
        from kratos.outbox.alerts import call

        return call(notifier, "\n".join(lines), sev, worst=worst, machines=[r.machine for r in results],
                    findings=[f for r in results for f in _open(r.findings)])
    except Exception:  # noqa: BLE001 -- a notification must never sink the run
        logger.warning("fleet: grouped notification failed", exc_info=True)
        return None
