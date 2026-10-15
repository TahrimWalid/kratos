"""prepare(): make sure the basics are fresh for one machine, by code, on a time budget.

For each check of the requested classes: a fresh result is reused; a stale one is
claimed (so two processes never run the same check on the same machine at once) and
run in its own thread, all in parallel; whatever has not finished when the budget
runs out is cancelled -- its `ssh`/`nmap` process killed, never left running -- and
reported as "not checked this time". Then `correlate_findings` runs once over the
refreshed inputs. No model is called anywhere in here.
"""
from __future__ import annotations

import contextvars
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos import kratos_config, settings_store
from kratos.collect import registry, state
from kratos.collect import settings as collect_settings
from kratos.collect.registry import Check, CheckContext, CheckResult
from kratos.target_key import target_key
from kratos.utils import cancel

logger = logging.getLogger(__name__)

Dispatch = Callable[[str, dict[str, Any], Path], dict[str, Any]]

CANCEL_GRACE_SECONDS = 3.0        # how long a cancelled check gets to unwind before we stop waiting
WAIT_POLL_SECONDS = 0.25
OVER_BUDGET = "not checked this time (over the time budget)"


@dataclass
class CheckOutcome:
    name: str
    label: str
    cost: str
    status: str                       # ok | partial | failed | skipped | not_supported
    source: str                       # ran | reused | waited | skipped
    summary: str
    gaps: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    finished_at: float | None = None  # epoch UTC of the result being reported
    age_seconds: float | None = None
    reason: str = ""                  # why it was skipped, in plain words
    tools: list[str] = field(default_factory=list)
    inputs: tuple[str, ...] = ()
    steps: list[dict[str, Any]] = field(default_factory=list)   # the tool calls a fresh run made (transcript)

    @property
    def usable(self) -> bool:
        return self.status in ("ok", "partial")


@dataclass
class CollectionReport:
    target: str
    target_key: str
    transport: str | None
    checks: list[CheckOutcome] = field(default_factory=list)
    correlation: dict[str, Any] | None = None     # correlate_findings' inner result, when it succeeded
    correlation_error: str | None = None
    correlation_step: dict[str, Any] | None = None   # {"tool","args","observation"} of the correlate_findings call
    started: float = 0.0
    finished: float = 0.0
    budget_seconds: float = 0.0
    disabled_reason: str | None = None            # set when nothing was attempted (off, no target, ...)

    @property
    def findings(self) -> list[dict[str, Any]]:
        return list((self.correlation or {}).get("findings") or [])

    @property
    def cold(self) -> bool:
        """True when nothing was reused: every check had to run (or was skipped)."""
        return not any(c.source in ("reused", "waited") for c in self.checks)

    @property
    def elapsed(self) -> float:
        return max(0.0, self.finished - self.started)

    def gaps(self) -> list[str]:
        out: list[str] = []
        for c in self.checks:
            for g in c.gaps:
                if g not in out:
                    out.append(g)
        return out

    def tools_used(self) -> list[str]:
        out: list[str] = []
        for c in self.checks:
            for t in c.tools:
                if t not in out:
                    out.append(t)
        if self.correlation is not None and "correlate_findings" not in out:
            out.append("correlate_findings")
        return out

    def any_ok(self) -> bool:
        return any(c.usable for c in self.checks)


WARM_WAIT_SECONDS = 3.0


def _warm_ssh(host: str) -> None:
    """Open the shared SSH connection before the checks start, so they reuse one
    handshake instead of racing to open several (phase A audit: 10 logins in one
    second from one cold collection). Waits at most WARM_WAIT_SECONDS; a slow or
    unreachable machine just goes on as before -- the checks report what fails."""
    def warm() -> None:
        try:
            from kratos.adapters import ssh_remote
            with kratos_config.pinned_target(host):
                ssh_remote.warm_connection()
        except Exception:  # noqa: BLE001 -- best effort only
            logger.debug("collect: ssh warm-up failed", exc_info=True)

    t = threading.Thread(target=contextvars.copy_context().run, args=(warm,), name="collect-ssh-warm", daemon=True)
    t.start()
    t.join(WARM_WAIT_SECONDS)


def _available_transports(target: str, data_dir: Path) -> tuple[set[str], str | None]:
    """(transports a check may use for this machine, the one reads go through first)."""
    from kratos.subagent import routing

    host = routing.normalize_host(target)
    if host in routing._LOOPBACK:
        return {"local"}, "local"
    link = routing.link_for(target, data_dir)
    if link is None:
        return {"ssh"}, "ssh"
    if link.mode == routing.MODE_SUBAGENT:
        return {"agent"}, "agent"
    return {"ssh", "agent"}, "ssh"


def _inputs_present(check: Check, data_dir: Path, target: str) -> bool:
    """A fresh row whose input files are gone (a different data folder, deleted) is not
    a fresh result for the findings engine."""
    from kratos.adapters.findings_engine import find_latest_inputs

    try:
        found = find_latest_inputs(data_dir, target)
    except Exception:  # noqa: BLE001 -- discovery trouble means "re-run", never a crash
        return False
    # "events" is not a findings-engine file: that check's result lives in the event store.
    # "events" and "vuln_scan" are not files find_latest_inputs discovers (the event store; the
    # findings engine loads the newest scan itself): nothing to check for those.
    return all(found.get(cat) is not None for cat in check.inputs if cat in found)


class _Box:
    """A check thread's result slot."""
    __slots__ = ("result", "error", "cancelled", "done")

    def __init__(self) -> None:
        self.result: CheckResult | None = None
        self.error: BaseException | None = None
        self.cancelled = False
        self.done = threading.Event()


def _short_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc)[:200]}"


def _thread_main(check: Check, ctx: CheckContext, scope: cancel.CancelScope, box: _Box) -> None:
    try:
        with cancel.bound(scope), kratos_config.pinned_target(ctx.target):
            box.result = check.run(ctx)
    except cancel.Cancelled:
        box.cancelled = True
    except BaseException as e:  # noqa: BLE001 -- one check failing must not stop the others
        box.error = e
    finally:
        box.done.set()


def _default_dispatch() -> Dispatch:
    from kratos.agent.loop import execute_tool_call

    return execute_tool_call


def prepare(
    target: str | None = None,
    data_dir: Path | str | None = None,
    *,
    classes: tuple[str, ...] = ("quick",),
    budget: float | None = None,
    force: bool = False,
    only: tuple[str, ...] | None = None,
    dispatch: Dispatch | None = None,
    correlate: bool = True,
    now: float | None = None,
    on_outcome: Callable[[CheckOutcome], None] | None = None,
) -> CollectionReport:
    from kratos.collect import checks as _checks  # noqa: F401 -- the built-in checks register themselves on import

    data_dir = Path(data_dir) if data_dir is not None else kratos_config.get_active_data_dir()
    host = (target or kratos_config.get_active_target() or "").strip()
    started = time.time() if now is None else now
    report = CollectionReport(target=host, target_key=target_key(host) if host else "", transport=None,
                              started=started, finished=started)
    if not host:
        report.disabled_reason = "no target is set"
        return report
    if data_dir is None:
        report.disabled_reason = "no data folder"
        return report
    if budget is None:
        budget = float(settings_store.get(collect_settings.START_BUDGET, data_dir=data_dir))
    report.budget_seconds = float(budget)
    available, first = _available_transports(host, data_dir)
    report.transport = first
    if first == "ssh":
        _warm_ssh(host)
    dispatch = dispatch or _default_dispatch()
    owner = state.new_owner()
    mono_start = time.monotonic()
    overall_deadline = mono_start + budget
    stale_claim = max(2.0 * budget, 30.0)

    selected = [c for c in registry.checks() if c.cost in classes and (only is None or c.name in only)]
    running: list[tuple[Check, threading.Thread, cancel.CancelScope, _Box, float, CheckContext]] = []
    waiting: list[tuple[Check, state.Row]] = []
    by_name: dict[str, CheckOutcome] = {}

    def outcome(check: Check, **kw: Any) -> CheckOutcome:
        o = CheckOutcome(name=check.name, label=check.label, cost=check.cost, inputs=check.inputs, **kw)
        by_name[check.name] = o
        if on_outcome is not None:
            try:
                on_outcome(o)
            except Exception:  # noqa: BLE001 -- a display callback must not break collection
                logger.debug("collect: on_outcome callback failed", exc_info=True)
        return o

    for check in selected:
        usable = check.transports & available
        if not usable:
            outcome(check, status="not_supported", source="skipped", summary="not checked on this machine",
                    reason=f"needs {'/'.join(sorted(check.transports))}; this machine is reached by "
                           f"{'/'.join(sorted(available))}")
            continue
        ttl_s = 60.0 * int(settings_store.get(check.ttl_setting, data_dir=data_dir))
        claim = state.claim(data_dir, report.target_key, check.name, ttl_seconds=ttl_s,
                            stale_claim_seconds=stale_claim, owner=owner,
                            force=force or not _inputs_present(check, data_dir, host), now=started)
        if claim.kind == "fresh":
            row = claim.row
            assert row is not None
            outcome(check, status=row.status or "ok", source="reused", summary=row.summary, gaps=list(row.gaps),
                    finding_ids=list(row.finding_ids), finished_at=row.finished_at, age_seconds=row.age(started))
            continue
        if claim.kind == "busy":
            assert claim.row is not None
            waiting.append((check, claim.row))
            continue
        scope = cancel.CancelScope()
        box = _Box()
        ctx = CheckContext(
            target=host, target_key=report.target_key, data_dir=data_dir,
            transport=first if first in usable else sorted(usable)[0],
            dispatch=dispatch, deadline=min(overall_deadline, mono_start + check.budget_seconds), now=started)
        pycontext = contextvars.copy_context()
        thread = threading.Thread(target=pycontext.run, args=(_thread_main, check, ctx, scope, box),
                                  name=f"collect-{check.name}", daemon=True)
        running.append((check, thread, scope, box, time.time(), ctx))
        thread.start()

    # --- wait for the checks we started, up to each one's own cap and the overall budget ---
    for check, thread, scope, box, t_start, ctx in running:
        limit = min(overall_deadline, mono_start + check.budget_seconds)
        box.done.wait(timeout=max(0.0, limit - time.monotonic()))
        out_of_time = not box.done.is_set()
        if out_of_time:
            scope.cancel()
            box.done.wait(timeout=CANCEL_GRACE_SECONDS)
        finished = time.time()
        if box.result is not None and not box.cancelled and not out_of_time:
            res = box.result
            o = outcome(check, status=res.status, source="ran", summary=res.summary, gaps=list(res.coverage_gaps),
                        finished_at=finished, age_seconds=0.0, tools=list(res.tools), steps=list(ctx.steps))
            state.finish(data_dir, report.target_key, check.name, owner=owner, started_at=t_start,
                         finished_at=finished, status=res.status, summary=res.summary, gaps=o.gaps,
                         detail=res.detail)
        else:
            if box.error is not None and not out_of_time:
                reason, detail = "the check failed", _short_error(box.error)
                logger.warning("collect: %s failed: %s", check.name, detail)
                summary, status = f"could not be checked ({reason})", "failed"
            else:
                reason, detail = "over the time budget", "cancelled at the time budget"
                summary, status = OVER_BUDGET, "skipped"
            outcome(check, status=status, source="skipped", summary=summary, reason=reason,
                    gaps=[f"{check.label}: {summary}"], finished_at=finished, age_seconds=0.0)
            state.finish(data_dir, report.target_key, check.name, owner=owner, started_at=t_start,
                         finished_at=finished, status=status, summary=summary, gaps=[f"{check.label}: {summary}"],
                         detail=detail)

    # --- checks someone else is running: wait for their result, within what is left of the budget ---
    for check, holder in waiting:
        got: state.Row | None = None
        while time.monotonic() < overall_deadline:
            row = state.get(data_dir, report.target_key, check.name)
            if row is not None and (row.running_by != holder.running_by or row.running_since is None):
                got = row
                break
            time.sleep(WAIT_POLL_SECONDS)
        if got is not None and got.status in state.USABLE and (got.finished_at or 0) >= started - 1:
            outcome(check, status=got.status or "ok", source="waited", summary=got.summary, gaps=list(got.gaps),
                    finding_ids=list(got.finding_ids), finished_at=got.finished_at, age_seconds=got.age(started))
        else:
            outcome(check, status="skipped", source="skipped", summary="not checked this time (another run is still checking)",
                    reason="another run was still checking", gaps=[f"{check.label}: not checked this time"])

    report.checks = [by_name[c.name] for c in selected if c.name in by_name]

    if correlate and report.any_ok():
        try:
            res = dispatch("correlate_findings", {}, data_dir)
        except Exception as e:  # noqa: BLE001
            report.correlation_error = _short_error(e)
        else:
            report.correlation_step = {"tool": "correlate_findings", "args": {}, "observation": res}
            inner = res.get("result") if isinstance(res, dict) else None
            if isinstance(inner, dict) and isinstance(inner.get("findings"), list):
                report.correlation = inner
            else:
                report.correlation_error = str((res or {}).get("observation") or "correlate_findings failed")[:200]
        _attach_findings(report, data_dir)

    report.finished = time.time()
    return report


def _attach_findings(report: CollectionReport, data_dir: Path) -> None:
    """Tell each check which findings rest on its inputs (digest: "-> LOG-001 (high)")."""
    if report.correlation is None:
        return
    from kratos.adapters.findings_engine import rule_inputs

    for o in report.checks:
        ids: list[str] = []
        for f in report.findings:
            fid = str(f.get("id") or "")
            if fid and set(rule_inputs(fid)) & set(o.inputs) and fid not in ids:
                ids.append(fid)
        o.finding_ids = ids
        if o.source == "ran" or o.source == "reused":
            try:
                state.set_finding_ids(data_dir, report.target_key, o.name, ids)
            except Exception:  # noqa: BLE001 -- bookkeeping only
                logger.debug("collect: could not store finding ids for %s", o.name, exc_info=True)
