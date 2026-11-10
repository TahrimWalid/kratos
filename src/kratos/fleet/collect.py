"""Collect a group of machines in parallel, each isolated (D.2 §3.2).

Every machine gets its own thread with ``kratos_config.pinned_target`` set, its own
target lock (one Kratos run per machine at a time, across processes), its own time
context (so one machine's measurements can never answer another's window), its own
A.0 ``prepare()`` and correlation -- exactly what a single-machine run does. Bounds:

* at most ``fleet.max_parallel`` machines at once (the rest wait their turn);
* ``fleet.machine_seconds`` per machine, waiting for the lock included -- a machine
  still running after that is reported ``timeout`` and its own commands are killed;
  the orchestrator never waits on it again;
* the per-host SSH slots and each check's own limits, as always.

Outcomes: ``ok`` (every check read) / ``partial`` (some read, some not) /
``unreachable`` (the reachability read failed; why, in plain words) / ``busy``
(another Kratos run held the machine for the whole limit) / ``timeout`` / ``failed``
(Kratos itself raised) / ``stopped`` (the person stopped the run). One machine's
exception never stops the others. No model is called here.
"""
from __future__ import annotations

import contextvars
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos import kratos_config
from kratos.fleet import settings as fleet_settings
from kratos.trace import recorder as _trace
from kratos.utils import cancel

logger = logging.getLogger(__name__)

OUTCOMES = ("ok", "partial", "unreachable", "busy", "timeout", "failed", "stopped", "refused-by-scope",
            "access-removed")
COLLECTED = frozenset({"ok", "partial"})
POLL_SECONDS = 0.2
CLOCK_SKEW_NOTE_SECONDS = 60.0
OUTCOME_WORDS = {
    "ok": "fully read",
    "partial": "partly read",
    "unreachable": "not reached",
    "busy": "busy (another Kratos run was using it)",
    "timeout": "timed out",
    "failed": "could not be checked (Kratos hit an error)",
    "stopped": "not checked (the run was stopped)",
    "refused-by-scope": "outside your access",
    "access-removed": "not checked (your access to it was removed during the run)",
}


def host_for(machine: str) -> str:
    """The address a stored machine (target_key form) is reached at."""
    return "127.0.0.1" if machine == "loopback" else machine


@dataclass
class MachineResult:
    machine: str                         # target_key form -- the id in every record
    label: str = ""                      # the sub-agent's name, when it has one (display only)
    outcome: str = "failed"
    reason: str = ""                     # why it isn't fully read, in plain words
    transport: str = ""                  # "SSH (key)" | "SSH (certificate)" | "sub-agent" | "this machine"
    agent_version: str | None = None
    cert_state: str | None = None
    report: Any = None                   # collect.runner.CollectionReport, when collected
    time_ctx: Any = None                 # this machine's own timewin.TimeContext
    clock_offset: float | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)   # what Kratos read, as transcript entries
    started: float = 0.0
    elapsed: float = 0.0
    span_id: str | None = None

    @property
    def collected(self) -> bool:
        return self.outcome in COLLECTED

    @property
    def findings(self) -> list[dict[str, Any]]:
        return list(getattr(self.report, "findings", None) or [])

    @property
    def gaps(self) -> list[str]:
        out = list(self.report.gaps()) if self.report is not None else []
        if self.outcome not in COLLECTED and self.status_text not in out:
            out.insert(0, self.status_text)
        return out

    @property
    def outcome_words(self) -> str:
        return OUTCOME_WORDS.get(self.outcome, self.outcome)

    @property
    def status_text(self) -> str:
        """'not reached: ssh: connect to host ... timed out' -- the outcome and why."""
        return self.outcome_words + (f": {self.reason}" if self.reason else "")

    @property
    def clock_note(self) -> str:
        if self.clock_offset is None or abs(self.clock_offset) < CLOCK_SKEW_NOTE_SECONDS:
            return ""
        ahead = "ahead of" if self.clock_offset > 0 else "behind"
        return f"its clock is {abs(self.clock_offset):.0f} s {ahead} Kratos's (times are corrected where Kratos measured)"


def machine_info(data_dir: Path, machine: str) -> dict[str, Any]:
    """How a machine is reached, its sub-agent name and version, its certificate state --
    read from Kratos's own records (no read of the machine)."""
    from kratos.subagent import routing

    host = host_for(machine)
    info: dict[str, Any] = {"label": "", "transport": "SSH (key)", "agent_version": None, "cert_state": None,
                            "target_id": None}
    if machine == "loopback":
        info["transport"] = "this machine"
        return info
    link = routing.link_for(host, data_dir)
    if link is not None and not link.revoked:
        info["label"] = link.name or ""
        info["target_id"] = link.target_id
        info["transport"] = "sub-agent" if link.mode == routing.MODE_SUBAGENT else "SSH, sub-agent if SSH fails"
        try:
            from kratos.storage.subagent_store import SubAgentStore

            row = SubAgentStore(Path(data_dir) / "kratos.db").get_target(link.target_id)
            info["agent_version"] = (row or {}).get("agent_version")
        except Exception:  # noqa: BLE001 -- display detail only
            logger.debug("fleet: no agent row for %s", machine, exc_info=True)
    try:
        from kratos.sshca import store as ca_store

        enr = ca_store.get_enrolment(Path(data_dir), host)
        if enr is not None:
            info["cert_state"] = enr.state
            if enr.state in ("cert", "cert_only") and info["transport"] == "SSH (key)":
                info["transport"] = "SSH (certificate)"
    except Exception:  # noqa: BLE001 -- no CA set up: not enrolled
        pass
    return info


class _Box:
    __slots__ = ("result", "done", "scope", "wake")

    def __init__(self, wake: threading.Event | None = None) -> None:
        self.result: MachineResult | None = None
        self.done = threading.Event()
        self.scope = cancel.CancelScope()
        self.wake = wake                      # the orchestrator's: a free slot is used at once


def _measure_windows(res: MachineResult, data_dir: Path, dispatch: Callable[..., dict[str, Any]]) -> list[str]:
    """The question's periods, counted on THIS machine by code (measure_auth_activity per
    window), then one re-correlation so the findings include those numbers. Returns what
    could not be measured -- the machine then counts as partly read, never fully."""
    from kratos.timewin.windows import reset_current_context, set_current_context

    ctx = res.time_ctx
    windows = [ctx.windows[i] for i in getattr(ctx, "goal_ids", ()) if i in ctx.windows] if ctx is not None else []
    if not windows:
        return []
    missed: list[str] = []
    token = set_current_context(ctx)
    try:
        for w in windows[:4]:
            obs = dispatch("measure_auth_activity", {"window": {"id": w.id}}, data_dir)
            res.steps.append({"tool": "measure_auth_activity", "args": {"window": {"id": w.id}}, "observation": obs,
                              "collected": True})
            if not (isinstance(obs, dict) and obs.get("status") == "ok"):
                why = str((obs or {}).get("observation") or "the read failed") if isinstance(obs, dict) else "the read failed"
                missed.append(f"{w.label or w.id} not measured ({why[:160]})")
        obs = dispatch("correlate_findings", {}, data_dir)
        res.steps.append({"tool": "correlate_findings", "args": {}, "observation": obs, "collected": True})
        inner = obs.get("result") if isinstance(obs, dict) else None
        if isinstance(inner, dict) and isinstance(inner.get("findings"), list) and res.report is not None:
            res.report.correlation = inner
        else:
            missed.append("the findings could not be correlated again after measuring")
    finally:
        reset_current_context(token)
    return missed


def _collect_one(machine: str, data_dir: Path, *, classes: tuple[str, ...], force: bool, limit: float,
                 make_time_ctx: Callable[[], Any], dispatch: Callable[..., dict[str, Any]] | None,
                 box: _Box, span: Any, should_stop: Callable[[], bool] | None) -> None:
    from kratos import authz
    from kratos.adapters import ssh_remote
    from kratos.agent import target_lock
    from kratos.collect import runner

    t0 = time.monotonic()
    info = machine_info(data_dir, machine)
    res = MachineResult(machine=machine, label=info["label"], transport=info["transport"],
                        agent_version=info["agent_version"], cert_state=info["cert_state"], started=time.time())
    res.span_id = getattr(span, "span_id", None)
    host = host_for(machine)
    handle = None
    try:
        with kratos_config.pinned_target(host), cancel.bound(box.scope), \
                _trace.use_span(span if span is not None else _trace.NO_SPAN):
            authz.check_run_access(host, data_dir=data_dir)    # D.7: checked per machine, at its first read
            handle = target_lock.acquire_target_blocking(data_dir, host, timeout=limit, should_stop=should_stop)
            if handle is None:
                stopped = should_stop is not None and should_stop()
                res.outcome = "stopped" if stopped else "busy"
                return
            remaining = limit - (time.monotonic() - t0)
            if machine != "loopback":
                ok, why, offset = ssh_remote.probe_reachable()
                if not ok:
                    res.outcome, res.reason = "unreachable", why
                    return
                res.clock_offset = offset
            res.time_ctx = make_time_ctx()
            remaining = limit - (time.monotonic() - t0)
            report = runner.prepare(host, data_dir, classes=classes, budget=max(5.0, remaining - 5.0),
                                    force=force, dispatch=dispatch)
            authz.check_run_access(host, data_dir=data_dir)    # removed while it was being read?
            res.report = report
            for o in report.checks:
                res.steps.extend(o.steps)
            if report.correlation_step is not None:
                res.steps.append({**report.correlation_step, "collected": True})
            if report.disabled_reason:
                res.outcome, res.reason = "failed", f"not collected ({report.disabled_reason})"
                return
            unmeasured = _measure_windows(res, data_dir, dispatch or runner._default_dispatch())
            usable = [o for o in report.checks if o.usable]
            if not usable:
                first = next((o.reason or o.summary for o in report.checks if o.reason or o.summary), "")
                res.outcome, res.reason = "unreachable", f"nothing could be read{': ' + first if first else ''}"
            elif len(usable) < len(report.checks) or report.correlation is None:
                res.outcome = "partial"
                missed = [o.label for o in report.checks if not o.usable]
                res.reason = (", ".join(missed[:6]) + " not read" if missed
                              else "the findings could not be correlated")
            else:
                res.outcome = "ok"
            if unmeasured and res.outcome in COLLECTED:
                # The question's own period could not be counted here: never "fully read".
                res.outcome = "partial"
                res.reason = "; ".join(x for x in [res.reason, *unmeasured] if x)
    except authz.AccessRemoved as e:
        res.outcome, res.reason = "access-removed", str(e)
        res.report = None
        res.steps = []
    except cancel.Cancelled:
        res.outcome, res.reason = "timeout", f"still running after {limit:.0f} s; its commands were stopped"
    except Exception as e:  # noqa: BLE001 -- one machine failing must not stop the others
        logger.warning("fleet: collecting %s failed", machine, exc_info=True)
        res.outcome, res.reason = "failed", f"Kratos hit {type(e).__name__}"
    finally:
        if handle is not None:
            target_lock.release_target(handle)
        res.elapsed = time.monotonic() - t0
        box.result = res
        box.done.set()
        if box.wake is not None:
            box.wake.set()


def collect_fleet(machines: list[str], data_dir: Path | str, *, classes: tuple[str, ...] = ("quick",),
                  force: bool = False, make_time_ctx: Callable[[], Any] = lambda: None,
                  dispatch: Callable[..., dict[str, Any]] | None = None,
                  on_progress: Callable[[str], None] | None = None,
                  should_stop: Callable[[], bool] | None = None,
                  max_parallel: int | None = None, machine_seconds: float | None = None) -> list[MachineResult]:
    """Collect every machine in ``machines`` (target_key form) and return one result each,
    in the same order. Never raises for a machine's failure."""
    data_dir = Path(data_dir)
    par = int(max_parallel or fleet_settings.get(fleet_settings.MAX_PARALLEL, data_dir))
    limit = float(machine_seconds or fleet_settings.get(fleet_settings.MACHINE_SECONDS, data_dir))
    results: dict[str, MachineResult] = {}
    pending = list(dict.fromkeys(machines))
    running: dict[str, tuple[threading.Thread, _Box, float, Any]] = {}
    wake = threading.Event()

    def say(line: str) -> None:
        if on_progress is not None:
            try:
                on_progress(line)
            except Exception:  # noqa: BLE001 -- a display callback never breaks collection
                logger.debug("fleet: progress callback failed", exc_info=True)

    def finish(m: str, res: MachineResult, sp: Any) -> None:
        results[m] = res
        if hasattr(sp, "finish"):
            sp.finish("ok" if res.collected else res.outcome, outcome=res.outcome, reason=res.reason or None,
                      transport=res.transport, elapsed_s=round(res.elapsed, 2))
        say(f"{res.label or m}: {res.status_text}")

    while pending or running:
        while pending and len(running) < par:
            m = pending.pop(0)
            if should_stop is not None and should_stop():
                results[m] = MachineResult(machine=m, outcome="stopped")
                continue
            sp = _trace.start_span("fleet_machine", m, machine=m)
            box = _Box(wake)
            t = threading.Thread(target=contextvars.copy_context().run,
                                 args=(_collect_one, m, data_dir),
                                 kwargs={"classes": classes, "force": force, "limit": limit,
                                         "make_time_ctx": make_time_ctx, "dispatch": dispatch, "box": box,
                                         "span": sp, "should_stop": should_stop},
                                 name=f"fleet-{m}", daemon=True)
            running[m] = (t, box, time.monotonic(), sp)
            say(f"collecting {m}…")
            t.start()
        wake.wait(POLL_SECONDS)               # a machine finished, or time to check the limits
        wake.clear()
        for m in list(running):
            t, box, started, sp = running[m]
            if box.done.is_set() and box.result is not None:
                finish(m, box.result, sp)
                del running[m]
            elif time.monotonic() - started > limit + cancel_grace():
                # Still going past its limit: kill what it started and never wait on it again.
                box.scope.cancel()
                info = machine_info(data_dir, m)
                finish(m, MachineResult(machine=m, label=info["label"], transport=info["transport"],
                                        agent_version=info["agent_version"], cert_state=info["cert_state"],
                                        outcome="timeout",
                                        reason=f"still running after {limit:.0f} s; its commands were stopped",
                                        elapsed=time.monotonic() - started), sp)
                del running[m]
    return [results[m] for m in dict.fromkeys(machines)]


def cancel_grace() -> float:
    from kratos.collect.runner import CANCEL_GRACE_SECONDS

    return CANCEL_GRACE_SECONDS
