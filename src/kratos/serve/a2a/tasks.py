"""A2A tasks and AG-UI runs, mapped onto Kratos's runs (docs/phaseE/E.5 §3.5).

One engine for both doors. A task is started by a person's token; its skill is checked
against that person's role and machines (D.7) BEFORE anything runs; a skill that runs
something (an investigation, a group question, a hunt) then takes, in this order:

1. one of this person's `a2a.max_open_tasks` open tasks;
2. one of the server's open turns (`ServeState.open_turn`, shared with chat) -- beyond
   that the task is REJECTED "busy", never queued without a bound;
3. one of the token's hourly requests (`serve.requests_per_hour`, shared with chat/MCP);
4. a run slot (`serve.max_parallel`) -- the task is SUBMITTED until it has one;

and runs on the server's own turn pool through the SAME functions chat and MCP use
(`serve.runs.run_investigation`, `fleet.run.run_fleet`, `hunt.front.start_hunt`), so
every answer check, NOTE, budget cap, mask and run record applies unchanged. A read-only
skill (finding states, the caller's machines) answers at once.

States (A2A 1.0 TaskState): SUBMITTED -> WORKING -> COMPLETED | FAILED | CANCELED, or
REJECTED before it starts. INPUT_REQUIRED and AUTH_REQUIRED are never used: Kratos never
asks a remote agent for an approval or a credential -- a run here offers no tool that
could ask, and if anything still asked, the answer is no (`serve.runs`). A finished task
never changes again; a result that arrives after a cancel is dropped.
"""
from __future__ import annotations

import collections
import contextvars
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos.serve.a2a import parts as P
from kratos.serve.a2a import store as S
from kratos.serve.a2a.skills import Call

logger = logging.getLogger(__name__)

SUBMITTED, WORKING = "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING"
COMPLETED, FAILED = "TASK_STATE_COMPLETED", "TASK_STATE_FAILED"
CANCELED, REJECTED = "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"
MAX_KEPT = 300
PROGRESS_KEPT = 40
RESTARTED = "Kratos restarted while this task ran -- start a new task"
STOPPED = "Kratos stopped while this task ran -- start a new task"


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + f".{int((epoch % 1) * 1000):03d}Z"


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_urlsafe(18)}"


@dataclass
class TaskRun:
    """One task in this process: what streams and GetTask read while it runs."""
    task_id: str
    context_id: str
    door: str
    skill: str
    target: str
    user_id: str
    token_id: str
    state: str = SUBMITTED
    reason: str | None = None
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)
    progress: "collections.deque[str]" = field(default_factory=lambda: collections.deque(maxlen=PROGRESS_KEPT))
    result: dict[str, Any] | None = None
    run_id: str | None = None
    session_id: str | None = None
    stop: threading.Event = field(default_factory=threading.Event)
    ended: threading.Event = field(default_factory=threading.Event)     # the worker thread is done
    lock: threading.Lock = field(default_factory=threading.Lock)
    _subs: list[tuple[Any, Any]] = field(default_factory=list)          # (loop, asyncio.Queue)

    @property
    def finished(self) -> bool:
        return self.state in S.TERMINAL

    # -- events (thread-safe; queues live on their event loop)
    def subscribe(self, loop: Any) -> Any:
        """A queue receiving every later event; the caller reads `snapshot()` first."""
        import asyncio

        q: Any = asyncio.Queue()
        with self.lock:
            self._subs.append((loop, q))
        return q

    def unsubscribe(self, q: Any) -> None:
        with self.lock:
            self._subs = [(lp, x) for lp, x in self._subs if x is not q]

    def _publish(self, event: tuple[str, Any]) -> None:
        with self.lock:
            subs = list(self._subs)
        for loop, q in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, event)
            except RuntimeError:                 # that loop is closed: its reader is gone
                self.unsubscribe(q)

    def note_progress(self, line: str) -> None:
        from kratos import untrusted

        text = untrusted.for_display(line, max_len=300).replace("\n", " ")
        self.progress.append(text)
        self.updated = time.time()
        self._publish(("progress", text))

    def set_state(self, state: str, reason: str | None = None) -> bool:
        with self.lock:
            if self.finished:
                return False
            self.state, self.updated = state, time.time()
            if reason is not None:
                self.reason = reason
        self._publish(("state", state))
        return True

    def finish(self, state: str, *, reason: str | None = None, result: dict[str, Any] | None = None) -> bool:
        if reason is not None:     # a run's error text can quote what it read: cleaned like every exit
            from kratos import untrusted

            reason = untrusted.for_display(reason, max_len=500)
        with self.lock:
            if self.finished:
                return False
            self.state, self.updated = state, time.time()
            self.reason = reason if reason is not None else self.reason
            self.result = result
        if result is not None:
            self._publish(("result", result))
        self._publish(("state", state))
        return True


# --------------------------------------------------------------------------- the A2A view
def _agent_message(task_id: str, context_id: str, text: str) -> dict[str, Any]:
    return {"messageId": f"{task_id}-status-{secrets.token_hex(4)}", "contextId": context_id, "taskId": task_id,
            "role": "ROLE_AGENT", "parts": [{"text": text}]}


def status_json(*, task_id: str, context_id: str, state: str, updated: float, reason: str | None,
                progress: str | None) -> dict[str, Any]:
    status: dict[str, Any] = {"state": state, "timestamp": _iso(updated)}
    text = reason if state in (FAILED, CANCELED, REJECTED) else (progress if state in (SUBMITTED, WORKING) else None)
    if text:
        status["message"] = _agent_message(task_id, context_id, text)
    return status


def artifact_json(task_id: str, result: dict[str, Any]) -> dict[str, Any]:
    parts_ = [P.text_part(str(result.get("text") or ""))]
    if isinstance(result.get("data"), dict):
        parts_.append(P.data_part(result["data"]))
    return {"artifactId": f"{task_id}-answer", "name": "answer", "parts": parts_}


def task_json(row: dict[str, Any]) -> dict[str, Any]:
    """A2A Task for a stored row or a TaskRun's snapshot."""
    out: dict[str, Any] = {
        "id": row["task_id"], "contextId": row["context_id"],
        "status": status_json(task_id=row["task_id"], context_id=row["context_id"], state=row["state"],
                              updated=float(row.get("updated") or row.get("created") or time.time()),
                              reason=row.get("reason"), progress=row.get("progress")),
        "metadata": {"kratos": {k: v for k, v in (("skill", row.get("skill")), ("target", row.get("target") or None),
                                                  ("runId", row.get("run_id")), ("sessionId", row.get("session_id")),
                                                  ("door", row.get("door"))) if v}},
    }
    if row.get("result"):
        out["artifacts"] = [artifact_json(row["task_id"], row["result"])]
    return out


def snapshot(t: TaskRun) -> dict[str, Any]:
    with t.lock:
        return {"task_id": t.task_id, "context_id": t.context_id, "state": t.state, "updated": t.updated,
                "created": t.created, "reason": t.reason, "progress": t.progress[-1] if t.progress else None,
                "result": t.result, "skill": t.skill, "target": t.target, "run_id": t.run_id,
                "session_id": t.session_id, "door": t.door}


# --------------------------------------------------------------------------- the registry
class Tasks:
    """The tasks of this server process (the rows in `a2a_tasks` outlive it)."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self._live: "collections.OrderedDict[str, TaskRun]" = collections.OrderedDict()
        self._lock = threading.Lock()

    def add(self, t: TaskRun) -> None:
        with self._lock:
            self._live[t.task_id] = t
            while len(self._live) > MAX_KEPT:
                victim = next((k for k, v in self._live.items() if v.ended.is_set()), None)
                if victim is None:
                    break
                del self._live[victim]

    def live(self, task_id: str, user_id: str, token_id: str) -> TaskRun | None:
        """This person's task, started with this token -- else None (see store.get)."""
        import hmac

        with self._lock:
            t = self._live.get(str(task_id or ""))
        if t is None or not (hmac.compare_digest(t.user_id, str(user_id))
                             and hmac.compare_digest(t.token_id, str(token_id))):
            return None
        return t

    def running_for(self, user_id: str) -> int:
        """This person's tasks whose run hasn't ended -- a cancelled task counts until its
        run has actually stopped, so cancel-and-restart can't pile runs up."""
        with self._lock:
            return sum(1 for t in self._live.values() if t.user_id == user_id and not t.ended.is_set())

    def view(self, task_id: str, user_id: str, token_id: str) -> dict[str, Any] | None:
        t = self.live(task_id, user_id, token_id)
        if t is not None:
            return snapshot(t)
        return S.get(self.data_dir, task_id, user_id, token_id)

    def shutdown(self, timeout: float = 10.0) -> None:
        with self._lock:
            live = [t for t in self._live.values() if not t.ended.is_set()]
        for t in live:
            t.stop.set()
        deadline = time.monotonic() + timeout
        for t in live:
            t.ended.wait(max(0.0, deadline - time.monotonic()))
        for t in live:
            if t.finish(FAILED, reason=STOPPED):
                _store_finish(self.data_dir, t)


# --------------------------------------------------------------------------- start
class Rejected(Exception):
    """Refused before it ran: the plain reason goes in the REJECTED status."""


def _note_run(data_dir: Path, t: TaskRun) -> None:
    try:
        S.note_run(data_dir, t.task_id, run_id=t.run_id, session_id=t.session_id)
    except Exception:  # noqa: BLE001 -- bookkeeping
        logger.debug("a2a: could not note the run", exc_info=True)


def _store_finish(data_dir: Path, t: TaskRun) -> None:
    try:
        S.update(data_dir, t.task_id, state=t.state, reason=t.reason, result=t.result, run_id=t.run_id,
                 session_id=t.session_id)
    except Exception:  # noqa: BLE001 -- the caller already has the result; the row is history
        logger.warning("a2a: could not record a finished task", exc_info=True)


def _require(actor: Any, action: str, machine: str | None, data_dir: Path, *, obj: str, audit: bool = True) -> None:
    from kratos import authz

    try:
        authz.require(actor, action, machine, data_dir=data_dir, obj=obj, audit_allowed=audit)
    except authz.Denied as e:
        raise Rejected(str(e)) from None


def _door_action(door: str) -> str:
    from kratos.authz import permissions as P_

    return P_.AGUI_USE if door == "agui" else P_.A2A_USE


def _resolve_machine(client: Any, name: str, data_dir: Path, actor: Any, door: str) -> str:
    """The machine `name` stands for, if the caller may reach it; refused (and recorded)
    without saying whether such a machine exists."""
    from kratos import authz
    from kratos.serve.openai_routes import MODEL_PREFIX, target_for_model

    wanted = str(name or "").strip().lower()
    resolved = target_for_model(client, f"{MODEL_PREFIX}/{wanted}", data_dir) if wanted else None
    if resolved is None or resolved.startswith("@"):
        authz.record_refusal(actor, authz.P.READ, "a machine this person may not use", machine=wanted[:200] or None,
                             obj=f"{door} machine", data_dir=data_dir)
        raise Rejected("no machine by that name that you may use -- the list_machines skill lists yours")
    return resolved


def _resolve_group(client: Any, name: str, data_dir: Path, actor: Any, door: str) -> str:
    from kratos import authz
    from kratos.serve.openai_routes import MODEL_PREFIX, target_for_model

    wanted = str(name or "").strip().lower()
    wanted = wanted if wanted.startswith("@") else "@" + wanted
    resolved = target_for_model(client, f"{MODEL_PREFIX}/{wanted}", data_dir)
    if resolved is None or not resolved.startswith("@"):
        authz.record_refusal(actor, authz.P.FLEET_ASK, "a group this person may not use", obj=f"{door} group",
                             data_dir=data_dir)
        raise Rejected("no group by that name that you may ask about (groups need investigator access and at "
                       "least one of your machines)")
    return resolved


@dataclass
class Started:
    task: TaskRun
    queue: Any = None                    # subscribed before the run began (streams), else None


def start_task(state: Any, *, actor: Any, client: Any, door: str, call: Call, loop: Any = None) -> Started:
    """Check, record and start a task (or finish it at once). Never raises for a refusal:
    a refused task is REJECTED with the reason. Runs on a worker thread (it touches the
    stores); `loop`: subscribe a queue on that event loop before the run begins."""
    from kratos import authz

    data_dir = Path(state.data_dir)
    user_id = str(getattr(actor, "user_id", "") or "")
    t = TaskRun(task_id=new_id("task"), context_id=call.context_id or new_id("ctx"), door=door, skill=call.skill,
                target="", user_id=user_id, token_id=client.token_id)
    queue = t.subscribe(loop) if loop is not None else None
    reservations: list[Callable[[], None]] = []

    def reject(reason: str) -> Started:
        for undo in reversed(reservations):
            undo()
        t.finish(REJECTED, reason=reason)
        t.ended.set()
        _record(state, t)
        return Started(t, queue)

    try:
        with authz.acting_as(actor):
            plan = _plan_task(state, actor=actor, client=client, door=door, call=call, task=t)
    except Rejected as e:
        return reject(str(e))
    if plan.immediate is not None:               # a read-only skill: answered now
        t.finish(COMPLETED, result=plan.immediate)
        t.ended.set()
        _record(state, t)
        return Started(t, queue)

    # Limits, in a fixed order; each one taken is given back if a later one refuses.
    from kratos import settings_store
    from kratos.serve.a2a import settings as AS
    from kratos.serve.openai_routes import _hourly_limit

    cap = int(settings_store.get(AS.MAX_OPEN_TASKS, data_dir=data_dir))
    with state.a2a_open_lock:
        if state.a2a_tasks.running_for(user_id) >= cap:
            return reject(f"you already have {cap} unfinished tasks (a2a.max_open_tasks) -- try again when one "
                          "finishes")
        state.a2a_tasks.add(t)                   # counted from here
    reservations.append(lambda: t.ended.set())
    if not state.open_turn():
        return reject(f"Kratos is busy ({state.max_open_turns} conversations and tasks open) -- try again in a "
                      "minute")
    reservations.append(state.close_turn)
    limit = _hourly_limit(data_dir)
    meter_user = None                            # agent doors take person tokens only: the token is the person
    if not state.reserve_metered(client.token_id, limit, meter_user):
        return reject(f"this token has used its {limit} requests for this hour (serve.requests_per_hour)")
    reservations.append(lambda: state.release_metered(client.token_id, meter_user))
    _record(state, t)

    def worker() -> None:
        try:
            with authz.acting_as(actor, action=plan.action):
                _execute_task(state, t, plan)
        except Exception as e:  # noqa: BLE001 -- a task always ends with a state
            logger.warning("a2a: task failed", exc_info=True)
            if t.finish(FAILED, reason=f"Kratos hit an error running this task ({type(e).__name__})"):
                _store_finish(data_dir, t)
        finally:
            try:
                _audit(state, t, metered=True)
            finally:
                state.release_metered(client.token_id, meter_user)
                state.close_turn()
                t.ended.set()
                state.note_runs()

    try:
        state.turn_pool.submit(contextvars.copy_context().run, worker)
    except BaseException:
        return reject("Kratos could not start the task (the server is stopping)")
    return Started(t, queue)


@dataclass
class Plan:
    action: str | None = None
    immediate: dict[str, Any] | None = None
    question: str = ""
    machines: list[str] = field(default_factory=list)       # the caller's scope (machines)
    hunt: Any = None                                         # hunt.front.Prepared


def _plan_task(state: Any, *, actor: Any, client: Any, door: str, call: Call, task: TaskRun) -> Plan:
    """Who may do what (D.7), resolved before anything runs. Raises Rejected."""
    from kratos.authz import permissions as P_
    from kratos.serve.openai_routes import group_models_for, models_for, scope_machines

    data_dir = Path(state.data_dir)
    args = call.args
    obj = f"{door} {call.skill}"
    question = args.get("question", "")
    if args.get("window"):
        question = f"{question}\n\n(Time window: {args['window']})"
    if call.skill == "list_machines":
        _require(actor, P_.READ, None, data_dir, obj=obj)
        machines = scope_machines(client, data_dir)
        groups = [t for _m, t in group_models_for(client, data_dir)]
        data = {"kind": "kratos.machines.v1", "machines": machines, "groups": groups}
        text = ("You may use: " + (", ".join(machines) if machines else "no machine") +
                (". Groups: " + ", ".join(groups) if groups else "") + ".")
        return Plan(immediate={"text": _md_text(text), "data": _clean(data)})
    if call.skill == "finding_states":
        if args.get("machine"):
            machines = [_resolve_machine(client, args["machine"], data_dir, actor, door)]
        else:
            machines = scope_machines(client, data_dir)
        task.target = machines[0] if len(machines) == 1 else ""
        if not machines:
            raise Rejected("you may see no machine")
        for m in machines:
            _require(actor, P_.FINDINGS_READ, m, data_dir, obj=obj)
        return Plan(immediate=_finding_states(data_dir, machines, args.get("state") or "open_verified"))
    # Skills that run something: the skill's own permission (its refusal names what the
    # person can't do), then the door's (a2a.use / agui.use -- investigators and up).
    if call.skill == "investigate_machine":
        machine = _resolve_machine(client, args["machine"], data_dir, actor, door)
        task.target = machine
        _require(actor, P_.INVESTIGATE, machine, data_dir, obj=obj)
        _require(actor, _door_action(door), machine, data_dir, obj=obj, audit=False)
        return Plan(action=P_.INVESTIGATE, question=question, machines=[machine])
    if call.skill == "ask_group":
        _require(actor, P_.FLEET_ASK, None, data_dir, obj=obj, audit=False)   # the fleet run records its own start
        _require(actor, _door_action(door), None, data_dir, obj=obj, audit=False)
        group = _resolve_group(client, args["group"], data_dir, actor, door)
        task.target = group
        return Plan(action=P_.FLEET_ASK, question=question, machines=scope_machines(client, data_dir))
    if call.skill == "hunt_indicator":
        from kratos.hunt import front

        _require(actor, P_.HUNT, None, data_dir, obj=obj, audit=False)
        _require(actor, _door_action(door), None, data_dir, obj=obj)
        scope = [t for _m, t in models_for(client, data_dir)]
        machine = args.get("machine") or ""
        req = front.Request(words=[w for w in args["indicators"].replace(",", " ").split() if w],
                            kind=args.get("kind") or None, since=args.get("since") or None,
                            until=args.get("until") or None, machines=[machine] if machine else [])
        try:
            prepared = front.resolve_hunt(req, scope=sorted(set(scope)), data_dir=data_dir)
        except front.HuntUsageError as e:
            raise Rejected(str(e)) from None
        if prepared.ambiguous:
            a = prepared.ambiguous[0]
            raise Rejected(f"{a.question()} Send it again with kind set to one of: {', '.join(a.options)}")
        task.target = machine.lower()
        return Plan(action=P_.HUNT, hunt=prepared, machines=sorted(set(scope)))
    raise Rejected("unknown skill")  # pragma: no cover -- skills.parse allows only card.SKILL_IDS


def _clean(value: Any) -> Any:
    from kratos import untrusted

    return untrusted.for_model(value, field_cap=2000)


def _md_text(text: str) -> str:
    from kratos.serve import render as R

    return R.kratos_note_markdown(text)


def _finding_states(data_dir: Path, machines: list[str], state_filter: str) -> dict[str, Any]:
    from kratos import mcp_server as _stdio

    rows: list[dict[str, Any]] = []
    for m in machines:
        for r in _stdio._finding_states_for(data_dir, m, state_filter, 200):
            v = r.get("verdict") if isinstance(r.get("verdict"), dict) else None
            ssvc = r.get("ssvc") if isinstance(r.get("ssvc"), dict) else None
            rows.append({"machine": m, "rule": r.get("rule_id"), "title": r.get("title"),
                         "severity": r.get("severity"), "state": r.get("state"), "finding_key": r.get("finding_key"),
                         "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"),
                         "verdict": v.get("tag") if v else None,
                         "ssvc": {"outcome": ssvc.get("outcome"), "label": ssvc.get("label")} if ssvc else None,
                         "attack": [a.get("technique_id") for a in r.get("attack") or [] if isinstance(a, dict)]})
    rows = rows[:500]
    lines = [f"{r['severity'] or 'info'}  {r['rule']}  {r['state']}  {r['machine']}  {r['title'] or ''}" for r in rows]
    text = "\n".join(lines) if lines else "No findings in that state."
    from kratos.serve import render as R

    return {"text": R.kratos_text_markdown(text),
            "data": _clean({"kind": "kratos.finding_states.v1", "state": state_filter, "count": len(rows),
                            "findings": rows})}


# --------------------------------------------------------------------------- execute
_RUN_TO_STATE = {"final_answer": COMPLETED, "max_iters_reached": COMPLETED, "stopped_by_budget": COMPLETED,
                 "stopped": CANCELED, "refused_by_budget": REJECTED, "access_removed": FAILED, "error": FAILED}


def _execute_task(state: Any, t: TaskRun, plan: Plan) -> None:
    data_dir = Path(state.data_dir)
    if not state.slots.acquire(should_stop=t.stop.is_set,
                               on_wait=lambda: t.note_progress("waiting for another investigation to finish…")):
        if t.finish(CANCELED, reason="cancelled before it started"):
            _store_finish(data_dir, t)
        return
    try:
        if not t.set_state(WORKING):
            return                               # cancelled while waiting for the slot
        S.update(data_dir, t.task_id, state=WORKING)
        state.note_runs()
        if t.skill == "investigate_machine":
            result, final_state, reason = _run_investigation_task(state, t, plan)
        elif t.skill == "ask_group":
            result, final_state, reason = _run_group_task(state, t, plan)
        else:
            result, final_state, reason = _run_hunt_task(state, t, plan)
    finally:
        state.slots.release()
    if t.finish(final_state, reason=reason, result=result if final_state == COMPLETED else None):
        _store_finish(data_dir, t)


def _run_investigation_task(state: Any, t: TaskRun, plan: Plan) -> tuple[dict[str, Any] | None, str, str | None]:
    from kratos.serve.runs import RunRequest, run_investigation

    data_dir = Path(state.data_dir)

    def on_session(sid: str) -> None:
        t.session_id = sid
        try:
            S.update(data_dir, t.task_id, session_id=sid)
        except Exception:  # noqa: BLE001
            logger.debug("a2a: could not note the session", exc_info=True)

    outcome = run_investigation(RunRequest(goal=plan.question, target=t.target, data_dir=data_dir, source=t.door,
                                           should_stop=t.stop.is_set, on_progress=t.note_progress,
                                           on_session=on_session))
    t.run_id = outcome.run_id
    _note_run(data_dir, t)
    final_state = _RUN_TO_STATE.get(outcome.status, COMPLETED)
    if final_state != COMPLETED:
        return None, final_state, outcome.final_answer or outcome.error or outcome.status
    return ({"text": P.answer_text(outcome, data_dir=data_dir),
             "data": P.findings_data(outcome.findings, data_dir=data_dir, machines=[t.target])},
            COMPLETED, None)


def _run_group_task(state: Any, t: TaskRun, plan: Plan) -> tuple[dict[str, Any] | None, str, str | None]:
    from kratos import authz
    from kratos.fleet import run as FR

    data_dir = Path(state.data_dir)
    actor = authz.current_actor()
    try:
        out = FR.run_fleet(FR.FleetRequest(question=plan.question, group=t.target, data_dir=data_dir, source=t.door,
                                           actor=actor, scope=plan.machines, on_progress=t.note_progress,
                                           should_stop=t.stop.is_set))
    except FR.FleetError as e:
        return None, FAILED, str(e)
    t.run_id = out.run_id
    _note_run(data_dir, t)
    if out.status == "refused_by_budget":
        return None, REJECTED, out.text
    if out.status == "cancelled":
        return None, CANCELED, "cancelled"
    by_machine = {str(f.get("finding_key")): r.machine for r in out.results for f in r.findings
                  if isinstance(f, dict) and f.get("finding_key")}
    findings = [f for r in out.results for f in r.findings]
    return ({"text": P.fleet_text(out, data_dir=data_dir),
             "data": P.findings_data(findings, data_dir=data_dir, machines=plan.machines, by_machine=by_machine)},
            COMPLETED, None)


def _run_hunt_task(state: Any, t: TaskRun, plan: Plan) -> tuple[dict[str, Any] | None, str, str | None]:
    from kratos import authz
    from kratos.hunt import front, report
    from kratos.run_context import run_scope
    from kratos.serve import render as R

    data_dir = Path(state.data_dir)
    actor = authz.current_actor()
    t.note_progress("searching what Kratos holds…")
    with run_scope("a2a" if t.door == "a2a" else "agui"):
        result = front.start_hunt(data_dir, plan.hunt, source="a2a",
                                  actor=f"{getattr(actor, 'user', '?')} (token {t.token_id})")
    data = result.as_dict()
    return ({"text": R.kratos_text_markdown(report.render(result)), "data": _clean({"kind": "kratos.hunt.v1", **data})},
            COMPLETED, None)


# --------------------------------------------------------------------------- cancel / record
class NotFound(Exception):
    pass


class NotCancelable(Exception):
    pass


def cancel_task(state: Any, task_id: str, user_id: str, token_id: str) -> dict[str, Any]:
    """Cancel this person's task: the run stops at its next read (the same should_stop path
    chat and the TUI use). Returns the task's view. NotFound / NotCancelable."""
    data_dir = Path(state.data_dir)
    t = state.a2a_tasks.live(task_id, user_id, token_id)
    if t is None:
        row = S.get(data_dir, task_id, user_id, token_id)
        if row is None:
            raise NotFound(task_id)
        raise NotCancelable(row["state"])
    if t.finished:
        raise NotCancelable(t.state)
    t.stop.set()
    if t.finish(CANCELED, reason="cancelled by the caller"):
        _store_finish(data_dir, t)
    return snapshot(t)


def _record(state: Any, t: TaskRun) -> None:
    """The row (a2a_tasks) and, for a task that ended here, its serve_audit row."""
    data_dir = Path(state.data_dir)
    try:
        S.insert(data_dir, task_id=t.task_id, context_id=t.context_id, door=t.door, user_id=t.user_id,
                 token_id=t.token_id, skill=t.skill, target=t.target, state=t.state, reason=t.reason,
                 result=t.result)
    except Exception:  # noqa: BLE001
        logger.warning("a2a: could not record a task", exc_info=True)
    if t.finished:
        _audit(state, t, metered=False)


def _audit(state: Any, t: TaskRun, *, metered: bool) -> None:
    from kratos.serve import store as SS

    status = {COMPLETED: "ok", REJECTED: "refused", CANCELED: "stopped", FAILED: "error"}.get(t.state, "ok")
    try:
        SS.audit(state.data_dir, door=t.door, endpoint=f"{t.door}:{t.skill}", status=status, token_id=t.token_id,
                 target=t.target or None, run_id=t.run_id, metered=metered, duration=time.time() - t.created,
                 detail=(t.reason or None) and str(t.reason)[:200], user_id=t.user_id)
    except Exception:  # noqa: BLE001
        logger.debug("a2a: audit failed", exc_info=True)
