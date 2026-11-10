"""`require()`: the one permission check (docs/phaseD/D.7 §3.5, §3.11, §5.2).

Called at the start of every request and every state-changing action, and again at
every read inside a run (`check_run_access`, from `execute_tool_call` and the fleet
collector) -- so narrowing a user's scope, disabling them, demoting them or revoking
their token stops their running investigation at its next read.

Fail closed: no user, an unknown role, a scope that can't be read, a token that is
gone or expired, an audit row that can't be written -- each is a refusal with a plain
reason. Every refusal is recorded; every allowed action is recorded too, except the
per-read re-checks inside a run (the run's start is the recorded action).

Who is acting: an `Actor` (kratos.lifecycle.decide). The current one travels with the
run in a context variable (`acting_as`); a local process (TUI, CLI, stdio MCP, a
schedule) with none set acts as the owner. The chat server never falls back: a request
with no actor is refused (`set_network_process`).
"""
from __future__ import annotations

import contextlib
import contextvars
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from kratos.authz import permissions as P
from kratos.authz.scope import Scope, ScopeError

logger = logging.getLogger(__name__)

OWNER_ID = "owner"
INTERFACES = ("tui", "cli", "mcp", "serve", "schedule")
# Interfaces where an actor without a user id is the owner (the Kratos host itself).
_LOCAL_DEFAULT = ("tui", "cli", "mcp", "schedule")
# Actions an agent tool may never trigger (people decide, the model suggests).
_PEOPLE_ONLY = P.LOCAL_ONLY | frozenset({P.FINDING_DECIDE, P.EXPORT_REDACTED})


class Denied(PermissionError):
    """A refusal; `str()` is the plain reason a person reads."""

    def __init__(self, reason: str, *, action: str = "", machine: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.action = action
        self.machine = machine


class AccessRemoved(Denied):
    """Raised at a read inside a run whose person may no longer read that machine."""

    trace_status = "stopped"   # the run record ends as "stopped", not as a crash

    @classmethod
    def for_machine(cls, machine: str | None, why: str) -> "AccessRemoved":
        where = f" to {machine}" if machine else ""
        return cls(f"stopped: your access{where} was removed ({why})", action=P.READ, machine=machine)


@dataclass(frozen=True)
class Principal:
    actor: Any
    user: Any            # kratos.authz.users.User
    scope: Scope

    @property
    def is_owner(self) -> bool:
        return self.user.is_owner


_ACTOR: contextvars.ContextVar[Any] = contextvars.ContextVar("kratos_actor", default=None)
_RUN_ACTION: contextvars.ContextVar[str | None] = contextvars.ContextVar("kratos_run_action", default=None)
_network_process = False


def set_network_process(on: bool = True) -> None:
    """The chat server (`kratos serve`): from now on an action with no actor is refused --
    never treated as the owner. One-way in production; tests reset it."""
    global _network_process
    _network_process = bool(on)


def network_process() -> bool:
    return _network_process


_local_interface = "cli"


def set_local_interface(interface: str) -> None:
    """The full-screen app says it is the TUI, so actions without an explicit actor are
    recorded as the owner at the TUI (not the CLI). Only tui / cli."""
    global _local_interface
    if interface in ("tui", "cli"):
        _local_interface = interface


def owner_actor(interface: str = "cli") -> Any:
    from kratos.lifecycle.decide import Actor

    a = Actor.current(interface if interface in _LOCAL_DEFAULT else "cli")
    return a


def current_actor() -> Any:
    """The actor of this run / request, else the owner for a local process, else None."""
    a = _ACTOR.get()
    if a is not None:
        return a
    if _network_process:
        return None
    from kratos import run_context

    ctx = run_context.current()
    if ctx is not None and ctx.source == "web":
        return None
    interface = {"mcp": "mcp", "schedule": "schedule", "trigger": "schedule", "watch": "schedule",
                 "interactive": "tui", "evolve": "tui"}.get(ctx.source if ctx is not None else "", _local_interface)
    return owner_actor(interface)


@contextlib.contextmanager
def acting_as(actor: Any, *, action: str | None = None) -> Iterator[Any]:
    """Run the block as `actor`. `action`: what this run was allowed to do (re-checked at
    each read, so a demotion stops it too)."""
    t1 = _ACTOR.set(actor)
    t2 = _RUN_ACTION.set(action) if action is not None else None
    try:
        yield actor
    finally:
        if t2 is not None:
            _RUN_ACTION.reset(t2)
        _ACTOR.reset(t1)


def run_action() -> str | None:
    return _RUN_ACTION.get()


def _data_dir(data_dir: Path | str | None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    from kratos import kratos_config, paths

    return kratos_config.get_active_data_dir() or paths.default_data_dir()


def is_local_owner(actor: Any) -> bool:
    return (actor is not None and getattr(actor, "interface", None) in _LOCAL_DEFAULT
            and getattr(actor, "user_id", None) in (None, OWNER_ID) and not getattr(actor, "credential", None))


def token_id_of(credential: str | None) -> str | None:
    """'token:<id>' or 'gateway:<id>+openwebui:<sub>' -> '<id>'."""
    text = str(credential or "")
    for prefix in ("token:", "gateway:"):
        if text.startswith(prefix):
            return text[len(prefix):].split("+", 1)[0] or None
    return None


def _token_problem(row: dict[str, Any] | None) -> str | None:
    import time

    if row is None:
        return "the token no longer exists"
    if row.get("revoked_at"):
        return "the token was revoked"
    exp = row.get("expires_at")
    if exp is not None and float(exp) <= time.time():
        return "the token expired on " + time.strftime("%Y-%m-%d", time.localtime(float(exp)))
    return None


def _audit(dd: Path, actor: Any, *, action: str, result: str, user: Any = None, machine: str | None = None,
           obj: str | None = None, reason: str | None = None) -> None:
    from kratos.authz import audit

    audit.record(dd, interface=str(getattr(actor, "interface", "") or "?"), action=action, result=result,
                 user_id=getattr(user, "user_id", None) or getattr(actor, "user_id", None),
                 user_name=getattr(user, "name", None) or getattr(actor, "user", None),
                 credential=getattr(actor, "credential", None), machine=machine, obj=obj, reason=reason)


def _refuse(dd: Path, actor: Any, action: str, reason: str, *, user: Any = None, machine: str | None = None,
            obj: str | None = None) -> Denied:
    try:
        _audit(dd, actor, action=action, result="refused", user=user, machine=machine, obj=obj, reason=reason)
    except Exception:  # noqa: BLE001 -- the refusal stands either way
        logger.warning("authz: could not record a refusal", exc_info=True)
    return Denied(reason, action=action, machine=machine)


def principal_of(actor: Any, *, data_dir: Path | str | None = None) -> Principal:
    """The user and scope behind `actor`, or Denied. Records nothing."""
    from kratos.authz import scope as SC
    from kratos.authz import users as U
    from kratos.lifecycle.decide import Actor

    dd = _data_dir(data_dir)
    if not isinstance(actor, Actor) or actor.interface not in INTERFACES or not str(actor.user or "").strip():
        raise Denied("no person is attached to this request")
    uid = actor.user_id or (OWNER_ID if actor.interface in _LOCAL_DEFAULT and not actor.credential else None)
    if not uid:
        raise Denied("no Kratos user is attached to this request")
    try:
        user = U.get(dd, uid)
    except Exception as e:  # noqa: BLE001
        raise Denied(f"the user record could not be read ({type(e).__name__})") from e
    if user is None:
        raise Denied("this Kratos user no longer exists")
    if user.disabled:
        raise Denied("your Kratos account is disabled -- ask the Kratos owner")
    if user.role not in P.ROLES:
        raise Denied(f"your Kratos role ({user.role!r}) is not known")
    token = None
    tid = token_id_of(actor.credential)
    if actor.credential:
        if tid is None:
            raise Denied("the credential on this request is not a Kratos token")
        try:
            token = SC.token_row(dd, tid)
        except Exception as e:  # noqa: BLE001
            raise Denied(f"the token could not be read ({type(e).__name__})") from e
        problem = _token_problem(token)
        if problem:
            raise Denied(problem)
        if token.get("user_id", OWNER_ID) != user.user_id and token.get("kind") != "gateway":
            raise Denied("the token belongs to another user")
    elif actor.interface == "serve":
        raise Denied("a request over the network needs a Kratos token")
    try:
        scope = SC.effective(dd, user, token=token, local=is_local_owner(actor))
    except ScopeError as e:
        raise Denied(str(e)) from e
    return Principal(actor=actor, user=user, scope=scope)


def require(actor: Any, action: str, machine: str | None = None, *, data_dir: Path | str | None = None,
            obj: str | None = None, audit_allowed: bool = True) -> Principal:
    """Allow `actor` to do `action` (on `machine`), or raise Denied with the reason.
    Every refusal is recorded; an allowed action is recorded unless `audit_allowed` is
    False (the per-read re-checks). Fails closed on every lookup problem."""
    if action not in P.ACTIONS:
        raise ValueError(f"unknown action {action!r} (kratos.authz.permissions)")
    dd = _data_dir(data_dir)
    from kratos import settings_store

    tool = settings_store.in_tool_call()
    if tool is not None and action in _PEOPLE_ONLY:
        raise _refuse(dd, actor, action, f"agent tools may not do this (tool {tool!r} tried)", machine=machine,
                      obj=obj)
    try:
        p = principal_of(actor, data_dir=dd)
    except Denied as e:
        raise _refuse(dd, actor, action, e.reason, machine=machine, obj=obj) from None
    if not P.allowed(p.user.role, action):
        raise _refuse(dd, actor, action, P.refusal_text(p.user.role, action), user=p.user, machine=machine, obj=obj)
    if action in P.LOCAL_ONLY and (actor.interface not in P.LOCAL_INTERFACES or not p.is_owner):
        raise _refuse(dd, actor, action, "this is done only by the Kratos owner, on the Kratos computer (TUI or CLI)",
                      user=p.user, machine=machine, obj=obj)
    if machine is not None and not p.scope.allows(machine):
        raise _refuse(dd, actor, action, f"no machine {machine!r} that you may see", user=p.user, machine=machine,
                      obj=obj)
    if audit_allowed:
        try:
            _audit(dd, actor, action=action, result="allowed", user=p.user, machine=machine, obj=obj)
        except Exception as e:  # noqa: BLE001 -- an unrecorded action is not allowed
            raise Denied(f"the action could not be recorded in the audit trail ({type(e).__name__})",
                         action=action, machine=machine) from e
    return p


def record_refusal(actor: Any, action: str, reason: str, *, machine: str | None = None, obj: str | None = None,
                   data_dir: Path | str | None = None) -> None:
    """Record a refusal decided before `require` could run (a model or machine the
    caller may not see, refused by the door's own lookup) -- every refusal is in the trail."""
    _refuse(_data_dir(data_dir), actor, action, reason, machine=machine, obj=obj)


def check_run_access(machine: str | None = None, *, data_dir: Path | str | None = None) -> None:
    """The per-read check inside a run (execute_tool_call, the fleet collector): may this
    run's person still do what started the run, on this machine? Raises AccessRemoved."""
    actor = current_actor()
    if actor is None:
        raise AccessRemoved.for_machine(machine, "no person is attached to this run")
    if is_local_owner(actor):
        return
    if machine is None:
        from kratos import kratos_config

        machine = kratos_config.get_active_target() or None
    action = _RUN_ACTION.get() or P.READ
    try:
        require(actor, action, machine, data_dir=data_dir, audit_allowed=False)
    except Denied as e:
        raise AccessRemoved.for_machine(machine, e.reason) from None


def require_person(action: str, *, data_dir: Path | str | None = None, actor: Any = None, machine: str | None = None,
                   obj: str | None = None) -> Principal:
    """`require` for a people-only change whose callers pass no Actor (settings, keys,
    whitelist, prune, schedules...): the person acting right now -- the owner at the
    Kratos host, or the network user, who is refused (admin actions are local-only)."""
    return require(actor if actor is not None else current_actor(), action, machine, data_dir=data_dir, obj=obj)


def unattended_actor(kind: str, name: str, run_as: str | None) -> Any:
    """The Actor of a schedule or trigger: it acts as the Kratos user it runs as (D.7 §3.9)."""
    from kratos.lifecycle.decide import Actor

    return Actor(user=f"{kind}:{name}", interface="schedule", user_id=str(run_as or OWNER_ID))


def unattended_refusal(actor: Any, action: str, machine: str | None, *, data_dir: Path | str) -> str | None:
    """None when the schedule/trigger may run now (recorded), else why not -- its creator is
    disabled, demoted, gone, or the machine is outside their scope."""
    try:
        require(actor, action, machine, data_dir=data_dir, obj=f"unattended run {actor.user}")
    except Denied as e:
        who = "the owner"
        if actor.user_id != OWNER_ID:
            try:
                from kratos.authz import users as U

                u = U.get(_data_dir(data_dir), actor.user_id)
                who = u.name if u is not None else f"{actor.user_id} (no longer a user)"
            except Exception:  # noqa: BLE001
                who = actor.user_id
        return f"{actor.user} runs as {who} and was refused: {e.reason}"
    return None
