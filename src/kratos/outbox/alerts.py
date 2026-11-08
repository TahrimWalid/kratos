"""Text alerts to channels by name: what triggers, schedules, live detections, fleet runs,
budget notices, the model's ``send_notification`` tool and MCP's ``kratos_notify_findings``
call instead of sending anything themselves.

``OutboxNotifier`` keeps the old notifier shape -- ``notifier(message, severity) -> dict`` --
so every caller (and every test that passes its own notifier) works unchanged. It only
ENQUEUES: one outbox row per channel the alert passes, rendered for that channel, then
wakes this process's delivery worker if it runs one. The result says what happened per
channel: ``queued``, ``not_configured`` (ntfy without a topic), ``disabled``,
``filtered`` (the channel's filters don't take it), ``not_alerts`` (the channel only
forwards findings or events) or ``unknown`` (no channel by that name).
"""
from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox.formats import SEVERITY_RANK, Alert
from kratos.outbox.render import alert as render_alert

logger = logging.getLogger(__name__)

# ntfy bucket -> the finding severity it stands for (for a channel's severity filter)
BUCKET_SEVERITY = {"critical": "high", "warning": "medium", "info": "info"}
UNFILTERED_KINDS = frozenset({"notice", "test"})     # about Kratos itself: always go to the channels asked for


def _data_dir(data_dir: Path | str | None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    from kratos.budget.guard import data_dir as active

    return Path(active())


def in_scope(ch: C.Channel, machines: Sequence[str], data_dir: Path) -> bool:
    """A channel limited to some machines or groups takes an alert only when every machine
    it is about is inside that scope (an alert about other machines would tell their story)."""
    f = ch.filters
    if not f.machines and not f.groups:
        return True
    if not machines:
        return False
    from kratos.target_key import target_key

    for m in machines:
        key = target_key(m)
        if key in f.machines:
            continue
        if f.groups:
            try:
                from kratos.fleet.groups import groups_of

                if set(groups_of(data_dir, key)) & set(f.groups):
                    continue
            except Exception:  # noqa: BLE001 -- unknown membership: not in scope
                pass
        return False
    return True


def alert_passes(ch: C.Channel, a: Alert, machines: Sequence[str], data_dir: Path) -> tuple[bool, str]:
    if a.kind in UNFILTERED_KINDS:
        return True, ""
    f = ch.filters
    sev = a.worst or BUCKET_SEVERITY.get(a.bucket, "info")
    if f.min_severity and SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK[f.min_severity]:
        return False, f"below {f.min_severity}"
    if f.rule_prefixes and a.findings:
        ids = {str(x.get("id") or "").upper() for x in a.findings}
        if not any(i.startswith(p) for i in ids for p in f.rule_prefixes):
            return False, "no matching rule"
    if f.min_ssvc:
        from kratos.ssvc.tree import rank

        if not any(rank(str(x.get("ssvc") or "")) >= rank(f.min_ssvc) for x in a.findings):
            return False, f"no decision {f.min_ssvc} or above"
    if f.only_new_or_worse and a.findings and any("change" in x for x in a.findings):
        from kratos.outbox.formats import NEWS

        if not any(x.get("change") in NEWS for x in a.findings):
            return False, "nothing new or worse"
    if not in_scope(ch, machines, data_dir):
        return False, "other machines"
    return True, ""


def _finding_summary(findings: Iterable[dict[str, Any]] | None) -> tuple[dict[str, Any], ...]:
    out = []
    for f in findings or ():
        if not isinstance(f, dict):
            continue
        item = {k: f.get(k) for k in ("id", "severity", "title", "finding_key", "change") if f.get(k)}
        ssvc = f.get("ssvc")
        if isinstance(ssvc, dict) and ssvc.get("outcome"):
            item["ssvc"] = ssvc["outcome"]
        out.append(item)
    return tuple(out[:50])


def enqueue_alert(text: str, severity: str = "info", *, deliver: Iterable[str] | None = None,
                  data_dir: Path | str | None = None, kind: str = "alert", worst: str | None = None,
                  machine: str | None = None, machines: Sequence[str] | None = None,
                  findings: Iterable[dict[str, Any]] | None = None, source: str | None = None,
                  name: str | None = None, message_id: str | None = None,
                  exclude: Iterable[str] = ()) -> dict[str, Any]:
    """Enqueue one alert for each channel in ``deliver`` (default: every channel that
    receives alerts). Never sends, never raises; returns what happened per channel."""
    dd = _data_dir(data_dir)
    bucket = (severity or "info").lower()
    bucket = bucket if bucket in BUCKET_SEVERITY else "info"
    if worst is not None and worst not in SEVERITY_RANK:
        worst = None
    from kratos import run_context

    ctx = run_context.current()
    machines = tuple(m for m in (machines or ((machine,) if machine else ())) if m)
    from kratos.outbox.render import redact_obj

    text = redact_obj(str(text or ""))              # secrets out before anything is stored, summary included
    a = Alert(text=text, bucket=bucket, worst=worst, machine=machine or (machines[0] if len(machines) == 1
                                                                                   else None),
              findings=_finding_summary(findings), kind=kind, source=source or (ctx.source if ctx else None),
              name=name, at=time.time(), message_id=message_id or f"{kind}:{uuid.uuid4().hex}")
    result: dict[str, Any] = {"status": "not_sent", "channels": {}, "outbox_ids": [], "message_id": a.message_id,
                              "severity": bucket}
    try:
        names = C.resolve_deliver(dd, list(deliver) if deliver is not None else None)
        known = {c.name: c for c in C.list_channels(dd)}
    except Exception as e:  # noqa: BLE001 -- a broken database must not sink the run that alerts
        logger.warning("outbox: could not read channels: %s", e)
        result.update(status="failed", observation=f"the outbox could not be opened: {e}")
        return result
    skip = {str(x).lower() for x in exclude}
    queued: list[S.Enqueued] = []
    try:
        with S.opened(dd) as conn:
            for n in names:
                if n in skip:
                    continue
                ch = known.get(n)
                if ch is None:
                    result["channels"][n] = "unknown"
                    continue
                ok, why = C.usable(ch)
                if not ok:
                    result["channels"][n] = "disabled" if not ch.enabled else "not_configured"
                    continue
                if "alerts" not in ch.scopes:
                    result["channels"][n] = "not_alerts"
                    continue
                passes, why = alert_passes(ch, a, machines, dd)
                if not passes:
                    result["channels"][n] = f"filtered ({why})"
                    continue
                payload = render_alert(ch, a, dd)
                with S.immediate(conn):
                    e = S.enqueue(conn, channel=ch.name, kind=kind, message_id=a.message_id, payload=payload,
                                  summary=a.subject, severity=worst or BUCKET_SEVERITY[bucket], machine=a.machine,
                                  source=a.source, run_id=ctx.run_id if ctx else None, now=a.at)
                queued.append(e)
                result["channels"][n] = "queued"
    except Exception as e:  # noqa: BLE001
        logger.warning("outbox: enqueue failed: %s", e)
        result.update(status="failed", observation=f"the outbox could not take the message: {e}")
        return result
    result["outbox_ids"] = [e.id for e in queued]
    if queued:
        result["status"] = "queued"
        result["observation"] = ("queued for " + ", ".join(e.channel for e in queued)
                                 + " -- Kratos delivers it and retries while a receiver is down (see /outbox)")
        from kratos.outbox import worker

        worker.wake()
    elif result["channels"] and all(v == "not_configured" for v in result["channels"].values()):
        from kratos.agent.notify import NOT_CONFIGURED_HINT

        result.update(status="not_configured", observation=NOT_CONFIGURED_HINT)
    else:
        from kratos.agent.notify import NOT_CONFIGURED_HINT

        why = "; ".join(f"{k}: {v}" for k, v in result["channels"].items()) or "no channel receives alerts"
        result["observation"] = f"not sent ({why})." + ("" if result["channels"] else " " + NOT_CONFIGURED_HINT)
        if not result["channels"]:
            result["status"] = "not_configured"
    return result


class OutboxNotifier:
    """``notifier(message, severity) -> dict``, enqueueing to channels by name. Extra
    context (the worst finding severity, the machine, the findings) may be passed as
    keyword arguments; callers that only know the old shape keep working."""

    def __init__(self, deliver: Iterable[str] | None = None, *, data_dir: Path | str | None = None,
                 source: str | None = None, name: str | None = None, kind: str = "alert"):
        self.deliver = list(deliver) if deliver is not None else None
        self.data_dir = data_dir
        self.source = source
        self.name = name
        self.kind = kind

    def __call__(self, message: str, severity: str = "info", **ctx: Any) -> dict[str, Any]:
        deliver = ctx.pop("deliver", self.deliver)
        return enqueue_alert(message, severity, deliver=deliver, data_dir=self.data_dir,
                             kind=ctx.pop("kind", self.kind), source=ctx.pop("source", self.source),
                             name=ctx.pop("name", self.name), **ctx)


def call(notifier: Any, message: str, severity: str, **ctx: Any) -> Any:
    """Call a notifier with context when it takes it (``OutboxNotifier``), else the old way
    (a test's own ``(message, severity)`` function)."""
    if isinstance(notifier, OutboxNotifier):
        return notifier(message, severity, **ctx)
    return notifier(message, severity)


def delivery_state(result: Any) -> str:
    """One word for a notifier result: sent | queued | not_configured | failed | not_sent."""
    if not isinstance(result, dict):
        return "not_sent"
    return str(result.get("status") or "not_sent")
