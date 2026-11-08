"""The forwarding producers: findings changes and host events -> outbox messages.

Both read an append-only source by row id after a per-channel cursor
(``forward_cursors``), so nothing is missed or sent twice across restarts:

* **findings** -- ``finding_events`` (every lifecycle change from every path: a run, a
  person's decision, a re-match after ``vulndb-update``). Each change of a matching
  finding becomes one message (``message_id`` ``finding:<finding_key>:<event id>``, sent
  in order per finding); an email channel gets one digest per run instead.
* **events** -- ``host_events``. Matching events are batched (at most ``BATCH_EVENTS`` or
  ``BATCH_BYTES`` of stored documents per message). The message holds the row ids, not a
  copy: the events are rendered from ``host_events`` when sent, so the outbox never
  becomes a second copy of the host history. While a channel already has
  ``MAX_EVENT_BACKLOG`` batches waiting (its receiver is down, or its rate cap holds them),
  the cursor waits too -- the events stay where they are, nothing is dropped.

The cursor moves in the same transaction that enqueues, and only if no other producer
moved it meanwhile (two processes producing at once enqueue nothing twice).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.outbox import config as C
from kratos.outbox import render as R
from kratos.outbox import store as S
from kratos.outbox.formats import NEWS, SEVERITY_RANK, FindingChange

logger = logging.getLogger(__name__)

BATCH_EVENTS = 500
BATCH_BYTES = 1_000_000
SCAN_ROWS = 5000                 # source rows looked at per channel per pass
MAX_EVENT_BACKLOG = 20           # batches waiting before the events cursor stops
MAX_FINDING_CHANGES = 500        # findings changes per channel per pass


# --- findings -------------------------------------------------------------------------------
def _details(raw: Any) -> dict[str, Any]:
    try:
        d = json.loads(raw or "{}")
        return d if isinstance(d, dict) else {}
    except (TypeError, ValueError):
        return {}


def change_of(kind: str, *, reason: str | None, to_state: str | None, details: dict[str, Any]) -> str | None:
    """A finding_events row -> the change a receiver sees (None: not forwarded)."""
    from kratos.lifecycle.store import DECIDED

    if kind == "created":
        return "new"
    if kind in ("reopened", "expired"):
        return "recurred" if reason == "recurred" else "reopened"
    if kind == "severity_changed":
        return "worse" if SEVERITY_RANK.get(str(details.get("to")), 0) > SEVERITY_RANK.get(str(details.get("from")), 0) \
            else "changed"
    if kind == "ssvc_changed":
        from kratos.ssvc.tree import rank

        return "worse" if rank(details.get("to")) > rank(details.get("from")) else "changed"
    if kind == "entities_changed":
        return "changed"
    if kind == "state_changed":
        if to_state in ("mitigated", "inactive"):
            return str(to_state)
        if to_state in DECIDED:
            return "decided"
        if to_state == "verified":
            return "verified"
        if to_state == "open":
            return "reopened"
        return "changed"
    return None                                      # "imported" history is not news


def _label(data_dir: Path, machine: str, cache: dict[str, str]) -> str:
    if machine not in cache:
        try:
            from kratos.agent.trigger_eval import machine_label

            cache[machine] = machine_label(data_dir, machine)
        except Exception:  # noqa: BLE001
            cache[machine] = machine
    return cache[machine]


def _changes(conn: sqlite3.Connection, after: int, limit: int, data_dir: Path) -> tuple[list[FindingChange], int]:
    try:
        rows = conn.execute(
            "SELECT e.id, e.finding_key, e.at, e.kind, e.from_state, e.to_state, e.actor, e.reason, e.run_id, "
            "e.details, r.rule_id, r.target, r.state, r.severity, r.title, r.latest FROM finding_events e "
            "JOIN finding_records r ON r.finding_key = e.finding_key WHERE e.id > ? ORDER BY e.id LIMIT ?",
            (after, limit)).fetchall()
    except sqlite3.OperationalError:          # the lifecycle tables don't exist yet
        return [], after
    labels: dict[str, str] = {}
    out = []
    last = after
    for r in rows:
        last = int(r["id"])
        d = _details(r["details"])
        change = change_of(r["kind"], reason=r["reason"], to_state=r["to_state"], details=d)
        if change is None:
            continue
        try:
            latest = json.loads(r["latest"] or "{}")
        except ValueError:
            latest = {}
        sev = str(d.get("to")) if r["kind"] == "severity_changed" and d.get("to") in SEVERITY_RANK else r["severity"]
        out.append(FindingChange(
            event_id=int(r["id"]), change=change, at=float(r["at"]), finding_key=r["finding_key"],
            rule_id=r["rule_id"], machine=r["target"], state=r["to_state"] or r["state"], severity=sev,
            title=r["title"], finding=latest if isinstance(latest, dict) else {}, from_state=r["from_state"],
            to_state=r["to_state"], reason=r["reason"], actor=r["actor"], run_id=r["run_id"],
            machine_label=_label(data_dir, r["target"], labels)))
    return out, last


def finding_passes(ch: C.Channel, c: FindingChange, data_dir: Path) -> bool:
    from kratos.outbox.alerts import in_scope

    f = ch.filters
    if f.min_severity and SEVERITY_RANK.get(c.severity, 0) < SEVERITY_RANK[f.min_severity]:
        return False
    if f.rule_prefixes and not any(c.rule_id.upper().startswith(p) for p in f.rule_prefixes):
        return False
    if f.min_ssvc:
        from kratos.ssvc.tree import rank

        ssvc = c.finding.get("ssvc") if isinstance(c.finding.get("ssvc"), dict) else {}
        if rank(ssvc.get("outcome")) < rank(f.min_ssvc):
            return False
    if f.only_new_or_worse and c.change not in NEWS:
        return False
    return in_scope(ch, [c.machine], data_dir)


def produce_findings(data_dir: Path | str, *, channels: list[C.Channel] | None = None) -> int:
    """Enqueue every new findings change for every channel that receives findings.
    Returns how many messages were added."""
    dd = Path(data_dir)
    added = 0
    for ch in channels if channels is not None else C.list_channels(dd):
        if not ch.enabled or "findings" not in ch.scopes:
            continue
        try:
            added += _produce_findings_for(ch, dd)
        except Exception:  # noqa: BLE001 -- one channel's trouble never stops the others
            logger.warning("outbox: forwarding findings to %s failed", ch.name, exc_info=True)
    return added


def _produce_findings_for(ch: C.Channel, dd: Path) -> int:
    with S.opened(dd) as conn:
        cur = S.cursor(conn, ch.name, "findings")
        if cur is None:
            return 0
        changes, last = _changes(conn, cur, MAX_FINDING_CHANGES, dd)
    if last == cur:
        return 0
    chosen = [c for c in changes if finding_passes(ch, c, dd)]
    messages: list[dict[str, Any]] = []
    if ch.kind == "email":
        groups: dict[str, list[FindingChange]] = {}
        for c in chosen:
            groups.setdefault(c.run_id or f"event-{c.event_id}", []).append(c)
        for key, items in groups.items():
            subject, _body = R.F_text.digest(items)
            messages.append({"kind": "findings_digest", "message_id": f"findings:{key}:{items[0].event_id}-"
                                                                       f"{items[-1].event_id}",
                             "payload": R.findings_digest(ch, items, dd), "summary": subject,
                             "severity": max((c.severity for c in items), key=lambda s: SEVERITY_RANK.get(s, 0)),
                             "machine": items[0].machine if len({c.machine for c in items}) == 1 else None,
                             "order_key": None, "run_id": items[0].run_id, "at": items[-1].at})
    else:
        for c in chosen:
            messages.append({"kind": "finding", "message_id": c.message_id, "payload": R.finding(ch, c, dd),
                             "summary": R.F_text.headline(c), "severity": c.severity, "machine": c.machine,
                             "order_key": c.finding_key, "run_id": c.run_id, "at": c.at})
    with S.opened(dd) as conn, S.immediate(conn):
        if S.cursor(conn, ch.name, "findings") != cur:
            return 0                                   # another process forwarded these meanwhile
        for m in messages:
            S.enqueue(conn, channel=ch.name, kind=m["kind"], message_id=m["message_id"], payload=m["payload"],
                      summary=m["summary"], severity=m["severity"], machine=m["machine"], order_key=m["order_key"],
                      source="forward", run_id=m["run_id"])
        S.set_cursor(conn, ch.name, "findings", last)
    return len(messages)


# --- events -----------------------------------------------------------------------------------
def produce_events(data_dir: Path | str, *, channels: list[C.Channel] | None = None) -> int:
    dd = Path(data_dir)
    added = 0
    for ch in channels if channels is not None else C.list_channels(dd):
        if not ch.enabled or "events" not in ch.scopes:
            continue
        try:
            added += _produce_events_for(ch, dd)
        except Exception:  # noqa: BLE001
            logger.warning("outbox: forwarding events to %s failed", ch.name, exc_info=True)
    return added


def _produce_events_for(ch: C.Channel, dd: Path) -> int:
    from kratos.outbox.alerts import in_scope

    added = 0
    for _round in range(MAX_EVENT_BACKLOG):
        with S.opened(dd) as conn:
            if S.backlog(conn, ch.name, "events") >= MAX_EVENT_BACKLOG:
                return added                          # the receiver is behind: let the events wait where they are
            cur = S.cursor(conn, ch.name, "events")
            if cur is None:
                return added
            try:
                rows = conn.execute("SELECT id, target, length(doc) n FROM host_events WHERE id > ? ORDER BY id "
                                    "LIMIT ?", (cur, SCAN_ROWS)).fetchall()
            except sqlite3.OperationalError:
                return added
        if not rows:
            return added
        ids: list[int] = []
        machines: set[str] = set()
        size = 0
        last = cur
        scope_cache: dict[str, bool] = {}
        for r in rows:
            m = r["target"]
            if m not in scope_cache:
                scope_cache[m] = in_scope(ch, [m], dd)
            if scope_cache[m]:
                if ids and (len(ids) >= BATCH_EVENTS or size + int(r["n"]) > BATCH_BYTES):
                    break
                ids.append(int(r["id"]))
                machines.add(m)
                size += int(r["n"])
            last = int(r["id"])
        with S.opened(dd) as conn, S.immediate(conn):
            if S.cursor(conn, ch.name, "events") != cur:
                return added
            if ids:
                ref = {"ref": {"stream": "host_events", "ids": ids, "machines": sorted(machines)}}
                S.enqueue(conn, channel=ch.name, kind="events", message_id=f"events:{ids[0]}-{ids[-1]}", payload=ref,
                          summary=f"{len(ids)} event(s) from " + ", ".join(sorted(machines)[:3])
                          + (" ..." if len(machines) > 3 else ""), severity="info",
                          machine=next(iter(machines)) if len(machines) == 1 else None, order_key="events",
                          source="forward")
                added += 1
            S.set_cursor(conn, ch.name, "events", last)
        if last == int(rows[-1]["id"]) and len(rows) < SCAN_ROWS:
            return added                              # read to the end of what is stored
    return added


def materialize(ch: C.Channel, payload: dict[str, Any], data_dir: Path) -> tuple[dict[str, Any], str]:
    """An events message's stored reference -> the payload to send (rendered now from the
    stored events), and a note (events no longer stored, events with no OCSF class)."""
    ref = payload.get("ref")
    if not isinstance(ref, dict):
        return payload, ""
    ids = [int(i) for i in ref.get("ids") or []]
    rows: list[tuple[int, str, dict[str, Any]]] = []
    with S.opened(data_dir) as conn:
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            for r in conn.execute(f"SELECT id, target, doc FROM host_events WHERE id IN ({','.join('?' * len(chunk))}) "
                                  "ORDER BY id", chunk):
                try:
                    rows.append((int(r["id"]), r["target"], json.loads(r["doc"])))
                except ValueError:
                    continue
    notes = []
    if len(rows) < len(ids):
        notes.append(f"{len(ids) - len(rows)} event(s) were pruned before they could be sent")
    out, skipped = R.events(ch, rows, data_dir, at=time.time(), first_row=ids[0] if ids else 0,
                            last_row=ids[-1] if ids else 0)
    if skipped:
        notes.append(f"{skipped} event(s) have no OCSF event class here and were left out")
    return out, "; ".join(notes)


def events_waiting(data_dir: Path | str, ch: C.Channel) -> int:
    """Stored events after this channel's cursor (not yet batched): the hidden part of the
    backlog. Counted by row id (cheap), so other machines' events are included."""
    with S.opened(data_dir) as conn:
        cur = S.cursor(conn, ch.name, "events")
        if cur is None:
            return 0
        try:
            return int(conn.execute("SELECT COUNT(*) FROM host_events WHERE id > ?", (cur,)).fetchone()[0])
        except sqlite3.OperationalError:
            return 0
