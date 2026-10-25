"""Apply one run's findings to the lifecycle: identity, automatic moves, annotations.

Called from findings_engine.write_findings_report -- the one place every path
(the agent's correlate_findings, scheduled runs, `kratos run`,
`findings-generate`) writes a report -- after the rules ran. Detection is
untouched; this only remembers.

In one BEGIN IMMEDIATE transaction:

- each finding is matched to its record by finding_key (created if new);
- the deterministic moves happen, each recorded with actor "kratos", the run
  id and a reason: present after mitigated/inactive -> open (regressed /
  recurred); absent in a run that re-checked its rule -> mitigated / inactive;
  a decision that expired, or no longer covers what the finding shows (a new
  entity, a higher severity) -> open;
- a person's decision at a broader scope (this rule on this machine / this rule
  everywhere) that covers a finding applies to it.

Idempotent per run: applying the same findings in the same run again changes
nothing (scheduled runs write a second report at the end of the run). A
finding's `change` is read from this run's events, so it stays the same too.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from kratos.lifecycle import store as S
from kratos.lifecycle.coverage import Coverage
from kratos.lifecycle.keys import finding_key, normalise_subject
from kratos.lifecycle.rules import rule_info
from kratos.run_context import RunContext
from kratos.utils.timeutil import epoch_to_utc_iso

logger = logging.getLogger(__name__)

KRATOS = "kratos"
SUMMARY_KEYS = ("new", "still_open", "fixed", "not_rechecked", "hidden", "expired_this_run")
_INTERFACE = {"interactive": "tui", "evolve": "tui", "pipeline": "tui", "schedule": "scheduled",
              "trigger": "scheduled", "cli": "cli", "mcp": "mcp", "web": "web",
              "watch": "scheduled"}
_ABSENT_TO = {"condition": "mitigated", "occurrence": "inactive"}


def interface_for(run: RunContext | None) -> str:
    return _INTERFACE.get(run.source, run.source) if run else "cli"


def _iso(epoch: float | None) -> str | None:
    return epoch_to_utc_iso(epoch) if epoch is not None else None


def _entities(finding: dict[str, Any]) -> list[str]:
    return sorted({str(e) for e in finding.get("entities") or [] if str(e)})


def _decision_dict(exc: sqlite3.Row) -> dict[str, Any]:
    return {"kind": exc["kind"], "owner": exc["owner"], "reason": exc["reason"],
            "expires_at": _iso(exc["expires_at"]), "scope": exc["scope"],
            "decided_at": _iso(exc["created_at"]), "decided_by": exc["created_by"], "id": exc["id"]}


class _Run:
    def __init__(self, conn: sqlite3.Connection, *, target: str, run_id: str, interface: str, now: float):
        self.conn, self.target, self.run_id, self.interface, self.now = conn, target, run_id, interface, now

    def event(self, key: str, kind: str, *, from_state: str | None = None, to_state: str | None = None,
              reason: str | None = None, details: dict[str, Any] | None = None) -> None:
        S.add_event(self.conn, key, at=self.now, kind=kind, actor=KRATOS, from_state=from_state,
                    to_state=to_state, interface=self.interface, reason=reason, run_id=self.run_id,
                    details=details)

    def move(self, key: str, frm: str, to: str, kind: str, reason: str,
             details: dict[str, Any] | None = None) -> None:
        S.set_state(self.conn, key, to)
        self.event(key, kind, from_state=frm, to_state=to, reason=reason, details=details)

    def settle_decision(self, rec: sqlite3.Row, *, present: bool, severity: str, entities: list[str]) -> None:
        """Re-evaluate the decision behind (or now covering) a record."""
        key, state = rec["finding_key"], rec["state"]
        exc = S.applicable_exception(self.conn, key=key, rule_id=rec["rule_id"], target=rec["target"],
                                     now=self.now)
        if state in S.DECIDED:
            if exc is None:
                gone = S.expired_exception(self.conn, key=key, rule_id=rec["rule_id"], target=rec["target"],
                                           now=self.now)
                if gone is not None:
                    self.move(key, state, "open", "expired",
                              f"your decision ({gone['kind'].replace('_', ' ')}) expired "
                              f"{_iso(gone['expires_at'])}", {"exception_id": gone["id"]})
                else:
                    self.move(key, state, "open", "reopened", "no decision covers it any more")
                return
            if present:
                ok, why = S.covers(exc, severity=severity, entities=entities)
                if not ok:
                    self.move(key, state, "open", "reopened", why, {"exception_id": exc["id"]})
                    if exc["scope"] == "key":
                        self.conn.execute(
                            "UPDATE finding_exceptions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
                            "WHERE id = ?", (self.now, KRATOS, why, exc["id"]))
                    return
            if exc["kind"] != state:     # a newer decision of another kind took over
                self.move(key, state, exc["kind"], "state_changed",
                          f"your decision #{exc['id']} ({exc['scope']}) applies", {"exception_id": exc["id"]})
            return
        if present and exc is not None and state in S.SHOWN_BY_DEFAULT:
            ok, _why = S.covers(exc, severity=severity, entities=entities)
            if ok:
                self.move(key, state, exc["kind"], "state_changed",
                          f"covered by your decision #{exc['id']} ({exc['scope'].replace('_', ' ')}, "
                          f"by {exc['created_by']})", {"exception_id": exc["id"]})


def _upsert_present(r: _Run, finding: dict[str, Any], coverage: Coverage) -> str | None:
    rid = str(finding.get("id") or "")
    info = rule_info(rid)
    kind = info.kind if info else "condition"   # an unknown rule is never marked gone (never covered)
    subject = normalise_subject(finding.get("subject"))
    key = finding_key(rid, r.target, subject)
    severity = str(finding.get("severity") or "info").lower()
    entities = _entities(finding)
    covered = coverage.covered(rid)
    latest = json.dumps(finding, sort_keys=True, default=str)
    rec = S.get_record(r.conn, key)
    if rec is None:
        r.conn.execute(
            "INSERT INTO finding_records (finding_key, rule_id, target, subject, kind, state, severity, title, "
            "entities, latest, first_seen, last_seen, last_checked, last_run_id, times_seen) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (key, rid, r.target, subject, kind, severity, str(finding.get("title") or ""), json.dumps(entities),
             latest, r.now, r.now, r.now if covered else None, r.run_id),
        )
        r.event(key, "created", to_state="open", reason="first seen")
    else:
        seen_again = rec["last_run_id"] != r.run_id
        r.conn.execute(
            "UPDATE finding_records SET severity = ?, title = ?, entities = ?, latest = ?, last_seen = ?, "
            "last_checked = COALESCE(?, last_checked), last_run_id = ?, times_seen = times_seen + ? "
            "WHERE finding_key = ?",
            (severity, str(finding.get("title") or ""), json.dumps(entities), latest, r.now,
             r.now if covered else None, r.run_id, 1 if seen_again else 0, key),
        )
        if rec["severity"] != severity:
            r.event(key, "severity_changed", from_state=rec["state"], to_state=rec["state"],
                    reason=f"severity {rec['severity']} -> {severity}",
                    details={"from": rec["severity"], "to": severity})
        old_entities = json.loads(rec["entities"] or "[]")
        if old_entities != entities:
            added = sorted(set(entities) - set(old_entities))
            removed = sorted(set(old_entities) - set(entities))
            r.event(key, "entities_changed", from_state=rec["state"], to_state=rec["state"],
                    reason="; ".join(p for p in (f"new: {', '.join(added)}" if added else "",
                                                 f"gone: {', '.join(removed)}" if removed else "") if p),
                    details={"added": added, "removed": removed})
        if rec["state"] == "mitigated":
            r.move(key, "mitigated", "open", "reopened", "regressed")
        elif rec["state"] == "inactive":
            r.move(key, "inactive", "open", "reopened", "recurred")
    rec = S.get_record(r.conn, key)
    r.settle_decision(rec, present=True, severity=severity, entities=entities)
    return key


def _settle_absent(r: _Run, rec: sqlite3.Row, coverage: Coverage) -> None:
    key, state = rec["finding_key"], rec["state"]
    covered = coverage.covered(rec["rule_id"], json.loads(rec["entities"] or "[]"))
    if covered:
        r.conn.execute("UPDATE finding_records SET last_checked = ? WHERE finding_key = ?", (r.now, key))
    if state in S.DECIDED:
        # An accepted risk that went away is still an accepted decision -- unless it expired.
        r.settle_decision(rec, present=False, severity=rec["severity"], entities=json.loads(rec["entities"]))
        return
    info = rule_info(rec["rule_id"])
    if info is not None and info.sticky:
        return  # evidence of tampering: never closed by a later run not seeing it (rules.RuleInfo.sticky)
    if state in S.SHOWN_BY_DEFAULT and covered:
        to = _ABSENT_TO.get(rec["kind"], "mitigated")
        r.move(key, state, to, "state_changed",
               "not found in a run that re-checked it" if to == "mitigated"
               else "no recurrence in a run that re-checked it",
               {"rechecked": list(rule_info(rec["rule_id"]).covering_inputs) if rule_info(rec["rule_id"]) else []})


_CHANGE_PRIORITY = ("new", "recurred", "reopened", "changed", "unchanged")


def _change_of(events: list[sqlite3.Row]) -> str:
    found = {"unchanged"}
    for e in events:
        if e["kind"] == "created":
            found.add("new")
        elif e["kind"] in ("reopened", "expired"):
            found.add("recurred" if e["reason"] == "recurred" else "reopened")
        elif e["kind"] in ("severity_changed", "entities_changed"):
            found.add("changed")
    return next(c for c in _CHANGE_PRIORITY if c in found)


def _annotate(conn: sqlite3.Connection, finding: dict[str, Any], key: str, run_id: str, now: float) -> dict[str, Any]:
    rec = S.get_record(conn, key)
    events = conn.execute("SELECT * FROM finding_events WHERE finding_key = ? AND run_id = ? ORDER BY id",
                          (key, run_id)).fetchall()
    out = dict(finding)
    out.update(finding_key=key, state=rec["state"], first_seen=_iso(rec["first_seen"]),
               last_seen=_iso(rec["last_seen"]), change=_change_of(events))
    exc = S.decision_of(conn, rec, now)
    if exc is not None:
        out["decision"] = _decision_dict(exc)
    return out


def empty_summary() -> dict[str, Any]:
    return {"new": [], "still_open": [], "fixed": [], "not_rechecked": [],
            "hidden": {k: 0 for k in S.EXCEPTION_KINDS}, "expired_this_run": []}


def apply_run(findings: list[dict[str, Any]], *, target: str, coverage: Coverage, run: RunContext | None,
              data_dir: Path, now: float | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(annotated findings in the same order, lifecycle summary). Run notes pass
    through with state "run_note" and no key; they are never stored or hidden."""
    now = time.time() if now is None else now
    run_id = run.run_id if run is not None else "adhoc-" + uuid.uuid4().hex
    target = target or "unknown"
    with S.opened(data_dir) as conn, S.immediate(conn):
        r = _Run(conn, target=target, run_id=run_id, interface=interface_for(run), now=now)
        keys: list[str | None] = []
        for f in findings:
            info = rule_info(str(f.get("id") or ""))
            if info is not None and info.kind == "run_note":
                keys.append(None)
                continue
            if info is None:
                logger.warning("finding rule %s has no lifecycle entry (lifecycle/rules.py); treating it as a "
                               "condition that is never marked gone", f.get("id"))
            keys.append(_upsert_present(r, f, coverage))
        present = {k for k in keys if k}
        for rec in S.list_records(conn, target=target):
            if rec["finding_key"] not in present:
                _settle_absent(r, rec, coverage)

        annotated: list[dict[str, Any]] = []
        summary = empty_summary()
        for f, key in zip(findings, keys):
            if key is None:
                annotated.append({**f, "state": "run_note", "change": None})
                continue
            a = _annotate(conn, f, key, run_id, now)
            annotated.append(a)
            if a["state"] in S.DECIDED:
                summary["hidden"][a["state"]] += 1
            elif a["state"] in S.SHOWN_BY_DEFAULT:
                summary["new" if a["change"] in ("new", "reopened", "recurred") else "still_open"].append(key)
        for row in conn.execute("SELECT DISTINCT e.finding_key, e.kind, e.to_state FROM finding_events e "
                                "JOIN finding_records r ON r.finding_key = e.finding_key "
                                "WHERE e.run_id = ? AND r.target = ?", (run_id, target)):
            if row["kind"] == "state_changed" and row["to_state"] in ("mitigated", "inactive"):
                summary["fixed"].append(row["finding_key"])
            if row["kind"] == "expired":
                summary["expired_this_run"].append(row["finding_key"])
        fixed = set(summary["fixed"])
        for rec in S.list_records(conn, target=target, states=set(S.SHOWN_BY_DEFAULT)):
            if rec["finding_key"] not in present and rec["finding_key"] not in fixed:
                info = rule_info(rec["rule_id"])
                # sticky evidence stays open until a person decides: it is still open, not "unchecked"
                summary["still_open" if info is not None and info.sticky else "not_rechecked"].append(
                    rec["finding_key"])
        for name in ("fixed", "expired_this_run", "not_rechecked", "still_open"):
            summary[name] = sorted(set(summary[name]))
    summary["hidden_total"] = sum(summary["hidden"].values())
    summary["target"] = target
    summary["run_id"] = run_id
    return annotated, summary


def footer_line(summary: dict[str, Any] | None) -> str | None:
    """The deterministic line under an answer, a report and a notification:
    'New 2 · Still open 3 · Fixed 1 · Hidden by your decisions 4'."""
    if not summary:
        return None
    hidden = summary.get("hidden_total")
    if hidden is None:
        hidden = sum((summary.get("hidden") or {}).values())
    return (f"New {len(summary.get('new') or [])} · Still open {len(summary.get('still_open') or [])} · "
            f"Fixed {len(summary.get('fixed') or [])} · Hidden by your decisions {hidden}")
