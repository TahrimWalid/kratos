"""Service activity from systemd itself (journal entries with _PID=1).

    Started Regular background program processing daemon.     (UNIT=cron.service)
    Stopped ... / Stopping ... / Reloading ... / Reloaded ...
    cron.service: Deactivated successfully.
    Failed to start ... / foo.service: Failed with result 'exit-code'.
    foo.service: Main process exited, code=exited, status=1/FAILURE
"""
from __future__ import annotations

import re
from typing import Any

from kratos.logsources.parsers import Parsed, journal_int, record_parts

_UNIT_PREFIX = re.compile(r"^(?P<unit>[A-Za-z0-9@._:\\-]+\.(?:service|socket|timer|mount|target|path|scope|slice|"
                          r"swap|automount|device)): (?P<rest>.*)$", re.DOTALL)
_RULES: tuple[tuple[re.Pattern[str], str, str | None], ...] = (
    (re.compile(r"^Failed to start "), "unit_failed", "failure"),
    (re.compile(r"Failed with result"), "unit_failed", "failure"),
    (re.compile(r"Main process exited, code=(?:exited|killed|dumped), status=(?!0/)"), "unit_failed", "failure"),
    (re.compile(r"^Started "), "unit_started", "success"),
    (re.compile(r"^Starting "), "unit_starting", None),
    (re.compile(r"^Stopped "), "unit_stopped", "success"),
    (re.compile(r"^Stopping "), "unit_stopping", None),
    (re.compile(r"Deactivated successfully"), "unit_stopped", "success"),
    (re.compile(r"^Reloaded "), "unit_reloaded", "success"),
    (re.compile(r"^Reloading"), "unit_reloading", None),
    (re.compile(r"^Finished "), "unit_finished", "success"),
)


def to_parsed(rec: Any) -> Parsed | None:
    if rec.kind != "journal":
        return None
    e = rec.entry or {}
    if journal_int(e, "_PID") not in (1, None):
        return None
    _prog, _pid, msg, _orig, cursor = record_parts(rec)
    unit = e.get("UNIT") if isinstance(e.get("UNIT"), str) else None
    text = msg
    m = _UNIT_PREFIX.match(msg)
    if m:
        unit = unit or m.group("unit")
        text = m.group("rest")
    action, outcome = "systemd_other", None
    for rx, act, out in _RULES:
        if rx.search(text):
            action, outcome = act, out
            break
    fields: dict[str, Any] = {"service_name": unit, "process_pid": 1, "process_name": "systemd",
                              "log_syslog_priority": journal_int(e, "PRIORITY")}
    return Parsed(ts=rec.ts, action=action, provider="systemd", outcome=outcome, message=msg,
                  fields={k: v for k, v in fields.items() if v not in (None, "")}, cursor=cursor)


def parse(read: Any) -> list[Parsed]:
    return [p for p in (to_parsed(r) for r in read.records) if p is not None]
