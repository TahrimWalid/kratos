"""Which way the last read of a machine went (SSH, the sub-agent, this computer).

``ssh_remote._route`` notes the transport of every named read; ``evidence.record`` reads
it back for the file the read produced. A context variable, so a fleet run's parallel
machines (each in its own thread with its own context) never see each other's.
"""
from __future__ import annotations

import contextvars

from kratos.target_key import target_key

_LAST: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar("kratos_evidence_transport",
                                                                              default=None)


def note_transport(machine: str | None, transport: str) -> None:
    key = target_key(machine or "")
    if not key:
        return
    current = dict(_LAST.get() or {})
    current[key] = transport
    _LAST.set(current)


def last_transport(machine: str | None) -> str | None:
    return (_LAST.get() or {}).get(target_key(machine or ""))
