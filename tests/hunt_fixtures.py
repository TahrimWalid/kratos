"""Shared builders for the C.3 hunt tests (neutral values: RFC 5737 addresses,
example.com, alice/bob)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from kratos.events.model import Event

UTC = timezone.utc


def event(ts: float, *, target: str = "web01", n: int = 0, dataset: str = "kratos.auth", **fields) -> Event:
    t = datetime.fromtimestamp(ts, UTC)
    eid = hashlib.sha256(f"{target}|{ts}|{n}|{sorted(fields.items())}".encode()).hexdigest()[:32]
    return Event(timestamp=t, created=t, event_id=eid, kind="event", dataset=dataset, host_name=target,
                 transport="ssh", parser="test", **fields)
