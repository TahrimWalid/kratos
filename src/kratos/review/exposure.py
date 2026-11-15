"""Exposure of a confirmed root's serving process (E.7b §3.4, point 3): internet >
network > local > unknown, and a root whose serving process isn't running ranks last.

A review doesn't take a new live read -- it reuses what A.5's newest live snapshot and the
root's own stored ``serving`` listeners already say, classified with D.3's own address rules
(``ssvc.exposure``), so one listener's verdict is never paired with another's address.

The result is one word used only for ranking and for capping severity in judge.py; it degrades
to ``unknown`` whenever the data can't decide, never to a guess.
"""
from __future__ import annotations

from typing import Any, Iterable

from kratos.ssvc import exposure as X

INTERNET, NETWORK, LOCAL, UNKNOWN, NOT_RUNNING = (
    X.INTERNET, X.NETWORK, X.LOCAL, X.UNKNOWN, "not_running")
_RANK = {INTERNET: 0, NETWORK: 1, LOCAL: 2, UNKNOWN: 3, NOT_RUNNING: 4}


def _addr_exposure(address: Any, machine_public: list[Any]) -> str:
    ip = X._ip(address)
    if ip is None:
        # A unix socket or an address Kratos can't parse: not a network exposure by itself.
        return LOCAL if isinstance(address, str) and address.startswith("/") else UNKNOWN
    if ip.is_loopback:
        return LOCAL
    if X._public(ip):
        return INTERNET
    if X._wildcard(ip):
        return INTERNET if machine_public else NETWORK
    return NETWORK


def _machine_public(local_addresses: Iterable[str]) -> list[Any]:
    return [a for a in (X._ip(x) for x in local_addresses or []) if a is not None and X._public(a)]


def root_exposure(serving: list[dict[str, Any]] | None, local_addresses: Iterable[str] | None = None,
                  *, running: bool | None = None) -> str:
    """The most-exposed classification of a root's serving listeners. ``serving`` is the root's
    stored listener list (``{address, pid, port, ...}``). ``running`` overrides the
    not-running call when the newest live read knows the serving pid is gone; when it is None
    an empty ``serving`` list is taken as not running (the last read saw no listener for it)."""
    items = [s for s in (serving or []) if isinstance(s, dict)]
    if running is False or (running is None and not items):
        return NOT_RUNNING
    if not items:
        return UNKNOWN
    machine_public = _machine_public(local_addresses or [])
    best = UNKNOWN
    for item in items:
        e = _addr_exposure(item.get("address"), machine_public)
        if _RANK[e] < _RANK[best]:
            best = e
    return best


def serving_running(serving: list[dict[str, Any]] | None, live_doc: dict[str, Any] | None) -> bool | None:
    """Whether the root's serving pid still appears among the newest live snapshot's listeners.
    None when there's no live snapshot or the root names no pid (can't tell)."""
    if not live_doc:
        return None
    pids = {s.get("pid") for s in (serving or []) if isinstance(s, dict) and s.get("pid") is not None}
    if not pids:
        return None
    try:
        from kratos.live import record as LR
        live_pids = {x.get("pid") for x in LR.listeners(live_doc) if isinstance(x, dict)}
    except Exception:  # noqa: BLE001
        return None
    if not live_pids:
        return None
    return bool(pids & live_pids)
