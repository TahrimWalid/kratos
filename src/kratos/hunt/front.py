"""The one way every surface starts a hunt (CLI, TUI, chat, MCP).

`parse_command("198.51.100.7 --since 30d --machine web01")` reads the words people
type after `/hunt`; `resolve_hunt(...)` classifies the indicators, refuses what can't be
hunted, returns the ambiguous ones to ask about and scopes the machines;
`start_hunt(...)` runs it. The scope is the CALLER's: a chat or MCP token passes the machines it may see,
and a `--machine` outside that scope is refused, never widened.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos.hunt import indicators as I
from kratos.target_key import target_key

_SHORT = re.compile(r"^(\d{1,5})\s*([mhdw])$", re.IGNORECASE)
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


class HuntUsageError(ValueError):
    """Something in what was typed can't be used, said plainly."""


def time_bound(text: str | None) -> float | None:
    """'30d', '24h', '7 days ago', 'yesterday', '2026-10-01', '@<epoch>' -> epoch seconds."""
    if text is None or not str(text).strip():
        return None
    from kratos.utils.time_window import TimeBoundError, resolve_time_bound

    t = str(text).strip()
    m = _SHORT.match(t)
    if m:
        t = f"{m.group(1)} {_UNITS[m.group(2).lower()]} ago"
    try:
        value = resolve_time_bound(t)
    except TimeBoundError as e:
        raise HuntUsageError(str(e)) from None
    from kratos.datainv import to_epoch

    epoch = to_epoch(value) if not isinstance(value, (int, float)) else float(value)
    if epoch is None:
        raise HuntUsageError(f"could not understand the time {text!r}")
    return float(epoch)


@dataclass
class Request:
    words: list[str] = field(default_factory=list)
    kind: str | None = None
    since: str | None = None
    until: str | None = None
    machines: list[str] = field(default_factory=list)


def parse_command(text: str) -> Request:
    """The words after `/hunt`: indicators, then --type, --since, --until, --machine."""
    try:
        parts = shlex.split(str(text or ""))
    except ValueError as e:
        raise HuntUsageError(f"could not read that: {e}") from None
    req = Request()
    it = iter(parts)
    for p in it:
        if p in ("--type", "-t", "--since", "--until", "--machine", "-m"):
            try:
                value = next(it)
            except StopIteration:
                raise HuntUsageError(f"{p} needs a value") from None
            if p in ("--type", "-t"):
                req.kind = value
            elif p == "--since":
                req.since = value
            elif p == "--until":
                req.until = value
            else:
                req.machines.append(value)
        elif p.startswith("--"):
            raise HuntUsageError(f"unknown option {p} (use --type, --since, --until, --machine)")
        else:
            req.words.append(p)
    if not req.words:
        raise HuntUsageError("what should Kratos hunt for? e.g. /hunt 203.0.113.9  (an address, a CIDR network, "
                             "a SHA-256, an account, a domain, a program or a path)")
    return req


USAGE = ("Usage: /hunt <indicator> [more ...] [--type ip|sha256|account|domain|program|path] [--since 30d] "
         "[--until <time>] [--machine <name>]")


@dataclass
class Prepared:
    indicators: list[I.Indicator]
    ambiguous: list[I.Ambiguous]
    machines: list[str] | None
    start: float | None
    end: float | None


def resolve_hunt(req: Request, *, scope: list[str] | None = None) -> Prepared:
    """Classify and scope. `scope`: the machines the caller may search (None = all)."""
    try:
        parsed = I.parse(req.words, I.kind_of(req.kind) if req.kind else None)
    except I.IndicatorError as e:
        raise HuntUsageError(str(e)) from None
    start, end = time_bound(req.since), time_bound(req.until)
    if start is not None and end is not None and end <= start:
        raise HuntUsageError("--until must be after --since")
    allowed = None if scope is None else sorted({target_key(m) for m in scope})
    machines: list[str] | None = allowed
    if req.machines:
        wanted = sorted({target_key(m) for m in req.machines})
        if allowed is not None:
            outside = [m for m in wanted if m not in allowed]
            if outside:
                raise HuntUsageError(f"not a machine you may search here: {', '.join(outside)}")
        machines = wanted
    return Prepared(parsed.indicators, parsed.ambiguous, machines, start, end)


def start_hunt(data_dir: Path | str, prepared: Prepared, *, source: str, actor: str,
        progress: Callable[[str], None] | None = None) -> Any:
    from kratos.hunt.search import run_hunt

    if prepared.ambiguous:
        raise HuntUsageError(prepared.ambiguous[0].question() + " Add --type " + "|".join(prepared.ambiguous[0].options))
    if not prepared.indicators:
        raise HuntUsageError("nothing to hunt for")
    return run_hunt(data_dir, prepared.indicators, machines=prepared.machines, start=prepared.start,
                    end=prepared.end, source=source, actor=actor, progress=progress)
