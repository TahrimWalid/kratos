"""What /doctor, the status bar and the CLI say about delivery. Read-only."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.outbox import config as C
from kratos.outbox import store as S


@dataclass
class ChannelHealth:
    name: str
    kind: str
    enabled: bool
    usable: bool
    why_not: str
    destination: str
    pending: int = 0
    failed: int = 0
    dead: int = 0
    delivered: int = 0
    events_waiting: int = 0
    last_success_at: float | None = None
    last_error: str | None = None
    last_error_at: float | None = None
    failing_since: float | None = None

    @property
    def failing(self) -> bool:
        return self.failing_since is not None and (self.failed or self.pending or self.dead)

    @property
    def backlog(self) -> int:
        return self.pending + self.failed + self.events_waiting


@dataclass
class Health:
    deliverer: str | None                  # the process holding the lease, in plain words
    deliverer_live: bool
    channels: list[ChannelHealth] = field(default_factory=list)

    @property
    def dead(self) -> int:
        return sum(c.dead for c in self.channels)

    @property
    def failing(self) -> list[ChannelHealth]:
        return [c for c in self.channels if c.enabled and c.failing]


def read(data_dir: Path | str) -> Health:
    from kratos.outbox import forward

    dd = Path(data_dir)
    channels = C.list_channels(dd)
    with S.opened(dd) as conn:
        lease = S.lease_info(conn)
        counts = S.counts(conn)
    live = lease is not None and lease.live()
    who = None
    if lease is not None:
        who = f"{lease.label} (pid {lease.pid} on {lease.host})"
    out = Health(who, live)
    for ch in channels:
        ok, why = C.usable(ch)
        n = counts.get(ch.name, {})
        waiting = forward.events_waiting(dd, ch) if "events" in ch.scopes and ch.enabled else 0
        out.channels.append(ChannelHealth(ch.name, ch.kind, ch.enabled, ok, why, ch.destination,
                                          n.get("pending", 0), n.get("failed", 0), n.get("dead", 0),
                                          n.get("delivered", 0), waiting, ch.last_success_at, ch.last_error,
                                          ch.last_error_at, ch.failing_since))
    return out


def status_bar_text(data_dir: Path | str) -> str | None:
    """'delivery failing: soc-webhook' while a channel's attempts are failing, else None."""
    try:
        h = read(data_dir)
    except Exception:  # noqa: BLE001 -- a status line never breaks the screen
        return None
    names = [c.name for c in h.failing]
    if not names:
        return None
    return "delivery failing: " + ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")


def ago(epoch: float | None) -> str:
    if epoch is None:
        return "never"
    s = max(0, int(time.time() - epoch))
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            return f"{s // n} {unit} ago"
    return f"{s} s ago"


def doctor_rows(data_dir: Path | str) -> list[dict[str, Any]]:
    """/doctor's delivery rows: who delivers, then one row per channel that is set up."""
    h = read(data_dir)
    rows: list[dict[str, Any]] = []
    if h.deliverer_live:
        rows.append({"check": "delivery", "status": "pass", "detail": f"delivered by {h.deliverer}", "fix": ""})
    else:
        waiting = sum(c.backlog for c in h.channels)
        rows.append({"check": "delivery", "status": "warn" if waiting else "info",
                     "detail": ("nothing long-running delivers right now: messages wait until Kratos next runs"
                                + (f" ({waiting} waiting)" if waiting else "")),
                     "fix": "install the always-on listener (`L` in /subagent), or keep the TUI open; "
                            "`kratos outbox flush` sends now"})
    for c in h.channels:
        if c.kind == "ntfy" and not c.usable and c.enabled:
            continue                                   # the notifications row already says how to set ntfy up
        if not c.enabled:
            rows.append({"check": f"channel {c.name}", "status": "info", "detail": f"{c.kind}: turned off",
                         "fix": f"kratos channels enable {c.name}"})
            continue
        bits = [f"{c.kind} -> {c.destination}", f"last success {ago(c.last_success_at)}"]
        if c.backlog:
            bits.append(f"{c.backlog} waiting")
        if c.dead:
            bits.append(f"{c.dead} dead letter(s)")
        status = "pass"
        fix = ""
        if c.failing:
            status = "warn"
            bits.append(f"failing since {ago(c.failing_since)}: {c.last_error}")
            fix = "check the receiver; `kratos outbox list --channel " + c.name + "` shows each attempt"
        elif c.dead:
            status = "warn"
            fix = "`kratos outbox list --status dead` shows why; `kratos outbox retry --dead` after fixing it"
        rows.append({"check": f"channel {c.name}", "status": status, "detail": "; ".join(bits), "fix": fix})
    try:
        from kratos import signing

        k = signing.info(data_dir)
        if k is not None:
            rows.append({"check": "signing key", "status": "pass", "detail": f"Ed25519 {k.fingerprint}", "fix": ""})
    except Exception:  # noqa: BLE001
        pass
    return rows
