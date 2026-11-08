"""The delivery worker: the one process that sends what the outbox holds.

At most one worker delivers at a time, across every Kratos process on this computer: it
holds the ``outbox_lease`` row (claimed with a TTL in BEGIN IMMEDIATE, renewed every
cycle). The always-on listener runs one; so do the TUI, ``kratos serve`` and
``kratos mcp-serve`` -- whichever gets the lease delivers, the others wait and take over
if it stops (a dead holder's lease runs out after ``LEASE_TTL_SECONDS``). A scheduled run
flushes before it exits when nothing else delivers; ``kratos outbox flush`` does it on demand.

Threads: one loop thread per worker; sends run on a small pool (``POOL``), with at most
``CONCURRENCY[kind]`` attempts in flight per channel (1 for syslog and email, 4 for a
webhook), and at most the channel's ``max_per_minute`` attempts per minute (a flood
queues; nothing is dropped). Each attempt is claimed per message, so two threads or
processes never send one message at the same time; a message whose sender died is sent
again with the same id after its claim runs out (the receiver drops the repeat).

A channel whose messages have been failing for ``outbox.alert_after_minutes`` gets one
notice through the person's other alert channels, and one more when it recovers.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox.channels import CONCURRENCY, TIMEOUT_SECONDS, Delivery, clean_reason, sender_for

logger = logging.getLogger(__name__)

POLL_SECONDS = 2.0
PRODUCE_EVERY_SECONDS = 5.0
POOL = 8
CLAIM_MARGIN_SECONDS = 30.0

_live: "set[Worker]" = set()
_live_lock = threading.Lock()


def wake(*, produce: bool = False) -> None:
    """Tell this process's workers there is something to send now (an enqueue happened);
    ``produce``: also look for new findings changes and events at once (a report was
    written, a person decided)."""
    with _live_lock:
        workers = list(_live)
    for w in workers:
        if produce:
            w._produce_now = True
        w._wake.set()


def running_worker(data_dir: Path | str) -> "Worker | None":
    with _live_lock:
        for w in _live:
            if Path(w.data_dir) == Path(data_dir) and w.is_alive():
                return w
    return None


class Worker:
    def __init__(self, data_dir: Path | str, *, label: str, poll: float = POLL_SECONDS,
                 produce_every: float = PRODUCE_EVERY_SECONDS):
        self.data_dir = Path(data_dir)
        self.label = label
        self.poll = poll
        self.produce_every = produce_every
        self.holder = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._inflight: dict[str, int] = {}
        self._lock = threading.Lock()
        self._last_produce = 0.0
        self._produce_now = False
        self.holding = False

    # --- lifecycle -------------------------------------------------------------------
    def start(self) -> "Worker":
        if self._thread is not None:
            return self
        self._pool = ThreadPoolExecutor(max_workers=POOL, thread_name_prefix="kratos-outbox")
        self._thread = threading.Thread(target=self._loop, name="kratos-outbox-worker", daemon=True)
        with _live_lock:
            _live.add(self)
        self._thread.start()
        return self

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self, timeout: float = 15.0) -> None:
        """Stop sending: no new attempts, wait for the ones in flight, give the lease up."""
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout)
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
        with _live_lock:
            _live.discard(self)
        if self.holding:
            try:
                with S.opened(self.data_dir) as conn:
                    S.release_lease(conn, self.holder)
            except Exception:  # noqa: BLE001 -- the lease runs out on its own
                pass
            self.holding = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.cycle()
            except Exception:  # noqa: BLE001 -- a bad cycle never ends delivery
                logger.warning("outbox: delivery cycle failed", exc_info=True)
            self._wake.wait(self.poll)
            self._wake.clear()

    # --- one cycle ----------------------------------------------------------------------
    def take_lease(self) -> bool:
        with S.opened(self.data_dir) as conn:
            self.holding = S.acquire_lease(conn, holder=self.holder, label=self.label, pid=os.getpid(),
                                           host=socket.gethostname())
        return self.holding

    def cycle(self, *, now: float | None = None, wait: bool = False) -> dict[str, int]:
        """Renew the lease; produce forwarding messages; start the due attempts. With
        ``wait`` the attempts run before returning (a flush)."""
        stats = {"produced": 0, "started": 0}
        if not self.take_lease():
            return stats
        now = time.time() if now is None else now
        channels = C.list_channels(self.data_dir)
        if self._produce_now or now - self._last_produce >= self.produce_every:
            self._last_produce, self._produce_now = now, False
            from kratos.outbox import forward

            stats["produced"] = forward.produce_findings(self.data_dir, channels=channels) \
                + forward.produce_events(self.data_dir, channels=channels)
        futures = []
        for ch in channels:
            ok, _why = C.usable(ch)
            if not ok:
                continue
            futures.extend(self._start_due(ch, now, run_inline=wait))
        stats["started"] = len(futures)
        for ch in channels:
            self._check_outage(ch, now)
        if wait:
            for f in futures:
                f.result()
        return stats

    def _start_due(self, ch: C.Channel, now: float, *, run_inline: bool) -> list[Any]:
        with self._lock:
            room = CONCURRENCY.get(ch.kind, 1) - self._inflight.get(ch.name, 0)
        if room <= 0:
            return []
        with S.opened(self.data_dir) as conn:
            room = min(room, ch.max_per_minute - S.sent_in_window(conn, ch.name, since=now - 60))
            if room <= 0:
                return []
            rows = S.due(conn, ch.name, now=now, limit=room)
            claimed = []
            ttl = TIMEOUT_SECONDS.get(ch.kind, 30) + CLAIM_MARGIN_SECONDS
            for r in rows:
                att = S.claim(conn, int(r["id"]), holder=self.holder, ttl=ttl, now=now)
                if att is not None:
                    claimed.append((r, att))
        out = []
        for r, att in claimed:
            with self._lock:
                self._inflight[ch.name] = self._inflight.get(ch.name, 0) + 1
            if self._pool is None or run_inline and self._thread is None:
                from concurrent.futures import Future

                fut: Future = Future()
                try:
                    fut.set_result(self._deliver(ch, r, att))
                except Exception as e:  # noqa: BLE001
                    fut.set_exception(e)
                out.append(fut)
            else:
                out.append(self._pool.submit(self._deliver, ch, r, att))
        return out

    def _deliver(self, ch: C.Channel, row: Any, attempt_id: int) -> str | None:
        try:
            return self._attempt(ch, row, attempt_id)
        finally:
            with self._lock:
                self._inflight[ch.name] = max(0, self._inflight.get(ch.name, 1) - 1)

    def _attempt(self, ch: C.Channel, row: Any, attempt_id: int) -> str | None:
        import json

        from kratos.outbox import forward

        oid = int(row["id"])
        secrets = C.read_secrets(self.data_dir, ch.name)
        note = ""
        try:
            payload = json.loads(row["payload"])
            payload, note = forward.materialize(ch, payload, self.data_dir)
        except Exception as e:  # noqa: BLE001
            outcome = S.Outcome(False, True, clean_reason(f"could not prepare the message: {e}", *secrets.values()))
        else:
            if payload.get("content_type") == "skip" or (row["kind"] == "events" and not payload.get("frames")
                                                         and not payload.get("body")):
                outcome = S.Outcome(True, False, "nothing to send: " + (note or "no events"))
            else:
                sender = sender_for(ch.kind)
                try:
                    outcome = sender(Delivery(row["message_id"], row["kind"], payload, int(row["attempts"])), ch,
                                     secrets, self.data_dir)
                except Exception as e:  # noqa: BLE001 -- senders don't raise; belt and braces
                    outcome = S.Outcome(False, True, clean_reason(f"sender failed: {e}", *secrets.values()))
        if note and outcome.ok:
            outcome = S.Outcome(True, False, f"{outcome.detail} ({note})", outcome.status_code)
        now = time.time()
        with S.opened(self.data_dir) as conn:
            status = S.finish(conn, oid, attempt_id, holder=self.holder, outcome=outcome, now=now)
            with S.immediate(conn):
                health = C.record_health(conn, ch.name, ok=outcome.ok, error=None if outcome.ok else outcome.detail,
                                         now=now)
        if outcome.ok and health.get("recovered_from"):
            self._notice_recovered(ch, float(health["recovered_from"]))
        log = logger.info if outcome.ok else logger.warning
        log("outbox: %s #%d to %s: %s (%s)", row["kind"], oid, ch.name, status or "superseded", outcome.detail)
        return status

    # --- outage notices ----------------------------------------------------------------------
    def _check_outage(self, ch: C.Channel, now: float) -> None:
        if ch.failing_since is None or ch.outage_notified_at is not None:
            return
        from kratos.outbox.settings import alert_after_minutes

        if now - ch.failing_since < alert_after_minutes(self.data_dir) * 60:
            return
        with S.opened(self.data_dir) as conn:
            if S.backlog(conn, ch.name) == 0 and not conn.execute(
                    "SELECT 1 FROM outbox WHERE channel = ? AND status = 'dead' AND dead_at >= ?",
                    (ch.name, ch.failing_since)).fetchone():
                return                                     # nothing is waiting or lost: not an outage
            with S.immediate(conn):
                if not C.mark_outage_notified(conn, ch.name, now):
                    return
        since = self._when(ch.failing_since)
        reason = ch.last_error or "it doesn't answer"
        self._notice(f"Kratos can't reach {ch.name} since {since}: {reason}. Messages wait in the outbox and are "
                     "retried; see /outbox.", f"outage:{ch.name}:{int(ch.failing_since)}", ch.name, "warning")

    def _notice_recovered(self, ch: C.Channel, since: float) -> None:
        self._notice(f"Kratos reaches {ch.name} again (it was failing since {self._when(since)}); waiting messages "
                     "are being delivered.", f"recovered:{ch.name}:{int(since)}", ch.name, "info")

    def _notice(self, text: str, message_id: str, channel: str, severity: str) -> None:
        from kratos.outbox.alerts import enqueue_alert

        try:
            enqueue_alert(text, severity, deliver=None, data_dir=self.data_dir, kind="notice", source="outbox",
                          message_id=message_id, exclude=(channel,))
        except Exception:  # noqa: BLE001
            logger.warning("outbox: could not enqueue a notice about %s", channel, exc_info=True)

    def _when(self, epoch: float) -> str:
        from kratos.utils.timeutil import epoch_to_utc_iso, format_for_display

        return format_for_display(epoch_to_utc_iso(epoch), "%Y-%m-%d %H:%M %Z", self.data_dir)


# --- flushing from a short-lived process -------------------------------------------------------
def flush(data_dir: Path | str, *, label: str, deadline_seconds: float = 30.0) -> dict[str, Any]:
    """Deliver what is due now, from this process, then give the lease back. When another
    process already delivers (its lease is live), do nothing and say who. Returns
    {"delivered_by": label | None, "attempts": n, "due_left": n}."""
    dd = Path(data_dir)
    existing = running_worker(dd)
    if existing is not None:
        # this process already runs a worker: run its cycles inline until done
        w, own = existing, False
    else:
        w, own = Worker(dd, label=label, produce_every=0.0), True
    attempts = 0
    end = time.monotonic() + deadline_seconds
    try:
        while time.monotonic() < end:
            if not w.take_lease():
                with S.opened(dd) as conn:
                    info = S.lease_info(conn)
                return {"delivered_by": info.label if info else None, "attempts": attempts, "due_left": due_now(dd)}
            stats = w.cycle(wait=True)
            attempts += stats["started"]
            if stats["started"] == 0 and stats["produced"] == 0:
                break
    finally:
        if own:
            w.stop(timeout=1)
    return {"delivered_by": label, "attempts": attempts, "due_left": due_now(dd)}


def due_now(data_dir: Path | str) -> int:
    with S.opened(data_dir) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM outbox WHERE status IN ('pending', 'failed') "
                                "AND next_attempt_at <= ?", (time.time(),)).fetchone()[0])


def start_background(data_dir: Path | str, *, label: str) -> Worker | None:
    """Start a delivery worker in this long-running process (idempotent). It delivers only
    while it holds the lease; otherwise it waits to take over."""
    existing = running_worker(data_dir)
    if existing is not None:
        return existing
    try:
        return Worker(data_dir, label=label).start()
    except Exception:  # noqa: BLE001 -- delivery must never stop the process starting
        logger.warning("outbox: could not start the delivery worker", exc_info=True)
        return None
