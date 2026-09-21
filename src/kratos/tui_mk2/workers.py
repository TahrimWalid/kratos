"""
Worker resilience for the mk2 TUI.

Textual re-raises an unhandled exception from a background worker (`@work`) as a
fatal `WorkerFailed` and tears the whole app down -- a single bug inside an
investigation, evolve run, or any threaded worker would drop the user out of the
TUI back to a bare shell, losing the session. That is never an acceptable
outcome for a long-running security console.

`ResilientWorkerHost` is a mixin for every node that STARTS workers (the app and
each screen). It forces `exit_on_error=False` on every worker so a raised
exception becomes a non-fatal `WorkerState.ERROR` instead of a crash. The app's
`on_worker_state_changed` (see app.py) then surfaces it as a friendly message.

This is deliberately a `run_worker` override rather than editing each of the ~50
`@work` decorators: the decorator ultimately calls `self.run_worker(...)`, so one
override per worker-hosting class covers every decorated method on it, and future
`@work` methods are covered automatically with nothing to remember.

The mixin also carries `on_worker_state_changed`, which surfaces a failed worker
as a friendly, non-crashing message and stops the event from bubbling (so the
same failure isn't reported twice as it travels screen -> app). Whichever node
owns the worker handles it: a SessionScreen emits into its live transcript; a
worker started on the app (or on a chrome screen with no transcript) falls back
to a toast.
"""
from __future__ import annotations

from typing import Any


class ResilientWorkerHost:
    """Mixin: make every worker this node starts non-fatal, and report a failure
    kindly instead of crashing.

    Must come BEFORE the Textual base (App/Screen) in the MRO so this
    `run_worker` shadows the framework's, e.g. ``class Foo(ResilientWorkerHost,
    Screen)``.
    """

    def run_worker(self, *args: Any, **kwargs: Any):  # type: ignore[override]
        # Force non-fatal regardless of what the @work decorator passed (its
        # default is exit_on_error=True). A worker that raises then resolves to
        # WorkerState.ERROR, caught below, instead of killing the TUI.
        kwargs["exit_on_error"] = False
        return super().run_worker(*args, **kwargs)  # type: ignore[misc]

    def on_worker_state_changed(self, event: Any) -> None:
        """Last-resort safety net for background workers.

        Because `run_worker` forces every worker non-fatal, a raised exception
        arrives here as WorkerState.ERROR rather than tearing the TUI down. This
        backs up the per-command dispatch guard (which wraps synchronous
        slash-command handlers): this one catches failures INSIDE async/threaded
        workers -- an investigation body, an evolve run, a modal-driving worker
        -- that a try/except around dispatch can never reach. The session, its
        stored history, and the store are all untouched by a worker crash.
        """
        from textual.worker import WorkerState

        if event.state is not WorkerState.ERROR:
            return
        # Handled here; don't let it bubble screen -> app and get reported twice.
        try:
            event.stop()
        except Exception:  # noqa: BLE001 -- stop() should never fail, but never throw from the net
            pass

        err = getattr(event.worker, "error", None)
        name = getattr(event.worker, "name", None) or "a background task"
        try:  # keep the raw error in the log for real diagnosis; never show a bare traceback
            self.log.error(f"worker {name!r} failed: {err!r}")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass

        friendly = (
            f"Something went wrong while running {name} ({type(err).__name__ if err else 'error'}). "
            "The session is fine — nothing was lost. If it keeps happening, /doctor can help."
        )
        # Prefer the live transcript when this node (or the current screen) has
        # one; otherwise a toast. `self` is a Screen with _emit, or the App whose
        # `.screen` is the current one.
        target = self if hasattr(self, "_emit") else getattr(self, "screen", None)
        emit = getattr(target, "_emit", None)
        set_busy = getattr(target, "_set_busy", None)
        surfaced = False
        if callable(emit):
            try:
                from kratos.tui_mk2 import render as R

                emit(R.error_line(friendly))
                surfaced = True
            except Exception:  # noqa: BLE001 -- never let the safety net itself throw
                surfaced = False
        if not surfaced:
            try:
                self.notify(friendly, severity="error", timeout=8)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
        # A worker that died mid-turn may have left the screen "busy" (spinner /
        # disabled input); clear it so the user isn't stuck.
        if callable(set_busy):
            try:
                set_busy(False)
            except Exception:  # noqa: BLE001
                pass
