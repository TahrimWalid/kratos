"""
Bridge between Kratos's approval gate (agent/tools.py::request_approval) and a
Textual modal.

request_approval is called synchronously from deep inside tool handlers, which
run on a background THREAD worker in the TUI (run_agent is blocking). A blocking
input() there can't drive a Textual modal, and Textual widgets can only be
touched from the app's own event loop. So the provider:

  1. schedules the modal push on the event loop via app.call_from_thread, and
  2. blocks the worker thread on a threading.Event until the modal is dismissed.

The fail-safe (any failure -> denial) and the central _approval_log recording
still live in request_approval itself (see agent/tools.py) -- this provider
only supplies the render+decide step, so it can never weaken the
no-force-accept invariant. If anything goes wrong scheduling/showing the modal,
it returns False (deny), never True.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

from textual.app import App

from kratos.tui_mk2.modals import ApprovalModal


def make_textual_approval_provider(app: App) -> Callable[[str, dict[str, Any]], bool]:
    """Returns a provider suitable for agent.tools.set_approval_prompt_provider.
    Safe to call from a thread worker."""

    def _provider(tool_name: str, details: dict[str, Any]) -> bool:
        done = threading.Event()
        box: dict[str, bool] = {"approved": False}

        def _push() -> None:
            def _on_dismiss(result: bool | None) -> None:
                box["approved"] = bool(result)
                done.set()

            app.push_screen(ApprovalModal(tool_name, details), _on_dismiss)

        try:
            app.call_from_thread(_push)
        except Exception:  # noqa: BLE001 -- scheduling failed: fail safe (deny)
            return False

        done.wait()
        return box["approved"]

    return _provider
