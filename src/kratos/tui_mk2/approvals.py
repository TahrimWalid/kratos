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

from kratos.tui_mk2.modals import ApprovalModal, ClarifyModal


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

            # Legibility: drop a "paused for approval" line into the transcript
            # so a mid-investigation approval reads as a deliberate pause, not a
            # modal out of nowhere. Only when the live screen is the conversation
            # (has _emit); harmless otherwise.
            emit = getattr(app.screen, "_emit", None)
            if callable(emit):
                from kratos.tui_mk2 import render as _R
                emit(_R.note_line(f"paused — approve '{tool_name}' to continue (answer the prompt)"))
            app.push_screen(ApprovalModal(tool_name, details), _on_dismiss)

        try:
            app.call_from_thread(_push)
        except Exception:  # noqa: BLE001 -- scheduling failed: fail safe (deny)
            return False

        done.wait()
        return box["approved"]

    return _provider


def make_textual_clarify_provider(app: App) -> Callable[[str, list[dict[str, Any]]], "str | None"]:
    """Returns a provider for agent.loop.set_clarify_provider. Same thread->modal
    bridge as the approval provider, but for a multiple-choice clarifying
    question (ClarifyModal) that AUTHORIZES NOTHING -- it only gathers the user's
    intent. Returns the chosen/typed answer, or None if dismissed or if
    scheduling fails; None is safe, the loop then proceeds with best judgment."""

    def _provider(question: str, options: list[dict[str, Any]]) -> "str | None":
        done = threading.Event()
        box: dict[str, Any] = {"answer": None}

        def _push() -> None:
            def _on_dismiss(result: "str | None") -> None:
                box["answer"] = result
                done.set()

            # Same legibility note as the approval provider above, and for the
            # same reason: a clarify can now fire more often (broadened intake/
            # scope triggers, docs/clarify_expansion.md lever 1) and a modal
            # appearing mid-investigation with no lead-in reads as a stall, not
            # a deliberate pause.
            emit = getattr(app.screen, "_emit", None)
            if callable(emit):
                from kratos.tui_mk2 import render as _R
                emit(_R.note_line("paused — Kratos has a clarifying question (answer the prompt)"))
            app.push_screen(ClarifyModal(question, options), _on_dismiss)

        try:
            app.call_from_thread(_push)
        except Exception:  # noqa: BLE001 -- scheduling failed: no answer (proceed)
            return None

        done.wait()
        return box["answer"]

    return _provider
