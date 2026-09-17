"""
Textual implementation of agent.guided_evolve.GuidedPrompter (A7).

The guided build (run_guided_build) runs on a Textual THREAD worker because it
ends in the blocking run_self_write_loop. Textual widgets may only be touched
from the event loop, so every prompt schedules its modal via
app.call_from_thread and blocks the worker thread on a threading.Event until the
modal is dismissed -- the exact same thread->modal bridge approvals.py already
uses for the approval gate (proven pattern; kept identical on purpose).

The in-loop KEEP approval is unaffected and unchanged: it still routes through
agent.tools.request_approval -> the globally-installed approval provider
(app.py) -> ApprovalModal. This prompter only supplies the PRE/POST guided
surface (idea/name/harness questions + status lines); it never touches the keep
gate or its no-force-accept semantics.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Literal

from rich.text import Text
from textual.app import App

from kratos.agent.guided_evolve import GuidedPrompter
from kratos.tui_mk2 import render as R
from kratos.tui_mk2.modals import ConfirmModal, ListPickerModal, PromptModal


class TextualGuidedPrompter(GuidedPrompter):
    """Drives run_guided_build's questions through mk2's modals and writes its
    status lines into the live transcript. Constructed on the event loop, used
    from the evolve thread worker."""

    def __init__(self, app: App, screen: Any) -> None:
        self._app = app
        self._screen = screen

    # --- output (into the transcript, thread-safe via the screen's helper) ---
    def _emit(self, renderable: Any) -> None:
        self._screen._emit_from_worker(renderable)

    def say(self, message: str, kind: Literal["note", "success", "error", "plain"] = "note") -> None:
        line = {
            "note": R.note_line,
            "success": R.success_line,
            "error": R.error_line,
        }.get(kind)
        self._emit(line(message) if line else Text(message))

    def show(self, renderable: Any) -> None:
        self._emit(Text(renderable) if isinstance(renderable, str) else renderable)

    # --- input (thread -> modal -> thread bridge) ---------------------------
    def _push_wait(self, factory: Callable[[], Any]) -> Any:
        done = threading.Event()
        box: dict[str, Any] = {"result": None}

        def _push() -> None:
            def _on_dismiss(result: Any) -> None:
                box["result"] = result
                done.set()

            self._app.push_screen(factory(), _on_dismiss)

        try:
            self._app.call_from_thread(_push)
        except Exception:  # noqa: BLE001 -- scheduling failed: fail safe (treat as cancelled)
            return None
        done.wait()
        return box["result"]

    def ask_text(self, title: str, hint: str = "", default: str = "") -> str | None:
        return self._push_wait(lambda: PromptModal(title, hint, initial=default))

    def ask_confirm(self, title: str, body: str = "") -> bool:
        # ConfirmModal is fail-safe by construction (only 'y' confirms); a
        # scheduling failure returns None -> bool(None) is False -> also safe.
        return bool(self._push_wait(lambda: ConfirmModal(title, body)))

    def ask_choice(self, title: str, options: list[tuple[str, str]], subtitle: str = "") -> str | None:
        return self._push_wait(lambda: ListPickerModal(title, options, subtitle))
