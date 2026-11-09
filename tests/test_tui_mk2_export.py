"""D.6: /export in the TUI -- the questions, the estimate, a person's yes, then a bundle
that verifies and the two OpenSSH/coreutils commands in a copy-safe box."""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.app import App

import _export_fixture as FX
from kratos.export import verify as V
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, ListPickerModal
from kratos.tui_mk2.screens.session import SessionScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _setup(tmp_path, monkeypatch):
    d = tmp_path / "data"
    FX.build(d)
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: FX.M1)
    store = SessionStore(d / "kratos.db")
    sid = store.create_session([FX.M1], "m")
    screen = SessionScreen(store, d, sid, [FX.M1], "")
    shown: list[str] = []
    for name in ("_emit", "_emit_from_worker"):
        orig = getattr(screen, name)

        def capture(renderable, _orig=orig):
            shown.append(getattr(renderable, "plain", str(renderable)))
            return _orig(renderable)
        monkeypatch.setattr(screen, name, capture)

    def no_model(*_a, **_k):
        raise AssertionError("an export without a summary must not call the model")
    monkeypatch.setattr("kratos.llm_interface.agent_chat", no_model)
    return d, screen, shown


def _run(screen, shown, answers, pushed):
    async def go():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def scripted(modal):
                pushed.append(modal)
                return answers.pop(0) if answers else None

            app.push_screen_wait = scripted  # type: ignore[method-assign]
            orig_push = app.push_screen

            def push(s, *a, **k):
                pushed.append(s)
                if isinstance(s, CommandModal):
                    return None
                return orig_push(s, *a, **k)
            app.push_screen = push  # type: ignore[method-assign]
            screen._dispatch_slash("/export")
            for _ in range(600):
                await pilot.pause()
                if any(("Bundle:" in s or "Not exported" in s or "/export failed" in s) for s in shown) and not screen._busy:
                    break
            for _ in range(20):
                await pilot.pause()
    asyncio.run(go())


def test_export_makes_a_verifiable_bundle_and_shows_the_commands(tmp_path, monkeypatch):
    d, screen, shown = _setup(tmp_path, monkeypatch)
    pushed: list = []
    answers = [("machines", [FX.M1]), "3d", "full", False, True]
    _run(screen, shown, answers, pushed)
    text = "\n".join(shown)
    assert "Bundle:" in text, text[-2000:]
    bundle = Path(next(s for s in shown if s.startswith("Bundle:")).split("Bundle: ", 1)[1])
    assert V.verify(bundle, data_dir=d).ok
    kinds = [type(m) for m in pushed]
    assert kinds[:3] == [ListPickerModal, ListPickerModal, ListPickerModal] and ConfirmModal in kinds
    box = next(m for m in pushed if isinstance(m, CommandModal))
    assert "ssh-keygen -Y verify" in box._command and "sha256sum -c SHA256SUMS" in box._command
    confirm = [m for m in pushed if isinstance(m, ConfirmModal)][-1]
    assert "evidence files" in str(confirm._body)


def test_export_cancelled_at_the_last_question_writes_nothing(tmp_path, monkeypatch):
    d, screen, shown = _setup(tmp_path, monkeypatch)
    _run(screen, shown, [("machines", [FX.M1]), "7d", "redacted", False, False], [])
    assert any("Not exported" in s for s in shown)
    assert not (d / "exports").exists() or not any((d / "exports").iterdir())
