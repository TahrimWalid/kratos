"""
kratos-mk2 entry point -- the Textual App and its `main()`.

Boot flow:
  1. install the Textual approval provider (agent/tools.py::request_approval
     then renders as a modal instead of blocking on input()),
  2. first-run trust + optional default target (mirrors cli/repl.py's wizard,
     gated on the same `trusted` flag in kratos_local_config.json), then
  3. the launch/session chooser (LaunchScreen).

Nothing here touches the classic `kratos` REPL. Promotion later = point the
`kratos` console-script at this main() and drop the kratos-mk2 line in
pyproject.toml.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from rich.align import Align
from rich.text import Text
from textual.app import App, ComposeResult
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import Static

from kratos.agent import console as _console
from kratos.agent.tools import set_approval_prompt_provider
from kratos.agent.self_write_loop import load_kept_tools
from kratos import kratos_config as _kconfig
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.approvals import make_textual_approval_provider
from kratos.tui_mk2.modals import ConfirmModal, PromptModal
from kratos.tui_mk2.screens.launch import LaunchScreen

# --- Mouse: clicks + scroll, but NOT motion --------------------------------
# Textual's LinuxDriver enables ?1003h (SET_ANY_EVENT_MOUSE), which makes the
# terminal emit an escape sequence on every mouse *move*. Over SSH (esp. into
# Windows Terminal) that motion stream is heavy and fragmentation-prone, and it
# is the root cause of three real symptoms: a flood of `\x1b[<..M` bytes, stray
# bytes occasionally leaking through as key presses (a lone leaked `[` used to
# cycle the /settings tabs -- "ghost" tab switching), and the same codes getting
# dumped to the shell if the app exits without cleanly disabling the mode.
#
# Dropping *only* ?1003h keeps click-to-select and scroll-wheel (both reported by
# ?1000h) while eliminating the move-driven flood entirely. The only thing lost
# is mouse-hover highlighting and drag, neither of which Kratos relies on. This
# is preferred over disabling the mouse outright (App.run(mouse=False)) so the
# pointer still works for users who want it. ?1003l is still sent on exit by the
# unmodified _disable_mouse_support (harmless: turning off an unset mode).
try:  # LinuxDriver imports termios/tty -- guard so app.py imports on any platform
    from textual.drivers.linux_driver import LinuxDriver as _LinuxDriver

    class _ClickOnlyLinuxDriver(_LinuxDriver):
        """LinuxDriver that reports mouse clicks + scroll but not motion."""

        def _enable_mouse_support(self) -> None:
            if not self._mouse:
                return
            write = self.write
            write("\x1b[?1000h")  # button press/release + wheel (SET_VT200_MOUSE)
            write("\x1b[?1015h")  # urxvt ext coords (harmless; SGR preferred below)
            write("\x1b[?1006h")  # SGR extended coords (SET_SGR_EXT_MODE_MOUSE)
            # Deliberately NOT ?1003h (SET_ANY_EVENT_MOUSE) -- see module note above.
            self.flush()
except Exception:  # pragma: no cover -- non-Linux; auto-detect keeps the default
    _LinuxDriver = None
    _ClickOnlyLinuxDriver = None


class TooSmallScreen(Screen):
    """Turn 14c -- a hard blocking screen when the terminal is too small for the
    fixed-column layouts, rather than letting them overlap. Shown/hidden by the
    app's on_resize; the app never dismisses it while still too small."""

    CSS = f"""
    TooSmallScreen {{ align: center middle; background: {T.BG}; }}
    TooSmallScreen Static {{ width: auto; color: {T.ATTENTION}; }}
    """

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        yield Static(Align.center(Text(self._message)))


class KratosTUI(App):
    CSS = T.APP_CSS
    TITLE = "kratos"
    # Disable Textual's built-in ctrl+p palette so our own command palette
    # (CommandPaletteModal, design turn 7a) owns that trigger instead.
    ENABLE_COMMAND_PALETTE = False

    # Kept deliberately low so Kratos is usable in a split/half-screen pane on a
    # small laptop (a 13" display split in two is ~60-71 cols) -- the transcript
    # wraps and modals cap at 90% width, so the layout stays legible well below
    # the old 72x18 floor. This is the point below which fixed chrome (header/
    # footer, tables) genuinely can't render, not a comfort preference.
    MIN_WIDTH = 56
    MIN_HEIGHT = 16

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self.data_dir = data_dir
        self.store = SessionStore(data_dir / "kratos.db")
        self._too_small_active = False
        self._booted = False  # gate the resize guard until boot pushed a real screen

    def on_resize(self, event: Resize) -> None:
        # Ignore resizes until boot has pushed the first real screen -- otherwise
        # an early startup resize pushes the block, then the boot flow's own
        # push_screen(LaunchScreen) lands on top of it (a real race, caught in
        # testing). After boot, this handler owns the block/unblock transitions.
        if self._booted:
            self._apply_size_guard(event.size.width, event.size.height)

    def _apply_size_guard(self, width: int, height: int) -> None:
        too_small = width < self.MIN_WIDTH or height < self.MIN_HEIGHT
        if too_small and not self._too_small_active:
            self._too_small_active = True
            self.push_screen(
                TooSmallScreen(
                    f"Terminal too small\n\nResize to at least {self.MIN_WIDTH}×{self.MIN_HEIGHT} "
                    f"(now {width}×{height})."
                )
            )
        elif not too_small and self._too_small_active:
            self._too_small_active = False
            if isinstance(self.screen, TooSmallScreen):
                self.pop_screen()

    def get_driver_class(self):
        # Substitute the click+scroll-only driver ONLY when the platform driver
        # is the real LinuxDriver -- leave Windows/headless/env-forced drivers
        # untouched so tests (headless) and other platforms are unaffected.
        base = super().get_driver_class()
        if _ClickOnlyLinuxDriver is not None and base is _LinuxDriver:
            return _ClickOnlyLinuxDriver
        return base

    def model_label(self) -> str:
        from kratos.llm_config import get_active_llm_model

        return get_active_llm_model()

    def on_mount(self) -> None:
        # Register + apply a Kratos theme so Textual's own default-themed widgets
        # (Tabs/Buttons/Select/Input focus borders used by the /settings screen)
        # pull the mk2 canvas palette instead of Textual's stock blue -- one
        # source of truth for widget colors, matching the hand-styled screens.
        self._install_theme()
        # Route every approval gate (run_linux_command, capture_traffic,
        # self-write keep, threat-intel, vulscan staleness) to a Textual modal.
        set_approval_prompt_provider(make_textual_approval_provider(self))
        self._boot()

    def _install_theme(self) -> None:
        # Register ONE Textual theme per pack (named by the pack) so switching
        # packs is just `self.theme = <pack>` -- a real reactive change that
        # live-updates Textual's own widget chrome (tab underline, focus/select,
        # buttons). The active pack's identity accent drives primary/accent.
        from textual.theme import Theme

        for name, pack in T.PACKS.items():
            accent = pack["ACCENT"]
            self.register_theme(
                Theme(
                    name=name,
                    primary=accent,        # active tab underline, focus, primary buttons
                    secondary=pack["ADMIN"],
                    accent=accent,
                    foreground=T.TEXT,
                    background=T.BG,
                    surface=T.PANEL_BG,
                    panel=T.TITLEBAR_BG,
                    success=T.SAFE,
                    warning=T.ATTENTION,
                    error=T.CRITICAL,      # CRITICAL is constant across packs (danger red)
                    dark=True,
                )
            )
        self.theme = T.active_pack_name()

    def apply_theme_pack(self, name: str) -> bool:
        """Switch theme packs live (from the Settings General tab): re-bind the
        palette globals, flip the Textual theme (updates widget chrome instantly),
        and ask the current screen to re-render its dynamic content. A full
        repaint of scrolled-back transcript lines happens on next launch (the
        persisted choice is read at import). Returns False for an unknown pack."""
        if not T.set_active_pack(name):
            return False
        self.theme = name  # a distinct value -> Textual reactive fires -> live chrome
        hook = getattr(self.screen, "refresh_theme", None)
        if callable(hook):
            hook()
        return True

    def on_unmount(self) -> None:
        set_approval_prompt_provider(None)

    def _boot(self) -> None:
        # Textual runs this as a worker so push_screen_wait can be awaited.
        self.run_worker(self._boot_flow(), exclusive=True)

    async def _boot_flow(self) -> None:
        config = _kconfig.load_local_config(self.data_dir)
        if not config.get("trusted"):
            trusted = await self.push_screen_wait(
                ConfirmModal(
                    "Kratos — first run",
                    "Do you trust the files in this folder?\n\n"
                    "Kratos may read, write, or execute files in this directory.",
                )
            )
            if not trusted:
                self.exit()
                return
            _kconfig.save_local_config(self.data_dir, trusted=True)
            target = await self.push_screen_wait(
                PromptModal(
                    "Default target (optional)",
                    f"IP/hostname for investigations (currently {_kconfig.SSH_TARGET_HOST}) — Enter to skip",
                )
            )
            if target:
                _kconfig.save_local_config(self.data_dir, default_target=target)
                _kconfig.set_active_target(target)
        else:
            persisted = config.get("default_target")
            if persisted:
                _kconfig.set_active_target(persisted)

        self.push_screen(LaunchScreen(self.store, self.data_dir))
        # Now that a real screen exists, enable the resize guard and apply it
        # once for the current size (covers launching into an already-small
        # terminal, which the pre-boot on_resize deliberately skipped).
        self._booted = True
        self._apply_size_guard(self.size.width, self.size.height)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(prog="kratos-mk2", description="Kratos Textual TUI (preview).")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    no_color = args.no_color or bool(os.environ.get("NO_COLOR"))
    _console.configure(no_color)
    args.data_dir.mkdir(parents=True, exist_ok=True)

    # Layer previously-kept self-written tools on top of the built-ins, exactly
    # as cli/app.py::main does for every classic entry point.
    load_kept_tools()

    KratosTUI(args.data_dir).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
