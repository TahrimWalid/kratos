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

from textual.app import App

from kratos.agent import console as _console
from kratos.agent.tools import set_approval_prompt_provider
from kratos.agent.self_write_loop import load_kept_tools
from kratos import kratos_config as _kconfig
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.approvals import make_textual_approval_provider
from kratos.tui_mk2.modals import ConfirmModal, PromptModal
from kratos.tui_mk2.screens.launch import LaunchScreen


class KratosTUI(App):
    CSS = T.APP_CSS
    TITLE = "kratos"
    # Disable Textual's built-in ctrl+p palette so our own command palette
    # (CommandPaletteModal, design turn 7a) owns that trigger instead.
    ENABLE_COMMAND_PALETTE = False

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self.data_dir = data_dir
        self.store = SessionStore(data_dir / "kratos.db")

    def model_label(self) -> str:
        from kratos.llm_config import get_active_llm_model

        return get_active_llm_model()

    def on_mount(self) -> None:
        # Route every approval gate (run_linux_command, capture_traffic,
        # self-write keep, threat-intel, vulscan staleness) to a Textual modal.
        set_approval_prompt_provider(make_textual_approval_provider(self))
        self._boot()

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
