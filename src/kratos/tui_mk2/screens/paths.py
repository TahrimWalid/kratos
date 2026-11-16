"""`/paths [group]` (E.1): the attack paths across a group of machines.

Four blocks -- entry points (ranked), paths to the machines that matter (each hop with its
evidence and an observed/assumed tag; out-of-scope hops masked), the one fix that cuts the
most paths (shown, never run), and what Kratos could not see as numbers. `r` builds or
rebuilds (a read-free synthesis over stored evidence -- no model, no machine read); `escape`
goes back. Nothing here runs a fix or reads a machine.

The stored build is loaded (``read_scoped``) and rebuilt (``run_path_build``) on a Textual
thread worker -- those touch the database and the permission check, and running them on the
event loop during ``on_mount`` leaves the screen unmounted. Navigation follows
tui_mk2/modals.py (Escape back).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen

from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.safe_widgets import SafeStatic as Static
from kratos.untrusted_rich import SafeText as Text


class PathsScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("r", "build", "build / rebuild", show=True),
    ]

    CSS = """
    PathsScreen { padding: 1 2; }
    PathsScreen #pa-banner { height: auto; padding: 0 0 1 0; }
    PathsScreen #pa-body { height: 1fr; }
    PathsScreen #pa-content { height: auto; }
    PathsScreen #pa-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, group: str = "all") -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._group = (group or "all").lstrip("@") or "all"
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Static(Text(""), id="pa-banner")
        yield VerticalScroll(Static(Text(""), id="pa-content"), id="pa-body")
        yield Static(Text("r build / rebuild · escape back", style=T.TEXT_DIM), id="pa-hints")

    def on_mount(self) -> None:
        self._banner()
        self._load()

    def _actor(self) -> Actor:
        return Actor.current("tui")

    def _banner(self) -> None:
        self.query_one("#pa-banner", Static).update(
            Text(f"Attack paths for @{self._group}" + ("  (building…)" if self._busy else ""), style=T.TEXT_BRIGHT))

    @work(thread=True, exclusive=True)
    def _load(self) -> None:
        """Read the newest stored build (scoped) off the event loop; render on it."""
        from kratos.attackpaths import build as PB

        doc: Any = None
        err = ""
        try:
            doc, _visible = PB.read_scoped(self._data_dir, self._actor(), self._group)
        except PB.PathBuildError as e:
            err = str(e)
        except Exception as e:  # noqa: BLE001 -- a read failure is shown, never a crash
            err = f"couldn't read the build: {e}"
        self.app.call_from_thread(self._show, doc, err)

    def _show(self, doc: Any, err: str) -> None:
        from kratos.attackpaths import present as PP

        content = self.query_one("#pa-content", Static)
        if err:
            content.update(Text(err, style=T.CRITICAL))
            return
        if doc is None:
            content.update(Text("No attack-path build yet. Press r to build it (read-free: no model, no machine "
                                "read). This is coverage, not a clean bill of health.", style=T.ATTENTION))
            return
        text = "\n".join(PP.render_build(doc, doc.get("group") or self._group))
        content.update(Text(text, style=T.TEXT))

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_build(self) -> None:
        if self._busy:
            return
        self._busy = True
        self._banner()
        self.query_one("#pa-content", Static).update(Text("Building… (read-free synthesis over stored evidence)",
                                                          style=T.TEXT_DIM))
        self._do_build()

    @work(thread=True, exclusive=True)
    def _do_build(self) -> None:
        from kratos.attackpaths import build as PB

        err = ""
        try:
            PB.run_path_build(data_dir=self._data_dir, group=self._group, actor=self._actor(), source="interactive")
        except PB.PathBuildError as e:
            err = str(e)
        except Exception as e:  # noqa: BLE001 -- a build failure is shown, never a crash
            err = f"build failed: {e}"
        self.app.call_from_thread(self._after_build, err)

    def _after_build(self, err: str) -> None:
        self._busy = False
        self._banner()
        if err:
            self.query_one("#pa-content", Static).update(Text(err, style=T.CRITICAL))
        else:
            self._load()
