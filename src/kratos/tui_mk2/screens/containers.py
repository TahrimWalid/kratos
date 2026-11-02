"""`/containers`: the containers on the active machine, from its newest container read (D.5).

One row per container: name, image (short id), user, published ports with "reachable
despite firewall" marks, and its risky settings; stopped containers are greyed. Enter
shows what the engine reported (machine text cleaned; environment variables as names
only -- their values never leave the machine). `r` reads the machine again (through its
sub-agent when it has one). Nothing here changes a container. Navigation follows
tui_mk2/modals.py: Escape back.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.cli.containers_cmd import RISK_WORDS
from kratos.containers import record
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import InfoModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeTable as Table
from kratos.untrusted_rich import SafeText as Text

COLUMNS = ("container", "image", "user", "ports", "risks")


class ContainersScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("r", "refresh", "read again", show=True),
    ]

    CSS = """
    ContainersScreen { padding: 1 2; }
    ContainersScreen #ct-banner { height: auto; padding: 0 0 1 0; }
    ContainersScreen DataTable { height: auto; max-height: 65%; }
    ContainersScreen #ct-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    ContainersScreen #ct-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, target: str | None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._target = target
        self._doc: dict[str, Any] | None = None
        self._rows: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="ct-banner")
            yield DataTable(id="ct-table", cursor_type="row")
            yield VerticalScroll(id="ct-log")
            yield Static(Text("↑↓ select · enter details · r read the machine again · esc back", style=T.TEXT_DIM),
                         id="ct-hints")

    def on_mount(self) -> None:
        self._doc = record.load(self._data_dir, self._target) if self._target else None
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def note(self, renderable: Any) -> None:
        area = self.query_one("#ct-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    def refresh_rows(self) -> None:
        table = self.query_one("#ct-table", DataTable)
        doc = self._doc or {}
        self._rows = list(doc.get("rows") or [])
        table.clear(columns=True)
        table.add_columns(*COLUMNS)
        cells = []
        for r in self._rows:
            style = T.TEXT if r.get("running") else T.TEXT_MUTED
            risks = [RISK_WORDS.get(x, x) for x in r.get("risks") or []]
            ports = r.get("ports") or []
            name = str(r.get("name") or "") + ("" if r.get("running") else f" ({r.get('state') or 'stopped'})")
            cells.append([Text(name, style=style), Text(f"{r.get('image') or '?'} {r.get('digest') or ''}".strip(),
                                                        style=style),
                          Text(str(r.get("user") or "?"), style=style),
                          Text("; ".join(ports) or "-", style=T.ATTENTION if any("despite" in p for p in ports)
                               else style),
                          Text(", ".join(risks) or "-", style=T.CRITICAL if risks else style)])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(3, 30), (1, 20), (4, 24)], headers=COLUMNS)):
            table.add_row(*row, key=str(self._rows[i].get("id") or i))
        banner = Text()
        banner.append("Containers", style=f"bold {T.ACCENT}")
        if not self._target:
            banner.append("\nNo machine selected: set a target first.", style=T.TEXT_DIM)
        elif not doc:
            banner.append(f"   {self._target}", style=T.TEXT_DIM)
            banner.append("\nNo container read of this machine yet -- press r to read it now.", style=T.TEXT_DIM)
        else:
            banner.append(f"   {self._target} · read {doc.get('checked_at')} via {doc.get('via')}", style=T.TEXT_DIM)
            banner.append("\n" + record.summary_line(doc), style=T.TEXT_MUTED)
            for g in (doc.get("coverage_gaps") or [])[:4]:
                banner.append(f"\nnot checked: {g}", style=T.ATTENTION)
        self.query_one("#ct-banner", Static).update(banner)

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#ct-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    def action_details(self) -> None:
        r = self.selected()
        if r is None:
            return
        body = Table.grid(padding=(0, 2))
        body.add_column(style=T.TEXT_DIM)
        body.add_column()
        body.add_row("container", f"{r.get('name')} ({str(r.get('id') or '')[:12]}) — {r.get('state')}")
        body.add_row("engine", str(r.get("engine") or "?"))
        body.add_row("image", f"{r.get('image') or '?'} ({r.get('digest') or '-'})")
        body.add_row("user", str(r.get("user") or "?"))
        comp = r.get("compose") or {}
        if comp:
            body.add_row("compose", f"project {comp.get('project')}, service {comp.get('service')}"
                                    + (f"\n{comp.get('file')}" if comp.get("file") else ""))
        body.add_row("network", str(r.get("network_mode") or "-"))
        for i, p in enumerate(r.get("ports") or ["-"]):
            body.add_row("ports" if i == 0 else "", str(p))
        for i, m in enumerate(r.get("mounts") or []):
            body.add_row("mounts" if i == 0 else "", f"{m.get('source')} -> {m.get('destination')} "
                                                     f"({'writable' if m.get('rw') else 'read-only'})")
        if r.get("cap_add"):
            body.add_row("added capabilities", ", ".join(r["cap_add"]))
        body.add_row("log driver", str(r.get("log_driver") or "-"))
        body.add_row("risks", ", ".join(RISK_WORDS.get(x, x) for x in r.get("risks") or []) or "none found")
        if r.get("env_keys"):
            body.add_row("environment", ", ".join(r["env_keys"]) + "\n(names only -- values never leave the machine)")
        labels = [f"{k}={v}" if v else k for k, v in (r.get("labels") or {}).items()]
        if labels:
            body.add_row("labels", "\n".join(labels[:20]))
        self.app.push_screen(InfoModal(f"Container {r.get('name')}", body))

    def action_refresh(self) -> None:
        if not self._target:
            return
        self.note(Text(f"Reading the containers on {self._target}…", style=T.TEXT_DIM))
        self._read()

    @work(thread=True, exclusive=True)
    def _read(self) -> None:
        doc = record.run(self._data_dir, self._target)
        self.app.call_from_thread(self._done, doc)

    def _done(self, doc: dict[str, Any]) -> None:
        if doc.get("status") != "ok":
            self.note(Text(f"Could not read the containers: {doc.get('observation')}", style=T.CRITICAL))
            return
        self._doc = doc
        self.refresh_rows()
        self.note(Text("Read again.", style=T.TEXT_DIM))
