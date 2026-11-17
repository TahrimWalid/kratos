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
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import InfoModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeTable as Table
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import format_for_display, resolve_display_tz

COLUMNS = ("container", "image", "ports", "risks")   # user, digest and every port: the detail pane


class ContainersScreen(Screen):
    _ALL_KEYS = "↑↓ select · enter details · r read the machine again · esc back"
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("r", "refresh", "read again", show=True),
    ]

    # A2: title row, the table, a detail pane with the selected container's full ports and
    # risks (the columns are cut at 80), a short log and a key bar.
    CSS = layout_css("ContainersScreen", "ct")

    def __init__(self, data_dir: Path, *, target: str | None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._target = target
        self._doc: dict[str, Any] | None = None
        self._rows: list[dict[str, Any]] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="ct-banner")
            yield DataTable(id="ct-table", cursor_type="row")
            yield Static(id="ct-detail")
            yield VerticalScroll(id="ct-log")
            yield Static(key_bar([("r", "read again"), ("?", "all keys"), ("esc", "back")]), id="ct-hints")

    def on_mount(self) -> None:
        self._doc = record.load(self._data_dir, self._target) if self._target else None
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        doc = self._doc or {}
        if doc:
            body.append(f"\n\n{record.summary_line(doc)}", style=T.TEXT_MUTED)
            body.append(f"\nread {self._when(doc.get('checked_at'))} via {doc.get('via')}", style=T.TEXT_DIM)
            for g in doc.get("coverage_gaps") or []:
                body.append(f"\nnot checked: {g}", style=T.ATTENTION)
        body.append("\n\nNothing here changes a container. Environment variables are shown as names only.",
                    style=T.TEXT_DIM)
        self.app.push_screen(InfoModal("Containers — all keys", body))

    def _when(self, value: Any) -> str:
        return format_for_display(value, "%Y-%m-%d %H:%M", tz=self._tz) if value else "-"

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
            cells.append([Text(name, style=style), Text(str(r.get("image") or "?"), style=style),
                          Text("; ".join(ports) or "-", style=T.ATTENTION if any("despite" in p for p in ports)
                               else style),
                          Text(", ".join(risks) or "-", style=T.CRITICAL if risks else style)])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(2, 12), (1, 12), (3, 12), (0, 10)], headers=COLUMNS)):
            table.add_row(*row, key=str(self._rows[i].get("id") or i))
        if not self._target:
            banner = title_row("Containers", note="no machine selected -- set a target first", note_style=T.TEXT_DIM)
        elif not doc:
            banner = title_row("Containers", self._target, "no container read yet -- r reads it now")
        else:
            running = int((doc.get("counts") or {}).get("running") or 0)
            gaps = doc.get("coverage_gaps") or []
            banner = title_row("Containers", self._target,
                               f"{plural(running, 'running container')} · read {self._when(doc.get('checked_at'))}",
                               note=f"{plural(len(gaps), 'gap')} (?)" if gaps else "")
        self.query_one("#ct-banner", Static).update(banner)
        self._show_detail()

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        """The selected container in full: image, user, every port and every risk (A2)."""
        try:
            detail = self.query_one("#ct-detail", Static)
            hints = self.query_one("#ct-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        r = self.selected()
        out = Text()
        if r is None:
            doc = self._doc or {}
            out.append(record.summary_line(doc) if doc else "Press r to read this machine's containers.",
                       style=T.TEXT_MUTED)
            detail.update(out)
            hints.update(key_bar([("r", "read again"), ("?", "all keys"), ("esc", "back")]))
            return
        out.append(str(r.get("name") or "?"), style=f"bold {T.TEXT_BRIGHT}")
        out.append(f"   {r.get('state') or ('running' if r.get('running') else 'stopped')}",
                   style=T.TEXT if r.get("running") else T.TEXT_MUTED)
        out.append(f"\n{r.get('image') or '?'} {r.get('digest') or ''}".rstrip(), style=T.DATA)
        out.append(f" · user {r.get('user') or '?'}", style=T.TEXT_MUTED)
        ports = r.get("ports") or []
        if ports:
            out.append("\nports: " + "; ".join(ports),
                       style=T.ATTENTION if any("despite" in x for x in ports) else T.TEXT)
        risks = [RISK_WORDS.get(x, x) for x in r.get("risks") or []]
        out.append("\nrisks: " + (", ".join(risks) if risks else "none found"), style=T.CRITICAL if risks else T.SAFE)
        detail.update(out)
        hints.update(key_bar([("enter", "details"), ("r", "read again"), ("?", "all keys"), ("esc", "back")]))

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
