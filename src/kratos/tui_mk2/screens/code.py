"""`/code [machine]`: the code a machine serves (E.7a).

Candidates with why they were offered, and confirmed folders with their git state, drift,
dependencies and secrets. `c` confirms a candidate (Kratos reads it from now on), `i` ignores
one (it stays ignored until a person confirms it), `a` adds a folder by path, `s` accepts a
confirmed folder's current state (after a deploy, with no git), Enter shows the details and
the folder's files (changed first), `r` runs the code check now. Every decision is confirmed
and recorded with who made it. Kratos never runs anything in a folder: no git, no package
manager, no build. Navigation follows tui_mk2/modals.py: Escape back, `y` confirms.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.code import present as P
from kratos.code import roots as RT
from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import format_for_display, resolve_display_tz

STATUS_STYLE = {"confirmed": T.SAFE, "candidate": T.ATTENTION, "ignored": T.TEXT_DIM, "stale": T.TEXT_DIM}


CODE_ABOUT = ("Kratos reads a confirmed folder's files and git state; it never runs anything in a folder: no "
              "git, no package manager, no build. Every decision is confirmed and recorded with who made it.")


class CodeScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter details and files · c confirm a candidate · i ignore one\n"
                 "a add a folder by path · s accept a folder's current state · r check now · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter", "details", "details / files", show=True, priority=True),
        Binding("c", "confirm", "confirm", show=True),
        Binding("i", "ignore", "ignore", show=True),
        Binding("a", "add", "add a folder", show=True),
        Binding("s", "accept", "accept state", show=True),
        Binding("r", "run", "check now", show=True),
    ]

    # A2: title row, the folders (hidden when there are none), a detail pane, a log, a key bar.
    CSS = layout_css("CodeScreen", "code")

    def __init__(self, data_dir: Path, *, machine: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._machine = machine
        self._view: dict[str, Any] | None = None
        self._error = ""
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="code-banner")
            yield DataTable(id="code-table", cursor_type="row")
            yield Static(id="code-detail")
            yield VerticalScroll(id="code-log")
            yield Static(key_bar([("a", "add a folder"), ("r", "check now"), ("?", "all keys"), ("esc", "back")]),
                         id="code-hints")

    def on_mount(self) -> None:
        self.reload()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.render_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{CODE_ABOUT}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("Code — all keys", body))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        try:
            detail = self.query_one("#code-detail", Static)
            hints = self.query_one("#code-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        r = self.selected()
        if r is None:
            v = self._view
            words = (self._error or "Nothing to show.") if v is None else \
                "No code folders found yet. r runs a check; a adds a folder by path."
            detail.update(Text(words, style=T.TEXT_MUTED))
            hints.update(key_bar([("a", "add a folder"), ("r", "check now"), ("?", "all keys"), ("esc", "back")]))
            return
        out = Text()
        out.append(f"{r['status']:<10}", style=f"bold {STATUS_STYLE.get(r['status'], T.TEXT)}")
        out.append(r["path"], style=f"bold {T.TEXT_BRIGHT}")
        if r["status"] == "confirmed":
            g = r.get("git")
            state = (f"git {str((g or {}).get('commit') or '?')[:10]}" if g else
                     ("no git: compared with the accepted state" if r.get("no_git") else "not read yet"))
            out.append(f"\n{state} · {plural(r.get('files') or 0, 'file')}", style=T.TEXT_MUTED)
            found = ", ".join(f"{k} x{n}" for k, n in sorted(r["findings"].items()))
            out.append(f"\n{found or 'nothing found'}", style=T.ATTENTION if found else T.SAFE)
            if r["gone"]:
                out.append("\nThe folder is no longer there.", style=T.ATTENTION)
            keys = [("enter", "details"), ("s", "accept state"), ("r", "check now")]
        else:
            for why in (r["why"] or [])[:2]:
                out.append(f"\n{why}", style=T.TEXT_MUTED)
            keys = [("enter", "details"), ("c", "confirm"), ("i", "ignore")]
        detail.update(out)
        hints.update(key_bar(keys + [("?", "all keys"), ("esc", "back")]))

    def note(self, renderable: Any) -> None:
        area = self.query_one("#code-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    def reload(self) -> None:
        self._error = ""
        try:
            tk, _scope = P.resolve_code_reader(self._data_dir, Actor.current("tui"), self._machine)
            self._machine = tk
            self._view = P.view(self._data_dir, tk)
        except Exception as e:  # noqa: BLE001 -- shown, never a crash
            self._view, self._error = None, str(e)
        self.render_rows()

    def render_rows(self) -> None:
        table = self.query_one("#code-table", DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        v = self._view
        if v is None:
            self.query_one("#code-banner", Static).update(
                title_row("Code", note=self._error or "nothing to show", note_style=T.CRITICAL))
            table.display = False
            self._show_detail()
            return
        when = format_for_display(v["checked_at"], "%Y-%m-%d %H:%M", tz=self._tz) if v.get("checked_at") else ""
        confirmed = sum(1 for r in v["roots"] if r["status"] == "confirmed")
        candidates = sum(1 for r in v["roots"] if r["status"] == "candidate")
        summary = " · ".join(b for b in (plural(confirmed, "confirmed folder"),
                                         (plural(candidates, "candidate") if candidates else ""),
                                         (f"checked {when}" if when else "")) if b)
        self.query_one("#code-banner", Static).update(title_row("Code", v["machine"], summary))
        cells: list[list[Any]] = []
        for r in v["roots"]:
            if r["status"] == "confirmed":
                found = sum(r["findings"].values())
                detail = (f"{plural(found, 'finding')}" if found else "nothing found") + \
                    (" · gone" if r["gone"] else "")
            else:
                detail = (r["why"] or [""])[0]
            cells.append([Text(r["status"], style=STATUS_STYLE.get(r["status"], T.TEXT)), r["path"], detail])
        columns = ("", "folder", "what Kratos knows")
        table.add_columns(*columns)
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(1, 20), (2, 16)], headers=columns):
            table.add_row(*row)
        table.display = bool(v["roots"])         # no empty grid under "no code folders found yet"
        if v["roots"]:
            table.move_cursor(row=min(cursor or 0, len(v["roots"]) - 1))
        self._show_detail()

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#code-table", DataTable)
        roots = (self._view or {}).get("roots") or []
        if not roots or table.cursor_row is None:
            return None
        return roots[min(table.cursor_row, len(roots) - 1)]

    def action_details(self) -> None:
        r = self.selected()
        if r is None:
            return
        body = Text()
        body.append(f"{r['path']}  [{r['status']}]\n", style=T.TEXT)
        for w in r["why"]:
            body.append(f"why: {w}\n", style=T.TEXT_DIM)
        if r.get("decided_by"):
            body.append(f"{r['status']} by {r['decided_by']} at {r['decided_at']}\n", style=T.TEXT_DIM)
        if r["status"] == "confirmed":
            if r.get("git"):
                g = r["git"]
                body.append(f"git: {g.get('ref') or 'detached'} @ {g.get('commit') or '?'}\n")
                body.append("drift: " + (", ".join(f"{n} {k}" for k, n in sorted((g.get("counts") or {}).items()))
                                         or "none") + "\n")
            elif r.get("no_git"):
                body.append(f"no git: compared with the state accepted {r.get('accepted_at') or 'at the first read'}\n")
            body.append(f"{r.get('dependencies') or 0} dependencies ({', '.join(r['ecosystems']) or 'none'}), "
                        f"{r['vulnerable_dependencies']} vulnerable; {r['secrets']} secret(s) found\n")
            try:
                files = P.files(self._data_dir, self._machine, r["path"], limit=60)
            except P.ViewError:
                files = []
            if files:
                body.append("\nfiles (changed and untracked first):\n", style=T.ACCENT)
                for f in files:
                    body.append(f"  {f['git_status'] or '-':10} {f['relpath']}\n", style=T.TEXT_DIM)
        else:
            body.append("\nNot read until a person confirms it (c).", style=T.ATTENTION)
        self.app.push_screen(InfoModal("Code folder", body))

    @work(exclusive=True)
    async def _decide(self, fn, verb: str, warn: str) -> None:
        r = self.selected()
        if r is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(f"{verb.capitalize()} this folder?", f"{r['path']}\n{warn}"))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            fn(self._data_dir, self._machine, r["path"], actor=Actor.current("tui"))
        except RT.CodeRootError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text({"confirm": "Confirmed", "ignore": "Ignored", "accept": "Accepted"}[verb]
                       + " (recorded with your name).", style=T.SAFE))
        self.reload()

    def action_confirm(self) -> None:
        self._decide(RT.confirm, "confirm", "Kratos reads its files on every code check (contents are used in memory "
                                            "and never stored). Nothing is run there.")

    def action_ignore(self) -> None:
        self._decide(RT.ignore, "ignore", "Kratos stops checking it until you confirm it again.")

    def action_accept(self) -> None:
        self._decide(RT.accept_state, "accept", "Its current files become the state later changes are measured "
                                                "against (after a deploy, with no git).")

    @work(exclusive=True)
    async def action_add(self) -> None:
        path = await self.app.push_screen_wait(PromptModal("Folder on the machine (absolute path)", "/srv/app",
                                                           initial=""))
        if not path:
            return
        ok = await self.app.push_screen_wait(ConfirmModal("Add and confirm this folder?", path))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            RT.add(self._data_dir, self._machine, path.strip(), actor=Actor.current("tui"))
        except RT.CodeRootError as e:
            self.note(Text(f"Not added: {e}", style=T.CRITICAL))
            return
        self.note(Text("Added and confirmed; the next check reads it (r).", style=T.SAFE))
        self.reload()

    def action_run(self) -> None:
        self.note(Text("Checking the code folders…", style=T.TEXT_DIM))
        self._run()

    @work(thread=True, exclusive=True)
    def _run(self) -> None:
        from kratos.collect import runner
        from kratos.kratos_config import pinned_target
        from kratos.run_context import run_scope

        try:
            with run_scope("interactive", target=self._machine), pinned_target(self._machine):
                rep = runner.prepare(self._machine, self._data_dir, classes=("quick", "slow"), force=True,
                                     only=("code_roots", "code"))
            line = "; ".join(f"{o.label}: {o.summary}" for o in rep.checks) or "nothing ran"
        except Exception as e:  # noqa: BLE001
            line = f"not run ({type(e).__name__}: {e})"
        self.app.call_from_thread(self._after_run, line)

    def _after_run(self, line: str) -> None:
        self.note(Text(line, style=T.TEXT))
        self.reload()
