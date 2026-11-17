"""`/compliance`: how a machine (or a group) stands against CIS, ISO 27001 and NIS2 (E.2).

Every control shows one of six statuses, from Kratos's own checks over facts it read --
a pass only with fresh, complete proof; organisational controls "need a person". Enter
shows a control's checks with what was found, when it was read, and the fix (a command
a person runs; Kratos never runs it). `o` sets an owner, `n` marks a control not
applicable (with a reason and an expiry), `l` the CIS level, `r` reads the machine again.
Decisions are confirmed and recorded with who made them. Navigation follows
tui_mk2/modals.py: Escape back, `y` confirms.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.compliance import frameworks as F
from kratos.compliance import owners as O
from kratos.compliance import report as RP
from kratos.compliance import status as ST
from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import format_for_display, resolve_display_tz

STYLE = {"pass": T.SAFE, "fail": T.CRITICAL, "partial": T.ATTENTION, "not_checked": T.TEXT_DIM,
         "needs_person": T.TEXT_MUTED, "not_applicable": T.TEXT_DIM}
FW_WORDS = {"cis": "CIS", "iso27001": "ISO 27001", "nis2": "NIS2"}
# Worst first, as /findings does; control order is kept within each status (a stable sort).
STATUS_ORDER = {"fail": 0, "partial": 1, "needs_person": 2, "pass": 3, "not_checked": 4, "not_applicable": 5}
CHECK_ORDER = {"fail": 0, "partial": 1, "unknown": 2, "pass": 3, "na": 4}
CHECK_STYLE = {"pass": T.SAFE, "fail": T.CRITICAL, "partial": T.ATTENTION, "unknown": T.TEXT_DIM, "na": T.TEXT_DIM}
# The shared reason text names the CLI; on this screen `r` reads the machine again.
_CLI_READ = re.compile(r"run a check of the machine \(`kratos collect [^`]*`\)|\(run `kratos collect [^`]*`\)")


def _screen_words(text: str) -> str:
    def say(m: re.Match) -> str:
        return "(press r to read it again)" if m.group(0).startswith("(") else "press r to read the machine again"
    return _CLI_READ.sub(say, text or "")


def worst_first(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda r: STATUS_ORDER.get(r.get("status"), 9))


class ComplianceScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter evidence · o owner · n not applicable · l CIS level\n"
                 "f framework · a show controls Kratos has no check for\nr read again · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("f", "framework", "framework", show=True),
        Binding("o", "owner", "owner", show=True),
        Binding("n", "na", "not applicable", show=True),
        Binding("l", "level", "CIS level", show=True),
        Binding("a", "toggle_all", "all rows", show=True),
        Binding("r", "refresh", "read again", show=True),
    ]

    # A2: one title row, the table (worst first), a detail pane for the selected control,
    # a short log and a key bar. The disclaimer and read details live in the pane and behind ?.
    CSS = layout_css("ComplianceScreen", "co")

    def __init__(self, data_dir: Path, *, machine: str | None = None, group: str | None = None,
                 framework: str = "cis") -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._machine = machine
        self._group = group
        self._fw = framework if framework in F.FRAMEWORKS else "cis"
        self._all = False
        self._doc: dict[str, Any] | None = None
        self._rows: list[dict[str, Any]] = []
        self._error = ""
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="co-banner")
            yield DataTable(id="co-table", cursor_type="row")
            yield Static(id="co-detail")
            yield VerticalScroll(id="co-log")
            yield Static(key_bar([("enter", "evidence"), ("?", "all keys"), ("esc", "back")]), id="co-hints")

    def on_mount(self) -> None:
        self.reload()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.render_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{self._disclaimer()}", style=T.TEXT_DIM)
        single = self._single()
        if single is not None and single.get("status") == "read":
            body.append(f"\n\n{single.get('summary')}\n{self._read_line(single)}", style=T.TEXT_DIM)
        self.app.push_screen(InfoModal("Compliance — all keys", body))

    def _when(self, value: Any) -> str:
        return format_for_display(value, "%Y-%m-%d %H:%M", tz=self._tz) if value else "-"

    def _read_line(self, single: dict[str, Any]) -> str:
        bits = [f"read {self._when(single.get('read_at'))} via {single.get('via')}"]
        if single.get("product_note"):
            bits.append(single["product_note"])
        return " · ".join(bits)

    def _disclaimer(self) -> str:
        text = F.NOT_A_CERTIFICATION
        return text if self._single() is not None else text.replace("on this machine", "on each machine")

    def note(self, renderable: Any) -> None:
        area = self.query_one("#co-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    # -- data --------------------------------------------------------------
    def reload(self) -> None:
        self._error = ""
        try:
            machines, outside, label = RP.resolve_machines(self._data_dir, Actor.current("tui"),
                                                           machine=self._machine, group=self._group)
            self._doc = RP.build(self._data_dir, self._fw, machines, outside_scope=outside, label=label)
        except Exception as e:  # noqa: BLE001 -- shown, never a crash
            self._doc, self._error = None, str(e)
        self.render_rows()

    def _single(self) -> dict[str, Any] | None:
        if self._doc and len(self._doc["machines"]) == 1:
            return self._doc["machines"][0]
        return None

    def render_rows(self) -> None:
        table = self.query_one("#co-table", DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        self._rows = []
        self._product = ""
        fw = FW_WORDS[self._fw]
        if self._doc is None:
            self.query_one("#co-banner", Static).update(
                title_row(f"Compliance — {fw}", note=self._error or "nothing to show", note_style=T.CRITICAL))
            self._show_detail()
            return
        single = self._single()
        if single is not None:
            columns = ("control", "status", "what Kratos looks at", "owner")
            controls = single.get("controls") or []
            rows = [c for c in controls if self._all or c["status"] != "not_checked" or c.get("checks")]
            self._hidden = len(controls) - len(rows)
            self._rows = worst_first(rows)
            cells = [[c["control"], Text(ST.STATUS_WORDS[c["status"]], style=STYLE[c["status"]]), c.get("text", ""),
                      c.get("owner") or "-"] for c in self._rows]
            if single.get("status") != "read":
                banner = title_row(f"Compliance — {fw}", single["machine"], note="not checked yet")
            else:
                level = str(single.get("level") or "")[:2].upper()     # "l1_server" -> "L1"
                product = f"{single.get('product')} {level}".strip() if self._fw == "cis" else ""
                banner = title_row(f"Compliance — {fw}", single["machine"],
                                   " · ".join(b for b in (self._counts_words(self._count(controls)), product) if b))
        else:
            n = len(self._doc["machines"])
            columns = ("control", "status", "what Kratos looks at", "machines")
            rollup = [r for r in self._doc.get("rollup") or [] if self._all or r["status"] != "not_checked"]
            self._hidden = len(self._doc.get("rollup") or []) - len(rollup)
            self._rows = worst_first(rollup)
            products = {r.get("product") or "" for r in self._rows}
            one_product = len(products) == 1          # the profile goes in the title once, not on every row
            self._product = next(iter(products)) if one_product else ""
            cells = [[("" if one_product or not r.get("product") else f"{r['product']} ") + r["control"],
                      Text(ST.STATUS_WORDS[r["status"]], style=STYLE[r["status"]]), r.get("text", ""),
                      ", ".join(f"{ST.STATUS_WORDS[k]} {v}" for k, v in r["counts"].items() if v)]
                     for r in self._rows]
            summary = plural(n, "machine") + (f" · {self._product}" if self._product else "")
            outside = self._doc.get("outside_scope")
            banner = title_row(f"Compliance — {fw}", self._doc["scope"], summary,
                               note=f"{outside} outside your access (not shown)" if outside else "")
        self.query_one("#co-banner", Static).update(banner)
        table.add_columns(*columns)
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(2, 20), (3, 10)], headers=columns):
            table.add_row(*row)
        if self._rows:
            table.move_cursor(row=min(cursor or 0, len(self._rows) - 1))
        self._show_detail()

    @staticmethod
    def _count(controls: list[dict[str, Any]]) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in controls:
            out[c["status"]] = out.get(c["status"], 0) + 1
        return out

    @staticmethod
    def _counts_words(counts: dict[str, int]) -> str:
        words = []
        for status in ("fail", "partial", "pass"):          # "needs a person" is in the table and ?
            n = counts.get(status, 0)
            if n:
                words.append(f"{n} " + ("need a person" if status == "needs_person" and n != 1 else
                                        "needs a person" if status == "needs_person" else ST.STATUS_WORDS[status]))
        return " · ".join(words)

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        """The selected control in words: its status and, for a failure, the check that
        failed and what was found -- plus the keys that apply to it (A2)."""
        try:
            detail = self.query_one("#co-detail", Static)
            hints = self.query_one("#co-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        c = self.selected()
        out = Text()
        if c is None:
            single = self._single()
            if self._doc is None:
                out.append("Nothing to show.", style=T.TEXT_MUTED)
            elif single is not None and single.get("status") != "read":
                out.append(f"Not checked: {_screen_words(single.get('reason') or '')}", style=T.ATTENTION)
            else:
                out.append("No controls to show. a shows the ones Kratos has no check for.", style=T.TEXT_MUTED)
            detail.update(out)
            hints.update(key_bar([("r", "read again"), ("f", "framework"), ("?", "all keys"), ("esc", "back")]))
            return
        out.append(f"{ST.STATUS_WORDS[c['status']]:<8}", style=f"bold {STYLE[c['status']]}")
        out.append(f"{c['control']}  ", style=T.DATA)
        out.append(c.get("text", ""), style=f"bold {T.TEXT_BRIGHT}")
        if self._single() is None:
            counts = ", ".join(f"{ST.STATUS_WORDS[k]} on {plural(v, 'machine')}" for k, v in c["counts"].items() if v)
            out.append(f"\n{counts}", style=T.TEXT_MUTED)
            detail.update(out)
            hints.update(key_bar([("enter", "details"), ("o", "owner"), ("n", "N/A"), ("?", "all keys"),
                                  ("esc", "back")]))
            return
        results = sorted(c.get("check_results") or [], key=lambda r: CHECK_ORDER.get(r["status"], 9))
        lead = next((r for r in results if r["status"] in ("fail", "partial")), None)
        if lead is not None:
            out.append(f"\n{lead['text']}: ", style=T.TEXT)
            out.append(_screen_words(lead.get("found") or lead.get("reason") or ""), style=CHECK_STYLE[lead["status"]])
        elif c.get("reason"):
            out.append(f"\n{_screen_words(c['reason'])}", style=T.TEXT_MUTED)
        passed = [r for r in results if r["status"] == "pass"]
        if passed:
            out.append(f"\n{plural(len(passed), 'other check')} passed" if lead else
                       f"\n{plural(len(passed), 'check')} passed", style=T.TEXT_DIM)
        if c.get("owner"):
            out.append(f" · owner {c['owner']}", style=T.TEXT_DIM)
        detail.update(out)
        hints.update(key_bar([("enter", "evidence"), ("o", "owner"), ("n", "N/A"), ("r", "read again"),
                              ("?", "all keys"), ("esc", "back")]))

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#co-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    # -- actions -----------------------------------------------------------
    def action_toggle_all(self) -> None:
        self._all = not self._all
        self.render_rows()

    @work(exclusive=True)
    async def action_framework(self) -> None:
        pick = await self.app.push_screen_wait(ListPickerModal(
            "Which framework?", [(f, F.FRAMEWORK_NAMES[f]) for f in F.FRAMEWORKS],
            subtitle="the same Kratos checks, mapped to each framework's control ids"))
        if pick:
            self._fw = pick
            self.reload()

    def action_details(self) -> None:
        c = self.selected()
        if c is None:
            return
        body = Text()
        if self._single() is None:
            body.append(f"{c.get('text', '')}\n\n", style=T.TEXT)
            for k, v in c["counts"].items():
                if v:
                    body.append(f"{ST.STATUS_WORDS[k]}: {plural(v, 'machine')}\n")
            body.append("\nOpen one machine with /compliance <machine> for its evidence.", style=T.TEXT_DIM)
            self.app.push_screen(InfoModal(f"{FW_WORDS[self._fw]} {c['control']}", body))
            return
        body.append(f"{ST.STATUS_WORDS[c['status']]}", style=f"bold {STYLE[c['status']]}")
        body.append(f"  {c.get('text', '')}\n", style=T.TEXT)
        results = sorted(c.get("check_results") or [], key=lambda r: CHECK_ORDER.get(r["status"], 9))
        if not results and c.get("reason"):
            body.append(f"{_screen_words(c['reason'])}\n", style=T.TEXT_MUTED)
        if c.get("person"):
            body.append(f"A person supplies: {c['person']}\n", style=T.TEXT_MUTED)
        if c.get("owner"):
            body.append(f"Owner: {c['owner']}\n")
        if c.get("uncovered_rules"):
            body.append("Not checked by Kratos (ComplianceAsCode rules — OpenSCAP can check them): "
                        + ", ".join(c["uncovered_rules"]) + "\n", style=T.TEXT_DIM)
        # The check that failed leads, with what was found; the ones that passed follow under it.
        shown_pass_header = False
        for r in results:
            if r["status"] == "pass" and not shown_pass_header and len(results) > 1:
                body.append("\n\nChecks that passed", style=f"bold {T.TEXT_MUTED}")
                shown_pass_header = True
            body.append(f"\n{r['text']}  ", style=f"bold {T.TEXT_BRIGHT}" if r["status"] != "pass" else T.TEXT)
            body.append({"unknown": "not checked", "na": "not applicable"}.get(r["status"], r["status"]),
                        style=CHECK_STYLE.get(r["status"], T.TEXT))
            body.append(f"\n  found: {_screen_words(r['found'] or r['reason'])}  ", style=T.TEXT)
            body.append(r["id"], style=T.TEXT_DIM)
            if r.get("read_at"):
                body.append(f"\n  read {self._when(r['read_at'])} via {r.get('via')}", style=T.TEXT_DIM)
            if r.get("note"):
                body.append(f"\n  {r['note']}", style=T.ATTENTION)
            if r.get("linked_finding"):
                body.append(f"\n  already a finding: {r['linked_finding']} (see /findings)", style=T.ATTENTION)
            if r.get("other_read"):
                o = r["other_read"]
                body.append(f"\n  the {o.get('via')} read said {o.get('status')}: {o.get('found')}", style=T.TEXT_DIM)
            if r.get("fix"):
                body.append(f"\n  fix (you run it): {r['fix']}", style=T.SAFE)
        self.app.push_screen(InfoModal(f"{FW_WORDS[self._fw]} {c['control']}", body))

    async def _scope(self, c: dict[str, Any]) -> str | None:
        single = self._single()
        choices = []
        if single is not None:
            choices.append((f"machine:{single['machine']}", f"this machine ({single['machine']})"))
        if self._group:
            choices.append((f"group:{self._group.lstrip('@')}", f"the group @{self._group.lstrip('@')}"))
        choices.append(("all", "every machine"))
        return await self.app.push_screen_wait(ListPickerModal(f"For {FW_WORDS[self._fw]} {c['control']} on:",
                                                               choices))

    @work(exclusive=True)
    async def action_owner(self) -> None:
        c = self.selected()
        if c is None:
            return
        scope = await self._scope(c)
        if scope is None:
            return
        who = await self.app.push_screen_wait(PromptModal("Owner (a Kratos user's name, or any name)", "",
                                                          initial=""))
        if not who:
            return
        due = await self.app.push_screen_wait(PromptModal("Due date (YYYY-MM-DD, empty for none)", "", initial=""))
        if due is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(f"Set the owner of {FW_WORDS[self._fw]} {c['control']}?",
                                                          f"{who}" + (f", due {due}" if due else "") + f"\n{scope}"))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            O.set_owner(self._data_dir, Actor.current("tui"), self._fw, c["control"], scope, who, due=due or None)
        except O.ComplianceError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"Owner set for {c['control']} (recorded with your name).", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_na(self) -> None:
        c = self.selected()
        if c is None:
            return
        scope = await self._scope(c)
        if scope is None:
            return
        reason = await self.app.push_screen_wait(PromptModal("Why doesn't it apply? (required)", "", initial=""))
        if not reason:
            return
        days = await self.app.push_screen_wait(PromptModal("For how many days? (1-365; Kratos asks again then)", "",
                                                           initial="365"))
        if not days:
            return
        try:
            n = int(days)
        except ValueError:
            self.note(Text("Not changed: days is a number.", style=T.CRITICAL))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Mark {FW_WORDS[self._fw]} {c['control']} not applicable?", f"{reason}\nfor {n} days · {scope}"))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            O.set_na(self._data_dir, Actor.current("tui"), self._fw, c["control"], scope, reason, n)
        except O.ComplianceError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"{c['control']} is not applicable for {n} days (recorded with your name).", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_level(self) -> None:
        single = self._single()
        if single is None:
            self.note(Text("Open one machine to set its CIS level.", style=T.TEXT_DIM))
            return
        pick = await self.app.push_screen_wait(ListPickerModal(
            f"CIS profile for {single['machine']}", [("1", "Level 1 Server (the default)"),
                                                     ("2", "Level 2 Server (stricter; includes Level 1)")]))
        if pick is None:
            return
        try:
            O.set_level(self._data_dir, Actor.current("tui"), single["machine"], pick)
        except O.ComplianceError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.reload()

    def action_refresh(self) -> None:
        self.note(Text("Reading the hardening facts again…", style=T.TEXT_DIM))
        self._refresh()

    @work(thread=True, exclusive=True)
    def _refresh(self) -> None:
        from kratos.compliance import record
        from kratos.kratos_config import pinned_target
        from kratos.run_context import run_scope

        machines = [s["machine"] for s in (self._doc or {}).get("machines") or []]
        lines = []
        for m in machines:
            try:
                with run_scope("interactive", target=m), pinned_target(m):
                    doc = record.run(self._data_dir, m)
                lines.append(f"{m}: {record.summary_line(doc)}")
            except Exception as e:  # noqa: BLE001
                lines.append(f"{m}: not read ({type(e).__name__}: {e})")
        self.app.call_from_thread(self._after_refresh, lines)

    def _after_refresh(self, lines: list[str]) -> None:
        for ln in lines:
            self.note(Text(ln, style=T.TEXT))
        self.reload()
