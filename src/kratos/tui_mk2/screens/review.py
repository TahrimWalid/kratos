"""`/review [machine]`: the AI review of the code a machine serves (E.7b).

Confirmed folders with their last review (counts per verdict, cost, profile, date). `p` prepares
a review: Kratos reads the folder locally and shows the plan -- where the code goes, the masking,
the exact slices and bytes, the estimated cost, how many are cached, reproduction on/off -- and
**only an explicit yes sends**. A run is refused above the cost ceiling and stops at the amount you
agree to. Enter opens a finding to its code-made verdict and evidence. Navigation follows
tui_mk2/modals.py: Escape back, `y` confirms. Nothing runs on the monitored machine.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import ConfirmModal, InfoModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import epoch_to_utc_iso, format_for_display, resolve_display_tz

_VERDICT_STYLE = {"confirmed": T.ATTENTION, "needs_validation": T.TEXT_MUTED, "rejected": T.TEXT_DIM}
REVIEW_ABOUT = ("Opt-in, per folder. p reads the folder here and shows the plan -- where the code goes, the "
                "masking, the slices and bytes, the estimated cost -- and only an explicit yes sends. Secrets are "
                "always removed. Nothing runs on the monitored machine.")
COLUMNS = ("folder", "last review", "verdicts", "cost")      # the profile and date: the detail pane


class ReviewScreen(Screen):
    _ALL_KEYS = "↑↓ select · p prepare a review (asks before sending) · enter the newest finding · esc back"
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter", "details", "verdict / evidence", show=True, priority=True),
        Binding("p", "prepare", "prepare + review", show=True),
    ]

    # A2: title row, the confirmed folders (hidden when there are none -- the sentence says
    # what to do), a detail pane, the review's progress log and a key bar.
    CSS = layout_css("ReviewScreen", "rv")

    def __init__(self, data_dir: Path, *, machine: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._machine = machine
        self._rows: list[dict[str, Any]] = []
        self._findings: list[dict[str, Any]] = []
        self._loglines: list[str] = []
        self._busy = False
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="rv-banner")
            yield DataTable(id="rv-table", cursor_type="row")
            yield Static(id="rv-detail")
            with VerticalScroll(id="rv-log"):
                yield Static("", id="rv-log-body")
            yield Static(key_bar([("?", "all keys"), ("esc", "back")]), id="rv-hints")

    def on_mount(self) -> None:
        self._reload()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self._reload)

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{REVIEW_ABOUT}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("AI code review — all keys", body))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        try:
            detail = self.query_one("#rv-detail", Static)
            hints = self.query_one("#rv-hints", Static)
            table = self.query_one("#rv-table", DataTable)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        if not self._rows or table.cursor_row is None:
            hints.update(key_bar([("?", "all keys"), ("esc", "back")]))
            return
        row = self._rows[min(table.cursor_row, len(self._rows) - 1)]
        last = row["last"]
        out = Text()
        out.append(row["root"], style=f"bold {T.TEXT_BRIGHT}")
        if last:
            out.append(f"   {last['state']}", style=T.TEXT)
            epoch = last.get("finished_at") or last.get("started_at")     # stored as epoch seconds
            when = format_for_display(epoch_to_utc_iso(epoch), "%Y-%m-%d %H:%M", tz=self._tz) if epoch else "-"
            out.append(f"\nlast review {when or '-'} · profile {last.get('profile') or '-'} · "
                       f"${last.get('actual_usd', 0):.4f}", style=T.TEXT_MUTED)
        else:
            out.append("   never reviewed", style=T.TEXT_MUTED)
        out.append(f"\n{REVIEW_ABOUT}", style=T.TEXT_DIM)
        detail.update(out)
        keys = [("p", "prepare a review")] + ([("enter", "finding")] if self._findings else [])
        hints.update(key_bar(keys + [("?", "all keys"), ("esc", "back")]))

    def _actor(self) -> Actor:
        return Actor.current("tui")

    def _reload(self) -> None:
        from kratos.code import present as P
        from kratos.review import store as RST
        banner = self.query_one("#rv-banner", Static)
        detail = self.query_one("#rv-detail", Static)
        t = self.query_one("#rv-table", DataTable)
        if not self._machine:
            banner.update(title_row("AI code review", note="per machine: /review <machine>"))
            t.display = False
            detail.update(Text(REVIEW_ABOUT, style=T.TEXT_MUTED))
            return
        try:
            tk, _scope = P.resolve_code_reader(self._data_dir, self._actor(), self._machine)
            confirmed = [r for r in P.view(self._data_dir, tk)["roots"] if r["status"] == "confirmed"]
        except Exception as e:  # noqa: BLE001
            banner.update(title_row("AI code review", self._machine, note=f"can't read code folders: {e}",
                                    note_style=T.CRITICAL))
            t.display = False
            return
        runs = RST.runs(self._data_dir, tk)
        self._rows = []
        cursor = t.cursor_row
        t.clear(columns=True)
        t.add_columns(*COLUMNS)
        cells = []
        for r in confirmed:
            last = next((x for x in runs if x["root"] == r["path"]), None)
            counts = (last or {}).get("counts") or {}
            vsum = f"{counts.get('reviewed', 0)} reviewed / {counts.get('reproduced', 0)} reproduced" if last else "-"
            cells.append([r["path"], (last["state"] if last else "never reviewed"), vsum,
                          (f"${last.get('actual_usd', 0):.4f}" if last else "-")])
            self._rows.append({"root": r["path"], "machine": self._machine, "last": last})
        available = t.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(0, 16), (2, 12)], headers=COLUMNS):
            t.add_row(*row)
        t.display = bool(self._rows)            # no empty grid under the "confirm one first" sentence
        banner.update(title_row("AI code review", self._machine, plural(len(confirmed), "confirmed folder")))
        if not confirmed:
            detail.update(Text("No confirmed code folders on this machine. Confirm one first in /code.",
                               style=T.ATTENTION))
        elif cursor is not None:
            t.move_cursor(row=min(cursor, len(self._rows) - 1))
        self._show_detail()

    def _log(self, text: str, style: str = T.TEXT_MUTED) -> None:
        self._loglines.append(text)
        self._loglines[:] = self._loglines[-40:]
        self.query_one("#rv-log-body", Static).update(Text("\n".join(self._loglines), style=style))

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_details(self) -> None:
        if not self._findings:
            return
        t = self.query_one("#rv-table", DataTable)
        # the findings panel is shown from the most recent run; pick by cursor only when it maps.
        f = self._findings[0]
        lines = [f"{f['verdict']}" + (f"({f['strength']})" if f.get("strength") else "")
                 + f"  {f['cls']}  {f['rel']}:{f['function']}"]
        if f.get("evidence"):
            lines.append(str(f["evidence"]))
        if f.get("question"):
            lines.append("open question: " + str(f["question"]))
        if f.get("fix_words"):
            lines.append("proposed fix: " + str(f["fix_words"])
                         + (f"  ({f['fix_check']})" if f.get("fix_check") else ""))
        self.app.push_screen(InfoModal("Review finding", Text("\n".join(lines))))

    @work(exclusive=True)
    async def action_prepare(self) -> None:
        if self._busy or not self._rows:
            return
        t = self.query_one("#rv-table", DataTable)
        idx = t.cursor_row if t.cursor_row is not None else 0
        if idx >= len(self._rows):
            return
        row = self._rows[idx]
        self._busy = True
        try:
            await self._prepare_and_run(row["machine"], row["root"])
        finally:
            self._busy = False
            self._reload()

    async def _prepare_and_run(self, machine: str, root: str) -> None:
        from kratos.review import cost as COST
        from kratos.review import run as RUN
        from kratos.review import settings as RS
        from kratos.review.plan import PlanError
        from kratos.review.run import ReviewRefused

        self._log(f"reading and slicing {root} on {machine} …", T.TEXT_MUTED)
        try:
            plan = await asyncio.to_thread(RUN.prepare_review, self._data_dir, self._actor(), machine, root)
        except (ReviewRefused, PlanError) as e:
            self._log(str(e), T.CRITICAL)
            return
        s = plan.consent_summary()
        max_run = float(RS.get(RS.MAX_RUN_USD, self._data_dir))
        over = not COST.fits_ceiling(plan.estimate.usd, max_run)
        body = Text(
            s["line"] + "\n"
            + f"reads/slices {plural(s['slices_to_send'], 'slice')}, {s['bytes_to_send']} bytes; "
            + f"cached {s['slices_cached']}; reproduction {'on' if s['reproduction'] else 'OFF'}\n"
            + (f"estimated cost ${s['estimate_usd']:.4f} ({s['est_calls']} calls)" if s["priced"]
               else f"estimated cost $0 (a model on your own network; {s['est_calls']} calls)")
            + f"  ·  reduction {s['reduction']}x")
        if over:
            self.app.push_screen(InfoModal(
                "Over the cost ceiling",
                Text(f"The estimate ${plan.estimate.usd:.4f} is over the ceiling "
                     f"${COST.ceiling_for(max_run, None):.2f} (review.max_run_usd). Raise it in Settings or with "
                     "`kratos review start … --raise-to`.")))
            return
        agreed = COST.ceiling_for(max_run, None)
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Send these code slices to the model?", body, yes_label="send", no_label="cancel"))
        if not ok:
            self._log("not sent; nothing left the machine.", T.TEXT_DIM)
            return
        self._log("reviewing … (verdicts are decided by code; the real dangerous call is never run)", T.ATTENTION)

        def on_progress(stage: str, info: dict[str, Any]) -> None:
            self.app.call_from_thread(self._log, f"  {stage}: {info}", T.TEXT_MUTED)

        try:
            res = await asyncio.to_thread(RUN.start_review, self._data_dir, self._actor(), plan.plan_id,
                                          agreed_usd=agreed, on_progress=on_progress)
        except (ReviewRefused, PlanError) as e:
            self._log(str(e), T.CRITICAL)
            return
        self._findings = res.findings
        self._log(f"done: {res.state}" + (f" ({res.stop_reason})" if res.stop_reason else "")
                  + f"  ·  ${res.actual_usd:.4f}  ·  {plural(len(res.findings), 'finding')} — Enter to open", T.SAFE)
