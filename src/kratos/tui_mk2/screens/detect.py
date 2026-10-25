"""`/detect`: the detection rules (Sigma, phase C.1).

The pack (version, rules by level), each rule with its author and whether it is on
for the session's machine, the candidates that were not shipped with why, the last
detection pass per machine and what it could not check. A person may turn a rule off
for this machine or everywhere, with a reason (kratos.detect.store, people only), and
run the rules now. Navigation follows tui_mk2/modals.py: Escape back, `y` confirms.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.detect import pack as P
from kratos.detect import store as ST
from kratos.events import sigma_fields as SF
from kratos.lifecycle.decide import Actor
from kratos.target_key import target_key
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeTable as Table
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import format_for_display, resolve_display_tz, epoch_to_utc_iso

COLUMNS = ("rule", "level", "on", "reads", "title", "author")
SKIPPED_COLUMNS = ("why not shipped", "level", "reads", "title", "author")
_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _reads(meta: dict[str, Any]) -> str:
    ls = meta.get("logsource") or {}
    found = SF.LOGSOURCES.get((ls.get("product") or "", ls.get("service"), ls.get("category")))
    return found.label if found else "/".join(v for v in ls.values() if v)


class DetectScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("x", "toggle_here", "on/off here", show=True),
        Binding("e", "toggle_everywhere", "on/off everywhere", show=True),
        Binding("s", "toggle_view", "shipped / not shipped", show=True),
        Binding("r", "run_now", "run now", show=True),
    ]

    CSS = """
    DetectScreen { padding: 1 2; }
    DetectScreen #dt-banner { height: auto; padding: 0 0 1 0; }
    DetectScreen DataTable { height: auto; max-height: 65%; }
    DetectScreen #dt-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    DetectScreen #dt-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, target: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._target = target_key(target) if target else None
        self._skipped_view = False
        self._rows: list[dict[str, Any]] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="dt-banner")
            yield DataTable(id="dt-table", cursor_type="row")
            yield VerticalScroll(id="dt-log")
            yield Static(Text("↑↓ select · enter details · x on/off for this machine · e on/off everywhere\n"
                              "s shipped / not shipped · r run the rules now · esc back", style=T.TEXT_DIM),
                         id="dt-hints")

    def on_mount(self) -> None:
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def note(self, renderable: Any) -> None:
        area = self.query_one("#dt-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    # -- data --------------------------------------------------------------
    def _load(self) -> list[dict[str, Any]]:
        loaded = P.load(self._data_dir)
        self._loaded = loaded
        if self._skipped_view:
            return [dict(s, _pack=lp.pack_id) for lp in loaded.loaded for s in P.skipped(lp)]
        off = ST.disabled_rules(self._data_dir, self._target) if self._target else set()
        rows = [{"meta": r.meta, "pack": lp.pack_id, "on": r.id not in off} for lp, r in loaded.rules()]
        rows.sort(key=lambda x: (_LEVEL_ORDER.get(x["meta"]["level"], 9), _reads(x["meta"]), x["meta"]["title"]))
        return rows

    def refresh_rows(self) -> None:
        table = self.query_one("#dt-table", DataTable)
        cursor = table.cursor_row
        self._rows = self._load()
        table.clear(columns=True)
        headers = SKIPPED_COLUMNS if self._skipped_view else COLUMNS
        table.add_columns(*headers)
        cells = []
        for r in self._rows:
            if self._skipped_view:
                cells.append([str(r.get("reason") or ""), str(r.get("level") or "-"), str(r.get("logsource") or "-"),
                              str(r.get("title") or r.get("path") or ""), str(r.get("author") or "")])
            else:
                m = r["meta"]
                on = Text("on", style=T.SAFE) if r["on"] else Text("OFF", style=T.ATTENTION)
                cells.append([m["id"], Text(m["level"], style=T.SEVERITY_COLOR.get(m["level"], T.TEXT)), on,
                              _reads(m), m["title"], m["author"]])
        available = table.size.width or max(self.app.size.width - 6, 40)
        shrink = [(0, 30), (3, 14), (4, 24)] if self._skipped_view else [(3, 12), (4, 28), (5, 18)]
        for row in fit_columns(cells, available, shrink=shrink, headers=headers):
            table.add_row(*row)
        if cursor is not None and self._rows:
            table.move_cursor(row=min(cursor, len(self._rows) - 1))
        self._update_banner()

    def _update_banner(self) -> None:
        banner = Text()
        banner.append("Detection rules", style=f"bold {T.ACCENT}")
        packs = ", ".join(f"{lp.pack_id} v{lp.version} ({len(lp.pack.rules)})" for lp in self._loaded.loaded)
        banner.append(f" — {packs}", style=T.TEXT)
        by_level: dict[str, int] = {}
        for _lp, r in self._loaded.rules():
            by_level[r.meta["level"]] = by_level.get(r.meta["level"], 0) + 1
        banner.append("\n" + " · ".join(f"{n} {lvl}" for lvl, n in sorted(by_level.items(),
                                                                            key=lambda kv: _LEVEL_ORDER.get(kv[0], 9))),
                      style=T.TEXT_MUTED)
        banner.append("   Rules by their authors (SigmaHQ), Detection Rule License 1.1.", style=T.TEXT_DIM)
        if self._skipped_view:
            banner.append(f"\nShowing the {len(self._rows)} candidates NOT shipped, with why. "
                          "Import any of them yourself: kratos detect import.", style=T.TEXT)
        machine = self._target or "no machine selected"
        banner.append(f"\nOn/off and last pass for: {machine}", style=T.TEXT)
        if self._target:
            runs = ST.last_runs_by_target(self._data_dir)
            run = runs.get(self._target)
            if run is None:
                banner.append(" — the rules have not run here yet (press r)", style=T.TEXT_DIM)
            else:
                when = format_for_display(epoch_to_utc_iso(run.finished_at or run.started_at), "%Y-%m-%d %H:%M",
                                          tz=self._tz)
                banner.append(f" — last pass {when}: {run.events:,} log event(s), {run.detections} match(es)"
                              + (f", {run.status}: {run.reason}" if run.status != "ok" else ""), style=T.TEXT_MUTED)
            for line in self._coverage_lines():
                banner.append("\n  " + line, style=T.ATTENTION)
        for ref in self._loaded.refused:
            banner.append(f"\nRefused rule pack {Path(ref.path).name}: {ref.reason}", style=T.CRITICAL)
        watch = self._watch_line()
        if watch:
            banner.append(f"\nLive: {watch}. The rules also run on schedule over the logs Kratos collects.",
                          style=T.SAFE if "NOT running" not in watch else T.CRITICAL)
        else:
            banner.append("\nThese rules run on the logs Kratos collected, on schedule — not continuously"
                          + (" (a machine with a sub-agent can be watched continuously: /subagent, w)."
                             if self._target else "."), style=T.TEXT_DIM)
        self.query_one("#dt-banner", Static).update(banner)

    def _watch_line(self) -> str | None:
        if not self._target:
            return None
        try:
            from kratos.detect import live as L

            return L.watch_line(self._data_dir, self._target)
        except Exception:  # noqa: BLE001 -- the banner must render
            return None

    def _coverage_lines(self) -> list[str]:
        from kratos.adapters.findings_engine import find_latest_inputs
        from kratos.detect.findings import _WATCH_FEEDS, _watched_now, load_recent

        doc = load_recent(find_latest_inputs(self._data_dir, self._target).get("detections"))
        if not doc:
            return []
        watched = _watched_now(doc)
        out = []
        for c in doc.get("coverage") or []:
            if c.get("state") == "checked":
                continue
            feeds = [d for d in c.get("datasets") or [] if d in _WATCH_FEEDS]
            if feeds and all(_WATCH_FEEDS[d] in watched for d in feeds):
                continue            # read live by the machine's agent (C.2)
            out.append(f"{c['label']} ({c['rules']} rules): {c['note']}")
        return out

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#dt-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    # -- actions -----------------------------------------------------------
    def action_toggle_view(self) -> None:
        self._skipped_view = not self._skipped_view
        self.refresh_rows()

    def action_details(self) -> None:
        row = self.selected()
        if row is None:
            return
        body = Table.grid(padding=(0, 2))
        body.add_column(style=T.TEXT_DIM)
        body.add_column()
        if self._skipped_view:
            for k in ("title", "author", "path", "status", "level", "logsource", "reason"):
                body.add_row(k, str(row.get(k) or "-"))
            self.app.push_screen(InfoModal("Not shipped — details", body))
            return
        m = row["meta"]
        src = m.get("source") or {}
        body.add_row("rule", f"{m['id']} — {m['title']}")
        body.add_row("level", m["level"])
        body.add_row("author", m["author"])
        body.add_row("licence", m.get("license") or "")
        body.add_row("source", f"{src.get('path') or ''}\n{src.get('url') or ''}")
        body.add_row("SigmaHQ id", str(m.get("sigma_id") or ""))
        body.add_row("reads", _reads(m))
        if m.get("description"):
            body.add_row("about", m["description"])
        if m.get("attack"):
            body.add_row("ATT&CK", ", ".join(m["attack"]))
        for i, fp in enumerate(m.get("falsepositives") or []):
            body.add_row("false positives" if i == 0 else "", fp)
        if m.get("count"):
            c = m["count"]
            body.add_row("counts", f"{c['threshold']}+ matches within {c['window_seconds']} s"
                                   + (f", per {c['group_by']}" if c.get("group_by") else ""))
        body.add_row("on here", "yes" if row["on"] else "no (turned off)")
        for o in ST.overrides(self._data_dir):
            if o.rule_id == m["id"]:
                where = "every machine" if o.target == ST.EVERYWHERE else o.target
                body.add_row("changed", f"{'on' if o.enabled else 'off'} for {where} by {o.actor}: {o.reason}")
        self.app.push_screen(InfoModal(f"{m['id']} — details", body))

    @work(exclusive=True)
    async def action_toggle_here(self) -> None:
        await self._toggle(everywhere=False)

    @work(exclusive=True)
    async def action_toggle_everywhere(self) -> None:
        await self._toggle(everywhere=True)

    async def _toggle(self, *, everywhere: bool) -> None:
        row = self.selected()
        if row is None or self._skipped_view:
            self.note(Text("Select a shipped rule first (s switches back).", style=T.TEXT_DIM))
            return
        if not everywhere and not self._target:
            self.note(Text("No machine is selected for this session -- use e to turn it off everywhere.",
                           style=T.TEXT_DIM))
            return
        rule_id = row["meta"]["id"]
        turn_on = not row["on"] if not everywhere else rule_id in ST.disabled_everywhere(self._data_dir)
        where = "every machine" if everywhere else self._target
        verb = "on" if turn_on else "off"
        if everywhere:
            ok = await self.app.push_screen_wait(ConfirmModal(
                f"Turn {rule_id} {verb} for every machine?",
                Text(f"{row['meta']['title']} -- {verb} everywhere until you change it.")))
            if not ok:
                return
        reason = await self.app.push_screen_wait(PromptModal(
            f"Turn {rule_id} {verb} for {where}", hint="Why? (required — saved with your name)"))
        if not reason or not str(reason).strip():
            self.note(Text("Nothing changed (a reason is required).", style=T.TEXT_DIM))
            return
        try:
            ST.set_rule_enabled(self._data_dir, rule_id, turn_on, target=None if everywhere else self._target,
                                reason=str(reason), actor=Actor.current("tui"))
        except ST.OverrideError as e:
            self.note(Text(str(e), style=T.CRITICAL))
            return
        self.note(Text(f"✓ {rule_id} is now {verb} for {where}.", style=T.SAFE))
        self.refresh_rows()

    def action_run_now(self) -> None:
        if not self._target:
            self.note(Text("No machine is selected for this session.", style=T.TEXT_DIM))
            return
        self.note(Text(f"Running the rules over the logs Kratos holds for {self._target}…", style=T.TEXT_DIM))
        self._run_worker()

    @work(thread=True, exclusive=True)
    def _run_worker(self) -> None:
        from kratos import kratos_config
        from kratos.adapters import findings_engine as FE
        from kratos.detect import run as R
        from kratos.run_context import run_scope

        started = time.time()
        try:
            with run_scope("interactive", target=self._target), kratos_config.pinned_target(self._target):
                report = R.run_pass(self._target, self._data_dir)
                FE.write_findings_report(data_dir=self._data_dir)
        except Exception as e:  # noqa: BLE001 -- shown, never a crash of the screen
            self.app.call_from_thread(self.note, Text(f"The pass failed: {type(e).__name__}: {e}", style=T.CRITICAL))
            return
        rules = sorted({m["rule_id"] for m in report.matches})
        msg = (f"✓ {report.events:,} new log event(s) checked in {time.time() - started:.1f}s — "
               f"{len(report.matches)} new match(es)" + (f": {', '.join(rules)}" if rules else "")
               + ". New matches are in /findings.")
        self.app.call_from_thread(self.note, Text(msg, style=T.SAFE if not report.matches else T.ATTENTION))
        self.app.call_from_thread(self.refresh_rows)
