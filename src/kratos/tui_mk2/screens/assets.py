"""`/assets`: every machine Kratos knows and what you've said about it (D.3).

Criticality (how much the machine matters -- it feeds CISA's SSVC tree, which ranks
its vulnerabilities), public well-being impact, whether it is reachable from the
internet (what Kratos can't measure), groups, role and an owner note. A machine Kratos
holds data for but nobody has described yet is shown as "not set up", never hidden.
Every edit is confirmed and recorded with who made it (kratos.assets.store). Navigation
follows tui_mk2/modals.py: Escape back, `y` confirms.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.assets import store as AS
from kratos.lifecycle.decide import Actor
from kratos.ssvc import mission as M
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import epoch_to_utc_iso, format_for_display, resolve_display_tz

COLUMNS = ("machine", "criticality", "well-being", "exposure", "groups", "role", "owner note")

CRITICALITY_CHOICES = [
    ("critical", "critical — the organisation stops without it"),
    ("high", "high — an important service (customer-facing, holds sensitive data)"),
    ("medium", "medium — supports other work"),
    ("low", "low — a test box, nothing depends on it"),
    ("unset", "not set — Kratos assumes medium and says so"),
]
WELLBEING_CHOICES = [(v, f"{v} — {M.WELLBEING_TEXT[v]}") for v in M.WELLBEING]
EXPOSURE_CHOICES = [
    ("unset", "as measured — Kratos decides from what it reads on the machine"),
    ("internet", "reachable from the internet (e.g. behind a NAT or proxy Kratos can't see)"),
    ("private", "not reachable from the internet"),
]


def measured_exposure(data_dir: Path, target: str) -> str:
    from kratos.cli.assets_cmd import _measured

    return _measured(data_dir, target)


class AssetsScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("enter,e", "edit", "edit", show=True, priority=True),
        Binding("c", "criticality", "criticality", show=True),
        Binding("h", "history", "history", show=True),
    ]

    CSS = """
    AssetsScreen { padding: 1 2; }
    AssetsScreen #as-banner { height: auto; padding: 0 0 1 0; }
    AssetsScreen DataTable { height: auto; max-height: 65%; }
    AssetsScreen #as-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    AssetsScreen #as-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, configured: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._configured = configured
        self._rows: list[AS.Asset] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="as-banner")
            yield DataTable(id="as-table", cursor_type="row")
            yield VerticalScroll(id="as-log")
            yield Static(Text("↑↓ select · enter edit everything · c criticality only · h history · esc back",
                              style=T.TEXT_DIM), id="as-hints")

    def on_mount(self) -> None:
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def note(self, renderable: Any) -> None:
        area = self.query_one("#as-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    def refresh_rows(self) -> None:
        table = self.query_one("#as-table", DataTable)
        cursor = table.cursor_row
        self._rows = AS.known_machines(self._data_dir, configured=self._configured)
        table.clear(columns=True)
        table.add_columns(*COLUMNS)
        cells = []
        for a in self._rows:
            if not a.set_up:
                crit = Text("not set up", style=T.ATTENTION)
            elif a.criticality:
                crit = Text(a.criticality, style=T.CRITICAL if a.criticality == "critical" else T.TEXT)
            else:
                crit = Text("not set (assumed medium)", style=T.TEXT_MUTED)
            measured = measured_exposure(self._data_dir, a.target)
            exp = measured + (f" · you: {a.exposure_override}" if a.exposure_override else "")
            cells.append([a.target, crit, a.wellbeing if a.set_up else "-", exp, ", ".join(a.groups) or "-",
                          a.role or "-", a.owner_note or "-"])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(6, 12), (5, 8), (4, 10), (0, 16)],
                                            headers=COLUMNS)):
            table.add_row(*row, key=self._rows[i].target)
        if cursor is not None and self._rows:
            table.move_cursor(row=min(cursor, len(self._rows) - 1))
        banner = Text()
        banner.append("Machines", style=f"bold {T.ACCENT}")
        banner.append(f"   ({len(self._rows)})", style=T.TEXT_DIM)
        banner.append("\nCriticality decides how CISA's SSVC tree ranks each machine's vulnerabilities "
                      "(Track · Track* · Attend · Act). Exposure is what Kratos measured; set it only for what Kratos "
                      "can't see.", style=T.TEXT_MUTED)
        if not self._rows:
            banner.append("\nNo machines yet: they appear after a check or an investigation.", style=T.TEXT_DIM)
        self.query_one("#as-banner", Static).update(banner)

    def selected(self) -> AS.Asset | None:
        table = self.query_one("#as-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    # -- edits (people only, confirmed, recorded) --------------------------
    def action_criticality(self) -> None:
        a = self.selected()
        if a:
            self._edit(a, full=False)

    def action_edit(self) -> None:
        a = self.selected()
        if a:
            self._edit(a, full=True)

    @work(exclusive=True)
    async def _edit(self, a: AS.Asset, *, full: bool) -> None:
        changes: dict[str, Any] = {}
        crit = await self.app.push_screen_wait(ListPickerModal(
            f"How much does {a.target} matter?", CRITICALITY_CHOICES,
            subtitle=f"now: {a.criticality or 'not set'} · ↑↓ pick · esc cancel"))
        if crit is None:
            return
        changes["criticality"] = crit
        if full:
            wb = await self.app.push_screen_wait(ListPickerModal(
                "If it were compromised, could people outside your organisation be harmed?", WELLBEING_CHOICES,
                subtitle=f"now: {a.wellbeing} · most machines: minimal · esc cancel"))
            if wb is None:
                return
            changes["wellbeing"] = wb
            ex = await self.app.push_screen_wait(ListPickerModal(
                "Is it reachable from the internet?", EXPOSURE_CHOICES,
                subtitle=f"now: {a.exposure_override or 'as measured'} · esc cancel"))
            if ex is None:
                return
            changes["exposure_override"] = ex
            for field, title, hint, now in (
                    ("role", "Role (a label for you; never sent to the model)", "web, db, build ...", a.role),
                    ("groups", "Groups (comma-separated)", "prod, eu ...", ", ".join(a.groups)),
                    ("owner_note", "Owner note — who to call (never sent to the model)", "", a.owner_note)):
                value = await self.app.push_screen_wait(PromptModal(title, hint, initial=now))
                if value is None:
                    return
                changes[field] = value
        summary = "\n".join(f"{k.replace('_', ' ')}: {v or '(unset)'}" for k, v in changes.items())
        ok = await self.app.push_screen_wait(ConfirmModal(f"Save for {a.target}?", summary))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            saved = AS.update(self._data_dir, a.target, Actor.current("tui"), **changes)
        except AS.AssetError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"Saved {saved.target}: criticality {saved.criticality or 'not set'} (recorded as "
                       f"{saved.updated_by}). Vulnerability decisions use it from the next report.", style=T.SAFE))
        self.refresh_rows()

    def action_history(self) -> None:
        a = self.selected()
        if not a:
            return
        events = AS.events(self._data_dir, a.target)
        body = Text()
        if not events:
            body.append("No changes recorded.", style=T.TEXT_DIM)
        for e in events:
            when = format_for_display(epoch_to_utc_iso(e["at"]), "%Y-%m-%d %H:%M", tz=self._tz)
            what = "asked how much it matters" if e["field"] == "asked" else \
                f"{e['field'].replace('_', ' ')}: {e['old_value'] or '(unset)'} → {e['new_value'] or '(unset)'}"
            body.append(f"{when}  {e['actor']} ({e['interface']})  {what}\n")
        self.app.push_screen(InfoModal(f"History of {a.target}", body))


async def ask_criticality_once(app: Any, data_dir: Path, target: str, *, why: str) -> str | None:
    """The one-time question (D.3 §3 decision 3): asked once per machine (onboarding, or
    the first time a package finding appears); any answer -- including "not now" -- is
    recorded so it isn't asked again. Returns the criticality set, or None."""
    from kratos import settings_store
    from kratos.ssvc import settings as SS

    if not settings_store.get(SS.ASK_CRITICALITY, data_dir=data_dir) or not AS.needs_question(data_dir, target):
        return None
    choices = [c for c in CRITICALITY_CHOICES if c[0] != "unset"] + [
        ("later", "not now — assume medium (change it any time with /assets)")]
    crit = await app.push_screen_wait(ListPickerModal(f"How much does {target} matter?", choices, subtitle=why))
    actor = Actor.current("tui")
    if crit in (None, "later"):
        AS.mark_asked(data_dir, target, actor)
        return None
    AS.update(data_dir, target, actor, criticality=crit)
    AS.mark_asked(data_dir, target, actor)
    return crit
