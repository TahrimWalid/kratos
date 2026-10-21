"""`/findings` (alias `/f`): the findings Kratos remembers across runs, and the
decisions people make about them (kratos.lifecycle).

The default view shows open and verified findings for the session's machine
(Settings: findings.default_view); the banner always counts what the user's own
decisions hide, so nothing disappears silently. Every decision goes through
kratos.lifecycle.decide as this person ("tui"), with a reason; a decision about
a rule everywhere asks once more. Navigation follows tui_mk2/modals.py: Escape
back, `y` confirms, any other key declines.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from kratos.untrusted import annotate_lookalikes
from kratos.untrusted_rich import SafeTable as Table
from kratos.untrusted_rich import SafeText as Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Input, RadioButton, RadioSet
from kratos.tui_mk2.safe_widgets import SafeButton as Button, SafeDataTable as DataTable, SafeStatic as Static

from kratos import settings_store
from kratos.attack import format_label
from kratos.lifecycle import decide as D
from kratos.lifecycle import query as Q
from kratos.lifecycle import settings as LS
from kratos.triage import run as TR
from kratos.target_key import target_key
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.table_fit import fit_columns
from kratos.utils.timeutil import format_for_display, resolve_display_tz

COLUMNS = ("state", "severity", "rule", "title", "verdict", "machine", "first seen", "last seen", "until")
STATE_WORDS = {"open": "open", "verified": "verified", "mitigated": "fixed", "inactive": "no recurrence",
               "risk_accepted": "risk accepted", "false_positive": "not a problem", "out_of_scope": "out of scope"}
STATE_COLOR = {"open": T.ATTENTION, "verified": T.CRITICAL, "mitigated": T.SAFE, "inactive": T.SAFE,
               "risk_accepted": T.TEXT_MUTED, "false_positive": T.TEXT_MUTED, "out_of_scope": T.TEXT_MUTED}
# s cycles through these views
STATE_VIEWS = (("open_verified", "open and verified"), ("decided", "hidden by your decisions"),
               ("fixed", "fixed / no recurrence"), ("all", "everything"))
SEVERITY_FLOORS = (("info", "any severity"), ("low", "low and above"), ("medium", "medium and above"),
                   ("high", "high and above"))
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
EXPIRY_CHOICES = (7, 30, 90, 180)

DECISION_TITLES = {
    "risk_accepted": ("Accept the risk until…", "risk_accepted"),
    "false_positive": ("Not a real problem", "false_positive"),
    "out_of_scope": ("Not relevant for this machine", "out_of_scope"),
}


class DecisionModal(ModalScreen[dict[str, Any] | None]):
    """Owner (accept only), reason (required), until (days or a date; required
    and capped for accept, optional otherwise), scope. Enter or Save checks it
    here; kratos.lifecycle.decide checks it again. esc cancels (nothing changes)."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]
    CSS = """
    DecisionModal RadioSet { width: 1fr; height: auto; }
    DecisionModal #d-error { height: auto; }
    """

    def __init__(self, kind: str, finding_label: str, *, cap_days: int, default_owner: str) -> None:
        super().__init__()
        self._kind = kind
        self._label = finding_label
        self._cap_days = cap_days
        self._owner = default_owner

    def compose(self) -> ComposeResult:
        title, technical = DECISION_TITLES[self._kind]
        accept = self._kind == "risk_accepted"
        with Vertical(classes="modal-card"):
            yield Static(Text(title, style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(Text(f"{self._label}\n(state: {technical})", style=T.TEXT_DIM))
            if accept:
                yield Static(Text("Owner — who is responsible for this risk", style=T.TEXT))
                yield Input(value=self._owner, id="d-owner", select_on_focus=False)
            yield Static(Text("Reason (required)", style=T.TEXT))
            yield Input(id="d-reason", placeholder="e.g. our own vulnerability scanner")
            choices = " / ".join(str(d) for d in EXPIRY_CHOICES if d <= self._cap_days)
            yield Static(Text(
                f"Until — days ({choices}) or a date (2026-12-31); at most {self._cap_days} days" if accept
                else "Until (optional) — days or a date; leave empty for no end date", style=T.TEXT))
            yield Input(value=str(min(30, self._cap_days)) if accept else "", id="d-until", select_on_focus=False)
            yield Static(Text("Applies to", style=T.TEXT))
            with RadioSet(id="d-scope"):
                yield RadioButton("this finding", value=True, id="scope-key")
                yield RadioButton("this rule on this machine", id="scope-rule_target")
                yield RadioButton("this rule everywhere (asks again)", id="scope-rule")
            yield Static("", id="d-error")
            yield Button("Save", id="d-save", variant="primary")
            yield Static(Text("Enter / Save · esc cancel (nothing changes)", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        self.query_one("#d-reason", Input).focus()

    def _error(self, message: str) -> None:
        self.query_one("#d-error", Static).update(Text(message, style=f"bold {T.CRITICAL}"))

    def _scope(self) -> str:
        pressed = self.query_one("#d-scope", RadioSet).pressed_button
        return (pressed.id or "scope-key").removeprefix("scope-") if pressed else "key"

    def validate(self) -> dict[str, Any] | None:
        """The cleaned values, or None after showing what's wrong."""
        reason = self.query_one("#d-reason", Input).value
        if not reason.strip():
            self._error("A reason is required.")
            return None
        if len(reason) > D.MAX_REASON:
            self._error(f"The reason is too long (at most {D.MAX_REASON} characters).")
            return None
        until = self.query_one("#d-until", Input).value.strip()
        expires: float | None = None
        now = time.time()
        try:
            if until:
                expires = D.expiry_from_days(float(until), now=now) if _is_number(until) else D.parse_expiry(until)
        except D.DecisionError as e:
            self._error(str(e))
            return None
        if self._kind == "risk_accepted":
            if expires is None:
                self._error("Accepting a risk needs an end: a number of days or a date.")
                return None
            if expires > now + self._cap_days * 86400 + 60:
                self._error(f"At most {self._cap_days} days (Settings → General: findings.accept_max_days).")
                return None
        if expires is not None and expires <= now:
            self._error("The end must be in the future.")
            return None
        owner = self.query_one("#d-owner", Input).value.strip() if self._kind == "risk_accepted" else None
        return {"reason": reason, "expires_at": expires, "owner": owner or None, "scope": self._scope()}

    def _submit(self) -> None:
        values = self.validate()
        if values is not None:
            self.dismiss(values)

    @on(Input.Submitted)
    def _on_enter(self, _event: Input.Submitted) -> None:
        self._submit()

    @on(Button.Pressed, "#d-save")
    def _on_save(self, _event: Button.Pressed) -> None:
        self._submit()

    def action_cancel(self) -> None:
        self.dismiss(None)


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


class FindingsScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        # priority: the focused DataTable would otherwise take Enter itself
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("v", "verify", "verify", show=True),
        Binding("a", "accept", "accept risk", show=True),
        Binding("f", "false_positive", "not a problem", show=True),
        Binding("o", "out_of_scope", "out of scope", show=True),
        Binding("r", "reopen", "reopen", show=True),
        Binding("k", "recheck", "re-check", show=True),
        Binding("t", "retest", "retest", show=True),
        Binding("n", "dismiss_suggestion", "dismiss note", show=False),
        Binding("h", "history", "history", show=True),
        Binding("s", "cycle_state", "which", show=True),
        Binding("p", "cycle_severity", "severity", show=True),
        Binding("m", "pick_machine", "machine", show=True),
        Binding("slash", "search", "search", show=True),
        Binding("c", "copy_attack", "copy ATT&CK link", show=True),
    ]

    CSS = """
    FindingsScreen { padding: 1 2; }
    FindingsScreen #fd-banner { height: auto; padding: 0 0 1 0; }
    FindingsScreen DataTable { height: auto; max-height: 70%; }
    FindingsScreen #fd-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    FindingsScreen #fd-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, target: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._target = target_key(target) if target else None
        default_view = settings_store.get(LS.DEFAULT_VIEW, data_dir=self._data_dir)
        self._state = "all" if default_view == "all" else "open_verified"
        self._floor = "info"
        self._search = ""
        self._rows: list[dict[str, Any]] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="fd-banner")
            yield DataTable(id="fd-table", cursor_type="row")
            yield VerticalScroll(id="fd-log")
            yield Static(Text(
                "↑↓ select · enter details · h history · c copy ATT&CK\n"
                "v verify · a accept risk · f not a real problem · o out of scope · r reopen\n"
                "k re-check · t retest · n dismiss note\n"
                "s which findings · p severity · m machine · / search · esc back",
                style=T.TEXT_DIM), id="fd-hints")

    def on_mount(self) -> None:
        self.query_one("#fd-table", DataTable).add_columns(*COLUMNS)
        self.refresh_rows()

    def on_screen_resume(self) -> None:
        self.call_after_refresh(self.refresh_rows)

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    # -- data --------------------------------------------------------------
    def _when(self, value: str | None) -> str:
        return format_for_display(value, "%Y-%m-%d %H:%M", tz=self._tz) if value else "-"

    def _verdict_cell(self, row: dict[str, Any]) -> Text:
        v = row.get("verdict")
        if not isinstance(v, dict):
            return Text("-", style=T.TEXT_DIM)
        verdict = str(v.get("verdict") or "")
        color = {"reproduced": T.CRITICAL, "seen": T.ATTENTION, "partly": T.ATTENTION, "not_reproduced": T.SAFE,
                 "couldnt_check": T.TEXT_MUTED, "verifying": T.TEXT_DIM}.get(verdict, T.TEXT)
        return Text(str(v.get("tag") or verdict), style=color)

    def visible_rows(self) -> list[dict[str, Any]]:
        rows = Q.list_findings(self._data_dir, target=self._target, state=self._state)
        TR.enrich_rows(rows, self._data_dir)
        floor = _RANK.get(self._floor, 0)
        rows = [r for r in rows if _RANK.get(str(r["severity"]).lower(), 0) >= floor]
        if self._search:
            needle = self._search.lower()
            rows = [r for r in rows if needle in " ".join(
                [r["rule_id"], r["title"], r["finding_key"], r["target"], *r["entities"]]).lower()]
        return rows

    def refresh_rows(self) -> None:
        table = self.query_one("#fd-table", DataTable)
        cursor = table.cursor_row
        self._rows = self.visible_rows()
        table.clear()
        cells = []
        for r in self._rows:
            until = (r.get("decision") or {}).get("expires_at")
            cells.append([
                Text(STATE_WORDS.get(r["state"], r["state"]), style=STATE_COLOR.get(r["state"], T.TEXT)),
                Text(r["severity"], style=T.SEVERITY_COLOR.get(r["severity"], T.TEXT)),
                r["rule_id"], r["title"], self._verdict_cell(r), r["target"],
                self._when(r["first_seen"]), self._when(r["last_seen"]),
                self._when(until) if until else "",
            ])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(3, 14), (4, 16), (5, 10), (6, 10)], headers=COLUMNS)):
            table.add_row(*row, key=self._rows[i]["finding_key"])
        if cursor is not None and self._rows:
            table.move_cursor(row=min(cursor, len(self._rows) - 1))
        self._update_banner()

    def _update_banner(self) -> None:
        view = dict(STATE_VIEWS).get(self._state, self._state)
        machine = self._target or "every machine"
        banner = Text()
        banner.append("Findings", style=f"bold {T.ACCENT}")
        banner.append(f" — {view} · {dict(SEVERITY_FLOORS)[self._floor]} · {machine}", style=T.TEXT)
        if self._search:
            banner.append(f" · matching “{self._search}”", style=T.TEXT)
        banner.append(f"   ({len(self._rows)} shown)", style=T.TEXT_DIM)
        hidden = sum(Q.hidden_counts(self._data_dir, self._target).values())
        if self._state != "decided":
            banner.append(f"\nHidden by your decisions: {hidden}", style=T.TEXT_MUTED)
            if hidden:
                banner.append(" — press s to see them", style=T.TEXT_DIM)
        if not self._rows and self._state == "open_verified":
            banner.append("\nNothing open. Findings appear here after an investigation or /run.", style=T.TEXT_DIM)
        self.query_one("#fd-banner", Static).update(banner)

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#fd-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    def note(self, renderable: Any) -> None:
        area = self.query_one("#fd-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    def _need_row(self) -> dict[str, Any] | None:
        row = self.selected()
        if row is None:
            self.note(Text("No finding selected.", style=T.TEXT_DIM))
        return row

    # -- filters -----------------------------------------------------------
    def action_cycle_state(self) -> None:
        names = [s for s, _ in STATE_VIEWS]
        self._state = names[(names.index(self._state) + 1) % len(names)] if self._state in names else names[0]
        self.refresh_rows()

    def action_cycle_severity(self) -> None:
        names = [s for s, _ in SEVERITY_FLOORS]
        self._floor = names[(names.index(self._floor) + 1) % len(names)]
        self.refresh_rows()

    @work
    async def action_pick_machine(self) -> None:
        entries: list[tuple[Any, str]] = [("", "every machine")] + [(t, t) for t in Q.targets(self._data_dir)]
        picked = await self.app.push_screen_wait(ListPickerModal("Which machine?", entries))
        if picked is None:
            return
        self._target = picked or None
        self.refresh_rows()

    @work
    async def action_search(self) -> None:
        text = await self.app.push_screen_wait(PromptModal(
            "Search findings", hint="Rule, title, IP, account, path or key. Empty clears the search.",
            initial=self._search))
        if text is None:
            return
        self._search = text
        self.refresh_rows()

    # -- details / history -------------------------------------------------
    def action_details(self) -> None:
        row = self._need_row()
        if row is None:
            return
        _rec, latest, _events = Q.get_finding(self._data_dir, row["finding_key"])
        body = Table.grid(padding=(0, 2))
        body.add_column(style=T.TEXT_DIM)
        body.add_column()
        body.add_row("rule", f"{row['rule_id']} — {annotate_lookalikes(row['title'])}")
        body.add_row("state", f"{STATE_WORDS.get(row['state'], row['state'])}  ({row['state']})")
        body.add_row("severity", row["severity"])
        body.add_row("machine", row["target"])
        body.add_row("about", annotate_lookalikes(", ".join(row["entities"])) or "-")
        for i, lab in enumerate(row.get("attack") or []):
            body.add_row("ATT&CK" if i == 0 else "", f"{format_label(lab)}\n{lab.get('url')}")
        body.add_row("seen", f"{row['times_seen']} time(s), first {self._when(row['first_seen'])}, "
                              f"last {self._when(row['last_seen'])}")
        body.add_row("last re-checked", self._when(row["last_checked"]))
        v = row.get("verdict")
        if isinstance(v, dict):
            body.add_row("verdict", f"{v.get('tag')}\n{v.get('sentence') or ''}")
            for i, c in enumerate(v.get("checks") or []):
                where = f" (over {c.get('transport')})" if c.get("transport") else ""
                body.add_row("re-read" if i == 0 else "", f"{c.get('name')}{where}")
            for i, line in enumerate((v.get("evidence") or [])[:6]):
                body.add_row("verdict evidence" if i == 0 else "", annotate_lookalikes(line))
        for i, s in enumerate(row.get("suggestions") or []):
            label = "the model suggests" if i == 0 else ""
            body.add_row(label, f"{s['kind'].replace('_', ' ')}: {annotate_lookalikes(s['why'])}  "
                                f"(#{s['id']} -- you decide; n dismisses)")
        d = row.get("decision")
        if d:
            body.add_row("decision", f"{STATE_WORDS.get(d['kind'])} — {D.SCOPE_WORDS.get(d['scope'])}, by "
                                     f"{d['decided_by']}" + (f", owner {d['owner']}" if d.get("owner") else "")
                                     + (f", until {self._when(d['expires_at'])}" if d.get("expires_at") else ""))
            body.add_row("reason", d["reason"])
        for i, line in enumerate((latest.get("evidence") or [])[:12]):
            body.add_row("evidence" if i == 0 else "", annotate_lookalikes(line))
        body.add_row("key", row["finding_key"])
        self.app.push_screen(InfoModal(f"{row['rule_id']} — details", body))

    def action_copy_attack(self) -> None:
        """Copy the selected finding's ATT&CK technique link(s) (Kratos-generated
        urls from the pinned table), one per line."""
        row = self._need_row()
        if row is None:
            return
        labels = row.get("attack") or []
        if not labels:
            self.note(Text(f"{row['rule_id']} has no ATT&CK label -- it describes exposure or a weakness, "
                           "not an attacker's action.", style=T.TEXT_DIM))
            return
        self.app.copy_to_clipboard("\n".join(f"{format_label(lab)} {lab.get('url')}" for lab in labels))
        self.note(Text(f"✓ Copied {len(labels)} ATT&CK link(s) for {row['rule_id']}.", style=T.SAFE))

    def action_history(self) -> None:
        row = self._need_row()
        if row is None:
            return
        _rec, _latest, events = Q.get_finding(self._data_dir, row["finding_key"])
        table = Table(show_header=True, header_style="bold", expand=True)
        for col in ("when", "what", "change", "by", "why"):
            table.add_column(col, overflow="fold")
        for e in events:
            move = f"{e['from_state'] or '-'} → {e['to_state']}" if e["to_state"] else ""
            table.add_row(self._when(e["at"]), e["kind"], move,
                          f"{e['actor']} ({e['interface'] or '-'})", e["reason"] or "")
        self.app.push_screen(InfoModal(f"{row['rule_id']} on {row['target']} — history", table))

    # -- decisions ---------------------------------------------------------
    def _actor(self) -> D.Actor:
        return D.Actor.current("tui")

    def _done(self, result: dict[str, Any], words: str) -> None:
        scope = result.get("scope")
        extra = f" ({D.SCOPE_WORDS[scope]})" if scope and scope != "key" else ""
        self.note(Text(f"✓ {result['finding_key'][:12]}: {words}{extra}.", style=T.SAFE))
        self.refresh_rows()

    def _refused(self, e: Exception) -> None:
        self.note(Text(f"Not changed: {e}", style=T.ATTENTION))

    async def _reason(self, title: str) -> str | None:
        text = await self.app.push_screen_wait(PromptModal(title, hint="Why? (required — saved with the decision)"))
        if text is None:
            return None
        if not text.strip():
            self._refused(D.DecisionError("a reason is required"))
            return None
        return text

    @work
    async def action_verify(self) -> None:
        row = self._need_row()
        if row is None:
            return
        reason = await self._reason(f"Confirm {row['rule_id']} is real (verify)")
        if reason is None:
            return
        try:
            self._done(D.verify(row["finding_key"], actor=self._actor(), reason=reason, data_dir=self._data_dir),
                       "confirmed real")
        except D.DecisionError as e:
            self._refused(e)

    @work
    async def action_reopen(self) -> None:
        row = self._need_row()
        if row is None:
            return
        reason = await self._reason(f"Show {row['rule_id']} again (reopen)")
        if reason is None:
            return
        try:
            self._done(D.reopen(row["finding_key"], actor=self._actor(), reason=reason, data_dir=self._data_dir),
                       "reopened")
        except D.DecisionError as e:
            self._refused(e)

    @work(thread=True)
    def action_recheck(self) -> None:
        """B.1: re-check the selected finding by a fresh read (a verdict, not the 'verify'
        decision). The read can touch SSH, so it runs off the UI thread."""
        row = self._need_row()
        if row is None:
            return
        from kratos.kratos_config import get_active_target
        from kratos.run_context import run_scope

        self.app.call_from_thread(self.note, Text(f"Re-checking {row['rule_id']}…", style=T.TEXT_DIM))
        _rec, latest, _ev = Q.get_finding(self._data_dir, row["finding_key"])
        latest.setdefault("first_seen", row.get("first_seen"))   # occurrence re-measure window
        tgt = TR.machine_of(row["target"], get_active_target() or None)   # the finding's own machine
        try:
            with run_scope("interactive", target=tgt):   # a thread worker opens its own scope
                v = TR.verify_finding(latest, data_dir=self._data_dir, target=tgt)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self.note, Text(f"Could not re-check: {e}", style=T.ATTENTION))
            return
        self.app.call_from_thread(self.note, Text(f"✓ {row['rule_id']}: {v.tag()} — {v.sentence}", style=T.SAFE))
        self.app.call_from_thread(self.refresh_rows)

    @work(thread=True)
    def action_retest(self) -> None:
        """B.1: after a fix, re-collect what covers this finding and say if it is gone."""
        row = self._need_row()
        if row is None:
            return
        from kratos.kratos_config import get_active_target
        from kratos.run_context import run_scope

        self.app.call_from_thread(self.note, Text(f"Retesting {row['rule_id']}… (re-collecting)", style=T.TEXT_DIM))
        tgt = TR.machine_of(row["target"], get_active_target() or None)   # the finding's own machine
        try:
            with run_scope("interactive", target=tgt):
                out = TR.retest(row["finding_key"], data_dir=self._data_dir, target=tgt)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self.note, Text(f"Could not retest: {e}", style=T.ATTENTION))
            return
        moved = f"{STATE_WORDS.get(out['before_state'], out['before_state'])} → " \
                f"{STATE_WORDS.get(out['after_state'], out['after_state'])}"
        v = out["verdict"]
        msg = f"✓ {out['rule_id']}: {moved}; {v['tag']} — {v['sentence']}"
        if out.get("incomplete"):
            msg += f"  (re-collection incomplete: {out['incomplete']} — left open)"
        self.app.call_from_thread(self.note, Text(msg, style=T.SAFE if out.get("fixed") else T.TEXT))
        self.app.call_from_thread(self.refresh_rows)

    def action_dismiss_suggestion(self) -> None:
        """Dismiss the newest open model suggestion on the selected finding (the model
        suggests; a person decides -- dismissing is not a finding decision)."""
        row = self._need_row()
        if row is None:
            return
        from kratos.triage import store as TS

        open_suggestions = TS.suggestions_for(self._data_dir, row["finding_key"], state="new")
        if not open_suggestions:
            self.note(Text("No model suggestion to dismiss on this finding.", style=T.TEXT_DIM))
            return
        s = open_suggestions[0]
        TS.resolve_suggestion(self._data_dir, s["id"], state="dismissed", by=D.Actor.current("tui").user)
        self.note(Text(f"Dismissed the model's suggestion (#{s['id']}).", style=T.TEXT))
        self.refresh_rows()

    def action_accept(self) -> None:
        self._decide_flow("risk_accepted")

    def action_false_positive(self) -> None:
        self._decide_flow("false_positive")

    def action_out_of_scope(self) -> None:
        self._decide_flow("out_of_scope")

    @work
    async def _decide_flow(self, kind: str) -> None:
        row = self._need_row()
        if row is None:
            return
        cap = int(settings_store.get(LS.ACCEPT_MAX_DAYS, data_dir=self._data_dir))
        actor = self._actor()
        values = await self.app.push_screen_wait(DecisionModal(
            kind, f"{row['rule_id']} — {row['title']} on {row['target']}", cap_days=cap, default_owner=actor.user))
        if values is None:
            return
        if values["scope"] == "rule":
            ok = await self.app.push_screen_wait(ConfirmModal(
                "This rule everywhere?",
                f"This decision will also cover {row['rule_id']} on EVERY machine, now and in future runs, "
                "as long as it shows nothing new. Only y confirms.", yes_label="yes, everywhere"))
            if not ok:
                self.note(Text("Not changed (you didn't confirm the rule-everywhere scope).", style=T.TEXT_DIM))
                return
        fn = {"risk_accepted": D.accept_risk, "false_positive": D.mark_false_positive,
              "out_of_scope": D.mark_out_of_scope}[kind]
        kwargs: dict[str, Any] = dict(actor=actor, reason=values["reason"], scope=values["scope"],
                                      expires_at=values["expires_at"], data_dir=self._data_dir)
        if kind == "risk_accepted":
            kwargs["owner"] = values["owner"]
        try:
            result = fn(row["finding_key"], **kwargs)
        except D.DecisionError as e:
            self._refused(e)
            return
        words = {"risk_accepted": "risk accepted", "false_positive": "marked not a real problem",
                 "out_of_scope": "marked out of scope"}[kind]
        if result.get("expires_at"):
            from kratos.utils.timeutil import epoch_to_utc_iso

            words += f" until {self._when(epoch_to_utc_iso(result['expires_at']))}"
        self._done(result, words)
