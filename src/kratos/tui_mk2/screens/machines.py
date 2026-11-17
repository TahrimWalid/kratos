"""/machines: one row per machine with everything about how Kratos reaches it (A5).

Before this screen, "is web-01 healthy and how do I reach it?" meant visiting the
header, /target verify, /target link, /subagent, /whitelist and /target seal. Here
each machine has one row (how it's reached, its sub-agent's connection, the last
setup check, journal sealing, continuous watching, whether fixes may run, and its
open findings) and the selected one is explained underneath. The deep screens stay
where they are; this one opens them for the selected machine.

Read-only: nothing here changes a machine or a setting.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen

from kratos.untrusted_rich import SafeText as Text
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar

_LOCAL = {"127.0.0.1", "localhost", "::1"}
_COLUMNS = ["machine", "reach", "agent", "setup", "sealed", "watch", "fixes", "findings"]
_NARROW_DROP = ("sealed", "watch")      # under 110 columns these two are in the detail pane only


def _cell(text: str, style: str) -> Text:
    return Text(text, style=style)


class MachinesScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter or f its findings · x its allowlist (fixes)\n"
                 "a sub-agents · d its detection rules · r refresh · esc back")

    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter,f", "open_findings", "findings", show=True, priority=True),
        Binding("x", "allowlist", "allowlist", show=True),
        Binding("a", "subagents", "sub-agents", show=True),
        Binding("d", "detect", "detection rules", show=False),
        Binding("r", "refresh", "refresh", show=False),
    ]

    CSS = f"""
    MachinesScreen {{ padding: 1 2; }}
    MachinesScreen #m-title {{ height: 2; padding: 0 0 1 0; }}
    MachinesScreen DataTable {{ height: auto; max-height: 55%; }}
    MachinesScreen #m-detail {{ height: 1fr; border-top: solid {T.BORDER}; padding-top: 1; }}
    MachinesScreen #m-keys {{ height: 1; background: $panel; padding: 0 1; }}
    """

    def __init__(self, data_dir: Path, *, active: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._active = active
        self._rows: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield Static("", id="m-title")
        yield DataTable(id="m-table", cursor_type="row", zebra_stripes=False)
        yield Static("", id="m-detail")
        yield Static(key_bar([("enter", "findings"), ("x", "allowlist"), ("a", "sub-agents"),
                              ("?", "all keys"), ("esc", "back")]), id="m-keys")

    def on_mount(self) -> None:
        self.action_refresh()
        self.query_one("#m-table", DataTable).focus()

    # --- data ------------------------------------------------------------------
    def _hosts(self) -> list[str]:
        """Every machine Kratos knows: session targets, the active target, machines
        with findings, linked hosts, and paired agents not linked to a host yet."""
        seen: dict[str, None] = {}

        def add(h: Any) -> None:
            h = str(h or "").strip()
            if h and h.lower() not in _LOCAL and h.lower() not in {k.lower() for k in seen}:
                seen[h] = None

        if self._active:
            add(self._active)
        try:
            from kratos.storage.session_store import SessionStore

            for s in SessionStore(self._data_dir / "kratos.db").list_recent_sessions(limit=10_000):
                for t in s.get("targets") or []:
                    add(t)
        except Exception:  # noqa: BLE001
            pass
        try:
            from kratos.lifecycle import query as Q

            for t in Q.targets(self._data_dir):
                add(t)
        except Exception:  # noqa: BLE001
            pass
        linked_ids: set[str] = set()
        try:
            from kratos.storage.subagent_store import SubAgentStore

            store = SubAgentStore(self._data_dir / "kratos.db")
            for ln in store.list_links():
                add(ln.get("host"))
                linked_ids.add(ln.get("target_id"))
            for t in store.list_targets(include_revoked=False):
                if t["target_id"] not in linked_ids:
                    add(t.get("name") or t.get("hostname") or t["target_id"])
        except Exception:  # noqa: BLE001
            pass
        return list(seen)

    def _agent_for(self, host: str, states: dict[str, Any], targets: list[dict[str, Any]]):
        """(target dict, ConnectionState, link) of the sub-agent that reads `host`, if any."""
        from kratos.subagent import routing

        link = None
        try:
            link = routing.link_for(host, self._data_dir)
        except Exception:  # noqa: BLE001
            pass
        tid = link.target_id if link is not None else None
        if tid is None:
            h = host.lower()
            for t in targets:
                if h in {(t.get("name") or "").lower(), (t.get("hostname") or "").lower()}:
                    tid = t["target_id"]
                    break
        if tid is None:
            return None, None, link
        t = next((t for t in targets if t["target_id"] == tid), {"target_id": tid})
        return t, states.get(tid), link

    def _machine(self, host: str, states: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
        from kratos.subagent import routing
        from kratos.tui_mk2 import target_memory as TM

        m: dict[str, Any] = {"host": host, "needs_look": []}
        agent, state, link = self._agent_for(host, states, targets)
        m["agent"], m["state"], m["link"] = agent, state, link
        if link is not None:
            m["reached"] = "agent" if link.mode == routing.MODE_SUBAGENT else "SSH→agent"
        else:
            m["reached"] = "SSH"
        try:
            m["setup"], m["setup_info"] = TM.setup_state(self._data_dir, host)
        except Exception:  # noqa: BLE001
            m["setup"], m["setup_info"] = "new", None
        if m["setup"] == "issues":
            m["needs_look"].append("setup check found problems")
        try:
            from kratos.logsources import seal

            m["seal"] = seal.latest_summary(self._data_dir, host)
        except Exception:  # noqa: BLE001
            m["seal"] = None
        if m["seal"] and m["seal"].get("failed"):
            m["needs_look"].append("sealed logs failed to verify")
        m["watching"] = None
        m["exec"] = None
        if agent is not None:
            try:
                from kratos.detect import live as L

                ps = L.pack_state(self._data_dir, agent["target_id"])
                m["watching"] = bool(ps and ps.get("enabled"))
                if m["watching"] and not L.health(self._data_dir, agent["target_id"]).healthy:
                    m["watching"] = "down"
                    m["needs_look"].append("continuous watching isn't running")
            except Exception:  # noqa: BLE001
                pass
            try:
                from kratos.storage.whitelist_store import WhitelistStore

                m["exec"] = WhitelistStore(self._data_dir / "kratos.db").get_execution_opt_in(agent["target_id"])
            except Exception:  # noqa: BLE001
                pass
            if state is not None and state.severity in ("attention", "critical"):
                m["needs_look"].append(f"sub-agent {state.label}")
        try:
            from kratos.lifecycle import query as Q

            open_ = Q.list_findings(self._data_dir, target=host, state="open_verified")
        except Exception:  # noqa: BLE001
            open_ = []
        m["open"] = len(open_)
        m["open_high"] = sum(1 for f in open_ if str(f.get("severity") or "").lower() in ("high", "critical"))
        if m["open_high"]:
            m["needs_look"].append(f"{m['open_high']} HIGH or CRITICAL finding(s) open")
        return m

    def _cells(self, m: dict[str, Any]) -> list[Text]:
        from kratos.subagent import status as ST
        from kratos.tui_mk2.screens.subagent import _STATE_STYLE

        name = Text(("▸ " if m["host"] == self._active else "  ") + m["host"],
                    style=f"bold {T.TEXT_BRIGHT}" if m["needs_look"] else T.TEXT)
        reached = _cell(m["reached"], T.TEXT_MUTED)
        st = m["state"]
        if st is None:
            agent = _cell("—", T.TEXT_DIM)
        else:
            glyph, color = _STATE_STYLE.get(st.state, ("○", T.TEXT_DIM))
            agent = _cell(f"{glyph} {st.label}", color)
        setup = {"ready": _cell("✓ passed", T.SAFE), "linked": _cell("—", T.TEXT_DIM),
                 "new": _cell("not checked", T.TEXT_DIM), "local": _cell("—", T.TEXT_DIM)}.get(m["setup"])
        if setup is None:
            n = (m.get("setup_info") or {}).get("issues", 0)
            setup = _cell(f"! {n} issue{'s' if n != 1 else ''}", T.ATTENTION)
        seal = m["seal"]
        if seal is None:
            sealed = _cell("no", T.TEXT_DIM)
        elif seal.get("failed"):
            sealed = _cell("! failed", T.CRITICAL)
        elif seal.get("status") == "not_verified_yet":
            sealed = _cell("key only", T.TEXT_MUTED)
        else:
            sealed = _cell("✓ yes", T.SAFE)
        w = m["watching"]
        watching = (_cell("—", T.TEXT_DIM) if w is None else _cell("! down", T.ATTENTION) if w == "down"
                    else _cell("on", T.SAFE) if w else _cell("off", T.TEXT_DIM))
        ex = m["exec"]
        fixes = (_cell("suggest", T.TEXT_MUTED) if not ex else _cell("DIRECT", f"bold {T.CRITICAL}"))
        if m["open"]:
            findings = _cell(f"{m['open']}" + (f" ({m['open_high']} high)" if m["open_high"] else ""),
                             T.CRITICAL if m["open_high"] else T.ATTENTION)
        else:
            findings = _cell("none", T.TEXT_DIM)
        return [name, reached, agent, setup, sealed, watching, fixes, findings]

    def action_refresh(self) -> None:
        from kratos.subagent import status as ST
        from kratos.storage.subagent_store import SubAgentStore
        from kratos.tui_mk2.table_fit import fit_columns

        table = self.query_one("#m-table", DataTable)
        prev = table.cursor_row
        try:
            store = SubAgentStore(self._data_dir / "kratos.db")
            assessed = ST.assess_all(store, now=ST.utc_now())
        except Exception:  # noqa: BLE001
            assessed = []
        targets = [t for t, _s in assessed]
        states = {t["target_id"]: s for t, s in assessed}
        machines = [self._machine(h, states, targets) for h in self._hosts()]
        machines.sort(key=lambda m: (not m["needs_look"], m["host"] != self._active, m["host"].lower()))
        self._rows = machines
        table.clear(columns=True)
        look = sum(1 for m in machines if m["needs_look"])
        title = Text("Machines", style=f"bold {T.ACCENT}")
        title.append(f"   {len(machines)}", style=T.TEXT_MUTED)
        if look:
            title.append(f" · {look} need{'s' if look == 1 else ''} a look", style=T.ATTENTION)
        elif machines:
            title.append(" · all fine", style=T.SAFE)
        self.query_one("#m-title", Static).update(title)
        if not machines:
            table.add_column("", width=60)
            table.add_row(Text("No machines yet. Start a session with a target, or pair a sub-agent (a).",
                               style=T.TEXT_DIM))
            self.query_one("#m-detail", Static).update("")
            return
        available = max(self.app.size.width - 6, 40)
        keep = [i for i, h in enumerate(_COLUMNS) if self.app.size.width >= 110 or h not in _NARROW_DROP]
        headers = [_COLUMNS[i] for i in keep]
        cells = [[c[i] for i in keep] for c in (self._cells(m) for m in machines)]
        rows = fit_columns(cells, available, shrink=[(0, 10), (2, 8), (len(keep) - 1, 6)], headers=headers)
        widths = [max([len(h)] + [r[i].cell_len for r in rows]) for i, h in enumerate(headers)]
        for h, w in zip(headers, widths):
            table.add_column(h, width=w)
        for r in rows:
            table.add_row(*r)
        if prev is not None and 0 <= prev < len(machines):
            table.move_cursor(row=prev)
        self._show_detail()

    # --- detail ------------------------------------------------------------------
    def _selected(self) -> dict[str, Any] | None:
        row = self.query_one("#m-table", DataTable).cursor_row
        return self._rows[row] if self._rows and row is not None and 0 <= row < len(self._rows) else None

    def _show_detail(self) -> None:
        m = self._selected()
        out = Text()
        if m is None:
            self.query_one("#m-detail", Static).update(out)
            return
        from kratos.subagent import routing
        from kratos.subagent import status as ST

        out.append(m["host"], style=f"bold {T.TEXT_BRIGHT}")
        if m["host"] == self._active:
            out.append("  · this session's machine", style=T.TEXT_DIM)
        link, agent, st = m["link"], m["agent"], m["state"]
        if link is not None:
            out.append(f"\nRead {routing.MODE_LABELS.get(link.mode, link.mode)} ({link.label}).", style=T.TEXT)
        elif agent is not None:
            out.append("\nRead over SSH. A sub-agent is paired with it — /target link reads through it instead.",
                       style=T.TEXT)
        else:
            out.append("\nRead over SSH.", style=T.TEXT)
        if st is not None:
            age = ST.human_age(ST._age(st.last_contact, ST.utc_now())) if st.last_contact else "never"
            out.append(f"\nSub-agent {st.label}: {st.reason}, last contact {age}"
                       + (f" · version {agent.get('agent_version')}" if agent and agent.get("agent_version") else ""),
                       style=T.TEXT_MUTED)
        info = m.get("setup_info") or {}
        setup_line = {"ready": "Setup check passed", "issues": f"Setup check found {info.get('issues', 0)} problem(s)",
                      "new": "Setup not checked yet"}.get(m["setup"], "")
        if setup_line:
            when = str(info.get("checked_at") or "")[:16].replace("T", " ")
            out.append(f"\n{setup_line}" + (f" ({when} UTC)" if when else "") + " · /target verify re-checks it.",
                       style=T.ATTENTION if m["setup"] == "issues" else T.TEXT_MUTED)
        seal = m["seal"]
        if seal is None:
            out.append("\nJournal not sealed · /target seal sets it up.", style=T.TEXT_DIM)
        elif seal.get("failed"):
            out.append(f"\nSealed journal FAILED to verify: {', '.join(map(str, seal['failed'][:3]))}.",
                       style=T.CRITICAL)
        else:
            out.append("\nJournal sealed" + (" — not verified yet." if seal.get("status") == "not_verified_yet"
                                             else " and verified."), style=T.TEXT_MUTED)
        w = m["watching"]
        if w is not None:
            out.append("\nContinuous watching: " + ("NOT RUNNING" if w == "down" else "on" if w else
                                                   "off (w on the sub-agents screen turns it on)"),
                       style=T.ATTENTION if w == "down" else T.TEXT_MUTED)
        if m["exec"]:
            out.append("\nFixes: DIRECT EXECUTION is on — allowed actions can run after you type EXECUTE (x).",
                       style=T.CRITICAL)
        elif agent is not None:
            out.append("\nFixes: recommend-only — Kratos suggests commands, you run them (x to review).",
                       style=T.TEXT_MUTED)
        if m["open"]:
            out.append(f"\n{m['open']} open finding(s)" + (f", {m['open_high']} HIGH or worse" if m["open_high"] else "")
                       + " — enter to open them.", style=T.CRITICAL if m["open_high"] else T.ATTENTION)
        self.query_one("#m-detail", Static).update(out)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    # --- actions ---------------------------------------------------------------------
    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        from kratos.tui_mk2.modals import InfoModal

        self.app.push_screen(InfoModal("Machines — all keys", all_keys_text(self._ALL_KEYS)))

    def action_open_findings(self) -> None:
        m = self._selected()
        if m is None:
            return
        from kratos.tui_mk2.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(self._data_dir, target=m["host"]))

    def action_detect(self) -> None:
        m = self._selected()
        if m is None:
            return
        from kratos.tui_mk2.screens.detect import DetectScreen

        self.app.push_screen(DetectScreen(self._data_dir, target=m["host"]))

    def action_allowlist(self) -> None:
        m = self._selected()
        if m is None:
            return
        if m["agent"] is None:
            self.notify(f"{m['host']} has no paired sub-agent, so nothing can run there — fixes stay recommend-only.",
                        timeout=5)
            return
        from kratos.tui_mk2.screens.whitelist import WhitelistScreen

        self.app.push_screen(WhitelistScreen(self._data_dir, target_id=m["agent"]["target_id"]))

    def action_subagents(self) -> None:
        from kratos.tui_mk2.screens.subagent import SubAgentScreen

        self.app.push_screen(SubAgentScreen(self._data_dir))

    def on_screen_resume(self) -> None:
        self.action_refresh()
