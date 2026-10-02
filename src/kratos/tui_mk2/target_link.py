"""
Tie a session target (the IP/hostname being investigated) to a paired
sub-agent -- explicitly, with the user's say-so (docs/subagent_read_routing.md
D3). Shared by onboarding, /target, /subagent and /doctor so the wording and
the rules are the same everywhere:

- a link is never made silently: a typed target that LOOKS like a paired box
  (same name, hostname, or the address its agent connects from) is only ever
  OFFERED; picking "Sub-agent" in onboarding is itself the explicit choice;
- every place that shows a target says how it is reached and how to change it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.text import Text

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import routing
from kratos.tui_mk2 import theme as T

MODE_OPTIONS: list[tuple[str, str]] = [
    (routing.MODE_SUBAGENT, "Through the sub-agent only — this box has no SSH from Kratos"),
    (routing.MODE_SSH_FIRST, "SSH first, sub-agent if SSH can't connect — both are set up"),
]
MODE_SUBTITLE = (
    "Through the sub-agent, Kratos reads logs, processes, open files, config and file hashes and runs YARA "
    "with the box's own rules — the agent runs only its built-in reads. Network scans (open ports, "
    "vulnerabilities) need a direct path from Kratos, so they're skipped for a sub-agent-only box and the "
    "answer says so."
)


def _store(data_dir: Path) -> SubAgentStore:
    return SubAgentStore(Path(data_dir) / "kratos.db")


def agent_label(target: dict[str, Any]) -> str:
    return target.get("name") or target.get("hostname") or target["target_id"]


def current_link(data_dir: Path, host: str) -> routing.Link | None:
    return routing.link_for(host, Path(data_dir))


def matching_agents(data_dir: Path, host: str) -> list[dict[str, Any]]:
    """Paired (not unpaired) agents that look like `host` -- by name, by the
    box's own hostname, or by the address its agent last connected from.
    Candidates to OFFER, never to apply."""
    h = routing.normalize_host(host)
    if not h or h in {"127.0.0.1", "localhost", "::1"}:
        return []
    store = _store(data_dir)
    out = []
    for t in store.list_targets(include_revoked=False):
        names = {routing.normalize_host(t.get("name") or ""), routing.normalize_host(t.get("hostname") or "")}
        conn = store.get_connection(t["target_id"]) or {}
        peer = routing.normalize_host(str(conn.get("peer") or ""))
        if h in names or (peer and h == peer):
            out.append(t)
    return out


def paired_agents(data_dir: Path) -> list[dict[str, Any]]:
    return _store(data_dir).list_targets(include_revoked=False)


def describe(data_dir: Path, host: str) -> Text:
    """One line: how this target is reached, and how to change it."""
    if not host or routing.normalize_host(host) in {"127.0.0.1", "localhost", "::1"}:
        return Text("Kratos's own host — read locally.", style=T.TEXT_MUTED)
    link = current_link(data_dir, host)
    if link is None:
        line = Text(f"{host} is reached over SSH.", style=T.TEXT_MUTED)
        if paired_agents(data_dir):
            line.append(" /target link to read it through a paired sub-agent instead.", style=T.TEXT_DIM)
        return line
    if link.revoked:
        return Text(f"{host} is linked to sub-agent {link.label}, which is no longer paired — /target link to fix.",
                    style=T.ATTENTION)
    how = "only through its sub-agent" if link.mode == routing.MODE_SUBAGENT else (
        "over SSH, falling back to its sub-agent")
    line = Text(f"{host} is reached {how} ({link.label}).", style=T.TEXT_MUTED)
    line.append(" /target link to change.", style=T.TEXT_DIM)
    return line


def apply_link(data_dir: Path, host: str, target_id: str, mode: str) -> Text:
    _store(data_dir).set_link(host, target_id, mode)
    t = _store(data_dir).get_target(target_id) or {"target_id": target_id}
    return Text(f"✓ {host} is now investigated {routing.MODE_LABELS[mode]} ({agent_label(t)}).", style=T.SAFE)


async def ask_mode(app: Any, host: str, agent: dict[str, Any]) -> str | None:
    from kratos.tui_mk2.modals import ListPickerModal

    return await app.push_screen_wait(ListPickerModal(
        f"How should Kratos read {host} through {agent_label(agent)}?", MODE_OPTIONS, subtitle=MODE_SUBTITLE))


async def offer_link(app: Any, data_dir: Path, host: str) -> str | None:
    """If `host` has no link yet but looks like a paired box, ASK whether to
    read it through that box's sub-agent. Returns the chosen mode, or None
    (no match, already linked, or declined)."""
    from kratos.tui_mk2.modals import ListPickerModal

    if current_link(data_dir, host) is not None:
        return None
    matches = matching_agents(data_dir, host)
    if not matches:
        return None
    options = [(t["target_id"], f"Yes — {agent_label(t)} ({t.get('hostname') or '?'}, agent "
                                f"{t.get('agent_version') or '?'})") for t in matches]
    options.append(("no", "No — not that box (stay with SSH)"))
    picked = await app.push_screen_wait(ListPickerModal(
        f"{host} looks like a box you've paired. Read it through that sub-agent?", options,
        subtitle="Kratos only links a target when you say so — a wrong link would read the wrong machine. "
                 "Change it any time with /target link."))
    if not picked or picked == "no":
        return None
    agent = next(t for t in matches if t["target_id"] == picked)
    mode = await ask_mode(app, host, agent)
    if mode is None:
        return None
    apply_link(data_dir, host, agent["target_id"], mode)
    return mode


async def choose_link(app: Any, data_dir: Path, host: str) -> Text | None:
    """`/target link`: pick which paired sub-agent (or none) `host` is read
    through, and how. Returns a line describing the result, or None if
    cancelled."""
    from kratos.tui_mk2.modals import ListPickerModal

    agents = paired_agents(data_dir)
    link = current_link(data_dir, host)
    if not agents and link is None:
        return Text("No sub-agents are paired yet — add one with /subagent first.", style=T.TEXT_MUTED)
    options = [(t["target_id"], f"{agent_label(t)}  ({t.get('hostname') or '?'}, agent {t.get('agent_version') or '?'})"
                + ("  ← linked now" if link and link.target_id == t["target_id"] else "")) for t in agents]
    options.append(("ssh", "None — reach it over SSH only" + ("  ← now" if link is None else "")))
    picked = await app.push_screen_wait(ListPickerModal(
        f"Which sub-agent is {host}?", options,
        subtitle="Pick the paired box this target really is. Kratos never guesses this."))
    if picked is None:
        return None
    if picked == "ssh":
        if link is not None:
            _store(data_dir).remove_link(host)
            return Text(f"✓ {host} is reached over SSH only now (unlinked from {link.label}).", style=T.SAFE)
        return Text(f"{host} stays on SSH.", style=T.TEXT_MUTED)
    agent = next(t for t in agents if t["target_id"] == picked)
    mode = await ask_mode(app, host, agent)
    if mode is None:
        return None
    return apply_link(data_dir, host, picked, mode)
