"""Every local entry point and what it needs (docs/phaseD/D.7 §5.2).

The TUI and the CLI are the owner at the Kratos host -- always an admin with every
machine -- so their checks never refuse today; they are here so that (a) every action
lands in the one audit trail with the person and interface, and (b) nothing is
reachable without an actor if the identity model ever changes. Each entry is one of:

- an action: checked (and recorded) at the one dispatch point -- `cli.app.main` for
  subcommands, `SessionScreen._dispatch_slash` for slash commands;
- CORE: the command's changes go through people-only functions that check themselves
  (named, so `tests/test_authz_scan.py` can confirm each one calls `require`);
- READ: read-only for the owner, with the reason.

`tests/test_authz_scan.py` fails when a subcommand or slash command is missing here,
when a named core function stops calling `require`, or when a dispatch point stops
checking.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos.authz import permissions as P


@dataclass(frozen=True)
class Entry:
    action: str | None = None              # checked at the dispatch point
    core: tuple[str, ...] = ()             # "module:function" names that check themselves
    read: str = ""                         # why it is read-only for the owner

    def __post_init__(self) -> None:
        assert (self.action is not None) + bool(self.core) + bool(self.read) >= 1


def A(action: str, *core: str) -> Entry:
    return Entry(action=action, core=tuple(core))


def CORE(*core: str) -> Entry:
    return Entry(core=tuple(core))


def READ(why: str) -> Entry:
    return Entry(read=why)


_DECIDE = ("kratos.lifecycle.decide:_authorize",)
_TRIAGE_READ = "shows findings; its re-check runs reads, recorded as retest"

# --- `kratos <subcommand>` (the function argparse dispatches to) -----------------
CLI: dict[str, Entry] = {
    "cmd_analyze": A(P.CHAT),
    "cmd_assets": CORE("kratos.assets.store:_check_actor"),
    "cmd_attack_layer": READ("writes an ATT&CK Navigator file from stored findings"),
    "cmd_audit": A(P.AUDIT_READ, "kratos.authz.audit:prune"),
    "cmd_baseline_compare": A(P.INVESTIGATE),
    "cmd_baseline_create": A(P.INVESTIGATE),
    "cmd_budget": CORE("kratos.settings_store:set", "kratos.budget.breaker:resume"),
    "cmd_channels": CORE("kratos.outbox.config:_check_actor"),
    "cmd_chat": A(P.CHAT),
    "cmd_collect": A(P.INVESTIGATE),
    "cmd_containers": A(P.INVESTIGATE),
    "cmd_context_collect": A(P.INVESTIGATE),
    "cmd_daily_report": READ("a report of stored findings"),
    "cmd_data": CORE("kratos.dataprune:apply_prune"),
    "cmd_detect": A(P.LOCAL_RUN, "kratos.detect.store:set_rule_enabled", "kratos.detect.live:set_watching"),
    "cmd_doctor": READ("a health check: reads settings, keys' fingerprints and the stores"),
    "cmd_events": READ("lists stored events"),
    "cmd_evidence": A(P.KEYS_MANAGE),
    "cmd_export": CORE("kratos.export.create:create"),
    "cmd_findings": CORE(*_DECIDE),
    "cmd_findings_generate": A(P.INVESTIGATE),
    "cmd_findings_show": READ("prints a findings report"),
    "cmd_fleet": CORE("kratos.fleet.run:run_fleet"),
    "cmd_groups": CORE("kratos.fleet.groups:_check_actor"),
    "cmd_hunt": A(P.HUNT),
    "cmd_init": A(P.SETTINGS_CHANGE),
    "cmd_investigate": A(P.INVESTIGATE),
    "cmd_llm_serve": A(P.LOCAL_RUN),
    "cmd_logs_parse": A(P.INVESTIGATE),
    "cmd_logs_patterns": READ("summarises stored log events"),
    "cmd_logs_patterns_show": READ("prints a stored summary"),
    "cmd_logs_trends": READ("summarises stored log events"),
    "cmd_mcp_serve": A(P.LOCAL_RUN),
    "cmd_network_anomalies": READ("reads a saved capture"),
    "cmd_network_capture": A(P.INVESTIGATE),
    "cmd_outbox": CORE("kratos.outbox.store:retry_now", "kratos.outbox.store:prune"),
    "cmd_prepare_bundle": A(P.LOCAL_RUN),
    "cmd_run": A(P.INVESTIGATE),
    "cmd_scan": A(P.INVESTIGATE),
    "cmd_scan_parse": READ("parses a saved scan file"),
    "cmd_scan_summary": READ("summarises a saved scan"),
    "cmd_scheduled_run": CORE("kratos.authz.check:unattended_refusal"),
    "cmd_seal": CORE("kratos.logsources.seal:_people_only"),
    "cmd_serve": CORE("kratos.serve.auth:_people_only"),
    "cmd_signing": CORE("kratos.signing:rotate"),
    "cmd_snapshots": CORE("kratos.timewin.snapshots:apply_retention"),
    "cmd_ssh_ca": CORE("kratos.sshca.ca:_authorize_ca", "kratos.sshca.enrol:build_checklist",
                       "kratos.sshca.enrol:unenrol"),
    "cmd_store_anomalies": READ("reads stored data"),
    "cmd_subagent_install": CORE("kratos.storage.subagent_store:SubAgentStore.create_pairing_code"),
    "cmd_subagent_pair": CORE("kratos.storage.subagent_store:SubAgentStore.create_pairing_code"),
    "cmd_subagent_serve": A(P.LOCAL_RUN),
    "cmd_subagent_status": READ("lists paired machines"),
    "cmd_subagent_tls": CORE("kratos.subagent.tls:rotate"),
    "cmd_threat_intel_sync": A(P.LOCAL_RUN),
    "cmd_tokens": CORE("kratos.serve.auth:_people_only"),
    "cmd_trace": READ("shows run records"),
    "cmd_users": CORE("kratos.authz.users:_require"),
    "cmd_vulndb_update": A(P.LOCAL_RUN),
    "cmd_vulscan_install": A(P.LOCAL_RUN),
    "cmd_weekly_report": READ("a report of stored findings"),
}

# --- TUI slash commands (SessionScreen._dispatch_slash_impl) -------------------------
_SCHED = ("kratos.agent.schedules:_authorize_change", "kratos.agent.triggers:_authorize_change")
_PRESETS = ("kratos.agent.presets:_authorize_change",)
TUI: dict[str, Entry] = {
    "/exit": READ("leaves the app"), "/quit": READ("leaves the app"),
    "/sessions": READ("back to the session list"), "/back": READ("back to the session list"),
    "/help": READ("help text"), "/guide": READ("help text"), "/start": READ("help text"),
    "/getting-started": READ("help text"),
    "/report": READ("shows stored findings"), "/usage": READ("today's spending"),
    "/context": READ("what the model sees"), "/doctor": READ("health check"), "/health": READ("health check"),
    "/trace": READ("run records"), "/traces": READ("run records"),
    "/tools": READ("lists tools"), "/preview": READ("pictures of future screens, nothing wired"),
    "/model": CORE("kratos.settings_store:set"), "/settings": CORE("kratos.settings_store:set"),
    "/timezone": A(P.SETTINGS_CHANGE),
    "/schedule": CORE(*_SCHED), "/schedules": CORE(*_SCHED),
    "/trigger": CORE(*_SCHED), "/triggers": CORE(*_SCHED),
    "/preset": CORE(*_PRESETS), "/presets": CORE(*_PRESETS), "/preset-new": CORE(*_PRESETS),
    "/preset-describe": CORE(*_PRESETS), "/describe": CORE(*_PRESETS), "/preset-scaffold": CORE(*_PRESETS),
    "/preset-new-pipeline": CORE(*_PRESETS), "/preset-list": READ("lists presets"),
    "/preset-ls": READ("lists presets"), "/preset-run": A(P.INVESTIGATE), "/preset-edit": CORE(*_PRESETS),
    "/preset-delete": CORE(*_PRESETS), "/preset-del": CORE(*_PRESETS), "/preset-show": READ("shows a preset"),
    "/preset-export": READ("writes a copy of a preset"), "/preset-import": CORE(*_PRESETS),
    "/data": CORE("kratos.dataprune:apply_prune"),
    "/collect": A(P.INVESTIGATE),
    "/clear": A(P.SESSIONS_OWN), "/compact": A(P.SESSIONS_OWN), "/reset": A(P.SESSIONS_OWN),
    "/delete": A(P.SESSIONS_OWN), "/rename": A(P.SESSIONS_OWN),
    "/target": A(P.LOCAL_RUN),
    "/ssh-ca": CORE("kratos.sshca.ca:_authorize_ca", "kratos.sshca.enrol:build_checklist"),
    "/certs": CORE("kratos.sshca.ca:_authorize_ca", "kratos.sshca.enrol:build_checklist"),
    "/ssh-cert": CORE("kratos.sshca.ca:_authorize_ca", "kratos.sshca.enrol:build_checklist"),
    "/evolve": A(P.TOOLS_MANAGE),
    "/use": A(P.INVESTIGATE), "/tool": A(P.INVESTIGATE), "/run-tool": A(P.INVESTIGATE),
    "/subagent": CORE("kratos.storage.subagent_store:SubAgentStore.create_pairing_code"),
    "/subagents": CORE("kratos.storage.subagent_store:SubAgentStore.create_pairing_code"),
    "/agents": CORE("kratos.storage.subagent_store:SubAgentStore.create_pairing_code"),
    "/connect": CORE("kratos.storage.subagent_store:SubAgentStore.create_pairing_code"),
    "/detect": CORE("kratos.detect.store:set_rule_enabled", "kratos.detect.live:set_watching"),
    "/rules": CORE("kratos.detect.store:set_rule_enabled", "kratos.detect.live:set_watching"),
    "/hunt": A(P.HUNT),
    "/export": CORE("kratos.export.create:create"),
    "/containers": READ("shows the saved container read"), "/docker": READ("shows the saved container read"),
    "/channels": CORE("kratos.outbox.config:_check_actor"),
    "/integrations": CORE("kratos.outbox.config:_check_actor"),
    "/outbox": CORE("kratos.outbox.store:retry_now"),
    "/assets": CORE("kratos.assets.store:_check_actor"), "/machines": CORE("kratos.assets.store:_check_actor"),
    "/findings": CORE(*_DECIDE), "/f": CORE(*_DECIDE),
    "/whitelist": CORE("kratos.storage.whitelist_store:WhitelistStore.create_user_entry",
                       "kratos.storage.whitelist_store:WhitelistStore.set_execution_opt_in"),
    "/run-fix": CORE("kratos.storage.whitelist_store:WhitelistStore.create_dispatch_request"),
    "/run-recommended": CORE("kratos.storage.whitelist_store:WhitelistStore.create_dispatch_request"),
    "/groups": CORE("kratos.fleet.groups:_check_actor"), "/group": CORE("kratos.fleet.groups:_check_actor"),
    "/fleet": CORE("kratos.fleet.run:run_fleet"), "/look": A(P.INVESTIGATE),
    "/investigate-host": A(P.INVESTIGATE), "/investigate-self": A(P.INVESTIGATE), "/host": A(P.INVESTIGATE),
    "/run": A(P.INVESTIGATE), "/plan": READ("shows a plan without running it"),
    "/scan": A(P.INVESTIGATE), "/logs-parse": A(P.INVESTIGATE), "/findings-generate": A(P.INVESTIGATE),
    "/users": CORE("kratos.authz.users:_require", "kratos.serve.auth:_people_only"),
    "/audit": A(P.AUDIT_READ),
}


def _check(actor: Any, entry: Entry | None, what: str, data_dir: Path | str | None) -> None:
    from kratos.authz import check

    if entry is None:
        raise check.Denied(f"{what} is not in Kratos's list of entry points (kratos.authz.entrypoints)")
    if entry.action is not None:
        check.require(actor, entry.action, data_dir=data_dir, obj=what)


def require_cli(actor: Any, func_name: str, *, command: str, data_dir: Path | str | None) -> None:
    """At `kratos <command>`'s dispatch: an unknown entry point is refused (fail closed)."""
    _check(actor, CLI.get(func_name), f"kratos {command}", data_dir)


def require_tui(actor: Any, word: str, *, data_dir: Path | str | None) -> None:
    """At a slash command's dispatch. A word that isn't a built-in command is a preset name
    or a question -- those go through their own checked paths, so nothing is checked here."""
    entry = TUI.get(word)
    if entry is not None:
        _check(actor, entry, word, data_dir)
