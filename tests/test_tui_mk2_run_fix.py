"""The recommend -> run bridge: after an investigation, a recommended target command that is
exactly one run of an ENABLED allowlist entry on the session target's paired sub-agent is
offered via /run-fix (which opens /whitelist's normal typed-EXECUTE gate, pre-filled)."""
from __future__ import annotations

from types import SimpleNamespace

from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.tui_mk2.screens.session import SessionScreen


def _pair(sa: SubAgentStore, name: str) -> str:
    code = sa.create_pairing_code(name=name)["code"]
    return sa.redeem_pairing_code(code, agent_id=f"a-{name}", hostname=f"host-{name}", agent_version="0.2.0")["target_id"]


def test_pairing_keeps_the_chosen_name(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "15.204.216.9")
    t = sa.get_target(tid)
    assert t["name"] == "15.204.216.9" and t["hostname"] == "host-15.204.216.9"
    code = sa.create_pairing_code()["code"]  # no name chosen -> hostname
    assert sa.get_target(sa.redeem_pairing_code(code, agent_id="z", hostname="box", agent_version="0.2.0")["target_id"])["name"] == "box"


def _match(tmp_path, target, commands):
    fake = SimpleNamespace(session_state={"targets": [target]}, _data_dir=tmp_path)
    return SessionScreen._match_runnable_fixes(fake, commands)


BAN = {"command": "sudo fail2ban-client set sshd banip 8.8.4.4", "explanation": "ban", "run_on": "target"}


def test_matching_recommendation_is_offered_for_the_right_target(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "10.136.28.168")
    [fix] = _match(tmp_path, "10.136.28.168", [BAN])
    assert fix["target_id"] == tid and fix["action_id"] == "fail2ban.ban_ip"
    assert fix["values"] == {"jail": "sshd", "ip": "8.8.4.4"}


def test_nothing_offered_when_disabled_unpaired_ambiguous_or_not_on_the_target(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    wl = WhitelistStore(tmp_path / "kratos.db")
    assert _match(tmp_path, "10.0.0.9", [BAN]) == []                        # no sub-agent for this target
    tid = _pair(sa, "web")
    assert _match(tmp_path, "web", [{**BAN, "run_on": "kratos_host"}]) == []  # meant for Kratos's own host
    assert _match(tmp_path, "web", [{**BAN, "command": BAN["command"] + " && reboot"}]) == []
    wl.set_maintainer_override(tid, "fail2ban.ban_ip", False)
    assert _match(tmp_path, "web", [BAN]) == []                              # entry turned off
    _pair(sa, "web")                                                        # a second agent also named "web"
    wl.set_maintainer_override(tid, "fail2ban.ban_ip", True)
    assert _match(tmp_path, "web", [BAN]) == []                              # ambiguous -> never guess


def test_an_explicitly_picked_machine_is_matched(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "devserver3")
    fake = SimpleNamespace(session_state={"targets": ["15.204.216.9"]}, _data_dir=tmp_path)
    assert SessionScreen._match_runnable_fixes(fake, [BAN]) == []           # no automatic tie
    [fix] = SessionScreen._match_runnable_fixes(fake, [BAN], target_id=tid)  # the user said which machine
    assert fix["target_id"] == tid
