"""entry_builder: the logic behind the /whitelist form -- typed commands with {blanks},
exact commands, the target-side allow snippet, and matching a recommended command to an
enabled entry (the /run-fix bridge)."""
from __future__ import annotations

import os
import shlex
import stat
import subprocess

import pytest

from kratos.subagent import ceiling as C
from kratos.subagent import entry_builder as EB
from kratos.subagent import whitelist as W

CEILING = C.DEFAULT_CEILING


def test_blank_types_come_from_the_ceiling_not_the_person():
    [d] = EB.draft_command("sudo fail2ban-client set sshd banip {ip}", CEILING)
    assert d.tokens[0] == "fail2ban-client" and d.shape.id == "fail2ban.banip"
    [b] = d.blanks
    assert b.kind == "ip" and b.default_slot().ip_deny_private is True and "public" in b.describe()


def test_enum_blank_offers_only_allowed_values_minus_the_deny_list():
    [d] = EB.draft_command("systemctl disable --now {unit}", CEILING)
    vals = d.blanks[0].allowed_values()
    assert "vsftpd" in vals and "sshd" not in vals and "tailscaled" not in vals


@pytest.mark.parametrize("text,needle", [
    ("", "Type a command"),
    ("systemctl reboot", "isn't an allowed form"),
    ("rm -rf {path}", "exact command"),
    ("fail2ban-client set {x} banip {x}", "own name"),
    ("fail2ban-client set sshd banip ip{ip}", "whole word"),
    ("{prog} set sshd banip 1.2.3.4", "program itself"),
    ("fail2ban-client set 'sshd banip", "Couldn't read"),
])
def test_bad_input_gets_a_plain_explanation(text, needle):
    with pytest.raises(EB.EntryDraftError, match=needle):
        EB.draft_command(text, CEILING)


def test_a_literal_value_is_checked_against_the_ceiling_too():
    with pytest.raises(EB.EntryDraftError):
        EB.draft_command("fail2ban-client set sshd banip 10.0.0.1", CEILING)  # private IP where public is required
    assert EB.draft_command("fail2ban-client set sshd banip 8.8.8.8", CEILING)[0].blanks == []


def test_drafted_entry_passes_the_store_level_ceiling_check():
    [d] = EB.draft_command("fail2ban-client set {jail} banip {ip}", CEILING)
    spec = W.ActionSpec(id="user.custom.x1", layer="user", argv_template=tuple(d.tokens),
                        slots={b.name: b.default_slot() for b in d.blanks}, **{k: v for k, v in EB.default_texts(d.shape).items()})
    assert C.check_spec(spec, CEILING)


def test_allowed_forms_read_like_commands():
    forms = EB.allowed_forms(CEILING, "fail2ban-client")
    assert "fail2ban-client set <a short name (letters, digits, - and _)> banip <a public IP address>" in forms


# ---------------------------------------------------------------------------
# The target-side allow snippet actually produces a file the agent trusts.
# ---------------------------------------------------------------------------
def test_allow_snippet_refuses_non_plain_commands():
    with pytest.raises(C.CeilingError):
        EB.allow_file_snippet("bash -c 'id'")


def test_allow_snippet_quotes_safely_and_yields_a_trusted_file(tmp_path, monkeypatch):
    target = tmp_path / "etc" / "kratos-subagent" / "allowed-commands"
    monkeypatch.setattr(C, "LOCAL_ALLOW_FILE", str(target))
    line = "adduser --disabled-password --gecos 'Alice O' alice"
    snippet = EB.allow_file_snippet(line).replace("sudo ", "")  # run as ourselves in the test
    for _ in range(2):  # idempotent: running it twice adds the line once
        subprocess.run(["sh", "-c", snippet], check=True)
    assert target.read_text().splitlines() == [shlex.join(shlex.split(line))]
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    shapes, problems = C.load_local_commands(str(target))
    assert problems == [] and shapes[0].description == shlex.join(shlex.split(line))


# ---------------------------------------------------------------------------
# /run-fix matching
# ---------------------------------------------------------------------------
def _row(spec):
    return {"spec": spec, "state": "on", "label": spec.id}


BAN = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")


@pytest.mark.parametrize("cmd,expected", [
    ("sudo fail2ban-client set sshd banip 8.8.8.8", {"jail": "sshd", "ip": "8.8.8.8"}),
    ("/usr/bin/fail2ban-client set sshd banip 8.8.8.8", {"jail": "sshd", "ip": "8.8.8.8"}),
    ("fail2ban-client set sshd banip 10.0.0.9", None),               # value outside the slot
    ("fail2ban-client set sshd banip 8.8.8.8 && reboot", None),      # shell syntax never matches
    ("fail2ban-client set sshd banip 8.8.8.8; id", None),
    ("fail2ban-client set sshd banip", None),
    ("echo fail2ban-client set sshd banip 8.8.8.8", None),
    ("fail2ban-client set 'sshd", None),                              # unparseable
])
def test_match_recommendation(cmd, expected):
    hit = EB.match_recommendation(cmd, [_row(BAN)])
    assert (hit[1] if hit else None) == expected


def test_match_recommendation_for_an_exact_entry():
    exact = W.ActionSpec(id="user.custom.e1", layer="user", argv_template=("adduser", "--disabled-password", "alice"),
                         effect="e", reversibility="r", blast_radius="b")
    assert EB.match_recommendation("sudo adduser --disabled-password alice", [_row(exact)])[1] == {}
    assert EB.match_recommendation("adduser --disabled-password bob", [_row(exact)]) is None
