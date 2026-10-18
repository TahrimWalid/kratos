"""B.2 §5.4: the places masking can break, one test each (neutral values only)."""
from __future__ import annotations

import json

import pytest

from kratos.finding_facts import RULE_TEXT
from kratos.privacy.mask import Masker, ip_kind
from kratos.privacy.values import KnownValues
from kratos.privacy.vocabulary import fixed_words

TARGET = "192.0.2.10"


def _m(mode: str = "standard", **values) -> Masker:
    kv = KnownValues(**{"target_ips": {TARGET}, **values})
    return Masker(mode=mode, scope=None, data_dir=None, machine=TARGET, values=kv)


# --- an IP-shaped package version -------------------------------------------------------
@pytest.mark.parametrize("text", [
    "libfoo 1.2.3.4-1", "zlib1g 1:1.2.13.dfsg-1", "linux-generic 5.15.0.91.88", "bind9 1:9.18.18-0ubuntu0.22.04.2",
    '{"name": "libx", "version": "2.35.0.1"}', '{"installed_version": "4.3.2.1", "fixed": "4.3.2.2"}',
    "OID 1.3.6.1.4.1.311", "python3.10 3.10.12-1~22.04.3", "snapd 2.61.3+22.04", "v1.2.3.4+git",
    "ca-certificates 20230311ubuntu0.22.04.1", "kernel 5.14.0-362.24.1.el9_3",
])
def test_package_versions_are_not_addresses(text):
    assert _m().mask(text) == text


def test_a_package_inventory_keeps_every_version():
    inventory = {"packages": [
        {"manager": "dpkg", "name": "curl", "version": "7.88.1-10+deb12u4", "source": "curl"},
        {"manager": "dpkg", "name": "zlib1g", "version": "1:1.2.13.dfsg-1", "source": "zlib"},
        {"manager": "dpkg", "name": "openssh-server", "version": "1:9.2p1-2+deb12u2", "source": "openssh"},
        {"manager": "rpm", "name": "kernel", "version": "5.14.0-362.24.1.el9_3", "source": "kernel"},
        {"manager": "apk", "name": "musl", "version": "1.2.4-r2", "source": "musl"},
        {"manager": "dpkg", "name": "linux-image-generic", "version": "5.15.0.91.88", "source": "linux-meta"},
        {"manager": "dpkg", "name": "libfoo", "version": "2.0.1.3", "source": "foo"}]}
    text = json.dumps(inventory)
    assert _m().mask(text) == text


def test_addresses_keep_their_class_and_never_masked_ones_stay():
    out = _m().mask(f"from 203.0.113.7 and 10.1.2.3 to {TARGET}")
    assert "PUBLIC_IP_1_" in out and "PRIVATE_IP_1_" in out and "TARGET_IP_" in out
    keep = "127.0.0.1 0.0.0.0 :: ::1 224.0.0.251 ff02::1 255.255.255.255 255.255.255.0 CVE-2024-6387 T1110.001"
    assert _m().mask(keep) == keep
    assert ip_kind("100.64.1.2")[0] == "private_ip" and ip_kind("198.51.100.9")[0] == "public_ip"


# --- short usernames ------------------------------------------------------------------------
def test_short_names_are_left_in_standard_and_whole_words_in_strict():
    text = "user al logged in; ec too; alpha, special, ecology"
    m = _m(accounts={"al": 1001, "ec": 1002})
    assert m.mask(text) == text and m.stats.short_names_left == 2
    strict = _m("strict", accounts={"al": 1001, "ec": 1002}).mask(text)
    assert "user USER_" in strict and "alpha, special, ecology" in strict


# --- a username that is also a word ------------------------------------------------------
def test_a_log_only_username_that_is_a_word_changes_no_kratos_text():
    """A login attempt named after a word Kratos writes ("status", "severity", ...) is
    replaced where it appears as a name -- and nowhere in Kratos's own text."""
    from kratos.agent.loop import build_system_prompt

    word = "severity"
    assert word in fixed_words()
    system = build_system_prompt("check logins")
    rule_lines = "\n".join(f"{rid}: {text}" for rid, text in RULE_TEXT.items())
    kratos_json = json.dumps({"status": "ok", "severity": "high", "title": "SSH exposed with failed-login burst"})
    log = (f"sshd: Invalid user {word} from 203.0.113.5 port 4\n"
           + json.dumps({"top_failed_login_users": [{"user": word, "count": 3}]}))
    m = _m()
    sent_system, sent_prompt = m.mask_request(system, "\n".join((rule_lines, kratos_json, log)))
    assert sent_system.startswith(system)                          # only the placeholder note is added
    assert rule_lines in sent_prompt and kratos_json in sent_prompt
    assert f"Invalid user {word} from" not in sent_prompt and f'"user": "{word}"' not in sent_prompt
    assert m.restore(sent_prompt) == "\n".join((rule_lines, kratos_json, log))


def test_a_trusted_account_named_like_a_kratos_word_is_masked_only_as_a_name():
    m = _m(accounts={"backup": 1002}, account_list_complete=True)
    text = "Accepted password for backup from 203.0.113.5\nMalicious files: check the backup folder"
    out = m.mask(text)
    assert "Accepted password for USER_" in out and "check the backup folder" in out


def test_a_trusted_account_that_is_no_word_is_masked_everywhere():
    out = _m(accounts={"alice": 1001}).mask("alice's notes: alice ran it; /home/alice/.ssh")
    assert "alice" not in out


def test_a_log_only_name_is_masked_only_in_its_field():
    out = _m().mask('{"user": "carol"} and later the word carol in prose')
    assert '"user": "USER_' in out and "the word carol in prose" in out


def test_dictionary_guesses_stay_readable_only_in_standard():
    text = "sshd: Invalid user oracle from 203.0.113.5\nsshd: Invalid user qz_rare from 203.0.113.5"
    out = _m().mask(text)
    assert "Invalid user oracle from" in out and "qz_rare" not in out and "INVALID_USER_1_" in out
    assert "oracle" not in _m("strict").mask(text)


def test_image_default_logins_stay_readable_in_standard():
    out = _m(accounts={"ubuntu": 1000, "alice": 1001}).mask("ID=ubuntu; ubuntu and alice logged in")
    assert "ID=ubuntu; ubuntu and USER_1_" in out
    assert "ubuntu" not in _m("strict", accounts={"ubuntu": 1000}).mask("ubuntu logged in")


def test_system_accounts_follow_the_machines_uids():
    out = _m(accounts={"builder": 999, "carol": 1001}, account_list_complete=True).mask("builder carol root sshd")
    assert out.startswith("builder USER_1_") and out.endswith(" root sshd")


# --- paths ------------------------------------------------------------------------------------
def test_home_paths_keep_their_shape_and_restore():
    m = _m(accounts={"alice": 1001})
    out = m.mask("/home/alice/.ssh/authorized_keys and /home/alice/.bashrc")
    tag = m.tag
    assert out == f"/home/USER_1_{tag}/.ssh/authorized_keys and /home/USER_1_{tag}/.bashrc"
    assert m.restore(f'{{"path": "/home/USER_1_{tag}/.bashrc"}}') == '{"path": "/home/alice/.bashrc"}'


# --- names next to an @ ------------------------------------------------------------------
def test_systemd_units_are_not_logins_and_key_comments_are():
    out = _m().mask("unit user@1000.service getty@tty1.service; key bob@laptop9")
    assert "user@1000.service getty@tty1.service" in out
    assert "bob" not in out and "laptop9" not in out
