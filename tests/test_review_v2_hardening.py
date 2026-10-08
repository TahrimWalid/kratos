"""
Review v2 hardening notes H-3 and H-5.

H-3: a denied network also denies its IPv4-mapped IPv6 form, on its own
     (not only because ip_deny_private happens to reject it too).
H-5: values that land in a generated shell script are checked by the script
     builder itself, not just by whoever calls it.
"""
from __future__ import annotations

import pytest

from kratos.adapters import privileged_accounts as PA
from kratos.subagent import ceiling as C
from kratos.subagent import whitelist as W
from kratos.timewin import measure as M


@pytest.mark.parametrize("value,ok", [
    ("100.64.0.1", False), ("::ffff:100.64.0.1", False), ("::ffff:8.8.8.8", True), ("8.8.8.8", True),
    ("fd7a:115c:a1e0::1", False), ("2001:db8::1", True),
])
def test_a_denied_network_also_denies_its_ipv4_mapped_form(value, ok):
    var = C.Var(W.Slot(kind="ip", ip_deny_private=False), deny_networks=("100.64.0.0/10", "fd7a:115c:a1e0::/48"))
    assert C._value_ok(var, value) is ok


def test_the_shipped_ban_slot_refuses_a_mapped_tailnet_address():
    assert C._value_ok(C._BANNABLE_IP, "::ffff:100.64.0.1") is False


@pytest.mark.parametrize("prefix", ["sudo", "sudo -n; id", "doas", "$(id)", "sudo -n -u root"])
def test_builders_refuse_any_other_privilege_prefix(prefix):
    with pytest.raises(ValueError):
        PA.build_script(0, prefix)
    with pytest.raises(ValueError):
        PA.build_script(0, "", sudo=prefix)
    with pytest.raises(ValueError):
        M.build_script(0, None, journalctl_prefix=prefix)


def test_builders_accept_the_real_prefixes_and_force_ints():
    for prefix in ("", "sudo -n", "sudo -n "):
        assert "journalctl" in PA.build_script(0, prefix)
        assert "journalctl" in M.build_script(0, None, journalctl_prefix=prefix)
    with pytest.raises((TypeError, ValueError)):
        PA.build_script("0; id", "")


@pytest.mark.parametrize("glob", ["/var/log/a b*", "/var/log/x;id", "var/log/rel*", "/var/log/$(id)", "/var/log/`id`"])
def test_log_globs_must_be_plain(glob):
    with pytest.raises(ValueError):
        M.build_script(0, None, classic_globs=(glob,))
    with pytest.raises(ValueError):
        M.build_script(0, None, fail2ban_glob=glob)


def test_shipped_globs_pass():
    assert M.build_script(0, None)  # CLASSIC_GLOBS + FAIL2BAN_GLOB
