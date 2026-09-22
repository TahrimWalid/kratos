"""
Tests for the sub-agent action whitelist MECHANISM (control 3/3a;
kratos.subagent.whitelist) -- the inert schema/validator/hard-exclusion
library described in docs/subagent_whitelist_design.md. No storage, no CRUD,
no dispatch, no TUI -- these tests only exercise validate_spec()/render_argv()
and the illustrative §8 starter set as pure functions.
"""
from __future__ import annotations

import copy

import pytest

from kratos.subagent import whitelist as W


# ---------------------------------------------------------------------------
# The illustrative starter set itself must be internally consistent.
# ---------------------------------------------------------------------------
def test_builtin_specs_are_all_structurally_valid():
    specs = W.list_builtin_action_specs()
    assert len(specs) >= 4
    for spec in specs:
        W.validate_spec(spec)  # must not raise


def test_builtin_specs_are_not_registered_anywhere():
    # Mechanism-only: this module has no registry, dispatch function, or
    # side-effecting call anywhere -- confirmed structurally by the module's
    # own surface, not just its docstring.
    assert not hasattr(W, "dispatch")
    assert not hasattr(W, "execute")
    assert not hasattr(W, "TOOL_REGISTRY")
    assert not hasattr(W, "ACTION_REGISTRY")


def test_fail2ban_ban_ip_renders_a_safe_argv_list():
    spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
    argv = W.render_argv(spec, {"jail": "sshd", "ip": "203.0.113.7"})
    assert argv == ["fail2ban-client", "set", "sshd", "banip", "203.0.113.7"]
    assert isinstance(argv, list) and all(isinstance(t, str) for t in argv)


def test_service_enable_now_rejects_a_unit_outside_the_enum():
    spec = next(s for s in W.list_builtin_action_specs() if s.id == "service.enable_now")
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"unit": "sshd"})  # not in the fixed allowlist (fail2ban, ufw)


# ---------------------------------------------------------------------------
# §2 -- the fixed-template-never-a-string principle, structurally enforced.
# ---------------------------------------------------------------------------
def test_argv_template_must_be_a_tuple_not_a_string():
    spec = W.ActionSpec(
        id="bad.stringcmd", layer="maintainer",
        argv_template="systemctl restart fail2ban",  # a string, not a tuple -- rejected
        slots={}, effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_binary_itself_cannot_be_a_slot():
    spec = W.ActionSpec(
        id="bad.freecommand", layer="maintainer",
        argv_template=("{binary}", "restart", "fail2ban"),
        slots={"binary": W.Slot(kind="enum", values=("systemctl",))},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_partial_token_placeholder_mix_is_rejected():
    spec = W.ActionSpec(
        id="bad.partialtoken", layer="maintainer",
        argv_template=("rm", "-rf", "{path}*"),
        slots={"path": W.Slot(kind="enum", values=("/var/log/app",))},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_unused_declared_slot_is_rejected():
    spec = W.ActionSpec(
        id="bad.unusedslot", layer="maintainer",
        argv_template=("systemctl", "restart", "fail2ban"),
        slots={"unused": W.Slot(kind="enum", values=("x",))},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_undeclared_placeholder_is_rejected():
    spec = W.ActionSpec(
        id="bad.undeclared", layer="maintainer",
        argv_template=("systemctl", "restart", "{unit}"),
        slots={},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_no_path_or_freetext_slot_kind_exists():
    # Structurally impossible, not just discouraged: an unrecognized kind
    # (e.g. anyone hand-rolling a 'path' or 'freetext' kind) is rejected.
    spec = W.ActionSpec(
        id="bad.pathkind", layer="maintainer",
        argv_template=("cat", "{p}"),
        slots={"p": W.Slot(kind="path")},  # type: ignore[arg-type]
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


# ---------------------------------------------------------------------------
# §5 -- hard exclusions.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("argv0", ["sh", "bash", "python3", "eval", "env", "/usr/bin/bash"])
def test_shell_and_interpreter_binaries_are_hard_rejected(argv0):
    spec = W.ActionSpec(
        id="bad.shell", layer="maintainer",
        argv_template=(argv0, "-c", "{cmd}"),
        slots={"cmd": W.Slot(kind="token")},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


def test_shell_interpreter_hard_rejected_even_when_not_argv0():
    # sudo as argv[0] with bash buried later in the template -- the scan
    # covers every literal token, not just argv[0].
    spec = W.ActionSpec(
        id="bad.sudoshell", layer="maintainer",
        argv_template=("sudo", "bash", "-c", "{cmd}"),
        slots={"cmd": W.Slot(kind="token")},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


def test_package_manager_is_hard_rejected_even_with_an_enum_slot():
    spec = W.ActionSpec(
        id="bad.pkginstall", layer="maintainer",
        argv_template=("apt-get", "install", "-y", "{pkg}"),
        slots={"pkg": W.Slot(kind="enum", values=("nginx", "curl"))},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


@pytest.mark.parametrize("argv0", ["useradd", "usermod", "passwd", "groupadd", "visudo"])
def test_account_and_privilege_binaries_are_hard_rejected(argv0):
    spec = W.ActionSpec(
        id="bad.account", layer="maintainer",
        argv_template=(argv0, "{name}"),
        slots={"name": W.Slot(kind="token")},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


def test_ufw_allow_from_is_rejected_open_decision_6_unresolved():
    """The design doc's own §8 flags ufw.allow_from as 'proposed but flagged'
    and §9 item 6 leaves 'whether any firewall action is allowed at all' as
    an open decision for the human owner + reviewer. This module resolves
    that as default-deny, not a judgment call made here -- so the exact
    illustrative example from the doc must be rejected until that open
    decision is actually made."""
    spec = W.ActionSpec(
        id="ufw.allow_from", layer="maintainer",
        argv_template=("ufw", "allow", "from", "{ip}"),
        slots={"ip": W.Slot(kind="ip")},
        effect="Allows inbound traffic from one IP.",
        reversibility="Reversible -- ufw delete allow from <ip>.",
        blast_radius="Firewall rule change on the target.",
        sensitivity="high",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


@pytest.mark.parametrize("literal", [
    "/root/.ssh/authorized_keys",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/kratos",
    "/etc/crontab",
    "/etc/systemd/system/evil.service",
])
def test_sensitive_literal_path_is_hard_rejected(literal):
    spec = W.ActionSpec(
        id="bad.sensitiveliteral", layer="maintainer",
        argv_template=("cat", literal),
        slots={}, effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


def test_sensitive_path_hidden_inside_an_enum_value_is_hard_rejected():
    # Smuggled via a slot's fixed CHOICES, not a literal token -- the scan
    # must cover both, per §5 "checked against every entry ... at author/load
    # time" (a 'narrow-looking' enum can't smuggle a sensitive path in).
    spec = W.ActionSpec(
        id="bad.sensitiveenum", layer="maintainer",
        argv_template=("cat", "{file}"),
        slots={"file": W.Slot(kind="enum", values=("/root/.ssh/authorized_keys", "/var/log/app.log"))},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(spec)


# ---------------------------------------------------------------------------
# effect/reversibility/blast_radius must be real, human-authored text.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("field", ["effect", "reversibility", "blast_radius"])
def test_disclosure_fields_must_be_non_empty(field):
    kwargs = dict(effect="x", reversibility="x", blast_radius="x")
    kwargs[field] = "   "
    spec = W.ActionSpec(
        id="bad.emptydisclosure", layer="maintainer",
        argv_template=("systemctl", "restart", "fail2ban"),
        slots={}, **kwargs,
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_invalid_sensitivity_is_rejected():
    spec = W.ActionSpec(
        id="bad.sensitivity", layer="maintainer",
        argv_template=("systemctl", "restart", "fail2ban"),
        slots={}, effect="x", reversibility="x", blast_radius="x",
        sensitivity="extreme",  # type: ignore[arg-type]
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_invalid_layer_is_rejected():
    spec = W.ActionSpec(
        id="bad.layer", layer="ai",  # type: ignore[arg-type]
        argv_template=("systemctl", "restart", "fail2ban"),
        slots={}, effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


# ---------------------------------------------------------------------------
# §4 -- slot validators, at both definition time and render (value) time.
# ---------------------------------------------------------------------------
def test_enum_slot_requires_nonempty_unique_values():
    with pytest.raises(W.ActionSpecError):
        W._validate_slot_definition("x", W.Slot(kind="enum", values=()))
    with pytest.raises(W.ActionSpecError):
        W._validate_slot_definition("x", W.Slot(kind="enum", values=("a", "a")))


def test_int_range_requires_min_le_max():
    with pytest.raises(W.ActionSpecError):
        W._validate_slot_definition("x", W.Slot(kind="int_range", min_value=10, max_value=5))


def test_int_range_value_bounds_enforced():
    spec = W.ActionSpec(
        id="test.port2", layer="maintainer",
        argv_template=("nc", "-z", "localhost", "{port}"),
        slots={"port": W.Slot(kind="int_range", min_value=1, max_value=65535)},
        effect="x", reversibility="x", blast_radius="x",
    )
    W.validate_spec(spec)
    assert W.render_argv(spec, {"port": 22}) == ["nc", "-z", "localhost", "22"]
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"port": 0})
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"port": 70000})
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"port": True})  # bool must not sneak in as an int
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"port": "22"})  # str, not an actual int


def test_ip_slot_rejects_garbage_and_optionally_private_ranges():
    spec_public_only = W.ActionSpec(
        id="test.ip", layer="maintainer",
        argv_template=("fail2ban-client", "set", "sshd", "banip", "{ip}"),
        slots={"ip": W.Slot(kind="ip", ip_deny_private=True)},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec_public_only, {"ip": "not-an-ip"})
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec_public_only, {"ip": "10.0.0.5"})  # private, denied by this spec
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec_public_only, {"ip": "127.0.0.1"})  # loopback, denied
    # A genuinely global address (not one of the RFC 5737 documentation
    # ranges, which Python's ipaddress classifies as is_private=True).
    assert W.render_argv(spec_public_only, {"ip": "8.8.8.8"}) == \
        ["fail2ban-client", "set", "sshd", "banip", "8.8.8.8"]


@pytest.mark.parametrize("bad_value", [
    "; rm -rf /", "$(whoami)", "`whoami`", "../../etc/passwd", "/etc/shadow",
    "a && reboot", "a b", "-la", "--help", "a/b", "a.b",
])
def test_token_slot_rejects_injection_shaped_values(bad_value):
    spec = W.ActionSpec(
        id="test.token", layer="maintainer",
        argv_template=("logger", "{msg}"),
        slots={"msg": W.Slot(kind="token")},
        effect="x", reversibility="x", blast_radius="x",
    )
    W.validate_spec(spec)  # the default pattern itself must be definition-valid
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"msg": bad_value})


def test_token_slot_accepts_a_well_formed_value():
    spec = W.ActionSpec(
        id="test.token2", layer="maintainer",
        argv_template=("logger", "{msg}"),
        slots={"msg": W.Slot(kind="token")},
        effect="x", reversibility="x", blast_radius="x",
    )
    assert W.render_argv(spec, {"msg": "kratos-note-1"}) == ["logger", "kratos-note-1"]


def test_too_permissive_custom_token_pattern_is_rejected_at_definition_time():
    # A custom pattern that would accept "; rm -rf /"-shaped input must be
    # caught when the SLOT is defined, not only if someone happens to try
    # that exact value later.
    spec = W.ActionSpec(
        id="bad.permissivepattern", layer="maintainer",
        argv_template=("logger", "{msg}"),
        slots={"msg": W.Slot(kind="token", pattern=r".*", max_length=256)},
        effect="x", reversibility="x", blast_radius="x",
    )
    with pytest.raises(W.ActionSpecError):
        W.validate_spec(spec)


def test_token_max_length_enforced():
    spec = W.ActionSpec(
        id="test.tokenlen", layer="maintainer",
        argv_template=("logger", "{msg}"),
        slots={"msg": W.Slot(kind="token", max_length=4)},
        effect="x", reversibility="x", blast_radius="x",
    )
    assert W.render_argv(spec, {"msg": "abcd"}) == ["logger", "abcd"]
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"msg": "abcde"})


# ---------------------------------------------------------------------------
# render_argv's slot-set matching + re-validation-before-dispatch behavior.
# ---------------------------------------------------------------------------
def test_render_argv_rejects_missing_or_extra_slot_values():
    spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"jail": "sshd"})  # missing ip
    with pytest.raises(W.SlotValueError):
        W.render_argv(spec, {"jail": "sshd", "ip": "203.0.113.7", "extra": "1"})


def test_render_argv_never_produces_a_shell_string():
    spec = next(s for s in W.list_builtin_action_specs() if s.id == "service.restart")
    argv = W.render_argv(spec, {"unit": "fail2ban"})
    assert isinstance(argv, list)
    assert all(";" not in t and "|" not in t and "&" not in t for t in argv)


def test_validation_is_pure_and_deterministic_across_independent_calls():
    """Simulates the design doc's 'validated twice, independently' spirit
    (core validates, then the agent re-validates from its own copy) --
    calling validate_spec/render_argv on independently deep-copied spec
    objects must produce identical results, with no shared mutable state."""
    spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
    core_side = copy.deepcopy(spec)
    agent_side = copy.deepcopy(spec)
    W.validate_spec(core_side)
    W.validate_spec(agent_side)
    values = {"jail": "sshd", "ip": "198.51.100.4"}
    assert W.render_argv(core_side, values) == W.render_argv(agent_side, values)
