"""
Tests for kratos.subagent.whitelist_templates -- the picker+parameter-form
layer (design doc §9 #3): a user configures a vetted maintainer TEMPLATE
(enable/disable, scope which enum values are in play, extend an explicitly
extensible slot) but never authors a new argv_template. No storage/CRUD/TUI
here -- pure construction of effective ActionSpecs.
"""
from __future__ import annotations

import pytest

from kratos.subagent import whitelist as W
from kratos.subagent import whitelist_templates as T


def test_builtin_templates_cover_every_builtin_action():
    templates = T.list_builtin_templates()
    ids = {t.base.id for t in templates}
    assert ids == {s.id for s in W.list_builtin_action_specs()}


def test_only_service_templates_have_an_extensible_unit_slot():
    for t in T.list_builtin_templates():
        if "unit" in t.base.slots:
            assert "unit" in t.extensible_slots
        else:
            assert t.extensible_slots == {}


def test_get_template_by_id():
    assert T.get_template("service.enable_now") is not None
    assert T.get_template("nonexistent.action") is None


def test_default_effective_spec_matches_template_base_values():
    template = T.get_template("service.enable_now")
    effective = T.build_effective_spec(template, instance_id="e1")
    assert effective.slots["unit"].values == template.base.slots["unit"].values
    assert effective.layer == "user"
    assert effective.id == "service.enable_now.e1"
    assert effective.argv_template == template.base.argv_template


def test_narrowing_to_a_non_firewall_unit_lowers_the_tier():
    template = T.get_template("service.enable_now")
    assert template.base.reachability_adjacent is True  # the raw template spans ufw too

    narrowed = T.build_effective_spec(template, instance_id="e2", selected_values={"unit": ("fail2ban",)})
    assert narrowed.slots["unit"].values == ("fail2ban",)
    assert narrowed.reachability_adjacent is False
    assert W.compute_sensitivity_tier(narrowed) != "high"

    with_ufw = T.build_effective_spec(template, instance_id="e3", selected_values={"unit": ("fail2ban", "ufw")})
    assert with_ufw.reachability_adjacent is True
    assert W.compute_sensitivity_tier(with_ufw) == "high"


def test_selecting_a_value_outside_the_template_allowlist_is_rejected():
    template = T.get_template("service.enable_now")
    with pytest.raises(T.TemplateInstanceError):
        T.build_effective_spec(template, instance_id="e4", selected_values={"unit": ("nginx",)})


def test_extending_an_extensible_slot_with_a_new_value():
    template = T.get_template("service.enable_now")
    effective = T.build_effective_spec(
        template, instance_id="e5",
        selected_values={"unit": ("fail2ban",)},
        extra_values={"unit": ("nginx",)},
    )
    assert set(effective.slots["unit"].values) == {"fail2ban", "nginx"}
    argv = W.render_argv(effective, {"unit": "nginx"})
    assert argv == ["systemctl", "enable", "--now", "nginx"]


def test_extending_a_non_extensible_slot_is_rejected():
    template = T.get_template("fail2ban.ban_ip")
    assert template.extensible_slots == {}
    with pytest.raises(T.TemplateInstanceError):
        T.build_effective_spec(template, instance_id="e6", extra_values={"jail": ("apache",)})


def test_too_many_extra_values_rejected():
    template = T.get_template("service.enable_now")
    policy = template.extensible_slots["unit"]
    too_many = tuple(f"svc{i}" for i in range(policy.max_extra_values + 1))
    with pytest.raises(T.TemplateInstanceError):
        T.build_effective_spec(template, instance_id="e7", extra_values={"unit": too_many})


@pytest.mark.parametrize("bad_value", ["Nginx", "nginx service", "nginx;rm -rf /", "-nginx", "nginx/../etc"])
def test_extra_value_failing_the_pattern_is_rejected(bad_value):
    template = T.get_template("service.enable_now")
    with pytest.raises(T.TemplateInstanceError):
        T.build_effective_spec(template, instance_id="e8", extra_values={"unit": (bad_value,)})


def test_extending_disable_now_with_sshd_is_hard_rejected_end_to_end():
    """Even though 'sshd' matches the unit-name pattern (it's a syntactically
    fine unit name), extending service.disable_now's unit allowlist with it
    must still be caught -- by the SAME hard-exclusion machinery a
    maintainer entry goes through (design doc §9 #1: never sever your own
    access), applied to the effective merged spec, not a separate check
    special-cased for user entries."""
    template = T.get_template("service.disable_now")
    with pytest.raises(W.HardExclusionError):
        T.build_effective_spec(template, instance_id="e9", extra_values={"unit": ("sshd",)})


def test_unknown_slot_reference_is_rejected():
    template = T.get_template("service.enable_now")
    with pytest.raises(T.TemplateInstanceError):
        T.build_effective_spec(template, instance_id="e10", selected_values={"nope": ("x",)})


def test_narrowing_to_zero_values_is_rejected():
    template = T.get_template("service.enable_now")
    with pytest.raises(T.TemplateInstanceError):
        T.build_effective_spec(template, instance_id="e11", selected_values={"unit": ()})


def test_effective_spec_always_revalidates_cleanly():
    for template in T.list_builtin_templates():
        effective = T.build_effective_spec(template, instance_id="x")
        W.validate_spec(effective)  # must not raise -- redundant with build_effective_spec's own call


def test_non_enum_slots_are_never_customizable():
    template = T.get_template("fail2ban.ban_ip")
    # 'ip' is an ip-kind slot, not enum -- selected_values/extra_values for it
    # are simply ignored (not an error) since only enum slots are
    # scope/extend-able at all; it always keeps the template's own Slot object.
    effective = T.build_effective_spec(template, instance_id="e12")
    assert effective.slots["ip"] == template.base.slots["ip"]
