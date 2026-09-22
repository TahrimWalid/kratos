"""
Tests for kratos.storage.whitelist_store -- per-target CRUD for the
whitelist's user layer (template instances) + maintainer per-target
enable/disable overrides. No signing, no dispatch -- this only ever answers
"what does this target's whitelist look like right now."
"""
from __future__ import annotations

import pytest

from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import whitelist as W
from kratos.subagent import whitelist_templates as T


@pytest.fixture
def store(tmp_path):
    return WhitelistStore(tmp_path / "kratos.db")


TARGET = "tgt_abc123"


# ---------------------------------------------------------------------------
# User layer CRUD.
# ---------------------------------------------------------------------------
def test_create_and_list_user_entry(store):
    entry_id = store.create_user_entry(
        TARGET, "service.enable_now", selected_values={"unit": ("fail2ban",)}
    )
    entries = store.list_user_entries(TARGET)
    assert len(entries) == 1
    e = entries[0]
    assert e.entry_id == entry_id
    assert e.enabled is True
    assert e.error is None
    assert e.effective_spec is not None
    assert e.effective_spec.slots["unit"].values == ("fail2ban",)
    assert e.tier != "high"  # narrowed away from ufw


def test_create_user_entry_requires_target_id(store):
    with pytest.raises(ValueError):
        store.create_user_entry("", "service.enable_now")


def test_create_user_entry_rejects_unknown_template(store):
    with pytest.raises(ValueError):
        store.create_user_entry(TARGET, "nonexistent.template")
    assert store.list_user_entries(TARGET) == []


def test_create_user_entry_validates_before_persisting(store):
    with pytest.raises(T.TemplateInstanceError):
        store.create_user_entry(TARGET, "service.enable_now", selected_values={"unit": ("nginx",)})
    # Nothing was written -- the invalid attempt never reached the DB.
    assert store.list_user_entries(TARGET) == []


def test_update_user_entry(store):
    entry_id = store.create_user_entry(TARGET, "service.enable_now", selected_values={"unit": ("fail2ban",)})
    store.update_user_entry(entry_id, selected_values={"unit": ("fail2ban", "ufw")})
    entries = store.list_user_entries(TARGET)
    assert set(entries[0].effective_spec.slots["unit"].values) == {"fail2ban", "ufw"}
    assert entries[0].tier == "high"


def test_update_user_entry_rejects_invalid_new_values_and_keeps_old(store):
    entry_id = store.create_user_entry(TARGET, "service.enable_now", selected_values={"unit": ("fail2ban",)})
    with pytest.raises(T.TemplateInstanceError):
        store.update_user_entry(entry_id, selected_values={"unit": ("nginx",)})
    entries = store.list_user_entries(TARGET)
    assert entries[0].effective_spec.slots["unit"].values == ("fail2ban",)  # unchanged


def test_update_unknown_entry_raises(store):
    with pytest.raises(ValueError):
        store.update_user_entry("nope", selected_values={})


def test_set_user_entry_enabled_toggle(store):
    entry_id = store.create_user_entry(TARGET, "fail2ban.ban_ip")
    store.set_user_entry_enabled(entry_id, False)
    assert store.list_user_entries(TARGET)[0].enabled is False
    store.set_user_entry_enabled(entry_id, True)
    assert store.list_user_entries(TARGET)[0].enabled is True


def test_set_enabled_on_unknown_entry_raises(store):
    with pytest.raises(ValueError):
        store.set_user_entry_enabled("nope", True)


def test_delete_user_entry(store):
    entry_id = store.create_user_entry(TARGET, "fail2ban.ban_ip")
    store.delete_user_entry(entry_id)
    assert store.list_user_entries(TARGET) == []


def test_entries_are_scoped_per_target(store):
    store.create_user_entry(TARGET, "fail2ban.ban_ip")
    store.create_user_entry("tgt_other", "fail2ban.ban_ip")
    assert len(store.list_user_entries(TARGET)) == 1
    assert len(store.list_user_entries("tgt_other")) == 1


def test_list_user_entries_surfaces_a_stale_template_as_an_error_not_a_silent_drop(store, monkeypatch):
    entry_id = store.create_user_entry(TARGET, "service.enable_now", selected_values={"unit": ("fail2ban",)})

    monkeypatch.setattr("kratos.storage.whitelist_store.T.get_template", lambda _tid: None)
    entries = store.list_user_entries(TARGET)
    assert len(entries) == 1  # still listed, not dropped
    assert entries[0].entry_id == entry_id
    assert entries[0].effective_spec is None
    assert "no longer exists" in entries[0].error


# ---------------------------------------------------------------------------
# Maintainer per-target overrides.
# ---------------------------------------------------------------------------
def test_maintainer_status_defaults_to_tier_derived_enablement(store):
    status = {row["spec"].id: row for row in store.list_maintainer_status(TARGET)}
    assert status["fail2ban.ban_ip"]["tier"] == "low"
    assert status["fail2ban.ban_ip"]["enabled"] is True
    assert status["fail2ban.ban_ip"]["overridden"] is False
    assert status["service.enable_now"]["tier"] == "high"
    assert status["service.enable_now"]["enabled"] is False  # high-tier: disabled by default
    assert status["service.enable_now"]["overridden"] is False


def test_maintainer_override_enables_a_high_tier_action(store):
    store.set_maintainer_override(TARGET, "service.enable_now", True)
    status = {row["spec"].id: row for row in store.list_maintainer_status(TARGET)}
    assert status["service.enable_now"]["enabled"] is True
    assert status["service.enable_now"]["overridden"] is True


def test_maintainer_override_disables_a_low_tier_action(store):
    store.set_maintainer_override(TARGET, "fail2ban.ban_ip", False)
    status = {row["spec"].id: row for row in store.list_maintainer_status(TARGET)}
    assert status["fail2ban.ban_ip"]["enabled"] is False


def test_clear_maintainer_override_reverts_to_default(store):
    store.set_maintainer_override(TARGET, "fail2ban.ban_ip", False)
    store.clear_maintainer_override(TARGET, "fail2ban.ban_ip")
    status = {row["spec"].id: row for row in store.list_maintainer_status(TARGET)}
    assert status["fail2ban.ban_ip"]["enabled"] is True
    assert status["fail2ban.ban_ip"]["overridden"] is False


def test_maintainer_override_rejects_unknown_action_id(store):
    with pytest.raises(ValueError):
        store.set_maintainer_override(TARGET, "no.such.action", True)


def test_maintainer_overrides_are_per_target(store):
    store.set_maintainer_override(TARGET, "fail2ban.ban_ip", False)
    other_status = {row["spec"].id: row for row in store.list_maintainer_status("tgt_other")}
    assert other_status["fail2ban.ban_ip"]["enabled"] is True  # unaffected


# ---------------------------------------------------------------------------
# Combined effective action set.
# ---------------------------------------------------------------------------
def test_effective_action_set_combines_maintainer_and_user_and_excludes_disabled(store):
    store.set_maintainer_override(TARGET, "service.enable_now", True)  # opt in a high-tier default
    user_entry = store.create_user_entry(TARGET, "fail2ban.ban_ip")
    disabled_entry = store.create_user_entry(TARGET, "fail2ban.unban_ip")
    store.set_user_entry_enabled(disabled_entry, False)

    effective = store.effective_action_set(TARGET)
    ids = {row["spec"].id for row in effective}
    assert "service.enable_now" in ids  # opted-in high-tier maintainer default
    assert "service.disable_now" not in ids  # still high-tier, not opted in
    assert any(row.get("entry_id") == user_entry for row in effective)
    assert not any(row.get("entry_id") == disabled_entry for row in effective)


def test_effective_action_set_excludes_an_invalid_user_entry(store, monkeypatch):
    entry_id = store.create_user_entry(TARGET, "fail2ban.ban_ip")
    monkeypatch.setattr("kratos.storage.whitelist_store.T.get_template", lambda _tid: None)
    effective = store.effective_action_set(TARGET)
    assert not any(row.get("entry_id") == entry_id for row in effective)


# ---------------------------------------------------------------------------
# Whitelist version -- design doc §9 #5 (anti-rollback / core-push watch).
# ---------------------------------------------------------------------------
def test_whitelist_version_starts_at_zero(store):
    assert store.get_whitelist_version(TARGET) == 0


def test_every_mutation_bumps_the_version(store):
    v0 = store.get_whitelist_version(TARGET)
    entry_id = store.create_user_entry(TARGET, "fail2ban.ban_ip")
    v1 = store.get_whitelist_version(TARGET)
    assert v1 == v0 + 1

    store.update_user_entry(entry_id, selected_values={"jail": ("sshd",)})
    assert store.get_whitelist_version(TARGET) == v1 + 1

    store.set_user_entry_enabled(entry_id, False)
    assert store.get_whitelist_version(TARGET) == v1 + 2

    store.set_maintainer_override(TARGET, "service.enable_now", True)
    assert store.get_whitelist_version(TARGET) == v1 + 3

    store.clear_maintainer_override(TARGET, "service.enable_now")
    assert store.get_whitelist_version(TARGET) == v1 + 4

    store.delete_user_entry(entry_id)
    assert store.get_whitelist_version(TARGET) == v1 + 5


def test_version_is_monotonic_and_never_decreases(store):
    entry_id = store.create_user_entry(TARGET, "fail2ban.ban_ip")
    versions = [store.get_whitelist_version(TARGET)]
    for _ in range(5):
        store.set_user_entry_enabled(entry_id, True)
        versions.append(store.get_whitelist_version(TARGET))
    assert versions == sorted(versions)
    assert len(set(versions)) == len(versions)  # strictly increasing


def test_version_is_per_target(store):
    store.create_user_entry(TARGET, "fail2ban.ban_ip")
    assert store.get_whitelist_version(TARGET) == 1
    assert store.get_whitelist_version("tgt_other") == 0


def test_failed_create_does_not_bump_version(store):
    v0 = store.get_whitelist_version(TARGET)
    with pytest.raises(ValueError):
        store.create_user_entry(TARGET, "nonexistent.template")
    assert store.get_whitelist_version(TARGET) == v0


# ---------------------------------------------------------------------------
# Control 6 -- per-target execution opt-in.
# ---------------------------------------------------------------------------
def test_execution_opt_in_defaults_to_false(store):
    assert store.get_execution_opt_in(TARGET) is False


def test_execution_opt_in_toggle(store):
    store.set_execution_opt_in(TARGET, True)
    assert store.get_execution_opt_in(TARGET) is True
    store.set_execution_opt_in(TARGET, False)
    assert store.get_execution_opt_in(TARGET) is False


def test_execution_opt_in_is_per_target(store):
    store.set_execution_opt_in(TARGET, True)
    assert store.get_execution_opt_in("tgt_other") is False


# ---------------------------------------------------------------------------
# Dispatch request queue.
# ---------------------------------------------------------------------------
def test_create_dispatch_request_requires_opt_in(store):
    with pytest.raises(ValueError):
        store.create_dispatch_request(TARGET, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 1)


def test_dispatch_request_lifecycle(store):
    store.set_execution_opt_in(TARGET, True)
    request_id = store.create_dispatch_request(TARGET, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 3)

    pending = store.list_pending_dispatch_requests(TARGET)
    assert len(pending) == 1
    assert pending[0]["request_id"] == request_id
    assert pending[0]["slot_values"] == {"jail": "sshd", "ip": "8.8.8.8"}
    assert pending[0]["whitelist_version"] == 3

    store.complete_dispatch_request(request_id, {"status": "ok", "exit_code": 0})
    assert store.list_pending_dispatch_requests(TARGET) == []

    row = store.get_dispatch_request(request_id)
    assert row["status"] == "done"
    assert row["result"] == {"status": "ok", "exit_code": 0}
    assert row["completed_at"] is not None


def test_get_dispatch_request_unknown_returns_none(store):
    assert store.get_dispatch_request("nope") is None


def test_pending_requests_are_scoped_per_target(store):
    store.set_execution_opt_in(TARGET, True)
    store.set_execution_opt_in("tgt_other", True)
    store.create_dispatch_request(TARGET, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 1)
    assert len(store.list_pending_dispatch_requests(TARGET)) == 1
    assert len(store.list_pending_dispatch_requests("tgt_other")) == 0


def test_pending_requests_ordered_oldest_first(store):
    store.set_execution_opt_in(TARGET, True)
    r1 = store.create_dispatch_request(TARGET, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 1)
    r2 = store.create_dispatch_request(TARGET, "fail2ban.ban_ip", {"jail": "sshd", "ip": "1.1.1.1"}, 1)
    pending = store.list_pending_dispatch_requests(TARGET)
    assert [p["request_id"] for p in pending] == [r1, r2]
