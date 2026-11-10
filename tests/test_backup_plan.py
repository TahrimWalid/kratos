"""What a backup takes (kratos.backup.plan): built from the inventory, every category with
its reason, nothing outside Kratos's three folders (docs/phaseD/D.8 §3.3, §7 Completeness)."""
from __future__ import annotations

import os

import _backup_helpers as H
import pytest

from kratos import datainv
from kratos.backup import create as CR
from kratos.backup import plan as P


def _archives(plan):
    return {i.archive for i in plan.items}


def test_every_category_is_decided_with_a_reason(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    pl = P.build(r.data, roots=r)
    assert [d.key for d in pl.decisions] == [c.key for c in datainv.CATEGORIES]
    assert all(d.reason for d in pl.decisions)
    by = {d.key: d for d in pl.decisions}
    assert by["vulndb"].included is False and "vulndb-update" in by["vulndb"].reason
    assert by["subagent_installers"].included is False and "pairing code" in by["subagent_installers"].reason
    assert by["sandbox"].included is False
    assert by["agent_link_keys"].included and by["signing_key"].included and by["settings_file"].included


def test_the_dry_run_lists_every_category(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    d = CR.dry_run(r.data, dest=tmp_path / "bk", roots=r)
    assert {c["key"] for c in d["categories"]} == {c.key for c in datainv.CATEGORIES}
    assert d["files"] > 5 and "data/kratos.db" in d["databases"]
    assert not (tmp_path / "bk").exists()          # a dry run writes nothing


def test_what_goes_in(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    (r.data / "kratos-subagent-install-web.sh").write_text("CODE=1A2B-3C4D")
    (r.data / "vulndb").mkdir()
    (r.data / "vulndb" / "vulndb.sqlite").write_bytes(b"")
    (r.state / "sandbox_staging").mkdir()
    (r.state / "sandbox_staging" / "cand.py").write_text("x")
    a = _archives(P.build(r.data, roots=r))
    assert {"data/kratos.db", "config/.env", "state/kept_tools/tool_x.py", "data/sessions/s1_turn1.json",
            "data/fss/m1.json"} <= a
    assert any(x.startswith("data/subagent-tls/key-") for x in a)
    assert "data/kratos-subagent-install-web.sh" not in a
    assert not any(x.startswith("data/vulndb/") for x in a)
    assert not any(x.startswith("state/sandbox_staging") for x in a)
    assert not any(x.endswith(("-wal", "-shm")) for x in a)
    b = _archives(P.build(r.data, roots=r, include_rebuildable=True))
    assert "data/vulndb/vulndb.sqlite" in b


def test_without_secrets_leaves_out_keys_and_names_the_database_secrets(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    pl = P.build(r.data, roots=r, without_secrets=True)
    a = _archives(pl)
    assert "config/.env" not in a and not any(x.startswith(("data/subagent-tls", "data/fss", "data/signing"))
                                              for x in a)
    assert any("subagent_targets" in s for s in pl.scrubbed)


def test_exclude_empties_the_tables_in_the_copy_and_refuses_unknown(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    pl = P.build(r.data, roots=r, exclude=("host_events",))
    assert "host_events" in pl.emptied_tables
    with pytest.raises(P.PlanError):
        P.build(r.data, roots=r, exclude=("nope",))


def test_per_run_ssh_keys_and_the_ca_agent_socket_never_travel(tmp_path):
    r = H.home(tmp_path)
    ca = r.data / "ssh-ca"
    (ca / "runs" / "r1").mkdir(parents=True)
    (ca / "runs" / "r1" / "id").write_text("ephemeral")
    (ca / "agent.pid").write_text("1")
    (ca / "user_ca-abc").write_text("key")
    a = _archives(P.build(r.data, roots=r))
    assert "data/ssh-ca/user_ca-abc" in a
    assert not any("runs" in x or "agent.pid" in x for x in a)


def test_links_are_not_followed_and_are_named(tmp_path):
    r = H.home(tmp_path)
    (r.data / "sessions").mkdir()
    secret = tmp_path / "outside.txt"
    secret.write_text("not Kratos's")
    os.symlink(secret, r.data / "sessions" / "link.json")
    pl = P.build(r.data, roots=r)
    assert "data/sessions/link.json" not in _archives(pl)
    assert any("link.json" in s for s in pl.skipped)


def test_unlisted_entries_and_an_outside_ssh_key_are_named_not_taken(tmp_path, monkeypatch):
    from kratos import kratos_config

    r = H.home(tmp_path)
    (r.data / "attack_logs").mkdir()
    (r.data / "attack_logs" / "x").write_text("x")
    key = tmp_path / "id_ed25519"
    key.write_text("k")
    monkeypatch.setattr(kratos_config, "SSH_TARGET_KEY_PATH", key)
    pl = P.build(r.data, roots=r)
    whats = " ".join(i["what"] for i in pl.not_included)
    assert "attack_logs" in whats and "SSH key" in whats
    assert not any("attack_logs" in x for x in _archives(pl))


def test_a_tpm_sealed_ca_key_is_marked(tmp_path):
    r = H.home(tmp_path)
    ca = r.data / "ssh-ca"
    ca.mkdir()
    (ca / "user_ca-abc.cred").write_bytes(b"sealed")
    pl = P.build(r.data, roots=r)
    assert [i.kind for i in pl.items if i.archive == "data/ssh-ca/user_ca-abc.cred"] == ["ca_sealed"]
