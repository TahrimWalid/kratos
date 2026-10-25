"""Kratos's agent link keys (Phase C.4): made once, owner-only, refused when
loose or damaged, rotated by a person, never logged, inventoried as secret."""
from __future__ import annotations

import json
import logging
import multiprocessing
import os
import ssl
import stat

import pytest

from kratos import datainv, settings_store
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import pinning, tls


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_keys_are_made_once_owner_only(tmp_path):
    ks = tls.ensure_keys(tmp_path)
    d = tls.tls_dir(tmp_path)
    assert _mode(d) == 0o700
    files = sorted(p.name for p in d.iterdir())
    assert set(files) >= {tls.STATE_NAME, tls.README_NAME, ks.key_path.name, ks.backup_key_path.name,
                          ks.cert_path.name}
    for p in d.iterdir():
        if p.name != ".lock":
            assert _mode(p) == 0o600, p
    again = tls.ensure_keys(tmp_path)
    assert (again.active_pin, again.backup_pin, again.version) == (ks.active_pin, ks.backup_pin, 1)
    assert ks.active_pin != ks.backup_pin
    # the certificate carries the active key; the pin is its SPKI hash
    der = ssl.PEM_cert_to_DER_cert(ks.cert_path.read_text())
    assert pinning.spki_sha256(der).hex() == ks.active_pin
    assert tls.load_keys(tmp_path) == ks


def _make(path):
    tls.ensure_keys(path)
    return tls.load_keys(path).pins()


def test_several_processes_starting_at_once_make_one_key_set(tmp_path):
    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(6) as pool:
        results = pool.map(_make, [tmp_path] * 6)
    assert len({tuple(r) for r in results}) == 1
    assert len(list(tls.tls_dir(tmp_path).glob("key-*.pem"))) == 2


@pytest.mark.parametrize("what", ["folder", "key", "state"])
def test_loose_permissions_are_refused(tmp_path, what):
    ks = tls.ensure_keys(tmp_path)
    target = {"folder": ks.directory, "key": ks.key_path, "state": ks.directory / tls.STATE_NAME}[what]
    os.chmod(target, 0o755 if what == "folder" else 0o644)
    with pytest.raises(tls.TLSKeyError, match="read by other users"):
        tls.load_keys(tmp_path)
    with pytest.raises(tls.TLSKeyError):
        tls.ensure_keys(tmp_path)


def test_a_symlinked_key_or_a_swapped_key_is_refused(tmp_path):
    ks = tls.ensure_keys(tmp_path)
    real = ks.key_path.read_bytes()
    ks.key_path.unlink()
    elsewhere = tmp_path / "elsewhere.pem"
    elsewhere.write_bytes(real)
    os.chmod(elsewhere, 0o600)
    ks.key_path.symlink_to(elsewhere)
    with pytest.raises(tls.TLSKeyError, match="symbolic link"):
        tls.load_keys(tmp_path)
    ks.key_path.unlink()
    # the backup key in the active key's place: the record names another key
    ks.key_path.write_bytes(ks.backup_key_path.read_bytes())
    os.chmod(ks.key_path, 0o600)
    with pytest.raises(tls.TLSKeyError, match="doesn't hold the key"):
        tls.load_keys(tmp_path)


def test_rotation_promotes_the_backup_and_makes_a_new_one(tmp_path):
    before = tls.ensure_keys(tmp_path)
    old_active_file = before.key_path
    b, after = tls.rotate(tmp_path, actor="test")
    assert b == before
    assert after.version == before.version + 1
    assert after.active_pin == before.backup_pin
    assert after.backup_pin not in (before.active_pin, before.backup_pin)
    assert not old_active_file.exists()  # the retired key doesn't linger
    assert tls.load_keys(tmp_path) == after
    der = ssl.PEM_cert_to_DER_cert(after.cert_path.read_text())
    assert pinning.spki_sha256(der).hex() == before.backup_pin
    # a server context loads from the rotated files
    assert isinstance(tls.server_context(after), ssl.SSLContext)


def test_rotation_is_a_persons_decision(tmp_path):
    tls.ensure_keys(tmp_path)
    with settings_store.tool_call_scope("run_linux_command"):
        with pytest.raises(tls.TLSKeyError, match="person's decision"):
            tls.rotate(tmp_path, actor="model")
    assert tls.load_keys(tmp_path).version == 1


def test_key_material_is_never_logged(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    ks = tls.ensure_keys(tmp_path)
    cert_text = ks.cert_path.read_text()
    old_keys = [p.read_text() for p in tls.tls_dir(tmp_path).glob("key-*.pem")]
    tls.rotate(tmp_path, actor="test")
    logged = caplog.text
    assert "PRIVATE KEY" not in logged
    for text in old_keys + [p.read_text() for p in tls.tls_dir(tmp_path).glob("key-*.pem")]:
        body = "".join(text.splitlines()[1:-1])
        assert body[:40] not in logged
    assert cert_text[40:80] not in logged


def test_inventory_lists_the_keys_as_secret(tmp_path):
    cat = datainv.category("agent_link_keys")
    assert cat.personal == datainv.SECRET and "subagent-tls" in cat.files
    tls.ensure_keys(tmp_path)
    assert datainv.owner_of("subagent-tls") == "agent_link_keys"
    assert tls.tls_dir(tmp_path) not in datainv.unlisted(tmp_path)


def test_require_setting_defaults_off_and_is_people_only(tmp_path, monkeypatch):
    assert tls.require_encryption(tmp_path) is False
    settings_store.set(tls.REQUIRE, "on", data_dir=tmp_path, actor="test")
    assert tls.require_encryption(tmp_path) is True
    with settings_store.tool_call_scope("some_tool"):
        with pytest.raises(settings_store.SettingError):
            settings_store.set(tls.REQUIRE, "off", data_dir=tmp_path, actor="model")
    assert tls.require_encryption(tmp_path) is True


def test_status_says_which_agents_hold_which_pins_and_what_to_do(tmp_path):
    store = SubAgentStore(tmp_path / "kratos.db")
    ks = tls.ensure_keys(tmp_path)
    ids = []
    for name in ("new", "old", "plain"):
        code = store.create_pairing_code(name=name)["code"]
        ids.append(store.redeem_pairing_code(code, agent_id=name, hostname=name, agent_version="0.8.0")["target_id"])
    store.record_link(ids[0], mode=tls.LINK_TLS, pin_version=ks.version)
    store.record_link(ids[2], mode=tls.LINK_PLAIN, pin_version=None)
    st = tls.status(tmp_path, store)
    states = {a["name"]: a["state"] for a in st["agents"]}
    assert states["new"] == "encrypted" and states["plain"] == "plaintext (no key pins: g)"
    store.record_connected(ids[2], hostname="plain", agent_version="0.7.1")
    assert {a["name"]: a["state"] for a in tls.status(tmp_path, store)["agents"]}["plain"] == \
        "plaintext (agent too old: g)"
    assert "not connected" in states["old"]
    assert "Update 2 agent(s)" in st["next"]
    _, after = tls.rotate(tmp_path, actor="test")
    blockers = tls.rotate_blockers(store, after)
    assert [b["name"] for b in blockers] == ["new"]  # holds pin set 1 of 2 until it reconnects
    store.record_pin_version(ids[0], after.version)
    assert tls.rotate_blockers(store, after) == []


def test_status_reports_damaged_keys_instead_of_failing(tmp_path):
    store = SubAgentStore(tmp_path / "kratos.db")
    ks = tls.ensure_keys(tmp_path)
    (ks.directory / tls.STATE_NAME).write_text(json.dumps({"version": "x"}))
    st = tls.status(tmp_path, store)
    assert st["ok"] is False and "damaged" in st["error"]
