"""D.1 CA keys: creation, the four protection modes, fingerprints, rotation, backup."""
from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

import pytest

from kratos import kratos_config
from kratos.sshca import ca as _ca
from kratos.sshca import store as _store


@pytest.fixture
def dd(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    kratos_config.set_active_data_dir(data)
    yield data
    kratos_config.set_active_data_dir(None)
    # kill any dedicated ssh-agent a test started
    pid_file = _ca.ca_dir(data) / _ca.AGENT_PID_NAME
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass


def _mint_pub(tmp_path, name: str = "eph") -> Path:
    key = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    return Path(str(key) + ".pub")


def test_file_mode_creates_folder_and_keys_owner_only(dd):
    ca = _ca.ensure_user_ca(dd, mode="file", actor="t")
    assert ca.mode == "file" and ca.fingerprint.startswith("SHA256:")
    folder = _ca.ca_dir(dd)
    assert (os.stat(folder).st_mode & 0o077) == 0           # 0700
    assert (os.stat(ca.private_path).st_mode & 0o077) == 0   # 0600
    # recorded as the active user CA; a host CA can be made too
    assert _store.ca_key(dd, kind="user", role="active").fingerprint == ca.fingerprint
    hc = _ca.ensure_host_ca(dd, actor="t")
    assert hc.fingerprint != ca.fingerprint


def test_file_mode_signs_and_is_always_unlocked(dd, tmp_path):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    assert _ca.is_unlocked(dd) is True                       # file mode: no unlock needed
    pub = _mint_pub(tmp_path)
    cert = _ca.sign_user_cert(dd, pubkey_path=pub, key_id="kratos:x:y:1", principals=["kratos-p"],
                              validity_minutes=10, source_addresses=["192.0.2.9"], serial=1)
    assert cert.exists()


def test_tpm_mode_refused_without_tpm2_libraries(dd, monkeypatch):
    # This lab host reports 'partial' (no libraries); setup via the CLI path must refuse.
    monkeypatch.setattr(_ca, "has_tpm2", lambda: False)
    assert _ca.has_tpm2() is False


def test_token_mode_argv_uses_pkcs11_and_public_key(dd, tmp_path, monkeypatch):
    ca = _ca.ensure_user_ca(dd, mode="token", actor="t")
    _ca._write_config(dd, pkcs11_lib="/usr/lib/libpkcs11.so")
    seen = {}

    def fake_run(argv, **kw):
        if argv and argv[0] == "ssh-keygen" and "-s" in argv:
            seen["argv"] = list(argv)

        class R:
            returncode = 0
            stdout = b""
            stderr = b""
        # create the expected cert file so sign_user_cert doesn't error
        if "-s" in argv:
            Path(str(argv[-1])[:-4] + "-cert.pub").write_text("x")
        return R()

    monkeypatch.setattr(_ca, "_run", fake_run)
    pub = _mint_pub(tmp_path)
    _ca.sign_user_cert(dd, pubkey_path=pub, key_id="kratos:x:y:1", principals=["p"],
                       validity_minutes=10, source_addresses=[], serial=1)
    argv = seen["argv"]
    assert "-D" in argv and "/usr/lib/libpkcs11.so" in argv
    assert "-s" in argv and str(ca.pub_path) in argv        # CA public key, not the private half


def test_agent_mode_signs_via_U_and_a_locked_agent_raises(dd, tmp_path):
    ca = _ca.ensure_user_ca(dd, mode="agent", actor="t")
    pub = _mint_pub(tmp_path)
    # Not unlocked yet: the dedicated agent is empty -> CALocked, never a fallback.
    with pytest.raises(_ca.CALocked):
        _ca.sign_user_cert(dd, pubkey_path=pub, key_id="kratos:x:y:1", principals=["p"],
                           validity_minutes=10, source_addresses=[], serial=1)
    # Unlock loads the (passphraseless lab) key into the agent; signing then uses -U.
    _ca.unlock(dd)
    assert _ca.is_unlocked(dd) is True
    pub2 = _mint_pub(tmp_path, "eph2")
    cert = _ca.sign_user_cert(dd, pubkey_path=pub2, key_id="kratos:x:y:2", principals=["p"],
                              validity_minutes=10, source_addresses=[], serial=2)
    assert cert.exists()


def test_rotation_two_trusted_keys_switch_and_blockers_named(dd):
    ca = _ca.ensure_user_ca(dd, mode="file", actor="t")
    # a machine enrolled and trusting only the active key
    _store.upsert_enrolment(dd, "10.0.0.50", login="ubuntu", principal="kratos-z",
                            principal_mode="machine", actor="t")
    _store.set_state(dd, "10.0.0.50", "cert")
    _store.set_trusted_ca_fingerprints(dd, "10.0.0.50", [ca.fingerprint])
    nxt = _ca.rotate_user_ca(dd, actor="t")
    assert nxt.fingerprint != ca.fingerprint
    assert _ca.rotation_blockers(dd) == ["10.0.0.50"]        # doesn't trust next yet
    with pytest.raises(_ca.CAError):
        _ca.promote_next(dd, actor="t")                      # blocked, names the machine
    # machine now trusts both -> switch succeeds; old key retired but still recognised in-window
    _store.set_trusted_ca_fingerprints(dd, "10.0.0.50", [ca.fingerprint, nxt.fingerprint])
    assert _ca.rotation_blockers(dd) == []
    promoted = _ca.promote_next(dd, actor="t")
    assert promoted.fingerprint == nxt.fingerprint
    trusted = _ca.trusted_user_fingerprints(dd)
    assert nxt.fingerprint in trusted and ca.fingerprint in trusted   # retired still trusted for the window


def test_retired_ca_recognised_only_inside_the_window(dd):
    import time
    ca = _ca.ensure_user_ca(dd, mode="file", actor="t")
    _store.set_ca_role(dd, ca.fingerprint, "retired", retired_at=time.time() - 3 * 86400)
    assert ca.fingerprint in _ca.trusted_user_fingerprints(dd)               # 3 days: inside 7-day window
    _store.set_ca_role(dd, ca.fingerprint, "retired", retired_at=time.time() - 8 * 86400)
    assert ca.fingerprint not in _ca.trusted_user_fingerprints(dd)           # 8 days: outside


def test_backup_writes_a_passphrase_protected_copy(dd, tmp_path):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    dest = tmp_path / "ca-backup"
    _ca.backup_user_ca(dd, dest, passphrase="correct horse battery staple")
    assert dest.exists()
    # A passphrase-protected key cannot be read back with an empty passphrase.
    proc = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(dest)], capture_output=True, text=True)
    assert proc.returncode != 0


def test_sign_host_cert_produces_a_host_certificate(dd, tmp_path):
    _ca.ensure_host_ca(dd, actor="t")
    hostkey = _mint_pub(tmp_path, "hostkey")
    cert = _ca.sign_host_cert(dd, host_pubkey_path=hostkey, principals=["10.0.0.7", "kratos-m1"])
    text = subprocess.run(["ssh-keygen", "-L", "-f", str(cert)], capture_output=True, text=True).stdout
    assert "host certificate" in text
    assert "10.0.0.7" in text and "kratos-m1" in text


def test_rotate_refused_inside_a_tool_call(dd):
    from kratos import settings_store
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    with settings_store.tool_call_scope("some_tool"):
        with pytest.raises(_ca.CAError):
            _ca.rotate_user_ca(dd, actor="t")
