"""D.1 minting, ephemeral key lifecycle, the SSH argv hook and multiplexing."""
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from kratos import kratos_config, run_context
from kratos.sshca import ca as _ca
from kratos.sshca import mint as _mint
from kratos.sshca import store as _store


@pytest.fixture
def dd(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    kratos_config.set_active_data_dir(data)
    yield data
    kratos_config.set_active_data_dir(None)
    # agent mode starts a dedicated ssh-agent; stop it (it outlived every suite run before)
    pid_file = _ca.ca_dir(data) / _ca.AGENT_PID_NAME
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass


def _enrol_cert(data: Path, host: str, principal: str = "kratos-m1", addr: str = "192.0.2.5"):
    _store.upsert_enrolment(data, host, login="ubuntu", principal=principal, principal_mode="machine",
                            actor="t", apparent_address=addr)
    _store.set_state(data, host, "cert")


def _cert_text(cert_path: Path) -> str:
    return subprocess.run(["ssh-keygen", "-L", "-f", str(cert_path)], capture_output=True, text=True).stdout


def test_minted_cert_has_no_forwarding_bounded_validity_and_source_address(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.7")
    with run_context.run_scope("cli", target="10.0.0.7"):
        m = _mint.credentials_for(dd, "10.0.0.7")
        assert m is not None
        text = _cert_text(m.cert_path)
    assert 'Key ID: "kratos:' in text
    assert "kratos-m1" in text                      # the machine's principal
    assert "source-address 192.0.2.5" in text        # bound to the machine's view of Kratos
    assert "Extensions: (none)" in text              # -O clear: no pty/forwarding/user-rc
    assert "permit-" not in text                     # nothing re-enabled
    # validity window bounded by the setting (default 10 min; -1m skew start => ~11 min)
    import re
    frm, to = re.search(r"Valid: from (\S+) to (\S+)", text).groups()
    import datetime
    span = (datetime.datetime.strptime(to, "%Y-%m-%dT%H:%M:%S")
            - datetime.datetime.strptime(frm, "%Y-%m-%dT%H:%M:%S")).total_seconds()
    assert span <= (_mint.MAX_VALIDITY_MINUTES + 2) * 60


def test_serials_are_unique_and_increasing(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.8")
    serials = []
    for i in range(3):
        with run_context.run_scope("cli", target="10.0.0.8"):
            m = _mint.credentials_for(dd, "10.0.0.8")
            serials.append(m.serial)
    assert serials == sorted(set(serials)) and len(set(serials)) == 3
    assert serials == [serials[0], serials[0] + 1, serials[0] + 2]


def test_exact_signing_argv_uses_clear_and_source_address_and_serial(dd, monkeypatch):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.9")
    seen = {}
    real = _ca._run

    def capture(argv, **kw):
        if argv and argv[0] == "ssh-keygen" and "-s" in argv:
            seen["argv"] = list(argv)
        return real(argv, **kw)

    monkeypatch.setattr(_ca, "_run", capture)
    with run_context.run_scope("cli", target="10.0.0.9"):
        _mint.credentials_for(dd, "10.0.0.9")
    argv = seen["argv"]
    assert "-O" in argv and "clear" in argv
    assert any(a.startswith("source-address=192.0.2.5") for a in argv)
    assert "-z" in argv                                  # a serial
    assert not any(a.startswith("permit-") for a in argv)
    assert "-V" in argv


def test_ephemeral_key_deleted_at_run_end_and_is_owner_only(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.10")
    with run_context.run_scope("cli", target="10.0.0.10") as ctx:
        m = _mint.credentials_for(dd, "10.0.0.10")
        assert m.key_path.exists()
        import os
        assert (os.stat(m.key_path).st_mode & 0o077) == 0   # 0600
        folder = _ca.ca_dir(dd) / "runs" / ctx.run_id
        assert folder.exists()
    assert not folder.exists()                              # cleaned at run end


def test_stale_run_folder_from_a_crash_is_swept(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.11")
    stale = _ca.ca_dir(dd) / "runs" / "deadbeef"
    stale.mkdir(parents=True)
    old = time.time() - _mint.RUN_SWEEP_AGE_SECONDS - 100
    import os
    os.utime(stale, (old, old))
    with run_context.run_scope("cli", target="10.0.0.11"):
        _mint.credentials_for(dd, "10.0.0.11")
    assert not stale.exists()


def test_control_persist_never_outlives_the_certificate(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.12")
    with run_context.run_scope("cli", target="10.0.0.12"):
        m = _mint.credentials_for(dd, "10.0.0.12")
        opts = _mint.ssh_options(m, dd)
        persist = next(int(o.split("=")[1]) for o in opts if o.startswith("ControlPersist="))
    assert persist <= m.validity_minutes * 60


def test_cache_reused_within_a_run(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.13")
    with run_context.run_scope("cli", target="10.0.0.13"):
        a = _mint.credentials_for(dd, "10.0.0.13")
        b = _mint.credentials_for(dd, "10.0.0.13")
        assert a.serial == b.serial                        # not re-minted


def test_not_enrolled_machine_returns_none(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    with run_context.run_scope("cli", target="10.0.0.99"):
        assert _mint.credentials_for(dd, "10.0.0.99") is None   # no enrolment -> old key path


def test_pending_enrolment_still_uses_old_key(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _store.upsert_enrolment(dd, "10.0.0.98", login="ubuntu", principal="kratos-x",
                            principal_mode="machine", actor="t")
    with run_context.run_scope("cli", target="10.0.0.98"):
        assert _mint.credentials_for(dd, "10.0.0.98") is None   # 'pending' -> not uses_cert


def test_locked_agent_mode_raises_cert_unavailable_never_falls_back(dd, monkeypatch):
    _ca.ensure_user_ca(dd, mode="agent", actor="t")
    _enrol_cert(dd, "10.0.0.14")
    # Agent mode with nothing loaded: signing must fail loudly, not fall back.
    monkeypatch.setattr(_ca, "_agent_has", lambda *a, **k: False)
    with run_context.run_scope("cli", target="10.0.0.14"):
        with pytest.raises(_mint.CertUnavailable):
            _mint.credentials_for(dd, "10.0.0.14")


def test_parallel_runs_on_different_machines_mint_separately(dd):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.21", principal="kratos-a")
    _enrol_cert(dd, "10.0.0.22", principal="kratos-b")
    with run_context.run_scope("cli", target="10.0.0.21"):
        ma = _mint.credentials_for(dd, "10.0.0.21")
        mb = _mint.credentials_for(dd, "10.0.0.22")
        assert ma.cert_path != mb.cert_path and ma.serial != mb.serial
        assert "kratos-a" in _cert_text(ma.cert_path) and "kratos-b" in _cert_text(mb.cert_path)


# --- the ssh_remote hook ----------------------------------------------------
def test_connection_options_uses_certificate_for_enrolled_and_key_otherwise(dd):
    from kratos.adapters import ssh_remote
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol_cert(dd, "10.0.0.31")
    with run_context.run_scope("cli", target="10.0.0.31"):
        opts = ssh_remote.connection_options("10.0.0.31", "ubuntu", dd)
    assert any(o.startswith("CertificateFile=") for o in opts)
    # a machine with no enrolment: the long-lived key, unchanged
    with run_context.run_scope("cli", target="10.0.0.32"):
        opts2 = ssh_remote.connection_options("10.0.0.32", "ubuntu", dd)
    assert not any(o.startswith("CertificateFile=") for o in opts2)
    assert any("IdentitiesOnly=yes" in o or o == "IdentitiesOnly=yes" for o in opts2)
