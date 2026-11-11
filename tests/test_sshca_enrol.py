"""D.1 enrolment: the checklist, the state machine, known_hosts, unenrol."""
from __future__ import annotations

import pytest

from kratos import kratos_config
from kratos.sshca import ca as _ca
from kratos.sshca import enrol as _enrol
from kratos.sshca import store as _store


@pytest.fixture
def dd(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    kratos_config.set_active_data_dir(data)
    yield data
    kratos_config.set_active_data_dir(None)


def test_checklist_machine_mode_has_ca_principal_and_include_detection(dd):
    plan = _enrol.build_checklist(dd, "10.0.1.5", login="ubuntu", host_cert=False, actor="t")
    c = plan.checklist
    assert _enrol.CA_FILE_ON_MACHINE in c                       # trusts the CA file
    assert "TrustedUserCAKeys" in c
    assert "AuthorizedPrincipalsFile" in c                      # machine mode: a principal file
    assert plan.principal in c and plan.principal.startswith("kratos-")
    # one block that handles BOTH drop-in and appended sshd_config (per-distro)
    assert "Include" in c and "sshd_config.d/60-kratos-ca.conf" in c and "tee -a /etc/ssh/sshd_config" in c
    assert plan.enrolment.state == "pending"                    # recorded, not yet verified


def test_checklist_simple_mode_uses_login_as_principal(dd):
    plan = _enrol.build_checklist(dd, "10.0.1.6", login="ubuntu", simple=True, host_cert=False, actor="t")
    assert plan.principal == "ubuntu"
    assert "AuthorizedPrincipalsFile" not in plan.checklist     # no per-machine principal in simple mode


def test_state_machine_moves_only_after_each_step(dd, monkeypatch):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol.build_checklist(dd, "10.0.1.7", login="ubuntu", host_cert=False, actor="t")
    monkeypatch.setattr(_enrol, "read_trusted_ca_fingerprints", lambda *a, **k: [])
    monkeypatch.setattr(_enrol, "probe_apparent_address", lambda *a, **k: None)

    # Step 1: certificate login works -> 'cert' (not cert-only).
    monkeypatch.setattr(_enrol, "_cert_login", lambda *a, **k: (True, "ok"))
    step = _enrol.verify_cert_login(dd, "10.0.1.7")
    assert step.ok and _store.get_enrolment(dd, "10.0.1.7").state == "cert"

    # Step 4 while the old key STILL works -> stays 'cert' (not certificate-only).
    monkeypatch.setattr(_enrol, "_old_key_login", lambda *a, **k: (True, "KRATOS_OLDKEY_OK"))
    step4 = _enrol.verify_old_key_refused(dd, "10.0.1.7")
    assert not step4.ok and _store.get_enrolment(dd, "10.0.1.7").state == "cert"

    # Old key removed -> refused -> 'cert_only'. A REAL refused login, not a claim.
    monkeypatch.setattr(_enrol, "_old_key_login", lambda *a, **k: (False, "Permission denied (publickey)"))
    step4b = _enrol.verify_old_key_refused(dd, "10.0.1.7")
    assert step4b.ok and _store.get_enrolment(dd, "10.0.1.7").state == "cert_only"


def test_cert_login_failure_leaves_state_pending(dd, monkeypatch):
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol.build_checklist(dd, "10.0.1.8", login="ubuntu", host_cert=False, actor="t")
    monkeypatch.setattr(_enrol, "_cert_login", lambda *a, **k: (False, "denied"))
    step = _enrol.verify_cert_login(dd, "10.0.1.8")
    assert not step.ok and _store.get_enrolment(dd, "10.0.1.8").state == "pending"


def test_rebuild_known_hosts_lists_cert_authority_for_active_host_certs(dd):
    hc = _ca.ensure_host_ca(dd, actor="t")
    _store.upsert_enrolment(dd, "10.0.1.9", login="ubuntu", principal="kratos-h",
                            principal_mode="machine", actor="t", apparent_address="192.0.2.9")
    # no host cert yet -> known_hosts empty
    kh = _enrol.rebuild_known_hosts(dd)
    assert kh.read_text().strip() == ""
    _store.set_host_cert(dd, "10.0.1.9", state="active", cert_fingerprint="SHA256:x", ca_fingerprint=hc.fingerprint)
    kh = _enrol.rebuild_known_hosts(dd)
    body = kh.read_text()
    assert body.startswith("@cert-authority 10.0.1.9,192.0.2.9 ")
    assert hc.record.public_key in body


def test_unenrol_forgets_the_machine(dd):
    _enrol.build_checklist(dd, "10.0.1.10", login="ubuntu", host_cert=False, actor="t")
    assert _store.get_enrolment(dd, "10.0.1.10") is not None
    _enrol.unenrol(dd, "10.0.1.10")
    assert _store.get_enrolment(dd, "10.0.1.10") is None


def test_principal_is_per_machine(dd):
    assert _enrol.principal_for("10.0.1.11") != _enrol.principal_for("10.0.1.12")
    assert _enrol.principal_for("10.0.1.11") == _enrol.principal_for("10.0.1.11")


def test_a_certificate_only_machine_is_never_shown_failing_the_old_key_check(dd, monkeypatch):
    """Audit D: `ssh-ca verify` on a certificate-only machine (and `--finish`) printed
    "[XX] Old key still works (nothing broken yet)" for the very result it wanted."""
    _ca.ensure_user_ca(dd, mode="file", actor="t")
    _enrol.build_checklist(dd, "10.0.1.9", login="ubuntu", host_cert=False, actor="t")
    for name in ("read_trusted_ca_fingerprints", "probe_apparent_address"):
        monkeypatch.setattr(_enrol, name, lambda *a, **k: None)
    monkeypatch.setattr(_enrol, "_cert_login", lambda *a, **k: (True, "ok"))
    monkeypatch.setattr(_enrol, "_old_key_login", lambda *a, **k: (False, "Permission denied (publickey)"))
    before = _enrol.run_full_verification(dd, "10.0.1.9", include_old_key_refused=False)
    assert "old_key_works" in [s.key for s in before.steps]          # still the safety check while moving
    finish = _enrol.run_full_verification(dd, "10.0.1.9", include_old_key_refused=True)
    assert [s.key for s in finish.steps] == ["cert_login", "old_key_refused"] and all(s.ok for s in finish.steps)
    assert finish.state == "cert_only"
    again = _enrol.run_full_verification(dd, "10.0.1.9", include_old_key_refused=False)
    assert [s.key for s in again.steps] == ["cert_login"] and again.steps[0].ok
