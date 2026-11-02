"""D.1 diagnosis of a failed certificate login, and own-login recognition for certs."""
from __future__ import annotations

from kratos.detect import own
from kratos.sshca import diagnose as _diag


# --- diagnosis: classify ssh -v output -------------------------------------
def test_classify_source_address_change():
    v = ("debug1: Server accepts key ...\n"
         "debug1: Authentications that can continue: publickey\n"
         "Certificate invalid: not permitted to connect from 203.0.113.9\n"
         "Permission denied (publickey).\n")
    assert _diag.classify_verbose(v) == _diag.CAUSE_ADDRESS


def test_classify_expired_certificate():
    v = "debug1: certificate expired at 2020-01-01T00:00:00\nPermission denied (publickey).\n"
    assert _diag.classify_verbose(v) == _diag.CAUSE_SKEW


def test_classify_old_sshd():
    v = "debug1: Remote protocol version 2.0, remote software version OpenSSH_6.2\n"
    assert _diag.classify_verbose(v) == _diag.CAUSE_SSHD_OLD


def test_classify_plain_denied_is_unknown_until_live_checks():
    v = ("debug1: Offering public key: ED25519-CERT ...\n"
         "debug1: Authentications that can continue: publickey\n"
         "Permission denied (publickey).\n")
    assert _diag.classify_verbose(v) == _diag.CAUSE_UNKNOWN


def test_every_cause_has_a_fix():
    for cause in (_diag.CAUSE_ADDRESS, _diag.CAUSE_PRINCIPAL, _diag.CAUSE_CA,
                  _diag.CAUSE_SKEW, _diag.CAUSE_SSHD_OLD, _diag.CAUSE_UNKNOWN):
        assert cause in _diag._FIX and len(_diag._FIX[cause]) > 10


# --- own-login recognition --------------------------------------------------
CA_FP = "SHA256:8zsYPH+FbpinmonqnhzGCHsJ6cqQeLD/3/nPFJoPWzE"
KEY_FP = "SHA256:OrWVNvEfVMhaRiNB4vJlpkhKHx3zEtRsqCaewQPRKvw"


def _cert_line(ca_fp: str, key_id: str = "kratos:m:r:3") -> str:
    return (f"Accepted publickey for ubuntu from 192.0.2.5 port 50000 ssh2: ED25519-CERT "
            f"{KEY_FP} ID {key_id} (serial 3) CA ED25519 {ca_fp}")


def test_certificate_login_by_kratos_ca_is_set_aside():
    ident = own.OwnIdentity(key_fingerprints=frozenset(), ca_fingerprints=frozenset({CA_FP}))
    assert own.is_own_login("ssh_success_login", _cert_line(CA_FP), ident)


def test_forged_key_id_under_another_ca_is_not_set_aside():
    ident = own.OwnIdentity(key_fingerprints=frozenset(), ca_fingerprints=frozenset({CA_FP}))
    foreign = "SHA256:FORGEDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    assert not own.is_own_login("ssh_success_login", _cert_line(foreign), ident)


def test_key_id_without_kratos_prefix_is_not_set_aside():
    ident = own.OwnIdentity(key_fingerprints=frozenset(), ca_fingerprints=frozenset({CA_FP}))
    assert not own.is_own_login("ssh_success_login", _cert_line(CA_FP, key_id="someoneelse:1"), ident)


def test_plain_key_login_still_recognised_for_unenrolled_machines():
    ident = own.OwnIdentity(key_fingerprints=frozenset({KEY_FP}), ca_fingerprints=frozenset())
    line = f"Accepted publickey for ubuntu from 192.0.2.5 port 50000 ssh2: ED25519 {KEY_FP}"
    assert own.is_own_login("ssh_success_login", line, ident)


def test_kratos_identity_reads_ca_fingerprints_from_the_store(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    from kratos.sshca import ca as _ca
    ca = _ca.ensure_user_ca(data, mode="file", actor="t")
    ident = own.kratos_identity(data)
    assert ca.fingerprint in ident.ca_fingerprints
    assert own.is_own_login("ssh_success_login", _cert_line(ca.fingerprint), ident)
