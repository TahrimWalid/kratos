"""D.4 webhook channel against a real HTTPS receiver on 127.0.0.1 (its own throwaway CA):
Standard Webhooks headers and signatures checked by an independent verifier written from
the specification (no Kratos code), redirects never followed, TLS failures retried with a
clear reason, and at most 4 KB of an error answer read."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import http.server
import json
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from kratos import kratos_config as kc
from kratos.lifecycle.decide import Actor
from kratos.outbox import alerts as A
from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox import worker as W

ACTOR = Actor(user="tester", interface="cli")


def verify_standard_webhook(secret: str, headers: dict, body: bytes, tolerance: int = 300) -> bool:
    """The receiver side, from the Standard Webhooks specification only."""
    key = base64.b64decode(secret.removeprefix("whsec_"))
    msg_id, ts = headers["webhook-id"], headers["webhook-timestamp"]
    if abs(time.time() - int(ts)) > tolerance:
        return False
    expected = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    return any(hmac.compare_digest(sig.split(",", 1)[1], expected)
               for sig in headers["webhook-signature"].split() if sig.startswith("v1,"))


def verify_v1a(whpk: str, headers: dict, body: bytes) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(whpk.removeprefix("whpk_")))
    content = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
    for sig in headers["webhook-signature"].split():
        if sig.startswith("v1a,"):
            try:
                pub.verify(base64.b64decode(sig.split(",", 1)[1]), content)
                return True
            except Exception:  # noqa: BLE001
                return False
    return False


def _cert(tmp_path, cn="localhost"):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    # Python 3.13 verifies with VERIFY_X509_STRICT: a leaf must name its issuer's key (AKI).
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(2)
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "srv.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "srv.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return tmp_path / "ca.pem"


class Receiver:
    def __init__(self, tmp_path):
        self.requests: list[tuple[str, dict, bytes]] = []
        self.status = 200
        self.extra: dict[str, str] = {}
        self.body_out = b"ok"
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("content-length") or 0)
                outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, self.rfile.read(n)))
                self.send_response(outer.status)
                for k, v in outer.extra.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(outer.body_out)))
                self.end_headers()
                self.wfile.write(outer.body_out)

            def log_message(self, *a):
                pass

        self.ca = _cert(tmp_path)
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tmp_path / "srv.pem", tmp_path / "srv.key")
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"https://localhost:{self.port}/in"

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def rx(tmp_path):
    r = Receiver(tmp_path)
    yield r
    r.close()


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    d = tmp_path / "data"
    d.mkdir()
    return d


def _add(dd, rx, **cfg):
    secret = C.new_webhook_secret()
    C.add_channel(dd, name="soc", kind="webhook", config={"url": rx.url, "ca_file": str(rx.ca), **cfg},
                  scopes=["alerts"], secrets={"signing_secret": secret}, actor=ACTOR)
    return secret


def test_headers_and_both_signatures_follow_standard_webhooks(dd, rx):
    secret = _add(dd, rx, sign_v1a=True)
    res = A.enqueue_alert("HIGH on web-01: SSH brute force", "critical", deliver=["soc"], data_dir=dd, worst="high")
    W.flush(dd, label="t")
    (path, headers, body), = rx.requests
    assert path == "/in" and headers["content-type"] == "application/json"
    assert headers["webhook-id"].startswith("msg_") and "." not in headers["webhook-id"]
    assert verify_standard_webhook(secret, headers, body)
    from kratos import signing

    assert verify_v1a(signing.public_key_whpk(dd), headers, body)
    doc = json.loads(body)
    assert doc["type"] == "kratos.alert" and doc["data"]["text"].startswith("HIGH on web-01")
    assert doc["data"]["id"] == res["message_id"]
    # a tampered body fails both
    assert not verify_standard_webhook(secret, headers, body + b" ")
    assert not verify_v1a(signing.public_key_whpk(dd), headers, body.replace(b"web-01", b"web-02"))


def test_a_retry_carries_the_same_webhook_id_and_a_fresh_valid_signature(dd, rx):
    secret = _add(dd, rx)
    rx.status = 503
    A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    rx.status = 200
    with S.opened(dd) as conn:
        conn.execute("UPDATE outbox SET next_attempt_at = 0")
    time.sleep(1.1)
    W.flush(dd, label="t")
    (_, h1, b1), (_, h2, b2) = rx.requests
    assert h1["webhook-id"] == h2["webhook-id"] and b1 == b2
    assert h1["webhook-timestamp"] != h2["webhook-timestamp"]
    assert verify_standard_webhook(secret, h2, b2)


def test_a_redirect_is_not_followed_and_is_final(dd, rx):
    _add(dd, rx)
    rx.status, rx.extra = 302, {"location": "https://elsewhere.example/in"}
    res = A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    assert len(rx.requests) == 1
    with S.opened(dd) as conn:
        row = S.get(conn, res["outbox_ids"][0])
    assert row["status"] == "dead" and "doesn't follow redirects" in row["last_error"]
    assert "elsewhere.example" in row["last_error"]


def test_a_tls_failure_is_retried_with_a_clear_reason(dd, rx, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    wrong_ca = _cert(other)
    C.add_channel(dd, name="soc", kind="webhook", config={"url": rx.url, "ca_file": str(wrong_ca)},
                  scopes=["alerts"], actor=ACTOR)
    res = A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        row = S.get(conn, res["outbox_ids"][0])
    assert row["status"] == "failed" and "TLS check failed" in row["last_error"] and rx.requests == []


def test_only_4kb_of_an_error_answer_is_read_and_secrets_never_echo(dd, rx):
    secret = _add(dd, rx)
    rx.status = 500
    rx.body_out = (b"boom " + secret.encode() + b" ") * 2000
    res = A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        row = S.get(conn, res["outbox_ids"][0])
        err = row["last_error"]
        dumped = "\n".join(str(tuple(r)) for t in ("outbox", "outbox_attempts", "channels", "channel_events")
                           for r in conn.execute(f"SELECT * FROM {t}"))
    assert row["status"] == "failed" and err.startswith("HTTP 500") and len(err) <= S.MAX_ERROR_CHARS
    assert secret not in dumped and secret[6:] not in dumped


def test_plain_http_needs_an_explicit_choice_and_a_private_address(dd):
    with pytest.raises(C.ChannelError, match="https"):
        C.add_channel(dd, name="a", kind="webhook", config={"url": "http://10.0.0.5/in"}, scopes=["alerts"],
                      actor=ACTOR)
    with pytest.raises(C.ChannelError, match="private"):
        C.add_channel(dd, name="a", kind="webhook", config={"url": "http://receiver.example/in", "allow_http": True},
                      scopes=["alerts"], actor=ACTOR)
    ch = C.add_channel(dd, name="a", kind="webhook", config={"url": "http://10.0.0.5/in", "allow_http": True},
                       scopes=["alerts"], actor=ACTOR)
    assert ch.config["allow_http"] is True
    with pytest.raises(C.ChannelError, match="user name or password"):
        C.add_channel(dd, name="b", kind="webhook", config={"url": "https://u:p@h.example/in"}, scopes=["alerts"],
                      actor=ACTOR)


def test_the_guide_receiver_snippet_verifies_a_real_delivery(dd, rx):
    """The ten-line verifier the GUIDE gives (stdlib only) accepts Kratos's request."""
    secret = _add(dd, rx)
    A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    (_, headers, body), = rx.requests
    import pathlib
    import re

    guide = (pathlib.Path(__file__).resolve().parents[1] / "docs" / "GUIDE.md").read_text()
    m = re.search(r"```python\n(# verify a Kratos webhook.*?)```", guide, re.S)
    assert m, "GUIDE has the webhook verifier snippet"
    ns: dict = {}
    exec(m.group(1), ns)  # noqa: S102 -- our own documentation's code
    assert ns["verify"](secret, headers, body) is True
    assert ns["verify"](secret, headers, body + b"x") is False


def test_a_bulk_answer_with_item_errors_is_not_counted_as_delivered(dd, rx):
    """Elasticsearch / OpenSearch answer _bulk with 200 even when a document was rejected."""
    C.add_channel(dd, name="soc", kind="webhook", config={"url": rx.url, "ca_file": str(rx.ca), "framing": "es_bulk"},
                  scopes=["alerts"], actor=ACTOR)
    rx.body_out = json.dumps({"took": 3, "errors": True, "items": [{"index": {
        "_id": "abc", "status": 400, "error": {"type": "mapper_parsing_exception",
                                               "reason": "failed to parse field [time]"}}}]}).encode()
    res = A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        row = S.get(conn, res["outbox_ids"][0])
    assert row["status"] == "dead" and "mapper_parsing_exception" in row["last_error"]
    from kratos.outbox.channels.webhook import bulk_item_failure

    assert bulk_item_failure(b'{"took":1,"errors":false,"items":[]}') is None
    assert bulk_item_failure(b'{"errors":true,"items":[{"index":{"status":429,"error":{"type":"x"}}}]}')[0] is True


def test_a_receiver_that_is_down_is_named_in_plain_words(dd):
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                         # nothing listens there now
    C.add_channel(dd, name="soc", kind="webhook", config={"url": f"https://127.0.0.1:{port}/in"}, scopes=["alerts"],
                  actor=ACTOR)
    res = A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        err = S.get(conn, res["outbox_ids"][0])["last_error"]
    assert err == f"connection refused by 127.0.0.1:{port} (is the receiver running?)"
