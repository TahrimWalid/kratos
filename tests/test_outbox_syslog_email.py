"""D.4 syslog over TLS and email, against real in-process TLS servers on 127.0.0.1:
RFC 5424 escaping, RFC 6587 octet counting, the server certificate always verified, no
plaintext transport offered; STARTTLS and implicit TLS verified, no attachments, one
digest per batch."""
from __future__ import annotations

import base64
import email
import re
import socket
import ssl
import threading

import pytest

from kratos import kratos_config as kc
from kratos.lifecycle.decide import Actor
from kratos.outbox import alerts as A
from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox import worker as W
from kratos.outbox.formats import FindingChange
from kratos.outbox.formats import rfc5424 as F
from kratos.outbox import render as R

from test_outbox_webhook import _cert

ACTOR = Actor(user="tester", interface="cli")


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    d = tmp_path / "data"
    d.mkdir()
    return d


def _server_ctx(tmp_path):
    ca = _cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "srv.pem", tmp_path / "srv.key")
    return ca, ctx


# --- RFC 5424 ------------------------------------------------------------------------------
def test_param_values_escape_quote_backslash_and_bracket():
    assert F.escape_param('a"b\\c]d') == 'a\\"b\\\\c\\]d'
    sd = F.structured_data([("kratos@32473", {"user": 'x"] [evil="1'})])
    assert sd == '[kratos@32473 user="x\\"\\] [evil=\\"1"]'


def test_a_message_has_the_rfc5424_shape_and_stays_under_the_size_cap():
    m = F.message(at=0, severity="high", msgid="finding", msg="hello", kratos_params={"rule": "CORR-SSH-001"},
                  host="kratos-host", sw_version="1.0")
    assert re.fullmatch(r'<107>1 1970-01-01T00:00:00\.000Z kratos-host kratos - finding '
                        r'\[origin software="Kratos" swVersion="1\.0"\]\[kratos@32473 rule="CORR-SSH-001"\] '
                        '﻿hello', m)
    big = F.message(at=0, severity="info", msgid="event", msg="x" * 50_000, kratos_params={}, host="h")
    assert len(big.encode()) <= F.MAX_BYTES


def test_octet_counting_frames_by_bytes_not_characters():
    from kratos.outbox.channels.syslog_tls import frame

    assert frame("äb") == b"3 \xc3\xa4b"


def test_no_plaintext_syslog_transport_exists():
    from kratos.outbox.channels import syslog_tls

    src = open(syslog_tls.__file__).read()
    assert "SOCK_DGRAM" not in src and "wrap_socket" in src
    assert "udp" not in C._clean_config("syslog", {"host": "logs.example"})


class SyslogTLSServer:
    def __init__(self, tmp_path):
        self.ca, ctx = _server_ctx(tmp_path)
        self.frames: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.ctx = ctx
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(c, server_side=True) as t:
                    data = b""
                    while chunk := t.recv(65536):
                        data += chunk
            except (OSError, ssl.SSLError):
                continue
            while data:                                  # RFC 6587 octet counting
                n, _, rest = data.partition(b" ")
                self.frames.append(rest[: int(n)].decode())
                data = rest[int(n):]

    def close(self):
        self.sock.close()


def _change(**kw):
    base = dict(event_id=7, change="new", at=0.0, finding_key="fk1", rule_id="CORR-SSH-001",
                machine="198.51.100.7", state="open", severity="high", title="Probable SSH brute force",
                finding={"evidence": ['user "alice"] from 203.0.113.9'], "attack": [
                    {"technique_id": "T1110.001", "technique": "Password Guessing", "tactic_id": "TA0006",
                     "tactic": "Credential Access"}]})
    base.update(kw)
    return FindingChange(**base)


def test_a_finding_reaches_a_tls_syslog_server_verified_and_framed(dd, tmp_path):
    srv = SyslogTLSServer(tmp_path)
    try:
        C.add_channel(dd, name="siem", kind="syslog", config={"host": "localhost", "port": srv.port,
                                                              "ca_file": str(srv.ca)},
                      scopes=["alerts", "findings"], format="text", actor=ACTOR)
        ch = C.get_channel(dd, "siem")
        with S.opened(dd) as conn:
            S.enqueue(conn, channel="siem", kind="finding", message_id="finding:fk1:7",
                      payload=R.finding(ch, _change(), dd), summary="x", order_key="fk1")
        W.flush(dd, label="t")
        import time

        for _ in range(50):
            if srv.frames:
                break
            time.sleep(0.05)
        (frame,), = [srv.frames]
        assert frame.startswith("<107>1 ") and " kratos - finding " in frame
        assert 'rule="CORR-SSH-001"' in frame and 'change="new"' in frame
        assert "NEW on 198.51.100.7: Probable SSH brute force (CORR-SSH-001)" in frame
    finally:
        srv.close()


def test_a_syslog_server_with_an_untrusted_certificate_is_refused_and_retried(dd, tmp_path):
    srv = SyslogTLSServer(tmp_path)
    try:
        C.add_channel(dd, name="siem", kind="syslog", config={"host": "localhost", "port": srv.port},
                      scopes=["alerts"], format="text", actor=ACTOR)        # system CAs: the test CA isn't one
        res = A.enqueue_alert("x", deliver=["siem"], data_dir=dd)
        W.flush(dd, label="t")
        with S.opened(dd) as conn:
            row = S.get(conn, res["outbox_ids"][0])
        assert row["status"] == "failed" and "TLS check failed" in row["last_error"] and srv.frames == []
    finally:
        srv.close()


def test_json_formats_over_syslog_stay_valid_json_when_shortened(dd):
    import json

    ch = C.Channel(name="s", kind="syslog", config={"host": "h", "port": 6514, "sd_pen": 32473},
                   scopes=("findings",), format="ecs")
    big = _change(finding={"evidence": ["e" * 3000] * 10, "recommendation": ["r" * 1000] * 5})
    (frame,) = R.finding(ch, big, None)["frames"]
    assert len(frame.encode()) <= F.MAX_BYTES
    doc = json.loads(frame.split("﻿", 1)[1])
    assert doc["rule"]["id"] == "CORR-SSH-001" and "evidence" not in doc["kratos"]


# --- email ---------------------------------------------------------------------------------
class SMTPServer:
    """A tiny SMTP server: STARTTLS (or implicit TLS), AUTH PLAIN, one recipient list."""

    def __init__(self, tmp_path, *, implicit=False, password="pw"):
        self.ca, self.ctx = _server_ctx(tmp_path)
        self.implicit, self.password = implicit, password
        self.messages: list[tuple[list[str], bytes]] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(c,), daemon=True).start()

    def _session(self, c):
        try:
            f = (self.ctx.wrap_socket(c, server_side=True) if self.implicit else c)
            rd = f.makefile("rb")

            def say(line):
                f.sendall(line.encode() + b"\r\n")

            say("220 test ESMTP")
            tls, rcpts, authed = self.implicit, [], False
            while True:
                line = rd.readline().decode().strip()
                cmd = line.split(" ", 1)[0].upper()
                if cmd in ("EHLO", "HELO"):
                    say("250-test")
                    if not tls:
                        say("250-STARTTLS")
                    say("250 AUTH PLAIN")
                elif cmd == "STARTTLS":
                    say("220 go")
                    f = self.ctx.wrap_socket(f, server_side=True)
                    rd, tls = f.makefile("rb"), True
                elif cmd == "AUTH":
                    raw = base64.b64decode(line.split()[2]).split(b"\0")
                    authed = raw[-1].decode() == self.password and tls
                    say("235 ok" if authed else "535 no")
                elif cmd == "MAIL":
                    say("250 ok" if authed else "530 auth first")
                elif cmd == "RCPT":
                    rcpts.append(line.split(":", 1)[1].strip(" <>"))
                    say("250 ok")
                elif cmd == "DATA":
                    say("354 go")
                    body = b""
                    while (ln := rd.readline()) not in (b".\r\n", b""):
                        body += ln
                    self.messages.append((rcpts, body))
                    say("250 queued")
                elif cmd == "QUIT":
                    say("221 bye")
                    return
                else:
                    say("502 ?")
        except (OSError, ssl.SSLError, IndexError, ValueError):
            return

    def close(self):
        self.sock.close()


def _email_channel(dd, srv, security):
    C.add_channel(dd, name="mail", kind="email",
                  config={"host": "localhost", "port": srv.port, "security": security, "from": "kratos@example.com",
                          "to": "ops@example.com, sec@example.com", "username": "kratos", "ca_file": str(srv.ca)},
                  scopes=["alerts", "findings"], secrets={"password": "pw"}, actor=ACTOR)


@pytest.mark.parametrize("security,implicit", [("starttls", False), ("tls", True)])
def test_email_goes_out_over_verified_tls_as_text_and_html_without_attachments(dd, tmp_path, security, implicit):
    srv = SMTPServer(tmp_path, implicit=implicit)
    try:
        _email_channel(dd, srv, security)
        A.enqueue_alert("HIGH on web-01: SSH brute force\nNext: open Kratos", "critical", deliver=["mail"],
                        data_dir=dd)
        W.flush(dd, label="t")
        (rcpts, raw), = srv.messages
        msg = email.message_from_bytes(raw)
        assert rcpts == ["ops@example.com", "sec@example.com"]
        assert msg["Subject"] == "Kratos: HIGH on web-01: SSH brute force"
        parts = [p.get_content_type() for p in msg.walk() if not p.is_multipart()]
        assert parts == ["text/plain", "text/html"]
        assert not any(p.get_filename() for p in msg.walk())
    finally:
        srv.close()


def test_a_server_without_starttls_is_never_used_in_the_clear(dd, tmp_path, monkeypatch):
    srv = SMTPServer(tmp_path)
    try:
        _email_channel(dd, srv, "starttls")
        import smtplib

        monkeypatch.setattr(smtplib.SMTP, "has_extn", lambda self, name: False if name == "starttls" else True)
        res = A.enqueue_alert("x", deliver=["mail"], data_dir=dd)
        W.flush(dd, label="t")
        with S.opened(dd) as conn:
            row = S.get(conn, res["outbox_ids"][0])
        assert row["status"] == "dead" and "never sends mail unencrypted" in row["last_error"] and not srv.messages
    finally:
        srv.close()


def test_a_wrong_password_is_final_and_not_echoed(dd, tmp_path):
    srv = SMTPServer(tmp_path, password="right")
    try:
        _email_channel(dd, srv, "starttls")
        res = A.enqueue_alert("x", deliver=["mail"], data_dir=dd)
        W.flush(dd, label="t")
        with S.opened(dd) as conn:
            row = S.get(conn, res["outbox_ids"][0])
        assert row["status"] == "dead" and "refused the login" in row["last_error"] and "pw" not in row["last_error"]
    finally:
        srv.close()


def test_findings_changes_of_one_run_become_one_digest_email(dd):
    ch = C.Channel(name="mail", kind="email", config={"from": "k@example.com", "to": ["o@example.com"]},
                   scopes=("findings",), format="text")
    changes = [_change(event_id=i, finding_key=f"k{i}", rule_id=r, severity=s, title=t, run_id="run1")
               for i, (r, s, t) in enumerate([("CORR-SSH-001", "high", "SSH brute force"),
                                               ("PKG-001", "medium", "openssl out of date"),
                                               ("NET-001", "low", "port 8080 open")], start=1)]
    p = R.findings_digest(ch, changes, None)
    assert p["subject"] == "Kratos: HIGH -- 3 new or worse finding(s) on 198.51.100.7"
    assert p["text"].index("SSH brute force") < p["text"].index("openssl") < p["text"].index("port 8080")
    assert "Evidence files are not attached" in p["text"]
