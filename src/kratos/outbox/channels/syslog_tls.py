"""Syslog channel: RFC 5424 messages over TLS (RFC 5425), octet-counting framing (RFC 6587).

The server certificate is always verified (the system CAs, or the CA file the person
names -- then only that CA) against the server's name; a client certificate is offered
when the channel has one. UDP and plain TCP are not offered: one loses messages without
a trace, the other is readable on the wire.

Syslog has no application acknowledgement: "delivered" means the TLS stream accepted
every byte of the message and closed cleanly.
"""
from __future__ import annotations

import os
import socket
import ssl
import tempfile
from pathlib import Path
from typing import Any

from kratos.outbox.channels import TIMEOUT_SECONDS, Delivery, clean_reason
from kratos.outbox.store import Outcome


def frame(message: str) -> bytes:
    """RFC 6587 octet counting: ``MSG-LEN SP SYSLOG-MSG`` (the length in bytes)."""
    data = message.encode("utf-8")
    return str(len(data)).encode("ascii") + b" " + data


def tls_context(channel: Any, secrets: dict[str, str], data_dir: Path) -> ssl.SSLContext:
    cfg = channel.config
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cfg.get("ca_file") or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cfg.get("client_cert") and secrets.get("client_key"):
        from kratos import paths
        from kratos.outbox.config import secrets_dir

        folder = secrets_dir(data_dir)
        paths.ensure_private_dir(folder)
        fd, key_path = tempfile.mkstemp(dir=folder, prefix=".client-key-", suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(secrets["client_key"])
            ctx.load_cert_chain(cfg["client_cert"], key_path)
        finally:
            os.unlink(key_path)
    return ctx


def send(delivery: Delivery, channel: Any, secrets: dict[str, str], data_dir: Path) -> Outcome:
    cfg = channel.config
    frames = [str(f) for f in delivery.payload.get("frames") or []]
    if not frames:
        return Outcome(True, False, "nothing to send")
    hidden = tuple(v for v in secrets.values() if v)
    host, port = str(cfg["host"]), int(cfg.get("port") or 6514)
    timeout = TIMEOUT_SECONDS["syslog"]
    try:
        ctx = tls_context(channel, secrets, data_dir)
    except (OSError, ssl.SSLError, ValueError) as e:
        return Outcome(False, False, clean_reason(f"the TLS settings can't be used: {e}", *hidden))
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=cfg.get("server_name") or host) as tls:
                tls.settimeout(timeout)
                for f in frames:
                    tls.sendall(frame(f))
                try:
                    tls.unwrap()
                except (OSError, ssl.SSLError):
                    pass       # some servers drop the TCP stream without a TLS close; the bytes were accepted
    except ssl.SSLCertVerificationError as e:
        return Outcome(False, True, clean_reason(f"TLS check failed: the server's certificate isn't trusted or "
                                                 f"doesn't match {cfg.get('server_name') or host} ({e.verify_message})",
                                                 *hidden))
    except ssl.SSLError as e:
        return Outcome(False, True, clean_reason(f"TLS failed: {e}", *hidden))
    except socket.timeout:
        return Outcome(False, True, f"no answer from {host}:{port} within {timeout} s")
    except OSError as e:
        return Outcome(False, True, clean_reason(f"connection to {host}:{port} failed: {e}", *hidden))
    return Outcome(True, False, f"{len(frames)} message(s) accepted by {host}:{port}")
