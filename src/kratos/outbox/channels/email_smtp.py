"""Email channel: SMTP with STARTTLS (587) or implicit TLS (465), the server always
verified; a login from the channel's secret when it has one. Plain text first, a small
HTML part after; one email per run or detection batch (a digest), never one per finding;
evidence files are never attached -- the email names findings and says where to look."""
from __future__ import annotations

import hashlib
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from typing import Any

from kratos.outbox.channels import TIMEOUT_SECONDS, Delivery, clean_reason
from kratos.outbox.store import Outcome


def build_message(delivery: Delivery, channel: Any) -> EmailMessage:
    cfg = channel.config
    p = delivery.payload
    msg = EmailMessage()
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg["Subject"] = " ".join(str(p.get("subject") or "Kratos").split())[:200]
    msg["Date"] = formatdate(localtime=False)
    # the same id on every retry: a mail system that keeps it can drop a repeat
    msg["Message-ID"] = f"<{hashlib.sha256(delivery.message_id.encode()).hexdigest()[:32]}@kratos.outbox>"
    msg["X-Kratos-Message"] = delivery.kind
    msg.set_content(str(p.get("text") or ""))
    if p.get("html"):
        msg.add_alternative(str(p["html"]), subtype="html")
    return msg


def _context(channel: Any) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=channel.config.get("ca_file") or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def send(delivery: Delivery, channel: Any, secrets: dict[str, str], data_dir: Path) -> Outcome:
    cfg = channel.config
    hidden = tuple(v for v in secrets.values() if v)
    host, port = str(cfg["host"]), int(cfg["port"])
    timeout = TIMEOUT_SECONDS["email"]
    try:
        ctx = _context(channel)
        msg = build_message(delivery, channel)
        if cfg.get("security") == "tls":
            client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            client = smtplib.SMTP(host, port, timeout=timeout)
        with client:
            client.ehlo()
            if cfg.get("security") != "tls":
                if not client.has_extn("starttls"):
                    return Outcome(False, False, f"{host}:{port} doesn't offer STARTTLS; Kratos never sends mail "
                                                 "unencrypted (use security tls on port 465 if it supports that)")
                client.starttls(context=ctx)
                client.ehlo()
            if cfg.get("username"):
                client.login(cfg["username"], secrets.get("password") or "")
            refused = client.send_message(msg)
        if refused:
            return Outcome(False, False, clean_reason(f"the server refused: {', '.join(sorted(refused))}", *hidden))
    except smtplib.SMTPAuthenticationError as e:
        return Outcome(False, False, clean_reason(f"the mail server refused the login ({e.smtp_code})", *hidden),
                       e.smtp_code)
    except smtplib.SMTPRecipientsRefused as e:
        return Outcome(False, False, clean_reason(f"every recipient was refused: {', '.join(sorted(e.recipients))}",
                                                  *hidden))
    except smtplib.SMTPResponseException as e:
        retryable = not 500 <= int(e.smtp_code) < 600
        return Outcome(False, retryable, clean_reason(f"SMTP {e.smtp_code}: {e.smtp_error!r}", *hidden), e.smtp_code)
    except ssl.SSLCertVerificationError as e:
        return Outcome(False, True, clean_reason(f"TLS check failed: {host}'s certificate isn't trusted or doesn't "
                                                 f"match ({e.verify_message})", *hidden))
    except (ssl.SSLError, smtplib.SMTPException, socket.timeout, OSError) as e:
        return Outcome(False, True, clean_reason(f"sending to {host}:{port} failed: {e}", *hidden))
    return Outcome(True, False, f"accepted by {host}:{port}")
