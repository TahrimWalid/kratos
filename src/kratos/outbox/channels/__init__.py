"""The four senders. Each is ``send(delivery, channel, secrets, data_dir) -> Outcome``:
no global state, never raises (a failure is an ``Outcome`` with a cleaned reason), and
no secret in any reason it returns."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from kratos.outbox.store import Outcome


@dataclass(frozen=True)
class Delivery:
    """One message as a sender sees it: its stable id, kind and rendered payload."""
    message_id: str
    kind: str
    payload: dict[str, Any]
    attempt: int = 1


Sender = Callable[[Delivery, Any, dict[str, str], Path], Outcome]


def clean_reason(text: Any, *secrets: str | None) -> str:
    """A failure reason fit for /outbox, logs and the outage notice: secrets removed,
    machine-controlled text neutralised, one line, bounded."""
    from kratos.privacy.secrets import redact
    from kratos.untrusted import for_display
    from kratos.utils.redact import redact_secrets

    s = redact_secrets(str(text or ""), *secrets)
    s, _n = redact(s)
    s = for_display(" ".join(s.split()))
    return s[:400]


def sender_for(kind: str) -> Sender:
    if kind == "ntfy":
        from kratos.outbox.channels import ntfy

        return ntfy.send
    if kind == "webhook":
        from kratos.outbox.channels import webhook

        return webhook.send
    if kind == "syslog":
        from kratos.outbox.channels import syslog_tls

        return syslog_tls.send
    if kind == "email":
        from kratos.outbox.channels import email_smtp

        return email_smtp.send
    raise ValueError(f"no sender for channel kind {kind!r}")


# How many attempts at once per channel kind (spec §5.1): syslog keeps one stream in
# order, a webhook can take a few in parallel.
CONCURRENCY = {"ntfy": 2, "webhook": 4, "syslog": 1, "email": 1}
# The longest one attempt may take (the claim on a message lasts a little longer).
TIMEOUT_SECONDS = {"ntfy": 15, "webhook": 10, "syslog": 15, "email": 30}
