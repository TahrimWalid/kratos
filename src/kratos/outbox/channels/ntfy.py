"""The built-in ntfy channel: the existing sender (``agent.notify.send_notification``),
called by the delivery worker. The message body, title, priority and tags are exactly
what Kratos sent before the outbox existed."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kratos.outbox import retry as _retry
from kratos.outbox.channels import Delivery, clean_reason
from kratos.outbox.store import Outcome


def send(delivery: Delivery, channel: Any, secrets: dict[str, str], data_dir: Path) -> Outcome:
    from kratos import kratos_config as kc
    from kratos.agent.notify import send_notification

    text = str(delivery.payload.get("text") or "")
    severity = str(delivery.payload.get("severity") or "info")
    try:
        res = send_notification(text, severity)
    except Exception as e:  # noqa: BLE001 -- send_notification never raises; belt and braces
        return Outcome(False, True, clean_reason(e, kc.NTFY_TOKEN))
    status = res.get("status")
    if status == "sent":
        return Outcome(True, False, "sent", res.get("http_status"))
    detail = clean_reason(res.get("observation") or status, kc.NTFY_TOKEN)
    if status in ("not_configured", "refused"):
        return Outcome(False, False, detail)
    code = res.get("http_status")
    retryable = _retry.http_retryable(int(code)) if isinstance(code, int) else True
    return Outcome(False, retryable, detail, code if isinstance(code, int) else None)
