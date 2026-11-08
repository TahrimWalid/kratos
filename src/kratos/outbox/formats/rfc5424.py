"""RFC 5424 syslog messages (sent over TLS by ``channels.syslog_tls``).

``<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] BOM MSG`` with APP-NAME ``kratos``,
MSGID the message kind (``alert``, ``notice``, ``finding``, ``event``, ``test``), the
IANA-registered ``origin`` element (software, version) and a ``kratos@<PEN>`` element with
the finding's identity. ``<PEN>`` is the channel's private enterprise number (default
32473, the number reserved for documentation, for organisations without their own).
PARAM-VALUEs escape ``"``, ``\\`` and ``]`` with a backslash (RFC 5424 §6.3.3); a
message is kept under ``MAX_BYTES``.
"""
from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from typing import Any, Iterable

FACILITY = 13                      # "log audit"
SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
MAX_BYTES = 8192                   # what rsyslog and syslog-ng accept by default
BOM = "﻿"
_SD_NAME_BAD = re.compile(r'[^\x21-\x7e]|[=\]" ]')


def escape_param(value: Any) -> str:
    """RFC 5424 §6.3.3: in a PARAM-VALUE, '"', '\\' and ']' are escaped with '\\'."""
    s = str(value if value is not None else "")
    s = "".join(ch for ch in s if ch in "\t" or ord(ch) >= 32)        # no control characters
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sd_name(name: str) -> str:
    n = _SD_NAME_BAD.sub("_", name)[:32]
    return n or "_"


def _field(value: Any, limit: int) -> str:
    """HOSTNAME / APP-NAME / PROCID / MSGID: printable US-ASCII without spaces, or '-'."""
    s = "".join(ch for ch in str(value or "") if 33 <= ord(ch) <= 126)[:limit]
    return s or "-"


def timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")


def hostname() -> str:
    try:
        return _field(socket.getfqdn() or socket.gethostname(), 255)
    except OSError:
        return "-"


def structured_data(elements: Iterable[tuple[str, dict[str, Any]]]) -> str:
    out = []
    for sd_id, params in elements:
        parts = [_sd_name(sd_id)]
        for k, v in params.items():
            if v is None or v == "":
                continue
            parts.append(f'{_sd_name(k)}="{escape_param(v)}"')
        out.append("[" + " ".join(parts) + "]")
    return "".join(out) or "-"


def message(*, at: float, severity: str, msgid: str, msg: str, kratos_params: dict[str, Any],
            pen: int = 32473, host: str | None = None, sw_version: str = "", facility: int = FACILITY) -> str:
    """One RFC 5424 message. ``msg`` is UTF-8 text (with a BOM) or JSON; it is shortened
    so the whole message fits ``MAX_BYTES``."""
    pri = facility * 8 + SEVERITY.get(severity, 6)
    sd = structured_data([("origin", {"software": "Kratos", "swVersion": sw_version or None}),
                          (f"kratos@{int(pen)}", kratos_params)])
    head = f"<{pri}>1 {timestamp(at)} {host or hostname()} kratos - {_field(msgid, 32)} {sd} "
    room = MAX_BYTES - len(head.encode("utf-8")) - len(BOM.encode("utf-8"))
    body = msg.encode("utf-8")
    if len(body) > room:
        body = body[: max(0, room - 3)].decode("utf-8", "ignore").encode("utf-8") + "…".encode("utf-8")
    return head + BOM + body.decode("utf-8")


def fits(msg: str, *, head_bytes: int) -> bool:
    return head_bytes + len(BOM.encode()) + len(msg.encode("utf-8")) <= MAX_BYTES


def sw_version() -> str:
    try:
        from importlib.metadata import version

        return version("kratos-security-assistant")
    except Exception:  # noqa: BLE001
        return ""
