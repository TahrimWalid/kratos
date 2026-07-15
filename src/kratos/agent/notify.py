"""
Standalone ntfy.sh notification sender.

Not tied to the agent loop or tool registry -- importable and callable on
its own (`from kratos.agent.notify import send_notification`).
"""
from __future__ import annotations

import sys
from typing import Any

import requests

from kratos.kratos_config import NTFY_BASE_URL, NTFY_TOPIC, NTFY_REQUEST_TIMEOUT_SECONDS

_SEVERITY_MAP = {
    "info": {"priority": "default", "tag": "information_source"},
    "warning": {"priority": "high", "tag": "warning"},
    "critical": {"priority": "urgent", "tag": "rotating_light"},
}


def send_notification(message: str, severity: str = "info") -> dict[str, Any]:
    """
    POST `message` to the configured ntfy.sh topic.

    Never raises: a delivery failure (unreachable ntfy, bad response, no
    network) is logged to stderr and returned as a structured failure result
    rather than crashing the caller.
    """
    severity_key = (severity or "info").lower()
    mapping = _SEVERITY_MAP.get(severity_key, _SEVERITY_MAP["info"])
    url = f"{NTFY_BASE_URL.rstrip('/')}/{NTFY_TOPIC}"

    try:
        resp = requests.post(
            url,
            data=message.encode("utf-8"),
            headers={
                "Priority": mapping["priority"],
                "Tags": mapping["tag"],
                "Title": f"Kratos [{severity_key.upper()}]",
            },
            timeout=NTFY_REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            return {
                "status": "sent",
                "topic": NTFY_TOPIC,
                "severity": severity_key,
                "http_status": resp.status_code,
            }
        print(f"[KRATOS-NOTIFY] ntfy returned HTTP {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return {
            "status": "failed",
            "topic": NTFY_TOPIC,
            "severity": severity_key,
            "http_status": resp.status_code,
            "observation": f"ntfy returned HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except requests.RequestException as e:
        print(f"[KRATOS-NOTIFY] Failed to reach ntfy ({url}): {e}", file=sys.stderr)
        return {
            "status": "failed",
            "topic": NTFY_TOPIC,
            "severity": severity_key,
            "observation": f"Failed to reach ntfy: {e}",
        }
