"""
Standalone ntfy notification sender.

Not tied to the agent loop or tool registry -- importable and callable on
its own (`from kratos.agent.notify import send_notification`).

Notifications are OFF until KRATOS_NTFY_TOPIC is set: Kratos ships no default
topic, because a topic named in public source is readable by anyone (ntfy
topics are unauthenticated). See kratos_config.py's ntfy section.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sys
from typing import Any
from urllib.parse import urlparse

import requests

from kratos import kratos_config as _kc
from kratos.utils.redact import redact_secrets

_SEVERITY_MAP = {
    "info": {"priority": "default", "tag": "information_source"},
    "warning": {"priority": "high", "tag": "warning"},
    "critical": {"priority": "urgent", "tag": "rotating_light"},
}

# ntfy's own topic rule: 1-64 of [-_A-Za-z0-9].
_TOPIC_RE = re.compile(r"[-_A-Za-z0-9]{1,64}")
# Shorter than this on a public server is guessable -- a warning, not a block.
_GUESSABLE_BELOW = 16
# SHA-256 of topics that were ever written in this repo's source (so they are
# public once the repo is). Refused outright: sending findings there would
# publish them. Stored hashed so the topic itself isn't repeated here.
_KNOWN_PUBLIC_TOPIC_HASHES = frozenset({"86a245b39df34089bccca158e491cdb4afeae670848621270a9cdb50c0d56872"})
_PUBLIC_SERVERS = ("ntfy.sh",)

NOT_CONFIGURED_HINT = (
    "Notifications are off: set KRATOS_NTFY_TOPIC in .env to a topic only you know "
    "(`kratos` /doctor suggests a random one), then subscribe to it in the ntfy app."
)


def suggest_topic() -> str:
    """A random, unguessable topic name for a new install to use."""
    return "kratos-" + secrets.token_hex(12)


def is_public_server(base_url: str | None = None) -> bool:
    host = (urlparse(base_url or _kc.NTFY_BASE_URL).hostname or "").lower()
    return host in _PUBLIC_SERVERS or host.endswith(tuple("." + h for h in _PUBLIC_SERVERS))


def notify_config_status() -> tuple[str, str]:
    """(status, detail) for /doctor: 'off', 'bad', 'warn' or 'ok'. Pure over
    the live config; makes no network call."""
    topic, base = _kc.NTFY_TOPIC, _kc.NTFY_BASE_URL
    if not topic:
        return "off", f"not configured. Suggested: KRATOS_NTFY_TOPIC={suggest_topic()}"
    problem = topic_problem(topic)
    if problem:
        return "bad", problem
    if is_public_server(base) and not _kc.NTFY_TOKEN:
        guess = " and it is short enough to guess" if len(topic) < _GUESSABLE_BELOW else ""
        return "warn", (f"on public {urlparse(base).hostname}: anyone who knows the topic name can read the "
                        f"findings{guess}. For real use, self-host ntfy (KRATOS_NTFY_BASE_URL) or add an "
                        "access token (KRATOS_NTFY_TOKEN).")
    return "ok", f"topic set on {urlparse(base).hostname}" + (" with an access token" if _kc.NTFY_TOKEN else "")


def topic_problem(topic: str) -> str | None:
    """Why `topic` must not be used, or None."""
    if not _TOPIC_RE.fullmatch(topic):
        return "KRATOS_NTFY_TOPIC must be 1-64 letters, digits, '-' or '_'."
    if hashlib.sha256(topic.encode("utf-8")).hexdigest() in _KNOWN_PUBLIC_TOPIC_HASHES:
        return ("KRATOS_NTFY_TOPIC is a topic that appeared in Kratos's public source, so anyone could read it. "
                "Choose your own (e.g. " + suggest_topic() + ").")
    return None


def send_notification(message: str, severity: str = "info") -> dict[str, Any]:
    """
    POST `message` to the configured ntfy topic.

    Never raises: no topic configured, a refused topic, or a delivery failure
    (unreachable ntfy, bad response, no network) is returned as a structured
    result rather than crashing the caller.
    """
    severity_key = (severity or "info").lower()
    mapping = _SEVERITY_MAP.get(severity_key, _SEVERITY_MAP["info"])
    topic, token = _kc.NTFY_TOPIC, _kc.NTFY_TOKEN
    if not topic:
        return {"status": "not_configured", "topic": None, "severity": severity_key,
                "observation": NOT_CONFIGURED_HINT}
    problem = topic_problem(topic)
    if problem:
        print(f"[KRATOS-NOTIFY] Not sending: {problem}", file=sys.stderr)
        return {"status": "refused", "topic": topic, "severity": severity_key, "observation": problem}

    url = f"{_kc.NTFY_BASE_URL.rstrip('/')}/{topic}"
    headers = {
        "Priority": mapping["priority"],
        "Tags": mapping["tag"],
        "Title": f"Kratos [{severity_key.upper()}]",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.post(
            url,
            data=message.encode("utf-8"),
            headers=headers,
            timeout=_kc.NTFY_REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            return {
                "status": "sent",
                "topic": topic,
                "severity": severity_key,
                "http_status": resp.status_code,
            }
        body = redact_secrets(resp.text[:200], token)
        print(f"[KRATOS-NOTIFY] ntfy returned HTTP {resp.status_code}: {body}", file=sys.stderr)
        return {
            "status": "failed",
            "topic": topic,
            "severity": severity_key,
            "http_status": resp.status_code,
            "observation": f"ntfy returned HTTP {resp.status_code}: {body}",
        }
    except requests.RequestException as e:
        err = redact_secrets(str(e), token)
        print(f"[KRATOS-NOTIFY] Failed to reach ntfy ({url}): {err}", file=sys.stderr)
        return {
            "status": "failed",
            "topic": topic,
            "severity": severity_key,
            "observation": f"Failed to reach ntfy: {err}",
        }
