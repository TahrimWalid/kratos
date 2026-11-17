"""The agent-door settings (people-only, `app_settings`; Settings -> General -> Chat server)."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from kratos import settings_store
from kratos.serve.settings import _bool, _int_range
from kratos.settings_store import SettingError, SettingSpec

A2A_ENABLED = "a2a.enabled"
AGUI_ENABLED = "agui.enabled"
MAX_OPEN_TASKS = "a2a.max_open_tasks"
PUBLIC_URL = "a2a.public_url"


def _public_url(value: Any) -> str:
    """'' (the address the request came to) or an http(s) origin, e.g. https://kratos.example.org."""
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path or parts.query or parts.fragment \
            or parts.username or parts.password or len(text) > 200 or any(c.isspace() for c in text):
        raise SettingError("an address like https://kratos.example.org (scheme and host, optionally a port; "
                           "no path) -- or empty")
    return text


for _spec in (
    SettingSpec(A2A_ENABLED, False, _bool,
                "Let other agents use Kratos over A2A (an Agent Card at /.well-known/agent-card.json and tasks "
                "at /a2a/v1): only with a person token that has the agent doors, with that person's role, "
                "machines and limits. Off by default."),
    SettingSpec(AGUI_ENABLED, False, _bool,
                "Let agent front ends (AG-UI) run investigations at /ag-ui/run: same person tokens, roles, "
                "machines and limits as A2A. Off by default."),
    SettingSpec(MAX_OPEN_TASKS, 4, _int_range(1, 16, "a number of tasks"),
                "How many unfinished A2A tasks and AG-UI runs one person may have at once; more are rejected "
                "(\"try again when one finishes\"), never queued."),
    SettingSpec(PUBLIC_URL, "", _public_url,
                "The address other agents reach Kratos at, written into the signed Agent Card (set it when a "
                "reverse proxy is in front, e.g. https://kratos.example.org). Empty: the address the request "
                "came to."),
):
    settings_store.register(_spec)
