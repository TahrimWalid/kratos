"""Which machines this Kratos has already connected, so setup isn't asked twice.

Starting a session with a machine used to show the "How should Kratos reach this
box?" screen every time, even right after the machine was set up and every check
passed. Each setup check's outcome is remembered here (in the data folder's
local config), and a new session with a known machine gets a one-line note
instead of the wizard:

- ``ready``        -- the last check passed: just go.
- ``issues``       -- Kratos could log in, but some checks failed: say how many
                      and how to re-check, without replaying the wizard.
- ``linked``       -- the machine is read through a paired sub-agent.
- ``new``          -- never set up, or the last attempt couldn't connect at all:
                      show the setup screen ("Skip for now" doesn't count as set up).
- ``local``        -- the Kratos machine itself: nothing to set up.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kratos import kratos_config as _kconfig
from kratos.utils.timeutil import utc_now_iso

_CONFIG_KEY = "connected_targets"
_LOCAL = {"127.0.0.1", "localhost", "::1"}
_UNREACHABLE = -1


def _key(host: str) -> str:
    return str(host or "").rpartition("@")[2].strip().strip("[]").lower()


def record_check(data_dir: Path, host: str, via: str, checks: list[dict[str, Any]] | None) -> None:
    """Remember a setup check of `host`. `checks` is the probe's list of
    {check, status, detail}; None means Kratos couldn't connect at all."""
    key = _key(host)
    if not key or key in _LOCAL:
        return
    if checks is None:
        issues = _UNREACHABLE
    else:
        issues = sum(1 for c in checks if str(c.get("status", "")).upper() not in ("PASS", "INFO"))
    known = dict(_kconfig.load_local_config(data_dir).get(_CONFIG_KEY) or {})
    known[key] = {"via": via, "issues": issues, "checked_at": utc_now_iso()}
    _kconfig.save_local_config(data_dir, **{_CONFIG_KEY: known})


def setup_state(data_dir: Path, host: str) -> tuple[str, dict[str, Any] | None]:
    key = _key(host)
    if not key or key in _LOCAL:
        return "local", None
    try:
        from kratos.subagent import routing

        link = routing.link_for(host, data_dir)
    except Exception:  # noqa: BLE001 -- a broken link table must not block starting a session
        link = None
    if link is not None:
        return "linked", {"label": getattr(link, "label", "") or host}
    info = (_kconfig.load_local_config(data_dir).get(_CONFIG_KEY) or {}).get(key)
    if not isinstance(info, dict) or info.get("issues", _UNREACHABLE) == _UNREACHABLE:
        return "new", info if isinstance(info, dict) else None
    return ("ready" if info.get("issues") == 0 else "issues"), info


def setup_note(host: str, state: str, info: dict[str, Any] | None) -> str:
    """The one line shown instead of the setup screen for a known machine."""
    if state == "linked":
        return f"{host} is read through its sub-agent ({(info or {}).get('label') or host}). /target verify re-checks it."
    if state == "ready":
        return f"{host} is already set up — the last check passed. /target verify re-checks it any time."
    if state == "issues":
        n = (info or {}).get("issues", 0)
        return (f"{host} is set up, but the last check found {n} problem{'s' if n != 1 else ''}. "
                "Investigations may miss some data — /target verify shows what and how to fix it.")
    return ""
