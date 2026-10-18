"""Masking mode: `privacy.mask_mode` (people-only) and the default for this model endpoint.

* `standard` -- names, addresses and accounts replaced; dictionary guesses that don't
  exist on the machine stay readable; names shorter than 3 characters are left;
* `strict`   -- every non-system name is replaced, short ones too;
* `off`      -- the text is sent exactly as written, secrets included (as before B.2).
* `auto` (the stored default) -- `standard` when the model is hosted, `off` when it
  runs on this machine (loopback) or on a host the person listed in
  `privacy.local_model_hosts` as their own.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

MODE_KEY = "privacy.mask_mode"
LOCAL_HOSTS_KEY = "privacy.local_model_hosts"
MODES = ("off", "standard", "strict")
_CHOICES = ("auto",) + MODES


def _mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text not in _CHOICES:
        raise SettingError("auto, off, standard or strict")
    return text


def _hosts(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else str(value or "").replace(",", " ").split()
    out: list[str] = []
    for item in items:
        host = str(item).strip().lower().strip("[]")
        if not host:
            continue
        if len(host) > 253 or any(c.isspace() or c in "/@?#" for c in host):
            raise SettingError("host names or addresses, separated by commas")
        if host not in out:
            out.append(host)
    return out


for _spec in (
    SettingSpec(MODE_KEY, "auto", _mode,
                "What the model sees: 'standard' replaces account names, machine names, addresses and emails "
                "with placeholders before anything is sent; 'strict' also replaces short names and attackers' "
                "guesses; 'off' sends them as they are. 'auto' is standard for a hosted model and off for "
                "one on your own machine."),
    SettingSpec(LOCAL_HOSTS_KEY, [], _hosts,
                "Machines you run your own model on (for 'auto' masking these count as local, like this "
                "machine): host names or addresses, separated by commas."),
):
    settings_store.register(_spec)


def _data_dir(data_dir: Path | None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    from kratos.budget.guard import data_dir as _budget_data_dir

    return _budget_data_dir()


def endpoint_is_local(base_url: str | None, *, data_dir: Path | None = None) -> bool:
    """The model runs on this machine, or on a host the person listed as their own."""
    from kratos.llm_config import is_local_base_url

    if is_local_base_url(base_url):
        return True
    host = (urlparse(base_url or "").hostname or "").lower()
    if not host:
        return False
    try:
        return host in settings_store.get(LOCAL_HOSTS_KEY, data_dir=_data_dir(data_dir))
    except Exception:  # noqa: BLE001 -- unreadable settings: treat as hosted (mask)
        return False


def stored_mode(*, data_dir: Path | None = None) -> str:
    try:
        return settings_store.get(MODE_KEY, data_dir=_data_dir(data_dir))
    except Exception:  # noqa: BLE001 -- unreadable settings fall back to the default
        return "auto"


def current_mode(*, local: bool | None = None, base_url: str | None = None, data_dir: Path | None = None) -> str:
    """The mode a request uses: the stored choice, or for 'auto' the endpoint's default.
    `local` is the request site's own answer (llm_interface knows its endpoint); else the
    active model profile's endpoint decides."""
    chosen = stored_mode(data_dir=data_dir)
    if chosen != "auto":
        return chosen
    if base_url is not None:
        local = endpoint_is_local(base_url, data_dir=data_dir)
    elif local is None:
        from kratos.llm_config import get_active_llm_base_url

        local = endpoint_is_local(get_active_llm_base_url(), data_dir=data_dir)
    return "off" if local else "standard"


def describe_mode(*, data_dir: Path | None = None, base_url: str | None = None) -> str:
    """One plain line for /doctor and /model: what the model is sent right now."""
    if base_url is None:
        from kratos.llm_config import get_active_llm_base_url

        base_url = get_active_llm_base_url()
    chosen = stored_mode(data_dir=data_dir)
    mode = current_mode(base_url=base_url, data_dir=data_dir)
    local = endpoint_is_local(base_url, data_dir=data_dir)
    how = "your choice" if chosen != "auto" else ("automatic: local model" if local else "automatic: hosted model")
    if mode == "off":
        return f"not masked -- names, addresses and secrets sent as they are ({how})"
    if mode == "strict":
        return f"names and addresses masked, short names and attackers' guesses too (strict; {how})"
    return f"names and addresses masked (standard; {how})"
