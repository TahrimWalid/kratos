"""The chat-server settings people edit (Settings -> General, `app_settings`, people-only)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

PORT = "serve.port"
ALLOW_NON_LOOPBACK = "serve.allow_non_loopback"
ALLOWED_HOSTS = "serve.allowed_hosts"
MAX_PARALLEL = "serve.max_parallel"
REQUESTS_PER_HOUR = "serve.requests_per_hour"
LINK_HOSTS = "serve.link_hosts"
MAX_BODY_BYTES = "serve.max_body_bytes"


def _int_range(lo: int, hi: int, what: str):
    def check(value: Any) -> int:
        if isinstance(value, bool):
            raise SettingError(f"{what}, {lo}-{hi}")
        try:
            n = int(str(value).strip())
        except (TypeError, ValueError):
            raise SettingError(f"{what}, {lo}-{hi}") from None
        if not lo <= n <= hi:
            raise SettingError(f"{what}, {lo}-{hi}")
        return n

    return check


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise SettingError("yes or no")


def _host_list(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else str(value or "").replace(",", " ").split()
    out: list[str] = []
    for item in items:
        host = str(item).strip().lower()
        if not host:
            continue
        if len(host) > 260 or any(c.isspace() or c in "/@?#\\" for c in host):
            raise SettingError("host names or addresses (optionally :port), separated by commas")
        if host not in out:
            out.append(host)
    return out


for _spec in (
    SettingSpec(PORT, 8770, _int_range(1024, 65535, "a port number"),
                "The port `kratos serve` listens on (on 127.0.0.1 unless you start it with --host). Not 8765: "
                "that is the sub-agent listener's."),
    SettingSpec(ALLOW_NON_LOOPBACK, False, _bool,
                "Allow `kratos serve --host <address>` to listen on an address other than this machine's own "
                "(127.0.0.1). Tokens then travel in clear text unless a TLS reverse proxy is in front."),
    SettingSpec(ALLOWED_HOSTS, [], _host_list,
                "Extra Host header values the chat server accepts (e.g. the name a reverse proxy uses). "
                "127.0.0.1, localhost and the bind address with the port are always accepted."),
    SettingSpec(MAX_PARALLEL, 2, _int_range(1, 8, "a number of investigations"),
                "How many investigations the chat server runs at once; more wait their turn."),
    SettingSpec(REQUESTS_PER_HOUR, 30, _int_range(1, 1000, "requests per hour"),
                "How many messages that use the model one chat-client token may send per hour."),
    SettingSpec(LINK_HOSTS, [], _host_list,
                "Web sites whose links stay clickable in answers shown in a chat client. Every other link "
                "and address is shown as text and never fetched. Empty by default."),
    SettingSpec(MAX_BODY_BYTES, 1_000_000, _int_range(10_000, 20_000_000, "a size in bytes"),
                "The largest request the chat server accepts, in bytes."),
):
    settings_store.register(_spec)
