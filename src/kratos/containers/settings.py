"""The `containers.*` settings (D.5): which containers' own log files are synced."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingError, SettingSpec

LOGS_MAX_CONTAINERS = "containers.logs.max_containers"
LOGS_MAX_LINES = "containers.logs.max_lines"
LOGS_EXCLUDE = "containers.logs.exclude"


def _patterns(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [v.strip() for v in value.replace(";", ",").split(",") if v.strip()]
    if not isinstance(value, (list, tuple)):
        raise SettingError("a list of container name patterns (shell style: web-*, *-worker)")
    out: list[str] = []
    for v in value:
        p = str(v).strip()
        if not p or len(p) > 128 or any(c in p for c in "\x00\n\t/"):
            raise SettingError(f"{v!r} is not a container name pattern (letters, digits, . _ - * ? [ ])")
        if p not in out:
            out.append(p)
    return out[:64]


for _spec in (
    SettingSpec(LOGS_MAX_CONTAINERS, 50, _whole(0, 500, "containers"),
                "The most running containers whose own log files Kratos syncs (0 turns container log files off)."),
    SettingSpec(LOGS_MAX_LINES, 5000, _whole(100, 100000, "lines"),
                "The most lines kept from one container's log in one sync; more are counted and the span is "
                "marked incomplete."),
    SettingSpec(LOGS_EXCLUDE, [], _patterns,
                "Containers whose log files Kratos does not read, by name pattern (e.g. noisy-*)."),
):
    settings_store.register(_spec)
