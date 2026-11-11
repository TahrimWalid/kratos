"""The `hashdb.*` settings (Settings -> General -> File reputation)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _on_off, _whole
from kratos.settings_store import SettingError, SettingSpec

MAX_FILES = "hashdb.max_files"
MAX_FILE_MB = "hashdb.max_file_mb"
MAX_RUN_MB = "hashdb.max_run_mb"
SECONDS = "hashdb.seconds"
ENTROPY = "hashdb.entropy_threshold"
ONLINE = "hashdb.online"
MB_EVERY_HOURS = "hashdb.malwarebazaar_every_hours"
CIRCL_WARN_DAYS = 60
MB_WARN_DAYS = 7


def _bits(value: Any) -> float:
    if isinstance(value, bool):
        raise SettingError("bits per byte, 5.0-8.0")
    try:
        f = float(str(value).strip())
    except (TypeError, ValueError):
        raise SettingError("bits per byte, 5.0-8.0") from None
    if not 5.0 <= f <= 8.0:
        raise SettingError("bits per byte, 5.0-8.0")
    return round(f, 2)


for _spec in (
    SettingSpec(MAX_FILES, 500, _whole(10, 5000, "files"),
                "The most files per machine whose reputation one check looks up (the most suspicious first; the "
                "rest is reported as not checked)."),
    SettingSpec(MAX_FILE_MB, 64, _whole(1, 4096, "MB"),
                "Files larger than this are hashed only while the per-check byte budget allows."),
    SettingSpec(MAX_RUN_MB, 2048, _whole(16, 65536, "MB"),
                "The most bytes one reputation check reads on a machine."),
    SettingSpec(SECONDS, 120, _whole(10, 1800, "seconds"),
                "The most time one reputation check spends reading files on a machine."),
    SettingSpec(ENTROPY, 7.2, _bits,
                "An unknown program whose first MiB is more random than this (bits per byte) is flagged as "
                "possibly packed or encrypted."),
    SettingSpec(ONLINE, False, _on_off,
                "Allow `kratos hash lookup --online` and the finding-detail key to send ONE hash, when you ask, to "
                "circl.lu and abuse.ch. Off: no hash ever leaves this computer."),
    SettingSpec(MB_EVERY_HOURS, 24, _whole(1, 720, "hours"),
                "Fetch the MalwareBazaar known-bad export at most this often (abuse.ch asks for at most hourly)."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Any) -> Any:
    return settings_store.get(key, data_dir=data_dir)
