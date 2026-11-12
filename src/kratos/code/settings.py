"""The `code.*` settings (Settings -> General -> "The code your servers run"), read fresh per run.
`review.max_read_mb` is the byte budget of the source read an E.7b review asks for (the
`review` purpose of E.7a's content read)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.adapters import code_facts as CF
from kratos.collect.settings import _whole
from kratos.settings_store import SettingError, SettingSpec

MAX_ROOTS = "code.max_roots"
MAX_FILES = "code.max_files"
MAX_DEPTH = "code.max_depth"
MAX_READ_MB = "code.max_read_mb"
MAX_PACK_MB = "code.max_pack_mb"
SECONDS = "code.inventory_seconds"
SKIP_FOLDERS = "code.skip_folders"
GROUP_AFTER = "code.group_after"
REVIEW_MAX_READ_MB = "review.max_read_mb"


def _folders(value: Any) -> str:
    if not isinstance(value, str):
        raise SettingError("a comma-separated list of: " + ", ".join(CF.SKIP_DIRS))
    names = [x.strip() for x in value.split(",") if x.strip()]
    bad = [n for n in names if n not in CF.SKIP_DIRS]
    if bad:
        raise SettingError("only these folders can be skipped: " + ", ".join(CF.SKIP_DIRS))
    return ",".join(dict.fromkeys(names))


for _spec in (
    SettingSpec(MAX_ROOTS, 20, _whole(1, 100, "folders"),
                "The most code folders (roots) Kratos checks per machine."),
    SettingSpec(MAX_FILES, CF.MAX_FILES, _whole(100, 200_000, "files"),
                "The most files Kratos lists in one code folder; the rest are counted as not read."),
    SettingSpec(MAX_DEPTH, CF.MAX_DEPTH, _whole(2, 64, "levels"),
                "How many folder levels deep Kratos looks inside a code folder."),
    SettingSpec(MAX_READ_MB, 64, _whole(1, 1024, "MB"),
                "The most file contents (lockfiles, files scanned for secrets, git files) Kratos reads from a "
                "machine in one code check. Contents are used in memory and never stored."),
    SettingSpec(MAX_PACK_MB, 512, _whole(16, 4096, "MB"),
                "The most git pack data the sub-agent reads on the machine to compare a checkout with its last "
                "commit (over SSH the content budget above applies)."),
    SettingSpec(SECONDS, CF.DEFAULT_SECONDS, _whole(30, 1800, "seconds"),
                "How long Kratos spends listing one code folder before it stops and says so."),
    SettingSpec(SKIP_FOLDERS, ",".join(CF.SKIP_DIRS), _folders,
                "Dependency folders Kratos counts but doesn't walk (it still reads what they say is installed). "
                "Remove one to have its files listed and compared too."),
    SettingSpec(GROUP_AFTER, 20, _whole(1, 10_000, "files"),
                "With no git, more changed files than this in one folder are one grouped finding "
                "(a deploy); accept it with `kratos code accept-state`."),
    SettingSpec(REVIEW_MAX_READ_MB, 128, _whole(1, 2048, "MB"),
                "The most source a person-started AI code review may read from one folder."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Any) -> Any:
    return settings_store.get(key, data_dir=data_dir)


def skip_folders(data_dir: Any) -> tuple[str, ...]:
    return tuple(x for x in str(get(SKIP_FOLDERS, data_dir)).split(",") if x)
