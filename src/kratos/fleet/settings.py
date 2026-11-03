"""The `fleet.*` settings (Settings -> General -> Fleet questions)."""
from __future__ import annotations

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingSpec

MAX_PARALLEL = "fleet.max_parallel"
MACHINE_SECONDS = "fleet.machine_seconds"
DIGEST_CHARS = "fleet.digest_chars"
EXTRA_READS = "fleet.extra_reads"

for _spec in (
    SettingSpec(MAX_PARALLEL, 4, _whole(1, 16, "machines"),
                "How many machines a question about a group collects at the same time."),
    SettingSpec(MACHINE_SECONDS, 90, _whole(15, 900, "seconds"),
                "The most time one machine of a group gets (waiting for it, collecting); a machine still "
                "going after that is reported as timed out."),
    SettingSpec(DIGEST_CHARS, 16000, _whole(2000, 100000, "characters"),
                "The most text about the group's machines the model reads at once; machines that don't fit "
                "are shortened to one line, and the answer says how many."),
    SettingSpec(EXTRA_READS, 3, _whole(0, 10, "reads"),
                "How many further reads (each on one machine) the model may ask for before answering a "
                "question about a group."),
):
    settings_store.register(_spec)


def get(key: str, data_dir) -> int:
    return int(settings_store.get(key, data_dir=data_dir))
