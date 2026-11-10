"""Removing old backups -- only when a person asks (docs/phaseD/D.8 §3.12).

The owner decided (2026-11-10) that Kratos never deletes a backup on its own: there is no
`backup.keep` setting. `kratos backup prune --keep N` is the only way, and it is manual,
CLI-only, shows what it would remove first, and is recorded in `data_prunes` (who, when,
how many, how big) and `backup_runs`.

Only files Kratos named itself are considered: `kratos-backup-<UTC time>.age` and their
`.sha256` sidecars in the backup folder. Copies on other disks or servers are never touched.
And only THIS Kratos's backups (its signer in the sidecar): two Kratos homes sharing the
default folder each keep their own N; a backup another Kratos made, or one with no sidecar,
is never removed here.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.backup import store as BR
from kratos.backup.create import NAME_RE


class PruneError(ValueError):
    pass


@dataclass
class PrunePlan:
    folder: Path
    keep: list[Path] = field(default_factory=list)
    remove: list[Path] = field(default_factory=list)
    others: list[Path] = field(default_factory=list)      # not this Kratos's: never removed here

    @property
    def bytes(self) -> int:
        return sum(p.stat().st_size for p in self.remove if p.exists())


def _authorize(actor: Any, data_dir: Path) -> None:
    from kratos import authz

    if getattr(actor, "interface", None) != "cli":
        raise PruneError("old backups are removed only from the command line (`kratos backup prune`)")
    try:
        authz.require(actor, authz.P.BACKUP_RESTORE, data_dir=data_dir, obj="backup prune")
    except authz.Denied as e:
        raise PruneError(f"refused: {e}") from None


def plan(folder: Path, keep: int, *, data_dir: Path) -> PrunePlan:
    """Which of THIS Kratos's backups in `folder` would go, keeping the newest `keep`."""
    from kratos.backup import origin
    from kratos.backup.create import read_sidecar

    if keep < 1:
        raise PruneError("--keep must be at least 1 (Kratos never removes your last backup)")
    every = sorted((p for p in Path(folder).iterdir() if NAME_RE.match(p.name) and p.is_file()),
                   key=lambda p: p.name) if Path(folder).is_dir() else []
    mine_keys = origin.local_fingerprints(Path(data_dir))
    files, others = [], []
    for p in every:
        meta = read_sidecar(p.with_name(p.name + ".sha256")) or {}
        (files if meta.get("signer") in mine_keys else others).append(p)
    pp = PrunePlan(Path(folder), others=others)
    pp.keep = files[-keep:]
    pp.remove = files[:-keep] if len(files) > keep else []
    return pp


def apply(data_dir: Path, pp: PrunePlan, *, actor: Any) -> dict[str, Any]:
    _authorize(actor, data_dir)
    done, size = [], 0
    for p in pp.remove:
        if not NAME_RE.match(p.name) or p in pp.others:
            continue
        size += p.stat().st_size
        p.unlink()                                   # deletion-scan: the person's own `kratos backup prune --apply`
        side = p.with_name(p.name + ".sha256")
        if side.is_file():
            side.unlink()                            # deletion-scan: the removed backup's sidecar
        done.append(p.name)
    from kratos import dataprune
    from kratos.storage.migrations import migrate_once
    from kratos.storage.sqlite_files import connect_store

    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, dataprune.COMPONENT, dataprune._STEPS)
        conn.execute(
            "INSERT INTO data_prunes (at, actor, category, older_than_days, cutoff, items, bytes, forced, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), f"{getattr(actor, 'interface', 'cli')}:{getattr(actor, 'user', '?')}"[:200], "backups", 0,
             0.0, len(done), size, 0, json.dumps({"folder": str(pp.folder), "removed": done,
                                                  "kept": [p.name for p in pp.keep]}, sort_keys=True)))
    finally:
        conn.close()
    BR.record(data_dir, "prune", actor, "ok", size=size,
              detail={"folder": str(pp.folder), "removed": done, "kept": len(pp.keep)})
    return {"removed": done, "bytes": size, "kept": [p.name for p in pp.keep]}
