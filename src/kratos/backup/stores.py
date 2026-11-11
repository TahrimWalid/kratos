"""Open every store on a database, so its migrations run (docs/phaseD/D.8 §3.8, §3.9).

A restored or drilled `kratos.db` may come from an older Kratos: each store brings its own
tables up to date the first time it is opened (`storage.migrations`). `migrate_all` does
that for every store at once, on a database given by path -- so a drill proves the copy
opens with this Kratos before a real restore relies on it. A database written by a NEWER
Kratos is reported (`newer_components`), never downgraded.

`tests/test_backup_restore.py` scans the source: every module that migrates a component
must be listed here, so a new store can't be forgotten.
"""
from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path

from kratos.storage import migrations

# Modules with COMPONENT and STEPS / _STEPS (migrated through storage.migrations).
MIGRATED = (
    "kratos.dataprune", "kratos.diskgrowth", "kratos.settings_store", "kratos.detect.store",
    "kratos.logsources.state_store", "kratos.sshca.store", "kratos.authz.store", "kratos.persist.baseline",
    "kratos.lifecycle.store", "kratos.evidence.ledger", "kratos.collect.state", "kratos.collect.sync.cursors",
    "kratos.triage.store", "kratos.budget.ledger", "kratos.assets.store", "kratos.serve.store",
    "kratos.fleet.groups", "kratos.fleet.record", "kratos.hunt.terms", "kratos.pkgvuln.inventory_store",
    "kratos.hunt.store", "kratos.privacy.pseudonyms", "kratos.events.store", "kratos.outbox.store",
    "kratos.backup.store", "kratos.hashdb.datasets", "kratos.hashdb.store",
    "kratos.compliance.store",
)
# Stores that create their tables in their constructor (no component version).
CONSTRUCTED = (
    ("kratos.storage.session_store", "SessionStore"),
    ("kratos.storage.subagent_store", "SubAgentStore"),
    ("kratos.storage.whitelist_store", "WhitelistStore"),
    ("kratos.storage.anomaly_store", "AnomalyStore"),
)


def known_versions() -> dict[str, int]:
    out: dict[str, int] = {}
    for name in MIGRATED:
        mod = importlib.import_module(name)
        steps = getattr(mod, "STEPS", None) or getattr(mod, "_STEPS")
        out[mod.COMPONENT] = len(steps)
    return out


def newer_components(versions: dict[str, int]) -> dict[str, tuple[int, int]]:
    """{component: (version in the database, newest this Kratos knows)} for each component
    a newer Kratos wrote."""
    known = known_versions()
    return {c: (v, known[c]) for c, v in versions.items() if c in known and int(v) > known[c]}


def migrate_all(db_path: Path) -> dict[str, int]:
    """Bring every component of `db_path` up to this Kratos's version. Returns the versions
    after. Never downgrades (storage.migrations leaves a newer component alone)."""
    from kratos.storage.sqlite_files import connect_store

    conn = connect_store(Path(db_path))
    try:
        for name in MIGRATED:
            mod = importlib.import_module(name)
            steps = getattr(mod, "STEPS", None) or getattr(mod, "_STEPS")
            migrations.migrate(conn, mod.COMPONENT, steps)
        versions = {r[0]: int(r[1]) for r in conn.execute("SELECT component, version FROM schema_versions")}
    finally:
        conn.close()
    for mod_name, cls in CONSTRUCTED:
        getattr(importlib.import_module(mod_name), cls)(Path(db_path))
    from kratos.timewin import snapshots

    try:
        snapshots._db(Path(db_path).parent).close()
    except sqlite3.Error:
        pass
    return versions
