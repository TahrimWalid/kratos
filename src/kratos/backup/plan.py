"""What a backup takes, built from the data inventory (docs/phaseD/D.8 §3.3, §5.1).

`build()` turns `kratos.datainv.CATEGORIES` plus the person's options into the list of
databases and files to copy, each with the category that owns it and the reason it is in
or out. It only lists and stats files -- it reads no contents and writes nothing -- so
`kratos backup create --dry-run` prints exactly what a real backup would take.

Archive paths are relative and start with the root they came from:
``data/`` (the data folder), ``state/`` (Kratos's own folder: kept tools, harnesses,
vulscan) and ``config/`` (the settings folder: ``.env``). A restore maps each back onto
the new computer's own folders -- never onto a path written in the backup.
"""
from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos import datainv, paths

DB_FILES = (datainv.DB, datainv.VULNDB)          # copied with SQLite's backup API
DB_COMPANIONS = ("-wal", "-shm", "-journal")

# Secrets that live inside kratos.db, handled in the database copy by --without-secrets
# (a whole category can't be dropped from one shared database file).
# (table, what is done, plain words)
DB_SECRETS: tuple[tuple[str, str, str], ...] = (
    ("subagent_targets", "token", "each paired agent's pairing token (the agents must be paired again)"),
    ("subagent_pairing_codes", "rows", "unused one-time pairing codes"),
)


# Files inside an included folder that must not travel: a run's ephemeral SSH keys (live
# only while that run lasts), the CA agent's socket and pid (this computer's process).
SKIP: tuple[tuple[str, str], ...] = (
    ("data/ssh-ca/runs/*", "per-run ephemeral SSH keys, alive only while their run lasts"),
    ("data/ssh-ca/agent.sock", "the CA agent's socket on this computer"),
    ("data/ssh-ca/agent.pid", "the CA agent's process id on this computer"),
)


@dataclass(frozen=True)
class Roots:
    data: Path
    state: Path
    config: Path

    @classmethod
    def current(cls, data_dir: Path | str) -> "Roots":
        return cls(Path(data_dir), paths.STATE_ROOT, paths.CONFIG_DIR)

    def for_prefix(self, prefix: str) -> Path:
        return {"data": self.data, "state": self.state, "config": self.config}[prefix]


@dataclass
class Item:
    category: str
    archive: str           # "data/kratos.db", "state/kept_tools/x.py", "config/.env"
    source: Path
    size: int
    mode: int
    kind: str = "file"     # file | db | ca_sealed (a TPM-sealed CA key: unsealed into the stream)
    secret: bool = False


@dataclass
class Decision:
    key: str
    name: str
    cls: str
    included: bool
    reason: str
    files: int = 0
    bytes: int = 0


@dataclass
class Plan:
    roots: Roots
    items: list[Item] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    emptied_tables: list[str] = field(default_factory=list)   # tables of excluded categories, emptied in the copy
    scrubbed: list[str] = field(default_factory=list)          # DB_SECRETS applied (--without-secrets)
    skipped: list[str] = field(default_factory=list)           # links, sockets and other non-files found
    not_included: list[dict[str, str]] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def total_bytes(self) -> int:
        return sum(i.size for i in self.items)

    def as_dict(self) -> dict[str, Any]:
        return {
            "options": self.options,
            "categories": [d.__dict__ for d in self.decisions],
            "files": len(self.items), "bytes": self.total_bytes,
            "secret_files": sum(1 for i in self.items if i.secret),
            "databases": [i.archive for i in self.items if i.kind == "db"],
            "emptied_tables": self.emptied_tables, "scrubbed": self.scrubbed,
            "skipped": self.skipped, "not_included": self.not_included,
        }


class PlanError(ValueError):
    pass


def _walk(top: Path, rel_top: str, skipped: list[str]) -> list[tuple[Path, str, os.stat_result]]:
    """Regular files under `top` (a file or a folder). A top-level link (a folder moved to
    another disk) is followed; links inside are not -- they are listed as skipped."""
    out: list[tuple[Path, str, os.stat_result]] = []
    try:
        st = os.stat(top)                 # follows a top-level link on purpose
    except OSError:
        return out
    if stat.S_ISREG(st.st_mode):
        return [(top, rel_top, st)]
    if not stat.S_ISDIR(st.st_mode):
        skipped.append(f"{rel_top} (not a file or folder)")
        return out
    real = Path(os.path.realpath(top))
    for root, dirs, files in os.walk(real, followlinks=False):
        rel_root = os.path.relpath(root, real)
        for d in list(dirs):
            if os.path.islink(os.path.join(root, d)):
                skipped.append(f"{_join(rel_top, rel_root, d)} (a link, not followed)")
                dirs.remove(d)
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            rel = _join(rel_top, rel_root, f)
            try:
                fst = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(fst.st_mode):
                out.append((Path(p), rel, fst))
            else:
                skipped.append(f"{rel} ({'a link' if stat.S_ISLNK(fst.st_mode) else 'not a regular file'})")
    return out


def _join(top: str, mid: str, name: str) -> str:
    return "/".join(x for x in (top, "" if mid == "." else mid, name) if x)


def _glob(base: Path, pattern: str) -> list[Path]:
    if not base.is_dir():
        return []
    if "/" in pattern:
        p = base / pattern
        return [p] if os.path.lexists(p) else []
    return sorted(p for p in base.iterdir() if fnmatch.fnmatch(p.name, pattern))


def _under(path: Path, roots: Roots) -> bool:
    try:
        rp = Path(os.path.realpath(path))
    except OSError:
        return False
    for r in (roots.data, roots.state, roots.config):
        try:
            rp.relative_to(os.path.realpath(r))
            return True
        except ValueError:
            continue
    return False


def _outside_items(roots: Roots, without_secrets: bool) -> list[dict[str, str]]:
    from kratos import kratos_config

    out = []
    key = Path(kratos_config.SSH_TARGET_KEY_PATH)
    if key.exists() and not _under(key, roots):
        out.append({"what": f"Kratos's SSH key ({key})",
                    "why": "it lives outside Kratos's folders (you may use it for other things)",
                    "fix": "back it up yourself, or enrol your machines in SSH certificates (`kratos ssh-ca`)"})
    kh = getattr(kratos_config, "SSH_KNOWN_HOSTS_PATH", None)
    if kh and Path(kh).exists() and not _under(Path(kh), roots):
        out.append({"what": f"the known_hosts file KRATOS_SSH_KNOWN_HOSTS points to ({kh})",
                    "why": "it lives outside Kratos's folders",
                    "fix": "copy it yourself; on the new computer set KRATOS_SSH_KNOWN_HOSTS to its new place"})
    mode = _ca_mode(roots.data)
    if mode == "token" and not without_secrets:
        out.append({"what": "the SSH certificate authority's private key",
                    "why": "it is held on your hardware token and can't leave it; the backup has its public half",
                    "fix": "keep the token: the restored Kratos signs with it once it is plugged in"})
    return out


def _ca_mode(data_dir: Path) -> str | None:
    import json

    p = Path(data_dir) / "ssh-ca" / "config.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("mode")
    except (OSError, ValueError, AttributeError):
        return None


def build(data_dir: Path | str, *, exclude: tuple[str, ...] | list[str] = (), include_rebuildable: bool = False,
          without_secrets: bool = False, roots: Roots | None = None) -> Plan:
    roots = roots or Roots.current(data_dir)
    keys = {c.key for c in datainv.CATEGORIES}
    unknown = [x for x in exclude if x not in keys]
    if unknown:
        raise PlanError(f"unknown category {', '.join(unknown)}; one of: {', '.join(sorted(keys))}")
    plan = Plan(roots, options={"exclude": sorted(exclude), "include_rebuildable": bool(include_rebuildable),
                                "without_secrets": bool(without_secrets)})
    db_tables_out: list[str] = []
    seen: set[str] = set()
    for c in datainv.CATEGORIES:
        if c.key in exclude:
            included, reason = False, "left out by --exclude"
        elif c.backup == datainv.BACKUP_NEVER:
            included, reason = False, "never backed up: " + c.backup_note
        elif c.backup == datainv.BACKUP_REBUILDABLE and not include_rebuildable:
            included, reason = False, "left out (rebuildable): " + c.backup_note
        elif c.backup == datainv.BACKUP_SECRET and without_secrets:
            included, reason = False, "a secret, left out by --without-secrets"
        else:
            included = True
            reason = {datainv.BACKUP_SECRET: "a secret -- in the encrypted backup",
                      datainv.BACKUP_REBUILDABLE: "rebuildable, included by --include-rebuildable"}.get(c.backup, "in")
            if c.backup_note and c.backup in (datainv.BACKUP_SECRET, datainv.BACKUP_INCLUDE):
                reason += f" ({c.backup_note})"
        d = Decision(c.key, c.name, c.backup, included, reason)
        plan.decisions.append(d)
        if not included:
            db_tables_out += [t for ref in c.tables if ref.db == datainv.DB for t in ref.tables]
            continue
        for prefix, base, globs in (("data", roots.data, c.files), ("state", roots.state, c.state_files),
                                    ("config", roots.config, c.config_files)):
            for pattern in globs:
                for top in _glob(base, pattern):
                    rel_top = os.path.relpath(top, base).replace(os.sep, "/")
                    for src, rel, st in _walk(top, rel_top, plan.skipped):
                        archive = f"{prefix}/{rel}"
                        if archive in seen or any(rel.endswith(db + sfx) for db in DB_FILES for sfx in DB_COMPANIONS):
                            continue
                        if any(fnmatch.fnmatch(archive, pat) for pat, _ in SKIP):
                            continue
                        seen.add(archive)
                        kind = "db" if prefix == "data" and rel in DB_FILES else "file"
                        if c.key == "ssh_ca" and rel.endswith(".cred"):
                            kind = "ca_sealed"
                        plan.items.append(Item(c.key, archive, src, st.st_size, stat.S_IMODE(st.st_mode), kind,
                                               c.backup == datainv.BACKUP_SECRET))
                        d.files += 1
                        d.bytes += st.st_size
    # kratos.db holds the tables of many categories: always copied, as long as any of
    # them is in (its own category row is the database itself).
    db = roots.data / datainv.DB
    if db.is_file():
        st = db.stat()
        plan.items.insert(0, Item("database", f"data/{datainv.DB}", db, st.st_size, stat.S_IMODE(st.st_mode), "db"))
        plan.emptied_tables = sorted(set(db_tables_out))
    if without_secrets:
        plan.scrubbed = [f"{t} ({what})" for t, _, what in DB_SECRETS]
    for entry in datainv.unlisted(roots.data):
        plan.not_included.append({"what": f"{entry.name} in the data folder",
                                  "why": "no Kratos data category owns it (something else put it there)",
                                  "fix": "copy it yourself if you need it"})
    plan.not_included += _outside_items(roots, without_secrets)
    return plan
