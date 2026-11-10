"""Restoring a backup (docs/phaseD/D.8 §3.9).

Careful by construction:

- By default only into an EMPTY Kratos home (a fresh install, a new KRATOS_HOME). A home
  holding only what Kratos writes on its own first start counts as empty.
- ``--replace`` first backs up the current state (to the same recipients; with no
  recipients set up, a passphrase the person types), then MOVES the current folders aside
  to ``<folder>.pre-restore-<UTC time>`` (owner-only, never deleted), then restores.
  Restore deletes nothing of the person's.
- Refuses while anything has the data open: the in-use lock (TUI, ``kratos serve``,
  ``kratos mcp-serve``, the agent listener, a scheduled run), a live listener status row,
  something answering on the agent port. It prints the exact stop and start lines.
- Refuses a backup made by a NEWER Kratos (naming the version needed); an older one is
  restored and migrated on first open (`stores.migrate_all`).
- Every member is checked against the manifest (kratos.backup.archive) and written to a
  staging folder inside ``<data>/.backup-work`` first; only when ALL of it checked out are
  the staged folders moved into place. Files are written 0600, folders 0700.
- Afterwards: a TPM-sealed CA key is sealed again to this computer's TPM (or kept in the
  mode the person picks) without touching disk on the way; the addresses the agents dial
  are compared with this computer's, and upgrade installers (same token, same pins) are
  written for agents that must dial somewhere new.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos import paths
from kratos.backup import archive as AR
from kratos.backup import inuse
from kratos.backup import store as BR
from kratos.backup.plan import Roots

LISTENER_SERVICE = "kratos-core-listener"
FRESH_TABLES = {   # tables Kratos fills on its own the first time a command runs
    "schema_versions", "audit_log", "audit_log_prune_permit", "users", "budget_state", "app_settings",
    "disk_samples", "collect_state", "backup_runs",
}


class RestoreError(RuntimeError):
    """Why a restore can't go ahead, in plain words with the fix."""


@dataclass
class Staged:
    manifest: dict[str, Any]
    folder: Path
    memory: dict[str, bytes] = field(default_factory=dict)
    files: int = 0
    bytes: int = 0


@dataclass
class RestoreResult:
    manifest: dict[str, Any]
    files: int = 0
    bytes: int = 0
    moved_aside: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    agents: list[dict[str, Any]] = field(default_factory=list)
    installers: list[str] = field(default_factory=list)
    pre_backup: str | None = None
    dry_run: bool = False


Progress = Callable[[str], None]


def _noop(_text: str) -> None:
    return None


# --------------------------------------------------------------------------- staging (shared)
def _new_dir(path: Path) -> Path:
    os.makedirs(path.parent, mode=0o700, exist_ok=True)
    os.mkdir(path, 0o700)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise RestoreError(f"{path} is not a folder")
    return path


def _write_member(root: Path, member: AR.Member) -> int:
    target = root / member.prefix / member.rel
    parent = target.parent
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        raise AR.ArchiveError(f"{member.path!r:.80} collides with another file in the backup") from None
    real_parent = os.path.realpath(parent)
    if not real_parent.startswith(os.path.realpath(root) + os.sep):
        raise AR.ArchiveError(f"{member.path!r:.80} would land outside the restore folder")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    n = 0
    try:
        with os.fdopen(fd, "wb") as w:
            for block in member.chunks():
                w.write(block)
                n += len(block)
            w.flush()
            os.fsync(w.fileno())
    except BaseException:
        try:
            os.unlink(target)   # deletion-scan: the half-written member that failed its check
        except OSError:
            pass
        raise
    return n


def stage(backup: Path, identities: list[object], folder: Path, *, write: bool = True,
          progress: Progress = _noop, need_free: bool = True) -> Staged:
    """Decrypt, check and (with `write`) write every member into `folder`/{data,state,config}.
    A CA key unsealed from a TPM is kept in memory, never written. On any failure nothing
    is left behind: the staging folder is removed."""
    if write:
        _new_dir(folder)
    try:
        with AR.opened(backup, identities) as ar:
            m = ar.read_manifest()
            need = AR.newer_than_this(m)
            if need:
                from kratos import __version__

                raise RestoreError(f"this backup was made by Kratos {need}; this is Kratos {__version__}. "
                                   f"Update Kratos first (pip install -U kratos-security-assistant), then restore.")
            total = int(m["totals"]["bytes"])
            if write and need_free:
                free = shutil.disk_usage(folder).free
                if free < total * 1.05 + 20_000_000:
                    raise RestoreError(f"not enough free space to restore: it needs about {total // 1_000_000 + 20} "
                                       f"MB, {free // 1_000_000} MB are free")
            st = Staged(m, folder)
            progress(f"checking {m['totals']['files']} files ({total // 1_000_000} MB)")
            for member in ar.members():
                if member.entry.get("kind") == "ca_unsealed":
                    st.memory[member.path] = member.read_all(cap=1 << 20)
                    st.bytes += member.entry["size"]
                elif write:
                    st.bytes += _write_member(folder, member)
                else:
                    for _block in member.chunks():
                        pass
                    st.bytes += member.entry["size"]
                st.files += 1
            ar.finish()
            return st
    except BaseException:
        if write and folder.exists():
            shutil.rmtree(folder, ignore_errors=True)   # deletion-scan: this restore's own staging copy
        raise


# --------------------------------------------------------------------------- pre-checks
def is_fresh(roots: Roots) -> tuple[bool, list[str]]:
    """Is there nothing here a person made? (what is here, when not)"""
    from kratos import datainv

    found: list[str] = []
    d = roots.data
    if d.is_dir():
        for entry in sorted(d.iterdir()):
            owner = datainv.owner_of(entry.name)
            if owner in ("runtime",) or entry.name == "backup":
                continue
            if owner == "database":
                busy = _db_rows(entry)
                if busy:
                    found.append(f"{entry} (holds data: {', '.join(busy[:4])})")
                continue
            if entry.is_dir() and not any(entry.iterdir()):
                continue
            found.append(str(entry))
    for c in datainv.CATEGORIES:
        for p in c.state_files:
            q = roots.state / p
            if q.exists() and (not q.is_dir() or any(q.iterdir())):
                if c.key == "kept_tools" and p == "tests/self_write_harnesses":
                    continue   # a source checkout ships this folder with its own example harness
                found.append(str(q))
    env = roots.config / ".env"
    if env.exists() and not _is_template_env(env):
        found.append(f"{env} (your settings)")
    return (not found), found


def _is_template_env(path: Path) -> bool:
    try:
        from importlib import resources

        tmpl = resources.files("kratos").joinpath("templates/env.example").read_text(encoding="utf-8")
        return path.read_text(encoding="utf-8").strip() == tmpl.strip()
    except (OSError, UnicodeDecodeError):
        return False


def _db_rows(db: Path) -> list[str]:
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return ["unreadable"]
    try:
        out = []
        for (t,) in conn.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            if t in FRESH_TABLES:
                continue
            n = conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]  # noqa: S608 -- names from the schema
            if n:
                out.append(f"{t} {n}")
        if "users" in {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}:
            n = conn.execute("SELECT COUNT(*) FROM users WHERE user_id != 'owner'").fetchone()[0]
            if n:
                out.append(f"users {n}")
        return out
    except sqlite3.Error:
        return ["unreadable"]
    finally:
        conn.close()


def running(roots: Roots) -> list[str]:
    """What has this data open right now (empty when nothing)."""
    out = []
    db = roots.data / "kratos.db"
    if db.exists():
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
            try:
                names = {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
                if "subagent_listeners" in names:
                    cutoff = time.time() - 90
                    for row in conn.execute("SELECT pid, host, port, heartbeat_at FROM subagent_listeners "
                                            "WHERE stopped_at IS NULL"):
                        from kratos.utils.timeutil import epoch_of

                        hb = epoch_of(row[3])
                        if hb is not None and hb >= cutoff:
                            out.append(f"the agent listener (pid {row[0]}, {row[1]}:{row[2]})")
            finally:
                conn.close()
        except sqlite3.Error:
            pass
    serve = roots.data / "serve"
    for status in serve.glob("*.json") if serve.is_dir() else []:
        try:
            doc = json.loads(status.read_text(encoding="utf-8"))
            pid = int(doc.get("pid") or 0)
            if pid and _pid_alive(pid):
                out.append(f"kratos serve (pid {pid})")
        except (OSError, ValueError, TypeError):
            continue
    return out


def port_note() -> str | None:
    """Something on this computer answers on the agent port. A listener of THIS data is
    already caught by the in-use lock and its status rows; this may be another Kratos, so
    it is said, not refused: the restored listener can't start until that one stops."""
    port = _agent_port_open()
    if port:
        return (f"something on this computer is listening on the agent port ({port}) -- if it is another Kratos's "
                "listener, stop it before starting this one")
    return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _agent_port_open() -> str | None:
    from kratos.subagent.installer import DEFAULT_CORE_PORT

    for host in ("127.0.0.1",):
        try:
            with socket.create_connection((host, DEFAULT_CORE_PORT), timeout=0.5):
                return f"{host}:{DEFAULT_CORE_PORT}"
        except OSError:
            continue
    return None


def stop_start_lines() -> tuple[list[str], list[str]]:
    stop = [f"systemctl --user stop {LISTENER_SERVICE}", "# and close the Kratos app, `kratos serve` and "
            "`kratos mcp-serve` if they are open; wait for a scheduled run to finish"]
    start = [f"systemctl --user start {LISTENER_SERVICE}"]
    return stop, start


# --------------------------------------------------------------------------- restore
def _authorize(actor: Any, data_dir: Path) -> None:
    from kratos import authz

    if getattr(actor, "interface", None) != "cli":
        raise RestoreError("restore is done only from the command line on the Kratos computer "
                           "(`kratos backup restore`) -- the app itself holds the data open")
    try:
        authz.require(actor, authz.P.BACKUP_RESTORE, data_dir=data_dir, obj="backup restore")
    except authz.Denied as e:
        raise RestoreError(f"refused: {e}") from None


def _state_patterns() -> list[str]:
    from kratos import datainv

    return [p for c in datainv.CATEGORIES for p in c.state_files]


def _installed_tops(st: Staged) -> dict[str, set[str]]:
    """What the backup installs, by root: data top-level names, state patterns, config files."""
    out: dict[str, set[str]] = {"data": set(), "state": set(), "config": set()}
    pats = sorted(_state_patterns(), key=len, reverse=True)
    for e in st.manifest["files"]:
        prefix, _, rel = e["path"].partition("/")
        if prefix == "data":
            out["data"].add(rel.split("/")[0])
        elif prefix == "state":
            for p in pats:
                if rel == p or rel.startswith(p + "/"):
                    out["state"].add(p)
                    break
        else:
            out["config"].add(rel)
    return out


def _move_aside(roots: Roots, tops: dict[str, set[str]], stamp: str) -> list[tuple[str, str]]:
    moved: list[tuple[str, str]] = []
    aside = roots.data.parent / f"{roots.data.name}.pre-restore-{stamp}"
    keep = {".backup-work", "locks"}
    if roots.data.is_dir():
        entries = [e for e in sorted(roots.data.iterdir()) if e.name not in keep]
        if entries:
            _new_dir(aside)
            for e in entries:
                os.rename(e, aside / e.name)
                moved.append((str(e), str(aside / e.name)))
    for p in sorted(tops["state"]):
        src = roots.state / p
        if src.exists() or src.is_symlink():
            dst = src.with_name(src.name + f".pre-restore-{stamp}")
            os.rename(src, dst)
            moved.append((str(src), str(dst)))
    for p in sorted(tops["config"]):
        src = roots.config / p
        if src.exists() or src.is_symlink():
            dst = src.with_name(src.name + f".pre-restore-{stamp}")
            os.rename(src, dst)
            moved.append((str(src), str(dst)))
    return moved


def _install(st: Staged, roots: Roots, tops: dict[str, set[str]]) -> None:
    staged = st.folder
    for name in sorted(tops["data"]):
        src = staged / "data" / name
        if src.exists():
            dst = roots.data / name
            if os.path.lexists(dst):
                raise RestoreError(f"{dst} appeared while restoring; nothing of it was overwritten")
            os.rename(src, dst)
    for p in sorted(tops["state"]):
        src = staged / "state" / p
        if src.exists():
            dst = roots.state / p
            paths.ensure_private_dir(dst.parent)
            if os.path.lexists(dst):
                raise RestoreError(f"{dst} appeared while restoring; nothing of it was overwritten")
            _move(src, dst)
    for p in sorted(tops["config"]):
        src = staged / "config" / p
        if src.exists():
            dst = roots.config / p
            paths.ensure_private_dir(dst.parent)
            if os.path.lexists(dst):
                raise RestoreError(f"{dst} appeared while restoring; nothing of it was overwritten")
            _move(src, dst)
    for sub in ("data", "state", "config"):
        _rmdirs(staged / sub)
    try:
        os.rmdir(staged)   # deletion-scan: the now-empty staging folder
    except OSError:
        pass


def _move(src: Path, dst: Path) -> None:
    try:
        os.rename(src, dst)
    except OSError:
        shutil.move(str(src), str(dst))   # another disk: copy then remove the staged copy


def _rmdirs(folder: Path) -> None:
    if not folder.is_dir():
        return
    for root, dirs, files in os.walk(folder, topdown=False):
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))   # deletion-scan: empty staging folders
            except OSError:
                pass
    try:
        os.rmdir(folder)   # deletion-scan: empty staging folders
    except OSError:
        pass


def _restore_ca(st: Staged, roots: Roots, ca_mode: str | None, notes: list[str]) -> None:
    if not st.memory:
        return
    from kratos.sshca import ca as _ca

    mode = ca_mode or ("tpm" if _ca.has_tpm2() else "file")
    if mode not in ("tpm", "file", "agent"):
        raise RestoreError("the CA mode for a restored TPM-sealed key is tpm, file or agent")
    data_dir = roots.data
    db = data_dir / "kratos.db"
    _ca._ensure_dir(_ca.ca_dir(data_dir))
    for path, priv in st.memory.items():
        rel = path.split("/", 1)[1]                      # ssh-ca/<key_ref>
        target = data_dir / rel
        key_ref = target.name
        if mode == "tpm":
            _ca._seal_private(data_dir, target, priv)
        else:
            _ca._write_private(target, priv)
        conn = sqlite3.connect(db)
        try:
            conn.execute("UPDATE ssh_ca_keys SET mode = ? WHERE key_ref = ?", (mode, key_ref))
            conn.commit()
        finally:
            conn.close()
    _ca._write_config(data_dir, mode=mode)
    st.memory.clear()
    where = "sealed again to this computer's TPM" if mode == "tpm" else (
        "kept as an owner-only file (ssh-ca/)" if mode == "file" else "kept for the CA agent (`kratos ssh-ca unlock`)")
    notes.append(f"the SSH CA key was TPM-sealed on the old computer; it is now {where}")


def _local_addresses() -> set[str]:
    out: set[str] = set()
    try:
        from kratos.subagent.hub_address import candidate_hub_addresses

        out |= {c.address for c in candidate_hub_addresses() if c.address}
    except Exception:  # noqa: BLE001
        pass
    try:
        proc = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, timeout=5)
        for iface in json.loads(proc.stdout or b"[]"):
            for a in iface.get("addr_info", []):
                if a.get("local"):
                    out.add(str(a["local"]))
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        out.add(socket.gethostname())
        out.add(socket.getfqdn())
    except OSError:
        pass
    return out


def _resolves_here(address: str, local: set[str]) -> bool:
    if address in local:
        return True
    try:
        infos = socket.getaddrinfo(address, None)
    except OSError:
        return False
    return any(i[4][0] in local for i in infos)


def agent_step(roots: Roots, manifest: dict[str, Any], *, hub_address: str | None = None) -> tuple[list[dict], list[str]]:
    """Each agent: does it dial an address this computer has? If not, an upgrade installer
    (same token and pins, the new address) is written for it."""
    agents = [a for a in manifest.get("agents") or [] if isinstance(a, dict)]
    if not agents:
        return [], []
    local = _local_addresses()
    out, written = [], []
    pins = None
    try:
        from kratos.subagent import tls

        ks = tls.load_keys(roots.data)
        pins = ks.as_pin_set() if ks is not None else None
    except Exception:  # noqa: BLE001
        pins = None
    new_host = hub_address
    if not new_host:
        try:
            from kratos.subagent.hub_address import candidate_hub_addresses

            new_host = next((c.address for c in candidate_hub_addresses() if c.address), None)
        except Exception:  # noqa: BLE001
            new_host = None
    for a in agents:
        dial = str(a.get("dials") or "")
        label = str(a.get("name") or a.get("hostname") or a.get("target_id") or "agent")[:64]
        same = bool(dial) and _resolves_here(dial, local)
        row = {"target_id": a.get("target_id"), "name": label, "dials": dial or None, "same": same}
        if not same:
            if not new_host:
                row["note"] = "this computer's address is unknown: pass --hub-address"
            elif pins is None:
                row["note"] = "no agent-link keys were restored (a --without-secrets backup): pair this machine again"
            else:
                from kratos.subagent import installer
                from kratos.utils.hostnames import is_ip_or_hostname

                if not is_ip_or_hostname(new_host):
                    row["note"] = f"{new_host!r} is not an address"
                else:
                    port = a.get("port") if isinstance(a.get("port"), int) else installer.DEFAULT_CORE_PORT
                    script = installer.generate_installer(new_host, None, core_port=port, upgrade=True,
                                                          server_pins=pins)
                    row["port"] = port
                    slug = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in label)[:40] or "agent"
                    path = roots.data / f"kratos-subagent-upgrade-{slug}.sh"
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(script)
                    row["installer"] = str(path)
                    row["new_address"] = new_host
                    written.append(str(path))
        out.append(row)
    return out, written


def _outgoing_address(host: str) -> str | None:
    """The address this computer sends from to reach `host` (a routing lookup; no packet
    leaves the computer)."""
    try:
        infos = socket.getaddrinfo(host, 22, type=socket.SOCK_DGRAM)
    except OSError:
        return None
    for family, _t, _p, _c, addr in infos:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sk:
                sk.connect(addr)
                return sk.getsockname()[0]
        except OSError:
            continue
    return None


def ssh_certificate_step(roots: Roots, *, local: set[str] | None = None) -> list[str]:
    """D.1 certificates carry a `source-address`: the address each machine saw Kratos from.
    On a computer with a different address, those certificates would be refused -- and a
    certificate-only machine has no old key to fall back on. Each enrolment is bound to the
    address this computer reaches that machine from, and the person is told to confirm with
    `kratos ssh-ca verify`."""
    notes: list[str] = []
    try:
        from kratos.sshca import store as _st

        enrolments = _st.list_enrolments(roots.data)
    except Exception:  # noqa: BLE001 -- no enrolments, or no CA in this backup
        return notes
    local = _local_addresses() if local is None else local
    for enr in enrolments:
        if not enr.source_address_enabled or not enr.apparent_address or enr.apparent_address in local:
            continue
        new = _outgoing_address(enr.host)
        if not new or new == enr.apparent_address:
            notes.append(f"{enr.host}: its SSH certificates were bound to {enr.apparent_address}; this computer's "
                         f"address there is unknown -- run `kratos ssh-ca verify {enr.host}` from here")
            continue
        _st.set_apparent_address(roots.data, enr.host, new)
        notes.append(f"{enr.host}: SSH certificates are now bound to {new}, the address this computer reaches it "
                     f"from (was {enr.apparent_address}); confirm with `kratos ssh-ca verify {enr.host}` (behind NAT, "
                     "the machine may see another address)")
    return notes


def restore(backup: Path, identities: list[object], *, roots: Roots, actor: Any, replace: bool = False,
            ca_mode: str | None = None, hub_address: str | None = None, dry_run: bool = False,
            pre_backup_passphrase: str | None = None, progress: Progress = _noop,
            authorize: bool = True, check_running: bool = True, kind: str = "restore") -> RestoreResult:
    """Restore `backup` into `roots`. `authorize`/`check_running` are off only for the
    drill, which restores into its own scratch home."""
    backup = Path(backup)
    paths.ensure_private_dir(roots.data)
    if authorize:
        _authorize(actor, roots.data)
    lock = inuse.exclusive(roots.data) if check_running else None
    if check_running and lock is None:
        stop, start = stop_start_lines()
        raise RestoreError("Kratos is using this data right now (the app, `kratos serve`, `kratos mcp-serve`, the "
                           "agent listener or a scheduled run). Stop them first:\n  " + "\n  ".join(stop)
                           + "\nAfterwards start them again:\n  " + "\n  ".join(start))
    block = inuse.backup_lock(roots.data) if check_running else None
    try:
        if check_running:
            if block is None:
                raise RestoreError("a backup or restore of this data is running; wait for it to finish")
            busy = running(roots)
            if busy:
                stop, start = stop_start_lines()
                raise RestoreError("Kratos is still running here: " + "; ".join(busy) + ". Stop it first:\n  "
                                   + "\n  ".join(stop) + "\nAfterwards:\n  " + "\n  ".join(start))
        fresh, found = is_fresh(roots)
        if not fresh and not replace and not dry_run:
            raise RestoreError("this Kratos home already holds data:\n  " + "\n  ".join(found[:8])
                               + "\nRestore into a fresh install (or a new KRATOS_HOME), or use --replace: the "
                               "current state is backed up first and moved aside (nothing is deleted).")
        result = RestoreResult({}, dry_run=dry_run)
        note = port_note() if check_running else None
        if note:
            result.notes.append(note)
        if dry_run:
            st = stage(backup, identities, roots.data / ".backup-work" / "unused", write=False, progress=progress)
            result.manifest, result.files, result.bytes = st.manifest, st.files, st.bytes
            tops = _installed_tops(st)
            result.notes += _summary_notes(st.manifest, tops, roots, fresh, found)
            return result
        from kratos.backup.create import utc_stamp, work_dir

        work = work_dir(roots.data)
        folder = work / f"restore-{uuid.uuid4().hex[:12]}"
        st = stage(backup, identities, folder, progress=progress)
        try:
            tops = _installed_tops(st)
            if replace and not fresh:
                progress("backing up the current state first")
                result.pre_backup = _pre_backup(roots, actor, pre_backup_passphrase)
            stamp = utc_stamp()
            progress("moving the current data aside")
            result.moved_aside = _move_aside(roots, tops, stamp)
            progress("putting the restored data in place")
            _install(st, roots, tops)
        except BaseException:
            if folder.exists():
                shutil.rmtree(folder, ignore_errors=True)   # deletion-scan: this restore's own staging copy
            raise
        result.manifest, result.files, result.bytes = st.manifest, st.files, st.bytes
        db = roots.data / "kratos.db"
        if db.exists():
            from kratos.backup import stores

            stores.migrate_all(db)
        _restore_ca(st, roots, ca_mode, result.notes)
        if kind == "restore":
            result.notes += ssh_certificate_step(roots)
        result.notes += _summary_notes(st.manifest, tops, roots, fresh, found, done=True)
        result.agents, result.installers = agent_step(roots, st.manifest, hub_address=hub_address)
        BR.record(roots.data, kind, actor, "ok", file=str(backup), size=backup.stat().st_size,
                  detail={"files": result.files, "bytes": result.bytes, "moved_aside": result.moved_aside,
                          "from_host": st.manifest.get("host"), "made": st.manifest.get("created"),
                          "pre_backup": result.pre_backup, "agents": result.agents})
        if authorize:
            from kratos import authz

            try:   # the restored trail records the restore too
                authz.require(actor, authz.P.BACKUP_RESTORE, data_dir=roots.data, obj=f"backup restored from "
                              f"{backup.name}")
            except authz.Denied:
                pass
        return result
    finally:
        inuse.release(block)
        inuse.release(lock)


def _pre_backup(roots: Roots, actor: Any, passphrase: str | None) -> str:
    from kratos.backup import create as CR
    from kratos.backup import keys as K

    recs = []
    try:
        recs = K.recipients(roots.data)
    except Exception:  # noqa: BLE001
        recs = []
    if not recs and not passphrase:
        raise RestoreError("--replace backs up the current state first, but no backup key is set up here: run "
                           "`kratos backup key new`, or answer the passphrase question")
    res = CR.create(roots.data, actor=actor, passphrase=passphrase if not recs else None, roots=roots,
                    copy_to=[], lock_held=True)
    return str(res.file)


def _summary_notes(m: dict[str, Any], tops: dict[str, set[str]], roots: Roots, fresh: bool, found: list[str],
                   done: bool = False) -> list[str]:
    notes = []
    opts = m.get("options") or {}
    if opts.get("without_secrets"):
        notes.append("this backup was made --without-secrets: pair your agents again (`/subagent`), set up and "
                     "enrol SSH certificates again (`kratos ssh-ca setup`), re-enter API keys in .env, set "
                     "journal seal keys again (`kratos seal set-key`); a new signing key is made on first use "
                     "(bundles signed by the old one still verify with its public key)")
    for item in m.get("not_included") or []:
        if isinstance(item, dict) and "SSH key" in str(item.get("what")):
            notes.append(f"not in this backup: {item.get('what')} -- {item.get('fix')}")
    out = [c for c in m.get("categories") or [] if isinstance(c, dict) and not c.get("included")
           and c.get("class") == "rebuildable"]
    if out:
        notes.append("left out of the backup, rebuild them: " + "; ".join(str(c.get("reason", "")).split(": ", 1)[-1]
                                                                           for c in out))
    if any(p.endswith("systemd") or p == "schedules" for p in tops["data"]):
        notes.append("timers are files Kratos wrote, not installed on this computer yet: install your schedules' "
                     "timers again from /schedules in the app, and re-run `kratos backup schedule …` and "
                     "`kratos vulndb-update --timer …` if you used them")
    if not fresh and not done:
        notes.append("--replace: this home holds data; it would be backed up and moved aside")
    return notes


def wait_for_agents(data_dir: Path, agents: list[dict[str, Any]], *, since: float, timeout: float = 120,
                    on_seen: Callable[[dict[str, Any]], None] = lambda a: None) -> list[str]:
    """Poll the restored database until each agent that dials this computer has connected
    (the listener records it). Returns the names still missing."""
    from kratos.storage.subagent_store import SubAgentStore
    from kratos.utils.timeutil import epoch_of

    waiting = {a["target_id"]: a for a in agents if a.get("same") and a.get("target_id")}
    store = SubAgentStore(Path(data_dir) / "kratos.db")
    deadline = time.monotonic() + timeout
    while waiting and time.monotonic() < deadline:
        for t in store.list_targets(include_revoked=False):
            tid = t.get("target_id")
            seen = epoch_of(t.get("last_seen"))
            if tid in waiting and seen is not None and seen >= since:
                on_seen(waiting.pop(tid))
        if waiting:
            time.sleep(2)
    return [str(a.get("name")) for a in waiting.values()]
