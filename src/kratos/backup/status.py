"""What /doctor, `/backup` and `kratos backup status` say about backups (D.8 §3.8, §5.2).

Read-only: settings, `backup_runs` and the backup folder's file sizes. There is no
`backup.keep` (decided 2026-11-10), so the backup folder only grows: its size, its
growth and the disk's free space are shown, with a warning once that disk is 80% full.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

from kratos.backup import settings as BS
from kratos.backup import store as BR
from kratos.utils.timeutil import epoch_of

FULL_DISK_WARN = 0.80
SCHEDULE_GRACE = {"daily": 36 * 3600, "weekly": 8 * 86400 + 12 * 3600}


def ago(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{s // 60} min"
    if s < 2 * 86400:
        return f"{s // 3600} h"
    return f"{s // 86400} days"


def destination(data_dir: Path) -> Path:
    from kratos.backup.create import DEFAULT_DEST

    text = str(BS.get(BS.DESTINATION, data_dir) or "").strip()
    return Path(text).expanduser() if text else DEFAULT_DEST


def backup_files(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.name.startswith("kratos-backup-") and p.name.endswith(".age")
                  and p.is_file())


def summary(data_dir: Path) -> dict[str, Any]:
    data_dir = Path(data_dir)
    now = time.time()
    recips = list(BS.get(BS.RECIPIENTS, data_dir))
    # After a restore, the history in backup_runs describes the OLD computer's backups and
    # disks: only what was done here since the newest restore counts.
    restored = BR.last(data_dir, "restore", outcome="ok")
    since = restored["id"] if restored else 0

    def newest(kind: str, outcome: str | None) -> dict | None:
        rows = [r for r in BR.runs(data_dir, kind=kind, outcome=outcome, limit=200) if r["id"] > since]
        return rows[0] if rows else None

    last_ok = newest("create", "ok")
    last_any = newest("create", None)
    drill = newest("drill", "ok")
    dest = destination(data_dir)
    files = backup_files(dest)
    total = sum(p.stat().st_size for p in files)
    month = sum(p.stat().st_size for p in files if p.stat().st_mtime >= now - 30 * 86400)
    try:
        du = shutil.disk_usage(dest if dest.exists() else dest.parent if dest.parent.exists() else Path.home())
    except OSError:
        du = None
    return {
        "recipients": recips, "schedule": BS.get(BS.SCHEDULE, data_dir), "destination": str(dest),
        "copy_targets": list(BS.get(BS.COPY_TARGETS, data_dir)), "drill_warn_days": BS.get(BS.DRILL_WARN_DAYS, data_dir),
        "last_ok": last_ok, "last_attempt": last_any, "last_drill": drill, "restored": restored,
        "last_ok_age": (now - epoch_of(last_ok["started_at"])) if last_ok else None,
        "last_drill_age": (now - epoch_of(drill["started_at"])) if drill else None,
        "files": len(files), "bytes": total, "bytes_30d": month,
        "disk_used_fraction": (du.used / du.total) if du and du.total else None,
        "disk_free": du.free if du else None,
    }


def doctor_rows(data_dir: Path) -> list[dict[str, str]]:
    from kratos.datainv import human_size

    s = summary(data_dir)
    rows: list[dict[str, str]] = []

    def row(check: str, status: str, detail: str, fix: str = "") -> None:
        r = {"check": check, "status": status, "detail": detail}
        if fix:
            r["fix"] = fix
        rows.append(r)

    if s["recipients"]:
        row("backup lock", "pass", f"encrypted to {len(s['recipients'])} recipient key(s); this computer holds no "
                                   "key that can open a backup")
    else:
        row("backup lock", "warn", "no backup key set up: backups can only be made by hand with a passphrase",
            fix="`kratos backup key new` (the secret half goes off this computer; scheduled backups need it)")
    from kratos.backup import origin

    signer = origin.signer_fingerprint(Path(data_dir))
    if s["recipients"] and signer:
        row("backup signer", "info", f"backups are signed by {signer} -- keep it with your backup key: a restore "
                                     "on a new computer checks it")
    restored = s.get("restored")
    if restored:
        d = restored.get("detail") or {}
        row("restored from", "info", f"a backup made {d.get('made', '?')} on {d.get('from_host', '?')}, restored "
                                     f"{ago(time.time() - (epoch_of(restored['started_at']) or time.time()))} ago "
                                     "(backups and drills before that were the old computer's)")
    last = s["last_ok"]
    if last is None:
        row("last backup", "warn", "none made yet", fix="`kratos backup create`, then `kratos backup drill <file>`")
    else:
        age = s["last_ok_age"] or 0
        detail = f"{ago(age)} ago ({last.get('file')})"
        status = "pass"
        fix = ""
        if last.get("file") and not Path(last["file"]).exists():
            status, fix = "warn", "the file is gone from where it was written; make a new backup"
            detail += " -- the file is no longer there"
        grace = SCHEDULE_GRACE.get(s["schedule"])
        if grace and age > grace:
            status = "warn"
            fix = f"the backup timer is set to {s['schedule']} but the newest backup is older: check " \
                  "`systemctl --user status kratos-backup.timer`"
        row("last backup", status, detail, fix)
        if last.get("same_disk"):
            copied = [c for c in (last.get("copies") or []) if isinstance(c, dict) and c.get("ok")
                      and not c.get("same_disk")]
            if not copied:
                row("backup on same disk", "warn", "the newest backup is on the same disk as the data it protects",
                    fix="copy it somewhere else: `kratos backup schedule daily --copy-to /mnt/usb/kratos` or "
                        "--copy-to sftp://user@host/path")
    attempt = s["last_attempt"]
    if attempt and attempt.get("outcome") == "failed" and (not last or attempt["id"] > last["id"]):
        row("backup failed", "fail", f"the newest backup attempt failed: {attempt.get('error') or 'see backup_runs'}",
            fix="run `kratos backup create` by hand to see why")
    drill_days = int(s["drill_warn_days"])
    if s["last_drill"] is None:
        if last is not None:
            row("restore drill", "warn", "no restore drill has passed yet -- a backup counts as verified only "
                                         "after one", fix=f"`kratos backup drill {last.get('file') or '<file>'}`")
    else:
        age = s["last_drill_age"] or 0
        status = "pass" if age <= drill_days * 86400 else "warn"
        row("restore drill", status, f"last successful drill {ago(age)} ago",
            "" if status == "pass" else f"no successful drill in {drill_days} days: `kratos backup drill <file>`")
    try:
        from kratos.backup import plan as P

        for item in P._outside_items(P.Roots.current(data_dir), False):
            row("not in backups", "info", f"{item['what']}: {item['why']}", item["fix"])
    except Exception:  # noqa: BLE001 -- a status row must never break /doctor
        pass
    if s["files"]:
        frac = s["disk_used_fraction"]
        detail = (f"{s['files']} backup(s), {human_size(s['bytes'])} in {s['destination']} "
                  f"(+{human_size(s['bytes_30d'])} in the last 30 days); Kratos deletes none on its own")
        if frac is not None and frac >= FULL_DISK_WARN:
            row("backup folder", "warn", detail + f"; that disk is {frac:.0%} full",
                fix="move old backups elsewhere, or `kratos backup prune --keep N` (shown first)")
        else:
            row("backup folder", "info", detail)
    return rows

