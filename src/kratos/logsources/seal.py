"""Journal sealing (Forward Secure Sealing, FSS) -- the verification key and its checks (0.3, spec §7).

The machine seals its journal with `journalctl --setup-keys` (a human runs it;
Kratos only shows the commands). That prints a *verification key*. Kratos keeps
it on the Kratos host only -- `data_dir/fss/<machine>.json`, owner-only (0600 in a
0700 folder) -- and NEVER sends it to the machine, to the model, to logs or to
transcripts. Verification runs here: journal files are copied from the machine
(SSH as the journal-group user, or the sub-agent's journal_file_chunk read) into
a private temp folder and checked with the local `journalctl --verify
--verify-key=...`, then deleted.

Known limitation (said, not hidden): `--verify-key` puts the key on that local
journalctl's command line for the second it runs, so another user on the Kratos
host could read it from /proc/<pid>/cmdline unless /proc is mounted hidepid.

Archived journal files never change, so each is verified once and its sha256
recorded; later runs re-hash it and skip it if unchanged. A verified archive
whose hash changed was altered (SEAL-001) -- even in parts the seal doesn't
cover. A sealed file failing verification is SEAL-001; files written after
sealing began that aren't sealed mean sealing stopped (SEAL-002); not being able
to check (key for another machine, journal unreadable, this host's journalctl
too old for the file) is SEAL-003, a run note -- never "tampered".
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.logsources import state_store
from kratos.settings_store import SettingError, SettingSpec
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

logger = logging.getLogger(__name__)

# 12-byte seed as four 6-hex groups, then "/<start>-<interval µs>" in hex (systemd's
# journalctl --setup-keys output, verified on systemd 249).
KEY_RE = re.compile(r"^[0-9a-f]{6}(?:-[0-9a-f]{6}){3}/[0-9a-f]{1,16}-[0-9a-f]{1,16}$")
KEY_SEARCH_RE = re.compile(r"[0-9a-f]{6}(?:-[0-9a-f]{6}){3}/[0-9a-f]{1,16}-[0-9a-f]{1,16}")
FSS_DIR = "fss"
VERIFY_TIMEOUT_SECONDS = 120
SEAL_BUDGET_KEY = "logs.seal_copy_budget_mb"
SEAL_INTERVAL_KEY = "logs.seal_verify_interval_minutes"


class SealKeyError(ValueError):
    """A key that doesn't have systemd's verification-key format, or a key file problem."""


def _int_setting(lo: int, hi: int, what: str):
    def check(value: Any) -> int:
        if isinstance(value, bool):
            raise SettingError(f"{what}, {lo}-{hi}")
        try:
            n = int(value)
        except (TypeError, ValueError):
            raise SettingError(f"{what}, {lo}-{hi}") from None
        if n != value and not (isinstance(value, str) and value.strip().isdigit()):
            raise SettingError(f"a whole number of {what}, {lo}-{hi}")
        if not lo <= n <= hi:
            raise SettingError(f"{what}, {lo}-{hi}")
        return n
    return check


settings_store.register(SettingSpec(
    key=SEAL_BUDGET_KEY, default=256, validate=_int_setting(16, 8192, "megabytes"),
    doc="How much sealed journal (MB) one verification copies from a machine; newest files first, the rest next time.",
))
settings_store.register(SettingSpec(
    key=SEAL_INTERVAL_KEY, default=60, validate=_int_setting(5, 10080, "minutes"),
    doc="The least time (minutes) between two background seal verifications of the same machine.",
))


# ---------------------------------------------------------------------------
# The key (Kratos host only)
# ---------------------------------------------------------------------------
def validate_key(key: str) -> str:
    key = str(key or "").strip()
    if not KEY_RE.fullmatch(key):
        raise SealKeyError("that doesn't look like a journal verification key -- it is the line journalctl "
                           "--setup-keys prints, like 'a1b2c3-d4e5f6-a7b8c9-d0e1f2/1a2b3c-35a4e900'")
    return key


def _key_file(data_dir: Path, target: str) -> Path:
    tk = target_key(target)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", tk)
    if safe != tk:
        safe += "-" + hashlib.sha256(tk.encode()).hexdigest()[:8]
    return Path(data_dir) / FSS_DIR / f"{safe}.json"


def _people_only(what: str) -> None:
    """The model suggests, people decide: a sealing key is set or removed only by a
    person (TUI, CLI), never inside an agent tool call (README §3)."""
    tool = settings_store.in_tool_call()
    if tool:
        raise SealKeyError(f"{what} is a person's decision -- refused inside the tool call {tool!r}")


def set_key(data_dir: Path, target: str, key: str, *, set_by: str, machine_id: str | None = None,
            journal_dir: str | None = None) -> Path:
    """Save the verification key for `target` (0600, folder 0700). Replaces an
    existing key. Never logs the key."""
    from kratos import paths as kpaths

    _people_only("setting a journal verification key")
    key = validate_key(key)
    path = _key_file(data_dir, target)
    if path.is_symlink():
        raise SealKeyError(f"{path} is a symbolic link -- refusing to write a key through it")
    kpaths.ensure_private_dir(path.parent)
    os.chmod(path.parent, 0o700)
    doc = {"target": target_key(target), "key": key, "set_at": time.time(), "set_by": str(set_by)[:120],
           "machine_id": machine_id, "journal_dir": journal_dir}
    kpaths.write_private_text(path, json.dumps(doc, indent=2) + "\n")
    os.chmod(path, 0o600)
    return path


def load_key(data_dir: Path, target: str) -> dict[str, Any] | None:
    path = _key_file(data_dir, target)
    try:
        if path.is_symlink():
            logger.warning("ignoring the seal key file for %s: it is a symbolic link", target_key(target))
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.warning("could not read the seal key file for %s (%s)", target_key(target), type(e).__name__)
        return None
    if not isinstance(doc, dict) or not KEY_RE.fullmatch(str(doc.get("key") or "")):
        logger.warning("the seal key file for %s has no valid key", target_key(target))
        return None
    return doc


def has_key(data_dir: Path, target: str) -> bool:
    return load_key(data_dir, target) is not None


def remove_key(data_dir: Path, target: str) -> bool:
    _people_only("removing a journal verification key")
    path = _key_file(data_dir, target)
    if not path.exists():
        return False
    path.unlink()
    return True


def _bind_machine(data_dir: Path, target: str, doc: dict[str, Any], machine_id: str) -> None:
    from kratos import paths as kpaths

    doc = {**doc, "machine_id": machine_id}
    kpaths.write_private_text(_key_file(data_dir, target), json.dumps(doc, indent=2) + "\n")


def keys_on_file(data_dir: Path) -> list[dict[str, Any]]:
    """Every machine with a key: {target, set_at, set_by, machine_id} -- never the key."""
    out = []
    d = Path(data_dir) / FSS_DIR
    for p in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("target"):
            out.append({k: doc.get(k) for k in ("target", "set_at", "set_by", "machine_id", "journal_dir")})
    return out


# ---------------------------------------------------------------------------
# Verifying (Kratos host)
# ---------------------------------------------------------------------------
class SealReader:
    """Reads from the machine (SSH or sub-agent). Tests pass their own."""

    def journal_headers(self) -> Any:
        from kratos.adapters.ssh_remote import fetch_journal_headers

        return fetch_journal_headers()

    def file_hash(self, directory: str, name: str) -> Any:
        from kratos.adapters.ssh_remote import fetch_journal_file_hash

        return fetch_journal_file_hash(directory, name)

    def copy(self, directory: str, name: str, dest: Path, max_bytes: int) -> Any:
        from kratos.adapters.ssh_remote import copy_journal_file

        return copy_journal_file(directory, name, dest, max_bytes)


def _failed(result: Any) -> str | None:
    if isinstance(result, dict):
        return None
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


_UNSUPPORTED = re.compile(r"(Protocol not supported|unsupported|Operation not supported|newer journal|"
                          r"incompatible)", re.IGNORECASE)
_TAIL = re.compile(r"final (\d+) entr(?:y|ies) not sealed")


def verify_file_locally(path: Path, key: str) -> dict[str, Any]:
    """Run this host's `journalctl --verify` on a copied file:
    {result: pass|fail|unsupported|error, detail, unsealed_tail}."""
    exe = shutil.which("journalctl")
    if exe is None:
        return {"result": "unsupported", "detail": "this Kratos host has no journalctl to verify with"}
    try:
        p = subprocess.run([exe, "--verify", f"--verify-key={key}", f"--file={path}"], capture_output=True,
                           text=True, timeout=VERIFY_TIMEOUT_SECONDS, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return {"result": "error", "detail": f"verification took longer than {VERIFY_TIMEOUT_SECONDS}s"}
    from kratos.utils.redact import redact_secrets

    out = redact_secrets((p.stdout or "") + "\n" + (p.stderr or ""), key)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and "old journald version" not in ln]
    tail = _TAIL.search(out)
    if p.returncode == 0 and any(ln.startswith("PASS:") for ln in lines):
        return {"result": "pass", "detail": next((ln for ln in lines if ln.startswith("=>")), "PASS"),
                "unsealed_tail": int(tail.group(1)) if tail else 0,
                "old_format_note": "old journald version" in out}
    if _UNSUPPORTED.search(out) and "Tag failed" not in out:
        return {"result": "unsupported", "detail": " ".join(lines[-2:])[:300]}
    detail = "; ".join(ln for ln in lines if not ln.startswith("FAIL:"))[:300] or "verification failed"
    return {"result": "fail", "detail": detail, "tag_failed": "Tag failed verification" in out}


def _budget_bytes(data_dir: Path) -> int:
    return int(settings_store.get(SEAL_BUDGET_KEY, data_dir=data_dir)) * 1024 * 1024


def verify(data_dir: Path, target: str, *, reader: SealReader | None = None, now: float | None = None,
           stop: threading.Event | None = None) -> dict[str, Any] | None:
    """Verify `target`'s sealed journal. Returns the summary (also remembered for
    check_log_integrity), or None when no key is set for it."""
    data_dir = Path(data_dir)
    doc = load_key(data_dir, target)
    if doc is None:
        return None
    key = doc["key"]
    reader = reader or SealReader()
    now = time.time() if now is None else now
    run_id = None
    try:
        from kratos import run_context

        cur = run_context.current()
        run_id = cur.run_id if cur else None
    except Exception:  # noqa: BLE001
        pass
    summary: dict[str, Any] = {"status": "verified", "checked_at": epoch_to_utc_iso(now), "checked_at_epoch": now,
                               "set_at": epoch_to_utc_iso(doc.get("set_at")) if doc.get("set_at") else None,
                               "passed": [], "failed": [], "changed_archives": [], "unsealed_after_setup": [],
                               "skipped_unchanged": 0, "deferred": [], "notes": [], "unverifiable": None}

    def finish(status: str | None = None, unverifiable: str | None = None) -> dict[str, Any]:
        if unverifiable:
            summary["unverifiable"] = unverifiable
            summary["status"] = "unverifiable"
        elif status:
            summary["status"] = status
        state_store.put_extra(data_dir, target, "seal_last", summary)
        return summary

    headers = reader.journal_headers()
    if (why := _failed(headers)) is not None:
        return finish(unverifiable=f"the machine's journal could not be listed ({why})")
    if not headers.get("available", True):
        return finish(unverifiable="the machine has no journald (journalctl missing)")
    mid = headers.get("machine_id")
    if doc.get("machine_id") and mid and mid != doc["machine_id"]:
        return finish(unverifiable="the key belongs to a different machine (its machine-id changed -- reinstalled "
                                   "or replaced?). Set up sealing again and give Kratos the new key.")
    if mid and not doc.get("machine_id"):
        _bind_machine(data_dir, target, doc, mid)
    files = [f for f in headers.get("files") or [] if f.get("header_read")]
    if not files:
        why = ("the journal directory isn't readable by the SSH user (add it to the systemd-journal group)"
               if headers.get("unreadable_dirs") else "no journal file headers could be read")
        return finish(unverifiable=why)
    sealed = [f for f in files if f.get("sealed")]
    newest_sealed_head = max((f.get("head_realtime") or 0 for f in sealed), default=None)
    for f in files:
        if f.get("sealed"):
            continue
        if newest_sealed_head is not None and (f.get("head_realtime") or 0) > newest_sealed_head:
            summary["unsealed_after_setup"].append({"name": f["name"], "head": epoch_to_utc_iso(f["head_realtime"])
                                                    if f.get("head_realtime") else None})
    if not sealed:
        set_at = doc.get("set_at") or now
        if now - set_at > 86400:
            summary["unsealed_after_setup"].extend(
                {"name": f["name"], "head": None} for f in files if (f.get("head_realtime") or 0) > set_at)
            if not summary["unsealed_after_setup"]:
                summary["notes"].append("no journal file is sealed yet")
        else:
            summary["notes"].append("sealing was set up less than a day ago and no file is sealed yet -- restart "
                                    "systemd-journald on the machine so new files are sealed")
        return finish("no_sealed_files")

    verified = state_store.verified_archives(data_dir, target)
    budget = _budget_bytes(data_dir)
    from kratos import paths as kpaths

    work = Path(data_dir) / "tmp"
    kpaths.ensure_private_dir(work)
    tmpdir = Path(tempfile.mkdtemp(prefix="seal-", dir=work))
    os.chmod(tmpdir, 0o700)
    try:
        archived = sorted((f for f in sealed if f.get("archived")), key=lambda f: f.get("tail_realtime") or 0,
                          reverse=True)
        active = [f for f in sealed if not f.get("archived")]
        used = 0
        for f in [*active, *archived]:
            if stop is not None and stop.is_set():
                summary["notes"].append("stopped early (Kratos was closing)")
                break
            name, directory = f["name"], f["dir"]
            is_archive = bool(f.get("archived"))
            if is_archive:
                h = reader.file_hash(directory, name)
                if (why := _failed(h)) is not None:
                    summary["notes"].append(f"{name}: could not be hashed ({why})")
                    continue
                known = verified.get(name)
                if known and known.get("sha256") == h["sha256"]:
                    summary["skipped_unchanged"] += 1
                    continue
                if known and known.get("sha256") != h["sha256"]:
                    entry = {"name": name, "detail": f"verified on {epoch_to_utc_iso(known['verified_at'])} with "
                                                     f"sha256 {known['sha256'][:12]}..., now {h['sha256'][:12]}..."}
                    summary["changed_archives"].append(entry)
                    state_store.add_verification(data_dir, target, file_name=name, sha256=h["sha256"], size=h.get("size"),
                                                 archived=True, sealed=True, result="fail",
                                                 detail="archive changed after it was verified", run_id=run_id)
                    continue
            size = int(f.get("size") or 0)
            if is_archive and used + size > budget:
                summary["deferred"].append(name)
                continue
            res = _copy_and_verify(reader, directory, name, tmpdir, key, size, retry=not is_archive)
            used += size
            if res["result"] == "pass":
                summary["passed"].append(name)
                if res.get("unsealed_tail"):
                    summary["notes"].append(f"{name}: the newest {res['unsealed_tail']} entr(ies) are written after "
                                            "the last seal -- protected only after the next sealing interval")
                if res.get("old_format_note"):
                    summary["notes"].append(f"{name}: sealed by an older journald -- completeness of the seal "
                                            "sequence can't be guaranteed (journald's own warning)")
            elif res["result"] == "fail" and (is_archive or res.get("tag_failed")):
                summary["failed"].append({"name": name, "detail": res["detail"]})
            elif res["result"] == "unsupported":
                summary["unverifiable"] = (f"this Kratos host's journalctl can't read {name} "
                                           f"({res['detail']}) -- the machine's systemd is newer; not 'tampered'")
            elif res["result"] in ("fail", "copy_error", "error"):
                summary["notes"].append(f"{name}: not verified ({res['detail']})")
            if res["result"] in ("pass", "fail") and res.get("sha256"):
                state_store.add_verification(data_dir, target, file_name=name, sha256=res["sha256"],
                                             size=res.get("bytes"), archived=is_archive, sealed=True,
                                             result=res["result"], detail=str(res.get("detail"))[:500], run_id=run_id)
        if summary["deferred"]:
            summary["notes"].append(f"{len(summary['deferred'])} older sealed file(s) not verified this time (copy "
                                    f"budget {budget // (1024 * 1024)} MB) -- the next verification continues")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    status = "failed" if summary["failed"] or summary["changed_archives"] else "verified"
    return finish(status, summary.get("unverifiable"))


def _copy_and_verify(reader: SealReader, directory: str, name: str, tmpdir: Path, key: str, size: int,
                     retry: bool) -> dict[str, Any]:
    attempts = 2 if retry else 1
    res: dict[str, Any] = {"result": "copy_error", "detail": "not copied"}
    for _ in range(attempts):
        dest = tmpdir / "copy.journal"
        cp = reader.copy(directory, name, dest, max(size, 1) * 2 + 1024 * 1024)
        if (why := _failed(cp)) is not None:
            if dest.exists():
                dest.unlink()
            res = {"result": "copy_error", "detail": why}
            continue
        res = {**verify_file_locally(dest, key), "sha256": cp.get("sha256"), "bytes": cp.get("bytes")}
        dest.unlink(missing_ok=True)
        if res["result"] != "fail" or res.get("tag_failed"):
            break  # a seal failure isn't retried; corruption on the live file is (it is being written)
    return res


def latest_summary(data_dir: Path, target: str) -> dict[str, Any] | None:
    """The last verification of `target` (for check_log_integrity), or None when
    sealing isn't set up for it."""
    if not has_key(data_dir, target):
        return None
    last = state_store.get_extra(data_dir, target, "seal_last")
    if last is None:
        return {"status": "not_verified_yet", "note": "a key is on file; no verification has run yet",
                "failed": [], "changed_archives": [], "unsealed_after_setup": [], "unverifiable": None}
    last.pop("_checked_at", None)
    return last


# ---------------------------------------------------------------------------
# In the background (after an investigation, never blocking it)
# ---------------------------------------------------------------------------
_bg_lock = threading.Lock()
_bg_running: dict[str, threading.Thread] = {}
_bg_stop = threading.Event()


def due(data_dir: Path, target: str, now: float | None = None) -> bool:
    if not has_key(data_dir, target):
        return False
    last = state_store.get_extra(data_dir, target, "seal_last")
    now = time.time() if now is None else now
    minutes = int(settings_store.get(SEAL_INTERVAL_KEY, data_dir=data_dir))
    return last is None or now - float(last.get("checked_at_epoch") or 0) >= minutes * 60


def maybe_verify_in_background(data_dir: Path, target: str, *, reader: SealReader | None = None) -> bool:
    """Start a verification of `target` on a daemon thread if one is due and none
    is running for it. Returns at once (True if one was started). The thread pins
    its target, so switching machines meanwhile can't redirect its reads."""
    if not target or not due(data_dir, target):
        return False
    tk = target_key(target)
    with _bg_lock:
        running = _bg_running.get(tk)
        if running is not None and running.is_alive():
            return False

        def work() -> None:
            from kratos import kratos_config
            from kratos.run_context import run_scope

            try:
                with kratos_config.pinned_target(target), run_scope("schedule", target=tk):
                    verify(data_dir, target, reader=reader, stop=_bg_stop)
            except Exception:  # noqa: BLE001 -- a background check must never surface as a crash
                logger.exception("background seal verification of %s failed", tk)

        t = threading.Thread(target=work, name=f"kratos-seal-{tk}", daemon=True)
        _bg_running[tk] = t
        t.start()
    return True


def stop_background(timeout: float = 2.0) -> None:
    """Ask running background verifications to stop (between files) and wait briefly."""
    _bg_stop.set()
    for t in list(_bg_running.values()):
        t.join(timeout)
    _bg_stop.clear()
