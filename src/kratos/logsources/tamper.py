"""Signs that a machine's logs were cleared or edited (0.3, spec §6).

Each check is a pure function over what the reads returned (hostfiles parsers)
and what was remembered last time (state_store), returning

    {"id", "status": "ok" | "suspicious" | "unknown", "evidence": [...],
     "coverage": "...", "items": [...]}

`items` are the individual signals the rule engine turns into findings
(LOG-001..005). Heuristics, so each one says exactly what it saw; the first
look at a machine is a baseline, never a finding.

  file_state      a log truncated, replaced, rewritten in place or deleted
                  outside rotation (LOG-001; wtmp/btmp shrinking: LOG-004)
  journal         a journal file missing from the middle of history (LOG-002)
  boots           a previous boot that ended without a clean shutdown (LOG-003)
  login_records   zeroed or out-of-order wtmp/btmp records (LOG-004)
  auditd          auditd stopped, disabled or its rules emptied (LOG-005)
"""
from __future__ import annotations

import time
from typing import Any

from kratos.logsources import catalog as _catalog, utmp as _utmp
from kratos.utils.timeutil import epoch_to_utc_iso

UTMP_NAMES = ("wtmp", "btmp")
HEAD_BYTES = _catalog.HEAD_HASH_BYTES   # how much of each file is hashed
COPYTRUNCATE_SLACK_BYTES = 4096
JOURNAL_GAP_MIN_ENTRIES = 64          # unexplained missing entries before a gap counts
JOURNAL_GAP_MIN_FRACTION = 0.10
BOOT_LOOKBACK_SECONDS = 30 * 86400
_PRESENT = ("ok", "no_content", "hardlink")


def _when(epoch: float | None) -> str:
    return epoch_to_utc_iso(epoch) if epoch is not None else "an earlier check"


def _base(path: str) -> str:
    return path.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# §6.1 log file state
# ---------------------------------------------------------------------------
def _rotated(prev: dict[str, Any], rot: dict[str, Any] | None, lr_now: str | None, lr_before: str | None) -> str | None:
    """Why this looks like a rotation since the last check, or None."""
    if rot and rot.get("status") in _PRESENT:
        if prev.get("inode") is not None and rot.get("inode") == prev.get("inode"):
            return f"the previous file is now {_base(rot['path'])} (rename rotation)"
        if prev.get("rot_inode") is None:
            return f"{_base(rot['path'])} appeared since the last check"
        if (rot.get("inode"), rot.get("size"), rot.get("mtime")) != (prev.get("rot_inode"), prev.get("rot_size"),
                                                                      prev.get("rot_mtime")):
            return f"{_base(rot['path'])} changed since the last check"
    if lr_now and lr_before and lr_now != lr_before:
        return f"logrotate recorded a rotation ({lr_now})"
    return None


def check_file_states(current: dict[str, Any], previous: dict[str, dict[str, Any]],
                      logrotate_before: dict[str, str] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(check result, rows to remember). `current`: hostfiles.parse_file_states."""
    items: list[dict[str, Any]] = []
    evidence: list[str] = []
    rows: list[dict[str, Any]] = []
    baseline: list[str] = []
    compared: list[str] = []
    no_content: list[str] = []
    lr = current.get("logrotate") or {}
    for path, cur in (current.get("files") or {}).items():
        rot = (current.get("rotations") or {}).get(path)
        rows.append({"path": path, "inode": cur.get("inode"), "size": cur.get("size"), "mtime": cur.get("mtime"),
                     "head_hash": cur.get("head_hash"), "status": cur.get("status"),
                     "rot_path": rot.get("path") if rot else None, "rot_inode": rot.get("inode") if rot else None,
                     "rot_size": rot.get("size") if rot else None, "rot_mtime": rot.get("mtime") if rot else None})
        if cur.get("status") == "no_content":
            no_content.append(path)
        prev = previous.get(path)
        if prev is None or prev.get("status") not in _PRESENT + ("symlink",):
            if cur.get("status") in _PRESENT:
                baseline.append(path)
            continue
        compared.append(path)
        why = _rotated(prev, rot, lr.get(path), (logrotate_before or {}).get(path))
        since = _when(prev.get("checked_at"))
        kind = detail = None
        if cur.get("status") == "symlink" and prev.get("status") != "symlink":
            kind, detail = "linked", "the log file was replaced by a symbolic link (e.g. to /dev/null)"
        elif cur.get("status") not in _PRESENT:
            if cur.get("status") == "missing" and prev.get("status") in _PRESENT and not why:
                kind, detail = "deleted", f"the log file is gone (it existed at {since}) and no rotation explains it"
        elif cur.get("inode") == prev.get("inode"):
            if (cur.get("size") or 0) < (prev.get("size") or 0):
                copied = rot and rot.get("status") in _PRESENT and (rot.get("size") or 0) >= (prev.get("size") or 0) - COPYTRUNCATE_SLACK_BYTES
                if not (why and copied) and not (why and "logrotate" in why):
                    kind = "truncated"
                    detail = (f"same file, but it shrank from {prev.get('size')} to {cur.get('size')} bytes since "
                              f"{since} with no rotation that explains it")
            # The hash covers the first 4 KiB: only comparable once the file already
            # had 4 KiB (a smaller file's appends change its "head" legitimately).
            elif ((prev.get("size") or 0) >= HEAD_BYTES and prev.get("head_hash") and cur.get("head_hash")
                  and prev["head_hash"] != cur["head_hash"] and not why):
                kind = "rewritten"
                detail = f"the start of the file changed since {since} (same file, not shorter) -- edited in place"
        elif not why:
            kind = "replaced"
            detail = (f"it is a different file than at {since} (inode {prev.get('inode')} -> {cur.get('inode')}) and "
                      "no rotation explains it -- deleted and recreated, or edited with a tool that rewrites the file")
        if kind:
            items.append({"path": path, "kind": kind, "detail": detail, "login_record": _base(path) in UTMP_NAMES})
            evidence.append(f"{path}: {detail}")
    parts = []
    if compared:
        parts.append(f"compared {len(compared)} log file(s) with their state at the last check")
    if baseline:
        parts.append(f"first look at {len(baseline)} file(s) ({', '.join(_base(p) for p in baseline[:6])}): "
                     "recorded as the baseline, not judged")
    if no_content:
        parts.append(f"{len(no_content)} file(s) not readable by this user, so in-place edits of them can't be seen "
                     "(size/inode changes still are)")
    if not compared and not baseline:
        parts.append("no tracked log file was found")
    return ({"id": "file_state", "status": "suspicious" if items else "ok", "evidence": evidence,
             "coverage": "; ".join(parts), "items": items}, rows)


# ---------------------------------------------------------------------------
# §6.2 journal continuity
# ---------------------------------------------------------------------------
def check_journal(headers: dict[str, Any] | None) -> dict[str, Any]:
    """A gap in sequence numbers BETWEEN two files that both still exist -- a file
    in the middle was deleted. A gap before the oldest file is normal retention
    (vacuuming removes the oldest). journald numbers entries across ALL its files
    (system and user journals interleave), so a gap only counts when the other
    files can't account for the missing numbers."""
    if not headers or not headers.get("available", True):
        return {"id": "journal", "status": "unknown", "evidence": [], "items": [],
                "coverage": "no journald on this machine (or journalctl missing) -- not checked"}
    files = [f for f in headers.get("files") or [] if f.get("header_read") and f.get("head_seqnum") is not None
             and f.get("tail_seqnum") is not None]
    unreadable = headers.get("unreadable_dirs") or []
    if not files:
        why = ("the journal directory isn't readable by this user (add it to the systemd-journal group)"
               if unreadable else "no journal file headers could be read")
        return {"id": "journal", "status": "unknown", "evidence": [], "items": [], "coverage": why + " -- not checked"}
    items: list[dict[str, Any]] = []
    evidence: list[str] = []
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for f in files:
        groups.setdefault((f["dir"], f["journal"], f.get("seqnum_id") or ""), []).append(f)
    for (directory, journal, _sid), fs in groups.items():
        fs.sort(key=lambda f: (f["head_seqnum"], f["tail_seqnum"]))
        for a, b in zip(fs, fs[1:]):
            lo, hi = a["tail_seqnum"] + 1, b["head_seqnum"] - 1
            missing = hi - lo + 1
            if missing <= 0:
                continue
            explained = 0.0
            for f in files:
                if f is a or f is b or f["dir"] != directory:
                    continue
                o_lo, o_hi = max(f["head_seqnum"], lo), min(f["tail_seqnum"], hi)
                if o_lo > o_hi:
                    continue
                span = f["tail_seqnum"] - f["head_seqnum"] + 1
                entries = _entries(f) or span
                explained += entries * (o_hi - o_lo + 1) / span
            unexplained = missing - explained
            if unexplained >= max(JOURNAL_GAP_MIN_ENTRIES, JOURNAL_GAP_MIN_FRACTION * missing):
                detail = (f"{journal} journal: entries {lo}-{hi} ({int(unexplained)} not in any remaining file) are "
                          f"missing between {a['name']} (ends {_when(a.get('tail_realtime'))}) and {b['name']} "
                          f"(starts {_when(b.get('head_realtime'))}) -- a journal file in the middle was removed")
                items.append({"journal": journal, "after": a["name"], "before": b["name"], "missing_from": lo,
                              "missing_to": hi, "unexplained": int(unexplained), "detail": detail,
                              "from_ts": a.get("tail_realtime"), "to_ts": b.get("head_realtime")})
                evidence.append(detail)
    # One deleted file can open a gap in several journals at once (they share one
    # numbering): report each missing range once -- the narrowest, which pinpoints
    # the deleted file best; overlapping ones folded in.
    kept: list[dict[str, Any]] = []
    for it in sorted(items, key=lambda i: (i["missing_to"] - i["missing_from"], -i["unexplained"])):
        if any(it["missing_from"] <= k["missing_to"] and k["missing_from"] <= it["missing_to"] for k in kept):
            continue
        kept.append(it)
    items = sorted(kept, key=lambda i: i["missing_from"])
    evidence = [i["detail"] for i in items]
    cov = f"compared the sequence numbers of {len(files)} journal file(s)"
    if unreadable:
        cov += f"; {len(unreadable)} journal folder(s) not readable"
    return {"id": "journal", "status": "suspicious" if items else "ok", "evidence": evidence, "coverage": cov,
            "items": items}


def _entries(f: dict[str, Any]) -> int | None:
    raw = (f.get("header") or {}).get("Entry objects")
    try:
        return int(str(raw).split()[0]) if raw else None
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# §6.3 boots without a clean shutdown
# ---------------------------------------------------------------------------
def check_boots(history: dict[str, Any] | None, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    if not history or not history.get("available", True):
        return {"id": "boots", "status": "unknown", "evidence": [], "items": [],
                "coverage": "boot history needs journald (not available here) -- not checked"}
    boots = history.get("boots") or []
    recent = [b for b in boots if b.get("last_ts") is None or now - b["last_ts"] <= BOOT_LOOKBACK_SECONDS]
    unclean = [b for b in recent if not b.get("clean") and b.get("entries")]
    items = [{"boot_id": b["boot_id"], "ended": b.get("last_ts"),
              "detail": f"boot {b['boot_id'][:12]} ended {_when(b.get('last_ts'))} without a clean shutdown"}
             for b in unclean]
    cov = f"looked at the end of {len(recent)} previous boot(s) in the last {BOOT_LOOKBACK_SECONDS // 86400} days"
    if history.get("container"):
        cov += (f"; this machine is a container ({history['container']}): a 'boot' is a container start, and a "
                "forced stop or a snapshot restore also ends one uncleanly")
    if not boots:
        cov = "no previous boot in the journal" + (f" (container: {history['container']})" if history.get("container") else "")
    return {"id": "boots", "status": "suspicious" if items else "ok",
            "evidence": [i["detail"] + " (a crash, a power cut or a forced reboot -- context, not proof of tampering)"
                         for i in items], "coverage": cov, "items": items}


# ---------------------------------------------------------------------------
# §6.4 login records
# ---------------------------------------------------------------------------
def check_login_records(reads: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    evidence: list[str] = []
    notes: list[str] = []
    for name in UTMP_NAMES:
        r = reads.get(name)
        if not r:
            notes.append(f"{name}: not read")
            continue
        status = r.get("status")
        if status == "missing":
            notes.append(f"{name}: not present" + (" (musl/Alpine keeps no real login records; newer distributions "
                                                   "use wtmpdb)" if name == "wtmp" else ""))
            continue
        if status != "ok":
            fix = (" (btmp is readable only by root and the utmp group -- read it through the sub-agent)"
                   if name == "btmp" and status == "unreadable" else "")
            notes.append(f"{name}: {status}{fix}")
            continue
        res = _utmp.check(r.get("data"), size=r.get("size"), offset=r.get("offset"), name=name)
        notes.append(res["coverage"])
        for z in res.get("zeroed") or []:
            items.append({"file": name, "kind": "zeroed", "record": z})
        for b in res.get("backwards") or []:
            items.append({"file": name, "kind": "out_of_order", "record": b["index"]})
        evidence += res["evidence"]
    status = "suspicious" if items else ("ok" if any("read the newest" in n for n in notes) else "unknown")
    return {"id": "login_records", "status": status, "evidence": evidence, "coverage": "; ".join(notes), "items": items}


# ---------------------------------------------------------------------------
# §6.5 auditd
# ---------------------------------------------------------------------------
def check_auditd(now_status: dict[str, Any] | None, previous: dict[str, Any] | None,
                 audit_events: list[Any] | None = None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(check result, state to remember or None). `audit_events`: stored auditd
    events since the last check (actions auditd_stopped, audit_rule_removed,
    audit_disabled) -- extra evidence when read_host_logs read the audit log."""
    if not now_status:
        return {"id": "auditd", "status": "unknown", "evidence": [], "items": [],
                "coverage": "auditd status could not be read -- not checked"}, None
    if not now_status.get("installed"):
        return {"id": "auditd", "status": "ok", "evidence": [], "items": [],
                "coverage": "auditd is not installed -- process execution history is unavailable on this machine"}, None
    active = now_status.get("active") == "active"
    rules = now_status.get("rules") if now_status.get("rules_read") else None
    kernel = now_status.get("kernel_enabled") if now_status.get("status_read") else None
    state = {"active": active, "rules": rules, "kernel_enabled": kernel, "enabled": now_status.get("enabled")}
    items: list[dict[str, Any]] = []
    prev_running = bool(previous and previous.get("active") and (previous.get("rules") or 0) > 0)
    since = _when(previous.get("_checked_at")) if previous else ""
    if prev_running and not active:
        items.append({"kind": "stopped", "severity": "high",
                      "detail": f"auditd was running with {previous.get('rules')} rule(s) at {since} and is now "
                                f"{now_status.get('active') or 'not running'}"})
    if prev_running and active and rules == 0:
        items.append({"kind": "rules_emptied", "severity": "high",
                      "detail": f"auditd had {previous.get('rules')} rule(s) at {since}; now it has none"})
    if previous and previous.get("kernel_enabled") == 1 and kernel == 0:
        items.append({"kind": "disabled", "severity": "high",
                      "detail": f"kernel auditing was enabled at {since} and is now disabled (audit_enabled=0)"})
    if not previous and not active:
        items.append({"kind": "not_running", "severity": "info",
                      "detail": f"auditd is installed but not running ({now_status.get('active') or 'unknown'})"})
    evidence = [i["detail"] for i in items]
    for e in audit_events or []:
        evidence.append(f"auditd's own log: {epoch_to_utc_iso(e.ts)} {e.action}"
                        + (f" by user {e.user_name or e.user_id}" if (e.user_name or e.user_id) else ""))
    cov_bits = [f"auditd is {now_status.get('active')} ({now_status.get('enabled')})"]
    cov_bits.append(f"{rules} rule(s) loaded" if rules is not None else
                    "rules not readable (allow `sudo -n auditctl -l` for the SSH user)")
    if previous is None:
        cov_bits.append("first look: recorded as the baseline")
    status = "suspicious" if any(i["severity"] == "high" for i in items) else "ok"
    return {"id": "auditd", "status": status, "evidence": evidence, "coverage": "; ".join(cov_bits),
            "items": items}, state
