"""Continuous detection on the agent (phase C.2): follow the logs, evaluate the rules.

Turned on per machine by a person in Kratos; Kratos then pushes the rule packs as
signed, versioned DATA (agent.py checks the signature and the version; this module
validates the packs with the one evaluator, kratos.subagent.detect, and refuses a
push whole on any problem). While on, the agent:

  * follows the systemd journal -- one `journalctl --follow` started by this module
    with a FIXED argument list (the closed matches in catalog.JOURNAL_MATCHES, the
    fixed output fields, and a cursor checked against logread.CURSOR_RE) -- and
    auditd's log (/var/log/audit/audit.log), opened with the hardened opener
    (hostfiles.open_log_file) and followed by inode and offset, finishing the old
    file when it rotates;
  * turns each entry into the same event values Kratos would store (the parsers and
    events/assemble.py ship in the bundle; core imports the same files) and runs the
    rules over it;
  * keeps each match in a bounded on-disk spool until Kratos acknowledges it (at
    least once; Kratos de-duplicates); the spool drops the oldest past its cap and
    counts the drop;
  * checkpoints where it got to and the counting rules' open windows every few
    seconds, and after a restart catches up from there -- at most
    `max_catchup_seconds` / `max_catchup_entries`; anything older is a recorded gap
    ("not watched from ... to ..."), never silently skipped;
  * sends at most `max_per_rule_minute` matches of one rule per minute and then one
    summary ("+N more"), and keeps evaluation inside a CPU budget (it sleeps and
    reports lag rather than competing with the machine's work), at a low priority.

It never acts: nothing here kills, blocks, bans, writes outside the agent's own
state folder, or starts any process other than the fixed journalctl read.

Standard-library Python 3.8 (the agent bundle).
"""
from __future__ import annotations

import json
import logging
import os
import queue
import re
import subprocess
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

try:  # in the agent bundle: sibling modules
    from . import catalog, detect as D, event_assemble as A, hostfiles, logread  # type: ignore[attr-defined]
    from . import lp_auditd, lp_auth, lp_cron, lp_firewall, lp_systemd  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:  # Kratos (the same files under their package names)
        from kratos.events import assemble as A
        from kratos.logsources import catalog, hostfiles, logread
        from kratos.logsources.parsers import auditd as lp_auditd
        from kratos.logsources.parsers import auth as lp_auth
        from kratos.logsources.parsers import cron as lp_cron
        from kratos.logsources.parsers import firewall as lp_firewall
        from kratos.logsources.parsers import systemd as lp_systemd
        from kratos.subagent import detect as D
    except ImportError:  # run directly
        import catalog  # type: ignore[no-redef]
        import detect as D  # type: ignore[no-redef]
        import event_assemble as A  # type: ignore[no-redef]
        import hostfiles  # type: ignore[no-redef]
        import logread  # type: ignore[no-redef]
        import lp_auditd  # type: ignore[no-redef]
        import lp_auth  # type: ignore[no-redef]
        import lp_cron  # type: ignore[no-redef]
        import lp_firewall  # type: ignore[no-redef]
        import lp_systemd  # type: ignore[no-redef]

logger = logging.getLogger("kratos.subagent.watch")

WATCH_API = 1
SOURCE_JOURNAL = "journal"
SOURCE_AUDITD = "auditd"
SOURCES = (SOURCE_JOURNAL, SOURCE_AUDITD)
AUDIT_LOG = "/var/log/audit/audit.log"
JOURNAL_GROUPS = ("auth", "cron", "systemd_pid1", "kernel")
DATASET_OF = {"auth": "kratos.auth", "cron": "kratos.cron", "systemd_pid1": "kratos.systemd",
              "kernel": "kratos.firewall"}
_AUTH_COMMS = frozenset({"sshd", "sshd-session", "sudo"})
_CRON_IDENTS = frozenset({"CRON", "cron", "CROND", "crond", "crontab"})

MAX_ENTRY_BYTES = 1024 * 1024          # one journal entry larger than this is skipped (and counted)
QUEUE_MAX = 5000                       # entries read but not evaluated yet (the readers wait beyond it)
CHECKPOINT_SECONDS = 5.0
STATUS_SECONDS = 60.0
RESEND_SECONDS = 30.0                  # an unacknowledged detection is sent again after this long
SPOOL_GAP_MERGE_SECONDS = 300.0        # drops this close together are one outage, one gap
RATE_QUIET_SECONDS = 10.0              # a rule's "+N more" goes out once it has been quiet this long
AUDIT_GROUP_IDLE_SECONDS = 0.5
AUDIT_OPEN_GROUPS_MAX = 64
AUDIT_POLL_SECONDS = 0.25
AUDITD_CHECK_SECONDS = 15.0
LINE_MAX_BYTES = logread.LINE_MAX_BYTES    # log sync's line cap: the same line gives the same event
FOLLOWER_BACKOFF_MAX = 60.0
EVENT_TEXT_MAX = 2048                  # each text value a detection carries
MESSAGE_MAX = 1024                     # the message a detection carries
MAX_GAPS_KEPT = 50
OWN_PIDS_MAX = 4096
OWN_PID_TTL_SECONDS = 3600.0
NICE = 10

# Settings Kratos may push (closed: name -> (default, lowest, highest)). Anything else is refused.
SETTINGS: Dict[str, Tuple[int, int, int]] = {
    "spool_max_detections": (2000, 100, 20000),
    "spool_max_bytes": (5 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024),
    "max_catchup_seconds": (6 * 3600, 60, 7 * 86400),
    "max_catchup_entries": (200000, 1000, 2000000),
    "max_per_rule_minute": (20, 1, 1000),
    "max_cpu_percent": (25, 5, 100),
    "follow_auditd": (1, 0, 1),
}
_RULE_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
_MACHINE = re.compile(r"^[a-z0-9][a-z0-9.:_\-\[\]]{0,252}$")
MAX_DISABLED = 5000
MAX_PACKS = 8

_IDENTITY_FIELDS = ("@timestamp", "event.id", "event.dataset", "event.provider", "event.action", "event.outcome",
                    "host.name", "source.ip", "user.name", "user.target.name", "user.effective.name",
                    "process.executable", "process.name", "process.pid", "process.parent.pid", "service.name",
                    "file.path", "network.transport", "kratos.audit.session", "event.sequence")


class WatchError(ValueError):
    """A push the watcher can't take (refused whole)."""


def _now() -> float:
    return time.time()


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Validating a push (the data Kratos sends)
# ---------------------------------------------------------------------------
def validate_settings(raw: Any) -> Dict[str, int]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise WatchError("settings must be an object")
    extra = set(raw) - set(SETTINGS)
    if extra:
        raise WatchError("unknown setting(s): %s" % ", ".join(sorted(str(x) for x in extra)[:5]))
    out: Dict[str, int] = {}
    for name, (default, lo, hi) in SETTINGS.items():
        v = raw.get(name, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise WatchError("setting %s must be a whole number %d-%d" % (name, lo, hi))
        out[name] = v
    return out


def validate_push(msg: Dict[str, Any], held: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The configuration a detect_pack_push carries, checked whole. `held` is the
    configuration this agent runs now (anti-rollback per pack). Raises WatchError."""
    enabled = msg.get("enabled")
    if not isinstance(enabled, bool):
        raise WatchError("enabled must be true or false")
    machine = msg.get("machine")
    if not isinstance(machine, str) or not _MACHINE.match(machine):
        raise WatchError("machine is not a machine name Kratos would use")
    settings = validate_settings(msg.get("settings"))
    disabled = msg.get("disabled") or []
    if not isinstance(disabled, list) or len(disabled) > MAX_DISABLED:
        raise WatchError("disabled must be a list of at most %d rule ids" % MAX_DISABLED)
    for rid in disabled:
        if not isinstance(rid, str) or not _RULE_ID.match(rid):
            raise WatchError("disabled lists something that is not a rule id")
    packs = msg.get("packs") or []
    if not isinstance(packs, list) or len(packs) > MAX_PACKS:
        raise WatchError("packs must be a list of at most %d rule packs" % MAX_PACKS)
    if enabled and not packs:
        raise WatchError("watching was turned on without a rule pack")
    held_versions = {p["pack_id"]: (p["pack_version"], p["sha256"]) for p in (held or {}).get("packs") or []
                     if isinstance(p, dict) and "pack_id" in p}
    seen_packs, seen_rules = set(), set()
    for pack in packs:
        try:
            D.validate_pack(pack)
        except D.PackError as e:
            raise WatchError("a rule pack was refused: %s" % e) from None
        pid, ver, sha = pack["pack_id"], pack["pack_version"], pack["sha256"]
        if pid in seen_packs:
            raise WatchError("the rule pack %s is in the push twice" % pid)
        seen_packs.add(pid)
        clash = {r["id"] for r in pack["rules"]} & seen_rules
        if clash:
            raise WatchError("rule id(s) in two packs: %s" % ", ".join(sorted(clash)[:3]))
        seen_rules |= {r["id"] for r in pack["rules"]}
        old = held_versions.get(pid)
        if old is not None:
            if ver < old[0]:
                raise WatchError("rule pack %s version %d is older than the one this agent holds (%d)"
                                 % (pid, ver, old[0]))
            if ver == old[0] and sha != old[1]:
                raise WatchError("rule pack %s changed without a new version number" % pid)
    return {"enabled": enabled, "machine": machine, "settings": settings, "disabled": sorted(set(disabled)),
            "packs": packs}


def pack_summary(config: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"pack_id": p["pack_id"], "pack_version": p["pack_version"], "sha256": p["sha256"]}
            for p in (config or {}).get("packs") or []]


# ---------------------------------------------------------------------------
# Files in the agent's own state folder (root-only)
# ---------------------------------------------------------------------------
def _write_private(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


class Spool:
    """Detections not yet acknowledged by Kratos, oldest first, bounded by count and
    bytes. Kept on disk (JSON lines, root-only) so a restart or a long outage loses
    nothing until the cap; past the cap the oldest are dropped and the drop counted.
    The file trims itself by design (it is bounded), the only thing this module removes."""

    def __init__(self, path: str, max_items: int, max_bytes: int):
        self.path = path
        self.max_items = max_items
        self.max_bytes = max_bytes
        self.items: "OrderedDict[int, Tuple[Dict[str, Any], int]]" = OrderedDict()
        self.size = 0
        self.dropped = 0
        self.dropped_first: Optional[float] = None
        self.dropped_last: Optional[float] = None
        self.sent_at: Dict[int, float] = {}
        self._lock = threading.Lock()
        self._dirty_lines = 0
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(rec, dict) and isinstance(rec.get("seq"), int):
                        if rec.get("acked"):
                            old = self.items.pop(rec["seq"], None)
                            if old is not None:
                                self.size -= old[1]
                            continue
                        n = len(line.encode("utf-8"))
                        self.items[rec["seq"]] = (rec, n)
                        self.size += n
        except OSError:
            pass
        self._trim()
        self._rewrite()

    def max_seq(self) -> int:
        return max(self.items, default=0)

    def _trim(self) -> List[Dict[str, Any]]:
        """Drop the oldest past the caps; returns what was dropped."""
        out: List[Dict[str, Any]] = []
        while self.items and (len(self.items) > self.max_items or self.size > self.max_bytes):
            _seq, (rec, n) = self.items.popitem(last=False)
            self.size -= n
            self.sent_at.pop(_seq, None)
            out.append(rec)
            ts = rec.get("ts") if isinstance(rec.get("ts"), (int, float)) else _now()
            self.dropped_first = ts if self.dropped_first is None else min(self.dropped_first, ts)
            self.dropped_last = ts if self.dropped_last is None else max(self.dropped_last, ts)
        self.dropped += len(out)
        return out

    def _rewrite(self) -> None:
        text = "".join(json.dumps(rec, separators=(",", ":")) + "\n" for rec, _n in self.items.values())
        try:
            _write_private(self.path, text)
        except OSError as e:
            logger.warning("could not save the detection spool (%s)", e)
        self._dirty_lines = 0

    def add(self, rec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Keep `rec` (it has a fresh `seq`); returns the old ones dropped to make room.
        Dropped ones are marked in the file like acknowledged ones (no rewrite per match
        while the spool is full); the file is rewritten once the marks outnumber the rest."""
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        n = len(line.encode("utf-8"))
        with self._lock:
            self.items[rec["seq"]] = (rec, n)
            self.size += n
            dropped = self._trim()
            text = line + "".join(json.dumps({"seq": d["seq"], "acked": True}) + "\n" for d in dropped)
            self._dirty_lines += len(dropped)
            if self._dirty_lines > max(50, len(self.items)):
                self._rewrite()
                return dropped
            try:
                os.makedirs(os.path.dirname(self.path) or ".", mode=0o700, exist_ok=True)
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(text)
            except OSError as e:
                logger.warning("could not add to the detection spool (%s)", e)
        return dropped

    def ack(self, seqs: List[int]) -> int:
        done = 0
        with self._lock:
            for s in seqs:
                old = self.items.pop(s, None)
                self.sent_at.pop(s, None)
                if old is not None:
                    self.size -= old[1]
                    done += 1
            if done:
                self._dirty_lines += done
                # Appending "acked" markers keeps acks cheap; the file is rewritten once
                # they outnumber what is still waiting.
                if self._dirty_lines > max(50, len(self.items)):
                    self._rewrite()
                else:
                    try:
                        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                                     0o600)
                        with os.fdopen(fd, "a", encoding="utf-8") as f:
                            f.write("".join(json.dumps({"seq": s, "acked": True}) + "\n" for s in seqs))
                    except OSError:
                        pass
        return done

    def due(self, now: float, limit: int) -> List[Dict[str, Any]]:
        """Waiting detections not sent in the last RESEND_SECONDS, oldest first."""
        out: List[Dict[str, Any]] = []
        with self._lock:
            for seq, (rec, _n) in self.items.items():
                sent = self.sent_at.get(seq)
                if sent is not None and now - sent < RESEND_SECONDS:
                    continue
                out.append(rec)
                if len(out) >= limit:
                    break
        return out

    def mark_sent(self, seq: int, now: float) -> None:
        with self._lock:
            if seq in self.items:
                self.sent_at[seq] = now

    def forget_sent(self) -> None:
        """A new connection: everything waiting goes out again."""
        with self._lock:
            self.sent_at.clear()

    def __len__(self) -> int:
        return len(self.items)


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------
class _Reader(threading.Thread):
    """A follower thread: puts ("entry"/"gap"/"state", ...) on the manager's queue."""

    def __init__(self, manager: "WatchManager", source: str):
        super().__init__(name="kratos-watch-" + source, daemon=True)
        self.m = manager
        self.source = source
        self.stopping = threading.Event()

    def put(self, item: Tuple[Any, ...]) -> bool:
        while not self.stopping.is_set():
            try:
                self.m.queue.put(item, timeout=0.5)
                return True
            except queue.Full:
                continue
        return False

    def state(self, state: str, error: Optional[str] = None) -> None:
        self.put(("state", self.source, state, error))

    def gap(self, start: float, end: float, reason: str) -> None:
        """A stretch not watched. Never dropped: a start after the end (the machine's
        clock, or a future-dated line) is clamped, so the gap is still said."""
        self.put(("gap", self.source, min(start, end), end, reason))


def journal_argv(after_cursor: Optional[str], since: Optional[float], journalctl: str = "journalctl") -> List[str]:
    """The ONE journalctl command the watcher runs: fixed fields, the closed matches of
    the sources Kratos syncs (OR-ed with "+"), and a checked cursor -- no text from
    anywhere else."""
    args = [journalctl, "--no-pager", "--follow", "-o", "json",
            "--output-fields=" + ",".join(logread.JOURNAL_FIELDS)]
    for i, group in enumerate(JOURNAL_GROUPS):
        if i:
            args.append("+")
        args.extend(catalog.JOURNAL_MATCHES[group])
    if after_cursor is not None:
        if not logread.valid_cursor(after_cursor):
            raise ValueError("not a journal cursor")
        args.append("--after-cursor=" + after_cursor)
    elif since is not None:
        args += ["--since", "@%d" % int(since)]
    else:
        args += ["--lines", "0"]
    return args


def _which(name: str) -> Optional[str]:
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _set_nice(pid: int) -> None:
    try:
        os.setpriority(os.PRIO_PROCESS, pid, NICE)
    except (OSError, AttributeError):
        pass


class JournalReader(_Reader):
    def __init__(self, manager: "WatchManager"):
        super().__init__(manager, SOURCE_JOURNAL)
        self.proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self.cursor: Optional[str] = None
        self.last_ts: Optional[float] = None

    def stop(self) -> None:
        with self._lock:
            self.stopping.set()
            proc = self.proc
        if proc is not None:
            self._end(proc)

    @staticmethod
    def _end(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def oldest_ts(self, exe: str) -> Optional[float]:
        """When the oldest entry the journal still holds was written (any source)."""
        try:
            p = subprocess.Popen([exe, "--no-pager", "-o", "json", "--output-fields=MESSAGE"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        except OSError:
            return None
        try:
            line = p.stdout.readline(MAX_ENTRY_BYTES) if p.stdout else b""
        finally:
            try:
                p.kill()
                p.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            return int(json.loads(line.decode("utf-8", "replace")).get("__REALTIME_TIMESTAMP")) / 1e6
        except (ValueError, TypeError, AttributeError):
            return None

    def run(self) -> None:
        exe = self.m.journalctl or _which("journalctl")
        if exe is None:
            self.state("not_available", "this machine has no journalctl")
            return
        # Where to read from: what this reader last put on the queue (a restart within
        # the process), else the checkpoint (what was last evaluated before a restart).
        self.cursor, self.last_ts = self.m.journal_cursor, self.m.last_ts.get(SOURCE_JOURNAL)
        backoff = 1.0
        while not self.stopping.is_set():
            now = _now()
            limit = self.m.settings["max_catchup_seconds"]
            cursor, since = self.cursor, None
            jump = self.m.take_journal_jump()
            if jump is not None:
                cursor, since = None, jump
            elif cursor is not None and self.last_ts is not None:
                oldest = self.oldest_ts(exe)
                if oldest is not None and oldest > self.last_ts + 2.0:
                    self.gap(self.last_ts, oldest, "journal entries were removed (vacuum or rotation) before they "
                                                   "were watched")
                    cursor, since = None, oldest
                if self.last_ts < now - limit:
                    self.gap(self.last_ts, now - limit, "older than the catch-up limit (%s) when watching resumed"
                             % _span(limit))
                    cursor, since = None, now - limit
            elif cursor is None:
                # first start: from when watching was turned on (bounded by the catch-up limit)
                start = self.last_ts if self.last_ts is not None else self.m.watch_since
                since = max(start, now - limit) if start is not None else None
            try:
                argv = journal_argv(cursor, since, exe)
            except ValueError:
                argv = journal_argv(None, self.last_ts, exe)
            started = _now()
            try:
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                                        close_fds=True)
            except OSError as e:
                self.state("error", "could not start journalctl (%s)" % (e.strerror or e))
                self._wait(backoff)
                backoff = min(backoff * 2, FOLLOWER_BACKOFF_MAX)
                continue
            _set_nice(proc.pid)
            with self._lock:
                self.proc = proc
                stopped = self.stopping.is_set()
            if stopped:                           # stop() came while it was starting: never leave it running
                self._end(proc)
                return
            err_tail: Deque[str] = deque(maxlen=5)
            threading.Thread(target=self._drain_stderr, args=(proc, err_tail), daemon=True).start()
            self.state("watching")
            entries = self._follow(proc, started)
            code = proc.wait()
            with self._lock:
                self.proc = None
            if self.stopping.is_set():
                return
            if self.m.peek_journal_jump():
                continue                              # a planned restart (too far behind): no backoff
            why = "; ".join(err_tail) or "journalctl exited (code %s)" % code
            self.state("restarting", why[:300])
            if entries:
                backoff = 1.0
            self._wait(backoff)
            backoff = min(backoff * 2, FOLLOWER_BACKOFF_MAX)

    def _wait(self, seconds: float) -> None:
        self.stopping.wait(seconds)

    @staticmethod
    def _drain_stderr(proc: subprocess.Popen, tail: Deque[str]) -> None:
        if proc.stderr is None:
            return
        for raw in iter(lambda: proc.stderr.readline(4096), b""):
            tail.append(raw.decode("utf-8", "replace").strip()[:200])

    def _follow(self, proc: subprocess.Popen, started: float) -> int:
        n = 0
        backlog = 0
        limit = self.m.settings["max_catchup_entries"]
        out = proc.stdout
        assert out is not None
        while not self.stopping.is_set():
            raw = out.readline(MAX_ENTRY_BYTES + 1)
            if not raw:
                return n
            if len(raw) > MAX_ENTRY_BYTES and not raw.endswith(b"\n"):
                while True:                       # the rest of an oversized entry
                    more = out.readline(MAX_ENTRY_BYTES)
                    if not more or more.endswith(b"\n"):
                        break
                self.m.note_skipped(self.source, "an entry larger than %d bytes" % MAX_ENTRY_BYTES)
                continue
            try:
                entry = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                self.m.note_skipped(self.source, "an entry that is not JSON")
                continue
            if not isinstance(entry, dict):
                continue
            n += 1
            ts = _entry_ts(entry)
            if ts is not None and ts < started - 5:
                backlog += 1
                if backlog > limit:
                    # Too far behind to catch up: say what is skipped, then follow from now.
                    self.gap(ts, started, "more than %d entries to catch up on" % limit)
                    self.m.journal_jump(started)
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                    return n
            if not self.put(("entry", self.source, entry)):
                return n
            cur = entry.get("__CURSOR")
            if logread.valid_cursor(cur):
                self.cursor = cur
            if ts is not None:
                self.last_ts = ts
        return n


def _span(seconds: float) -> str:
    return "%d h" % (seconds // 3600) if seconds >= 3600 else "%d min" % max(1, seconds // 60)


def _entry_ts(entry: Dict[str, Any]) -> Optional[float]:
    try:
        return int(entry.get("__REALTIME_TIMESTAMP")) / 1e6
    except (TypeError, ValueError):
        return None


class AuditReader(_Reader):
    """/var/log/audit/audit.log, by inode and offset; records grouped into events by serial."""

    def __init__(self, manager: "WatchManager", path: str = AUDIT_LOG):
        super().__init__(manager, SOURCE_AUDITD)
        self.path = path
        self.fd: Optional[int] = None
        self.inode: Optional[int] = None
        self.offset = 0
        self.buf = b""
        self.groups: "OrderedDict[Tuple[str, int], Dict[str, Any]]" = OrderedDict()
        self.skip_before: Optional[float] = None    # records older than this are past the catch-up limit
        self.check_daemon = manager.check_auditd       # tests replace it; None = look at the real auditd
        self._daemon_checked = 0.0
        self._daemon_down = False
        self.started = _now()
        self.backlog = 0

    def stop(self) -> None:
        self.stopping.set()

    def _close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
        self.fd = None

    def _open(self, path: str) -> Optional[os.stat_result]:
        try:
            fd, st = hostfiles.open_log_file(path)
        except hostfiles.FileRefused as e:
            if e.status == "missing":
                return None
            raise
        self._close()
        self.fd, self.inode, self.offset, self.buf = fd, st.st_ino, 0, b""
        return st

    def _resume(self) -> bool:
        """Open the file where the checkpoint left off. False: nothing to watch (yet)."""
        saved = self.m.audit_resume()
        st = self._open(self.path)
        if st is None:
            return False
        now = _now()
        if saved is None:
            # first start: from the end (watching starts now), unless asked to look back
            self.offset = st.st_size
            return True
        inode, offset, last_ts = saved
        limit = self.m.settings["max_catchup_seconds"]
        self.started, self.backlog = now, 0
        if last_ts is not None and last_ts < now - limit:
            self.gap(last_ts, now - limit, "older than the catch-up limit (%s) when watching resumed" % _span(limit))
            self.skip_before = now - limit
        if inode == st.st_ino:
            if st.st_size < offset:
                self.gap(last_ts or now, now, "the audit log was truncated")
                self.offset = 0
            else:
                self.offset = offset
            return True
        # rotated while the watcher was stopped: finish the old file first, if it is still there
        old = self.path + ".1"
        try:
            ofd, ost = hostfiles.open_log_file(old)
        except hostfiles.FileRefused:
            ofd, ost = None, None
        if ofd is not None and ost is not None and ost.st_ino == inode and ost.st_size >= offset:
            self._drain_old(ofd, offset)
        else:
            if ofd is not None:
                os.close(ofd)
            self.gap(last_ts or now, now, "the audit log rotated more than once while the watcher was stopped")
        self.offset = 0
        return True

    def _drain_old(self, fd: int, offset: int) -> None:
        keep_fd, keep_inode = self.fd, self.inode
        self.fd, self.offset, self.buf = fd, offset, b""
        try:
            while self._read_once() and not self.stopping.is_set():
                pass
            self._flush_groups(force=True)
        finally:
            os.close(fd)
            self.fd, self.inode, self.buf = keep_fd, keep_inode, b""

    def run(self) -> None:
        backoff = 1.0
        announced = None
        while not self.stopping.is_set():
            try:
                ok = self._resume()
            except hostfiles.FileRefused as e:
                self.state("error", "the audit log was refused (%s)" % e)
                self.stopping.wait(min(backoff, FOLLOWER_BACKOFF_MAX))
                backoff = min(backoff * 2, FOLLOWER_BACKOFF_MAX)
                continue
            if not ok:
                if announced != "not_available":
                    self.state("not_available", "no audit log at %s (is auditd installed?)" % self.path)
                    announced = "not_available"
                self.stopping.wait(30.0)
                continue
            announced = None
            self.state("watching")
            backoff = 1.0
            try:
                self._follow()
            except hostfiles.FileRefused as e:
                self.state("restarting", "the audit log was refused (%s)" % e)
            except OSError as e:
                self.state("restarting", "reading the audit log failed (%s)" % (e.strerror or e))
            self._flush_groups(force=True)
            self._close()
            self.stopping.wait(backoff)

    def _read_once(self) -> bool:
        assert self.fd is not None
        chunk = os.pread(self.fd, 256 * 1024, self.offset + len(self.buf))
        if not chunk:
            return False
        self.buf += chunk
        while True:
            nl = self.buf.find(b"\n")
            if nl < 0:
                break
            raw, self.buf = self.buf[:nl], self.buf[nl + 1:]
            start = self.offset
            self.offset += nl + 1
            self._line(raw[:LINE_MAX_BYTES].decode("utf-8", "replace"), start)
        if len(self.buf) > 4 * LINE_MAX_BYTES * 64:   # a "line" with no end: skip what can't be a record
            self.m.note_skipped(self.source, "a line longer than the audit log should have")
            self.offset += len(self.buf)
            self.buf = b""
        return True

    def _auditd_running(self) -> bool:
        """Is auditd itself running? A stopped auditd leaves its log in place and simply
        writes nothing more -- that must read as "not watching", never as quiet."""
        for pidfile in ("/run/auditd.pid", "/var/run/auditd.pid"):
            try:
                with open(pidfile) as f:
                    pid = int(f.read().strip())
                with open("/proc/%d/comm" % pid) as f:
                    if f.read().strip() == "auditd":
                        return True
            except (OSError, ValueError):
                continue
        try:
            for d in os.listdir("/proc"):
                if d.isdigit():
                    try:
                        with open("/proc/%s/comm" % d) as f:
                            if f.read().strip() == "auditd":
                                return True
                    except OSError:
                        continue
        except OSError:
            return True        # can't tell: don't claim it stopped
        return False

    def _check_daemon(self) -> None:
        now = _now()
        if now - self._daemon_checked < AUDITD_CHECK_SECONDS:
            return
        self._daemon_checked = now
        running = self.check_daemon() if self.check_daemon is not None else self._auditd_running()
        if not running and not self._daemon_down:
            self._daemon_down = True
            self.state("error", "auditd isn't running -- nothing new is being recorded in the audit log")
        elif running and self._daemon_down:
            self._daemon_down = False
            self.state("watching")

    def _follow(self) -> None:
        self._daemon_checked = 0.0
        while not self.stopping.is_set():
            self._check_daemon()
            if self._read_once():
                self._flush_groups(force=False)
                continue
            self._flush_groups(force=False)
            try:
                st = os.lstat(self.path)
            except OSError:
                st = None
            if st is None or st.st_ino != self.inode:
                # rotated: the old file is finished (read to its end above); switch
                self._flush_groups(force=True)
                if st is None:
                    self.stopping.wait(AUDIT_POLL_SECONDS)
                    continue
                if self._open(self.path) is None:
                    continue
                continue
            assert self.fd is not None
            if os.fstat(self.fd).st_size < self.offset:
                self.gap(self.m.last_ts.get(self.source) or _now(), _now(), "the audit log was truncated")
                self.offset, self.buf = 0, b""
            self.stopping.wait(AUDIT_POLL_SECONDS)

    def _line(self, text: str, start: int) -> None:
        m = lp_auditd._REC.match(text)
        if not m:
            return
        ts = float(m.group("ts"))
        if self.skip_before is not None:
            if ts < self.skip_before:
                return
            self.skip_before = None
        key = (m.group("ts"), int(m.group("serial")))
        g = self.groups.get(key)
        if g is None:
            g = self.groups[key] = {"lines": [], "start": start, "seen": _now()}
        g["lines"].append(text)
        g["seen"] = _now()
        g["end"] = self.offset
        if len(self.groups) > AUDIT_OPEN_GROUPS_MAX:
            self._emit(*self.groups.popitem(last=False))

    def _flush_groups(self, force: bool) -> None:
        now = _now()
        for key in list(self.groups):
            g = self.groups[key]
            if force or now - g["seen"] >= AUDIT_GROUP_IDLE_SECONDS or len(self.groups) > 1 and key != next(
                    reversed(self.groups)):
                del self.groups[key]
                self._emit(key, g)

    def _emit(self, key: Tuple[str, int], g: Dict[str, Any]) -> None:
        if float(key[0]) < self.started - 5:
            self.backlog += 1
            if self.backlog > self.m.settings["max_catchup_entries"]:
                # Too far behind to catch up: say what is skipped, then follow from the end.
                assert self.fd is not None
                self.gap(float(key[0]), self.started, "more than %d audit events to catch up on"
                         % self.m.settings["max_catchup_entries"])
                self.groups.clear()
                self.offset, self.buf = os.fstat(self.fd).st_size, b""
                self.backlog = -(10 ** 12)
                return
        safe = min([x["start"] for x in self.groups.values()] + [g["end"]])
        self.put(("entry", self.source, {"lines": g["lines"], "inode": self.inode, "offset": safe,
                                          "path": self.path}))


# ---------------------------------------------------------------------------
# The manager: evaluation, rate limits, checkpoint, status
# ---------------------------------------------------------------------------
class WatchManager:
    def __init__(self, state_dir: str, *, audit_path: str = AUDIT_LOG, own_pid: Optional[int] = None,
                 journalctl: Optional[str] = None):
        self.state_dir = state_dir
        self.journalctl = journalctl          # tests only; normally found in the system bin directories
        self.check_auditd: Any = None         # tests only: a function saying whether auditd runs
        self.config_path = os.path.join(state_dir, "watch_config.json")
        self.checkpoint_path = os.path.join(state_dir, "watch_checkpoint.json")
        self.spool_path = os.path.join(state_dir, "watch_spool.jsonl")
        self.audit_path = audit_path
        self.config: Optional[Dict[str, Any]] = None
        self.settings: Dict[str, int] = validate_settings({})
        self.queue: "queue.Queue[Tuple[Any, ...]]" = queue.Queue(maxsize=QUEUE_MAX)
        self.spool = Spool(self.spool_path, self.settings["spool_max_detections"], self.settings["spool_max_bytes"])
        self._lock = threading.RLock()
        self._threads: List[Any] = []
        self._eval_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.evaluator: Optional[D.Evaluator] = None
        self.rules_meta: Dict[str, Tuple[str, int, Dict[str, Any], frozenset]] = {}
        self.machine = ""
        self.seq = 0
        self.watch_since: Optional[float] = None
        # per source
        self.state: Dict[str, Dict[str, Any]] = {s: {"state": "off", "since": None, "error": None} for s in SOURCES}
        self.last_ts: Dict[str, Optional[float]] = {s: None for s in SOURCES}
        self.events: Dict[str, Deque[float]] = {s: deque(maxlen=20000) for s in SOURCES}
        self.matches: Dict[str, int] = {s: 0 for s in SOURCES}
        self.skipped: Dict[str, int] = {s: 0 for s in SOURCES}
        self.gaps: Dict[str, List[Dict[str, Any]]] = {s: [] for s in SOURCES}
        self.gap_id = 0
        self.journal_cursor: Optional[str] = None
        self.audit_pos: Optional[Tuple[int, int]] = None
        self._jump_to: Optional[float] = None
        self._rate: Dict[str, List[Any]] = {}      # rule -> [minute, sent, suppressed, first_ts, last_ts, pack, ver]
        self._own: "OrderedDict[int, float]" = OrderedDict()
        self.own_pid = own_pid if own_pid is not None else os.getpid()
        self._last_checkpoint = 0.0
        self.status_changed = threading.Event()
        self.cpu_seconds = 0.0
        self.throttled_seconds = 0.0
        self._load_checkpoint()

    # -- configuration --------------------------------------------------------
    def load_saved(self) -> None:
        """At agent start: carry on watching with the last configuration Kratos pushed."""
        cfg = _read_json(self.config_path)
        if not isinstance(cfg, dict):
            return
        try:
            cfg = validate_push(cfg, None)
        except WatchError as e:
            logger.warning("the saved watch configuration is unusable (%s); waiting for Kratos to push one", e)
            return
        self._apply(cfg, save=False)

    @property
    def enabled(self) -> bool:
        return bool(self.config and self.config.get("enabled"))

    def held(self) -> Optional[Dict[str, Any]]:
        return self.config

    def apply(self, cfg: Dict[str, Any]) -> None:
        """Apply a configuration `validate_push` returned (agent.py checked the push's
        signature and version first). Saved before it is used, so a restart keeps it."""
        self._apply(cfg, save=True)

    def _apply(self, cfg: Dict[str, Any], save: bool) -> None:
        packs = [D.Pack(p) for p in cfg["packs"]]
        if save:
            _write_private(self.config_path, json.dumps(cfg, separators=(",", ":")))
        with self._lock:
            self.stop_watching()
            self.config = cfg
            self.settings = cfg["settings"]
            self.machine = cfg["machine"]
            self.spool.max_items = self.settings["spool_max_detections"]
            self.spool.max_bytes = self.settings["spool_max_bytes"]
            if not cfg["enabled"]:
                for s in SOURCES:
                    self.state[s] = {"state": "off", "since": None, "error": None}
                self.status_changed.set()
                return
            disabled = frozenset(cfg["disabled"])
            merged = {"format": D.FORMAT, "format_version": D.FORMAT_VERSION, "pack_id": "merged",
                      "pack_version": 1, "rules": [r for p in packs for r in p.raw["rules"]]}
            merged["sha256"] = D.pack_digest(merged)
            evaluator = D.Evaluator(D.Pack(merged), disabled=disabled)
            evaluator.import_windows((self._saved or {}).get("windows"))
            self.evaluator = evaluator
            self.rules_meta = {}
            for p in packs:
                for r in p.rules:
                    self.rules_meta[r.id] = (p.pack_id, p.version, r.meta, _rule_fields(r.meta))
            if self.watch_since is None:
                self.watch_since = _now()
            self._start()
        self.status_changed.set()

    # -- threads ---------------------------------------------------------------
    def _start(self) -> None:
        self._stop.clear()
        self._eval_thread = threading.Thread(target=self._eval_loop, name="kratos-watch-eval", daemon=True)
        self._eval_thread.start()
        readers: List[Any] = [JournalReader(self)]
        if self.settings.get("follow_auditd", 1):
            readers.append(AuditReader(self, self.audit_path))
        else:
            self.state[SOURCE_AUDITD] = {"state": "off", "since": None, "error": "turned off in Kratos"}
        self._threads = readers
        for r in readers:
            r.start()

    def stop_watching(self) -> None:
        for r in self._threads:
            r.stop()
        for r in self._threads:
            r.join(timeout=10)
        self._threads = []
        self._stop.set()
        if self._eval_thread is not None:
            self._eval_thread.join(timeout=10)
            self._eval_thread = None
        self._save_checkpoint(force=True)

    def stop(self) -> None:
        with self._lock:
            self.stop_watching()

    # -- checkpoint ------------------------------------------------------------
    def _load_checkpoint(self) -> None:
        cp = _read_json(self.checkpoint_path)
        self._saved = cp if isinstance(cp, dict) else {}
        cur = self._saved.get("journal_cursor")
        if logread.valid_cursor(cur):
            self.journal_cursor = cur
        ts = self._saved.get("journal_ts")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            self.last_ts[SOURCE_JOURNAL] = float(ts)
        audit = self._saved.get("audit")
        if (isinstance(audit, dict) and isinstance(audit.get("inode"), int) and isinstance(audit.get("offset"), int)
                and audit["offset"] >= 0):
            self.audit_pos = (audit["inode"], audit["offset"])
            if isinstance(audit.get("ts"), (int, float)):
                self.last_ts[SOURCE_AUDITD] = float(audit["ts"])
        seq = self._saved.get("seq")
        self.seq = max(seq if isinstance(seq, int) and seq >= 0 else 0, self.spool.max_seq())
        since = self._saved.get("watch_since")
        if isinstance(since, (int, float)) and not isinstance(since, bool):
            self.watch_since = float(since)
        gaps = self._saved.get("gaps")
        if isinstance(gaps, dict):
            for s in SOURCES:
                if isinstance(gaps.get(s), list):
                    self.gaps[s] = [g for g in gaps[s] if isinstance(g, dict)][-MAX_GAPS_KEPT:]
        self.gap_id = max([g.get("id") for s in SOURCES for g in self.gaps[s] if isinstance(g.get("id"), int)]
                          + [0])

    def _save_checkpoint(self, force: bool = False) -> None:
        now = _now()
        if not force and now - self._last_checkpoint < CHECKPOINT_SECONDS:
            return
        self._last_checkpoint = now
        data = {
            "version": 1, "seq": self.seq, "watch_since": self.watch_since,
            "journal_cursor": self.journal_cursor, "journal_ts": self.last_ts.get(SOURCE_JOURNAL),
            "audit": ({"inode": self.audit_pos[0], "offset": self.audit_pos[1], "ts": self.last_ts.get(SOURCE_AUDITD)}
                      if self.audit_pos else None),
            "windows": self.evaluator.export_windows(now) if self.evaluator is not None else
            (self._saved or {}).get("windows"),
            "gaps": self.gaps,
        }
        try:
            _write_private(self.checkpoint_path, json.dumps(data, separators=(",", ":")))
            self._saved = data
        except OSError as e:
            logger.warning("could not save the watch checkpoint (%s)", e)

    def journal_jump(self, ts: float) -> None:
        """The journal reader is too far behind: restart it from `ts` (the gap is recorded)."""
        with self._lock:
            self._jump_to = ts

    def take_journal_jump(self) -> Optional[float]:
        with self._lock:
            jump, self._jump_to = self._jump_to, None
            return jump

    def peek_journal_jump(self) -> bool:
        with self._lock:
            return self._jump_to is not None

    def audit_resume(self) -> Optional[Tuple[int, int, Optional[float]]]:
        if self.audit_pos is None:
            return None
        return self.audit_pos[0], self.audit_pos[1], self.last_ts.get(SOURCE_AUDITD)

    def note_skipped(self, source: str, what: str) -> None:
        self.skipped[source] = self.skipped.get(source, 0) + 1
        logger.warning("watch (%s): skipped %s", source, what)

    # -- evaluation ------------------------------------------------------------
    def _eval_loop(self) -> None:
        try:
            os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), NICE)
        except (OSError, AttributeError):
            pass
        wall0, cpu0 = time.monotonic(), time.thread_time()
        while not self._stop.is_set():
            try:
                item = self.queue.get(timeout=0.5)
            except queue.Empty:
                self._minute_summaries(_now())
                self._save_checkpoint()
                continue
            try:
                self._handle(item)
            except Exception:  # noqa: BLE001 -- one odd entry must never stop watching
                logger.exception("watch: an entry could not be evaluated")
            self._minute_summaries(_now())
            self._save_checkpoint()
            # CPU budget: when evaluation alone uses more than its share of one core
            # (a catch-up), pause -- the queue fills, the readers wait, lag is reported.
            wall, cpu = time.monotonic() - wall0, time.thread_time() - cpu0
            budget = self.settings["max_cpu_percent"] / 100.0
            if wall >= 1.0:
                if cpu > budget * wall:
                    pause = min(cpu / budget - wall, 2.0)
                    self.throttled_seconds += pause
                    self._stop.wait(pause)
                self.cpu_seconds += cpu
                wall0, cpu0 = time.monotonic(), time.thread_time()

    def _handle(self, item: Tuple[Any, ...]) -> None:
        kind, source = item[0], item[1]
        if kind == "state":
            self._set_state(source, item[2], item[3])
            return
        if kind == "gap":
            self._add_gap(source, item[2], item[3], item[4])
            return
        if source == SOURCE_JOURNAL:
            entry = item[2]
            values = journal_values(entry, self.machine)
            cur = entry.get("__CURSOR")
            if logread.valid_cursor(cur):
                self.journal_cursor = cur
            ts = _entry_ts(entry)
            pos: Any = cur if isinstance(cur, str) else None
        else:
            g = item[2]
            values = audit_values(g["lines"], g["path"], self.machine)
            ts = values["timestamp"].timestamp() if values else None
            self.audit_pos = (g["inode"], g["offset"]) if g.get("inode") is not None else self.audit_pos
            pos = {"inode": g.get("inode"), "offset": g.get("offset")}
        if ts is not None:
            self.last_ts[source] = max(self.last_ts.get(source) or 0.0, ts)
        self.events[source].append(_now())
        if values is None or self.evaluator is None:
            return
        if self._own_process(values):
            return
        event = A.flat(values)
        for m in self.evaluator.evaluate(event, values["timestamp"].timestamp()):
            self.matches[source] += 1
            self._send(m, event, source, pos)

    def _own_process(self, values: Dict[str, Any]) -> bool:
        """Is this a program the agent itself started (its read probes, its journalctl)?
        Tracked by parent pid as each child starts, so grandchildren count too."""
        if values.get("dataset") != "kratos.auditd":
            return False
        pid, ppid = values.get("process_pid"), values.get("process_parent_pid")
        now = _now()
        mine = ppid == self.own_pid or (ppid in self._own and now - self._own[ppid] < OWN_PID_TTL_SECONDS)
        if mine and isinstance(pid, int):
            self._own[pid] = now
            self._own.move_to_end(pid)
            while len(self._own) > OWN_PIDS_MAX:
                self._own.popitem(last=False)
        return bool(mine)

    def _send(self, m: Any, event: Dict[str, Any], source: str, pos: Any) -> None:
        meta = self.rules_meta.get(m.rule_id)
        if meta is None:
            return
        pack_id, pack_version, _rule, used = meta
        minute = int(m.ts // 60)
        st = self._rate.get(m.rule_id)
        if st is None or st[0] != minute:
            self._flush_rule(m.rule_id)
            st = self._rate[m.rule_id] = [minute, 0, 0, None, None, pack_id, pack_version, 0.0]
        st[7] = _now()
        if st[1] >= self.settings["max_per_rule_minute"]:
            st[2] += 1
            st[3] = m.ts if st[3] is None else min(st[3], m.ts)
            st[4] = m.ts if st[4] is None else max(st[4], m.ts)
            return
        st[1] += 1
        self.seq += 1
        rec = {"type": "detection", "seq": self.seq, "rule_id": m.rule_id, "pack_id": pack_id,
               "pack_version": pack_version, "ts": m.ts, "first_ts": m.first_ts, "detected_at": round(_now(), 3),
               "source": source,
               "position": pos, "event": bounded_event(event, used), "group": m.group, "count": m.count,
               "event_ids": list(m.event_ids)[:D.MAX_MATCHED_IDS]}
        self._spool(rec)

    def _spool(self, rec: Dict[str, Any]) -> None:
        dropped = self.spool.add(rec)
        by_source: Dict[str, List[float]] = {}
        for d in dropped:
            src = d.get("source") if d.get("source") in SOURCES else SOURCE_JOURNAL
            ts = d.get("ts") if isinstance(d.get("ts"), (int, float)) and not isinstance(d.get("ts"), bool) else _now()
            by_source.setdefault(src, []).append(float(ts))
        for src, times in by_source.items():
            self._spool_gap(src, min(times), max(times), len(times))
        self.status_changed.set()

    def _spool_gap(self, source: str, start: float, end: float, n: int) -> None:
        """Matches dropped from a full spool: one gap per source and outage, kept up to date
        while drops continue (not one gap per dropped match)."""
        gaps = self.gaps.get(source, [])
        last = gaps[-1] if gaps else None
        if last is not None and last.get("kind") == "spool" and _now() - float(last.get("noted") or 0) < SPOOL_GAP_MERGE_SECONDS:
            last["from"] = round(min(float(last["from"]), start), 3)
            last["to"] = round(max(float(last["to"]), end), 3)
            last["dropped"] = int(last.get("dropped") or 0) + n
            last["reason"] = ("%d detection(s) dropped: the link was down longer than the spool holds"
                              % last["dropped"])
            last["noted"] = round(_now(), 3)
            self.status_changed.set()
            self._save_checkpoint()
            return
        self._add_gap(source, start, end, "%d detection(s) dropped: the link was down longer than the spool holds" % n,
                      kind="spool", dropped=n)

    def _flush_rule(self, rule_id: str) -> None:
        st = self._rate.get(rule_id)
        if not st or not st[2]:
            return
        self.seq += 1
        self._spool({"type": "detection", "seq": self.seq, "rule_id": rule_id, "pack_id": st[5],
                     "pack_version": st[6], "ts": st[4], "first_ts": st[3],
                     "summary": {"suppressed": st[2], "minute": st[0] * 60}})
        st[2] = 0

    def _minute_summaries(self, now: float) -> None:
        """Send a rule's "+N more" once its minute (in the events' own time) is over: when a
        match from a later minute arrives (_send), or once the minute is past on this clock
        and the rule has been quiet for RATE_QUIET_SECONDS -- never per match while catching
        up on an old flood."""
        minute = int(now // 60)
        for rid, st in list(self._rate.items()):
            if st[0] < minute and now - st[7] >= RATE_QUIET_SECONDS:
                self._flush_rule(rid)
                del self._rate[rid]

    # -- status ----------------------------------------------------------------
    def _set_state(self, source: str, state: str, error: Optional[str]) -> None:
        cur = self.state.get(source) or {}
        if cur.get("state") != state or cur.get("error") != error:
            since = _now() if cur.get("state") != state else cur.get("since")
            self.state[source] = {"state": state, "since": since, "error": error}
            self.status_changed.set()
            logger.info("watch (%s): %s%s", source, state, (" -- " + error) if error else "")

    def _add_gap(self, source: str, start: float, end: float, reason: str, kind: str = "watch",
                 dropped: Optional[int] = None) -> None:
        self.gap_id += 1
        gap = {"id": self.gap_id, "from": round(float(start), 3), "to": round(float(end), 3), "reason": reason[:300],
               "kind": kind, "noted": round(_now(), 3)}
        if dropped is not None:
            gap["dropped"] = dropped
        self.gaps[source] = (self.gaps.get(source, []) + [gap])[-MAX_GAPS_KEPT:]
        logger.warning("watch (%s): not watched from %s to %s: %s", source, _iso(start), _iso(end), reason)
        self.status_changed.set()
        self._save_checkpoint(force=True)

    def status(self) -> Dict[str, Any]:
        now = _now()
        out = []
        for s in SOURCES:
            ev = self.events[s]
            per_min = sum(1 for t in ev if now - t < 60)
            last = self.last_ts.get(s)
            st = self.state.get(s) or {}
            out.append({"name": s, "state": st.get("state") or "off", "since": st.get("since"),
                        "last_event_ts": last,
                        "events_per_min": per_min, "matches": self.matches.get(s, 0),
                        "lag_seconds": (round(max(0.0, now - last), 1)
                                        if last is not None and st.get("state") == "watching" and not self.queue.empty()
                                        else 0.0),
                        "dropped": self.spool.dropped, "skipped": self.skipped.get(s, 0),
                        "gaps": list(self.gaps.get(s, [])[-10:]), "error": st.get("error")})
        rss = None
        try:
            with open("/proc/self/statm") as f:
                rss = int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, IndexError):
            pass
        return {"enabled": self.enabled, "watch_since": self.watch_since, "sources": out,
                "packs": pack_summary(self.config), "spooled": len(self.spool), "queued": self.queue.qsize(),
                "cpu_seconds": round(self.cpu_seconds, 2), "throttled_seconds": round(self.throttled_seconds, 2),
                "rss": rss, "seq": self.seq}

    @property
    def watching(self) -> bool:
        return self.enabled and any((self.state.get(s) or {}).get("state") == "watching" for s in SOURCES)


# ---------------------------------------------------------------------------
# Entries -> event values (the same code Kratos uses for stored lines)
# ---------------------------------------------------------------------------
def _journal_group(entry: Dict[str, Any]) -> Optional[str]:
    comm = entry.get("_COMM")
    if comm in _AUTH_COMMS:
        return "auth"
    if entry.get("SYSLOG_IDENTIFIER") in _CRON_IDENTS:
        return "cron"
    if str(entry.get("_PID")) == "1":
        return "systemd_pid1"
    if entry.get("_TRANSPORT") == "kernel":
        return "kernel"
    return None


def journal_values(entry: Dict[str, Any], machine: str) -> Optional[Dict[str, Any]]:
    """One journal entry -> the event values log sync would store for it, or None."""
    group = _journal_group(entry)
    ts = _entry_ts(entry)
    if group is None or ts is None:
        return None
    rec = logread.Record(kind="journal", ts=ts, entry=entry, match=group)
    try:
        if group == "auth":
            ev = lp_auth.to_auth_event(rec, machine)
            if ev is None:
                return None
            return A.auth_values(ev, host=machine, line_prefix=False, time_zone=None,
                                 created=datetime.now(timezone.utc))
        parser = {"cron": lp_cron, "systemd_pid1": lp_systemd, "kernel": lp_firewall}[group]
        p = parser.to_parsed(rec)
        if p is None:
            return None
        return A.parsed_values(p, host=machine, dataset=DATASET_OF[group])
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def audit_values(lines: List[str], path: str, machine: str) -> Optional[Dict[str, Any]]:
    """One audit event's records -> its event values, or None."""
    events = lp_auditd.group([(t, path, False) for t in lines])
    if not events:
        return None
    try:
        p = lp_auditd.to_parsed(events[0])
        values = A.parsed_values(p, host=machine, dataset="kratos.auditd")
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    values["log_file_path"] = A.short(p.log_file_path, 4096)
    return values


def _rule_fields(rule: Dict[str, Any]) -> frozenset:
    """Every field a rule's condition (and its log source's) names."""
    out = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            f = node.get("field")
            if isinstance(f, str):
                out.add(f)
            for child in node.get("args") or ():
                walk(child)
            if node.get("arg") is not None:
                walk(node["arg"])

    walk(rule.get("match"))
    walk((rule.get("scope") or {}).get("where"))
    cnt = rule.get("count") or {}
    if isinstance(cnt.get("group_by"), str):
        out.add(cnt["group_by"])
    return frozenset(out)


def bounded_event(event: Dict[str, Any], used: frozenset) -> Dict[str, Any]:
    """What a detection carries of its event: the fields the rule used and the event's
    identity fields, each text value capped; the message shorter still. Never the
    surrounding log (log sync brings the full lines)."""
    out: Dict[str, Any] = {}
    for name in sorted(set(_IDENTITY_FIELDS) | set(used)):
        if name not in event:
            continue
        v = event[name]
        cap = MESSAGE_MAX if name == "message" else EVENT_TEXT_MAX
        if isinstance(v, str):
            v = A.short(v, cap) or ""
        elif isinstance(v, list):
            v = [A.short(x, cap) or "" if isinstance(x, str) else x for x in v[:64]]
        out[name] = v
    return out
