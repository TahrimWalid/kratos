"""Judging the live-response inventory -- on Kratos, never on the machine (A.5).

Input: one parsed inventory (kratos.adapters.live_response.parse_output). Output:
`Signal`s -- what a LIVE-* finding will say, already plain-worded and masked,
serialised into the snapshot the rule engine reads. Nothing here runs a command
or reaches a machine.

Live-response findings are point-in-time: a process is an event in time, so
LIVE-001/002/003/005/006 are *occurrence* rules (a later run that re-reads and
no longer sees the process marks it inactive); LIVE-004 (an executable dropped in
a world-writable directory) is a *condition* (the file is a state); LIVE-007 is a
run note (the restart-needed hint and what could not be read). There is no
baseline -- "right now" is the whole point.
"""
from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from kratos.adapters import live_response as _L
from kratos.events import redact
from kratos.logsources import attack

MAX_ITEMS_SHOWN = 12
MAX_EVIDENCE_LINES = 60
CMDLINE_SHOWN = 160

AGENT_FIX = "Read this machine through its sub-agent (it reads as root), or run the check as root."

# A shell/interpreter running under a network service is the classic web-shell /
# exploited-service shape (LIVE-006).
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "busybox",
                     "python", "python2", "python3", "perl", "ruby", "php", "node", "nodejs",
                     "lua", "tclsh", "nc", "ncat", "netcat", "socat"})
_NET_SERVICES = frozenset({"nginx", "apache2", "httpd", "lighttpd", "caddy", "haproxy",
                           "mysqld", "mariadbd", "postgres", "postmaster", "redis-server",
                           "memcached", "mongod", "php-fpm", "vsftpd", "proftpd", "pure-ftpd",
                           "smbd", "named", "dovecot", "exim4", "postfix"})

# ATT&CK v19 labels (verified against the official enterprise-attack-19.0 STIX bundle).
_FILE_DELETION = attack.FILE_DELETION               # T1070.004 (deleted running binary)
_REFLECTIVE = attack.REFLECTIVE_CODE_LOADING        # T1620 (memfd)
_DYNAMIC_LINKER = attack.DYNAMIC_LINKER             # T1574.006 (LD_PRELOAD/LD_AUDIT)
_UNIX_SHELL = attack.UNIX_SHELL                     # T1059.004
_WEB_SHELL = attack.WEB_SHELL                       # T1505.003


@dataclass(frozen=True)
class Signal:
    rule: str
    severity: str
    title: str
    evidence: list[str] = field(default_factory=list)
    recommendation: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    attack: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "title": self.title, "evidence": list(self.evidence),
                "recommendation": list(self.recommendation), "entities": list(self.entities),
                "attack": [dict(a) for a in self.attack]}


def _mask(text: Any) -> str:
    out, _changed = redact.mask(str(text or ""))
    return out


def _basename(path: str) -> str:
    base, _marker = _L._split_marker(str(path or ""))
    return posixpath.basename(base)


def entity_of(it: dict[str, Any]) -> str:
    """`exe|pid|starttime` -- a reused PID with a new start time is a new entity,
    the same process across runs is the same entity (A.5 §3.4)."""
    return f"{it.get('exe') or '?'}|{it.get('pid')}|{it.get('starttime')}"


def _attack(*labels: dict[str, str]) -> list[dict[str, str]]:
    return [dict(x) for x in labels]


class Judgement:
    def __init__(self, inv: dict[str, Any]):
        self.inv = inv
        self.answer_gaps: list[str] = []       # what the answer must say was not looked at (_coverage)
        self.procs: dict[int, dict[str, Any]] = {int(k): v for k, v in (inv.get("procs") or {}).items()}
        self.by_pid = self.procs
        self.ownership_known = bool((inv.get("ownership") or {}).get("source")) and not (inv.get("ownership") or {}).get("error")
        self.restart_hints: list[dict[str, Any]] = []
        self.signals: list[Signal] = []

    # ----------------------------------------------------------------- helpers
    def _proc_line(self, it: dict[str, Any], note: str = "") -> str:
        bits = [f"  pid {it.get('pid')} ({_mask(_basename(it.get('comm') or it.get('exe') or '?'))})"]
        if note:
            bits.append(f" -- {note}")
        bits.append(f"\n    exe: {_mask(it.get('exe') or 'unreadable')}")
        cmd = str(it.get("cmdline") or "")
        if cmd:
            bits.append(f"\n    command: {_mask(cmd)[:CMDLINE_SHOWN]}")
        user = it.get("user")
        if user and user != "UNKNOWN":
            bits.append(f"\n    running as: {_mask(user)}")
        return "".join(bits)

    def _exe_marker(self, it: dict[str, Any]) -> str:
        exe = str(it.get("exe") or "")
        base, marker = _L._split_marker(exe)
        if base.startswith("/memfd:") or "memfd:" in base:
            return "memfd"
        if marker:
            return "deleted"
        return "normal"

    def _real_path(self, it: dict[str, Any]) -> str | None:
        return _L._exe_real_path(str(it.get("exe") or ""))

    def _under_temp(self, path: str | None) -> bool:
        return bool(path) and any(path == d or path.startswith(d + "/") for d in _L.TEMP_DIRS)  # type: ignore[arg-type]

    def _upgrade_explained(self, it: dict[str, Any]) -> bool:
        """A deleted binary whose path exists again and is package-owned: a
        restart-pending service after an upgrade, not compromise (§3.3)."""
        return bool(it.get("exe_exists")) and bool(it.get("exe_package"))

    def _say(self, rule: str, severity: str, title: str, lines: list[str], recommendation: list[str],
             entities: list[str], labels: list[dict[str, str]]) -> None:
        if len(lines) > MAX_EVIDENCE_LINES:
            lines = lines[:MAX_EVIDENCE_LINES] + [f"  ... and more (showing the first {MAX_EVIDENCE_LINES} lines)"]
        self.signals.append(Signal(rule=rule, severity=severity, title=title, evidence=lines,
                                   recommendation=recommendation, entities=sorted(set(entities)), attack=labels))

    # ----------------------------------------------------------------- rules
    def _deleted_and_memfd(self) -> None:
        """LIVE-001 (deleted running binary) and LIVE-002 (memfd / anonymous exec
        from a world-writable directory)."""
        live001: list[dict[str, Any]] = []
        live002: list[dict[str, Any]] = []
        for it in self._ordered():
            marker = self._exe_marker(it)
            if marker == "normal":
                continue
            real = self._real_path(it)
            if marker == "memfd" or (marker == "deleted" and self._under_temp(real)):
                live002.append(it)
            elif marker == "deleted":
                if self._upgrade_explained(it):
                    self.restart_hints.append(it)
                else:
                    live001.append(it)
        if live001:
            lines: list[str] = []
            for it in live001[:MAX_ITEMS_SHOWN]:
                why = ("its file no longer exists on disk" if not it.get("exe_exists")
                       else "its file exists again but belongs to no installed package")
                lines.append(self._proc_line(it, f"running a deleted program -- {why}"))
            if len(live001) > MAX_ITEMS_SHOWN:
                lines.append(f"  ... and {len(live001) - MAX_ITEMS_SHOWN} more")
            self._say("LIVE-001", "high",
                      f"{len(live001)} running process(es) whose program was deleted from disk",
                      lines,
                      ["A program that deleted its own file while still running is a classic way for malware to "
                       "hide (there is nothing left on disk to scan). Normal after a package upgrade -- but then the "
                       "file exists again and belongs to a package, which is not the case here.",
                       "Do not kill it yet if you can help it: capture the running memory first "
                       "(`/proc/<pid>/exe` can be copied), then investigate how it started (its parent, its start time, "
                       "recent logins)."],
                      [entity_of(it) for it in live001], _attack(_FILE_DELETION))
        if live002:
            lines = []
            for it in live002[:MAX_ITEMS_SHOWN]:
                where = "a memory-only file (memfd)" if self._exe_marker(it) == "memfd" else \
                        f"a deleted file in {self._real_path(it)}"
                lines.append(self._proc_line(it, f"running from {where}"))
            if len(live002) > MAX_ITEMS_SHOWN:
                lines.append(f"  ... and {len(live002) - MAX_ITEMS_SHOWN} more")
            self._say("LIVE-002", "high",
                      f"{len(live002)} process(es) running from memory or a deleted temporary file",
                      lines,
                      ["Running a program straight from memory (memfd) or from a just-deleted file in /tmp or "
                       "/dev/shm leaves nothing on disk to scan -- a common way attackers run a payload. A few JIT "
                       "runtimes (Java, .NET) map memfd files but do not EXECUTE from them; this flags execution.",
                       "Capture the running memory before killing the process, then trace how it was started."],
                      [entity_of(it) for it in live002], _attack(_REFLECTIVE))

    def _preload(self) -> None:
        """LIVE-003: a process started with LD_PRELOAD or LD_AUDIT set."""
        unowned: list[tuple[dict[str, Any], str, str]] = []     # (proc, var, lib)
        owned: list[tuple[dict[str, Any], str, str]] = []
        for it in self._ordered():
            ld = it.get("ld") or {}
            for var in _L.PRELOAD_VARS:
                lib = ld.get(var)
                if not lib:
                    continue
                pkg = (it.get("preload_packages") or {}).get(lib) if lib.startswith("/") else None
                if lib.startswith("/") and pkg is not None:
                    owned.append((it, var, lib))
                else:
                    unowned.append((it, var, lib))
        if unowned:
            lines = []
            for it, var, lib in unowned[:MAX_ITEMS_SHOWN]:
                lines.append(self._proc_line(it, f"{var}={_mask(lib)} -- that library belongs to no installed package"
                                             if self.ownership_known else f"{var}={_mask(lib)}"))
            if len(unowned) > MAX_ITEMS_SHOWN:
                lines.append(f"  ... and {len(unowned) - MAX_ITEMS_SHOWN} more")
            self._say("LIVE-003", "high",
                      f"{len(unowned)} process(es) made to load an extra library no package owns",
                      lines,
                      ["LD_PRELOAD and LD_AUDIT force a program to load a chosen library, which runs inside it -- how "
                       "a userspace rootkit hides files, processes and logins. A library here is owned by no package.",
                       "Keep a copy of the library, find out what it does and how it was set, and treat the process "
                       "as possibly compromised."],
                      [entity_of(it) for it, _v, _l in unowned], _attack(_DYNAMIC_LINKER))
        if owned:
            lines = [self._proc_line(it, f"{var}={_mask(lib)} (part of {it.get('preload_packages', {}).get(lib)})")
                     for it, var, lib in owned[:MAX_ITEMS_SHOWN]]
            if len(owned) > MAX_ITEMS_SHOWN:
                lines.append(f"  ... and {len(owned) - MAX_ITEMS_SHOWN} more")
            self._say("LIVE-003", "low",
                      f"{len(owned)} process(es) load an extra library (worth a look)",
                      lines,
                      ["These use LD_PRELOAD/LD_AUDIT with a library a package does own (some monitoring and "
                       "sandboxing tools do this). Confirm it is expected on this machine."],
                      [entity_of(it) for it, _v, _l in owned], _attack(_DYNAMIC_LINKER))

    def _temp_executables(self) -> None:
        """LIVE-004: an ELF or script with the execute bit in /tmp, /dev/shm,
        /var/tmp (or /run/user on the agent). Running -> high; present only ->
        medium. A condition (the file is a state)."""
        exe_paths = {self._real_path(it) for it in self.procs.values()}
        running: list[dict[str, Any]] = []
        present: list[dict[str, Any]] = []
        for path, it in sorted((self.inv.get("temp_files") or {}).items()):
            header = str(it.get("header") or "")
            if header not in ("elf", "script"):
                continue
            (running if path in exe_paths else present).append(it)
        for group, severity, verb in ((running, "high", "is running right now"),
                                      (present, "medium", "is present")):
            if not group:
                continue
            lines = []
            for it in group[:MAX_ITEMS_SHOWN]:
                sha = str(it.get("sha256") or "")
                tail = (f", sha256 {sha[:12]}" if sha
                        else f", not hashed ({it['hash_skipped']})" if it.get("hash_skipped") else "")
                lines.append(f"  {_mask(it.get('path'))} ({'ELF binary' if it.get('header') == 'elf' else 'script'}, "
                             f"mode {it.get('perm')}, owned by {_mask(it.get('owner') or '?')}{tail})")
            if len(group) > MAX_ITEMS_SHOWN:
                lines.append(f"  ... and {len(group) - MAX_ITEMS_SHOWN} more")
            self._say("LIVE-004", severity,
                      f"{len(group)} executable file(s) in a world-writable directory -- one {verb}"
                      if len(group) == 1 else
                      f"{len(group)} executable file(s) in a world-writable directory ({verb.replace('is', 'are')})",
                      lines,
                      ["/tmp, /dev/shm and /var/tmp are writable by anyone, so an executable there is a common place "
                       "to stage a payload. Legitimate software occasionally does this (installers, build systems).",
                       "Check who owns each file and when it appeared; if it is not expected, keep a copy and remove it."],
                      [f"{it.get('path')}#{str(it.get('sha256') or '')[:12]}" for it in group], [])

    def _sockets(self) -> None:
        """LIVE-005: a listening socket owned by a process from a temp directory, a
        deleted executable, or an executable no package owns."""
        hits: list[tuple[dict[str, Any], dict[str, Any]]] = []     # (socket, proc)
        for sock in self.inv.get("sockets") or []:
            if str(sock.get("state") or "").upper() != "0A":       # TCP LISTEN
                continue
            pid = sock.get("pid")
            it = self.procs.get(pid) if pid is not None else None
            if it is None:
                continue
            marker = self._exe_marker(it)
            real = self._real_path(it)
            suspicious = marker != "normal" or self._under_temp(real) or \
                (self.ownership_known and real is not None and it.get("exe_package") is None)
            if suspicious:
                hits.append((sock, it))
        if not hits:
            return
        lines = []
        for sock, it in hits[:MAX_ITEMS_SHOWN]:
            where = "loopback" if _L.is_loopback_hex(str(sock.get("local_addr") or "")) else \
                    ("all interfaces" if _L.is_wildcard_hex(str(sock.get("local_addr") or "")) else "an address")
            lines.append(self._proc_line(it, f"is listening on {where} port {sock.get('local_port')} "
                                         f"({sock.get('proto')})"))
        if len(hits) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(hits) - MAX_ITEMS_SHOWN} more")
        self._say("LIVE-005", "high",
                  f"{len(hits)} network listener(s) run by a suspicious process",
                  lines,
                  ["A program that accepts connections and was run from /tmp, from a deleted file, or from a binary no "
                   "package installed is a likely backdoor or implant.",
                   "Identify what the listener is for; if it is not expected, capture it and investigate the process."],
                  [entity_of(it) for _s, it in hits], [])

    def _service_shells(self) -> None:
        """LIVE-006: a shell or interpreter whose parent is a network service (the
        web-shell / exploited-service shape)."""
        hits: list[tuple[dict[str, Any], dict[str, Any]]] = []     # (child, parent)
        for it in self._ordered():
            name = _basename(it.get("comm") or it.get("exe") or "")
            if name not in _SHELLS:
                continue
            parent = self.procs.get(it.get("ppid"))
            if parent is None:
                continue
            pname = _basename(parent.get("comm") or parent.get("exe") or "")
            if pname in _NET_SERVICES:
                hits.append((it, parent))
        if not hits:
            return
        lines = []
        for child, parent in hits[:MAX_ITEMS_SHOWN]:
            lines.append(self._proc_line(child, f"a {_mask(_basename(child.get('comm') or child.get('exe') or '?'))} "
                                         f"started by {_mask(_basename(parent.get('comm') or parent.get('exe') or '?'))} "
                                         f"(pid {parent.get('pid')})"))
        if len(hits) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(hits) - MAX_ITEMS_SHOWN} more")
        self._say("LIVE-006", "medium",
                  f"{len(hits)} shell or interpreter(s) started by a network service",
                  lines,
                  ["A web server or database does not normally spawn a shell. When it does, it is often a web shell or "
                   "a service that was just exploited to run commands.",
                   "Look at the command line above and the service's own logs around its start time."],
                  [entity_of(child) for child, _p in hits], _attack(_UNIX_SHELL, _WEB_SHELL))

    def _coverage(self) -> None:
        """LIVE-007 (run note): the restart-needed hint, and what could not be read."""
        lines: list[str] = []
        if self.restart_hints:
            n = len(self.restart_hints)
            names = sorted({_mask(_basename(it.get("exe") or "")) for it in self.restart_hints})[:8]
            lines.append(f"  {n} process(es) are still running a program file that a package update replaced "
                         f"({', '.join(names)}). This is normal after an upgrade; restart them (for example "
                         f"`systemctl restart <service>` or a reboot) to run the new version. Not a sign of compromise.")
        gaps = self.inv.get("proc_gaps") or {}
        if gaps:
            uid = self.inv.get("reader_uid")
            parts = ", ".join(f"{v} could not read {k}" for k, v in sorted(gaps.items()))
            lines.append(f"  Some processes could not be fully read as this user ({parts})"
                         + (f"; the read ran as uid {uid}" if uid else "")
                         + f". Other users' programs are not visible this way. {AGENT_FIX}")
        for t in self.inv.get("truncated") or []:
            lines.append(f"  more than the limit of {t.get('what')} were found ({t.get('count')}); "
                         f"only the first were looked at")
        if self.inv.get("hidepid") and self.inv.get("reader_uid") not in (0, None):
            lines.append("  /proc is mounted with hidepid, so this login cannot see other users' processes at "
                         f"all -- they are missing from this read, not absent from the machine. {AGENT_FIX}")
        denied = sorted(set(self.inv.get("temp_denied") or []))
        if denied:
            lines.append(f"  {len(denied)} folder(s) under the temp directories could not be opened by this login, "
                         "so executables inside them were not checked (e.g. "
                         + ", ".join(_mask(d) for d in denied[:3]) + f"). {AGENT_FIX}")
        if self.inv.get("temp_timeouts"):
            lines.append("  the search for dropped executables ran out of time in: "
                         + ", ".join(sorted(set(self.inv["temp_timeouts"]))[:8]))
        if not self.inv.get("complete"):
            lines.append("  the read did not finish inside its time budget, so this is a partial view of what is running")
        # The short form an investigation's answer names ("not checked"): only what was not
        # looked at -- never the restart-needed hint, which is housekeeping (phase A audit).
        short: list[str] = []
        if gaps:
            short.append(f"{max(gaps.values())} process(es) of other users could not be read over this SSH login")
        if self.inv.get("hidepid") and self.inv.get("reader_uid") not in (0, None):
            short.append("/proc hides other users' processes from this SSH login (hidepid)")
        if denied:
            short.append(f"{len(denied)} temp folder(s) could not be opened over this SSH login")
        if self.inv.get("temp_timeouts") or self.inv.get("truncated"):
            short.append("the search for dropped executables did not finish")
        if not self.inv.get("complete"):
            short.append("the read did not finish, so this check is partial")
        self.answer_gaps = short
        if lines:
            self._say("LIVE-007", "info", "What the live-response check noted",
                      lines,
                      ["A process or location that was not read is unknown, not clean.",
                       "A restart-needed note above is routine housekeeping, not a security finding."],
                      [], [])

    # ----------------------------------------------------------------- order
    def _ordered(self) -> list[dict[str, Any]]:
        return [self.procs[pid] for pid in sorted(self.procs)]

    def run(self) -> None:
        self._deleted_and_memfd()
        self._preload()
        self._temp_executables()
        self._sockets()
        self._service_shells()
        self._coverage()


def judge(inv: dict[str, Any]) -> Judgement:
    """Judge one live-response inventory. Nothing is written anywhere."""
    j = Judgement(inv)
    j.run()
    return j
