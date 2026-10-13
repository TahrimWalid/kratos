"""What this run actually saw -- the thing a suggested command's values are checked against.

Built from the investigation's tool results, the correlated findings, the goal and the
targets. A template value (an IP to ban, an account to lock, a PID to kill, a path to
restrict) is accepted only if it appears here; a free-form command's hosts are compared
against it. Nothing in this module trusts the text it reads -- it only asks "does this
value occur?".
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

_MAX_TEXT = 2_000_000          # characters of evidence kept per run
_MAX_DEPTH = 30

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_URL_HOST_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/\s@'\"]+@)?(\[[0-9A-Fa-f:]+\]|[^/\s:'\"?#]+)")
_AT_HOST_RE = re.compile(r"\b[\w.-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b")
_BARE_HOST_RE = re.compile(r"(?<![\w./@-])((?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]{1,23})(?![\w/-])")

# a dotted word that is a file name or a program, not a machine
FILE_SUFFIXES = frozenset({
    "conf", "cfg", "ini", "log", "txt", "sh", "py", "pl", "rb", "js", "json", "yaml", "yml", "xml", "toml",
    "service", "socket", "timer", "target", "mount", "path", "slice", "scope", "d", "so", "bak", "old", "orig",
    "key", "pub", "pem", "crt", "csr", "cer", "db", "sqlite", "lock", "pid", "sock", "tmp", "swp", "md", "rules",
    "deb", "rpm", "tar", "gz", "bz2", "xz", "zip", "tgz", "img", "iso", "bin", "exe", "dll", "ko", "a", "o",
    "list", "sources", "gpg", "asc", "sig", "hash", "yara", "yar", "csv", "html", "htm", "php", "jsp", "asp",
    "local", "localdomain", "internal", "lan", "home", "corp", "invalid", "test", "example",
})


def _walk_strings(value: Any, out: list[str], depth: int = 0, budget: list[int] | None = None) -> None:
    budget = budget if budget is not None else [_MAX_TEXT]
    if depth > _MAX_DEPTH or budget[0] <= 0:
        return
    if isinstance(value, str):
        out.append(value)
        budget[0] -= len(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                out.append(k)
                budget[0] -= len(k)
            _walk_strings(v, out, depth + 1, budget)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            _walk_strings(v, out, depth + 1, budget)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.append(str(value))
        budget[0] -= 8


def _walk_pids(value: Any, out: set[int], depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and k.lower() == "pid":
                if isinstance(v, int) and not isinstance(v, bool):
                    out.add(v)
                elif isinstance(v, str) and v.isdigit():
                    out.add(int(v))
            _walk_pids(v, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _walk_pids(v, out, depth + 1)


def hosts_in(text: str) -> set[str]:
    """Every IP address, URL host, user@host host and bare dotted hostname that `text` mentions
    (lower-cased). A dotted word that is only a file name (`sshd_config.bak`, `unit.service`)
    is not a host."""
    found: set[str] = set()
    for m in _IPV4_RE.finditer(text):
        try:
            found.add(str(ipaddress.ip_address(m.group(0))))
        except ValueError:
            continue
    for m in _IPV6_RE.finditer(text):
        try:
            found.add(str(ipaddress.ip_address(m.group(0))))
        except ValueError:
            continue
    for m in _URL_HOST_RE.finditer(text):
        host = m.group(1).strip("[]").lower()
        if host:
            found.add(host)
    for m in _AT_HOST_RE.finditer(text):
        found.add(m.group(1).lower())
    for m in _BARE_HOST_RE.finditer(text):
        word = m.group(1).lower()
        if word.rsplit(".", 1)[-1] in FILE_SUFFIXES:
            continue
        try:
            ipaddress.ip_address(word)
            continue
        except ValueError:
            pass
        found.add(word)
    return found


class Evidence:
    """The values this investigation saw. `protected` are addresses a suggested command must never
    block (the machine under investigation, loopback)."""

    def __init__(self, texts: Iterable[str] = (), *, finding_texts: Iterable[str] = (),
                 pids: Iterable[int] = (), protected: Iterable[str] = (), known_hosts: Iterable[str] = ()) -> None:
        self._text = "\n".join(t for t in texts if isinstance(t, str))[:_MAX_TEXT]
        self._finding_text = "\n".join(t for t in finding_texts if isinstance(t, str))[:_MAX_TEXT]
        self.pids: frozenset[int] = frozenset(pids)
        self.protected: frozenset[str] = frozenset(p.lower() for p in protected if p) | {"127.0.0.1", "::1", "localhost"}
        self._hosts: set[str] = hosts_in(self._text) | hosts_in(self._finding_text)
        self._hosts |= {h.lower() for h in known_hosts if h}
        self._hosts |= self.protected

    @classmethod
    def empty(cls) -> "Evidence":
        return cls()

    @classmethod
    def from_run(cls, *, transcript: Iterable[dict[str, Any]] = (), findings: Iterable[dict[str, Any]] | None = None,
                 goal: str = "", targets: Iterable[str] = ()) -> "Evidence":
        texts: list[str] = [goal or ""]
        pids: set[int] = set()
        for step in transcript or ():
            if not isinstance(step, dict):
                continue
            obs = step.get("observation")
            if obs is not None:
                _walk_strings(obs, texts)
                _walk_pids(obs, pids)
        finding_texts: list[str] = []
        for f in findings or ():
            if isinstance(f, dict):
                _walk_strings(f, finding_texts)
        target_list = [t for t in targets if t]
        return cls(texts + finding_texts, finding_texts=finding_texts, pids=pids,
                   protected=[t.split("@")[-1] for t in target_list], known_hosts=[t.split("@")[-1] for t in target_list])

    # -- lookups -------------------------------------------------------------------------------
    @staticmethod
    def _occurs(text: str, value: str) -> bool:
        if not value:
            return False
        return re.search(r"(?<![\w.-])" + re.escape(value) + r"(?![\w-])", text) is not None

    def contains(self, value: str) -> bool:
        """`value` appears as a whole token somewhere in this run's tool results or findings."""
        return self._occurs(self._text, value) or self._occurs(self._finding_text, value)

    def in_findings(self, value: str) -> bool:
        """`value` appears as a whole token in a finding (title, evidence, entities)."""
        return self._occurs(self._finding_text, value)

    def has_line(self, line: str) -> bool:
        """`line` appears verbatim, as a whole line or as a quoted/embedded string, in the evidence."""
        return bool(line) and (line in self._text or line in self._finding_text)

    def knows_host(self, host: str) -> bool:
        return host.strip("[]").lower() in self._hosts

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset(self._hosts)
