"""Risk flags for a command the model wrote itself (A.4 §3.4, §5.4).

A free-form suggested command is allowed -- the model may know a better fix than the
catalogue -- but a person is about to paste it into a root shell on a machine an attacker
may have touched, and the model reads attacker text. So each risky *shape* is named next to
the command, with its reason, and a flagged command needs a second confirmation to copy:

* `network` -- downloads or opens a connection (curl, wget, nc, /dev/tcp, ...)
* `pipe_to_shell` -- feeds text into a shell or interpreter (`| sh`, `python -c`, `eval`, `source <(`)
* `decode` -- decodes hidden content (base64 -d, xxd -r, \\x escapes)
* `substitution` -- runs a nested command (`$(...)`, backticks, `<(...)`)
* `unknown_host` -- names a host, address or URL that nothing in this investigation mentions
* `persistence` -- writes to a place that keeps access (cron, systemd units, profile files, authorized_keys)

Flags warn, they never forbid, and they are heuristics: no flags does not mean safe. A command
built by a catalogue template carries none (code wrote it from checked values).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from kratos.remediation.evidence import Evidence, hosts_in


@dataclass(frozen=True)
class Flag:
    id: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "reason": self.reason}


_NETWORK_PROGRAMS = ("curl", "wget", "fetch", "aria2c", "ftp", "tftp", "lwp-download", "nc", "ncat", "netcat",
                     "socat", "telnet")
_NETWORK_RE = re.compile(r"(?<![\w./-])(" + "|".join(map(re.escape, _NETWORK_PROGRAMS)) + r")(?![\w-])")
_DEV_TCP_RE = re.compile(r"/dev/(tcp|udp)/")

_SHELLS = r"(?:ba|z|da|k|a|c|tc|fi)?sh"
_INTERPRETERS = r"(?:python[\d.]*|perl|ruby|node|nodejs|php|lua|tclsh|osascript)"
_PIPE_TO_SHELL_RES = (
    re.compile(r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S*\s+)*(?:/\S*/)?(?:" + _SHELLS + "|" + _INTERPRETERS + r")(?![\w-])"),
    re.compile(r"(?<![\w-])" + _INTERPRETERS + r"\s+-[a-zA-Z]*[ce]\b"),
    re.compile(r"(?<![\w./-])eval(?![\w-])"),
    re.compile(r"(?<![\w-])source\s+<\("),
    re.compile(r"(?<![\w-])\.\s+<\("),
    re.compile(r"(?<![\w-])" + _SHELLS + r"\s+(?:-\w+\s+)*<\("),
    re.compile(r"(?<![\w-])" + _SHELLS + r"\s+-c\s+[\"']?\$\("),
    re.compile(r"\bxargs\b[^|;&]*\b" + _SHELLS + r"\b"),
)

_DECODE_RES = (
    re.compile(r"(?<![\w-])base64\s+(?:-\w*[dD]\w*|--decode)\b"),
    re.compile(r"(?<![\w-])openssl\s+(?:enc|base64)\b[^|;&]*\s-d\b"),
    re.compile(r"(?<![\w-])xxd\s+(?:-\w*r\w*)\b"),
    re.compile(r"(?<![\w-])(?:uudecode|basenc)\b"),
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}"),
    re.compile(r"(?:\\[0-7]{3}){3,}"),
)

_SUBSTITUTION_RES = (re.compile(r"\$\("), re.compile(r"`"), re.compile(r"<\("), re.compile(r">\("))

_PERSISTENCE_PLACES = re.compile(
    r"(/etc/cron[\w./-]*|/var/spool/cron[\w./-]*|/etc/anacron\w*|/etc/systemd/[\w./-]*|/usr/lib/systemd/[\w./-]*"
    r"|/lib/systemd/[\w./-]*|~?/?\.config/systemd/[\w./-]*|/etc/init\.d/[\w.-]*|/etc/rc\.local|/etc/profile(?:\.d/[\w.-]*)?"
    r"|/etc/(?:bash\.bashrc|environment|ld\.so\.preload|ld\.so\.conf\.d/[\w.-]*|sudoers(?:\.d/[\w.-]*)?)"
    r"|(?:~\w*|/home/[\w.-]+|/root)?/?\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|xinitrc)"
    r"|authorized_keys2?)")
_WRITE_VERB_RES = (
    re.compile(r">>?"),
    re.compile(r"(?<![\w-])(?:tee|cp|mv|ln|install|dd|rsync|scp|sponge|truncate)(?![\w-])"),
    re.compile(r"(?<![\w-])sed\s+(?:-\w*i\w*|--in-place)"),
    re.compile(r"(?<![\w-])systemctl\s+(?:link|edit)\b"),
)
# `crontab -` or `crontab FILE` installs a crontab; `crontab -l/-r/-e` and `-u user -l` do not
_CRONTAB_INSTALL_RE = re.compile(r"(?<![\w-])crontab\s+(?:-u\s+\S+\s+)?(?:-(?=\s*(?:$|[|;&]))|[^-\s;&|]\S*)")


def _network(command: str) -> Flag | None:
    m = _NETWORK_RE.search(command)
    if m:
        return Flag("network", f"downloads or opens a network connection ({m.group(1)})")
    if _DEV_TCP_RE.search(command):
        return Flag("network", "opens a network connection through /dev/tcp")
    return None


def _pipe_to_shell(command: str) -> Flag | None:
    for rx in _PIPE_TO_SHELL_RES:
        m = rx.search(command)
        if m:
            return Flag("pipe_to_shell", f"runs text as code ({' '.join(m.group(0).split())[:40]})")
    return None


def _decode(command: str) -> Flag | None:
    for rx in _DECODE_RES:
        m = rx.search(command)
        if m:
            return Flag("decode", f"decodes hidden content ({' '.join(m.group(0).split())[:40]})")
    return None


def _substitution(command: str) -> Flag | None:
    for rx in _SUBSTITUTION_RES:
        m = rx.search(command)
        if m:
            return Flag("substitution", f"runs a nested command ({m.group(0)})")
    return None


def _unknown_host(command: str, evidence: Evidence) -> Flag | None:
    unknown = sorted(h for h in hosts_in(command) if not evidence.knows_host(h))
    if unknown:
        shown = ", ".join(unknown[:3]) + (f" and {len(unknown) - 3} more" if len(unknown) > 3 else "")
        return Flag("unknown_host", f"names a host or address that nothing in this investigation mentions: {shown}")
    return None


def _persistence(command: str) -> Flag | None:
    if _CRONTAB_INSTALL_RE.search(command):
        return Flag("persistence", "installs a crontab")
    places = _PERSISTENCE_PLACES.findall(command)
    if places and any(rx.search(command) for rx in _WRITE_VERB_RES):
        return Flag("persistence", f"writes to a place that keeps access ({places[0]})")
    return None


def flag_command(command: str, evidence: Evidence | None = None) -> list[Flag]:
    """Every risky shape found in the free-form `command`, most serious first. Empty means none of
    these shapes was found -- not that the command is safe."""
    evidence = evidence or Evidence.empty()
    found = [
        _pipe_to_shell(command), _network(command), _decode(command), _persistence(command),
        _substitution(command), _unknown_host(command, evidence),
    ]
    return [f for f in found if f is not None]
