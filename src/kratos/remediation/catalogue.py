"""The closed list of fixes Kratos can build itself (A.4 §5.4).

Each template is a plain description, a few typed parameters, and the exact command they
render. The model picks a template and supplies values; this module -- not the model --
checks every value and writes the command:

* an IP must be a real address that this run's evidence mentions and must not be the machine
  under investigation or loopback;
* a unit must be on the vetted list the sub-agent's own ceiling uses (`subagent.ceiling`);
* an account name must have a username's shape and appear in a finding of this run;
* a PID must have been listed by a tool in this run;
* a path, fingerprint or cron line must occur verbatim in the evidence.

Anything else is refused with a reason, and the interface shows the explanation without a
command. DISPLAY-ONLY: a person copies and runs these -- nothing here executes, and the
catalogue is not connected to the fix channel's whitelist (it reuses its validators only).
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass
from typing import Callable

from kratos.remediation.evidence import Evidence
from kratos.subagent import ceiling as _ceiling
from kratos.subagent import whitelist as _wl


class TemplateError(ValueError):
    """The template id or one of its values was refused; the message says why, in plain words."""


_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._/+@:=,-]{1,300}$")
_SHA256_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_MD5_FP_RE = re.compile(r"^(?:MD5:)?(?:[0-9a-f]{2}:){15}[0-9a-f]{2}$")
_FORBIDDEN_PATH_PREFIXES = ("/proc/", "/sys/", "/dev/")
_FILE_MODES = ("go-w", "go-rwx", "u-s", "600", "640", "644", "700", "750", "755")
_MAX_LINE = 300
PID_MIN, PID_MAX = 2, 4_194_304

_UNITS = tuple(_ceiling.ENABLE_UNITS)

# The closed slot validators of the fix channel's whitelist, reused here so a unit, a PID, an
# address or an account name means exactly what it means there (the catalogue adds the
# evidence checks on top, and stays display-only).
_UNIT_SLOT = _wl.Slot(kind="enum", values=_UNITS)
_PID_SLOT = _wl.Slot(kind="int_range", min_value=PID_MIN, max_value=PID_MAX)
_IP_SLOT = _wl.Slot(kind="ip")
_USER_SLOT = _wl.Slot(kind="token", pattern=_USER_RE.pattern, max_length=32)
_MODE_SLOT = _wl.Slot(kind="enum", values=_FILE_MODES)


def _slot_ok(name: str, slot: _wl.Slot, value: object, problem: str) -> None:
    try:
        _wl.validate_slot_value("catalogue", name, slot, value)
    except _wl.SlotValueError:
        raise TemplateError(problem) from None


@dataclass(frozen=True)
class Param:
    name: str
    kind: str                      # ip | unit | user | pid | path | fingerprint | line | enum
    doc: str
    values: tuple[str, ...] = ()   # for enum/unit


@dataclass(frozen=True)
class Template:
    id: str
    description: str
    params: tuple[Param, ...]
    render: Callable[[dict[str, str]], str]

    def signature(self) -> str:
        return f"{self.id}({', '.join(p.name for p in self.params)})"

    def prompt_line(self) -> str:
        """`- "id" -- what it does. values: {"ip": ...}`: the id stands alone in quotes, so a model
        copies it as the template id and not the argument list with it."""
        values = ", ".join(f'"{p.name}"' for p in self.params)
        return f'- "{self.id}" -- {self.description}. values: {values}'


_ID_WITH_ARGS = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*\(.*\)\s*$")


# --- value checks ---------------------------------------------------------------------------------

def _check_ip(value: object, evidence: Evidence) -> str:
    if not isinstance(value, str):
        raise TemplateError("the IP address must be text")
    _slot_ok("ip", _IP_SLOT, value.strip(), f"{value!r} is not an IP address")
    addr = ipaddress.ip_address(value.strip())
    ip = str(addr)
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_reserved or addr.is_link_local:
        raise TemplateError(f"{ip} is not an address worth blocking")
    if ip in evidence.protected:
        raise TemplateError(f"{ip} is the machine under investigation -- blocking it would cut it off")
    if not evidence.contains(ip):
        raise TemplateError(f"{ip} does not appear anywhere in what this investigation saw")
    return ip


def _check_unit(value: object, evidence: Evidence) -> str:
    _slot_ok("unit", _UNIT_SLOT, value, f"{value!r} is not on the list of services Kratos will suggest managing")
    return value  # type: ignore[return-value]


def _check_user(value: object, evidence: Evidence) -> str:
    _slot_ok("user", _USER_SLOT, value, f"{value!r} is not a valid account name")
    if value == "root":
        raise TemplateError("root is not locked or changed by a suggested command")
    if not evidence.in_findings(value):
        raise TemplateError(f"the account {value!r} does not appear in any finding of this investigation")
    return value


def _check_pid(value: object, evidence: Evidence) -> str:
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TemplateError("the process id must be a number")
    _slot_ok("pid", _PID_SLOT, value, f"{value} is not a process id Kratos will suggest killing")
    if value not in evidence.pids:
        raise TemplateError(f"process {value} was not listed by any tool in this investigation")
    return str(value)


def _check_path(value: object, evidence: Evidence) -> str:
    if not isinstance(value, str) or not _PATH_RE.fullmatch(value):
        raise TemplateError(f"{value!r} is not a plain absolute path")
    if ".." in value.split("/") or value.endswith("/") or "//" in value:
        raise TemplateError(f"{value!r} is not a plain absolute path")
    if value.startswith(_FORBIDDEN_PATH_PREFIXES) or value == "/":
        raise TemplateError(f"{value} is not a path Kratos will suggest changing")
    if not evidence.contains(value):
        raise TemplateError(f"the path {value} does not appear in what this investigation saw")
    return value


def _check_fingerprint(value: object, evidence: Evidence) -> str:
    if not isinstance(value, str) or not (_SHA256_FP_RE.fullmatch(value) or _MD5_FP_RE.fullmatch(value)):
        raise TemplateError(f"{value!r} is not an SSH key fingerprint")
    if not evidence.contains(value):
        raise TemplateError("that key fingerprint does not appear in what this investigation saw")
    return value


def _check_line(value: object, evidence: Evidence) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TemplateError("the cron line must be text")
    if "\n" in value or "\r" in value or "\x00" in value or len(value) > _MAX_LINE:
        raise TemplateError("the cron line must be one line of at most 300 characters")
    if not evidence.has_line(value):
        raise TemplateError("that cron line does not appear verbatim in what this investigation saw")
    return value


def _enum(values: tuple[str, ...]) -> Callable[[object, Evidence], str]:
    slot = _MODE_SLOT if values == _FILE_MODES else _wl.Slot(kind="enum", values=values)

    def check(value: object, evidence: Evidence) -> str:
        _slot_ok("value", slot, value, f"{value!r} is not one of: {', '.join(values)}")
        return value  # type: ignore[return-value]

    return check


_CHECKS: dict[str, Callable[[object, Evidence], str]] = {
    "ip": _check_ip, "unit": _check_unit, "user": _check_user, "pid": _check_pid,
    "path": _check_path, "fingerprint": _check_fingerprint, "line": _check_line,
}


# --- the templates -------------------------------------------------------------------------------------

def _q(value: str) -> str:
    return shlex.quote(value)


def _remove_key(v: dict[str, str]) -> str:
    # Rewrites the account's authorized_keys without the one key whose fingerprint matches (a copy is
    # kept next to it). `~user` is expanded by the shell, so root and ordinary accounts both work.
    return (
        f'f=~{v["user"]}/.ssh/authorized_keys; sudo cp -p "$f" "$f.kratos.bak" && '
        f'while IFS= read -r l; do [ "$(printf \'%s\\n\' "$l" | ssh-keygen -lf - 2>/dev/null | awk \'{{print $2}}\')" '
        f'= {_q(v["fingerprint"])} ] || printf \'%s\\n\' "$l"; done < "$f.kratos.bak" | sudo tee "$f" >/dev/null'
    )


TEMPLATES: dict[str, Template] = {t.id: t for t in (
    Template("fail2ban.ban_ip", "Ban an attacking IP address with fail2ban's ssh jail",
             (Param("ip", "ip", "an address that attacked, from the evidence"),),
             lambda v: f'sudo fail2ban-client set sshd banip {v["ip"]}'),
    Template("ufw.deny_from", "Block an attacking IP address at the firewall (ufw)",
             (Param("ip", "ip", "an address that attacked, from the evidence"),),
             lambda v: f'sudo ufw deny from {v["ip"]} to any'),
    Template("service.enable_now", "Turn on and start a security service that should be running",
             (Param("unit", "unit", "the service", _UNITS),),
             lambda v: f'sudo systemctl enable --now {v["unit"]}'),
    Template("service.restart", "Restart a security service",
             (Param("unit", "unit", "the service", _UNITS),),
             lambda v: f'sudo systemctl restart {v["unit"]}'),
    Template("account.lock", "Lock an account's password (does not end its sessions or remove its keys)",
             (Param("user", "user", "an account named in a finding"),),
             lambda v: f'sudo usermod -L {v["user"]}'),
    Template("account.expire", "Expire an account so it can no longer log in",
             (Param("user", "user", "an account named in a finding"),),
             lambda v: f'sudo chage -E 0 {v["user"]}'),
    Template("ssh.remove_authorized_key", "Remove one SSH key from an account's authorized_keys, by fingerprint (a backup is kept)",
             (Param("user", "user", "an account named in a finding"),
              Param("fingerprint", "fingerprint", "the key's fingerprint, from the evidence")),
             _remove_key),
    Template("process.kill", "Stop a running process by its process id",
             (Param("pid", "pid", "a process id a tool listed"),),
             lambda v: f'sudo kill {v["pid"]}'),
    Template("cron.remove_line", "Remove one exact line from an account's crontab",
             (Param("user", "user", "an account named in a finding"),
              Param("line", "line", "the exact crontab line, from the evidence")),
             lambda v: f'sudo crontab -u {v["user"]} -l | grep -vxF -- {_q(v["line"])} | sudo crontab -u {v["user"]} -'),
    Template("file.restrict_mode", "Restrict a file's permissions",
             (Param("path", "path", "a path the evidence mentions"),
              Param("mode", "enum", "the permissions to set", _FILE_MODES)),
             lambda v: f'sudo chmod {v["mode"]} -- {_q(v["path"])}'),
)}


def template_ids() -> list[str]:
    return list(TEMPLATES)


def prompt_lines() -> str:
    """The short list the system prompt shows the model: one line per template."""
    return "\n".join(t.prompt_line() for t in TEMPLATES.values())


def render_template(template_id: object, values: object, evidence: Evidence) -> str:
    """The exact command for `template_id` with `values`, every value checked against `evidence`.
    Raises TemplateError (with a reason) for an unknown template, a missing or extra value, or a
    value that fails its check."""
    if isinstance(template_id, str):
        template_id = (_ID_WITH_ARGS.match(template_id).group(1)       # "fail2ban.ban_ip(ip)" -> "fail2ban.ban_ip"
                       if _ID_WITH_ARGS.match(template_id) else template_id.strip())
    tpl = TEMPLATES.get(template_id) if isinstance(template_id, str) else None
    if tpl is None:
        raise TemplateError(f"{template_id!r} is not a template Kratos knows")
    if not isinstance(values, dict):
        raise TemplateError("the template values must be an object")
    wanted = {p.name for p in tpl.params}
    extra = sorted(set(map(str, values)) - wanted)
    if extra:
        raise TemplateError(f"{tpl.id} takes no value named {', '.join(extra)}")
    clean: dict[str, str] = {}
    for p in tpl.params:
        if p.name not in values:
            raise TemplateError(f"{tpl.id} needs a value for {p.name}")
        check = _enum(p.values) if p.kind == "enum" else _CHECKS[p.kind]
        try:
            clean[p.name] = check(values[p.name], evidence)
        except TemplateError as e:
            raise TemplateError(f"{p.name}: {e}") from None
    return tpl.render(clean)


# --- recognising a model-written command that IS a template ----------------------------------------------
# A command the model wrote in plain text is often exactly a template's command. Matching is strict on
# purpose: the WHOLE line, an optional leading `sudo` (the templates all run with it), and for ufw an
# optional `to any` -- nothing else (no extra flags, no other arguments, no chaining). The values it
# captures still go through the same evidence checks as a template the model named, so a recognised
# command is exactly as safe as one built from scratch; one that fails them stays model-written (and
# flagged as before).
_S = r"(?:sudo\s+)?"
_TOKEN = r"[^\s;&|<>$`\\'\"()]+"
_RECOGNISERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fail2ban.ban_ip", re.compile(rf"^{_S}fail2ban-client\s+set\s+sshd\s+banip\s+(?P<ip>{_TOKEN})$")),
    ("ufw.deny_from", re.compile(rf"^{_S}ufw\s+deny\s+from\s+(?P<ip>{_TOKEN})(?:\s+to\s+any)?$")),
    ("service.enable_now", re.compile(rf"^{_S}systemctl\s+enable\s+--now\s+(?P<unit>{_TOKEN})$")),
    ("service.restart", re.compile(rf"^{_S}systemctl\s+restart\s+(?P<unit>{_TOKEN})$")),
    ("account.lock", re.compile(rf"^{_S}usermod\s+-L\s+(?P<user>{_TOKEN})$")),
    ("account.expire", re.compile(rf"^{_S}chage\s+-E\s+0\s+(?P<user>{_TOKEN})$")),
    ("process.kill", re.compile(rf"^{_S}kill\s+(?P<pid>\d{{1,8}})$")),
    ("file.restrict_mode", re.compile(rf"^{_S}chmod\s+(?P<mode>{_TOKEN})\s+(?:--\s+)?(?P<path>/{_TOKEN})$")),
)


def recognise(command: str) -> tuple[str, dict[str, str]] | None:
    """(template id, values) when `command` is, as a whole line, one of the template shapes above;
    otherwise None. Says nothing about whether the values are acceptable -- `render_template` does."""
    line = " ".join(str(command or "").split())
    for tid, rx in _RECOGNISERS:
        m = rx.match(line)
        if m:
            return tid, m.groupdict()
    return None
