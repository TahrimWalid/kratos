"""
Who holds privileged access on the monitored TARGET (eval scenario A6).

Read-only, one SSH round trip, POSIX `sh` (Ubuntu/Debian, RHEL, Alpine). It
collects:

  - members of the sudo-granting groups (sudo, wheel, admin) and of groups that
    are root-equivalent in practice (docker, lxd, libvirt, disk, shadow);
  - accounts with UID 0, and accounts whose PRIMARY group is one of the above;
  - sudoers grants, when the SSH user may read them with `sudo -n` (reported
    as not visible otherwise -- never silently treated as "none");
  - account/group change events (useradd, usermod, gpasswd, userdel, ...) from
    the target's journal, newest first, within a look-back window -- this is
    what turns "bob is in sudo" into "bob was ADDED to sudo yesterday";
  - mtimes of /etc/passwd, /etc/group, /etc/sudoers(.d) as a coarse change
    signal when no event log is available.

Nothing here changes the target. The parsing is split from the SSH call so it
can be tested on captured output.

Standard library only: this file also ships in the sub-agent bundle, where the
agent runs the same script for its `privileged_accounts` read
(kratos.subagent.reads) -- one builder for both transports.
"""
from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SUDO_GROUPS: tuple[str, ...] = ("sudo", "wheel", "admin")
# Membership in these is root-equivalent on a typical host (docker/lxd/libvirt
# can mount the host filesystem; disk reads raw block devices; shadow reads
# password hashes).
ROOT_EQUIVALENT_GROUPS: tuple[str, ...] = ("docker", "lxd", "libvirt", "disk", "shadow")
PRIVILEGED_GROUPS: tuple[str, ...] = SUDO_GROUPS + ROOT_EQUIVALENT_GROUPS

ACCOUNT_CHANGE_IDENTIFIERS: tuple[str, ...] = (
    "useradd", "usermod", "userdel", "gpasswd", "groupadd", "groupmod", "groupdel", "adduser", "deluser",
)
DEFAULT_LOOKBACK_DAYS = 30
MAX_EVENTS = 500
_NOLOGIN_SHELLS = ("nologin", "false", "sync", "halt", "shutdown")


# The only privilege prefixes a script may be built with. Checked here, not
# trusted from callers: these land in a shell script verbatim (review v2 H-5).
_ALLOWED_PREFIXES = frozenset({"", "sudo -n"})


def _checked_prefix(prefix: str, what: str) -> str:
    if str(prefix).strip() not in _ALLOWED_PREFIXES:
        raise ValueError(f"{what} must be one of {sorted(_ALLOWED_PREFIXES)}, not {prefix!r}")
    return str(prefix).strip()


def build_script(since_epoch: int, journalctl_prefix: str, sudo: str = "sudo -n") -> str:
    """The read-only probe. Every record is one tab-separated line. `sudo` is
    how sudoers is read: "sudo -n" over SSH, empty for an agent running as root.
    Every interpolated value is a fixed constant, an int, or checked here."""
    since_epoch = int(since_epoch)
    jp = _checked_prefix(journalctl_prefix, "journalctl_prefix")
    journalctl_prefix = jp + " " if jp else ""
    sudo = _checked_prefix(sudo, "sudo")
    groups = " ".join(PRIVILEGED_GROUPS)
    idents = " ".join(f"SYSLOG_IDENTIFIER={i}" for i in ACCOUNT_CHANGE_IDENTIFIERS)
    return f"""SUDO={shlex.quote(sudo)}
for g in {groups}; do
  line=$(getent group "$g" 2>/dev/null) && printf 'GROUP\\t%s\\n' "$line"
done
awk -F: 'NF >= 7 {{ printf "PASSWD\\t%s\\t%s\\t%s\\t%s\\n", $1, $3, $4, $7 }}' /etc/passwd
for f in /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d; do
  m=$(stat -c %Y "$f" 2>/dev/null) && printf 'MTIME\\t%s\\t%s\\n' "$f" "$m"
done
if $SUDO true 2>/dev/null; then
  # Only GRANT lines leave the box: continuation lines are joined first, and
  # comments, Defaults (which can carry mail addresses, paths, env settings),
  # @include directives and alias definitions are dropped. sudoers.d files are
  # the ones sudo itself loads (no '.' in the name, not ending in '~').
  {{ echo /etc/sudoers; $SUDO find /etc/sudoers.d -maxdepth 1 -type f ! -name '*.*' ! -name '*~' 2>/dev/null | sort; }} \\
  | while IFS= read -r f; do
    $SUDO awk '
      {{ if (sub(/\\\\$/, "")) {{ buf = buf $0 " "; next }} line = buf $0; buf = "" }}
      line ~ /^[[:space:]]*(#|$)/ {{ next }}
      line ~ /^[[:space:]]*(Defaults|@include|@includedir)/ {{ next }}
      line ~ /^[[:space:]]*(User|Runas|Host|Cmnd|Cmd)_Alias[[:space:]]/ {{ next }}
      {{ printf "SUDOERS\\t%s:%s\\n", FILENAME, line }}
    ' "$f" 2>/dev/null
  done
  printf 'SUDOERS_OK\\n'
  # Groups granted sudo IN sudoers (e.g. %devops) beyond the well-known ones:
  # resolve their members too, or a real admin would be missed.
  for g in $($SUDO grep -rhoE '^[[:space:]]*%[A-Za-z0-9_.-]+' /etc/sudoers /etc/sudoers.d 2>/dev/null | tr -d ' %\\t' | sort -u); do
    line=$(getent group "$g" 2>/dev/null) && printf 'SGROUP\\t%s\\n' "$line"
  done
else
  printf 'SUDOERS_ERR\\tsudoers is not readable here (not root, and no passwordless sudo)\\n'
fi
if command -v journalctl >/dev/null 2>&1; then
  if ev=$({journalctl_prefix}journalctl --no-pager -q -o short-unix --since @{since_epoch} --reverse -n {MAX_EVENTS} {idents} 2>&1); then
    printf '%s\\n' "$ev" | while IFS= read -r l; do [ -n "$l" ] && printf 'EVT\\t%s\\n' "$l"; done
    printf 'EVTSRC\\tjournal\\n'
    head=$({journalctl_prefix}journalctl --no-pager -q -o short-unix 2>/dev/null | head -n 1 | cut -d' ' -f1)
    [ -n "$head" ] && printf 'JHEAD\\t%s\\n' "$head"
  else
    printf 'EVTERR\\t%s\\n' "$(printf '%s' "$ev" | head -n 1)"
  fi
else
  printf 'EVTERR\\tno journalctl on the target\\n'
fi
"""


# ---------------------------------------------------------------------------
# Event parsing (shadow-utils / adduser syslog lines)
# ---------------------------------------------------------------------------
_EVENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # usermod/useradd: add 'bob' to group 'sudo'   |   add 'bob' to shadow group 'sudo'
    ("added_to_group", re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
    # gpasswd: user bob added by root to group sudo
    ("added_to_group", re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")),
    # usermod: delete 'bob' from group 'sudo'   |   gpasswd: user bob removed by root from group sudo
    ("removed_from_group", re.compile(r"delete '(?P<user>[^']+)' from (?:shadow )?group '(?P<group>[^']+)'")),
    ("removed_from_group", re.compile(r"user (?P<user>\S+) removed by \S+ from group (?P<group>\S+)")),
    # useradd: new user: name=bob, UID=1001, GID=1001, ...
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+), UID=(?P<uid>\d+)")),
    # userdel: delete user 'bob'
    ("user_deleted", re.compile(r"delete user '(?P<user>[^']+)'")),
    # usermod: change user 'bob' UID from '1001' to '0'
    ("uid_changed", re.compile(r"change user '(?P<user>[^']+)' UID from '(?P<old>\d+)' to '(?P<uid>\d+)'")),
)
_SHORT_UNIX_RE = re.compile(r"^(?P<ts>\d+(?:\.\d+)?)\s+\S+\s+(?P<ident>[\w.-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")


def parse_event(line: str) -> dict[str, Any] | None:
    m = _SHORT_UNIX_RE.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    for action, rx in _EVENT_PATTERNS:
        e = rx.search(msg)
        if e:
            ev: dict[str, Any] = {"ts": float(m.group("ts")), "action": action, "user": e.group("user"),
                                  "source": m.group("ident"), "message": msg[:300]}
            if "group" in e.groupdict():
                ev["group"] = e.group("group")
            if "uid" in e.groupdict():
                ev["uid"] = int(e.group("uid"))
            return ev
    return None


# ---------------------------------------------------------------------------
# Whole-output parsing
# ---------------------------------------------------------------------------
@dataclass
class PrivilegedInventory:
    accounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    group_members: dict[str, list[str]] = field(default_factory=dict)
    # Groups granted sudo in sudoers that aren't in PRIVILEGED_GROUPS.
    sudoers_groups: dict[str, list[str]] = field(default_factory=dict)
    sudoers_visible: bool = False
    sudoers_note: str = ""
    sudoers_grants: list[dict[str, str]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    events_source: str | None = None
    events_note: str = ""
    journal_head: float | None = None
    local_users: set[str] = field(default_factory=set)
    mtimes: dict[str, float] = field(default_factory=dict)


def _grant_subject(line: str) -> str | None:
    """First field of a sudoers grant (user, %group, or alias), or None for a
    Defaults/alias/include directive."""
    tok = line.split(None, 1)[0] if line.split() else ""
    if not tok or tok.startswith(("Defaults", "@include", "#include")) or tok.endswith("_Alias"):
        return None
    return tok


def parse_output(stdout: str) -> PrivilegedInventory:
    inv = PrivilegedInventory()
    passwd: dict[str, dict[str, Any]] = {}
    gid_to_group: dict[int, str] = {}
    for raw in stdout.splitlines():
        kind, _, rest = raw.partition("\t")
        if kind == "GROUP":
            parts = rest.split(":")
            if len(parts) >= 4:
                name, gid, members = parts[0], parts[2], parts[3]
                inv.group_members[name] = sorted(m for m in members.split(",") if m)
                if gid.isdigit():
                    gid_to_group[int(gid)] = name
        elif kind == "SGROUP":
            parts = rest.split(":")
            if len(parts) >= 4 and parts[0] not in PRIVILEGED_GROUPS:
                inv.sudoers_groups[parts[0]] = sorted(m for m in parts[3].split(",") if m)
                if parts[2].isdigit():
                    gid_to_group.setdefault(int(parts[2]), parts[0])
        elif kind == "PASSWD":
            f = rest.split("\t")
            if len(f) == 4 and f[1].isdigit() and f[2].isdigit():
                passwd[f[0]] = {"uid": int(f[1]), "gid": int(f[2]), "shell": f[3]}
        elif kind == "MTIME":
            path, _, ts = rest.partition("\t")
            if ts.isdigit():
                inv.mtimes[path] = float(ts)
        elif kind == "SUDOERS":
            path, _, line = rest.partition(":")
            subject = _grant_subject(line.strip())
            if subject:
                inv.sudoers_grants.append({"file": path, "subject": subject, "line": line.strip()[:300]})
        elif kind == "SUDOERS_OK":
            inv.sudoers_visible = True
        elif kind == "SUDOERS_ERR":
            inv.sudoers_note = rest.strip()
        elif kind == "EVT":
            ev = parse_event(rest)
            if ev:
                inv.events.append(ev)
        elif kind == "EVTSRC":
            inv.events_source = rest.strip()
        elif kind == "JHEAD":
            try:
                inv.journal_head = float(rest.strip())
            except ValueError:
                pass
        elif kind == "EVTERR":
            inv.events_note = rest.strip()[:300]
    inv.events.sort(key=lambda e: e["ts"])

    def _add(user: str, reason: str) -> None:
        acct = inv.accounts.setdefault(user, {"user": user, "via": []})
        if reason not in acct["via"]:
            acct["via"].append(reason)

    for group, members in inv.group_members.items():
        label = "root-equivalent group" if group in ROOT_EQUIVALENT_GROUPS else "sudo group"
        for m in members:
            _add(m, f"member of '{group}' ({label})")
    for group, members in inv.sudoers_groups.items():
        for m in members:
            _add(m, f"member of '{group}' (granted sudo in sudoers)")
    for user, p in passwd.items():
        if p["uid"] == 0:
            _add(user, "UID 0 (root)")
        primary = gid_to_group.get(p["gid"])
        if primary:
            _add(user, f"primary group is '{primary}'")
    for g in inv.sudoers_grants:
        subj = g["subject"]
        if subj.startswith("%"):
            continue  # a group grant -- its members are listed via the group itself when it's a known one
        if subj != "root":
            _add(subj, f"sudoers grant ({g['file']})")
    inv.local_users = set(passwd)
    for user, acct in inv.accounts.items():
        p = passwd.get(user)
        acct["uid"] = p["uid"] if p else None
        acct["shell"] = p["shell"] if p else None
        acct["login_shell"] = bool(p) and not p["shell"].rstrip("/").endswith(_NOLOGIN_SHELLS)
        acct["local_account"] = p is not None
    return inv


def notable_events(inv: PrivilegedInventory) -> list[dict[str, Any]]:
    """Events that grant privilege: added to a privileged group (including one
    granted sudo in sudoers), UID set to 0, or a new account created with UID 0."""
    out = []
    privileged = set(PRIVILEGED_GROUPS) | set(inv.sudoers_groups)
    for e in inv.events:
        if e["action"] == "added_to_group" and e.get("group") in privileged:
            out.append(e)
        elif e["action"] in ("uid_changed", "user_created") and e.get("uid") == 0:
            out.append(e)
    return out


def evidence_gaps(inv: PrivilegedInventory, since_epoch: float) -> list[str]:
    """Plain statements of what the event evidence can NOT show, so "no
    recent changes" is never claimed on missing data."""
    notes: list[str] = []
    if inv.events_source != "journal":
        notes.append("Account-change events are unavailable (" + (inv.events_note or "no event log") +
                     "); recent additions can only be inferred from file modification times.")
        head = None
    else:
        head = inv.journal_head
        if head and head > since_epoch:
            notes.append(f"The target's logs only go back to {iso(head)}, so account changes before then are not visible.")
    for path in ("/etc/group", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d"):
        mt = inv.mtimes.get(path)
        if mt and mt >= since_epoch and (head is None or mt < head):
            notes.append(f"{path} was modified at {iso(mt)}, which no available log entry explains -- "
                         "verify that change by hand.")
    if not inv.sudoers_visible:
        notes.append("sudoers could not be read, so accounts granted sudo directly in sudoers (not via a group) "
                     "are not listed" + (f" ({inv.sudoers_note})" if inv.sudoers_note else "") + ".")
    return notes


def grant_in_effect(inv: PrivilegedInventory, event: dict[str, Any]) -> bool:
    """Whether THIS grant still holds: still in that group, or still UID 0."""
    if event.get("group"):
        members = inv.group_members.get(event["group"]) or inv.sudoers_groups.get(event["group"]) or []
        return event["user"] in members
    acct = inv.accounts.get(event["user"])
    return bool(acct) and acct.get("uid") == 0


def grant_status(inv: PrivilegedInventory, event: dict[str, Any]) -> str:
    """Where a privilege grant stands NOW -- an old grant to an account that
    was since removed or deleted must never read like a live threat."""
    if grant_in_effect(inv, event):
        return "still in effect"
    if event["user"] in inv.accounts:
        return "no longer in effect (the account is still privileged another way)"
    return "no longer in effect" if event["user"] in inv.local_users else "account no longer exists"


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def diff_accounts(previous: dict[str, Any] | None, current: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not previous:
        return {"previous_snapshot_at": None, "added": [], "removed": []}
    before = set((previous.get("accounts") or {}).keys())
    now = set(current)
    return {"previous_snapshot_at": previous.get("checked_at"),
            "added": sorted(now - before), "removed": sorted(before - now)}


def fetch(lookback_days: int = DEFAULT_LOOKBACK_DAYS, *, run_remote_script, journalctl_prefix: list[str],
          now: float | None = None):
    """Run the probe. Returns (inventory, since_epoch) or the failed SSHResult."""
    since = int((now if now is not None else time.time()) - max(1, lookback_days) * 86400)
    prefix = " ".join(shlex.quote(p) for p in journalctl_prefix)
    result = run_remote_script(build_script(since, prefix + " " if prefix else ""), shell="sh")
    if not result.ok:
        return result
    return parse_output(result.stdout), since
