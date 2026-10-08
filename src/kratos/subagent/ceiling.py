"""
The execution CEILING -- the allowlist the sub-agent ships as code and
enforces on its own, regardless of what core sends it
(docs/subagent_execution_track.md §1; review findings F1/F2/F3).

Before this module the agent's only copy of "what may run" was whatever core
pushed, re-checked against a denylist. A compromised core (or a leaked pairing
token) could push any command that avoided the banned names. The trust flow is
now inverted:

  - The ceiling below is a closed set of command SHAPES: an exact binary, a
    fixed number of arguments, and at each position either an exact literal or
    a typed variable (the same four closed slot kinds `whitelist.Slot` uses),
    optionally with values that are never allowed (`deny`/`deny_networks`).
  - Everything core sends -- maintainer defaults and user-authored entries
    alike -- must be provably narrower than some shape (`check_spec`). An
    entry that isn't is refused and reported back, never applied.
  - Independently of the pushed entry, the FINAL argv the agent is about to
    run is matched against the ceiling again (`match_argv`), and the binary is
    resolved to an absolute path inside a fixed set of root-owned directories
    (`resolve_executable`). Even a bug in the subset check cannot widen what
    actually executes past this.

The ceiling can only be changed by changing this file on the target -- which
needs code-modify privilege there, the same integrity model the rest of the
agent bundle already relies on. A user authoring their own entries in the
Kratos UI works WITHIN the ceiling; widening the ceiling itself is a
maintainer code change that goes through review.

Stdlib-only -- deployed as a sibling of agent.py onto the target, same
constraint as protocol.py/signing.py/whitelist.py.
"""
from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
from dataclasses import dataclass
from typing import Any, Union

try:  # package-relative when imported as kratos.subagent.ceiling or subagent.ceiling
    from . import whitelist as wl
except ImportError:  # pragma: no cover -- `python3 subagent/agent.py` run directly
    import whitelist as wl  # type: ignore[no-redef]


class CeilingError(ValueError):
    """An action or a concrete argv is outside what this agent's ceiling
    permits. Always a hard refusal."""


# Root-owned system binary directories, searched in this order. A binary is
# only ever executed by an absolute path inside one of these -- never through
# $PATH, which the agent's own environment could have altered.
TRUSTED_BIN_DIRS: tuple[str, ...] = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")

# The fixed environment every dispatched command runs with.
EXEC_ENV: dict[str, str] = {"PATH": ":".join(TRUSTED_BIN_DIRS), "LANG": "C", "LC_ALL": "C"}

_INT_TOKEN_RE = re.compile(r"^-?[0-9]{1,18}$")


@dataclass(frozen=True)
class Lit:
    """An argument position that must be exactly this string."""

    value: str


@dataclass(frozen=True)
class Var:
    """An argument position filled by a value of one closed kind.

    `deny` lists values that are never allowed here (compared
    case-insensitively). `deny_networks` lists CIDRs an `ip` value may never
    fall in. `reachability_values` marks values whose presence makes an action
    able to affect network reachability -- an entry that can put one of them
    (or any unbounded token) at this position is floored to
    `reachability_adjacent=True` when its sensitivity tier is computed."""

    slot: wl.Slot
    deny: frozenset[str] = frozenset()
    deny_networks: tuple[str, ...] = ()
    reachability_values: frozenset[str] = frozenset()


Arg = Union[Lit, Var]  # typing.Union, not `|`: the bundle must import on python3.9 (RHEL 9)


@dataclass(frozen=True)
class Shape:
    """One permitted command shape. The risk flags are a FLOOR: an entry
    matching this shape is treated as at least this risky, whatever the entry
    itself declares."""

    id: str
    binary: str
    args: tuple[Arg, ...]
    description: str
    reversible: bool
    disrupts_running_service: bool
    reachability_adjacent: bool = False
    # True for an exact command the target's own admin allowlisted in
    # LOCAL_ALLOW_FILE (see load_local_commands) rather than shipped code.
    local: bool = False


@dataclass(frozen=True)
class Ceiling:
    version: int
    shapes: tuple[Shape, ...]

    def fingerprint(self) -> str:
        """Stable hash of the whole ceiling -- sent to core in `hello` so core
        can tell when an agent runs a different ceiling than its own copy."""
        return hashlib.sha256(json.dumps(_ceiling_to_json(self), sort_keys=True).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# The shipped ceiling. Changing this is a reviewed maintainer change.
# ---------------------------------------------------------------------------
_JAIL_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,31}$"

# Units whose loss would cut the operator (or Kratos) off from the box, blind
# its logging/audit trail, or break its clock -- never disabled by Kratos.
_NEVER_DISABLE_UNITS = frozenset({
    "ssh", "sshd", "tailscaled", "kratos-subagent",
    "networking", "network", "systemd-networkd", "systemd-resolved", "netplan", "wpa_supplicant",
    "dbus", "dbus-broker", "polkit", "systemd-logind", "getty",
    "systemd-journald", "rsyslog", "syslog-ng", "auditd",
    "chrony", "chronyd", "ntp", "ntpd", "systemd-timesyncd",
    "cloud-init",
})

_FIREWALL_UNITS = frozenset({"ufw", "iptables", "ip6tables", "nft", "nftables", "firewalld"})

# systemctl may only touch units on these vetted lists -- never "any unit": an
# open unit slot would let a compromised core start systemd-reboot,
# systemd-poweroff, debug-shell (a root shell on tty9), rescue/emergency, or
# stop anything not explicitly denied. A site-specific service belongs in the
# target's LOCAL_ALLOW_FILE instead, where the target's own admin decides.
#   enable --now: security controls worth turning ON.
ENABLE_UNITS: tuple[str, ...] = (
    "fail2ban", "ufw", "firewalld", "nftables", "auditd", "apparmor", "unattended-upgrades",
    "sshguard", "crowdsec", "clamav-daemon", "clamav-freshclam", "rsyslog", "chrony", "systemd-timesyncd",
)
#   disable --now: the firewall/ban controls above (their reversibility pair),
#   plus legacy/exposure services commonly found enabled by accident.
DISABLE_UNITS: tuple[str, ...] = (
    "fail2ban", "ufw", "firewalld", "nftables",
    "xinetd", "inetutils-inetd", "openbsd-inetd", "vsftpd", "proftpd", "pure-ftpd", "tftpd-hpa",
    "rpcbind", "avahi-daemon", "cups", "cups-browsed", "snmpd", "nfs-server", "smbd", "nmbd", "rsync",
)

# Never ban a tailnet address: that is how core (and usually the operator)
# reaches the box.
_TAILNET_NETWORKS = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")

_BANNABLE_IP = Var(wl.Slot(kind="ip", ip_deny_private=True), deny_networks=_TAILNET_NETWORKS)
_JAIL = Var(wl.Slot(kind="token", pattern=_JAIL_PATTERN, max_length=32))

DEFAULT_CEILING = Ceiling(
    version=1,
    shapes=(
        Shape(
            id="fail2ban.banip",
            binary="fail2ban-client",
            args=(Lit("set"), _JAIL, Lit("banip"), _BANNABLE_IP),
            description="Ban one public IP address in one fail2ban jail.",
            reversible=True,
            disrupts_running_service=False,
        ),
        Shape(
            id="fail2ban.unbanip",
            binary="fail2ban-client",
            args=(Lit("set"), _JAIL, Lit("unbanip"), Var(wl.Slot(kind="ip"))),
            description="Unban one IP address in one fail2ban jail.",
            reversible=True,
            disrupts_running_service=False,
        ),
        Shape(
            id="systemctl.enable_now",
            binary="systemctl",
            # No deny list here: _NEVER_DISABLE_UNITS guards against turning things
            # OFF, and it used to make rsyslog/chrony/auditd/systemd-timesyncd
            # impossible to turn ON (security review 2026-10-05, finding 6).
            args=(Lit("enable"), Lit("--now"),
                  Var(wl.Slot(kind="enum", values=ENABLE_UNITS), reachability_values=_FIREWALL_UNITS)),
            description="Enable and start one security service from a vetted list.",
            reversible=True,
            disrupts_running_service=False,
        ),
        Shape(
            id="systemctl.disable_now",
            binary="systemctl",
            args=(Lit("disable"), Lit("--now"),
                  Var(wl.Slot(kind="enum", values=DISABLE_UNITS), deny=_NEVER_DISABLE_UNITS,
                      reachability_values=_FIREWALL_UNITS)),
            description="Stop and disable one service from a vetted list (never an access/logging/clock-critical one).",
            reversible=True,
            disrupts_running_service=True,
        ),
    ),
)


# ---------------------------------------------------------------------------
# Target-local exact commands. The target's own admin may allow specific,
# complete commands (e.g. `adduser alice`) by listing them, one per line, in
# LOCAL_ALLOW_FILE. Kratos can then run exactly those lines and nothing
# resembling them. Core can never add to this file -- it lives on the target
# and must be owned by root (or the agent's own user) and writable by no one
# else, the same rule sudo applies to /etc/sudoers.
# ---------------------------------------------------------------------------
LOCAL_ALLOW_FILE = "/etc/kratos-subagent/allowed-commands"
MAX_LOCAL_COMMANDS = 200
_MAX_LOCAL_LINE = 512
_SHELL_META = (";", "|", "&", "<", ">", "`", "$(", "${", "\n")

# A local line may name any program in the trusted dirs EXCEPT one that would
# turn the line back into a string to re-parse (a shell or interpreter, under
# any versioned name -- wl.is_shell_or_interpreter), or whose purpose is to run
# the REST of the line as another command: that is a wrapper, not an exact
# command, and the command it runs is what the admin should list.
_LOCAL_BANNED_BINARIES = frozenset({
    "sudo", "su", "doas", "pkexec", "runuser", "sg", "newgrp",
    "nohup", "setsid", "timeout", "nice", "ionice", "chrt", "taskset", "stdbuf", "time", "command",
    "chroot", "unshare", "nsenter", "systemd-run", "flock", "parallel", "cgexec", "firejail",
    "start-stop-daemon", "daemonize", "busybox", "toybox", "script", "watch", "strace", "ltrace", "gdb",
})


def runs_other_commands(program: str) -> bool:
    base = program.rpartition("/")[2].lower()
    return base in _LOCAL_BANNED_BINARIES or wl.is_shell_or_interpreter(base)


def normalize_command(tokens: list[str]) -> list[str]:
    """Drop a leading `sudo`: the agent itself runs as the service user (root
    for a normal install), so `sudo` would only add a second, password-less
    privilege hop."""
    # Only a bare `sudo` prefix: with options (`sudo -u bob ...`) sudo is doing
    # something itself, so the line stays as written and is refused as sudo.
    if len(tokens) > 1 and tokens[0] == "sudo" and not tokens[1].startswith("-"):
        return tokens[1:]
    return tokens


def parse_command_line(line: str) -> list[str]:
    """Split one exact command the way a POSIX shell would split it (quotes
    respected, no expansion). Raises CeilingError for anything that isn't a
    plain, complete command."""
    if len(line) > _MAX_LOCAL_LINE:
        raise CeilingError(f"line is longer than {_MAX_LOCAL_LINE} characters")
    if any(ch in line for ch in ("\x00", "\n", "\r")):
        raise CeilingError("line contains a control character")
    try:
        tokens = normalize_command(shlex.split(line, comments=False, posix=True))
    except ValueError as e:
        raise CeilingError(f"can't parse: {e}") from e
    if not tokens:
        raise CeilingError("empty command")
    # Nothing here ever reaches a shell (argv, shell=False), so these would
    # just be odd literal arguments -- but a line that LOOKS like a pipeline
    # or a command list almost certainly isn't what the admin meant to allow.
    for t in tokens:
        bad = next((m for m in _SHELL_META if m in t), None)
        if bad:
            raise CeilingError(f"shell syntax ({bad!r}) is not allowed -- list one plain command per line")
    binary = tokens[0]
    base = binary.rpartition("/")[2]
    if not base or base.startswith("-"):
        raise CeilingError(f"{binary!r} is not a program name")
    if binary.startswith("/"):
        if binary.rpartition("/")[0] not in TRUSTED_BIN_DIRS:
            raise CeilingError(f"{binary!r} is not inside a trusted system directory {TRUSTED_BIN_DIRS}")
    elif "/" in binary:
        raise CeilingError(f"{binary!r}: use a bare program name or an absolute path")
    if runs_other_commands(base):
        raise CeilingError(f"{base!r} runs other commands -- list the actual command instead")
    return tokens


def local_command_shape(tokens: list[str]) -> Shape:
    digest = hashlib.sha256("\x00".join(tokens).encode()).hexdigest()[:12]
    base = tokens[0].rpartition("/")[2]
    return Shape(
        id=f"local.{digest}",
        binary=base,
        args=tuple(Lit(t) for t in tokens[1:]),
        description=shlex.join(tokens),
        # Kratos can't know what an arbitrary admin-chosen command does, so
        # it is treated as the riskiest tier until a human says otherwise.
        reversible=False,
        disrupts_running_service=True,
        reachability_adjacent=base.lower() in _FIREWALL_UNITS | {"ip", "ifdown", "ifup", "firewall-cmd"},
        local=True,
    )


def _file_is_trusted(st: os.stat_result, allowed_owners: tuple[int, ...]) -> str | None:
    if st.st_uid not in allowed_owners:
        return f"owned by uid {st.st_uid}, must be owned by root or the agent's own user"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "writable by group/others -- chmod go-w it"
    return None


def load_local_commands(path: str = LOCAL_ALLOW_FILE, allowed_owners: tuple[int, ...] | None = None
                        ) -> tuple[list[Shape], list[str]]:
    """Read the target's local exact-command allowlist. Returns (shapes,
    problems). A missing file is simply no local commands. An untrusted file
    (wrong owner or group/world-writable, or the same for its directory) is
    ignored ENTIRELY and reported -- never partially trusted."""
    if allowed_owners is None:
        allowed_owners = tuple({0, os.geteuid()})
    try:
        dir_st = os.stat(os.path.dirname(path) or "/")
        st = os.lstat(path)
    except FileNotFoundError:
        return [], []
    except OSError as e:
        return [], [f"{path}: unreadable ({e})"]
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return [], [f"{path}: must be a regular file, not a symlink -- ignored"]
    for what, s_ in (("file", st), ("directory", dir_st)):
        problem = _file_is_trusted(s_, allowed_owners)
        if problem:
            return [], [f"{path}: {what} {problem} -- ignored"]
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read(MAX_LOCAL_COMMANDS * (_MAX_LOCAL_LINE + 2))
    except (OSError, UnicodeDecodeError) as e:
        return [], [f"{path}: unreadable ({e})"]
    shapes, problems, seen = [], [], set()
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = parse_command_line(line)
        except CeilingError as e:
            problems.append(f"line {n}: {e} -- skipped")
            continue
        shape = local_command_shape(tokens)
        if shape.id in seen:
            continue
        if len(shapes) >= MAX_LOCAL_COMMANDS:
            problems.append(f"more than {MAX_LOCAL_COMMANDS} commands -- the rest are ignored")
            break
        seen.add(shape.id)
        shapes.append(shape)
    return shapes, problems


def with_local_commands(base: Ceiling, commands: list[str] | list[Shape]) -> Ceiling:
    """`base` plus exact local commands (Shapes, or command lines as reported
    by an agent). Core uses the line form to mirror what a target reported."""
    shapes: list[Shape] = []
    for c in commands:
        if isinstance(c, Shape):
            shapes.append(c)
            continue
        try:
            shapes.append(local_command_shape(parse_command_line(c)))
        except CeilingError:
            continue
    return Ceiling(version=base.version, shapes=(*base.shapes, *shapes))


# ---------------------------------------------------------------------------
# Runtime: the concrete argv the agent is about to run.
# ---------------------------------------------------------------------------
def _binary_matches(shape: Shape, argv0: str) -> bool:
    if argv0 == shape.binary:
        return True
    if argv0.startswith("/"):
        head, _, base = argv0.rpartition("/")
        return base == shape.binary and head in TRUSTED_BIN_DIRS
    return False


def _denied(var: Var, value: str) -> bool:
    return value.lower() in {d.lower() for d in var.deny}


def _value_ok(var: Var, value: str) -> bool:
    """Whether one concrete argv token is acceptable at a Var position."""
    if not isinstance(value, str) or _denied(var, value):
        return False
    slot = var.slot
    try:
        if slot.kind == "int_range":
            if not _INT_TOKEN_RE.fullmatch(value):
                return False
            wl.validate_slot_value("ceiling", "arg", slot, int(value))
        else:
            wl.validate_slot_value("ceiling", "arg", slot, value)
    except wl.SlotValueError:
        return False
    if slot.kind == "ip" and var.deny_networks:
        addr = ipaddress.ip_address(value)
        if any(addr in ipaddress.ip_network(n) for n in var.deny_networks):
            return False
    return True


def matching_shapes(argv: list[str], ceiling: Ceiling = DEFAULT_CEILING) -> list[Shape]:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return []
    out = []
    for shape in ceiling.shapes:
        if len(argv) != 1 + len(shape.args) or not _binary_matches(shape, argv[0]):
            continue
        if all(
            (tok == arg.value) if isinstance(arg, Lit) else _value_ok(arg, tok)
            for tok, arg in zip(argv[1:], shape.args)
        ):
            out.append(shape)
    return out


def match_argv(argv: list[str], ceiling: Ceiling = DEFAULT_CEILING) -> Shape:
    """The final gate before execution: the exact argv must fit a shape."""
    shapes = matching_shapes(argv, ceiling)
    if not shapes:
        raise CeilingError(f"command is outside this agent's execution ceiling: {argv!r}")
    return shapes[0]


def resolve_executable(argv0: str, bin_dirs: tuple[str, ...] = TRUSTED_BIN_DIRS) -> str | None:
    """Absolute path of the binary inside a trusted directory, or None if it
    isn't installed there. Never consults $PATH."""
    if argv0.startswith("/"):
        head, _, _ = argv0.rpartition("/")
        return argv0 if head in bin_dirs and os.path.isfile(argv0) and os.access(argv0, os.X_OK) else None
    if "/" in argv0:
        return None
    for d in bin_dirs:
        candidate = f"{d}/{argv0}"
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Static: is a pushed/authored ActionSpec provably inside the ceiling?
# ---------------------------------------------------------------------------
def _slot_within(entry: wl.Slot, var: Var) -> str | None:
    """None if every value `entry` can ever accept is also acceptable to
    `var`; otherwise the reason it isn't."""
    ceil = var.slot
    if entry.kind == "enum":
        bad = [v for v in (entry.values or ()) if not _value_ok(var, v)]
        return f"value(s) {bad} not allowed here" if bad else None
    if entry.kind != ceil.kind:
        return f"a {entry.kind!r} slot can't fill a {ceil.kind!r} position (use a list of allowed values instead)"
    if entry.kind == "ip":
        if ceil.ip_deny_private and not entry.ip_deny_private:
            return "this position only accepts public addresses -- the slot must reject private ones too"
        return None  # deny_networks is enforced on the concrete value at run time
    if entry.kind == "int_range":
        if entry.min_value < ceil.min_value or entry.max_value > ceil.max_value:
            return f"range [{entry.min_value}, {entry.max_value}] exceeds the allowed [{ceil.min_value}, {ceil.max_value}]"
        return None
    if entry.kind == "token":
        # Regex containment is undecidable in general, so a token slot must use
        # exactly the ceiling's own pattern (deny lists still apply at run time).
        if entry.pattern != ceil.pattern:
            return "a free-form value here must use the ceiling's own pattern"
        if entry.max_length > ceil.max_length:
            return f"max length {entry.max_length} exceeds the allowed {ceil.max_length}"
        return None
    return f"unknown slot kind {entry.kind!r}"  # pragma: no cover -- validate_spec rejects this first


def _spec_within_shape(spec: wl.ActionSpec, shape: Shape) -> str | None:
    template = spec.argv_template
    if len(template) != 1 + len(shape.args):
        return "wrong number of arguments"
    if not _binary_matches(shape, template[0]):
        return "different binary"
    for pos, (tok, arg) in enumerate(zip(template[1:], shape.args), start=1):
        m = wl._PLACEHOLDER_RE.fullmatch(tok)
        if m is None:
            if isinstance(arg, Lit):
                if tok != arg.value:
                    return f"argument {pos} must be {arg.value!r}"
            elif not _value_ok(arg, tok):
                return f"argument {pos} value {tok!r} is not allowed"
            continue
        slot = spec.slots[m.group(1)]
        if isinstance(arg, Lit):
            if not (slot.kind == "enum" and slot.values == (arg.value,)):
                return f"argument {pos} must be exactly {arg.value!r}"
            continue
        reason = _slot_within(slot, arg)
        if reason:
            return f"argument {pos} ({{{m.group(1)}}}): {reason}"
    return None


def check_spec(spec: wl.ActionSpec, ceiling: Ceiling = DEFAULT_CEILING) -> list[Shape]:
    """Every shape `spec` fits inside (usually one). Raises CeilingError with
    the closest shape's reason if it fits none. Run by the agent on every
    pushed action and by core on every stored entry.

    The maintainer denylist in `whitelist.validate_spec` still applies to
    anything matched by a shipped shape; it is skipped only for an exact
    command the target's admin allowlisted locally (their explicit choice on
    their own box)."""
    # A token slot can only ever fit a ceiling position with exactly the same
    # pattern (_slot_within), so refuse any other pattern BEFORE validate_spec
    # compiles it and runs it against the adversarial probes: a pattern from
    # core is never compiled or run (security review 2026-10-05, finding 4).
    known = {a.slot.pattern for sh in ceiling.shapes for a in sh.args
             if isinstance(a, Var) and a.slot.kind == "token"} | {wl.Slot(kind="token").pattern}
    for name, slot in (spec.slots or {}).items():
        if getattr(slot, "kind", None) == "token" and slot.pattern not in known:
            raise CeilingError(f"{spec.id}: slot {name!r} uses a free-form pattern this agent's ceiling doesn't have")
    wl.validate_spec(spec, hard_exclusions=False)
    fits, reasons = [], []
    for shape in ceiling.shapes:
        reason = _spec_within_shape(spec, shape)
        if reason is None:
            fits.append(shape)
        elif _binary_matches(shape, spec.argv_template[0]):
            reasons.append(f"{shape.id}: {reason}")
    if not fits:
        binary = spec.argv_template[0]
        if not reasons:
            raise CeilingError(f"{spec.id}: {binary!r} is not a program this agent's execution ceiling allows")
        raise CeilingError(f"{spec.id}: doesn't fit any allowed form of {binary!r} -- " + "; ".join(reasons))
    if not any(s.local for s in fits):
        wl.validate_spec(spec)  # shipped shapes keep the maintainer denylist as a second layer
    return fits


def uses_local_command(spec: wl.ActionSpec, ceiling: Ceiling = DEFAULT_CEILING) -> bool:
    """True if `spec` is allowed only because of a target-local exact
    command -- callers then render it without the maintainer denylist."""
    return any(s.local for s in check_spec(spec, ceiling))


def _entry_values_at(spec: wl.ActionSpec, tok: str) -> tuple[str, ...] | None:
    """The finite set of values a template token can take, or None if unbounded."""
    m = wl._PLACEHOLDER_RE.fullmatch(tok)
    if m is None:
        return (tok,)
    slot = spec.slots[m.group(1)]
    return tuple(slot.values or ()) if slot.kind == "enum" else None


def floored_spec(spec: wl.ActionSpec, shapes: list[Shape]) -> wl.ActionSpec:
    """`spec` with its risk flags raised to the floor of every shape it fits,
    so a user entry can never be tiered below what the ceiling says the
    command can do."""
    reachability = spec.reachability_adjacent
    for shape in shapes:
        reachability = reachability or shape.reachability_adjacent
        for tok, arg in zip(spec.argv_template[1:], shape.args):
            if isinstance(arg, Var) and arg.reachability_values:
                values = _entry_values_at(spec, tok)
                if values is None or {v.lower() for v in values} & arg.reachability_values:
                    reachability = True
    return dataclasses.replace(
        spec,
        reversible=spec.reversible and all(s.reversible for s in shapes),
        disrupts_running_service=spec.disrupts_running_service or any(s.disrupts_running_service for s in shapes),
        reachability_adjacent=reachability,
    )


def tier_for(spec: wl.ActionSpec, ceiling: Ceiling = DEFAULT_CEILING) -> wl.Sensitivity:
    """Sensitivity tier of `spec` after the ceiling's floor is applied."""
    return wl.compute_sensitivity_tier(floored_spec(spec, check_spec(spec, ceiling)))


# ---------------------------------------------------------------------------
# Serialization (fingerprint + display only -- a ceiling is never received
# over the wire).
# ---------------------------------------------------------------------------
def _arg_to_json(arg: Arg) -> dict[str, Any]:
    if isinstance(arg, Lit):
        return {"lit": arg.value}
    s = arg.slot
    return {
        "kind": s.kind, "values": list(s.values) if s.values else None, "ip_deny_private": s.ip_deny_private,
        "min": s.min_value, "max": s.max_value, "pattern": s.pattern, "max_length": s.max_length,
        "deny": sorted(arg.deny), "deny_networks": list(arg.deny_networks),
        "reachability_values": sorted(arg.reachability_values),
    }


def _ceiling_to_json(ceiling: Ceiling) -> dict[str, Any]:
    return {
        "version": ceiling.version,
        "shapes": [
            {"id": s.id, "binary": s.binary, "args": [_arg_to_json(a) for a in s.args],
             "reversible": s.reversible, "disrupts": s.disrupts_running_service, "reach": s.reachability_adjacent,
             "local": s.local}
            for s in ceiling.shapes
        ],
    }
