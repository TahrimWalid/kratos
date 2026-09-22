"""
Whitelist action TEMPLATES + effective-spec construction (design doc §9 #3 /
Appendix A #2, "BUILD-NOW-CHEAPER"): the decided shape of the user-CRUD layer
is a picker + parameter form over vetted maintainer templates, NEVER a raw
action editor. A user's `/whitelist` entry only:

  - enables/disables a maintainer template for a target;
  - SCOPES which of a template's already-vetted enum values are actually in
    play for that target (a subset -- always safe, since it only narrows);
  - for slots the template explicitly marks EXTENSIBLE, adds a small number
    of extra values matching that slot's own declared candidate pattern
    (e.g. "extend the service allowlist" -- design doc §9 #3's own example).

A user can never introduce a new `argv_template`, change the fixed command
shape, or touch a slot the template doesn't mark extensible. Whatever a user
ends up with is always built by `build_effective_spec()` here and then
re-validated through `kratos.subagent.whitelist.validate_spec()` -- the same
schema, validators, and §5 hard exclusions apply identically to a
user-scoped instance as to a maintainer default (design doc §6). This
deletes the "user authored a subtly-bad-but-valid entry" failure class
entirely: there is no code path through which a user's input becomes part of
`argv_template`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from kratos.subagent import whitelist as W

# A conservative systemd-unit-name-shaped pattern for the one extensible slot
# in the current illustrative set (service.enable_now/disable_now's "unit").
# Deliberately excludes '@' instance-unit syntax and '.' service-type
# suffixes for now -- a bare unit basename is enough for the illustrative set
# and keeps the extension surface narrow.
_UNIT_NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"


@dataclass(frozen=True)
class ExtensibleSlotPolicy:
    """What a user may add to one of a template's enum slots, beyond the
    template's own base values. `pattern`/`max_length` bound any single
    added value (never free text -- always re-validated as a `token`-shaped
    value through the same slot-value validator); `max_extra_values` bounds
    how many a user may pile on."""

    pattern: str = _UNIT_NAME_PATTERN
    max_length: int = 64
    max_extra_values: int = 8


@dataclass(frozen=True)
class ActionTemplate:
    """A maintainer-authored template: `base` is the full ActionSpec with
    every value it COULD ever allow declared in its enum slots.
    `extensible_slots` names which of those enum slots (by name) a user may
    add EXTRA values to; every other slot may only be narrowed (a subset of
    `base`'s own declared values), never extended."""

    base: W.ActionSpec
    extensible_slots: dict[str, ExtensibleSlotPolicy] = field(default_factory=dict)

    def __post_init__(self) -> None:
        W.validate_spec(self.base)
        for slot_name in self.extensible_slots:
            slot = self.base.slots.get(slot_name)
            if slot is None or slot.kind != "enum":
                raise W.ActionSpecError(
                    f"{self.base.id}: extensible_slots names {slot_name!r}, which isn't an enum slot on this template"
                )


class TemplateInstanceError(ValueError):
    """A user's requested customization (selected/extra values) of a
    template is invalid -- never persisted."""


def _validate_extra_values(template: ActionTemplate, slot_name: str, extra: tuple[str, ...]) -> None:
    policy = template.extensible_slots.get(slot_name)
    if not extra:
        return
    if policy is None:
        raise TemplateInstanceError(
            f"{template.base.id}: slot {slot_name!r} is not extensible -- cannot add values to it, "
            "only select a subset of the template's own declared values"
        )
    if len(extra) > policy.max_extra_values:
        raise TemplateInstanceError(
            f"{template.base.id}: slot {slot_name!r} allows at most {policy.max_extra_values} extra "
            f"value(s), got {len(extra)}"
        )
    compiled = re.compile(policy.pattern)
    for v in extra:
        if not isinstance(v, str) or len(v) > policy.max_length or not compiled.fullmatch(v):
            raise TemplateInstanceError(
                f"{template.base.id}: extra value {v!r} for slot {slot_name!r} fails its pattern/length check"
            )
    # Re-use the SAME hard-exclusion machinery a maintainer entry goes through
    # (e.g. an extended unit named "sshd" must still be caught by the
    # disruptive-systemctl-verb exclusion) -- done by build_effective_spec's
    # final validate_spec() call, not duplicated here.


def _validate_selected_subset(template: ActionTemplate, slot_name: str, selected: tuple[str, ...]) -> None:
    base_slot = template.base.slots[slot_name]
    base_values = set(base_slot.values or ())
    unknown = set(selected) - base_values
    if unknown:
        raise TemplateInstanceError(
            f"{template.base.id}: slot {slot_name!r} selection includes values not in the template's own "
            f"allowlist: {sorted(unknown)} (use an extensible slot's extra_values to add new ones, if allowed)"
        )


def build_effective_spec(
    template: ActionTemplate,
    *,
    instance_id: str,
    selected_values: dict[str, tuple[str, ...]] | None = None,
    extra_values: dict[str, tuple[str, ...]] | None = None,
) -> W.ActionSpec:
    """Build the concrete, user-scoped ActionSpec for one entry: `argv_template`
    and every non-enum property are copied unchanged from `template.base`
    (a user never touches those); each enum slot's effective values are
    `selected_values` (a validated subset of the template's own values,
    defaulting to ALL of them if the slot isn't mentioned) unioned with
    `extra_values` (only for slots the template marked extensible).

    `reachability_adjacent` is recomputed from the EFFECTIVE (possibly
    narrowed) slot values rather than inherited from the template's own
    (necessarily conservative, since it spans everything the template could
    allow) declaration -- an instance that only ever selects "fail2ban" from
    a unit slot whose template also allows "ufw" is not, itself,
    reachability-adjacent. This can only lower the tier relative to the raw
    template, never raise it beyond what the template already declared for a
    truly touching instance.

    Always ends with `whitelist.validate_spec()` on the result -- the exact
    same schema/validators/§5 exclusions a maintainer default goes through.
    Raises TemplateInstanceError for a user-input problem (unknown value,
    slot not extensible, too many extras) or the underlying
    ActionSpecError/HardExclusionError if the resulting spec is unsafe even
    though each individual input passed its own check (e.g. an extended unit
    value that happens to be "sshd" on a disruptive verb)."""
    selected_values = selected_values or {}
    extra_values = extra_values or {}

    if not re.fullmatch(r"[a-z0-9_]+", instance_id):
        raise TemplateInstanceError(f"instance_id {instance_id!r} must match [a-z0-9_]+ (a store-generated entry id)")

    unknown_slots = (set(selected_values) | set(extra_values)) - set(template.base.slots)
    if unknown_slots:
        raise TemplateInstanceError(f"{template.base.id}: unknown slot(s) referenced: {sorted(unknown_slots)}")

    effective_slots: dict[str, W.Slot] = {}
    for name, base_slot in template.base.slots.items():
        if base_slot.kind != "enum":
            effective_slots[name] = base_slot  # non-enum slots aren't user-customizable at all
            continue
        selected = tuple(selected_values.get(name, base_slot.values or ()))
        extra = tuple(extra_values.get(name, ()))
        _validate_selected_subset(template, name, selected)
        _validate_extra_values(template, name, extra)
        effective_values = tuple(dict.fromkeys((*selected, *extra)))  # de-dup, preserve order
        if not effective_values:
            raise TemplateInstanceError(f"{template.base.id}: slot {name!r} would have zero allowed values")
        effective_slots[name] = W.Slot(
            kind="enum", values=effective_values,
            ip_deny_private=base_slot.ip_deny_private,
            min_value=base_slot.min_value, max_value=base_slot.max_value,
            pattern=base_slot.pattern, max_length=base_slot.max_length,
        )

    # Recomputed from THIS instance's effective (possibly narrowed) enum
    # values, not inherited from the template -- see the docstring above.
    effective_reachability_adjacent = W.touches_firewall_related_unit(effective_slots)

    effective = W.ActionSpec(
        id=f"{template.base.id}.{instance_id}",
        layer="user",
        argv_template=template.base.argv_template,
        slots=effective_slots,
        effect=template.base.effect,
        reversibility=template.base.reversibility,
        blast_radius=template.base.blast_radius,
        reversible=template.base.reversible,
        disrupts_running_service=template.base.disrupts_running_service,
        reachability_adjacent=effective_reachability_adjacent,
        inverse_id=None,  # a user instance's inverse is a separate user instance, not tracked structurally here
        source_recommendation=template.base.source_recommendation,
        requires_typed_execute=True,
    )
    W.validate_spec(effective)
    return effective


_BUILTIN_TEMPLATES: tuple[ActionTemplate, ...] = tuple(
    ActionTemplate(
        base=spec,
        extensible_slots=(
            {"unit": ExtensibleSlotPolicy()} if "unit" in spec.slots else {}
        ),
    )
    for spec in W.list_builtin_action_specs()
)


def list_builtin_templates() -> tuple[ActionTemplate, ...]:
    """The maintainer-shipped templates a user's `/whitelist` CRUD picks
    from and parameterizes. Ships as CODE (design doc §9 #4 -- no editable
    data file, no hash-pin; needs code-modify privilege to alter, which is
    the realistic threat this integrity model is scoped to)."""
    return _BUILTIN_TEMPLATES


def get_template(template_id: str) -> ActionTemplate | None:
    return next((t for t in _BUILTIN_TEMPLATES if t.base.id == template_id), None)
