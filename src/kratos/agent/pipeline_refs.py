"""A2 Piece C -- bounded step-output threading for Tier-2 pipelines (SOAR chaining).

SECURITY BOUNDARY (the same discipline as ``pipeline_when.py``): a step arg may
reference an EARLIER step's OUTPUT VALUE via a STRUCTURED object
``{from, field}`` -- NEVER a string template, an expression, attribute/subscript
access, or ``eval()``. The referenced field must be in a fixed WHITELIST; its
value is extracted from the producer step's result, type-checked, and passed as a
real typed arg through ``execute_tool_call`` -- it is never concatenated into a
command string. So threading cannot smuggle in code execution, and an
attacker-controlled value in a finding can only ever land in a typed arg the
consuming tool already validates (identical boundary to A6.2 / the ``when`` guard).

The reference form (in a step's ``args``):

    args = { ip = { from = "correlate", field = "top_source_ip" } }

``from`` names a PRIOR step by its ``label`` (unique) or a 1-based index;
``field`` is a whitelisted extractable field of that step's tool; optional
``select`` (``"first"``/``"all"``) resolves a list field into a scalar/list arg.

Whitelist grounding: the shipped fields read ONLY the tool's own result dict (no
file reads, no evidence-text parsing), so extraction is robust. Extend the map as
tools grow; anything not in it is rejected at SAVE time. The resolver here is
imported by ``pipeline.py`` (run time) and ``presets.py`` (save-time validation),
and stays dependency-light (no engine/UI imports) so both headless and TUI paths
use it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

Extractor = Callable[[dict[str, Any]], Any]
Validator = Callable[[Any], bool]

_SELECT_MODES = {"first", "all"}


class RefError(ValueError):
    """A step-output reference is malformed or not in the whitelist. Message is
    user-facing (shown at save/validate time)."""


@dataclass(frozen=True)
class FieldSpec:
    """One whitelisted extractable field: its declared TYPE (``str`` / ``int`` /
    ``list[str]`` / ``list[int]``), a plain-language label for UIs, an extractor
    that reads the producer tool's result dict, and an optional run-time value
    validator (e.g. an IP must parse)."""

    type: str
    label: str
    extract: Extractor
    validate: Optional[Validator] = None


# --------------------------------------------------------------------------- #
# Extractors -- pure reads of a tool's own result dict (no file I/O, no text
# parsing), so a field either exists cleanly or resolves to None (-> fail-safe
# skip at run time).
# --------------------------------------------------------------------------- #
def _correlate_top_source_ip(result: dict[str, Any]) -> Optional[str]:
    for f in result.get("findings") or []:
        ips = f.get("source_ips") or []
        if ips:
            return str(ips[0])
    return None


def _correlate_finding_ids(result: dict[str, Any]) -> list[str]:
    return [str(f.get("id")) for f in (result.get("findings") or []) if f.get("id")]


def _correlate_finding_count(result: dict[str, Any]) -> Optional[int]:
    c = result.get("count")
    if isinstance(c, int):
        return c
    findings = result.get("findings")
    return len(findings) if isinstance(findings, list) else None


def _correlate_worst_severity(result: dict[str, Any]) -> Optional[str]:
    # generate_findings sorts findings by severity descending, so [0] is worst.
    findings = result.get("findings") or []
    return str(findings[0].get("severity")) if findings and findings[0].get("severity") else None


def _int_field(key: str) -> Extractor:
    def _x(result: dict[str, Any]) -> Optional[int]:
        v = result.get(key)
        return v if isinstance(v, int) else None
    return _x


def _valid_ip(value: Any) -> bool:
    # Reuse the TUI's IP/hostname validator (pure stdlib, no Textual import).
    from kratos.tui_mk2.target_input import validate_targets

    _cleaned, err = validate_targets([str(value)])
    return err is None


# The whitelist: producer TOOL name -> {field name: FieldSpec}. Ship what the
# grounding pair needs (correlate_findings.top_source_ip -> check_ip_reputation.ip)
# plus a few real siblings; every entry reads the result dict directly.
FIELD_WHITELIST: dict[str, dict[str, FieldSpec]] = {
    "correlate_findings": {
        "top_source_ip": FieldSpec("str", "the top source IP", _correlate_top_source_ip, _valid_ip),
        "finding_ids": FieldSpec("list[str]", "the finding IDs", _correlate_finding_ids),
        "finding_count": FieldSpec("int", "the number of findings", _correlate_finding_count),
        "worst_severity": FieldSpec("str", "the highest severity", _correlate_worst_severity),
    },
    "run_nmap_scan": {
        "open_port_count": FieldSpec("int", "the open-port count", _int_field("open_ports_total")),
        "host_count": FieldSpec("int", "the number of hosts up", _int_field("host_count")),
    },
}


# --------------------------------------------------------------------------- #
# Reference shape helpers
# --------------------------------------------------------------------------- #
def is_reference(value: Any) -> bool:
    """True if a step-arg value is a step-output reference (a table carrying both
    ``from`` and ``field``). Tool args are otherwise scalars/lists, so this shape
    is unambiguous."""
    return isinstance(value, dict) and "from" in value and "field" in value


def normalize_reference(value: dict[str, Any]) -> dict[str, Any]:
    """Return a clean ``{from, field, select?}`` dict, raising RefError on a
    malformed shape (non-string from/field, or an unknown select mode)."""
    frm = value.get("from")
    field = value.get("field")
    if not isinstance(frm, str) or not frm.strip():
        raise RefError("a reference needs a `from` (an earlier step's label or number)")
    if not isinstance(field, str) or not field.strip():
        raise RefError("a reference needs a `field` (which value to take from that step)")
    ref: dict[str, Any] = {"from": frm.strip(), "field": field.strip()}
    select = value.get("select")
    if select is not None:
        if select not in _SELECT_MODES:
            raise RefError(f"reference `select` must be one of {sorted(_SELECT_MODES)}")
        ref["select"] = select
    return ref


def _arg_is_list(type_str: str) -> bool:
    return type_str.strip().lower().startswith("list")


def _arg_base_type(type_str: str) -> str:
    """The scalar base of a param type: 'str|null' -> 'str', 'list[int]' -> 'int'."""
    t = type_str.strip().lower().split("|")[0].strip()
    if t.startswith("list[") and t.endswith("]"):
        return t[5:-1]
    if t == "list":
        return "any"
    return t


def _field_base_type(field_type: str) -> str:
    if field_type.startswith("list[") and field_type.endswith("]"):
        return field_type[5:-1]
    return field_type


def describe_reference(ref: dict[str, Any]) -> str:
    """Plain-language rendering of a reference for /preset show + previews, e.g.
    'the top source IP from the "correlate" step (first match)'. Never shows raw
    {from=...} syntax to a reader."""
    frm = ref.get("from", "?")
    field = ref.get("field", "?")
    label = field
    for fields in FIELD_WHITELIST.values():
        if field in fields:
            label = fields[field].label
            break
    suffix = ""
    if ref.get("select") == "first":
        suffix = " (first match)"
    elif ref.get("select") == "all":
        suffix = " (all)"
    return f"{label} from the '{frm}' step{suffix}"


# --------------------------------------------------------------------------- #
# Save-time validation (bounded, registry-independent where possible)
# --------------------------------------------------------------------------- #
def validate_reference(
    ref: dict[str, Any],
    *,
    prior_steps: list[tuple[Optional[str], str]],
    consumer_tool: str,
    consumer_arg: str,
    registry: Optional[dict[str, Any]] = None,
) -> None:
    """Raise RefError if a (already-normalized) reference is invalid. Checks that
    do NOT need the registry (forward-only resolution, unique-label, field in the
    whitelist) always run; the consumer-arg TYPE / list->scalar-arity check runs
    only when ``registry`` is provided (save time) and the consumer tool+arg are
    known. ``prior_steps`` is the ordered [(label, tool)] of steps BEFORE this
    one (forward-only: the context threads forward)."""
    frm, field = ref["from"], ref["field"]

    # Resolve the producer among PRIOR steps (forward-only).
    producer_tool: Optional[str] = None
    if frm.isdigit():
        idx = int(frm) - 1
        if not (0 <= idx < len(prior_steps)):
            raise RefError(
                f"reference `from = {frm}` must be an EARLIER step's number (1..{len(prior_steps)})")
        producer_tool = prior_steps[idx][1]
    else:
        matches = [tool for (lbl, tool) in prior_steps if lbl == frm]
        if not matches:
            raise RefError(
                f"reference `from = '{frm}'` doesn't match any EARLIER step's label "
                "(a step can only use a result from a step before it)")
        if len(matches) > 1:
            raise RefError(f"reference `from = '{frm}'` is ambiguous — two earlier steps share that label")
        producer_tool = matches[0]

    fields = FIELD_WHITELIST.get(producer_tool)
    if not fields:
        raise RefError(
            f"step '{frm}' ({producer_tool}) doesn't expose any threadable outputs yet")
    spec = fields.get(field)
    if spec is None:
        raise RefError(
            f"'{field}' isn't a threadable output of '{frm}' ({producer_tool}). "
            f"Available: {', '.join(sorted(fields))}")

    field_is_list = spec.type.startswith("list")
    select = ref.get("select")
    if select == "all" and not field_is_list:
        raise RefError(f"`select = 'all'` only applies to a list field ('{field}' is {spec.type})")

    # Consumer arg TYPE / arity check (needs the registry).
    if registry is None:
        return
    tool = registry.get(consumer_tool)
    if tool is None:
        return  # unknown consumer tool (kept tool not loaded) -> arg-name warning handles it
    param = (getattr(tool, "parameters", {}) or {}).get(consumer_arg)
    if param is None:
        return  # unknown arg -> the existing arg-name warning covers it
    consumer_type = str(param.get("type") or "")
    if not consumer_type:
        return
    consumer_is_list = _arg_is_list(consumer_type)
    consumer_base = _arg_base_type(consumer_type)

    if field_is_list and not consumer_is_list:
        # list field -> scalar arg: require an explicit `select = 'first'`.
        if select != "first":
            raise RefError(
                f"'{field}' is a list but '{consumer_arg}' takes a single value — "
                "add  select = 'first'  to take the first item (never a silent pick)")
        elem = _field_base_type(spec.type)
        if consumer_base not in ("any", elem):
            raise RefError(
                f"'{field}' items are {elem}, but '{consumer_arg}' expects {consumer_base}")
        return
    if not field_is_list and consumer_is_list:
        raise RefError(
            f"'{field}' is a single {spec.type}, but '{consumer_arg}' expects a list")
    # scalar->scalar (or list->list): base types must match.
    field_base = _field_base_type(spec.type)
    if consumer_base not in ("any", field_base):
        raise RefError(
            f"'{field}' is {spec.type}, but '{consumer_arg}' expects {consumer_type} "
            f"— types don't match")


def compatible_fields(consumer_type: str, producer_tool: str) -> list[tuple[str, str, bool]]:
    """For the guided builder: whitelisted fields of ``producer_tool`` that can
    feed a consumer arg of ``consumer_type``. Returns [(field, label,
    needs_first)] where needs_first means a list field feeding a scalar arg (the
    builder sets select='first'). Kept in sync with validate_reference's rules."""
    fields = FIELD_WHITELIST.get(producer_tool) or {}
    consumer_is_list = _arg_is_list(consumer_type)
    consumer_base = _arg_base_type(consumer_type)
    out: list[tuple[str, str, bool]] = []
    for name, spec in fields.items():
        field_is_list = spec.type.startswith("list")
        field_base = _field_base_type(spec.type)
        if field_is_list and not consumer_is_list:
            if consumer_base in ("any", field_base):
                out.append((name, spec.label, True))
        elif field_is_list == consumer_is_list:
            if consumer_base in ("any", field_base):
                out.append((name, spec.label, False))
    return out


# --------------------------------------------------------------------------- #
# Run-time resolution (fail-safe)
# --------------------------------------------------------------------------- #
def resolve_reference(ref: dict[str, Any], results: list[Any]) -> tuple[bool, Any, Optional[str]]:
    """Resolve a reference against the prior ``StepResult``s (``ctx.results``).
    Returns ``(ok, value, reason)``. NEVER raises: any problem (producer skipped/
    failed/excluded, field missing/empty, value fails its validator) returns
    ``ok=False`` with a human reason, so the caller fail-safe-SKIPs the consumer
    step rather than dispatching a garbage/``None`` value."""
    frm, field = ref["from"], ref["field"]
    select = ref.get("select")

    producer = None
    if frm.isdigit():
        idx = int(frm) - 1
        if 0 <= idx < len(results):
            producer = results[idx]
    else:
        matches = [r for r in results if getattr(r.step, "label", None) == frm]
        if len(matches) == 1:
            producer = matches[0]
    if producer is None:
        return False, None, f"its input '{field}' from step '{frm}' wasn't produced (step not found)"
    if getattr(producer, "status", None) != "ok":
        return False, None, (
            f"its input '{field}' from step '{frm}' wasn't produced "
            f"(that step was {getattr(producer, 'status', 'not run')})")

    fields = FIELD_WHITELIST.get(getattr(producer.step, "tool", "")) or {}
    spec = fields.get(field)
    if spec is None:
        return False, None, f"'{field}' is not a threadable output of step '{frm}'"

    try:
        value = spec.extract(producer.result or {})
    except Exception as e:  # noqa: BLE001 -- a bad result shape must fail safe, not crash
        return False, None, f"couldn't read '{field}' from step '{frm}' ({e})"

    if spec.type.startswith("list") and select == "first":
        value = value[0] if isinstance(value, list) and value else None
    if value is None or (isinstance(value, list) and not value):
        return False, None, f"step '{frm}' produced no '{field}' value to use"
    if spec.validate is not None and not spec.validate(value):
        return False, None, f"the value from '{frm}.{field}' ({value!r}) isn't valid for this arg"
    return True, value, None


def resolve_step_args(args: dict[str, Any], results: list[Any]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Resolve every reference in a step's args against prior results. Returns
    ``(resolved_args, None)`` on success, or ``(None, skip_reason)`` if ANY
    reference can't resolve -- the caller then fail-safe-SKIPs the step."""
    resolved: dict[str, Any] = {}
    for key, value in args.items():
        if is_reference(value):
            ok, resolved_value, reason = resolve_reference(value, results)
            if not ok:
                return None, reason
            resolved[key] = resolved_value
        else:
            resolved[key] = value
    return resolved, None
