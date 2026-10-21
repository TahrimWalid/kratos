"""The Kratos pySigma backend: a Sigma rule's condition -> one closed-operator node
(kratos.subagent.detect's format). Anything the format can't express faithfully
raises SigmaFeatureNotSupportedByBackendError with a plain reason, and the rule
is skipped -- never approximated.

Supported: and/or/not; string values with `*`/`?` wildcards (so the contains,
startswith, endswith and all modifiers, and whatever pySigma expands at compile
time: base64, base64offset, wide, windash); case-sensitive values (`cased`);
numbers (compared as text); CIDR; exists / null; keyword searches (looked for in
the message and the raw line). Not supported: regular expressions, numeric
comparisons, field references, timestamp parts, query expressions, and any field
the pipeline did not map to a Kratos event field.
"""
from __future__ import annotations

import re
from typing import Any, ClassVar

from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.types import SigmaCasedString, SigmaString, SpecialChars

from kratos.events import sigma_fields as SF
from kratos.subagent import detect as D

_INDEXED = re.compile(r"^(?P<field>[a-z_.@]+)\[(?P<index>\d{1,2})\]$")


def unsupported(reason: str) -> SigmaFeatureNotSupportedByBackendError:
    return SigmaFeatureNotSupportedByBackendError(reason)


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def string_leaf(field: str, index: int | None, value: SigmaString) -> dict[str, Any]:
    """A Sigma string value -> eq / contains / startswith / endswith / wildcard."""
    return parts_leaf(field, index, list(value.s), isinstance(value, SigmaCasedString))


def parts_leaf(field: str, index: int | None, parts: list[Any], cased: bool) -> dict[str, Any]:
    lead = bool(parts) and parts[0] == SpecialChars.WILDCARD_MULTI
    trail = len(parts) > 1 and parts[-1] == SpecialChars.WILDCARD_MULTI
    core = parts[1 if lead else 0:len(parts) - 1 if trail else len(parts)]
    if parts == [SpecialChars.WILDCARD_MULTI]:
        node: dict[str, Any] = {"op": "exists", "field": field, "value": True}
        if index is not None:
            node["index"] = index
        return node
    if all(isinstance(p, str) for p in core):
        text = "".join(core)  # type: ignore[arg-type]
        op = {(False, False): "eq", (True, True): "contains", (True, False): "endswith",
              (False, True): "startswith"}[(lead, trail)]
        node = {"op": op, "field": field, "value": text}
    else:
        pattern = "".join("*" if p == SpecialChars.WILDCARD_MULTI else "?" if p == SpecialChars.WILDCARD_SINGLE
                          else _escape(p) for p in parts)
        node = {"op": "wildcard", "field": field, "pattern": pattern}
    if cased:
        node["cased"] = True
    if index is not None:
        node["index"] = index
    return node


class KratosBackend(Backend):
    name: ClassVar[str] = "Kratos detection rules"
    formats: ClassVar[dict[str, str]] = {"default": "Kratos closed-operator rule nodes"}
    requires_pipeline: ClassVar[bool] = True

    # ---- fields
    def field(self, name: str) -> tuple[str, int | None]:
        m = _INDEXED.match(name or "")
        if m:
            field, index = m.group("field"), int(m.group("index"))
        else:
            field, index = name, None
        if field not in D.FIELDS:
            reason = SF.UNMAPPED.get(name)
            raise unsupported(f"field {name}: {reason}" if reason else
                              f"field {name} is not one Kratos's events have for this log source")
        if index is not None and field not in D.ORDERED_FIELDS:
            raise unsupported(f"field {name}: positions can't be chosen in {field}")
        return field, index

    # ---- boolean structure
    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Any:
        args = [self.convert_condition(a, state) for a in cond.args]
        return _merge_in({"op": "any_of", "args": args})

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        args = [self.convert_condition(a, state) for a in cond.args]
        flat: list[Any] = []
        for a in args:
            flat.extend(a["args"] if a.get("op") == "all_of" else [a])
        return flat[0] if len(flat) == 1 else {"op": "all_of", "args": flat}

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        return {"op": "not", "arg": self.convert_condition(cond.args[0], state)}

    def convert_condition_as_in_expression(self, cond: Any, state: ConversionState) -> Any:  # pragma: no cover
        return self.convert_condition_or(cond, state)

    def decide_convert_condition_as_in_expression(self, cond: Any, state: ConversionState) -> bool:
        return False

    # ---- field = value
    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field, index = self.field(cond.field)
        return string_leaf(field, index, cond.value)

    def convert_condition_field_eq_val_str_case_sensitive(self, cond: ConditionFieldEqualsValueExpression,
                                                         state: ConversionState) -> Any:
        return self.convert_condition_field_eq_val_str(cond, state)

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field, index = self.field(cond.field)
        node: dict[str, Any] = {"op": "eq", "field": field, "value": str(cond.value.number), "cased": True}
        if index is not None:
            node["index"] = index
        return node

    def convert_condition_field_eq_val_bool(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field, index = self.field(cond.field)
        node: dict[str, Any] = {"op": "eq", "field": field, "value": "true" if cond.value.boolean else "false"}
        if index is not None:
            node["index"] = index
        return node

    def convert_condition_field_eq_val_cidr(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field, index = self.field(cond.field)
        if index is not None:
            raise unsupported(f"field {cond.field}: a CIDR test on one position")
        return {"op": "cidr", "field": field, "values": [str(cond.value.network)]}

    def convert_condition_field_eq_val_null(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field, index = self.field(cond.field)
        node: dict[str, Any] = {"op": "exists", "field": field, "value": False}
        if index is not None:
            node["index"] = index
        return node

    def convert_condition_field_exists(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field, index = self.field(cond.field)
        node: dict[str, Any] = {"op": "exists", "field": field, "value": True}
        if index is not None:
            node["index"] = index
        return node

    def convert_condition_field_not_exists(self, cond: ConditionFieldEqualsValueExpression,
                                           state: ConversionState) -> Any:
        node = self.convert_condition_field_exists(cond, state)
        node["value"] = False
        return node

    # ---- keywords (values with no field): looked for in the message and the raw line
    def convert_condition_val_str(self, cond: Any, state: ConversionState) -> Any:
        value: SigmaString = cond.value
        parts = list(value.s)
        if not parts or parts[0] != SpecialChars.WILDCARD_MULTI:
            parts.insert(0, SpecialChars.WILDCARD_MULTI)
        if parts[-1] != SpecialChars.WILDCARD_MULTI or len(parts) == 1:
            parts.append(SpecialChars.WILDCARD_MULTI)
        cased = isinstance(value, SigmaCasedString)
        return {"op": "any_of", "args": [parts_leaf(f, None, parts, cased) for f in SF.KEYWORD_FIELDS]}

    def convert_condition_val_num(self, cond: Any, state: ConversionState) -> Any:
        text = str(cond.value.number)
        return {"op": "any_of", "args": [{"op": "contains", "field": f, "value": text} for f in SF.KEYWORD_FIELDS]}

    # ---- not supported, each with its reason
    def convert_condition_field_eq_val_re(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported(f"uses a regular expression (field {cond.field})")

    def convert_condition_val_re(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported("uses a regular expression")

    def convert_condition_field_compare_op_val(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported(f"uses a numeric comparison (field {cond.field})")

    def convert_condition_field_eq_field(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported(f"compares two fields ({cond.field})")

    def convert_condition_field_eq_val_timestamp_part(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported(f"tests part of a timestamp ({cond.field})")

    def convert_condition_field_eq_query_expr(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported("uses a backend query expression")

    def convert_condition_query_expr(self, cond: Any, state: ConversionState) -> Any:
        raise unsupported("uses a backend query expression")

    # ---- output
    def finalize_query_default(self, rule: SigmaRule, query: Any, index: int, state: ConversionState) -> Any:
        return query

    def finalize_output_default(self, queries: list[Any]) -> Any:
        return queries

    # ---- correlations are compiled by kratos.detect.sigma_build.compile (event_count only)
    def _no_correlation(self, *a: Any, **k: Any) -> Any:
        raise unsupported("this kind of correlation rule")

    convert_correlation_event_count_rule = _no_correlation
    convert_correlation_value_count_rule = _no_correlation
    convert_correlation_temporal_rule = _no_correlation
    convert_correlation_temporal_ordered_rule = _no_correlation
    convert_correlation_extended_temporal_rule = _no_correlation
    convert_correlation_extended_temporal_ordered_rule = _no_correlation
    convert_correlation_value_sum_rule = _no_correlation
    convert_correlation_value_avg_rule = _no_correlation
    convert_correlation_value_percentile_rule = _no_correlation
    convert_correlation_value_median_rule = _no_correlation


def _merge_in(node: dict[str, Any]) -> dict[str, Any]:
    """any_of over plain eq tests of one field (same case rule, same position) -> one `in`."""
    args = node["args"]
    groups: dict[tuple, list[str]] = {}
    rest: list[Any] = []
    order: list[Any] = []
    for a in args:
        if a.get("op") == "eq":
            key = (a["field"], bool(a.get("cased")), a.get("index"))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(a["value"])
        elif a.get("op") == "in":
            key = (a["field"], bool(a.get("cased")), a.get("index"))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].extend(a["values"])
        else:
            rest.append(a)
            order.append(a)
    out: list[Any] = []
    for item in order:
        if isinstance(item, tuple):
            field, cased, index = item
            values = list(dict.fromkeys(groups[item]))
            leaf: dict[str, Any] = ({"op": "eq", "field": field, "value": values[0]} if len(values) == 1
                                    else {"op": "in", "field": field, "values": values})
            if cased:
                leaf["cased"] = True
            if index is not None:
                leaf["index"] = index
            out.append(leaf)
        else:
            out.append(item)
    flat: list[Any] = []
    for a in out:
        flat.extend(a["args"] if a.get("op") == "any_of" else [a])
    return flat[0] if len(flat) == 1 else {"op": "any_of", "args": flat}
