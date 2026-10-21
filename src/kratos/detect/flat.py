"""An Event as the flat {ECS field name: value} dict the evaluator reads."""
from __future__ import annotations

from typing import Any

from kratos.events import fields as F
from kratos.events.model import Event, format_timestamp


def flat(event: Event) -> dict[str, Any]:
    """Every set field of `event` by its ECS name; arrays as lists, times as ISO text."""
    out: dict[str, Any] = {}
    for f in F.FIELDS:
        value = getattr(event, f.py_attr)
        if value is None or value == () or value is False:
            continue
        if f.base_type == "datetime":
            value = format_timestamp(value)
        elif f.base_type == "window":
            continue
        elif f.is_array:
            value = list(value)
        out[f.name] = value
    return out
