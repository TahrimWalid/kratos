"""The Kratos processing pipeline: renames Sigma fields to Kratos event fields,
per log source, from kratos/events/sigma_fields.py. A field it doesn't rename
keeps its Sigma name, and the backend refuses the rule (with the reason from
sigma_fields.UNMAPPED)."""
from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from kratos.events import sigma_fields as SF

PIPELINE_NAME = "Kratos events"
MAX_ARG_INDEX = 63


def _mapping(ls: SF.Logsource) -> dict[str, str]:
    out = dict(ls.fields)
    if ls.key == ("linux", "auditd", None):
        out.update({f"a{i}": f"process.args[{i}]" for i in range(MAX_ARG_INDEX + 1)})
    return out


def kratos_pipeline() -> ProcessingPipeline:
    items = []
    for ls in SF.LOGSOURCES.values():
        mapping = _mapping(ls)
        if not mapping:
            continue
        product, service, category = ls.key
        items.append(ProcessingItem(
            identifier="kratos_fields_" + "_".join(p for p in ls.key if p),
            transformation=FieldMappingTransformation(mapping),
            rule_conditions=[LogsourceCondition(product=product, service=service, category=category)],
        ))
    return ProcessingPipeline(name=PIPELINE_NAME, priority=20, items=items)
