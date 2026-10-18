"""The event field table vs. the committed JSON Schema and the ECS reference."""
from __future__ import annotations

import json
from dataclasses import fields as dc_fields
from pathlib import Path

import pytest

from kratos.events import fields as F
from kratos.events.model import Event
from kratos.events.write_schema import committed_schema_text

ECS_REF = json.loads((Path(__file__).parent / "fixtures" / "ecs" / "ecs_9.5.0_subset.json").read_text())["fields"]
# Kratos field type -> the ECS field types it may stand for.
_TYPE_OK = {"datetime": {"date"}, "keyword": {"keyword", "wildcard"}, "text": {"match_only_text", "text"},
            "ip": {"ip"}, "long": {"long"}}


def test_committed_schema_matches_the_table():
    assert committed_schema_text() == F.schema_text(), \
        "events/schema/event-v1.schema.json is stale: run `python -m kratos.events.write_schema`"


def test_ecs_version_pinned_to_the_reference_used():
    assert F.ECS_VERSION == "9.5.0"


@pytest.mark.parametrize("field", [f for f in F.FIELDS if not f.is_kratos], ids=lambda f: f.name)
def test_every_ecs_field_is_real_ecs(field):
    ref = ECS_REF.get(field.name)
    assert ref is not None, f"{field.name} is not an ECS {F.ECS_VERSION} field -- use a kratos.* name"
    assert ref["type"] in _TYPE_OK[field.base_type]
    assert field.is_array == ("array" in ref["normalize"])
    assert field.doc_url and field.doc_url.startswith("https://www.elastic.co/docs/reference/ecs/ecs-")


def test_every_field_has_an_ecs_link_or_a_kratos_name():
    for f in F.FIELDS:
        assert f.is_kratos or f.doc_url, f.name
        assert f.doc, f"{f.name} has no description"


@pytest.mark.parametrize("name, values", [
    ("event.kind", F.KIND_VALUES), ("event.category", F.CATEGORY_VALUES),
    ("event.type", F.TYPE_VALUES), ("event.outcome", F.OUTCOME_VALUES)])
def test_allowed_values_match_ecs(name, values):
    assert list(values) == ECS_REF[name]["allowed_values"]


def test_dataclass_follows_the_table():
    assert tuple(f.name for f in dc_fields(Event)) == tuple(f.py_attr for f in F.FIELDS)


def test_index_columns_are_store_columns():
    from kratos.events import store

    assert set(F.INDEXED) <= set(store.COLUMNS)


def test_schema_ships_as_package_data():
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib

    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert "events/schema/*.json" in pyproject["tool"]["setuptools"]["package-data"]["kratos"]
