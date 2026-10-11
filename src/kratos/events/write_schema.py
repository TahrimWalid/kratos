"""Regenerate the committed event JSON Schema from the field table:

    python -m kratos.events.write_schema

tests/test_event_schema.py fails if the committed file and the table drift.
"""
from __future__ import annotations

from importlib import resources

from kratos.events.fields import schema_text

SCHEMA_FILE = "event-v1.schema.json"


def committed_schema_text() -> str:
    return resources.files("kratos.events").joinpath("schema", SCHEMA_FILE).read_text(encoding="utf-8")


if __name__ == "__main__":
    path = resources.files("kratos.events").joinpath("schema", SCHEMA_FILE)
    with resources.as_file(path) as p:
        p.write_text(schema_text(), encoding="utf-8")
        print(f"wrote {p}")
