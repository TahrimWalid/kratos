"""Events: every log line Kratos reads, as one typed, ECS field-mapped record.

See events/fields.py (the field table), model.py (Event), converters.py (from
the existing parsers), redact.py (credential masking), store.py (the
append-only `host_events` table in kratos.db) and recording.py (where the
reads hand their lines over).
"""
from kratos.events.model import Event, EventError
from kratos.events.store import EventStore, record_events

__all__ = ["Event", "EventError", "EventStore", "record_events"]
