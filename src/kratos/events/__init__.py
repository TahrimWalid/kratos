"""Events: every log line Kratos reads, as one typed, ECS field-mapped record.

See events/fields.py (the field table), model.py (Event), converters.py (from
the existing parsers), redact.py (credential masking) and store.py (the
append-only `host_events` table in kratos.db).
"""
from kratos.events.model import Event, EventError

__all__ = ["Event", "EventError"]
