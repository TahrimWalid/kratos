"""The Event record: one log line Kratos read, field-mapped to ECS.

Attribute names and order follow `events/fields.py::FIELDS` (a test keeps them
in step). `to_ecs()` gives the nested ECS document; `from_ecs()` is its exact
inverse. Construction validates: ECS-allowed categorisation values only, UTC
times, byte caps, required fields present.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, fields as dc_fields
from datetime import datetime, timezone
from typing import Any

from kratos.events import fields as F

UTC = timezone.utc


class EventError(ValueError):
    """An event that doesn't satisfy the schema."""


@dataclass(frozen=True, slots=True)
class Event:
    timestamp: datetime
    created: datetime
    event_id: str
    kind: str
    category: tuple[str, ...] = ()
    type: tuple[str, ...] = ()
    action: str | None = None
    outcome: str | None = None
    dataset: str = ""
    provider: str | None = None
    original: str | None = None
    message: str | None = None
    host_name: str = ""
    user_name: str | None = None
    user_id: str | None = None
    user_effective_name: str | None = None
    user_target_name: str | None = None
    group_name: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    process_name: str | None = None
    process_pid: int | None = None
    process_parent_pid: int | None = None
    process_executable: str | None = None
    process_command_line: str | None = None
    file_path: str | None = None
    file_sha256: str | None = None
    service_name: str | None = None
    log_file_path: str | None = None
    log_syslog_priority: int | None = None
    sequence: int | None = None
    process_working_directory: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    network_transport: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    url_original: str | None = None
    http_request_method: str | None = None
    http_response_status_code: int | None = None
    user_agent_original: str | None = None
    process_args: tuple[str, ...] = ()
    user_effective_id: str | None = None
    rule_id: str | None = None
    rule_uuid: str | None = None
    rule_name: str | None = None
    rule_author: tuple[str, ...] = ()
    rule_reference: str | None = None
    rule_license: str | None = None
    rule_ruleset: str | None = None
    rule_version: str | None = None
    related_ip: tuple[str, ...] = ()
    related_user: tuple[str, ...] = ()
    ecs_version: str = F.ECS_VERSION
    schema_version: int = F.SCHEMA_VERSION
    transport: str = ""
    read: str | None = None
    run_id: str | None = None
    window: tuple[float | None, float | None] | None = None
    coverage: str | None = None
    parser: str = ""
    time_zone_assumed: bool = False
    redacted: bool = False
    truncated: bool = False
    audit_types: tuple[str, ...] = ()
    audit_key: str | None = None
    audit_syscall: str | None = None
    audit_paths: tuple[str, ...] = ()
    audit_created_paths: tuple[str, ...] = ()
    audit_session: str | None = None
    detect_matched: tuple[str, ...] = ()
    detect_level: str | None = None
    detect_group: str | None = None
    detect_count: int | None = None

    def __post_init__(self) -> None:
        _replace_lone_surrogates(self)
        _validate(self)

    @property
    def ts(self) -> float:
        """@timestamp as epoch seconds."""
        return self.timestamp.timestamp()

    def to_ecs(self) -> dict[str, Any]:
        """The nested ECS document. Unset fields (None, empty arrays, False flags)
        are left out; `from_ecs` restores them as their defaults."""
        doc: dict[str, Any] = {}
        for f in F.FIELDS:
            value = getattr(self, f.py_attr)
            if value is None or value == () or value is False:
                continue
            node = doc
            parts = f.name.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = _encode(f, value)
        return doc

    @classmethod
    def from_ecs(cls, doc: dict[str, Any]) -> "Event":
        if not isinstance(doc, dict):
            raise EventError("an ECS document must be an object")
        known = _flatten(doc)
        unknown = set(known) - set(F.BY_NAME)
        if unknown:
            raise EventError(f"fields not in schema v{F.SCHEMA_VERSION}: {sorted(unknown)}")
        kwargs = {F.BY_NAME[name].py_attr: _decode(F.BY_NAME[name], value) for name, value in known.items()}
        try:
            return cls(**kwargs)
        except TypeError as e:  # a required field missing
            raise EventError(str(e)) from None


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in doc.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and name not in F.BY_NAME:
            out.update(_flatten(value, name + "."))
        else:
            out[name] = value
    return out


def format_timestamp(dt: datetime) -> str:
    """ISO 8601 UTC with microseconds and a Z, e.g. 2026-10-11T09:01:02.000123Z."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_timestamp(text: str) -> datetime:
    dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise EventError(f"timestamp without a zone: {text!r}")
    return dt.astimezone(UTC)


def _encode(f: F.Field, value: Any) -> Any:
    base = f.base_type
    if base == "datetime":
        return format_timestamp(value)
    if base == "window":
        return {"since": value[0], "until": value[1]}
    if f.is_array:
        return list(value)
    return value


def _decode(f: F.Field, value: Any) -> Any:
    base = f.base_type
    if base == "datetime":
        return parse_timestamp(value)
    if base == "window":
        if not isinstance(value, dict):
            raise EventError(f"{f.name} must be an object")
        return (value.get("since"), value.get("until"))
    if f.is_array:
        if not isinstance(value, list):
            raise EventError(f"{f.name} must be an array")
        return tuple(value)
    return value


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _replace_lone_surrogates(event: "Event") -> None:
    """Text from a machine can carry an unpaired surrogate (a hostile or mis-decoded line); it cannot be
    encoded as UTF-8 or stored. Each one becomes U+FFFD so the event -- and the rest of its batch -- is
    kept rather than lost (kratos.untrusted, A.4)."""
    for f in dc_fields(event):
        value = getattr(event, f.name)
        if isinstance(value, str) and _LONE_SURROGATE.search(value):
            object.__setattr__(event, f.name, _LONE_SURROGATE.sub("\ufffd", value))
        elif isinstance(value, tuple) and any(isinstance(v, str) and _LONE_SURROGATE.search(v) for v in value):
            object.__setattr__(event, f.name, tuple(_LONE_SURROGATE.sub("\ufffd", v) if isinstance(v, str) else v
                                                    for v in value))


def _validate(e: Event) -> None:
    for f in F.FIELDS:
        value = getattr(e, f.py_attr)
        if f.required and (value is None or value == ""):
            raise EventError(f"{f.name} is required")
        if value is None:
            continue
        base = f.base_type
        if f.is_array:
            if not isinstance(value, tuple) or not all(isinstance(v, str) for v in value):
                raise EventError(f"{f.name} must be a tuple of strings")
            if not f.ordered and len(set(value)) != len(value):
                raise EventError(f"{f.name} has duplicates")
            items = value
        else:
            items = (value,)
        for item in items:
            if base == "datetime":
                if not isinstance(item, datetime) or item.utcoffset() != timezone.utc.utcoffset(None):
                    raise EventError(f"{f.name} must be a UTC datetime")
            elif base in ("keyword", "text"):
                if not isinstance(item, str):
                    raise EventError(f"{f.name} must be a string")
                if f.max_len and len(item.encode("utf-8")) > f.max_len:
                    raise EventError(f"{f.name} is longer than {f.max_len} bytes")
            elif base == "ip":
                try:
                    ipaddress.ip_address(item)
                except ValueError:
                    raise EventError(f"{f.name} is not an IP address: {item!r}") from None
            elif base == "long":
                if not isinstance(item, int) or isinstance(item, bool):
                    raise EventError(f"{f.name} must be an integer")
            elif base == "boolean":
                if not isinstance(item, bool):
                    raise EventError(f"{f.name} must be true or false")
            elif base == "window":
                if not (isinstance(item, tuple) and len(item) == 2 and
                        all(b is None or (isinstance(b, (int, float)) and not isinstance(b, bool)) for b in item)):
                    raise EventError(f"{f.name} must be (since, until) epoch seconds or None")
            allowed = F.enum_for(f.name)
            if allowed is not None and item not in allowed:
                raise EventError(f"{f.name}: {item!r} is not an allowed value")


def event_id(host: str, dataset: str, timestamp: datetime, provider: str | None, text: str | None) -> str:
    """Deterministic ID: the first 32 hex chars of
    sha256(host ␟ dataset ␟ @timestamp in µs ␟ provider ␟ original-or-message),
    with U+001F (unit separator) between the parts. The same line read twice
    (overlapping windows) gets the same ID, so it is stored once.

    Known limit: two genuinely identical lines from the same program in the same
    microsecond collapse into one event. Journal entries that carry their
    __CURSOR use cursor_event_id instead (0.3) -- except the sudo/sshd auth
    events (kratos.auth), which keep this ID so the same line read by the auth
    read and by the sudo source is still stored once."""
    micros = int(round(timestamp.astimezone(UTC).timestamp() * 1_000_000))
    raw = "\x1f".join((host, dataset, str(micros), provider or "", text or ""))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def cursor_event_id(host: str, cursor: str) -> str:
    """A journal entry's ID from its own __CURSOR: the first 32 hex chars of
    sha256(host ␟ cursor). Unique per entry even for identical lines in the same
    microsecond, and the same however often the entry is read."""
    raw = "\x1f".join((host, cursor))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def attribute_names() -> tuple[str, ...]:
    return tuple(f.name for f in dc_fields(Event))
