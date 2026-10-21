"""THE field table for Kratos events -- the single source of truth.

Field names are exactly ECS's (Elastic Common Schema, version `ECS_VERSION`,
https://www.elastic.co/docs/reference/ecs). Kratos-only fields live under
`kratos.*`. The Event dataclass, `to_ecs()`/`from_ecs()`, the SQL index columns
and the committed JSON Schema (`schema/event-v1.schema.json`, regenerate with
`python -m kratos.events.write_schema`)
are all derived from or tested against this table.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

ECS_VERSION = "9.5.0"
SCHEMA_VERSION = 1
SCHEMA_ID = "https://github.com/TahrimWalid/kratos/events/event-v1.schema.json"

# ECS 9.5.0 allowed values (event.* categorisation fields). Checked against the
# official definitions by tests/test_event_schema.py.
KIND_VALUES = ("alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal")
CATEGORY_VALUES = ("api", "authentication", "configuration", "database", "driver", "email", "file", "host",
                   "iam", "intrusion_detection", "library", "malware", "network", "package", "process",
                   "registry", "session", "threat", "vulnerability", "web")
TYPE_VALUES = ("access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied", "device",
               "end", "error", "group", "indicator", "info", "installation", "protocol", "start", "user")
OUTCOME_VALUES = ("failure", "success", "unknown")

TRANSPORT_VALUES = ("ssh", "agent", "local")
COVERAGE_VALUES = ("complete", "truncated", "sampled")

# Byte caps (UTF-8), applied at conversion (events/redact.py).
ORIGINAL_MAX_BYTES = 2048
MESSAGE_MAX_BYTES = 4096
COMMAND_LINE_MAX_BYTES = 4096


@dataclass(frozen=True)
class Field:
    name: str                 # ECS dotted name, or kratos.*
    py_attr: str              # Event attribute
    type: str                 # datetime | keyword | text | ip | long | boolean | window, "[]" suffix = array
    required: bool = False
    indexed: str | None = None    # host_events column holding it, if any
    max_len: int | None = None    # UTF-8 bytes (per element, for an array)
    doc: str = ""
    ordered: bool = False         # an array whose order means something and may repeat a value (process.args)

    @property
    def is_array(self) -> bool:
        return self.type.endswith("[]")

    @property
    def base_type(self) -> str:
        return self.type[:-2] if self.is_array else self.type

    @property
    def is_kratos(self) -> bool:
        return self.name.startswith("kratos.")

    @property
    def doc_url(self) -> str | None:
        """The field's page in the ECS reference (None for kratos.* fields)."""
        if self.is_kratos:
            return None
        if "." not in self.name:  # @timestamp, message: the base field set
            return f"https://www.elastic.co/docs/reference/ecs/ecs-base#field-{self.name.lstrip('@')}"
        fieldset = self.name.split(".")[0]
        return f"https://www.elastic.co/docs/reference/ecs/ecs-{fieldset}#field-{self.name.replace('.', '-')}"


FIELDS: tuple[Field, ...] = (
    Field("@timestamp", "timestamp", "datetime", required=True, indexed="ts",
          doc="When it happened (UTC)."),
    Field("event.created", "created", "datetime", required=True,
          doc="When Kratos collected it (UTC)."),
    Field("event.id", "event_id", "keyword", required=True, indexed="event_id", max_len=64,
          doc="Deterministic: the same line read twice gets the same ID."),
    Field("event.kind", "kind", "keyword", required=True, doc="`event` for everything in schema v1."),
    Field("event.category", "category", "keyword[]", doc="ECS category, allowed values only."),
    Field("event.type", "type", "keyword[]", doc="ECS type, allowed values only."),
    Field("event.action", "action", "keyword", indexed="action", max_len=128,
          doc="Kratos's verb for it, e.g. ssh_failed_login."),
    Field("event.outcome", "outcome", "keyword", indexed="outcome", doc="success / failure / unknown."),
    Field("event.dataset", "dataset", "keyword", required=True, indexed="dataset", max_len=64,
          doc="Which read it came from: kratos.auth, kratos.journal, kratos.privileged_accounts, kratos.auditd, "
              "kratos.cron, kratos.systemd, kratos.firewall, kratos.package or kratos.web."),
    Field("event.provider", "provider", "keyword", max_len=256, doc="The program that logged it: sshd, sudo, ..."),
    Field("event.original", "original", "keyword", max_len=ORIGINAL_MAX_BYTES,
          doc="The raw line, credentials masked, capped at 2048 bytes."),
    Field("message", "message", "text", max_len=MESSAGE_MAX_BYTES,
          doc="The log message, credentials masked, capped at 4096 bytes."),
    Field("host.name", "host_name", "keyword", required=True, max_len=256,
          doc="The machine it happened on, as target_key()."),
    Field("user.name", "user_name", "keyword", indexed="user_name", max_len=256,
          doc="The acting or authenticating user."),
    Field("user.id", "user_id", "keyword", max_len=64, doc="The acting user's ID."),
    Field("user.effective.name", "user_effective_name", "keyword", max_len=256,
          doc="Who a command ran as (sudo -u)."),
    Field("user.target.name", "user_target_name", "keyword", max_len=256,
          doc="The account being changed (useradd, usermod, ...)."),
    Field("group.name", "group_name", "keyword", max_len=256, doc="The group being changed."),
    Field("source.ip", "source_ip", "ip", indexed="source_ip", doc="Where it came from."),
    Field("source.port", "source_port", "long", doc="Source port."),
    Field("process.name", "process_name", "keyword", indexed="process_name", max_len=256, doc="Process name."),
    Field("process.pid", "process_pid", "long", doc="Process ID."),
    Field("process.parent.pid", "process_parent_pid", "long", doc="Parent process ID."),
    Field("process.executable", "process_executable", "keyword", max_len=1024, doc="Path of the program."),
    Field("process.command_line", "process_command_line", "keyword", max_len=COMMAND_LINE_MAX_BYTES,
          doc="Full command line, credentials masked, capped at 4096 bytes."),
    Field("file.path", "file_path", "keyword", max_len=4096, doc="A file the event is about."),
    Field("file.hash.sha256", "file_sha256", "keyword", indexed="file_sha256", max_len=64,
          doc="That file's SHA-256."),
    Field("service.name", "service_name", "keyword", max_len=256, doc="The systemd unit."),
    Field("log.file.path", "log_file_path", "keyword", max_len=4096, doc="The log file it was read from."),
    Field("log.syslog.priority", "log_syslog_priority", "long", doc="journald PRIORITY (0 emerg .. 7 debug)."),
    # Added in 0.3 (new log sources). Optional and additive, so the schema stays v1.
    Field("event.sequence", "sequence", "long", doc="The source's own record number, e.g. auditd's event serial."),
    Field("process.working_directory", "process_working_directory", "keyword", max_len=1024,
          doc="The directory a program ran in (auditd CWD)."),
    Field("destination.ip", "destination_ip", "ip", doc="Where a connection was going (firewall logs)."),
    Field("destination.port", "destination_port", "long", doc="Destination port."),
    Field("network.transport", "network_transport", "keyword", max_len=32, doc="tcp, udp, icmp, ..."),
    Field("package.name", "package_name", "keyword", max_len=256, doc="A software package installed or removed."),
    Field("package.version", "package_version", "keyword", max_len=128, doc="That package's version."),
    Field("url.original", "url_original", "keyword", max_len=2048,
          doc="The requested URL, query values that look like credentials masked, capped at 2048 bytes."),
    Field("http.request.method", "http_request_method", "keyword", max_len=32, doc="GET, POST, ..."),
    Field("http.response.status_code", "http_response_status_code", "long", doc="The HTTP status returned."),
    Field("user_agent.original", "user_agent_original", "keyword", max_len=1024,
          doc="The client's User-Agent, capped at 1024 bytes."),
    # Added in C.1 (detection rules). Optional and additive, so the schema stays v1.
    Field("process.args", "process_args", "keyword[]", max_len=1024, ordered=True,
          doc="The program's arguments in order, argv[0] first (auditd EXECVE), credentials masked, at most 64."),
    Field("user.effective.id", "user_effective_id", "keyword", max_len=64,
          doc="The user ID a program ran as (auditd euid)."),
    Field("rule.id", "rule_id", "keyword", max_len=64,
          doc="The detection rule that matched (kratos.detect events), e.g. SIGMA-1a2b3c4d."),
    Field("rule.uuid", "rule_uuid", "keyword", max_len=64, doc="The rule's own upstream id (the SigmaHQ rule id)."),
    Field("rule.name", "rule_name", "keyword", max_len=256, doc="The rule's title."),
    Field("rule.author", "rule_author", "keyword[]", max_len=256,
          doc="Who wrote the rule -- shown with every alert it raises (Detection Rule License 1.1)."),
    Field("rule.reference", "rule_reference", "keyword", max_len=1024,
          doc="Where the rule comes from: its source file at the pinned commit."),
    Field("rule.license", "rule_license", "keyword", max_len=64, doc="The rule's licence, e.g. DRL-1.1."),
    Field("rule.ruleset", "rule_ruleset", "keyword", max_len=64, doc="The rule pack, e.g. sigma-linux."),
    Field("rule.version", "rule_version", "keyword", max_len=32, doc="The rule pack's version."),
    Field("related.ip", "related_ip", "ip[]", doc="Every IP in the event, for pivoting."),
    Field("related.user", "related_user", "keyword[]", doc="Every user name in the event, for pivoting."),
    Field("ecs.version", "ecs_version", "keyword", required=True, doc="The ECS version the event follows."),
    Field("kratos.schema_version", "schema_version", "long", required=True, indexed="schema_version",
          doc="Kratos event schema version (1)."),
    Field("kratos.transport", "transport", "keyword", required=True,
          doc="How the line was read: ssh, agent (the machine's sub-agent) or local."),
    Field("kratos.read", "read", "keyword", max_len=64, doc="The named read, e.g. journal_auth."),
    Field("kratos.run_id", "run_id", "keyword", indexed="run_id", max_len=64,
          doc="The run (kratos.run_context) that read it."),
    Field("kratos.window", "window", "window", doc="{since, until} epoch seconds of the read's window, if windowed."),
    Field("kratos.coverage", "coverage", "keyword",
          doc="complete, truncated (the read was capped) or sampled."),
    Field("kratos.parser", "parser", "keyword", required=True, max_len=64,
          doc="Converter name and version, e.g. auth_log/1."),
    Field("kratos.time_zone_assumed", "time_zone_assumed", "boolean",
          doc="True when the source time had no zone and UTC was assumed."),
    Field("kratos.redacted", "redacted", "boolean", doc="True when credential masking changed anything."),
    Field("kratos.truncated", "truncated", "boolean", doc="True when a text field was cut to its byte cap."),
    # C.1: what auditd recorded that Sigma's auditd rules look at.
    Field("kratos.audit.types", "audit_types", "keyword[]", max_len=32,
          doc="The auditd record types of this event (SYSCALL, EXECVE, PATH, ...)."),
    Field("kratos.audit.key", "audit_key", "keyword", max_len=256, doc="The audit rule key that recorded it (-k)."),
    Field("kratos.audit.syscall", "audit_syscall", "keyword", max_len=64,
          doc="The system call's name (auditd's ENRICHED log format only)."),
    Field("kratos.audit.paths", "audit_paths", "keyword[]", max_len=4096, ordered=True,
          doc="Every PATH record's name, in record order, at most 32."),
    Field("kratos.audit.created_paths", "audit_created_paths", "keyword[]", max_len=4096,
          doc="The PATH names auditd recorded as created (nametype=CREATE)."),
    Field("kratos.audit.session", "audit_session", "keyword", max_len=16,
          doc="The login session auditd recorded (ses): every program started in one SSH login shares it."),
    # C.1: a detection (dataset kratos.detect, event.kind alert).
    Field("kratos.detect.matched", "detect_matched", "keyword[]", max_len=64,
          doc="The IDs of the stored events a detection matched, at most 100."),
    Field("kratos.detect.level", "detect_level", "keyword", doc="The rule's level: info, low, medium, high, critical."),
    Field("kratos.detect.group", "detect_group", "keyword", max_len=256,
          doc="For a counting rule: the value its events were grouped by (e.g. the source address)."),
    Field("kratos.detect.count", "detect_count", "long", doc="For a counting rule: how many events fell in its window."),
)

BY_NAME = {f.name: f for f in FIELDS}
BY_ATTR = {f.py_attr: f for f in FIELDS}
INDEXED = {f.indexed: f for f in FIELDS if f.indexed}

_ENUMS = {
    "event.kind": KIND_VALUES, "event.category": CATEGORY_VALUES, "event.type": TYPE_VALUES,
    "event.outcome": OUTCOME_VALUES, "kratos.transport": TRANSPORT_VALUES,
    "kratos.coverage": COVERAGE_VALUES, "kratos.detect.level": ("info", "low", "medium", "high", "critical"),
}


def enum_for(name: str) -> tuple[str, ...] | None:
    return _ENUMS.get(name)


def _leaf_schema(f: Field) -> dict[str, Any]:
    base = f.base_type
    if base == "datetime":
        s: dict[str, Any] = {"type": "string", "format": "date-time"}
    elif base in ("keyword", "text"):
        s = {"type": "string"}
        if f.max_len:
            s["maxLength"] = f.max_len  # characters <= bytes, so this is a safe outer bound
    elif base == "ip":
        s = {"type": "string", "anyOf": [{"format": "ipv4"}, {"format": "ipv6"}]}
    elif base == "long":
        s = {"type": "integer"}
    elif base == "boolean":
        s = {"type": "boolean"}
    elif base == "window":
        s = {"type": "object", "additionalProperties": False,
             "properties": {"since": {"type": ["number", "null"]}, "until": {"type": ["number", "null"]}}}
    else:  # pragma: no cover - the table is fixed
        raise ValueError(f"unknown field type {f.type}")
    values = enum_for(f.name)
    if values:
        s["enum"] = list(values)
    if f.is_array:
        s = {"type": "array", "items": s} if f.ordered else {"type": "array", "items": s, "uniqueItems": True}
    s["description"] = f.doc
    return s


def json_schema() -> dict[str, Any]:
    """The JSON Schema (draft 2020-12) of `Event.to_ecs()`, built from FIELDS."""
    root: dict[str, Any] = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    for f in FIELDS:
        node = root
        parts = f.name.split(".")
        for i, part in enumerate(parts[:-1]):
            child = node["properties"].setdefault(
                part, {"type": "object", "properties": {}, "required": [], "additionalProperties": False})
            if f.required and part not in node["required"]:
                node["required"].append(part)
            node = child
        node["properties"][parts[-1]] = _leaf_schema(f)
        if f.required:
            node["required"].append(parts[-1])

    def tidy(node: dict[str, Any]) -> None:
        if not node.get("required"):
            node.pop("required", None)
        for child in node.get("properties", {}).values():
            if child.get("type") == "object" and "properties" in child and "description" not in child:
                tidy(child)

    tidy(root)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        "title": "Kratos event",
        "description": (f"One log line Kratos read, field-mapped to ECS {ECS_VERSION} "
                        f"(kratos.* fields are Kratos's own). Schema version {SCHEMA_VERSION}. "
                        "Generated from kratos/events/fields.py -- do not edit by hand."),
        **root,
    }


def schema_text() -> str:
    return json.dumps(json_schema(), indent=2, sort_keys=False) + "\n"
