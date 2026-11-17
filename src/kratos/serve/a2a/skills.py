"""Reading an A2A message into one skill call (docs/phaseE/E.5 §3.3).

A message carries at most one data part -- `{"skill": ..., ...}`, checked against the
skill's own small schema (card.SKILLS: closed set of keys, strings only, lengths capped)
-- and text parts (the question). Kratos never fetches anything a message points at: a
`url` or `raw` (file) part is refused, not opened. A message with only text is the
question for `investigate_machine` when the caller may use exactly one machine; anything
else must name its skill.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from kratos.serve.a2a.card import MAX_QUESTION, SKILLS, SKILL_IDS

MAX_PARTS = 8
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SCHEMAS = {s["id"]: s["input"] for s in SKILLS}
RUNNING = frozenset({"investigate_machine", "ask_group", "hunt_indicator"})


class InputError(ValueError):
    """`reason`: the A2A error reason (INVALID_PARAMS, CONTENT_TYPE_NOT_SUPPORTED, ...)."""

    def __init__(self, message: str, reason: str = "INVALID_PARAMS") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class Call:
    skill: str
    args: dict[str, Any] = field(default_factory=dict)
    message_id: str = ""
    context_id: str | None = None
    task_id: str | None = None          # a message to an existing task (Kratos refuses: one message per task)

    @property
    def runs(self) -> bool:
        return self.skill in RUNNING


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def _check_schema(skill: str, data: dict[str, Any]) -> dict[str, Any]:
    schema = _SCHEMAS[skill]
    props = schema["properties"]
    extra = sorted(k for k in data if k not in props)
    if extra:
        raise InputError(f"{skill} doesn't take {', '.join(extra)[:200]} (see the agent card's skill-input extension)")
    for key in schema.get("required", ()):
        value = data.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise InputError(f"{skill} needs {key}")
    out: dict[str, Any] = {}
    for key, value in data.items():
        rule = props[key]
        if not isinstance(value, str):
            raise InputError(f"{key} must be text")
        if "const" in rule and value != rule["const"]:
            raise InputError(f"{key} must be {rule['const']!r}")
        if "enum" in rule and value not in rule["enum"]:
            raise InputError(f"{key} must be one of: {', '.join(rule['enum'])}")
        if len(value) > int(rule.get("maxLength", MAX_QUESTION)):
            raise InputError(f"{key} is longer than {rule.get('maxLength', MAX_QUESTION)} characters")
        if "\x00" in value:
            raise InputError(f"{key} contains a NUL character")
        out[key] = value.strip()
    return out


def parse(message: Any, *, single_machine: str | None = None) -> Call:
    """The skill call in an A2A Message. `single_machine`: the caller's only machine, for
    a text-only message (None when they may use none or several)."""
    if not isinstance(message, dict):
        raise InputError("message must be an object")
    role = message.get("role")
    if role not in ("ROLE_USER", None, ""):
        raise InputError("message.role must be ROLE_USER")
    mid = message.get("messageId")
    if not valid_id(mid):
        raise InputError("message.messageId is required (1-128 letters, digits, '_', '.', ':' or '-')")
    ctx = message.get("contextId") or None
    if ctx is not None and not valid_id(ctx):
        raise InputError("contextId must be 1-128 letters, digits, '_', '.', ':' or '-'")
    tid = message.get("taskId") or None
    if tid is not None and not isinstance(tid, str):
        raise InputError("taskId must be text")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise InputError("message.parts must be a non-empty list")
    if len(parts) > MAX_PARTS:
        raise InputError(f"at most {MAX_PARTS} parts")
    texts: list[str] = []
    data: dict[str, Any] | None = None
    for p in parts:
        if not isinstance(p, dict):
            raise InputError("each part must be an object")
        kinds = [k for k in ("text", "data", "raw", "url") if k in p]
        if len(kinds) != 1:
            raise InputError("each part holds exactly one of text, data, raw or url")
        kind = kinds[0]
        if kind in ("raw", "url"):
            raise InputError("Kratos takes text and data parts only -- it never opens a file or fetches a URL "
                             "from a message", reason="CONTENT_TYPE_NOT_SUPPORTED")
        if kind == "text":
            if not isinstance(p["text"], str):
                raise InputError("a text part's text must be text")
            texts.append(p["text"])
        else:
            if data is not None:
                raise InputError("at most one data part (the skill and its input)")
            if not isinstance(p["data"], dict):
                raise InputError("the data part must be an object: {\"skill\": ..., ...}")
            data = p["data"]
    text = "\n".join(t.strip() for t in texts if t.strip())
    if len(text) > MAX_QUESTION:
        raise InputError(f"the text is longer than {MAX_QUESTION} characters")
    if data is None:
        if not text:
            raise InputError("the message has no question")
        if single_machine is None:
            raise InputError("name a skill in a data part -- {\"skill\": \"investigate_machine\", \"machine\": ..., "
                             "\"question\": ...} (see the agent card); a text-only message works only when you may "
                             "use exactly one machine")
        data = {"skill": "investigate_machine", "machine": single_machine, "question": text}
    skill = data.get("skill")
    if skill not in SKILL_IDS:
        raise InputError(f"unknown skill -- one of: {', '.join(SKILL_IDS)}")
    if text and "question" in _SCHEMAS[skill]["properties"] and not str(data.get("question") or "").strip():
        data = {**data, "question": text}
    if text and skill == "hunt_indicator" and not str(data.get("indicators") or "").strip():
        data = {**data, "indicators": text}
    return Call(skill=skill, args=_check_schema(skill, data), message_id=mid, context_id=ctx, task_id=tid)
