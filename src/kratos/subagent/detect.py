"""The one detection-rule evaluator and rule-pack validator (phase C.1).

Standard-library Python 3.8, no kratos imports: this file ships in the sub-agent
bundle and is imported by core as kratos.subagent.detect -- the same file on both
sides (the protocol.py pattern), so core and an agent can never judge an event
differently.

A rule pack is DATA: JSON with closed operators only -- no code, no expressions,
no regular expressions. `load_pack()` validates the whole pack against the closed
schema below (size caps included) and refuses it whole on the first problem; a
pack is never partly applied. Evaluation is bounded per event: every leaf is a
plain comparison or a linear-time wildcard match over a length-capped value.

Pack:
  {"format": "kratos-detect-pack", "format_version": 1,
   "pack_id": "sigma-linux", "pack_version": 3,      (monotonically increasing)
   "source": {...provenance...}, "notice": "...",
   "rules": [RULE, ...], "skipped": [{...}, ...],
   "sha256": "<hex>"}   sha256 of canonical JSON of the pack without "sha256"

RULE:
  {"id": "SIGMA-1a2b3c4d", "title", "level": info|low|medium|high|critical,
   "author", "sigma_id", "license", "status", "description", "date", "modified",
   "source": {"path", "commit", "url"}, "tags": [...], "attack": [...],
   "references": [...], "falsepositives": [...],
   "logsource": {"product", "service", "category"},
   "scope": {"datasets": [...], "where": NODE | null},
   "match": NODE,
   "count": null | {"window_seconds", "group_by": FIELD | null, "op": "gte"|"gt", "threshold"},
   "samples": {"match": [EVENT, ...], "no_match": [EVENT, ...]}}

NODE (closed):
  {"op": "all_of"|"any_of", "args": [NODE, ...]}      {"op": "not", "arg": NODE}
  {"op": "eq"|"contains"|"startswith"|"endswith", "field": F, "value": S, "cased"?: bool, "index"?: int}
  {"op": "wildcard", "field": F, "pattern": S, "cased"?, "index"?}   `*` any run, `?` one character,
                                                                      a backslash escapes * ? and itself
  {"op": "in", "field": F, "values": [S, ...], "cased"?, "index"?}   equal to any of them
  {"op": "cidr", "field": F, "values": ["10.0.0.0/8", ...]}
  {"op": "exists", "field": F, "value": bool}

Matching is case-insensitive unless "cased" is true (as Sigma specifies). A leaf
on an array field matches when any element matches, or only element `index`
when it is given. A missing field never matches (and `exists: false` does).

EVENT: a flat dict of ECS field name -> str | int | float | bool | [str, ...],
with "event.id" and "event.dataset" present. Evaluation takes the event's time
(epoch seconds) separately.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import OrderedDict, deque
from typing import Any, Deque, Dict, FrozenSet, Iterable, List, Optional, Tuple

FORMAT = "kratos-detect-pack"
FORMAT_VERSION = 1

# ---- size caps (a pack over any of these is refused whole) -------------------
MAX_PACK_BYTES = 8 * 1024 * 1024
MAX_RULES = 1000
MAX_NODES_PER_RULE = 512          # match + scope.where together
MAX_DEPTH = 32
MAX_CHILDREN = 256
MAX_IN_VALUES = 512
MAX_STRING_BYTES = 1024           # a value or pattern in a rule
MAX_WILDCARDS = 32                # `*` and `?` in one pattern
MAX_TEXT_BYTES = 4096             # titles, descriptions
MAX_LIST_ITEMS = 64               # tags, references, datasets, ...
MAX_SAMPLES = 8                   # per kind
MAX_WINDOW_SECONDS = 86400
MAX_THRESHOLD = 10000
MAX_INDEX = 63
# Evaluation bounds
MAX_VALUE_CHARS = 65536           # a longer value is evaluated over its first 64 Ki characters
MAX_GROUPS_PER_RULE = 10000       # count-rule groups held at once (least recently seen dropped first)
MAX_HELD_PER_RULE = 200000        # (time, event id) pairs one counting rule holds across its groups
MAX_MATCHED_IDS = 100             # event ids one detection lists

LEVELS = ("info", "low", "medium", "high", "critical")
COUNT_OPS = ("gte", "gt")
LEAF_STRING_OPS = ("eq", "contains", "startswith", "endswith")
ALL_OPS = ("all_of", "any_of", "not", "eq", "contains", "startswith", "endswith", "wildcard", "in", "cidr", "exists")

# The event fields a rule may name (ECS names, plus Kratos's own). A core test keeps
# this a subset of kratos/events/fields.py.
FIELDS: FrozenSet[str] = frozenset({
    "@timestamp", "event.id", "event.kind", "event.category", "event.type", "event.action", "event.outcome",
    "event.dataset", "event.provider", "event.original", "event.sequence", "message",
    "host.name", "user.name", "user.id", "user.effective.name", "user.effective.id", "user.target.name",
    "group.name", "source.ip", "source.port", "destination.ip", "destination.port", "network.transport",
    "process.name", "process.pid", "process.parent.pid", "process.executable", "process.command_line",
    "process.args", "process.working_directory", "file.path", "file.hash.sha256", "service.name",
    "log.file.path", "log.syslog.priority", "package.name", "package.version", "url.original",
    "http.request.method", "http.response.status_code", "user_agent.original",
    "kratos.audit.types", "kratos.audit.key", "kratos.audit.syscall", "kratos.audit.paths",
    "kratos.audit.created_paths",
})
# Array fields whose order means something (an index may select one element).
ORDERED_FIELDS: FrozenSet[str] = frozenset({"process.args", "kratos.audit.paths"})
# The fields a counting rule may group by: identities, never free text.
GROUPABLE: FrozenSet[str] = frozenset({
    "source.ip", "destination.ip", "user.name", "user.target.name", "user.effective.name", "process.executable",
    "process.name", "service.name", "file.path", "host.name",
})
# Datasets a rule may be scoped to.
DATASETS: FrozenSet[str] = frozenset({
    "kratos.auth", "kratos.journal", "kratos.privileged_accounts", "kratos.auditd", "kratos.cron",
    "kratos.systemd", "kratos.firewall", "kratos.package", "kratos.web",
})

_RULE_KEYS = frozenset({"id", "title", "level", "author", "sigma_id", "license", "status", "description", "date",
                        "modified", "source", "tags", "attack", "references", "falsepositives", "logsource",
                        "scope", "match", "count", "samples"})
_RULE_REQUIRED = ("id", "title", "level", "author", "license", "scope", "match")
_PACK_KEYS = frozenset({"format", "format_version", "pack_id", "pack_version", "source", "notice", "rules",
                        "skipped", "sha256"})
_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
_PACK_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")


class PackError(ValueError):
    """A rule pack that fails validation. The whole pack is refused."""


# ---------------------------------------------------------------------------
# canonical form and digest
# ---------------------------------------------------------------------------
def canonical_bytes(obj: Any) -> bytes:
    """The one serialisation the digest is computed over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pack_digest(pack: Dict[str, Any]) -> str:
    """sha256 hex of the canonical JSON of `pack` without its "sha256" key."""
    body = {k: v for k, v in pack.items() if k != "sha256"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def _utf8_len(s: str) -> int:
    return len(s.encode("utf-8", "surrogatepass"))


def _str(value: Any, where: str, limit: int = MAX_STRING_BYTES, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise PackError("%s must be a string" % where)
    if not allow_empty and not value:
        raise PackError("%s must not be empty" % where)
    if _utf8_len(value) > limit:
        raise PackError("%s is longer than %d bytes" % (where, limit))
    return value


def _str_list(value: Any, where: str, limit_items: int = MAX_LIST_ITEMS, limit: int = MAX_STRING_BYTES) -> List[str]:
    if not isinstance(value, list):
        raise PackError("%s must be a list" % where)
    if len(value) > limit_items:
        raise PackError("%s has more than %d items" % (where, limit_items))
    return [_str(v, "%s[%d]" % (where, i), limit) for i, v in enumerate(value)]


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PackError("%s must be true or false" % where)
    return value


def _int(value: Any, where: str, lo: int, hi: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise PackError("%s must be a whole number %d-%d" % (where, lo, hi))
    return value


def _field(value: Any, where: str) -> str:
    name = _str(value, where, 64, allow_empty=False)
    if name not in FIELDS:
        raise PackError("%s: %r is not a field rules may use" % (where, name))
    return name


def _check_keys(node: Dict[str, Any], allowed: Iterable[str], where: str) -> None:
    extra = set(node) - set(allowed)
    if extra:
        raise PackError("%s: unknown key(s) %s" % (where, sorted(extra)))


def wildcard_count(pattern: str) -> int:
    n, i = 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            i += 2
            continue
        if c in "*?":
            n += 1
        i += 1
    return n


class _Counter:
    __slots__ = ("nodes",)

    def __init__(self) -> None:
        self.nodes = 0


def _validate_node(node: Any, where: str, depth: int, counter: _Counter) -> None:
    if depth > MAX_DEPTH:
        raise PackError("%s: nested deeper than %d" % (where, MAX_DEPTH))
    counter.nodes += 1
    if counter.nodes > MAX_NODES_PER_RULE:
        raise PackError("%s: more than %d nodes in one rule" % (where, MAX_NODES_PER_RULE))
    if not isinstance(node, dict):
        raise PackError("%s must be an object" % where)
    op = node.get("op")
    if op not in ALL_OPS:
        raise PackError("%s: unknown operator %r" % (where, op))
    if op in ("all_of", "any_of"):
        _check_keys(node, ("op", "args"), where)
        args = node.get("args")
        if not isinstance(args, list) or not args:
            raise PackError("%s: %s needs a non-empty list of args" % (where, op))
        if len(args) > MAX_CHILDREN:
            raise PackError("%s: more than %d args" % (where, MAX_CHILDREN))
        for i, child in enumerate(args):
            _validate_node(child, "%s.args[%d]" % (where, i), depth + 1, counter)
        return
    if op == "not":
        _check_keys(node, ("op", "arg"), where)
        _validate_node(node.get("arg"), where + ".arg", depth + 1, counter)
        return
    field = _field(node.get("field"), where + ".field")
    if op == "exists":
        _check_keys(node, ("op", "field", "value"), where)
        _bool(node.get("value"), where + ".value")
        return
    if op == "cidr":
        _check_keys(node, ("op", "field", "values"), where)
        values = _str_list(node.get("values"), where + ".values", MAX_IN_VALUES, 64)
        if not values:
            raise PackError("%s: cidr needs at least one network" % where)
        for v in values:
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise PackError("%s: %r is not a network" % (where, v))
        return
    allowed = ["op", "field", "cased", "index"]
    if op == "in":
        allowed.append("values")
        _check_keys(node, allowed, where)
        values = _str_list(node.get("values"), where + ".values", MAX_IN_VALUES)
        if not values:
            raise PackError("%s: in needs at least one value" % where)
    elif op == "wildcard":
        allowed.append("pattern")
        _check_keys(node, allowed, where)
        pattern = _str(node.get("pattern"), where + ".pattern")
        if wildcard_count(pattern) > MAX_WILDCARDS:
            raise PackError("%s: more than %d wildcards in one pattern" % (where, MAX_WILDCARDS))
    else:
        allowed.append("value")
        _check_keys(node, allowed, where)
        _str(node.get("value"), where + ".value")
    if "cased" in node:
        _bool(node["cased"], where + ".cased")
    if "index" in node:
        _int(node["index"], where + ".index", 0, MAX_INDEX)
        if field not in ORDERED_FIELDS:
            raise PackError("%s: %s is not a list whose positions can be chosen" % (where, field))


def _validate_event(ev: Any, where: str) -> None:
    if not isinstance(ev, dict):
        raise PackError("%s must be an object" % where)
    if len(ev) > 64:
        raise PackError("%s has too many fields" % where)
    for k, v in ev.items():
        if k not in FIELDS:
            raise PackError("%s: %r is not an event field" % (where, k))
        if isinstance(v, list):
            _str_list(v, "%s.%s" % (where, k), MAX_LIST_ITEMS, MAX_TEXT_BYTES)
        elif isinstance(v, str):
            _str(v, "%s.%s" % (where, k), MAX_TEXT_BYTES)
        elif not isinstance(v, (int, float)) or isinstance(v, bool):
            raise PackError("%s.%s must be text, a number or a list of text" % (where, k))


def _validate_rule(rule: Any, where: str) -> str:
    if not isinstance(rule, dict):
        raise PackError("%s must be an object" % where)
    _check_keys(rule, _RULE_KEYS, where)
    for key in _RULE_REQUIRED:
        if key not in rule:
            raise PackError("%s: %s is missing" % (where, key))
    rid = _str(rule["id"], where + ".id", 64, allow_empty=False)
    if not set(rid) <= _ID_CHARS or "-" not in rid or rid.startswith("-") or rid.endswith("-") or "--" in rid:
        raise PackError("%s: rule id %r is not like SIGMA-1a2b3c4d (upper case)" % (where, rid))
    where = "rule %s" % rid
    _str(rule["title"], where + ".title", 256, allow_empty=False)
    if rule["level"] not in LEVELS:
        raise PackError("%s: level must be one of %s" % (where, ", ".join(LEVELS)))
    _str(rule["author"], where + ".author", 1024, allow_empty=False)
    _str(rule["license"], where + ".license", 64, allow_empty=False)
    for key in ("sigma_id", "status", "date", "modified"):
        if key in rule and rule[key] is not None:
            _str(rule[key], "%s.%s" % (where, key), 128)
    if "description" in rule and rule["description"] is not None:
        _str(rule["description"], where + ".description", MAX_TEXT_BYTES)
    for key in ("tags", "attack", "references", "falsepositives"):
        if key in rule and rule[key] is not None:
            _str_list(rule[key], "%s.%s" % (where, key))
    for key in ("source", "logsource"):
        if key in rule and rule[key] is not None:
            obj = rule[key]
            if not isinstance(obj, dict) or len(obj) > 8:
                raise PackError("%s.%s must be a small object" % (where, key))
            for k, v in obj.items():
                _str(k, "%s.%s key" % (where, key), 64)
                if v is not None:
                    _str(v, "%s.%s.%s" % (where, key, k), MAX_STRING_BYTES)
    scope = rule["scope"]
    if not isinstance(scope, dict):
        raise PackError(where + ".scope must be an object")
    _check_keys(scope, ("datasets", "where"), where + ".scope")
    datasets = _str_list(scope.get("datasets"), where + ".scope.datasets", len(DATASETS), 64)
    if not datasets:
        raise PackError(where + ".scope.datasets must name at least one dataset")
    bad = [d for d in datasets if d not in DATASETS]
    if bad:
        raise PackError("%s.scope.datasets: unknown %s" % (where, bad))
    counter = _Counter()
    if scope.get("where") is not None:
        _validate_node(scope["where"], where + ".scope.where", 1, counter)
    _validate_node(rule["match"], where + ".match", 1, counter)
    count = rule.get("count")
    if count is not None:
        if not isinstance(count, dict):
            raise PackError(where + ".count must be an object")
        _check_keys(count, ("window_seconds", "group_by", "op", "threshold"), where + ".count")
        _int(count.get("window_seconds"), where + ".count.window_seconds", 1, MAX_WINDOW_SECONDS)
        _int(count.get("threshold"), where + ".count.threshold", 1, MAX_THRESHOLD)
        if count.get("op") not in COUNT_OPS:
            raise PackError("%s.count.op must be one of %s" % (where, ", ".join(COUNT_OPS)))
        gb = count.get("group_by")
        if gb is not None:
            _field(gb, where + ".count.group_by")
            if gb not in GROUPABLE:
                raise PackError("%s.count.group_by: %s can't be grouped by (only %s)"
                                % (where, gb, ", ".join(sorted(GROUPABLE))))
    samples = rule.get("samples")
    if samples is not None:
        if not isinstance(samples, dict):
            raise PackError(where + ".samples must be an object")
        _check_keys(samples, ("match", "no_match"), where + ".samples")
        for kind in ("match", "no_match"):
            items = samples.get(kind) or []
            if not isinstance(items, list) or len(items) > MAX_SAMPLES:
                raise PackError("%s.samples.%s must be a list of at most %d events" % (where, kind, MAX_SAMPLES))
            for i, ev in enumerate(items):
                _validate_event(ev, "%s.samples.%s[%d]" % (where, kind, i))
    return rid


def validate_pack(pack: Any, *, raw_size: Optional[int] = None) -> None:
    """Raise PackError (with the reason) unless `pack` is a valid, intact rule pack."""
    if raw_size is not None and raw_size > MAX_PACK_BYTES:
        raise PackError("the pack is larger than %d bytes" % MAX_PACK_BYTES)
    if not isinstance(pack, dict):
        raise PackError("a pack must be an object")
    _check_keys(pack, _PACK_KEYS, "pack")
    if pack.get("format") != FORMAT:
        raise PackError("not a Kratos detection pack (format %r)" % (pack.get("format"),))
    if pack.get("format_version") != FORMAT_VERSION:
        raise PackError("pack format version %r is not %d" % (pack.get("format_version"), FORMAT_VERSION))
    pid = _str(pack.get("pack_id"), "pack_id", 64, allow_empty=False)
    if not set(pid) <= _PACK_ID_CHARS:
        raise PackError("pack_id %r: lower-case letters, digits and - _ . only" % pid)
    _int(pack.get("pack_version"), "pack_version", 1, 2 ** 53)
    digest = pack.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise PackError("the pack carries no SHA-256")
    if pack_digest(pack) != digest:
        raise PackError("the pack's SHA-256 does not match its content (changed or damaged)")
    rules = pack.get("rules")
    if not isinstance(rules, list):
        raise PackError("rules must be a list")
    if len(rules) > MAX_RULES:
        raise PackError("more than %d rules" % MAX_RULES)
    if raw_size is None and len(canonical_bytes(pack)) > MAX_PACK_BYTES:
        raise PackError("the pack is larger than %d bytes" % MAX_PACK_BYTES)
    seen = set()
    for i, rule in enumerate(rules):
        rid = _validate_rule(rule, "rules[%d]" % i)
        if rid in seen:
            raise PackError("rule id %s appears twice" % rid)
        seen.add(rid)
    skipped = pack.get("skipped")
    if skipped is not None and (not isinstance(skipped, list) or len(skipped) > 4 * MAX_RULES):
        raise PackError("skipped must be a list")


def parse_pack_bytes(data: bytes) -> Dict[str, Any]:
    """JSON bytes -> a validated pack dict (PackError on anything wrong)."""
    if len(data) > MAX_PACK_BYTES:
        raise PackError("the pack is larger than %d bytes" % MAX_PACK_BYTES)
    try:
        pack = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise PackError("the pack is not valid JSON: %s" % e)
    validate_pack(pack, raw_size=len(data))
    return pack


# ---------------------------------------------------------------------------
# matching primitives
# ---------------------------------------------------------------------------
def split_wildcard(pattern: str) -> List[List[Optional[str]]]:
    """A glob -> segments between `*`; each segment is a list of characters where
    None stands for `?`. Backslash escapes `*`, `?` and itself."""
    segments: List[List[Optional[str]]] = [[]]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            segments[-1].append(pattern[i + 1])
            i += 2
            continue
        if c == "*":
            segments.append([])
        elif c == "?":
            segments[-1].append(None)
        else:
            segments[-1].append(c)
        i += 1
    return segments


class _Segment:
    """One fixed-length piece of a glob, found by str.find (no `?`) or by a
    bit-parallel Shift-And scan (with `?`): either way one pass over the text."""
    __slots__ = ("chars", "literal", "length", "masks", "accept")

    def __init__(self, chars: List[Optional[str]]):
        self.chars = chars
        self.length = len(chars)
        self.literal = None if None in chars else "".join(chars)  # type: ignore[arg-type]
        self.masks: Dict[str, int] = {}
        self.accept = 1 << (self.length - 1) if self.length else 0
        if self.literal is None:
            any_mask = 0
            for i, c in enumerate(chars):
                if c is None:
                    any_mask |= 1 << i
            self.masks = {"": any_mask}
            for i, c in enumerate(chars):
                if c is not None:
                    self.masks[c] = self.masks.get(c, any_mask) | (1 << i)

    def matches_at(self, text: str, pos: int) -> bool:
        if pos < 0 or pos + self.length > len(text):
            return False
        if self.literal is not None:
            return text.startswith(self.literal, pos)
        for i, c in enumerate(self.chars):
            if c is not None and text[pos + i] != c:
                return False
        return True

    def find_end(self, text: str, start: int) -> int:
        """End index of the earliest-ending occurrence at or after `start`, or -1."""
        if self.length == 0:
            return start
        if self.literal is not None:
            i = text.find(self.literal, start)
            return -1 if i < 0 else i + self.length
        masks, any_mask, accept = self.masks, self.masks[""], self.accept
        state = 0
        for i in range(start, len(text)):
            state = ((state << 1) | 1) & masks.get(text[i], any_mask)
            if state & accept:
                return i + 1
        return -1


class _Glob:
    __slots__ = ("segments",)

    def __init__(self, pattern: str):
        self.segments = [_Segment(s) for s in split_wildcard(pattern)]

    def match(self, text: str) -> bool:
        segs = self.segments
        if len(segs) == 1:
            seg = segs[0]
            return len(text) == seg.length and seg.matches_at(text, 0)
        first, last = segs[0], segs[-1]
        if len(text) < first.length + last.length:
            return False
        if not first.matches_at(text, 0):
            return False
        pos = first.length
        limit = len(text) - last.length
        for seg in segs[1:-1]:
            end = seg.find_end(text, pos)
            if end < 0 or end > limit:
                return False
            pos = end
        return pos <= limit and last.matches_at(text, limit)


def _norm(value: Any, cased: bool) -> Optional[str]:
    if value is None or isinstance(value, bool):
        return None if value is None else ("true" if value else "false")
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    text = value if isinstance(value, str) else str(value)
    if len(text) > MAX_VALUE_CHARS:
        text = text[:MAX_VALUE_CHARS]
    return text if cased else text.lower()


# ---------------------------------------------------------------------------
# prepared rules
# ---------------------------------------------------------------------------
class _Leaf:
    __slots__ = ("op", "field", "cased", "index", "value", "values", "glob", "nets", "want")

    def __init__(self, node: Dict[str, Any]):
        self.op = node["op"]
        self.field = node["field"]
        self.cased = bool(node.get("cased", False))
        self.index = node.get("index")
        fold = (lambda s: s) if self.cased else (lambda s: s.lower())
        self.value = fold(node["value"]) if self.op in LEAF_STRING_OPS else None
        self.values = frozenset(fold(v) for v in node["values"]) if self.op == "in" else None
        self.glob = _Glob(fold(node["pattern"])) if self.op == "wildcard" else None
        self.nets = [ipaddress.ip_network(v, strict=False) for v in node["values"]] if self.op == "cidr" else None
        self.want = bool(node["value"]) if self.op == "exists" else None

    def _texts(self, event: Dict[str, Any], cache: Optional[Dict[Any, List[Optional[str]]]]) -> List[Optional[str]]:
        """The field's values as normalised text, computed once per event and case rule."""
        key = (self.field, self.index, self.cased)
        if cache is not None:
            got = cache.get(key)
            if got is not None:
                return got
        texts = [_norm(v, self.cased) for v in self._items(event)]
        if cache is not None:
            cache[key] = texts
        return texts

    def _items(self, event: Dict[str, Any]) -> List[Any]:
        raw = event.get(self.field)
        if raw is None:
            return []
        if isinstance(raw, (list, tuple)):
            if self.index is not None:
                return [raw[self.index]] if self.index < len(raw) else []
            return list(raw)
        if self.index is not None:
            return []
        return [raw]

    def test(self, event: Dict[str, Any], cache: Optional[Dict[Any, Any]] = None) -> bool:
        if self.op == "exists":
            items = self._items(event)
            present = any(v is not None and v != "" for v in items)
            return present == self.want
        if self.op == "cidr":
            for v in self._items(event):
                try:
                    ip = ipaddress.ip_address(str(v))
                except ValueError:
                    continue
                for net in self.nets or ():
                    if ip.version == net.version and ip in net:
                        return True
            return False
        for text in self._texts(event, cache):
            if text is None:
                continue
            if self.op == "eq":
                if text == self.value:
                    return True
            elif self.op == "contains":
                if self.value in text:  # type: ignore[operator]
                    return True
            elif self.op == "startswith":
                if text.startswith(self.value):  # type: ignore[arg-type]
                    return True
            elif self.op == "endswith":
                if text.endswith(self.value):  # type: ignore[arg-type]
                    return True
            elif self.op == "in":
                if text in self.values:  # type: ignore[operator]
                    return True
            elif self.op == "wildcard":
                if self.glob.match(text):  # type: ignore[union-attr]
                    return True
        return False


_FOLDABLE = ("eq", "contains", "startswith", "endswith", "wildcard", "in")


class _AnyText:
    """Several string tests on one field (same case rule and position) OR-ed together --
    an `any_of` folded at load time, so a long keyword list costs one pass over the values,
    not one call per keyword. Same answers as the separate leaves."""
    __slots__ = ("leaf", "eq", "contains", "starts", "ends", "globs")

    def __init__(self, leaves: List["_Leaf"]):
        self.leaf = leaves[0]
        self.eq = frozenset(v for lf in leaves for v in ([lf.value] if lf.op == "eq" else
                                                          (lf.values or ()) if lf.op == "in" else ()))
        self.contains = tuple(lf.value for lf in leaves if lf.op == "contains")
        self.starts = tuple(lf.value for lf in leaves if lf.op == "startswith")
        self.ends = tuple(lf.value for lf in leaves if lf.op == "endswith")
        self.globs = tuple(lf.glob for lf in leaves if lf.op == "wildcard")

    def test(self, event: Dict[str, Any], cache: Optional[Dict[Any, Any]] = None) -> bool:
        for text in self.leaf._texts(event, cache):
            if text is None:
                continue
            if text in self.eq:
                return True
            if self.starts and text.startswith(self.starts):
                return True
            if self.ends and text.endswith(self.ends):
                return True
            for c in self.contains:
                if c in text:
                    return True
            for g in self.globs:
                if g.match(text):  # type: ignore[union-attr]
                    return True
        return False


class _Node:
    __slots__ = ("op", "children", "leaf")

    def __init__(self, node: Dict[str, Any]):
        self.op = node["op"]
        self.leaf = None
        self.children: List[Any] = []
        if self.op == "any_of":
            groups: "OrderedDict[Any, List[_Leaf]]" = OrderedDict()
            for c in node["args"]:
                if c.get("op") in _FOLDABLE:
                    lf = _Leaf(c)
                    groups.setdefault((lf.field, lf.cased, lf.index), []).append(lf)
                else:
                    self.children.append(_Node(c))
            for leaves in groups.values():
                if len(leaves) == 1:
                    n = _Node.__new__(_Node)
                    n.op, n.leaf, n.children = leaves[0].op, leaves[0], []
                    self.children.append(n)
                else:
                    self.children.append(_AnyText(leaves))
        elif self.op == "all_of":
            self.children = [_Node(c) for c in node["args"]]
        elif self.op == "not":
            self.children = [_Node(node["arg"])]
        else:
            self.leaf = _Leaf(node)

    def test(self, event: Dict[str, Any], cache: Optional[Dict[Any, Any]] = None) -> bool:
        if self.leaf is not None:
            return self.leaf.test(event, cache)
        if self.op == "all_of":
            for c in self.children:
                if not c.test(event, cache):
                    return False
            return True
        if self.op == "any_of":
            for c in self.children:
                if c.test(event, cache):
                    return True
            return False
        return not self.children[0].test(event, cache)


class Rule:
    """A validated rule, prepared for evaluation. `meta` is the rule's JSON."""
    __slots__ = ("id", "meta", "datasets", "where", "where_key", "match", "count")

    def __init__(self, rule: Dict[str, Any]):
        self.id = rule["id"]
        self.meta = rule
        self.datasets = frozenset(rule["scope"]["datasets"])
        where = rule["scope"].get("where")
        self.where = _Node(where) if where is not None else None
        # rules of one log source share its condition: tested once per event (cache)
        self.where_key = ("where", canonical_bytes(where)) if where is not None else None
        self.match = _Node(rule["match"])
        self.count = rule.get("count")

    def applies(self, event: Dict[str, Any], cache: Optional[Dict[Any, Any]] = None) -> bool:
        """The event is of a kind this rule looks at (its log source)."""
        if event.get("event.dataset") not in self.datasets:
            return False
        if self.where is None:
            return True
        if cache is not None:
            got = cache.get(self.where_key)
            if got is None:
                got = cache[self.where_key] = self.where.test(event, cache)
            return got
        return self.where.test(event)

    def matches(self, event: Dict[str, Any], cache: Optional[Dict[Any, Any]] = None) -> bool:
        """The event satisfies the rule's condition (a counting rule: one counted event).
        `cache`: one dict per event, shared across rules, so each value is normalised once."""
        return self.applies(event, cache) and self.match.test(event, cache)


class Pack:
    """A validated, prepared rule pack."""

    def __init__(self, pack: Dict[str, Any]):
        self.raw = pack
        self.pack_id = pack["pack_id"]
        self.version = pack["pack_version"]
        self.sha256 = pack["sha256"]
        self.rules = [Rule(r) for r in pack["rules"]]
        self.by_id = {r.id: r for r in self.rules}


def load_pack(pack: Dict[str, Any]) -> Pack:
    """Validate then prepare. PackError if anything is wrong -- nothing is half-loaded."""
    validate_pack(pack)
    return Pack(pack)


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------
class Match:
    """One detection: a single-event rule's match, or a counting rule crossing its threshold."""
    __slots__ = ("rule_id", "event_id", "ts", "group", "count", "event_ids", "first_ts")

    def __init__(self, rule_id: str, event_id: str, ts: float, group: Optional[str] = None,
                 count: Optional[int] = None, event_ids: Optional[List[str]] = None,
                 first_ts: Optional[float] = None):
        self.rule_id = rule_id
        self.event_id = event_id
        self.ts = ts
        self.group = group
        self.count = count
        self.event_ids = event_ids or [event_id]
        self.first_ts = ts if first_ts is None else first_ts

    def as_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "event_id": self.event_id, "ts": self.ts, "group": self.group,
                "count": self.count, "event_ids": list(self.event_ids), "first_ts": self.first_ts}


def _group_value(event: Dict[str, Any], field: Optional[str]) -> Optional[str]:
    if field is None:
        return ""
    v = event.get(field)
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if v is None or v == "":
        return None
    text = str(v)
    return text[:256]


class _CountState:
    """Sliding windows for one counting rule: per group the newest `threshold`
    (time, event id) pairs -- enough to know whether `threshold` events fall in the
    window -- and when the group last fired (one detection per group per window).
    Events are expected in time order; the window is measured back from the newest.
    Memory is bounded: at most MAX_HELD_PER_RULE pairs across all groups, the least
    recently seen groups dropped first."""
    __slots__ = ("window", "threshold", "groups", "fired", "held")

    def __init__(self, window: int, threshold: int):
        self.window = window
        self.threshold = threshold
        self.groups: "OrderedDict[str, Tuple[Deque[Tuple[float, str]], set]]" = OrderedDict()
        self.fired: Dict[str, float] = {}
        self.held = 0

    def _drop_oldest_group(self) -> None:
        old, (dq, _ids) = self.groups.popitem(last=False)
        self.held -= len(dq)
        self.fired.pop(old, None)

    def add_quiet(self, group: str, ts: float, event_id: str) -> None:
        """Hold an event in its group's window without firing (a restored checkpoint)."""
        fired = self.fired.get(group)
        self.add(group, ts, event_id)
        if fired is None:
            self.fired.pop(group, None)
        else:
            self.fired[group] = fired

    def add(self, group: str, ts: float, event_id: str) -> Optional[Tuple[int, List[str], float]]:
        entry = self.groups.get(group)
        if entry is None:
            entry = (deque(), set())
            self.groups[group] = entry
            while len(self.groups) > MAX_GROUPS_PER_RULE:
                self._drop_oldest_group()
        else:
            self.groups.move_to_end(group)
        dq, ids = entry
        if event_id in ids:
            return None                                  # the same event fed twice
        if len(dq) >= self.threshold:
            _t, old = dq.popleft()
            ids.discard(old)
            self.held -= 1
        dq.append((ts, event_id))
        ids.add(event_id)
        self.held += 1
        while dq and dq[0][0] <= ts - self.window:
            _t, old = dq.popleft()
            ids.discard(old)
            self.held -= 1
        if dq and dq[-1][0] < dq[0][0]:
            # Out of time order (a machine whose clock jumped back, or lines stored late):
            # count only what lies within one window of this event, either side, so a jump
            # neither stretches the window nor makes an old burst count as a new one.
            keep = [(t, e) for t, e in dq if ts - self.window < t <= ts + self.window]
            kept = {e for _t, e in keep}
            for _t, e in dq:
                if e not in kept:
                    ids.discard(e)
            self.held -= len(dq) - len(keep)
            dq.clear()
            dq.extend(sorted(keep))
        while self.held > MAX_HELD_PER_RULE and len(self.groups) > 1:
            self._drop_oldest_group()
        if len(dq) < self.threshold:
            return None
        last = self.fired.get(group)
        if last is not None and ts - last < self.window:
            return None
        self.fired[group] = ts
        recent = [eid for _t, eid in dq][-MAX_MATCHED_IDS:]
        return len(dq), recent, dq[0][0]


class Evaluator:
    """Evaluates events against a pack, keeping counting-rule windows between calls.

    `disabled`: rule ids not to evaluate. `fired`: per counting rule, when each group
    last fired (saved by the caller between passes, so a burst that straddles two
    passes is reported once)."""

    def __init__(self, pack: Pack, disabled: Iterable[str] = (),
                 fired: Optional[Dict[str, Dict[str, float]]] = None):
        self.pack = pack
        self.disabled = frozenset(disabled)
        self.active = [r for r in pack.rules if r.id not in self.disabled]
        self.by_dataset: Dict[str, List[Rule]] = {}
        for r in self.active:                         # in pack order within each dataset
            for d in r.datasets:
                self.by_dataset.setdefault(d, []).append(r)
        self.counts: Dict[str, _CountState] = {}
        for r in self.active:
            if r.count:
                op_gt = r.count["op"] == "gt"
                st = _CountState(int(r.count["window_seconds"]), int(r.count["threshold"]) + (1 if op_gt else 0))
                st.fired.update((fired or {}).get(r.id, {}))
                self.counts[r.id] = st

    def fired_state(self, now: float) -> Dict[str, Dict[str, float]]:
        """When each counting rule's groups last fired, the ones still inside their window."""
        out: Dict[str, Dict[str, float]] = {}
        for rid, st in self.counts.items():
            keep = {g: t for g, t in st.fired.items() if now - t < st.window}
            if keep:
                out[rid] = keep
        return out

    def export_windows(self, now: float) -> Dict[str, Any]:
        """The counting rules' open windows and last fires, as plain JSON data -- what an
        agent checkpoints so a restart in the middle of a window keeps its count (C.2).
        Only what is still inside each rule's window is kept."""
        out: Dict[str, Any] = {}
        for rid, st in self.counts.items():
            groups = []
            for group, (dq, _ids) in st.groups.items():
                pairs = [[t, eid] for t, eid in dq if now - t < st.window]
                if pairs:
                    groups.append([group, pairs])
            fired = {g: t for g, t in st.fired.items() if now - t < st.window}
            if groups or fired:
                out[rid] = {"groups": groups, "fired": fired}
        return out

    def import_windows(self, saved: Any) -> int:
        """Restore what `export_windows` saved (rules no longer in the pack, or turned off,
        are ignored; anything malformed is skipped). Returns the events restored."""
        if not isinstance(saved, dict):
            return 0
        restored = 0
        for rid, data in saved.items():
            st = self.counts.get(rid)
            if st is None or not isinstance(data, dict):
                continue
            for item in (data.get("groups") or [])[:MAX_GROUPS_PER_RULE]:
                if not (isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)
                        and isinstance(item[1], list)):
                    continue
                group = item[0][:256]
                for pair in item[1][-st.threshold:]:
                    if (isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], (int, float))
                            and not isinstance(pair[0], bool) and isinstance(pair[1], str)):
                        st.add_quiet(group, float(pair[0]), pair[1][:64])
                        restored += 1
            fired = data.get("fired")
            if isinstance(fired, dict):
                for g, t in list(fired.items())[:MAX_GROUPS_PER_RULE]:
                    if isinstance(g, str) and isinstance(t, (int, float)) and not isinstance(t, bool):
                        st.fired[g[:256]] = float(t)
        return restored

    @property
    def has_counting_rules(self) -> bool:
        return bool(self.counts)

    @property
    def longest_window(self) -> int:
        return max((st.window for st in self.counts.values()), default=0)

    def evaluate(self, event: Dict[str, Any], ts: float, history: bool = False) -> List[Match]:
        """The detections `event` raises. `history=True`: an event already evaluated in an
        earlier pass, fed again only so counting windows see it -- it raises nothing
        itself, and a group it carries over its threshold is treated as already reported."""
        out: List[Match] = []
        eid = str(event.get("event.id") or "")
        cache: Dict[Any, Any] = {}
        for rule in self.by_dataset.get(str(event.get("event.dataset") or ""), ()):
            if history and rule.count is None:
                continue
            if not rule.matches(event, cache):
                continue
            if rule.count is None:
                out.append(Match(rule.id, eid, ts))
                continue
            group = _group_value(event, rule.count.get("group_by"))
            if group is None:
                continue
            hit = self.counts[rule.id].add(group, ts, eid)
            if hit is not None and not history:
                n, ids, first = hit
                out.append(Match(rule.id, eid, ts, group=group or None, count=n, event_ids=ids, first_ts=first))
        return out


def check_samples(pack: Pack) -> List[str]:
    """Every rule's samples through its own condition: problems found (empty = all pass)."""
    problems: List[str] = []
    for rule in pack.rules:
        samples = rule.meta.get("samples") or {}
        for kind, want in (("match", True), ("no_match", False)):
            for i, ev in enumerate(samples.get(kind) or []):
                if rule.matches(ev) != want:
                    problems.append("%s: %s sample %d %s" % (rule.id, kind, i, "did not match" if want else "matched"))
    return problems
