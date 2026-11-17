"""RFC 8785 JSON Canonicalization Scheme (JCS) -- the part an Agent Card needs.

A2A 1.0 §8.4 signs the card's canonical form: the card without `signatures`, with empty
values removed, serialised by JCS. Kratos's card holds only strings, booleans, whole
numbers, lists and objects, so this is the strict subset:

* objects: members sorted by their names' UTF-16 code units (RFC 8785 §3.2.3);
* strings: `"` and `\\` escaped, U+0008/0009/000A/000C/000D as \\b \\t \\n \\f \\r, every
  other character below U+0020 as \\u00xx (lower-case hex); everything else as itself,
  UTF-8 encoded (§3.2.2.2);
* whole numbers in the IEEE-754 safe range as their decimal digits; booleans and null as
  literals.

Anything else -- a float, a lone surrogate, a non-string key, nesting deeper than
MAX_DEPTH -- raises CanonicalizationError rather than guessing (a wrong canonical form
would make every signature fail to verify, silently).
"""
from __future__ import annotations

from typing import Any

MAX_DEPTH = 32
_SAFE_INT = 2 ** 53 - 1
_SHORT = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r", '"': '\\"', "\\": "\\\\"}


class CanonicalizationError(ValueError):
    pass


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise CanonicalizationError("a lone surrogate can't be canonicalized")
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _value(v: Any, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH}")
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > _SAFE_INT:
            raise CanonicalizationError("a whole number outside the IEEE-754 safe range")
        return str(v)
    if isinstance(v, float):
        raise CanonicalizationError("floating-point numbers are not used in a Kratos card")
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_value(x, depth + 1) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonicalizationError("object member names must be strings")
        # UTF-16 code-unit order; big-endian UTF-16 bytes compare the same way, and
        # surrogates are rejected by _string below.
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _value(val, depth + 1) for k, val in items) + "}"
    raise CanonicalizationError(f"can't canonicalize a {type(v).__name__}")


def canonicalize(value: Any) -> str:
    """The JCS text of `value` (encode it as UTF-8 to sign it)."""
    return _value(value, 1)


def clean_empty(value: Any) -> Any:
    """What A2A 1.0 removes before canonicalizing: empty strings, lists and objects, at every
    level (None for a value that is itself empty). False and 0 stay."""
    if isinstance(value, dict):
        out = {k: c for k, v in value.items() if (c := clean_empty(v)) is not None}
        return out or None
    if isinstance(value, list):
        out_l = [c for v in value if (c := clean_empty(v)) is not None]
        return out_l or None
    if isinstance(value, str) and not value:
        return None
    return value
