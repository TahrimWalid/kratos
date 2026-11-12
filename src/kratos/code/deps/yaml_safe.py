"""The ONLY YAML entry point in Kratos (E.7a gate decision, 2026-11-12).

YAML here reads one thing: a ``pnpm-lock.yaml`` from a monitored machine, which an attacker
may have written. ``safe_load`` alone stops arbitrary objects but not alias expansion (a few
KB of nested ``&a`` / ``*a`` -- "billion laughs") and not deep nesting (libyaml's composer
recurses). So, before any object is built, the parser's EVENTS are checked: any anchor or
alias, or nesting deeper than ``MAX_DEPTH``, refuses the file. pnpm never writes anchors.
Only then is the document constructed, with ``CSafeLoader`` (``SafeLoader`` without libyaml).

Needs the optional ``code`` extra (PyYAML, MIT). Without it, ``available()`` is False and
the caller states the gap ("install kratos-security-assistant[code]"). A source-scan test
fails on any other PyYAML load call or full/unsafe loader anywhere in src/kratos.
"""
from __future__ import annotations

from typing import Any

MAX_DEPTH = 64
MAX_BYTES = 5 * 1024 * 1024

try:
    import yaml as _yaml
    _BASE = getattr(_yaml, "CSafeLoader", None) or _yaml.SafeLoader
except ImportError:  # the `code` extra is not installed
    _yaml = None  # type: ignore[assignment]
    _BASE = object  # type: ignore[assignment,misc]


class YamlRefused(ValueError):
    """The file was not read; the message says why in plain words."""


def available() -> bool:
    return _yaml is not None


if _yaml is not None:
    class NoAliasLoader(_BASE):  # type: ignore[misc,valid-type]
        """CSafeLoader (or SafeLoader) that is only ever used after `_check_events` passed."""
else:  # pragma: no cover -- without the extra
    NoAliasLoader = None  # type: ignore[assignment,misc]


def _check_events(text: str) -> None:
    loader = NoAliasLoader(text)
    depth = 0
    try:
        while loader.check_event():
            ev = loader.get_event()
            if isinstance(ev, _yaml.AliasEvent) or getattr(ev, "anchor", None) is not None:
                raise YamlRefused("it uses YAML anchors or aliases, which pnpm never writes (not a pnpm lockfile)")
            if isinstance(ev, (_yaml.SequenceStartEvent, _yaml.MappingStartEvent)):
                depth += 1
                if depth > MAX_DEPTH:
                    raise YamlRefused(f"it is nested deeper than {MAX_DEPTH} levels")
            elif isinstance(ev, (_yaml.SequenceEndEvent, _yaml.MappingEndEvent)):
                depth -= 1
    finally:
        loader.dispose()


def load(data: bytes | str) -> Any:
    """One YAML document from untrusted bytes, or YamlRefused. Never raises anything else
    for a bad file (YAML errors and deep recursion become YamlRefused)."""
    if _yaml is None:
        raise YamlRefused("YAML support is not installed (install kratos-security-assistant[code])")
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise YamlRefused("it is larger than Kratos reads")
        text = data.decode("utf-8", "replace")
    else:
        text = data
    try:
        _check_events(text)
        loader = NoAliasLoader(text)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except YamlRefused:
        raise
    except RecursionError:
        raise YamlRefused("it is nested too deeply to read") from None
    except _yaml.YAMLError as e:
        raise YamlRefused(f"it is not valid YAML ({type(e).__name__})") from None
