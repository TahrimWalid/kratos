"""What a person hunts for: one indicator, classified strictly (C.3 §3.2).

Kinds: an address (`ip`, one IPv4/IPv6 address or a CIDR network), a SHA-256 file
hash (`sha256`), an account name (`account`), a domain or host name (`domain`), a
program name (`program`) and a path (`path` -- a file or a program's full path).

The kind is detected by strict parsers (`ipaddress` for addresses); anything that
fits more than one kind is AMBIGUOUS and the caller asks the person which they
meant (or the person forces it with `--type`). MD5 and SHA-1 are refused with the
reason: Kratos keeps SHA-256 hashes only, so a "not found" for them would mean
nothing.

Normalised forms: compressed addresses and networks (`2001:db8::1`,
`10.0.0.0/8`), lower-case hashes and domains (a trailing dot dropped). Accounts,
programs and paths keep their case -- they are case-sensitive on Linux.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

KINDS = ("ip", "sha256", "account", "domain", "program", "path")
KIND_LABELS = {"ip": "address", "sha256": "SHA-256 file hash", "account": "account name",
               "domain": "domain or host name", "program": "program name", "path": "file or program path"}
# what people type for --type
KIND_ALIASES = {"ip": "ip", "address": "ip", "addr": "ip", "cidr": "ip", "network": "ip",
                "sha256": "sha256", "hash": "sha256", "account": "account", "user": "account",
                "username": "account", "domain": "domain", "host": "domain", "hostname": "domain",
                "program": "program", "process": "program", "exe": "program", "path": "path", "file": "path"}
MAX_INDICATORS = 10
MAX_LEN = 1024

_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_ACCOUNT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\$?$")
_PROGRAM = re.compile(r"^[A-Za-z0-9_+][A-Za-z0-9_.+:-]{0,254}$")
_LABEL = r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")
_PATH = re.compile(r"^/[^\x00-\x1f\x7f]{0,4095}$")
# A dotted word ending in one of these is as likely a script or program as a host name
# (`update.sh`, `payload.py`): ask rather than guess.
_PROGRAM_SUFFIXES = frozenset({"sh", "bash", "py", "pl", "rb", "php", "js", "so", "bin", "elf", "exe", "out",
                               "run", "jar", "lua", "ko"})
# A dotted word whose last label is a number (`python3.10`, `libc.so.6`) isn't a domain.
_NUMERIC_LAST = re.compile(r"\.\d+$")


class IndicatorError(ValueError):
    """An indicator Kratos can't hunt for, with the reason in plain words."""


@dataclass(frozen=True)
class Indicator:
    kind: str                # one of KINDS
    value: str               # the normalised value
    typed: str               # what the person typed (shown back, trimmed)

    @property
    def label(self) -> str:
        return KIND_LABELS[self.kind]

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        """The network for an address indicator (a single address is a /32 or /128)."""
        if self.kind != "ip":
            return None
        return ipaddress.ip_network(self.value, strict=False)

    @property
    def is_cidr(self) -> bool:
        net = self.network
        return net is not None and net.num_addresses > 1

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value, "label": self.label}


@dataclass(frozen=True)
class Ambiguous:
    """`typed` fits several kinds: the person picks one."""
    typed: str
    options: tuple[str, ...]
    reason: str = ""

    def question(self) -> str:
        names = " or ".join(("an " if KIND_LABELS[k][0] in "aeiou" else "a ") + KIND_LABELS[k] for k in self.options)
        return f"{self.typed!r} could be {names}. Which one?"


@dataclass
class Parsed:
    indicators: list[Indicator] = field(default_factory=list)
    ambiguous: list[Ambiguous] = field(default_factory=list)


def kind_of(text: str) -> str:
    """The kind a --type value names, or raise."""
    k = KIND_ALIASES.get(str(text or "").strip().lower())
    if k is None:
        raise IndicatorError(f"unknown type {text!r}: use one of {', '.join(KINDS)}")
    return k


def _as_ip(text: str) -> str | None:
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return net.compressed if net.num_addresses > 1 else net.network_address.compressed
        addr = ipaddress.ip_address(text)
        if addr.version == 6 and addr.ipv4_mapped is not None:   # ::ffff:203.0.113.9 is 203.0.113.9
            addr = addr.ipv4_mapped
        return addr.compressed
    except ValueError:
        return None


def _refuse_hash(text: str) -> None:
    if _HEX.match(text):
        if len(text) == 32:
            raise IndicatorError(f"{text!r} looks like an MD5 hash: Kratos keeps SHA-256 hashes only, so it "
                                 "can't hunt for MD5 -- use the file's SHA-256")
        if len(text) == 40:
            raise IndicatorError(f"{text!r} looks like a SHA-1 hash: Kratos keeps SHA-256 hashes only, so it "
                                 "can't hunt for SHA-1 -- use the file's SHA-256")


def _normal(kind: str, text: str) -> str:
    """The normalised value of `text` as `kind`, or raise."""
    if kind == "ip":
        v = _as_ip(text)
        if v is None:
            raise IndicatorError(f"{text!r} is not an IPv4/IPv6 address or network")
        return v
    if kind == "sha256":
        _refuse_hash(text)
        if len(text) != 64 or not _HEX.match(text):
            raise IndicatorError(f"{text!r} is not a SHA-256 hash (64 hex digits)")
        return text.lower()
    if kind == "domain":
        v = text.rstrip(".").lower()
        if len(v) > 253 or not (_DOMAIN.match(v) or re_single(v)):
            raise IndicatorError(f"{text!r} is not a domain or host name")
        return v
    if kind == "account":
        if not _ACCOUNT.match(text):
            raise IndicatorError(f"{text!r} is not an account name")
        return text
    if kind == "program":
        if text.startswith("/"):
            raise IndicatorError(f"{text!r} is a path: hunt it as a path (it covers programs run from there)")
        if not _PROGRAM.match(text):
            raise IndicatorError(f"{text!r} is not a program name")
        return text
    if kind == "path":
        if not _PATH.match(text):
            raise IndicatorError(f"{text!r} is not an absolute path")
        return text.rstrip("/") or "/"
    raise IndicatorError(f"unknown type {kind!r}")


def re_single(v: str) -> bool:
    """A one-label host name (`web01`) -- only when the person forces the type."""
    return bool(re.fullmatch(_LABEL, v))


def classify(text: str, forced: str | None = None) -> Indicator | Ambiguous:
    """One indicator, or the kinds it might be. Raises IndicatorError for something
    Kratos can't hunt for (with the reason)."""
    typed = str(text or "").strip()
    if not typed:
        raise IndicatorError("nothing to hunt for")
    if len(typed) > MAX_LEN:
        raise IndicatorError(f"an indicator is at most {MAX_LEN} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in typed):
        raise IndicatorError("an indicator can't contain control characters")
    if forced is not None:
        kind = kind_of(forced)
        return Indicator(kind, _normal(kind, typed), typed)

    if (ip := _as_ip(typed)) is not None:
        return Indicator("ip", ip, typed)
    if re.fullmatch(r"[0-9.:/]+", typed) and any(c in typed for c in ".:"):
        raise IndicatorError(f"{typed!r} is not a valid IPv4/IPv6 address or network")
    _refuse_hash(typed)
    if len(typed) == 64 and _HEX.match(typed):
        return Indicator("sha256", typed.lower(), typed)
    if typed.startswith("/"):
        return Indicator("path", _normal("path", typed), typed)
    if "/" in typed or " " in typed:
        raise IndicatorError(f"{typed!r} is not an address, hash, account, domain, program or absolute path")
    low = typed.rstrip(".").lower()
    if "." in typed and _DOMAIN.match(low) and not _NUMERIC_LAST.search(low):
        last = low.rsplit(".", 1)[-1]
        if last in _PROGRAM_SUFFIXES:
            return Ambiguous(typed, ("domain", "program"), "it ends like a script or program name")
        return Indicator("domain", low, typed)
    options = tuple(k for k, ok in (("account", bool(_ACCOUNT.match(typed))),
                                    ("program", bool(_PROGRAM.match(typed)))) if ok)
    if not options:
        raise IndicatorError(f"{typed!r} is not an address, hash, account, domain, program or absolute path")
    if len(options) == 1:
        return Indicator(options[0], typed, typed)
    return Ambiguous(typed, options, "a single word can be an account or a program")


def parse(texts: list[str] | str, forced: str | None = None) -> Parsed:
    """Several indicators (a list, or one string split on whitespace and commas).
    Raises IndicatorError for any that can't be hunted, or for too many."""
    if isinstance(texts, str):
        items = [t for t in re.split(r"[\s,]+", texts.strip()) if t]
    else:
        items = [str(t).strip() for t in texts if str(t).strip()]
    if not items:
        raise IndicatorError("nothing to hunt for")
    if len(items) > MAX_INDICATORS:
        raise IndicatorError(f"at most {MAX_INDICATORS} indicators per hunt")
    out = Parsed()
    seen: set[tuple[str, str]] = set()
    for t in items:
        got = classify(t, forced)
        if isinstance(got, Ambiguous):
            out.ambiguous.append(got)
        elif (got.kind, got.value) not in seen:
            seen.add((got.kind, got.value))
            out.indicators.append(got)
    return out
