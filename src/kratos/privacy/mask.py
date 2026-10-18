"""Mask a request, restore a reply.

`Masker` is made per model request (`request_masker`), at the one choke point
(`llm_interface._metered_call`). It masks the system prompt and the prompt, and the
request site restores the text the model returns with the same object.

Masking, in order:

1. secrets -> `[REDACTED]` (`secrets.redact`), never restored;
2. Kratos's own frame markers and "this is data" line (A.4) are left exactly as written;
3. email addresses -> `EMAIL_n`;
4. account names -> `USER_n` (an account on the machine) or `INVALID_USER_n` (a name an
   attacker tried that doesn't exist); system accounts are never masked; in standard mode
   an image's default login (`ubuntu`, `ec2-user`) and common dictionary guesses that
   don't exist stay readable, and names shorter than 3 characters are left (and counted);
5. machine names -> `TARGET` (the machine under investigation) or `HOST_n`.
   How widely (4, 5): TRUSTED values -- the machine's account list, the configured
   login and targets, the sub-agents -- are replaced as whole words everywhere, except a
   word of Kratos's own fixed text (`vocabulary`); a value only SEEN in a log line or a
   field may be an attacker's text and is replaced only where it appeared as a name, so
   no log line can change what Kratos itself wrote;
6. IP addresses -> `TARGET_IP`, `PRIVATE_IP_n` or `PUBLIC_IP_n`; loopback, 0.0.0.0/::,
   multicast, broadcast and reserved addresses stay, and so does anything that reads as a
   package version (`1.2.3.4-1`, `"version": "1.2.3.4"`).

Restoring replaces only placeholders this scope issued (exact match, its random tag);
anything else that looks like one is left as written and counted.
"""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.privacy import accounts as _acct
from kratos.privacy import pseudonyms as _ps
from kratos.privacy.secrets import redact
from kratos.privacy.values import KnownValues
from kratos.privacy.vocabulary import request_vocabulary

# What the model is told (B.2 §5.3), added to the system prompt only when the request
# actually carries a placeholder. Nothing else about masking reaches the model.
MODEL_NOTE = ("Names, addresses and accounts are replaced with placeholders like USER_1, PUBLIC_IP_2 and "
              "TARGET. Use the placeholders exactly as written when you refer to them or pass them to a tool; "
              "Kratos puts the real values back.")

# --- Kratos's own text that is never masked ------------------------------------------
def _protected_re() -> re.Pattern[str]:
    from kratos.untrusted import ENVELOPE_RULE

    return re.compile(r"<<[a-z_]+ run=[0-9A-Za-z]+ id=[\w-]+>>|<<end id=[\w-]+>>|" + re.escape(ENVELOPE_RULE))


_PROTECTED = _protected_re()

# --- patterns --------------------------------------------------------------------------
_UNIT_SUFFIXES = frozenset({"service", "socket", "target", "timer", "slice", "scope", "mount", "path", "device",
                            "swap", "automount"})
# `name@instance.service` is a systemd unit, not a login: never read it as a name or a host.
_NOT_A_UNIT = r"(?![A-Za-z0-9_.:\\-]*\.(?:service|socket|target|timer|slice|scope|mount|path|device|swap|automount)\b)"
_EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?P<tld>[A-Za-z]{2,24})"
                       r"(?![\w-])")
_N = r"""(?P<n>[^\s"'\\(),;:]+?)"""
# (pattern, what it says about the name): "exists", "absent" (sshd: invalid user), "unknown"
_NAME_CONTEXTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"\b[Ii]nvalid user {_N} from\b"), "absent"),
    (re.compile(rf"\bFailed [\w/-]+ for invalid user {_N} from\b"), "absent"),
    (re.compile(rf"\bFailed [\w/-]+ for (?!invalid user ){_N} from\b"), "exists"),
    (re.compile(rf"\bAccepted [\w/-]+ for {_N} from\b"), "exists"),
    (re.compile(rf"\bsession (?:opened|closed) for user {_N}(?=[\s(\\\"',]|$)"), "exists"),
    (re.compile(rf"\bsudo(?:\[\d+\])?:\s+{_N}\s+:"), "exists"),
    (re.compile(rf"\bnew user: name={_N}(?=,)"), "exists"),
    (re.compile(rf"\b(?:user|account) '{_N}'"), "exists"),
    (re.compile(rf"\badd '{_N}' to (?:shadow )?group\b"), "exists"),
    (re.compile(rf"/home/{_N}(?=[/\s\"'\\]|$)"), "exists"),
    (re.compile(rf"\({_N}\) CMD \("), "exists"),
    (re.compile(rf"\b(?:r?user|logname)={_N}(?=[\s;,\\\"']|$)"), "unknown"),
    (re.compile(r"""(?P<q>\\?")(?:user|username|user_name|user\.name|login|owner|sudo_user|account_name)(?P=q)"""
                r"""\s*:\s*\\?"(?P<n>[^"\\]{1,64})\\?\""""), "unknown"),
    (re.compile(r"(?<![\w.%+-])(?P<n>[A-Za-z_][A-Za-z0-9_.-]{0,31})@(?=[A-Za-z0-9\[])" + _NOT_A_UNIT), "unknown"),
)
_NAME_LIST_RE = re.compile(r"""(?P<q>\\?")(?:members|users|accounts)(?P=q)\s*:\s*\[(?P<list>[^\]]{0,8000})\]""")
_LIST_ITEM_RE = re.compile(r'\\?"(?P<n>[^"\\]{1,64})\\?"')
_HOST_CONTEXTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![\w.%+-])[A-Za-z_][A-Za-z0-9_.-]{0,31}@" + _NOT_A_UNIT + r"(?P<h>[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)"
               r"(?![\w@-])"),
    re.compile(r"""(?P<q>\\?")(?:hostname|host_name|host\.name|host|fqdn)(?P=q)\s*:\s*\\?"(?P<h>[^"\\]{1,253})\\?\""""),
)
_HOSTNAME_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*$")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_$][A-Za-z0-9_.$-]*")
_IPV4_RE = re.compile(r"(?<![\w.])(?<!\d:)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?![\w-]|\.\d|[+~])")
_IPV6_RE = re.compile(r"(?<![\w:.])(?P<ip>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:.])")
_VERSION_CONTEXT_RE = re.compile(r"(?:version|installed|fixed|candidate|available|release)\w*\\?\"?\s*[:=]\s*\\?\"?$",
                                 re.IGNORECASE)

_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"))
# Documentation and benchmarking ranges stand for public addresses in labs and examples.
_PUBLIC_SPECIAL = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "2001:db8::/32"))


def ip_kind(text: str, target_ips: set[str] | frozenset[str] = frozenset()) -> tuple[str | None, str]:
    """(placeholder kind or None for never-masked, canonical address)."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None, text
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    canon = str(ip)
    if canon in target_ips:
        return "target_ip", canon
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or canon == "255.255.255.255":
        return None, canon
    if any(ip in net for net in _PUBLIC_SPECIAL):
        return "public_ip", canon
    if any(ip in net for net in _PRIVATE_NETS) or not ip.is_global:
        return "private_ip", canon
    return "public_ip", canon


@dataclass
class MaskStats:
    replaced: dict[str, int] = field(default_factory=dict)       # kind -> occurrences replaced
    secrets: int = 0
    short_names_left: int = 0
    names_context_only: int = 0
    mask_ms: float = 0.0
    restored: int = 0
    unknown_placeholders: list[str] = field(default_factory=list)  # placeholder-shaped text Kratos never issued
    untagged_lookalikes: int = 0
    restore_ms: float = 0.0
    storage_error: str | None = None

    def as_trace(self) -> dict[str, Any]:
        """Counts only -- never a value (the run record must not become a copy of the map)."""
        out: dict[str, Any] = {"masked": dict(sorted(self.replaced.items())), "secrets_removed": self.secrets,
                               "mask_ms": round(self.mask_ms, 2)}
        if self.short_names_left:
            out["short_names_not_masked"] = self.short_names_left
        if self.names_context_only:
            out["names_masked_only_in_context"] = self.names_context_only
        if self.storage_error:
            out["pseudonym_map_error"] = self.storage_error[:200]
        return out

    def restore_trace(self) -> dict[str, Any]:
        out: dict[str, Any] = {"restored": self.restored, "restore_ms": round(self.restore_ms, 2)}
        if self.unknown_placeholders:
            out["unknown_placeholders"] = sorted(set(self.unknown_placeholders))[:20]
        if self.untagged_lookalikes:
            out["untagged_lookalikes"] = self.untagged_lookalikes
        return out


@dataclass
class _Plan:
    """What one request's masking replaces: name -> kind, split by how widely."""
    whole: dict[str, str] = field(default_factory=dict)      # trusted account names, case-sensitive
    context: dict[str, str] = field(default_factory=dict)    # names replaced only where they appear as a name
    hosts: dict[str, str] = field(default_factory=dict)      # trusted machine names (lower-case) -> kind
    host_kinds: dict[str, str] = field(default_factory=dict)  # kinds already issued in this conversation
    short_left: set[str] = field(default_factory=set)


class Masker:
    """One request's masking. `mode` "off" makes both directions the identity."""

    def __init__(self, *, mode: str, scope: str | None, data_dir: Path | None, machine: str,
                 values: KnownValues | None = None):
        self.mode = mode
        self.machine = machine or ""
        self.stats = MaskStats()
        self.span: Any = None
        self._values = values or KnownValues()
        self._map = _ps.PseudonymMap.open(scope, data_dir) if mode != "off" else None
        if self._map is not None and self._map.storage_error:
            self.stats.storage_error = self._map.storage_error
        self._vocabulary: frozenset[str] = frozenset()

    @property
    def active(self) -> bool:
        return self.mode != "off"

    @property
    def tag(self) -> str:
        return self._map.tag if self._map else ""

    # --- request ----------------------------------------------------------------------
    def mask_request(self, system_prompt: str, prompt: str) -> tuple[str, str]:
        """Both texts masked with one plan; MODEL_NOTE added to the system prompt when the
        request carries a placeholder. Mode off: both returned unchanged."""
        if not self.active:
            return system_prompt, prompt
        t0 = time.perf_counter()
        self._vocabulary = request_vocabulary((system_prompt, prompt))
        system_m, prompt_m = self._mask_pair(system_prompt or "", prompt or "")
        assert self._map is not None
        if self._map._pending:
            self._map.save()
            if self._map.storage_error and not self.stats.storage_error:
                self.stats.storage_error = self._map.storage_error
            # another process issued some of these values first: mask again with its labels
            if self._map._pending or self._relabelled(system_m + prompt_m):
                self.stats = MaskStats(storage_error=self.stats.storage_error)
                system_m, prompt_m = self._mask_pair(system_prompt or "", prompt or "")
        label_re = _ps.label_re(self.tag)
        if label_re.search(system_m) or label_re.search(prompt_m):
            system_m = f"{system_m}\n\n{MODEL_NOTE}" if system_m else MODEL_NOTE
        self.stats.mask_ms = (time.perf_counter() - t0) * 1000
        return system_m, prompt_m

    def _relabelled(self, masked: str) -> bool:
        assert self._map is not None
        return any(self._map.value_for(m.group(0)) is None for m in _ps.label_re(self.tag).finditer(masked))

    def _mask_pair(self, system_prompt: str, prompt: str) -> tuple[str, str]:
        system_s, n1 = redact(system_prompt)
        prompt_s, n2 = redact(prompt)
        self.stats.secrets += n1 + n2
        plan = self._plan(_unprotected(system_s) + "\n" + _unprotected(prompt_s))
        self.stats.short_names_left = len(plan.short_left)
        self.stats.names_context_only = len(plan.context)
        return self._apply(system_s, plan), self._apply(prompt_s, plan)

    def mask(self, text: str) -> str:
        """One text on its own (a reply re-fed, a test fixture)."""
        _system, masked = self.mask_request("", text)
        return masked

    # --- plan ---------------------------------------------------------------------------
    def _plan(self, text: str) -> _Plan:
        """Who is replaced, and how widely. TRUSTED values -- the machine's account list, the
        configured login and machines, the sub-agents -- are replaced as whole words, unless
        the word is Kratos's own text (`vocabulary`); everything else (names only seen in a
        log line or a field) is replaced only where it appeared as a name."""
        values = self._values
        strict = self.mode == "strict"
        seen: dict[str, str] = {}               # name -> strongest evidence from the text
        rank = {"exists": 2, "absent": 1, "unknown": 0}

        def note(name: str, how: str) -> None:
            name = name.rstrip(".-")
            if _acct.plausible_name(name) and rank[how] >= rank[seen.get(name, "unknown")]:
                seen[name] = how

        for pattern, how in _NAME_CONTEXTS:
            for m in pattern.finditer(text):
                note(m.group("n"), how)
        for m in _NAME_LIST_RE.finditer(text):
            for item in _LIST_ITEM_RE.finditer(m.group("list")):
                note(item.group("n"), "unknown")

        plan = _Plan()
        names = set(values.accounts) | set(seen) | values.seen_names | self._map_names("user") \
            | self._map_names("invalid_user")
        for name in names:
            # a name this conversation already gave a placeholder keeps it, whatever is learned later
            kind = self._existing_kind(name, ("user", "invalid_user"), account=True) \
                or self._account_kind(name, seen.get(name), values, strict)
            if kind is None:
                continue
            if len(name) < _acct.MIN_LEN and not strict:
                if name in text:
                    plan.short_left.add(name)
                continue
            if name in values.accounts and name.lower() not in self._vocabulary:
                plan.whole[name] = kind
            else:
                plan.context[name] = kind

        trusted_hosts: dict[str, str] = {}
        if self._map is not None:          # placeholders already issued in this conversation keep their kind
            for kind, _m, value, _label in self._map.entries():
                if kind in ("target", "host"):
                    plan.host_kinds[value] = kind
        for name in values.target_names:
            trusted_hosts.setdefault(name.lower(), "target")
        for name in values.hosts:
            trusted_hosts.setdefault(name.lower(), "host")
        for host, kind in trusted_hosts.items():
            kind = plan.host_kinds.setdefault(host, kind)
            if len(host) < _acct.MIN_LEN and not strict:
                continue
            if host.split(".", 1)[0] not in self._vocabulary:
                plan.hosts[host] = kind
        return plan

    def _map_names(self, kind: str) -> set[str]:
        if self._map is None:
            return set()
        return {v for k, m, v, _l in self._map.entries() if k == kind and m == self.machine}

    def _existing_kind(self, value: str, kinds: tuple[str, ...], *, account: bool = False) -> str | None:
        if self._map is None:
            return None
        machine = self.machine if account else ""
        return next((k for k in kinds if self._map.lookup(k, value, machine) is not None), None)

    def _account_kind(self, name: str, evidence: str | None, values: KnownValues, strict: bool) -> str | None:
        if not strict and name in _acct.IMAGE_DEFAULT_ACCOUNTS:
            return None                         # an image's default login names the image, not a person
        if name in values.accounts:
            if _acct.is_system(name, values.accounts[name]):
                return None
            return "user"
        if _acct.is_system(name):
            return None
        absent = evidence == "absent" or (values.account_list_complete and evidence != "exists") \
            or name in values.nonexistent
        if evidence == "exists" or not absent:
            return "user"
        if not strict and name in _acct.DICTIONARY_NAMES:
            return None                         # an attacker's dictionary guess: the analysis needs to see it
        return "invalid_user"

    # --- apply --------------------------------------------------------------------------
    def _label(self, kind: str, value: str, *, account: bool = False) -> str:
        assert self._map is not None
        self.stats.replaced[kind] = self.stats.replaced.get(kind, 0) + 1
        return self._map.label_for(kind, value, self.machine if account else "")

    def _apply(self, text: str, plan: _Plan) -> str:
        if not text:
            return text
        out: list[str] = []
        last = 0
        for m in _PROTECTED.finditer(text):
            out.append(self._apply_segment(text[last:m.start()], plan))
            out.append(m.group(0))
            last = m.end()
        out.append(self._apply_segment(text[last:], plan))
        return "".join(out)

    def _apply_segment(self, seg: str, plan: _Plan) -> str:
        if not seg:
            return seg
        seg = _EMAIL_RE.sub(self._email, seg)
        if plan.context:
            for pattern, _how in _NAME_CONTEXTS:
                seg = pattern.sub(lambda m: self._context_name(m, plan), seg)
        for pattern in _HOST_CONTEXTS:
            seg = pattern.sub(lambda m: self._context_host(m, plan), seg)
        seg = _TOKEN_RE.sub(lambda m: self._token(m.group(0), plan), seg)
        seg = _IPV4_RE.sub(self._ip, seg)
        seg = _IPV6_RE.sub(self._ip, seg)
        return seg

    def _email(self, m: re.Match[str]) -> str:
        if m.group("tld").lower() in _UNIT_SUFFIXES:
            return m.group(0)
        return self._label("email", m.group(0).lower())

    def _context_name(self, m: re.Match[str], plan: _Plan) -> str:
        name = m.group("n").rstrip(".-")
        kind = plan.context.get(name)
        if kind is None:
            return m.group(0)
        start, end = m.start("n") - m.start(), m.start("n") - m.start() + len(name)
        whole = m.group(0)
        return whole[:start] + self._label(kind, name, account=True) + whole[end:]

    def _context_host(self, m: re.Match[str], plan: _Plan) -> str:
        """A machine name where it appears as one (`user@host`, a hostname field)."""
        raw = m.group("h")
        host = raw.rstrip(".").lower()
        if not _HOSTNAME_RE.match(host) or ip_kind(host)[0] or host.rsplit(".", 1)[-1] in _UNIT_SUFFIXES:
            return m.group(0)
        if len(host) < _acct.MIN_LEN and self.mode != "strict":
            return m.group(0)
        if plan.hosts.get(host) is not None:
            return m.group(0)                   # trusted: the whole-word pass replaces it
        kind = plan.host_kinds.get(host, "host")
        start = m.start("h") - m.start()
        whole = m.group(0)
        return whole[:start] + self._label(kind, host) + whole[start + len(host):]

    def _token(self, token: str, plan: _Plan) -> str:
        core = token.rstrip(".-")
        tail = token[len(core):]
        if not core:
            return token
        kind = plan.whole.get(core)
        if kind is not None:
            return self._label(kind, core, account=True) + tail
        lower = core.lower()
        hkind = plan.hosts.get(lower)
        if hkind is not None:
            return self._label(hkind, lower) + tail
        if "." in core and not core[0].isdigit():
            head, dot, rest = core.partition(".")
            hkind = plan.hosts.get(head.lower())
            if hkind is not None and not rest[:1].isdigit():
                return self._label(hkind, head.lower()) + dot + rest + tail
        return token

    def _ip(self, m: re.Match[str]) -> str:
        text = m.group("ip")
        if _VERSION_CONTEXT_RE.search(m.string[max(0, m.start() - 40):m.start()]):
            return text
        kind, canon = ip_kind(text, self._values.target_ips)
        if kind is None:
            return text
        kind = self._existing_kind(canon, ("target_ip", "private_ip", "public_ip")) or kind
        return self._label(kind, canon)

    # --- reply ----------------------------------------------------------------------------
    def restore(self, text: Any) -> Any:
        """Placeholders this scope issued -> their real values. Anything else is left as
        written: `[REDACTED]`, an invented label (counted), a label from another scope."""
        if not self.active or not isinstance(text, str) or not text or self._map is None:
            return text
        t0 = time.perf_counter()
        own = _ps.label_re(self.tag)
        if any(self._map.value_for(m.group(0)) is None for m in own.finditer(text)):
            self._map.refresh()                 # issued by another request of this conversation since

        def back(m: re.Match[str]) -> str:
            value = self._map.value_for(m.group(0)) if self._map else None
            if value is None:
                self.stats.unknown_placeholders.append(m.group(0))
                return m.group(0)
            self.stats.restored += 1
            return value

        out = own.sub(back, text)
        for m in _ps.ANY_LABEL_RE.finditer(out):
            if not m.group(0).endswith("_" + self.tag):
                self.stats.unknown_placeholders.append(m.group(0))
        self.stats.untagged_lookalikes += len(_ps.UNTAGGED_RE.findall(out))
        self.stats.restore_ms += (time.perf_counter() - t0) * 1000
        if self.span is not None:
            try:
                self.span.set(**self.stats.restore_trace())
            except Exception:  # noqa: BLE001 -- the record must never change the reply
                pass
        return out


def _unprotected(text: str) -> str:
    return _PROTECTED.sub("\n", text or "")


def _machine() -> str:
    from kratos import kratos_config, run_context
    from kratos.target_key import target_key

    ctx = run_context.current()
    if ctx is not None and ctx.target:
        return ctx.target
    return target_key(kratos_config.get_active_target() or "")


def _scope() -> str | None:
    from kratos import run_context

    ctx = run_context.current()
    if ctx is None:
        return None
    return f"session:{ctx.session_id}" if ctx.session_id else f"run:{ctx.run_id}"


def request_masker(*, local: bool | None = None, base_url: str | None = None) -> Masker:
    """The masker for one model request, from the current run (scope, machine) and the
    mode for this endpoint. `local`/`base_url`: what the request site knows of its
    endpoint (the 'auto' default is off for a model on this machine)."""
    from kratos.budget.guard import data_dir as _data_dir
    from kratos.privacy import mode as _mode
    from kratos.privacy import values as _values

    data_dir = _data_dir()
    mode = _mode.current_mode(local=local, base_url=base_url, data_dir=data_dir)
    if mode == "off":
        return Masker(mode="off", scope=None, data_dir=None, machine="")
    machine = _machine()
    known = _values.gather(machine, data_dir) if machine else KnownValues()
    return Masker(mode=mode, scope=_scope(), data_dir=data_dir, machine=machine, values=known)
