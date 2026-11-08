"""Channels: the receivers Kratos delivers to, and the rules for editing them.

A channel is a kind (``ntfy`` | ``webhook`` | ``syslog`` | ``email``), a name, what it
receives (its *scopes*: ``alerts`` -- the text alerts triggers, schedules and notices
send by name; ``findings`` -- every lifecycle change of matching findings; ``events``
-- stored host events, forwarded by cursor), a format, filters and a send-rate cap.

* **People only.** Adding, editing, turning on or off and removing a channel needs an
  ``Actor`` from the TUI or the CLI and is refused inside a tool run; every edit is
  recorded in ``channel_events`` with who made it.
* **Secrets never enter the database.** A channel's secrets (a webhook's ``whsec_``
  signing secret or an ``Authorization`` value, an SMTP password, a syslog client key)
  live in ``data_dir/channel-secrets/<name>.json`` (folder 0700, file 0600); the row
  holds no secret, and ``describe`` / ``/doctor`` never show one.
* **ntfy is built in.** Its row (``ntfy``) is created on first use; its topic, server and
  token still come from ``KRATOS_NTFY_*`` in ``.env``, so existing installs keep working
  unchanged. A person may turn it off or give it filters like any other channel.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets as _secrets
import sqlite3
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from kratos import settings_store
from kratos.lifecycle.decide import Actor
from kratos.outbox import store as S

KINDS = ("ntfy", "webhook", "syslog", "email")
SCOPES = ("alerts", "findings", "events")
FORMATS = ("text", "kratos", "ocsf", "ecs")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
BUILTIN_NTFY = "ntfy"
ALL = "all"                                   # deliver = ["all"]: every enabled alerts channel
EDIT_INTERFACES = ("tui", "cli")
WEBHOOK_FRAMINGS = ("json", "ndjson", "es_bulk", "hec")
EMAIL_SECURITY = ("starttls", "tls")
SECRETS_DIR = "channel-secrets"
MAX_NAME = 32
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_RULE_PREFIX_RE = re.compile(r"[A-Z][A-Z0-9-]{0,40}")
_HEADER_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_EMAIL_RE = re.compile(r"[^@\s<>,;\"]{1,64}@[A-Za-z0-9.-]{1,253}")
_INDEX_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
_HOSTNAME_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}"
                          r"[A-Za-z0-9])?)*")
# The headers a webhook channel may not override: the signature, the framing and the
# HTTP plumbing are Kratos's.
_RESERVED_HEADERS = frozenset({"webhook-id", "webhook-timestamp", "webhook-signature", "content-type",
                               "content-length", "host", "user-agent", "transfer-encoding", "connection"})

# Which formats each kind can send, and which scopes each (kind, format) can carry.
_ALLOWED: dict[str, dict[str, frozenset[str]]] = {
    "ntfy": {"text": frozenset({"alerts"})},
    "webhook": {"kratos": frozenset(SCOPES), "ocsf": frozenset({"findings", "events"}),
                "ecs": frozenset({"findings", "events"})},
    "syslog": {"text": frozenset(SCOPES), "ocsf": frozenset({"findings", "events"}),
               "ecs": frozenset({"findings", "events"})},
    "email": {"text": frozenset({"alerts", "findings"})},
}
SECRET_KEYS = {"webhook": ("signing_secret", "auth_value"), "email": ("password",), "syslog": ("client_key",),
               "ntfy": ()}


class ChannelError(ValueError):
    """A value a channel can't take, a forbidden caller, or no person behind the edit."""


@dataclass(frozen=True)
class Filters:
    min_severity: str | None = None
    min_ssvc: str | None = None                 # track | track* | attend | act
    rule_prefixes: tuple[str, ...] = ()
    machines: tuple[str, ...] = ()              # target keys
    groups: tuple[str, ...] = ()
    only_new_or_worse: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"min_severity": self.min_severity, "min_ssvc": self.min_ssvc,
                "rule_prefixes": list(self.rule_prefixes), "machines": list(self.machines),
                "groups": list(self.groups), "only_new_or_worse": self.only_new_or_worse}

    def describe(self) -> str:
        parts = []
        if self.min_severity:
            parts.append(f"severity {self.min_severity}+")
        if self.min_ssvc:
            from kratos.ssvc.tree import label

            parts.append(f"decision {label(self.min_ssvc)}+")
        if self.rule_prefixes:
            parts.append("rules " + ", ".join(p + "*" for p in self.rule_prefixes))
        if self.machines:
            parts.append("machines " + ", ".join(self.machines))
        if self.groups:
            parts.append("groups " + ", ".join("@" + g for g in self.groups))
        if self.only_new_or_worse:
            parts.append("only new or worse")
        return "; ".join(parts) or "everything"


@dataclass(frozen=True)
class Channel:
    name: str
    kind: str
    builtin: bool = False
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)
    scopes: tuple[str, ...] = ("alerts",)
    format: str = "text"
    filters: Filters = field(default_factory=Filters)
    mask_values: bool = False
    max_per_minute: int = 60
    created_by: str = ""
    updated_at: float | None = None
    updated_by: str = ""
    failing_since: float | None = None
    outage_notified_at: float | None = None
    last_success_at: float | None = None
    last_error: str | None = None
    last_error_at: float | None = None

    def receives(self, scope: str) -> bool:
        return scope in self.scopes

    @property
    def destination(self) -> str:
        """Where messages go, in plain words (no secret)."""
        c = self.config
        if self.kind == "ntfy":
            from kratos import kratos_config as kc

            host = urlparse(kc.NTFY_BASE_URL).hostname or kc.NTFY_BASE_URL
            return f"ntfy topic on {host}" if kc.NTFY_TOPIC else "ntfy (not set up: KRATOS_NTFY_TOPIC)"
        if self.kind == "webhook":
            u = urlparse(str(c.get("url") or ""))
            return f"{u.scheme}://{u.hostname}{':' + str(u.port) if u.port else ''}{u.path or ''}"
        if self.kind == "syslog":
            return f"syslog over TLS to {c.get('host')}:{c.get('port', 6514)}"
        if self.kind == "email":
            return f"email to {', '.join(c.get('to') or [])} via {c.get('host')}:{c.get('port')}"
        return self.kind

    def disclosure(self) -> str:
        """What leaves Kratos through this channel and to whom, in plain words."""
        what = []
        if "alerts" in self.scopes:
            what.append("alert texts (severity, machine, what happened, finding ids; no evidence)")
        if "findings" in self.scopes:
            what.append("each change of matching findings with its title, severity, machine, entities "
                        "(account names, addresses, paths) and evidence lines")
        if "events" in self.scopes:
            what.append("stored log events of the matching machines (log lines, accounts, addresses, programs)")
        mask = (" Account names, addresses and host names are replaced by placeholders before sending."
                if self.mask_values else "")
        return (f"Sends to {self.destination}: " + "; ".join(what) + ". Secrets (keys, tokens, passwords) "
                "are removed first." + mask)


# --- validation ----------------------------------------------------------------------------
def check_name(name: str) -> str:
    n = str(name or "").strip().lower()
    if not _NAME_RE.fullmatch(n):
        raise ChannelError("a channel name is 1-32 lower-case letters, digits, '-' or '_', starting with a "
                           "letter or digit")
    if n == ALL:
        raise ChannelError("'all' is reserved (deliver = [\"all\"] means every alert channel)")
    return n


def _private_or_loopback(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return host.lower() in ("localhost",) or host.lower().endswith((".local", ".lan", ".internal", ".home.arpa"))


def _host(value: Any, what: str) -> str:
    h = str(value or "").strip()
    try:
        ipaddress.ip_address(h.strip("[]"))
        return h.strip("[]")
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(h):
        raise ChannelError(f"{what} must be a host name or an address")
    return h.lower()


def _port(value: Any, default: int) -> int:
    try:
        p = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        raise ChannelError("a port is a number 1-65535") from None
    if not 1 <= p <= 65535:
        raise ChannelError("a port is a number 1-65535")
    return p


def _file(value: Any, what: str) -> str | None:
    if value in (None, ""):
        return None
    p = Path(str(value)).expanduser()
    if not p.is_absolute():
        raise ChannelError(f"{what} must be a full path")
    if not p.is_file():
        raise ChannelError(f"{what} {p} is not a readable file")
    return str(p)


def _clean_config(kind: str, cfg: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(cfg or {})
    if kind == "ntfy":
        return {}
    if kind == "webhook":
        url = str(cfg.get("url") or "").strip()
        u = urlparse(url)
        if u.scheme not in ("https", "http") or not u.hostname or u.username or u.password:
            raise ChannelError("a webhook needs an https:// URL (no user name or password in it)")
        allow_http = bool(cfg.get("allow_http"))
        if u.scheme == "http":
            if not allow_http:
                raise ChannelError("plain http:// sends findings readable on the wire; use https://, or allow plain "
                                   "HTTP explicitly for a receiver on this machine or your own network")
            if not _private_or_loopback(u.hostname):
                raise ChannelError("plain HTTP is only allowed to a receiver on this machine or a private network "
                                   "address")
        framing = str(cfg.get("framing") or "json").lower()
        if framing not in WEBHOOK_FRAMINGS:
            raise ChannelError(f"framing is one of: {', '.join(WEBHOOK_FRAMINGS)}")
        out: dict[str, Any] = {"url": url, "allow_http": allow_http and u.scheme == "http", "framing": framing,
                               "ca_file": _file(cfg.get("ca_file"), "the CA file"),
                               "sign_v1a": bool(cfg.get("sign_v1a"))}
        if framing == "es_bulk":
            index = str(cfg.get("index") or "kratos").strip()
            if not _INDEX_RE.fullmatch(index):
                raise ChannelError("an index name is lower-case letters, digits, '.', '_' or '-'")
            out["index"] = index
        auth_header = str(cfg.get("auth_header") or "").strip()
        if auth_header:
            if not _HEADER_RE.fullmatch(auth_header) or auth_header.lower() in _RESERVED_HEADERS:
                raise ChannelError("the authorization header name must be a plain header name Kratos doesn't set "
                                   "itself (e.g. Authorization)")
            out["auth_header"] = auth_header
        return out
    if kind == "syslog":
        out = {"host": _host(cfg.get("host"), "the syslog server"), "port": _port(cfg.get("port"), 6514),
               "ca_file": _file(cfg.get("ca_file"), "the CA file"),
               "client_cert": _file(cfg.get("client_cert"), "the client certificate"),
               "server_name": _host(cfg.get("server_name"), "the server name") if cfg.get("server_name") else None,
               "sd_pen": int(cfg.get("sd_pen") or 32473)}
        if not 1 <= out["sd_pen"] <= 2 ** 31:
            raise ChannelError("the enterprise number is a positive whole number")
        return out
    if kind == "email":
        security = str(cfg.get("security") or "starttls").lower()
        if security not in EMAIL_SECURITY:
            raise ChannelError("email security is starttls (port 587) or tls (port 465); plain SMTP isn't offered")
        to = cfg.get("to") or []
        if isinstance(to, str):
            to = [t.strip() for t in to.split(",") if t.strip()]
        to = [str(t).strip() for t in to]
        if not to or len(to) > 20 or not all(_EMAIL_RE.fullmatch(t) for t in to):
            raise ChannelError("give 1-20 recipient addresses, comma separated")
        sender = str(cfg.get("from") or "").strip()
        if not _EMAIL_RE.fullmatch(sender):
            raise ChannelError("give the From address")
        user = str(cfg.get("username") or "").strip()
        if any(ord(ch) < 32 for ch in user) or len(user) > 200:
            raise ChannelError("the user name must be plain text")
        return {"host": _host(cfg.get("host"), "the mail server"),
                "port": _port(cfg.get("port"), 465 if security == "tls" else 587), "security": security,
                "from": sender, "to": to, "username": user or None,
                "ca_file": _file(cfg.get("ca_file"), "the CA file")}
    raise ChannelError(f"a channel kind is one of: {', '.join(KINDS)}")


def _clean_filters(raw: dict[str, Any] | Filters | None) -> Filters:
    if isinstance(raw, Filters):
        raw = raw.to_dict()
    raw = dict(raw or {})
    sev = raw.get("min_severity")
    sev = str(sev).strip().lower() if sev else None
    if sev and sev not in SEVERITIES:
        raise ChannelError(f"minimum severity is one of: {', '.join(SEVERITIES)}")
    ssvc = raw.get("min_ssvc")
    ssvc = str(ssvc).strip().lower() if ssvc else None
    if ssvc:
        from kratos.ssvc.tree import OUTCOMES

        if ssvc not in OUTCOMES:
            raise ChannelError(f"minimum decision is one of: {', '.join(OUTCOMES)}")
    prefixes = tuple(sorted({str(p).strip().upper().rstrip("*") for p in raw.get("rule_prefixes") or []
                             if str(p).strip()}))
    if any(not _RULE_PREFIX_RE.fullmatch(p) for p in prefixes):
        raise ChannelError("a rule prefix looks like PKG- or CORR-SSH")
    from kratos.target_key import target_key

    machines = tuple(sorted({target_key(str(m)) for m in raw.get("machines") or [] if str(m).strip()}))
    groups = tuple(sorted({str(g).strip().lstrip("@").lower() for g in raw.get("groups") or [] if str(g).strip()}))
    return Filters(sev, ssvc, prefixes, machines, groups, bool(raw.get("only_new_or_worse")))


def _check_shape(kind: str, fmt: str, scopes: Iterable[str]) -> tuple[str, tuple[str, ...]]:
    allowed = _ALLOWED.get(kind)
    if allowed is None:
        raise ChannelError(f"a channel kind is one of: {', '.join(KINDS)}")
    fmt = str(fmt or next(iter(allowed))).lower()
    if fmt not in allowed:
        raise ChannelError(f"a {kind} channel sends: {', '.join(allowed)}")
    sc = tuple(s for s in SCOPES if s in {str(x).strip().lower() for x in scopes or []})
    if not sc:
        raise ChannelError(f"choose what it receives: {', '.join(sorted(allowed[fmt]))}")
    extra = [s for s in sc if s not in allowed[fmt]]
    if extra:
        raise ChannelError(f"a {kind} channel in {fmt} format can receive: {', '.join(sorted(allowed[fmt]))} "
                           f"(not {', '.join(extra)})")
    return fmt, sc


def _check_actor(actor: Actor) -> str:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise ChannelError(f"agent tools may not change where Kratos sends findings (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in EDIT_INTERFACES or not str(actor.user or "").strip():
        raise ChannelError("a channel edit needs a person: an Actor from the TUI or the CLI")
    return str(actor.user)[:120]


def _rate(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ChannelError("the send rate is a whole number of messages per minute, 1-6000") from None
    if not 1 <= n <= 6000:
        raise ChannelError("the send rate is a whole number of messages per minute, 1-6000")
    return n


# --- secrets ------------------------------------------------------------------------------------
def secrets_dir(data_dir: Path | str) -> Path:
    return Path(data_dir) / SECRETS_DIR


def _secret_path(data_dir: Path | str, name: str) -> Path:
    return secrets_dir(data_dir) / f"{check_name(name)}.json"


def read_secrets(data_dir: Path | str, name: str) -> dict[str, str]:
    p = _secret_path(data_dir, name)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}


def _write_secrets(data_dir: Path | str, name: str, values: dict[str, str]) -> None:
    from kratos import paths

    p = _secret_path(data_dir, name)
    paths.ensure_private_dir(p.parent)
    paths.write_private_text(p, json.dumps(values, sort_keys=True))


def new_webhook_secret() -> str:
    """A Standard Webhooks signing secret: ``whsec_`` + base64 of 32 random bytes."""
    return "whsec_" + base64.b64encode(_secrets.token_bytes(32)).decode("ascii")


def check_webhook_secret(value: str) -> str:
    v = str(value or "").strip()
    if not v.startswith("whsec_"):
        raise ChannelError("a webhook signing secret starts with whsec_")
    try:
        raw = base64.b64decode(v[len("whsec_"):], validate=True)
    except (ValueError, base64.binascii.Error):
        raise ChannelError("the signing secret after whsec_ must be base64") from None
    if not 24 <= len(raw) <= 64:
        raise ChannelError("the signing secret must be 24-64 random bytes (Standard Webhooks)")
    return v


def _clean_secrets(kind: str, values: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (values or {}).items():
        if v in (None, ""):
            continue
        if k not in SECRET_KEYS.get(kind, ()):
            raise ChannelError(f"a {kind} channel has no secret named {k!r}")
        v = str(v)
        if k == "signing_secret":
            v = check_webhook_secret(v)
        elif k == "client_key" and "PRIVATE KEY" not in v:
            raise ChannelError("the client key must be a PEM private key")
        elif any(ch in v for ch in "\r\n") and k != "client_key":
            raise ChannelError("a secret is one line")
        out[k] = v
    return out


def secret_names(data_dir: Path | str, name: str) -> list[str]:
    """Which secrets a channel has (the names, never the values)."""
    return sorted(read_secrets(data_dir, name))


# --- rows ---------------------------------------------------------------------------------------
def _row(r: sqlite3.Row) -> Channel:
    def j(v: Any, default: Any) -> Any:
        try:
            return json.loads(v) if v else default
        except ValueError:
            return default

    filters = j(r["filters"], {})
    try:
        flt = _clean_filters(filters)
    except ChannelError:
        flt = Filters()
    return Channel(r["name"], r["kind"], bool(r["builtin"]), bool(r["enabled"]), j(r["config"], {}),
                   tuple(j(r["scopes"], ["alerts"])), r["format"], flt, bool(r["mask_values"]),
                   int(r["max_per_minute"]), r["created_by"], r["updated_at"], r["updated_by"], r["failing_since"],
                   r["outage_notified_at"], r["last_success_at"], r["last_error"], r["last_error_at"])


def _ensure_builtin(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT 1 FROM channels WHERE name = ?", (BUILTIN_NTFY,)).fetchone():
        return
    now = time.time()
    conn.execute(
        "INSERT OR IGNORE INTO channels (name, kind, builtin, enabled, config, scopes, format, filters, mask_values,"
        " max_per_minute, created_at, created_by, updated_at, updated_by) VALUES (?, 'ntfy', 1, 1, '{}', ?, 'text',"
        " '{}', 0, 60, ?, 'kratos', ?, 'kratos')", (BUILTIN_NTFY, json.dumps(["alerts"]), now, now))


def list_channels(data_dir: Path | str) -> list[Channel]:
    with S.opened(data_dir) as conn:
        _ensure_builtin(conn)
        return [_row(r) for r in conn.execute("SELECT * FROM channels ORDER BY builtin DESC, name")]


def get_channel(data_dir: Path | str, name: str) -> Channel | None:
    with S.opened(data_dir) as conn:
        _ensure_builtin(conn)
        r = conn.execute("SELECT * FROM channels WHERE name = ?", (str(name or "").strip().lower(),)).fetchone()
        return _row(r) if r else None


def ntfy_configured() -> bool:
    from kratos import kratos_config as kc
    from kratos.agent.notify import topic_problem

    return bool(kc.NTFY_TOPIC) and topic_problem(kc.NTFY_TOPIC) is None


def usable(ch: Channel) -> tuple[bool, str]:
    """(can it send now, why not) -- enabled and, for ntfy, set up."""
    if not ch.enabled:
        return False, "turned off"
    if ch.kind == "ntfy" and not ntfy_configured():
        from kratos.agent.notify import NOT_CONFIGURED_HINT

        return False, NOT_CONFIGURED_HINT
    return True, ""


def _event(conn: sqlite3.Connection, name: str, action: str, detail: dict[str, Any] | None, who: str,
           interface: str) -> None:
    conn.execute("INSERT INTO channel_events (channel, at, action, detail, actor, interface) VALUES (?, ?, ?, ?, ?, ?)",
                 (name, time.time(), action, json.dumps(detail or {}, sort_keys=True), who, interface))


def _source_max(conn: sqlite3.Connection, table: str) -> int:
    try:
        return int(conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0])
    except sqlite3.Error:
        return 0


def add_channel(data_dir: Path | str, *, name: str, kind: str, config: dict[str, Any], scopes: Iterable[str],
                format: str | None = None, filters: dict[str, Any] | Filters | None = None,  # noqa: A002
                mask_values: bool = False, max_per_minute: int = 60, secrets: dict[str, Any] | None = None,
                actor: Actor) -> Channel:
    """Add a channel. Forwarding starts from now: findings changes and events already
    stored are not sent (their cursors start at the newest row)."""
    who = _check_actor(actor)
    name = check_name(name)
    kind = str(kind or "").strip().lower()
    if kind == "ntfy":
        raise ChannelError("ntfy is built in (set KRATOS_NTFY_TOPIC in .env); add a webhook, syslog or email channel")
    cfg = _clean_config(kind, config)
    fmt, sc = _check_shape(kind, format or ("kratos" if kind == "webhook" else "text"), scopes)
    flt = _clean_filters(filters)
    rate = _rate(max_per_minute)
    sec = _clean_secrets(kind, secrets)
    if kind == "email" and cfg.get("username") and "password" not in sec:
        raise ChannelError("the mail server login needs a password")
    if kind == "syslog" and cfg.get("client_cert") and "client_key" not in sec:
        raise ChannelError("a client certificate needs its private key")
    now = time.time()
    with S.opened(data_dir) as conn, S.immediate(conn):
        _ensure_builtin(conn)
        if conn.execute("SELECT 1 FROM channels WHERE name = ?", (name,)).fetchone():
            raise ChannelError(f"there is already a channel named {name!r}")
        conn.execute(
            "INSERT INTO channels (name, kind, builtin, enabled, config, scopes, format, filters, mask_values,"
            " max_per_minute, created_at, created_by, updated_at, updated_by) VALUES (?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?)", (name, kind, json.dumps(cfg, sort_keys=True), json.dumps(list(sc)), fmt,
                         json.dumps(flt.to_dict(), sort_keys=True), int(bool(mask_values)), rate, now, who, now, who))
        S.set_cursor(conn, name, "findings", _source_max(conn, "finding_events"), now)
        S.set_cursor(conn, name, "events", _source_max(conn, "host_events"), now)
        _event(conn, name, "added", {"kind": kind, "config": cfg, "scopes": list(sc), "format": fmt,
                                     "filters": flt.to_dict(), "mask_values": bool(mask_values),
                                     "max_per_minute": rate, "secrets": sorted(sec)}, who, actor.interface)
        if sec:
            _write_secrets(data_dir, name, sec)
    ch = get_channel(data_dir, name)
    assert ch is not None
    return ch


_EDITABLE = ("config", "scopes", "format", "filters", "mask_values", "max_per_minute")


def edit_channel(data_dir: Path | str, name: str, *, actor: Actor, **changes: Any) -> Channel:
    """Change a channel's settings (any of: config, scopes, format, filters, mask_values,
    max_per_minute). The built-in ntfy channel takes filters and the rate only."""
    who = _check_actor(actor)
    ch = get_channel(data_dir, name)
    if ch is None:
        raise ChannelError(f"no channel named {name!r}")
    unknown = set(changes) - set(_EDITABLE)
    if unknown:
        raise ChannelError(f"can't change {', '.join(sorted(unknown))}")
    if ch.builtin and set(changes) - {"filters", "max_per_minute"}:
        raise ChannelError("the built-in ntfy channel is set up in .env (KRATOS_NTFY_*); only its filters and "
                           "send rate are edited here")
    cfg = _clean_config(ch.kind, {**ch.config, **changes["config"]}) if "config" in changes else ch.config
    fmt, sc = _check_shape(ch.kind, changes.get("format", ch.format), changes.get("scopes", ch.scopes))
    flt = _clean_filters(changes["filters"]) if "filters" in changes else ch.filters
    rate = _rate(changes.get("max_per_minute", ch.max_per_minute))
    mask = bool(changes.get("mask_values", ch.mask_values))
    new = replace(ch, config=cfg, format=fmt, scopes=sc, filters=flt, max_per_minute=rate, mask_values=mask)
    diff = {k: v for k, v in (("config", cfg), ("format", fmt), ("scopes", list(sc)), ("filters", flt.to_dict()),
                               ("max_per_minute", rate), ("mask_values", mask))
            if v != {"config": ch.config, "format": ch.format, "scopes": list(ch.scopes),
                     "filters": ch.filters.to_dict(), "max_per_minute": ch.max_per_minute,
                     "mask_values": ch.mask_values}[k]}
    with S.opened(data_dir) as conn, S.immediate(conn):
        conn.execute("UPDATE channels SET config = ?, scopes = ?, format = ?, filters = ?, mask_values = ?, "
                     "max_per_minute = ?, updated_at = ?, updated_by = ? WHERE name = ?",
                     (json.dumps(cfg, sort_keys=True), json.dumps(list(sc)), fmt,
                      json.dumps(flt.to_dict(), sort_keys=True), int(mask), rate, time.time(), who, ch.name))
        now = time.time()
        for stream in ("findings", "events"):          # a scope newly turned on starts from now too
            if stream in sc and stream not in ch.scopes:
                S.set_cursor(conn, ch.name, stream,
                             _source_max(conn, "finding_events" if stream == "findings" else "host_events"), now)
        _event(conn, ch.name, "edited", diff, who, actor.interface)
    return new


def set_enabled(data_dir: Path | str, name: str, enabled: bool, *, actor: Actor) -> Channel:
    who = _check_actor(actor)
    ch = get_channel(data_dir, name)
    if ch is None:
        raise ChannelError(f"no channel named {name!r}")
    with S.opened(data_dir) as conn, S.immediate(conn):
        conn.execute("UPDATE channels SET enabled = ?, updated_at = ?, updated_by = ? WHERE name = ?",
                     (int(bool(enabled)), time.time(), who, ch.name))
        _event(conn, ch.name, "enabled" if enabled else "disabled", None, who, actor.interface)
    return replace(ch, enabled=bool(enabled))


def set_secret(data_dir: Path | str, name: str, key: str, value: str | None, *, actor: Actor) -> None:
    """Set (or, with value None, clear) one secret of a channel. Recorded without the value."""
    who = _check_actor(actor)
    ch = get_channel(data_dir, name)
    if ch is None:
        raise ChannelError(f"no channel named {name!r}")
    current = read_secrets(data_dir, ch.name)
    if value in (None, ""):
        current.pop(key, None)
    else:
        current.update(_clean_secrets(ch.kind, {key: value}))
    _write_secrets(data_dir, ch.name, current)
    with S.opened(data_dir) as conn, S.immediate(conn):
        _event(conn, ch.name, "secret_set", {"secret": key, "set": value not in (None, "")}, who, actor.interface)


def remove_channel(data_dir: Path | str, name: str, *, actor: Actor) -> int:
    """Remove a channel on the person's own command. Its messages stay in the outbox (as
    history: pending ones are marked dead, "channel removed"); its secrets file is
    removed. Returns how many waiting messages were closed."""
    who = _check_actor(actor)
    ch = get_channel(data_dir, name)
    if ch is None:
        raise ChannelError(f"no channel named {name!r}")
    if ch.builtin:
        raise ChannelError("the built-in ntfy channel can be turned off, not removed")
    with S.opened(data_dir) as conn, S.immediate(conn):
        closed = conn.execute("UPDATE outbox SET status = 'dead', dead_at = ?, last_error = 'channel removed' "
                              "WHERE channel = ? AND status IN ('pending', 'failed')", (time.time(), ch.name)).rowcount
        conn.execute("DELETE FROM channels WHERE name = ?", (ch.name,))
        conn.execute("DELETE FROM forward_cursors WHERE channel = ?", (ch.name,))
        _event(conn, ch.name, "removed", {"closed_messages": closed}, who, actor.interface)
    p = _secret_path(data_dir, ch.name)
    if p.exists():
        p.unlink()
    return int(closed)


def history(data_dir: Path | str, name: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with S.opened(data_dir) as conn:
        sql = "SELECT * FROM channel_events" + (" WHERE channel = ?" if name else "") + " ORDER BY id DESC LIMIT ?"
        args = (name, limit) if name else (limit,)
        return [dict(r) for r in conn.execute(sql, args)]


# --- health (written by the worker) -------------------------------------------------------------
def record_health(conn: sqlite3.Connection, name: str, *, ok: bool, error: str | None, now: float) -> dict[str, Any]:
    """Update the channel's health after an attempt. Returns what changed:
    {"outage_started": float|None, "recovered_from": float|None}."""
    r = conn.execute("SELECT failing_since, outage_notified_at FROM channels WHERE name = ?", (name,)).fetchone()
    if r is None:
        return {}
    if ok:
        conn.execute("UPDATE channels SET last_success_at = ?, failing_since = NULL, outage_notified_at = NULL "
                     "WHERE name = ?", (now, name))
        return {"recovered_from": r["failing_since"] if r["outage_notified_at"] else None}
    conn.execute("UPDATE channels SET last_error = ?, last_error_at = ?, failing_since = COALESCE(failing_since, ?) "
                 "WHERE name = ?", (S.clip(error, S.MAX_ERROR_CHARS), now, now, name))
    return {"failing_since": r["failing_since"] or now}


def mark_outage_notified(conn: sqlite3.Connection, name: str, now: float) -> bool:
    """Claim the one outage notice for this outage. True for the caller that claims it."""
    cur = conn.execute("UPDATE channels SET outage_notified_at = ? WHERE name = ? AND failing_since IS NOT NULL "
                       "AND outage_notified_at IS NULL", (now, name))
    return bool(cur.rowcount)


def resolve_deliver(data_dir: Path | str, names: Iterable[str] | None) -> list[str]:
    """A trigger's or schedule's ``deliver`` list -> channel names (``all`` = every
    enabled channel that receives alerts). Unknown names are kept so the caller can say so."""
    names = [str(n).strip().lower() for n in (names if names is not None else [ALL]) if str(n).strip()]
    out: list[str] = []
    channels = None
    for n in names:
        if n == ALL:
            channels = channels or list_channels(data_dir)
            out.extend(c.name for c in channels if c.enabled and "alerts" in c.scopes)
        else:
            out.append(n)
    seen: set[str] = set()
    return [n for n in out if not (n in seen or seen.add(n))]


def check_deliver(data_dir: Path | str, names: Iterable[str]) -> list[str]:
    """Validate a ``deliver`` list for a trigger or schedule being saved: ``all``,
    ``ntfy`` or the name of a channel that receives alerts."""
    out = []
    known = {c.name: c for c in list_channels(data_dir)}
    for n in names:
        n = str(n).strip().lower()
        if not n:
            continue
        if n == ALL:
            out.append(n)
            continue
        c = known.get(n)
        if c is None:
            raise ChannelError(f"no channel named {n!r} (see /channels or `kratos channels list`)")
        if "alerts" not in c.scopes:
            raise ChannelError(f"channel {n!r} doesn't receive alerts (it forwards {', '.join(c.scopes)})")
        out.append(n)
    return out
