"""Web server logs (nginx / Apache).

    access (combined):  10.136.28.52 - - [11/Oct/2026:17:12:05 +0000] "GET /admin HTTP/1.1" 404 162 "-" "curl/7.81.0"
    nginx error:        2026/10/11 17:11:52 [error] 15299#15299: *1 open() "..." failed, client: 10.1.2.3, server: ...
    Apache error:       [Sun Oct 11 17:11:52.123456 2026] [core:error] [pid 123] [client 10.1.2.3:5678] AH00126: ...

A query value whose parameter name looks like a credential (password, token,
key, secret, session, ...) is masked before anything is stored, like any other
secret (events.redact).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from kratos.logsources.parsers import Parsed

_ACCESS = re.compile(r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[[^\]]+\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
                     r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
_NGINX_ERR = re.compile(r"^\S+ \S+ \[(?P<level>[a-z]+)\] (?P<msg>.*)$", re.DOTALL)
_APACHE_ERR = re.compile(r"^\[[^\]]+\] \[(?:[\w.-]*:)?(?P<level>[a-z0-9]+)\] (?P<msg>.*)$", re.DOTALL)
_CLIENT_NGINX = re.compile(r"\bclient: (?P<ip>[0-9A-Fa-f:.]+)")
_CLIENT_APACHE = re.compile(r"\[client (?P<ip>[0-9A-Fa-f:.]+?)(?::\d+)?\]")
_SENSITIVE = re.compile(r"(pass|pwd|token|secret|key|auth|session|sid|signature|sig|code|credential|otp|jwt)",
                        re.IGNORECASE)
_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND", "MKCOL"}
MASK = "[REDACTED]"


def mask_url(url: str) -> tuple[str, bool]:
    """Mask the values of credential-looking query parameters (and URL userinfo)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url, False
    changed = False
    query = parts.query
    if query:
        pieces = []
        for piece in query.split("&"):
            name, sep, value = piece.partition("=")
            if sep and value and _SENSITIVE.search(name):
                pieces.append(f"{name}={MASK}")
                changed = True
            else:
                pieces.append(piece)
        query = "&".join(pieces)
    netloc = parts.netloc
    if "@" in netloc and ":" in netloc.split("@", 1)[0]:
        user = netloc.split("@", 1)[0].split(":", 1)[0]
        netloc = f"{user}:{MASK}@{netloc.split('@', 1)[1]}"
        changed = True
    if not changed:
        return url, False
    out = parts._replace(query=query, netloc=netloc).geturl()
    return out, True


def _ip(text: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(text or ""))
    except ValueError:
        return None


def _access(rec: Any, text: str) -> Parsed | None:
    m = _ACCESS.match(text)
    if not m:
        return None
    method = url = None
    req = m.group("req").split(" ")
    if len(req) == 3 and req[0] in _METHODS:
        method, url = req[0], req[1]
    status = int(m.group("status"))
    masked, changed = None, False
    if url is not None:
        url, changed = mask_url(url)
        masked = url
    original = text if masked is None else text.replace(m.group("req"), f"{method} {masked} {req[2]}", 1)
    fields: dict[str, Any] = {
        "source_ip": _ip(m.group("ip")), "user_name": None if m.group("user") == "-" else m.group("user"),
        "http_request_method": method, "url_original": url, "http_response_status_code": status,
        "user_agent_original": m.group("ua") if m.group("ua") not in (None, "-", "") else None,
    }
    return Parsed(ts=rec.ts, action="http_request", provider="web", outcome="success" if status < 400 else "failure",
                  message=f"{method or '?'} {url or m.group('req')[:200]} -> {status}", original=original,
                  fields={k: v for k, v in fields.items() if v not in (None, "")}, log_file_path=rec.path,
                  redacted=changed)


def _error(rec: Any, text: str, apache: bool) -> Parsed | None:
    m = (_APACHE_ERR if apache else _NGINX_ERR).match(text)
    if not m:
        return None
    cm = (_CLIENT_APACHE if apache else _CLIENT_NGINX).search(m.group("msg"))
    fields = {"source_ip": _ip(cm.group("ip")) if cm else None}
    return Parsed(ts=rec.ts, action="web_error", provider="apache" if apache else "nginx", message=m.group("msg"),
                  original=text, fields={k: v for k, v in fields.items() if v}, log_file_path=rec.path,
                  zone_assumed=rec.zone_assumed)


def to_parsed(rec: Any) -> Parsed | None:
    if rec.kind != "file":
        return None
    text = rec.text
    if text[:1] == "[":
        return _error(rec, text, apache=True)
    if re.match(r"^\d{4}/\d\d/\d\d ", text):
        return _error(rec, text, apache=False)
    return _access(rec, text)


def parse(read: Any) -> list[Parsed]:
    return [p for p in (to_parsed(r) for r in read.records) if p is not None]
