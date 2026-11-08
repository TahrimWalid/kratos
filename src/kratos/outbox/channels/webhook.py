"""Webhook channel: an HTTPS POST signed per the Standard Webhooks specification.

Headers: ``webhook-id`` (the message's idempotency key -- the same on every retry),
``webhook-timestamp`` (when this attempt was sent, Unix seconds) and
``webhook-signature`` (``v1,<base64 HMAC-SHA256>`` with the channel's ``whsec_``
secret, and/or ``v1a,<base64 Ed25519>`` with Kratos's signing key, of
``<id>.<timestamp>.<body>``). TLS verification is always on (the system CAs or a CA
file the person names); redirects are never followed; 10 s timeout; at most 4 KB of the
response is read, for the error text only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
from pathlib import Path
from typing import Any

from kratos.outbox import retry as _retry
from kratos.outbox.channels import TIMEOUT_SECONDS, Delivery, clean_reason
from kratos.outbox.store import Outcome

RESPONSE_READ_LIMIT = 4096


def webhook_id(message_id: str) -> str:
    """The ``webhook-id`` for a message: stable, and free of '.' (the signed content is
    ``id.timestamp.body``)."""
    return "msg_" + hashlib.sha256(message_id.encode("utf-8")).hexdigest()[:32]


def _hmac_key(secret: str) -> bytes:
    return base64.b64decode(secret[len("whsec_"):])


def signed_content(msg_id: str, timestamp: str, body: bytes) -> bytes:
    return msg_id.encode("ascii") + b"." + timestamp.encode("ascii") + b"." + body


def signature_header(msg_id: str, timestamp: str, body: bytes, *, secret: str | None,
                     sign_v1a: bool, data_dir: Path) -> str:
    content = signed_content(msg_id, timestamp, body)
    sigs = []
    if secret:
        mac = hmac.new(_hmac_key(secret), content, hashlib.sha256).digest()
        sigs.append("v1," + base64.b64encode(mac).decode("ascii"))
    if sign_v1a:
        from kratos import signing

        sigs.append("v1a," + base64.b64encode(signing.sign(content, data_dir)).decode("ascii"))
    return " ".join(sigs)


def build_request(delivery: Delivery, channel: Any, secrets: dict[str, str], data_dir: Path,
                  now: float | None = None) -> tuple[str, dict[str, str], bytes]:
    """(url, headers, body) for one attempt -- pure apart from the clock and the key."""
    body = str(delivery.payload.get("body") or "").encode("utf-8")
    ts = str(int(time.time() if now is None else now))
    mid = webhook_id(delivery.message_id)
    headers = {
        "webhook-id": mid,
        "webhook-timestamp": ts,
        "content-type": str(delivery.payload.get("content_type") or "application/json"),
        "user-agent": "Kratos-Outbox/1",
    }
    sig = signature_header(mid, ts, body, secret=secrets.get("signing_secret"),
                           sign_v1a=bool(channel.config.get("sign_v1a")), data_dir=data_dir)
    if sig:
        headers["webhook-signature"] = sig
    auth_header = channel.config.get("auth_header")
    if auth_header and secrets.get("auth_value"):
        headers[auth_header] = secrets["auth_value"]
    return str(channel.config["url"]), headers, body


def bulk_item_failure(raw: bytes) -> tuple[bool, str] | None:
    """Elasticsearch / OpenSearch answer a ``_bulk`` request with 200 even when documents in
    it failed; the body says ``"errors": true`` and why per item. (retryable, reason) when
    something failed, else None. Only the first 4 KB are read: a cut-off body that says
    errors is still a failure (retried: the reason can't be seen)."""
    import json

    text = raw.decode("utf-8", "replace")
    if '"errors":true' not in text.replace(" ", ""):
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return True, "the response was too long to read the reason"
    for item in doc.get("items") or []:
        res = next(iter(item.values()), {}) if isinstance(item, dict) else {}
        if res.get("error"):
            err = res["error"]
            status = int(res.get("status") or 0)
            reason = f"{err.get('type')}: {err.get('reason')}" if isinstance(err, dict) else str(err)
            return status in (429, 503) or status >= 500, f"document {res.get('_id')}: {reason}"
    return True, "a document failed"


def plain_connection_error(e: BaseException, url: str) -> str:
    """'connection refused by host:port' rather than urllib3's pool message."""
    import socket
    from urllib.parse import urlparse

    u = urlparse(url)
    where = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
    seen: set[int] = set()
    cur: BaseException | None = e
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ConnectionRefusedError):
            return f"connection refused by {where} (is the receiver running?)"
        if isinstance(cur, socket.gaierror):
            return f"{u.hostname} doesn't resolve to an address"
        if isinstance(cur, (TimeoutError, socket.timeout)):
            return f"{where} didn't answer"
        if isinstance(cur, OSError) and cur.strerror:
            return f"connection to {where} failed: {cur.strerror}"
        nxt = getattr(cur, "reason", None) if isinstance(getattr(cur, "reason", None), BaseException) else None
        cur = nxt or cur.__cause__ or cur.__context__ or (cur.args[0] if cur.args and isinstance(cur.args[0],
                                                                                                    BaseException)
                                                          else None)
    return f"connection to {where} failed: {e}"


def _retry_after(resp: Any) -> float | None:
    v = (resp.headers or {}).get("retry-after")
    try:
        return float(v) if v is not None and str(v).strip().isdigit() else None
    except ValueError:
        return None


def send(delivery: Delivery, channel: Any, secrets: dict[str, str], data_dir: Path) -> Outcome:
    import requests

    hidden = tuple(v for v in secrets.values() if v)
    try:
        url, headers, body = build_request(delivery, channel, secrets, data_dir)
    except Exception as e:  # noqa: BLE001 -- a broken secret file etc.: say so, retry later
        return Outcome(False, True, clean_reason(f"could not build the request: {e}", *hidden))
    verify: Any = channel.config.get("ca_file") or True
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=TIMEOUT_SECONDS["webhook"],
                             allow_redirects=False, verify=verify, stream=True)
    except requests.exceptions.SSLError as e:
        return Outcome(False, True, clean_reason(f"TLS check failed (the receiver's certificate isn't trusted or "
                                                 f"doesn't match the name): {e}", *hidden))
    except requests.exceptions.Timeout:
        return Outcome(False, True, f"no answer within {TIMEOUT_SECONDS['webhook']} s")
    except requests.exceptions.ConnectionError as e:
        return Outcome(False, True, clean_reason(plain_connection_error(e, url), *hidden))
    except requests.RequestException as e:
        return Outcome(False, True, clean_reason(f"request failed: {e}", *hidden))
    try:
        raw = resp.raw.read(RESPONSE_READ_LIMIT, decode_content=True) if resp.raw is not None else b""
    except Exception:  # noqa: BLE001 -- the body is only for the error text
        raw = b""
    finally:
        resp.close()
    code = int(resp.status_code)
    if 200 <= code < 300:
        if (channel.config.get("framing") or "json") == "es_bulk":
            failed = bulk_item_failure(raw)
            if failed is not None:
                return Outcome(False, failed[0], clean_reason(f"HTTP {code} but the bulk request had errors: {failed[1]}",
                                                              *hidden), code)
        return Outcome(True, False, f"HTTP {code}", code)
    text = raw.decode("utf-8", "replace")
    if 300 <= code < 400:
        where = clean_reason(resp.headers.get("location") or "", *hidden)
        return Outcome(False, False, f"HTTP {code}: the receiver redirects{' to ' + where if where else ''}; Kratos "
                                     "doesn't follow redirects -- update the channel's URL", code)
    reason = clean_reason(f"HTTP {code}: {text}", *hidden)
    return Outcome(False, _retry.http_retryable(code), reason, code, _retry_after(resp))
