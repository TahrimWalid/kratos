"""Turn what a producer has (an ``Alert``, ``FindingChange``s, stored events) into the
payload one channel sends. Secrets are removed from every string value first (always);
then, for a channel with "mask values" on, account names, addresses and host names are
replaced with B.2's placeholders (never restored -- the receiver sees placeholders).

Payload shapes, by channel kind:
  ntfy     {"text", "severity"}                 (exactly what agent.notify sends)
  webhook  {"body", "content_type"}             (the bytes signed are the bytes sent)
  syslog   {"frames": [RFC 5424 message, ...]}  (one per finding change / event)
  email    {"subject", "text", "html"}
"""
from __future__ import annotations

import html
import json
from typing import Any, Iterable

from kratos.outbox.config import Channel
from kratos.outbox.formats import Alert, FindingChange
from kratos.outbox.formats import ecs as F_ecs
from kratos.outbox.formats import kratos_json as F_kj
from kratos.outbox.formats import ocsf as F_ocsf
from kratos.outbox.formats import rfc5424 as F_syslog
from kratos.outbox.formats import text as F_text

_BUCKET_SEVERITY = {"critical": "high", "warning": "medium", "info": "info"}


# --- redaction and masking ----------------------------------------------------------------
def redact_obj(obj: Any, extra: tuple[str, ...] = ()) -> Any:
    """Every string in ``obj`` with secrets removed (privacy.secrets + the given values)."""
    from kratos.privacy.secrets import redact
    from kratos.utils.redact import redact_secrets

    if isinstance(obj, str):
        out, _n = redact(redact_secrets(obj, *extra))
        return out
    if isinstance(obj, dict):
        return {k: redact_obj(v, extra) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, extra) for v in obj]
    return obj


def _masker(channel: Channel, machine: str | None, data_dir: Any) -> Any:
    from kratos.privacy.mask import KnownValues, Masker
    from kratos.privacy import values as _values

    m = machine or ""
    try:
        known = _values.gather(m, data_dir) if m else KnownValues()
    except Exception:  # noqa: BLE001 -- masking still runs on what the text shows
        known = KnownValues()
    return Masker(mode="standard", scope=f"channel:{channel.name}", data_dir=data_dir, machine=m, values=known)


def _keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_keys(v) for v in obj]
    return None


def mask_json_text(text: str, masker: Any) -> str:
    """Mask a serialised JSON body as one text (one plan, consistent placeholders); if that
    would change its structure (a key or a non-string value matched a name), mask each
    string value on its own instead."""
    masked = masker.mask(text)
    try:
        if _keys(json.loads(masked)) == _keys(json.loads(text)):
            return masked
    except ValueError:
        pass
    return json.dumps(_mask_leaves(json.loads(text), masker), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _mask_leaves(obj: Any, masker: Any) -> Any:
    if isinstance(obj, str):
        return masker.mask(obj)
    if isinstance(obj, dict):
        return {k: _mask_leaves(v, masker) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_leaves(v, masker) for v in obj]
    return obj


def _mask_ndjson(text: str, masker: Any) -> str:
    return "\n".join(mask_json_text(line, masker) if line.strip() else line for line in text.split("\n"))


# --- webhook bodies -----------------------------------------------------------------------
def _stable_id(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _webhook_body(channel: Channel, docs: list[tuple[dict[str, Any], str, str]], *, single: bool) -> dict[str, Any]:
    """docs: (document, stable id, sourcetype). ``single``: one message, not a batch."""
    framing = channel.config.get("framing") or "json"
    if framing == "json":
        body = F_kj.dumps(docs[0][0] if single else [d for d, _i, _s in docs])
        return {"body": body, "content_type": "application/json"}
    if framing == "ndjson":
        return {"body": "\n".join(F_kj.dumps(d) for d, _i, _s in docs) + "\n", "content_type": "application/x-ndjson"}
    if framing == "es_bulk":
        index = channel.config.get("index") or "kratos"
        lines = []
        for d, i, _s in docs:
            lines.append(F_kj.dumps({"index": {"_index": index, "_id": i}}))   # a retry overwrites, never duplicates
            lines.append(F_kj.dumps(d))
        return {"body": "\n".join(lines) + "\n", "content_type": "application/x-ndjson"}
    # hec: Splunk HTTP Event Collector style
    lines = [F_kj.dumps({"event": d, "source": "kratos", "sourcetype": s}) for d, _i, s in docs]
    return {"body": "\n".join(lines), "content_type": "application/json"}


def _finalise_webhook(channel: Channel, payload: dict[str, Any], machine: str | None, data_dir: Any) -> dict[str, Any]:
    if not channel.mask_values:
        return payload
    masker = _masker(channel, machine, data_dir)
    framing = channel.config.get("framing") or "json"
    body = payload["body"]
    payload = dict(payload)
    payload["body"] = mask_json_text(body, masker) if framing == "json" else _mask_ndjson(body, masker)
    return payload


def _mask_text(channel: Channel, text: str, machine: str | None, data_dir: Any) -> str:
    return _masker(channel, machine, data_dir).mask(text) if channel.mask_values else text


# --- alerts -------------------------------------------------------------------------------
def alert(channel: Channel, a: Alert, data_dir: Any) -> dict[str, Any]:
    from kratos.untrusted import for_display

    a = Alert(**{**a.__dict__, "text": redact_obj(a.text), "findings": tuple(redact_obj(list(a.findings)))})
    if channel.kind == "ntfy":
        return {"text": a.text, "severity": a.bucket}           # agent.notify cleans it again on send
    if channel.kind == "webhook":
        obj = F_kj.alert(a)
        return _finalise_webhook(channel, _webhook_body(channel, [(obj, _stable_id(a.message_id), "kratos:alert")],
                                                        single=True), a.machine, data_dir)
    text = for_display(a.text)
    if channel.kind == "syslog":
        params = {"id": a.message_id, "severity": a.worst or _BUCKET_SEVERITY.get(a.bucket, "info"),
                  "machine": a.machine, "source": a.source, "name": a.name,
                  "findings": ",".join(sorted({str(f.get("id")) for f in a.findings if f.get("id")})) or None}
        frame = F_syslog.message(at=a.at, severity=params["severity"], msgid=a.kind, msg=text, kratos_params=params,
                                 pen=int(channel.config.get("sd_pen") or 32473), sw_version=F_syslog.sw_version())
        return {"frames": [_mask_text(channel, frame, a.machine, data_dir)]}
    if channel.kind == "email":
        body = text + "\n\n-- \nSent by Kratos. Evidence stays on the Kratos computer; open Kratos and type /findings."
        subject = "Kratos: " + for_display(a.subject)
        body, subject = _mask_text(channel, body, a.machine, data_dir), _mask_text(channel, subject, a.machine, data_dir)
        return {"subject": subject, "text": body, "html": _html(body)}
    raise ValueError(f"no alert rendering for {channel.kind}")


def _html(text: str) -> str:
    return ("<html><body><pre style=\"font-family: ui-monospace, monospace; white-space: pre-wrap\">"
            + html.escape(text) + "</pre></body></html>")


# --- findings changes ------------------------------------------------------------------------
def _redact_change(c: FindingChange) -> FindingChange:
    return FindingChange(**{**c.__dict__, "finding": redact_obj(c.finding), "title": redact_obj(c.title),
                            "reason": redact_obj(c.reason) if c.reason else c.reason})


def finding_doc(channel: Channel, c: FindingChange) -> tuple[dict[str, Any], str]:
    """(the document for this change in the channel's format, its sourcetype)."""
    if channel.format == "ocsf":
        doc = F_ocsf.finding(c)
        return doc, f"ocsf:{doc['class_uid']}"
    if channel.format == "ecs":
        return F_ecs.finding(c), "ecs:finding"
    return F_kj.finding(c), "kratos:finding"


def finding(channel: Channel, c: FindingChange, data_dir: Any) -> dict[str, Any]:
    c = _redact_change(c)
    if channel.kind == "webhook":
        doc, st = finding_doc(channel, c)
        return _finalise_webhook(channel, _webhook_body(channel, [(doc, _stable_id(c.message_id), st)], single=True),
                                 c.machine, data_dir)
    if channel.kind == "syslog":
        return {"frames": [_mask_text(channel, _finding_frame(channel, c), c.machine, data_dir)]}
    if channel.kind == "email":
        return findings_digest(channel, [c], data_dir)
    raise ValueError(f"no findings rendering for {channel.kind}")


def _finding_frame(channel: Channel, c: FindingChange) -> str:
    params = {"id": c.message_id, "finding_key": c.finding_key, "rule": c.rule_id, "severity": c.severity,
              "change": c.change, "state": c.state, "machine": c.machine}
    pen = int(channel.config.get("sd_pen") or 32473)
    if channel.format == "text":
        msg = "\n".join(F_text.lines(c, evidence=False))
    else:
        doc, _st = finding_doc(channel, c)
        msg = F_kj.dumps(doc)
        head = len(F_syslog.message(at=c.at, severity=c.severity, msgid="finding", msg="", kratos_params=params,
                                    pen=pen).encode("utf-8"))
        if not F_syslog.fits(msg, head_bytes=head):     # keep it valid JSON: drop the bulky parts first
            for key in ("evidence", "recommendation", "entities"):
                _drop(doc, key)
                msg = F_kj.dumps(doc)
                if F_syslog.fits(msg, head_bytes=head):
                    break
    return F_syslog.message(at=c.at, severity=c.severity, msgid="finding", msg=msg, kratos_params=params, pen=pen,
                            sw_version=F_syslog.sw_version())


def _drop(doc: Any, key: str) -> None:
    if isinstance(doc, dict):
        doc.pop(key, None)
        for v in doc.values():
            _drop(v, key)
    elif isinstance(doc, list):
        for v in doc:
            _drop(v, key)


def findings_digest(channel: Channel, changes: Iterable[FindingChange], data_dir: Any) -> dict[str, Any]:
    changes = [_redact_change(c) for c in changes]
    subject, body = F_text.digest(changes)
    machine = changes[0].machine if len({c.machine for c in changes}) == 1 and changes else None
    subject, body = _mask_text(channel, subject, machine, data_dir), _mask_text(channel, body, machine, data_dir)
    return {"subject": subject, "text": body, "html": _html(body)}


# --- events --------------------------------------------------------------------------------
def events(channel: Channel, rows: list[tuple[int, str, dict[str, Any]]], data_dir: Any, *, at: float,
           first_row: int, last_row: int) -> tuple[dict[str, Any], int]:
    """(payload, how many events had no OCSF class and were skipped). rows: (row id,
    machine, stored ECS document)."""
    skipped = 0
    docs: list[tuple[dict[str, Any], str, str]] = []
    for row_id, machine, doc in rows:
        doc = redact_obj(doc)
        if channel.format == "ocsf":
            o = F_ocsf.event(doc, machine=machine, row_id=row_id)
            if o is None:
                skipped += 1
                continue
            docs.append((o, _stable_id(f"{machine}:{row_id}"), f"ocsf:{o['class_uid']}"))
        elif channel.format == "ecs":
            docs.append((F_ecs.event(doc), str((doc.get("event") or {}).get("id") or _stable_id(f"{machine}:{row_id}")),
                         "ecs:event"))
        else:
            docs.append((doc, str((doc.get("event") or {}).get("id") or row_id), "kratos:event"))
    machines = {m for _r, m, _d in rows}
    machine = next(iter(machines)) if len(machines) == 1 else None
    if channel.kind == "webhook":
        if channel.format == "kratos" and (channel.config.get("framing") or "json") == "json":
            obj = F_kj.events([d for d, _i, _s in docs], machine=machine, first_row=first_row, last_row=last_row, at=at)
            payload = {"body": F_kj.dumps(obj), "content_type": "application/json"}
        else:
            payload = _webhook_body(channel, docs, single=False) if docs else {"body": "", "content_type": "skip"}
        if payload.get("content_type") != "skip":
            payload = _finalise_webhook(channel, payload, machine, data_dir)
        return payload, skipped
    if channel.kind == "syslog":
        frames = []
        pen = int(channel.config.get("sd_pen") or 32473)
        for (d, i, _s), (row_id, m, raw) in zip(docs, [r for r in rows if channel.format != "ocsf"
                                                       or F_ocsf.event_class(r[2]) is not None]):
            if channel.format == "text":
                msg = str(raw.get("message") or (raw.get("event") or {}).get("original") or
                          (raw.get("event") or {}).get("action") or "")
            else:
                msg = F_kj.dumps(d)
            frame = F_syslog.message(at=_event_epoch(raw, at), severity="info", msgid="event", msg=msg,
                                     kratos_params={"id": i, "machine": m, "row": row_id,
                                                    "dataset": (raw.get("event") or {}).get("dataset")},
                                     pen=pen, sw_version=F_syslog.sw_version())
            frames.append(_mask_text(channel, frame, m, data_dir))
        return {"frames": frames}, skipped
    raise ValueError(f"no events rendering for {channel.kind}")


def _event_epoch(doc: dict[str, Any], default: float) -> float:
    from kratos.utils.timeutil import parse_stored_instant

    when = parse_stored_instant(doc.get("@timestamp"))
    return when.timestamp() if when is not None else default
