"""Lines containers wrote (D.5, dataset kratos.container).

- journald log driver (Docker, Podman): the journal entry carries CONTAINER_ID_FULL,
  CONTAINER_NAME and IMAGE_NAME; the line is MESSAGE. dockerd's / conmon's own messages
  (no CONTAINER_ID_FULL) are not container lines and are skipped;
- Docker json-file: ``{"log": "...\\n", "stream": "stdout", "time": "<RFC 3339>"}``;
- Podman k8s-file: ``<RFC 3339> stdout F <line>`` (P = a partial line continued next).

Every line is machine text (A.4): it is masked and capped when it becomes an event,
never interpreted.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from kratos.logsources.parsers import Parsed, journal_int, record_parts

_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_K8S_RE = re.compile(r"^(?P<ts>\S+) (?P<stream>stdout|stderr) (?P<tag>[FP]) ?(?P<msg>.*)$", re.DOTALL)
_FRACTION = re.compile(r"\.(\d{1,9})")


def parse_time(text: str) -> float | None:
    """RFC 3339 with up to nanoseconds ('2026-11-02T02:46:46.929699457Z') -> epoch seconds."""
    t = str(text or "").strip()
    if not t:
        return None
    t = t[:-1] + "+00:00" if t.endswith("Z") else t
    t = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], t, count=1)
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    return dt.timestamp() if dt.tzinfo is not None else None


def _container_fields(cid: str | None, name: str | None, image: str | None, image_hash: str | None,
                      runtime: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if cid and _ID_RE.match(cid):
        out["container_id"] = cid
    if name:
        out["container_name"] = str(name)[:256]
    if image:
        out["container_image_name"] = str(image)[:512]
    if image_hash and re.match(r"^sha256:[0-9a-f]{64}$", image_hash):
        out["container_image_hash"] = [image_hash]
    if runtime in ("docker", "podman"):
        out["container_runtime"] = runtime
    return out


def to_parsed(rec: Any) -> Parsed | None:
    """A journald-driver entry (the journal sync of source 'containers')."""
    if rec.kind != "journal":
        return None
    e = rec.entry or {}
    cid = e.get("CONTAINER_ID_FULL")
    if not isinstance(cid, str) or not _ID_RE.match(cid):
        return None
    _prog, _pid, msg, _orig, cursor = record_parts(rec)
    runtime = "podman" if str(e.get("_COMM") or "") in ("conmon", "podman") else "docker"
    fields = _container_fields(cid, e.get("CONTAINER_NAME") if isinstance(e.get("CONTAINER_NAME"), str) else None,
                               e.get("IMAGE_NAME") if isinstance(e.get("IMAGE_NAME"), str) else None, None, runtime)
    fields["log_syslog_priority"] = journal_int(e, "PRIORITY")
    return Parsed(ts=rec.ts, action="container_output", provider=str(e.get("CONTAINER_NAME") or "container")[:256],
                  message=msg, fields={k: v for k, v in fields.items() if v not in (None, "")}, cursor=cursor)


def parse(read: Any) -> list[Parsed]:
    return [p for p in (to_parsed(r) for r in read.records) if p is not None]


def file_line(fmt: str, raw: str, meta: dict[str, Any], cid: str) -> Parsed | None:
    """One json-file / k8s-file line from a container's log file (the agent's chunk read)."""
    if fmt == "json-file":
        try:
            d = json.loads(raw)
        except (ValueError, RecursionError):
            return None
        if not isinstance(d, dict) or not isinstance(d.get("log"), str):
            return None
        ts = parse_time(str(d.get("time") or ""))
        msg = d["log"].rstrip("\n")
        stream = str(d.get("stream") or "")
    else:
        m = _K8S_RE.match(raw)
        if not m:
            return None
        ts = parse_time(m.group("ts"))
        msg = m.group("msg")
        stream = m.group("stream")
    if ts is None:
        return None
    engine = str(meta.get("engine") or "")
    fields = _container_fields(cid, meta.get("name"), meta.get("image"), meta.get("image_id"),
                               "podman" if engine.startswith("podman") else "docker")
    return Parsed(ts=ts, action="container_output", provider=str(meta.get("name") or "container")[:256],
                  outcome=None, message=msg, original=raw, fields=fields,
                  log_file_path=None if stream not in ("stdout", "stderr") else None)
