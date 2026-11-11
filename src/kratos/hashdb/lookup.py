"""Looking up one hash -- offline always, online only when a person asks (E.4 §3.10).

`offline(data_dir, h)`: what Kratos already knows about a hash -- every machine it was
seen on (`hash_reputation`), whether the installed MalwareBazaar set lists it, whether
the CIRCL filter knows its SHA-1. Nothing leaves this computer.

`online(...)`: sends that ONE hash to CIRCL hashlookup (`/lookup/sha256|sha1`) and, when
a key is set, MalwareBazaar's `get_info` -- only when all of these hold:
`hashdb.online` is on; the caller is a person at the Kratos computer (the TUI or CLI:
the `hashdb.lookup_online` permission is local-only, so MCP, the chat server, a schedule
and every agent tool are refused); and the person answered `y` to "this sends the hash
to circl.lu / abuse.ch". Never reachable from a model tool (tests scan for it). The
answer is cached in `hash_reputation` under no machine, with source "online" and date.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable

CIRCL_API = "https://hashlookup.circl.lu/lookup/{kind}/{value}"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
HTTP_TIMEOUT = 20


class LookupRefused(Exception):
    """Nothing was sent; `str()` says why and how to change it."""


def kind_of(h: str) -> str:
    v = str(h or "").strip().lower()
    if _SHA256.fullmatch(v):
        return "sha256"
    if _SHA1.fullmatch(v):
        return "sha1"
    raise ValueError("give a SHA-256 (64 hex digits) or a SHA-1 (40 hex digits); MD5 isn't looked up")


def offline(data_dir: Path, h: str) -> dict[str, Any]:
    from kratos.hashdb import circl, malwarebazaar, store

    kind = kind_of(h)
    v = h.strip().lower()
    rows = store.lookup(data_dir, v) if kind == "sha256" else []
    sha1 = v if kind == "sha1" else next((r["sha1"] for r in rows if r.get("sha1")), None)
    mb = malwarebazaar.Reader(data_dir)
    cr = circl.Reader(data_dir)
    mb_installed, circl_installed = mb.conn is not None, cr.bf is not None
    try:
        mb_hit = mb.get(v) if kind == "sha256" and mb_installed else None
        circl_hit = (sha1 in cr) if (sha1 and circl_installed) else None
    finally:
        mb.close()
        cr.close()
    return {"hash": v, "kind": kind, "machines": [r for r in rows if r["target_key"]],
            "online_cached": [r for r in rows if not r["target_key"]],
            "malwarebazaar_installed": mb_installed, "malwarebazaar": mb_hit,
            "circl_installed": circl_installed, "circl": circl_hit, "sha1": sha1}


def online(data_dir: Path, h: str, *, confirm: Callable[[str], bool], session: Any = None,
           actor: Any = None) -> dict[str, Any]:
    """Person-only: ask CIRCL (and MalwareBazaar with a key) about ONE hash. Raises
    LookupRefused (nothing sent) when off, refused, or not confirmed."""
    from kratos.authz import check
    from kratos.authz import permissions as P
    from kratos.hashdb import datasets as D
    from kratos.hashdb import settings as S
    from kratos.hashdb import store

    kind = kind_of(h)
    v = h.strip().lower()
    if not S.get(S.ONLINE, data_dir):
        raise LookupRefused("online lookups are off, so nothing was sent. To allow sending one hash at a time when "
                            "you ask, turn on \"Online hash lookups\" in the app: Settings -> General -> File "
                            "reputation (hashdb.online).")
    try:
        check.require(actor if actor is not None else check.current_actor(), P.HASHDB_LOOKUP, data_dir=data_dir,
                      obj=f"online lookup of {v[:12]}...")
    except check.Denied as e:
        raise LookupRefused(f"an online lookup is a person's action at the Kratos computer ({e.reason}); nothing "
                            "was sent") from None
    key = D.read_key(data_dir, "malwarebazaar")
    where = "circl.lu" + (" and abuse.ch" if key else "")
    if not confirm(f"This sends the hash {v} to {where}. Send it?"):
        raise LookupRefused("not sent (you answered no)")
    import requests

    s = session or requests.Session()
    out: dict[str, Any] = {"hash": v, "kind": kind, "at": time.time(), "circl": None, "malwarebazaar": None,
                           "errors": []}
    try:
        r = s.get(CIRCL_API.format(kind=kind, value=v), timeout=HTTP_TIMEOUT, headers={"Accept": "application/json"})
        if r.status_code == 404:
            out["circl"] = {"found": False}
        elif r.status_code == 200:
            j = r.json() if hasattr(r, "json") else {}
            srcs = j.get("source") or j.get("hashlookup:source") or []
            out["circl"] = {"found": True, "trust": j.get("hashlookup:trust"),
                            "sources": [str(x)[:60] for x in (srcs if isinstance(srcs, list) else [srcs])][:10],
                            "file_name": str(j.get("FileName") or "")[:200]}
        else:
            out["errors"].append(f"circl.lu answered HTTP {r.status_code}")
    except (requests.RequestException, ValueError) as e:
        out["errors"].append(f"circl.lu: {e.__class__.__name__}")
    if key:
        try:
            r = s.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": v},
                       headers={"Auth-Key": key}, timeout=HTTP_TIMEOUT)
            j = r.json() if r.status_code == 200 else {}
            status = str(j.get("query_status") or f"HTTP {r.status_code}")
            if status == "ok" and j.get("data"):
                d = j["data"][0]
                out["malwarebazaar"] = {"found": True, "first_seen": str(d.get("first_seen") or "")[:40],
                                        "signature": str(d.get("signature") or "")[:120],
                                        "sha256": str(d.get("sha256_hash") or "")[:64]}
            elif status == "hash_not_found":
                out["malwarebazaar"] = {"found": False}
            else:
                out["errors"].append(f"abuse.ch: {status}"[:120])
        except (requests.RequestException, ValueError) as e:
            out["errors"].append(f"abuse.ch: {e.__class__.__name__}")
    mbh, ch = out.get("malwarebazaar") or {}, out.get("circl") or {}
    verdict = ("known_bad" if mbh.get("found") else
               "known_good" if ch.get("found") and (ch.get("trust") or 0) >= 50 else "unknown")
    sources = [{"source": "online", "detail": f"circl.lu: {'found' if ch.get('found') else 'not found'}"
                + (f", trust {ch.get('trust')}" if ch.get("trust") is not None else ""),
                "date": time.strftime("%Y-%m-%d", time.gmtime(out["at"]))}]
    if key:
        sources.append({"source": "online", "detail": "abuse.ch: " + ("listed" if mbh.get("found") else "not listed"),
                        "date": sources[0]["date"]})
    out["verdict"] = verdict
    store.put_many(data_dir, store.ONLINE, [{"sha256": v, "sha1": v if kind == "sha1" else None, "verdict": verdict,
                                             "sources": sources, "path": None, "note": "a person's online lookup"}],
                   at=out["at"])
    return out
