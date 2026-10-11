"""Login records (wtmp / btmp) as glibc writes them, and the signs of editing (0.3, §6.4).

`struct utmp` on glibc x86_64 and aarch64 is 384 bytes:

    short ut_type; pid_t ut_pid; char ut_line[32]; char ut_id[4]; char ut_user[32];
    char ut_host[256]; struct { short e_termination, e_exit; } ut_exit;
    int32 ut_session; struct { int32 tv_sec, tv_usec; } ut_tv; int32 ut_addr_v6[4];
    char reserved[20];

A file whose size isn't a multiple of 384, or whose records don't look like
utmp records, is reported as an unknown format -- never judged. musl (Alpine)
has no real wtmp, and newer distributions (Ubuntu 24.04+) keep logins in wtmpdb
instead; both show up as a coverage note.

Signs of editing, on the newest records read:
  * an all-zero record between real ones -- what log wipers leave behind;
  * time going backwards between consecutive records by more than a tolerance
    (clock-change records, types 3/4, are allowed to do that).

Standard library only.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

RECORD = struct.Struct("<hhi32s4s32s256shhiii4i20s")
assert RECORD.size == 384
TYPES = {0: "empty", 1: "run_level", 2: "boot", 3: "new_time", 4: "old_time", 5: "init", 6: "login_process",
         7: "user", 8: "dead", 9: "accounting"}
BACKWARDS_TOLERANCE_SECONDS = 300
_TS_MIN, _TS_MAX = 946684800, 4102444800   # 2000 .. 2100


@dataclass(frozen=True)
class Login:
    index: int
    type: int
    pid: int
    line: str
    user: str
    host: str
    ts: float
    zero: bool

    @property
    def type_name(self) -> str:
        return TYPES.get(self.type, str(self.type))


def _text(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def parse(data: bytes, first_index: int = 0) -> list[Login]:
    out: list[Login] = []
    for i in range(len(data) // RECORD.size):
        chunk = data[i * RECORD.size:(i + 1) * RECORD.size]
        (ut_type, _pad, pid, line, _id, user, host, _term, _exit, _session, sec, usec, *_rest) = RECORD.unpack(chunk)
        out.append(Login(index=first_index + i, type=ut_type, pid=pid, line=_text(line), user=_text(user),
                         host=_text(host), ts=sec + usec / 1_000_000, zero=not any(chunk)))
    return out


def looks_like_utmp(records: list[Login]) -> bool:
    """Most non-zero records have a known type and a time between 2000 and 2100."""
    real = [r for r in records if not r.zero]
    if not real:
        return True
    good = sum(1 for r in real if r.type in TYPES and _TS_MIN <= r.ts <= _TS_MAX)
    return good >= 0.9 * len(real)


def check(data: bytes | None, *, size: int | None, offset: int | None, name: str) -> dict[str, Any]:
    """{status: ok|suspicious|unknown, evidence: [...], coverage: str, records: n,
    zeroed: [...], backwards: [...]} for one login file's newest records."""
    if data is None:
        return {"status": "unknown", "evidence": [], "coverage": f"{name} could not be read", "records": 0}
    if size is not None and size % RECORD.size:
        return {"status": "unknown", "evidence": [], "records": 0,
                "coverage": f"{name} is {size} bytes, not a whole number of 384-byte glibc records -- unknown format "
                            "(not judged)"}
    first = (offset or 0) // RECORD.size
    records = parse(data, first)
    if not looks_like_utmp(records):
        return {"status": "unknown", "evidence": [], "records": len(records),
                "coverage": f"{name} doesn't look like glibc login records -- unknown format (not judged)"}
    evidence: list[str] = []
    zeroed: list[int] = []
    backwards: list[dict[str, Any]] = []
    real_idx = [i for i, r in enumerate(records) if not r.zero]
    if real_idx:
        lo, hi = real_idx[0], real_idx[-1]
        zeroed = [records[i].index for i in range(lo, hi + 1) if records[i].zero]
    prev: Login | None = None
    for r in records:
        if r.zero:
            continue
        if prev is not None and r.ts < prev.ts - BACKWARDS_TOLERANCE_SECONDS \
                and r.type not in (3, 4) and prev.type not in (3, 4):
            backwards.append({"index": r.index, "from": prev.ts, "to": r.ts, "user": r.user, "type": r.type_name})
        prev = r
    if zeroed:
        evidence.append(f"{name}: {len(zeroed)} all-zero record(s) between real login records "
                        f"(record number(s) {', '.join(map(str, zeroed[:10]))}) -- what log-wiping tools leave behind")
    for b in backwards[:5]:
        evidence.append(f"{name}: record {b['index']} ({b['type']}, user {b['user'] or '-'}) is "
                        f"{int(b['from'] - b['to'])} s EARLIER than the record before it -- records out of order")
    coverage = (f"read the newest {len(records)} record(s) of {name}"
                + (" (the whole file)" if not offset else f", from record {first}"))
    return {"status": "suspicious" if (zeroed or backwards) else "ok", "evidence": evidence, "coverage": coverage,
            "records": len(records), "zeroed": zeroed, "backwards": backwards}
