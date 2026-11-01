"""CISA's own per-CVE SSVC assessments, for the vulnerability index (D.3).

Source: CISA "vulnrichment" (https://github.com/cisagov/vulnrichment, CC0 1.0). One
CVE Record Format JSON file per CVE under ``<year>/<n>xxx/``; CISA's ADP container
(``providerMetadata.shortName == "CISA-ADP"``) carries an SSVC block::

    {"other": {"type": "ssvc", "content": {"id": "CVE-...", "options": [
        {"Exploitation": "none|poc|active"}, {"Automatable": "no|yes"},
        {"Technical Impact": "partial|total"}], "version": "2.0.3", "timestamp": "..."}}}

`kratos vulndb-update` downloads the repository's default branch as one tarball
(``codeload.github.com``, ~105 MB in November 2026), streams it -- nothing is
extracted to disk, a member is read only when its path is a CVE file of the expected
shape and size -- and keeps only those three values, CISA's timestamp and the SSVC
version. The archive's ETag is kept, so a repeat update of an unchanged archive is
one 304. An option value outside CISA's closed sets is dropped and counted (shown by
`kratos vulndb-update --status`), never stored.

The rows replace the table as a whole inside the update's transaction: a failed
download or parse keeps the previous rows (update.py's contract for enrichment).
"""
from __future__ import annotations

import json
import re
import sqlite3
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

VULNRICHMENT_URL = "https://codeload.github.com/cisagov/vulnrichment/tar.gz/refs/heads/develop"
SOURCE = "ssvc"                        # the `meta` row name
ARCHIVE_MAX_BYTES = 1024 ** 3          # ~105 MB today; refuse anything absurd
RECORD_MAX_BYTES = 16 * 1024 ** 2      # the largest record today is ~9.7 MB
MIN_ROWS = 10_000                      # ~205,000 today: far fewer means a broken archive

EXPLOITATION = ("none", "poc", "active")
AUTOMATABLE = ("no", "yes")
TECHNICAL_IMPACT = ("partial", "total")
_OPTION_KEYS = {"Exploitation": ("exploitation", EXPLOITATION), "Automatable": ("automatable", AUTOMATABLE),
                "Technical Impact": ("technical_impact", TECHNICAL_IMPACT)}

_MEMBER_RE = re.compile(r"^[A-Za-z0-9._-]+/\d{4}/\d{1,4}xxx/(CVE-\d{4}-\d{4,7})\.json$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_VERSION_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){0,3}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T[0-9:.]{1,20}(Z|[+-]\d{2}:?\d{2})?)?$")

NOTICE = ("- CISA vulnrichment (SSVC Exploitation / Automatable / Technical Impact per CVE, "
          "https://github.com/cisagov/vulnrichment): CC0 1.0.")


@dataclass
class Parsed:
    rows: list[tuple[str, str | None, str | None, str | None, str, str, str]]
    files: int = 0          # CVE files read
    dropped: int = 0        # option values outside CISA's closed sets
    skipped: int = 0        # members that were not a CVE file of the expected shape, or too large


def ssvc_of_record(rec: Any, cve: str) -> tuple[dict[str, str | None], str, str, int] | None:
    """(values, CISA's timestamp, SSVC version, dropped values) from one CVE record's
    CISA-ADP SSVC block, or None when it has none. `cve` is the file's own id: a block
    naming another CVE is ignored."""
    if not isinstance(rec, dict):
        return None
    adp = (rec.get("containers") or {}).get("adp") if isinstance(rec.get("containers"), dict) else None
    for container in adp or []:
        if not isinstance(container, dict):
            continue
        meta = container.get("providerMetadata") if isinstance(container.get("providerMetadata"), dict) else {}
        if meta.get("shortName") != "CISA-ADP":
            continue
        for metric in container.get("metrics") or []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or other.get("type") != "ssvc":
                continue
            content = other.get("content") if isinstance(other.get("content"), dict) else {}
            if str(content.get("id") or "").upper() != cve:
                continue
            values: dict[str, str | None] = {"exploitation": None, "automatable": None, "technical_impact": None}
            dropped = 0
            for opt in content.get("options") or []:
                if not isinstance(opt, dict):
                    dropped += 1
                    continue
                for key, raw in opt.items():
                    spec = _OPTION_KEYS.get(str(key))
                    if spec is None:
                        dropped += 1
                        continue
                    column, allowed = spec
                    value = str(raw or "").strip().lower()
                    if value in allowed:
                        values[column] = value
                    else:
                        dropped += 1
            stamp = str(content.get("timestamp") or "")
            version = str(content.get("version") or "")
            return (values, stamp if _TIMESTAMP_RE.match(stamp) else "",
                    version if _VERSION_RE.match(version) else "", dropped)
    return None


def parse_archive(path: Path) -> Parsed:
    """Stream the vulnrichment tarball. Raises ValueError for an archive that can't be read."""
    out = Parsed(rows=[])
    try:
        with tarfile.open(path, "r|gz") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                m = _MEMBER_RE.match(member.name)
                if not m:
                    continue
                if member.size > RECORD_MAX_BYTES:
                    out.skipped += 1
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    out.skipped += 1
                    continue
                cve = m.group(1).upper()
                try:
                    rec = json.loads(fh.read(RECORD_MAX_BYTES + 1))
                except (ValueError, UnicodeDecodeError):
                    out.skipped += 1
                    continue
                out.files += 1
                got = ssvc_of_record(rec, cve)
                if got is None:
                    continue
                values, stamp, version, dropped = got
                out.dropped += dropped
                if not any(values.values()):
                    continue
                out.rows.append((cve, values["exploitation"], values["automatable"], values["technical_impact"],
                                 stamp, version, "cisa-adp"))
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ValueError(f"the archive could not be read ({e.__class__.__name__})") from None
    return out


def store(conn: sqlite3.Connection, parsed: Parsed) -> None:
    """Replace every row (the caller holds the transaction)."""
    conn.execute("DELETE FROM ssvc_inputs")
    conn.executemany("INSERT OR REPLACE INTO ssvc_inputs (cve, exploitation, automatable, technical_impact, "
                     "assessed_at, ssvc_version, source) VALUES (?, ?, ?, ?, ?, ?, ?)", parsed.rows)


def detail_text(parsed: Parsed) -> str:
    return (f"{len(parsed.rows)} CISA assessments from {parsed.files} CVE records; "
            f"{parsed.dropped} option value(s) outside CISA's sets dropped; {parsed.skipped} file(s) skipped")


def lookup(conn: sqlite3.Connection, cves: Iterable[str]) -> dict[str, dict[str, Any]]:
    """CISA's assessment for each CVE that has one. An index built before D.3 has no
    table: then nothing (every input falls back to its documented estimate)."""
    wanted = sorted({str(c).upper() for c in cves if _CVE_RE.match(str(c).upper())})
    out: dict[str, dict[str, Any]] = {}
    try:
        for chunk in range(0, len(wanted), 500):
            part = wanted[chunk:chunk + 500]
            for r in conn.execute("SELECT cve, exploitation, automatable, technical_impact, assessed_at, "
                                  f"ssvc_version, source FROM ssvc_inputs WHERE cve IN ({','.join('?' * len(part))})",
                                  part):
                out[r[0]] = {"exploitation": r[1], "automatable": r[2], "technical_impact": r[3],
                             "assessed_at": r[4] or "", "ssvc_version": r[5] or "", "source": r[6] or "cisa-adp"}
    except sqlite3.OperationalError:
        return {}
    return out
