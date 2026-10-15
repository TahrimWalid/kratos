"""The local vulnerability index: ``data_dir/vulndb/vulndb.sqlite``.

A separate, replaceable file -- large and regenerable, never part of kratos.db.
``kratos vulndb-update`` (``kratos.pkgvuln.update``) builds a new one next to it
and swaps it in with one ``os.replace``; everything here only reads it.

Tables:

- ``info(key, value)``                 -- schema version, when it was built, the releases it holds;
- ``meta(source, fetched_at, etag, last_modified, rows, detail)`` -- one row per data source;
- ``ecosystems(id, name, selector)``   -- OSV release names kept, and which selector wanted them;
- ``advisories(id, osv_id, top, modified, published, summary, distro_severity, precise, withdrawn)``;
- ``ranges(advisory, ecosystem, package, introduced, fixed, last_affected, distro_severity)``;
- ``versions(advisory, ecosystem, package, version)`` -- explicit affected versions
  (kept only for an advisory entry that has no range: OSV's ``versions`` list is
  otherwise an expansion of the range, and Ubuntu's alone is gigabytes);
- ``advisory_cves(advisory, cve)``;
- ``precise_cves(top, osv_id, cve)`` -- every CVE that has a distribution per-CVE
  record, whichever releases it names (its silence about a release is information);
- ``seen(top, osv_id, modified)``      -- every advisory id the last build looked at
  (relevant or not), so an incremental update fetches only what changed;
- ``kev(cve, date_added, due_date, known_ransomware, vendor, product, name)``;
- ``epss(cve, score, percentile, date)``;
- ``cvss(cve, score, vector, version, severity)``.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 2
# A release counts as covered by its distribution's per-CVE records (DEBIAN-CVE-*,
# UBUNTU-CVE-*) when at least this many of them name it. Then a CVE that has a
# per-CVE record which does NOT name this release+package means "not affected
# here", and a bundle notice (USN, DSA) listing the CVE alongside others is not
# enough to report it. Below the threshold (Debian 11 today: ~1,400 records) the
# per-CVE data is partial and its silence proves nothing.
PRECISE_COVERAGE_MIN = 5000
DIR_NAME = "vulndb"
FILE_NAME = "vulndb.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS info (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS meta (source TEXT PRIMARY KEY, fetched_at REAL, etag TEXT, last_modified TEXT,
                                 rows INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS ecosystems (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, selector TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS advisories (id INTEGER PRIMARY KEY, osv_id TEXT NOT NULL, top TEXT NOT NULL,
                                       modified TEXT, published TEXT, summary TEXT, distro_severity TEXT,
                                       precise INTEGER NOT NULL DEFAULT 0, UNIQUE (top, osv_id));
CREATE TABLE IF NOT EXISTS ranges (advisory INTEGER NOT NULL, ecosystem INTEGER NOT NULL, package TEXT NOT NULL,
                                   introduced TEXT, fixed TEXT, last_affected TEXT, distro_severity TEXT);
CREATE INDEX IF NOT EXISTS ranges_pkg ON ranges (ecosystem, package);
CREATE INDEX IF NOT EXISTS ranges_adv ON ranges (advisory);
CREATE TABLE IF NOT EXISTS versions (advisory INTEGER NOT NULL, ecosystem INTEGER NOT NULL, package TEXT NOT NULL,
                                     version TEXT NOT NULL, distro_severity TEXT);
CREATE INDEX IF NOT EXISTS versions_pkg ON versions (ecosystem, package);
CREATE INDEX IF NOT EXISTS versions_adv ON versions (advisory);
CREATE TABLE IF NOT EXISTS advisory_cves (advisory INTEGER NOT NULL, cve TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS advisory_cves_adv ON advisory_cves (advisory);
CREATE INDEX IF NOT EXISTS advisory_cves_cve ON advisory_cves (cve);
CREATE TABLE IF NOT EXISTS precise_cves (top TEXT NOT NULL, osv_id TEXT NOT NULL, cve TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS precise_cves_cve ON precise_cves (top, cve);
CREATE INDEX IF NOT EXISTS precise_cves_id ON precise_cves (top, osv_id);
CREATE TABLE IF NOT EXISTS seen (top TEXT NOT NULL, osv_id TEXT NOT NULL, modified TEXT, PRIMARY KEY (top, osv_id));
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, date_added TEXT, due_date TEXT, known_ransomware TEXT,
                                vendor TEXT, product TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, percentile REAL, date TEXT);
CREATE TABLE IF NOT EXISTS cvss (cve TEXT PRIMARY KEY, score REAL, vector TEXT, version TEXT, severity TEXT);
"""


def path_for(data_dir: Path) -> Path:
    return Path(data_dir) / DIR_NAME / FILE_NAME


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR REPLACE INTO info (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))


def open_readonly(data_dir: Path) -> sqlite3.Connection | None:
    """The current index, read-only, or None when there is none (or it isn't one).
    Opening by URI with mode=ro: matching can never write to it."""
    p = path_for(data_dir)
    if not p.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT value FROM info WHERE key = 'schema_version'").fetchone()
    except sqlite3.Error:
        return None
    if row is None or str(row[0]) != str(SCHEMA_VERSION):
        conn.close()
        return None
    return conn


def get_info(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM info WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return row[0]


@dataclass
class Status:
    """What `kratos vulndb-update --status`, /doctor and every package result say
    about the index."""
    present: bool
    built_at: float | None = None
    selectors: list[str] = field(default_factory=list)
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    size_bytes: int = 0

    def age_days(self, now: float | None = None) -> float | None:
        if self.built_at is None:
            return None
        return max(0.0, ((time.time() if now is None else now) - self.built_at) / 86400.0)


def status(data_dir: Path) -> Status:
    conn = open_readonly(data_dir)
    if conn is None:
        return Status(present=False)
    try:
        built = get_info(conn, "built_at")
        sources = {r["source"]: {"fetched_at": r["fetched_at"], "rows": r["rows"], "detail": r["detail"]}
                   for r in conn.execute("SELECT source, fetched_at, rows, detail FROM meta")}
        return Status(present=True, built_at=float(built) if built is not None else None,
                      selectors=list(get_info(conn, "selectors", []) or []), sources=sources,
                      size_bytes=path_for(data_dir).stat().st_size)
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return Status(present=False)
    finally:
        conn.close()


def held_selectors(data_dir: Path) -> list[str]:
    """The releases the current index file was built for -- read even from an index
    of an older schema, so an update that rebuilds it keeps the same releases."""
    p = path_for(data_dir)
    if not p.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        try:
            row = conn.execute("SELECT value FROM info WHERE key = 'selectors'").fetchone()
        finally:
            conn.close()
        value = json.loads(row[0]) if row else []
    except (sqlite3.Error, ValueError, TypeError):
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


# --------------------------------------------------------------------------- queries matching uses
@dataclass(frozen=True)
class Entry:
    """One advisory's statement about one package in one release."""
    advisory: int
    osv_id: str
    precise: bool            # a per-CVE record (DEBIAN-CVE-*, UBUNTU-CVE-*, ALPINE-CVE-*), not a bundle notice
    introduced: str | None
    fixed: str | None
    last_affected: str | None
    version: str | None      # an explicit affected version (no range)
    distro_severity: str


def ecosystem_ids(conn: sqlite3.Connection, selector_key: str) -> list[int]:
    return [int(r[0]) for r in conn.execute("SELECT id FROM ecosystems WHERE selector = ?", (selector_key,))]


def entries_for(conn: sqlite3.Connection, eco_ids: Iterable[int], package: str) -> list[Entry]:
    ids = list(eco_ids)
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    out: list[Entry] = []
    for r in conn.execute(
            f"SELECT r.advisory, a.osv_id, a.precise, r.introduced, r.fixed, r.last_affected, "
            f"COALESCE(r.distro_severity, a.distro_severity, '') AS sev FROM ranges r "
            f"JOIN advisories a ON a.id = r.advisory WHERE r.ecosystem IN ({marks}) AND r.package = ?",
            (*ids, package)):
        out.append(Entry(int(r[0]), r[1], bool(r[2]), r[3], r[4], r[5], None, r[6] or ""))
    for r in conn.execute(
            f"SELECT v.advisory, a.osv_id, a.precise, v.version, COALESCE(v.distro_severity, a.distro_severity, '') "
            f"FROM versions v JOIN advisories a ON a.id = v.advisory "
            f"WHERE v.ecosystem IN ({marks}) AND v.package = ?", (*ids, package)):
        out.append(Entry(int(r[0]), r[1], bool(r[2]), None, None, None, r[3], r[4] or ""))
    return out


def cves_for(conn: sqlite3.Connection, advisory_ids: Iterable[int]) -> dict[int, list[str]]:
    ids = sorted(set(advisory_ids))
    out: dict[int, list[str]] = {i: [] for i in ids}
    for chunk in range(0, len(ids), 500):
        part = ids[chunk:chunk + 500]
        for r in conn.execute(f"SELECT advisory, cve FROM advisory_cves WHERE advisory IN ({','.join('?' * len(part))})",
                              part):
            out[int(r[0])].append(r[1])
    return out


def advisories_for_cves(conn: sqlite3.Connection, cves: Iterable[str]) -> dict[str, list[int]]:
    wanted = sorted({str(c).upper() for c in cves})
    out: dict[str, list[int]] = {}
    for chunk in range(0, len(wanted), 500):
        part = wanted[chunk:chunk + 500]
        for r in conn.execute(f"SELECT cve, advisory FROM advisory_cves WHERE cve IN ({','.join('?' * len(part))})",
                              part):
            out.setdefault(r[0], []).append(int(r[1]))
    return out


def enrichment(conn: sqlite3.Connection, cves: Iterable[str]) -> dict[str, dict[str, Any]]:
    """KEV / EPSS / CVSS for each CVE that has any."""
    wanted = sorted({str(c).upper() for c in cves})
    out: dict[str, dict[str, Any]] = {}
    for chunk in range(0, len(wanted), 500):
        part = wanted[chunk:chunk + 500]
        q = ",".join("?" * len(part))
        for r in conn.execute(f"SELECT cve, date_added, due_date, known_ransomware FROM kev WHERE cve IN ({q})", part):
            out.setdefault(r[0], {})["kev"] = {"date_added": r[1], "due_date": r[2], "known_ransomware": r[3]}
        for r in conn.execute(f"SELECT cve, score, percentile, date FROM epss WHERE cve IN ({q})", part):
            out.setdefault(r[0], {})["epss"] = {"score": r[1], "percentile": r[2], "date": r[3]}
        for r in conn.execute(f"SELECT cve, score, vector, version, severity FROM cvss WHERE cve IN ({q})", part):
            out.setdefault(r[0], {})["cvss"] = {"score": r[1], "vector": r[2], "version": r[3], "severity": r[4]}
    return out


def packages_for_advisories(conn: sqlite3.Connection, eco_ids: Iterable[int], advisory_ids: Iterable[int]) -> set[str]:
    """The package names these advisories list in these releases."""
    ecos = list(eco_ids)
    advs = sorted(set(advisory_ids))
    out: set[str] = set()
    if not ecos or not advs:
        return out
    em = ",".join("?" * len(ecos))
    for chunk in range(0, len(advs), 500):
        part = advs[chunk:chunk + 500]
        am = ",".join("?" * len(part))
        for table in ("ranges", "versions"):
            out.update(r[0] for r in conn.execute(
                f"SELECT DISTINCT package FROM {table} WHERE ecosystem IN ({em}) AND advisory IN ({am})", (*ecos, *part)))
    return out


def precise_coverage(conn: sqlite3.Connection, selector_key: str) -> int:
    """How many per-CVE records name this release (computed when the index was built)."""
    try:
        return int(get_info(conn, f"precise_count:{selector_key}", 0) or 0)
    except (TypeError, ValueError):
        return 0


def cves_with_precise_record(conn: sqlite3.Connection, top: str, cves: Iterable[str]) -> set[str]:
    wanted = sorted({str(c).upper() for c in cves})
    out: set[str] = set()
    for chunk in range(0, len(wanted), 500):
        part = wanted[chunk:chunk + 500]
        out.update(r[0] for r in conn.execute(
            f"SELECT DISTINCT cve FROM precise_cves WHERE top = ? AND cve IN ({','.join('?' * len(part))})", (top, *part)))
    return out
