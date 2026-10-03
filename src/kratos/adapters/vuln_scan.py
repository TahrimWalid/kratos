"""
Vulnerability-signal adapters: Nuclei (active, template-driven, multi-protocol
checks) + nmap's vulscan NSE script (passive, offline CVE correlation against
nmap's own -sV version-detection output). Both are network scanners invoked
FROM the Kratos host, targeting the monitored system over the network --
same execution model as adapters/nmap_scan.py, NOT SSH-remote-execution like
adapters/ssh_remote.py's fetchers. See agent/tools.py::tool_run_vuln_scan's
docstring for the full target-vs-host reasoning.

vulners.nse (nmap's OTHER built-in CVE-correlation script) is deliberately
NOT used here -- it queries a live external API per scan, reopening the
same cloud-dependency tension already resolved for threat-intel (see
docs/DESIGN.md's "Threat-intel enrichment" section). vulscan's cve.csv
is a locally-cached, offline database instead -- see check_vulscan_db_staleness
below for why that tradeoff needs its own visibility mechanism.

Known limitation: neither tool meaningfully covers OT/ICS protocols
(Modbus, DNP3, etc.) -- Nuclei's template set is overwhelmingly HTTP/web-
focused, and vulscan only correlates whatever product/version nmap's own
-sV probes can fingerprint (nmap's OT/ICS probe coverage is itself
limited). See docs/DESIGN.md's "Known limitations" section.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from kratos import paths as _paths

# ---------------------------------------------------------------------------
# vulscan layout -- the exact nested scripts/vulscan/ structure is required.
# A flat directory lets nmap load the SCRIPT fine but silently fail to find
# the DATABASE, since vulscan.nse resolves it via
# nmap.fetchfile("scripts/vulscan/" .. db), a path relative to an nmap
# data-directory root (NMAPDIR below), not to --script. Where the folder
# lives (a checkout's root or the per-user data home) is kratos/paths.py's
# call; `kratos vulscan-install` fills it.
# ---------------------------------------------------------------------------
VULSCAN_DIR = _paths.vulscan_dir()
VULSCAN_NSE_PATH = VULSCAN_DIR / "scripts" / "vulscan" / "vulscan.nse"
VULSCAN_DB_PATH = VULSCAN_DIR / "scripts" / "vulscan" / "cve.csv"
VULSCAN_DB_FILENAME = "cve.csv"
VULSCAN_SOURCE_FILENAME = "SOURCE.txt"

# The script and its licence come from the vulscan repository. Its CVE list does
# NOT: the copy there is a 2017 snapshot whose newest CVE is from 2013, and the
# maintained one (computec.ch) sits behind a bot challenge that rejects any
# scripted download. Kratos builds cve.csv itself from NVD's public yearly
# feeds instead (see build_cve_csv_from_nvd), in the same `ID;description`
# shape vulscan.nse reads.
VULSCAN_REPO_RAW = "https://raw.githubusercontent.com/scipag/vulscan/master"
VULSCAN_SCRIPT_FILES = ("vulscan.nse", "COPYING.TXT")
VULSCAN_SCRIPT_MAX_BYTES = 5 * 1024 * 1024
VULSCAN_INSTALL_HINT = "run `kratos vulscan-install` on the Kratos machine"

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_FIRST_FEED_YEAR = 2002          # the 2002 feed also holds CVE-1999..2001
NVD_FEED_MAX_BYTES = 200 * 1024 * 1024   # compressed; the largest year is ~35 MB today
NVD_NOTICE = ("This product uses data from the NVD API but is not endorsed or certified by the NVD. "
              "CVE descriptions: National Vulnerability Database (https://nvd.nist.gov), public domain.")
# A built list smaller than this, or one without CVEs from last year, means a
# feed was cut short or changed shape: refuse it rather than replace a good list.
MIN_BUILT_CVE_ENTRIES = 100_000

# A CVE list whose newest entry is older than this many years misses most of
# what a scan should find, however recently the file itself was copied.
STALE_CVE_YEARS = 1

# 30 days: a rebuild from NVD takes a couple of minutes, so it isn't done per
# scan. 30 days balances "know about anything from the last month" against not
# nagging the operator on every single investigation -- a round, operationally
# reasonable number, not a precisely-derived one.
STALENESS_THRESHOLD_DAYS = 30

# The actual tag names nuclei-templates metadata uses, not the plural/
# guessed forms ("cves"/"exposures"/"misconfiguration") that match almost
# no templates. ~6000 templates combined as of nuclei-templates v10.4.5 --
# a deliberate default subset, not the full 13,000+ template set, given
# the project's modest-hardware target; override via the tags parameter
# for a broader or narrower scan.
DEFAULT_NUCLEI_TAGS = "cve,exposure,misconfig"

# ~6000 templates (clustered) against a single-port host runs in the low
# tens of seconds; this leaves generous headroom for a target with more
# open ports/protocols, which multiplies actual requests after clustering.
# Deliberately erring toward "let it finish" over "cut it off early" on
# modest hardware.
NUCLEI_TIMEOUT_SECONDS = 600
NMAP_VULSCAN_TIMEOUT_SECONDS = 120


_CVE_YEAR_RE = re.compile(rb"^CVE-(\d{4})-", re.MULTILINE)
_newest_year_cache: dict[tuple[str, int, int], int | None] = {}


def newest_cve_year(db_path: Path = VULSCAN_DB_PATH) -> int | None:
    """The year of the newest CVE id in cve.csv (None if unreadable/empty).

    The file's mtime only says when it was copied: a database fetched today can
    still stop at CVEs from a decade ago, and the copy on the project's GitHub
    does. Cached per (path, mtime, size) -- reading ~16 MB takes a fraction of a
    second, but there is no reason to do it every scan."""
    try:
        st = db_path.stat()
    except OSError:
        return None
    key = (str(db_path), st.st_mtime_ns, st.st_size)
    if key not in _newest_year_cache:
        try:
            years = [int(y) for y in _CVE_YEAR_RE.findall(db_path.read_bytes())]
        except OSError:
            years = []
        _newest_year_cache.clear()
        _newest_year_cache[key] = max(years) if years else None
    return _newest_year_cache[key]


def check_vulscan_db_staleness(db_path: Path = VULSCAN_DB_PATH) -> dict[str, Any]:
    """
    Returns {"exists", "last_updated", "age_days", "newest_cve_year", "stale", "note"}.

    Two signals: the file's mtime (when it was last refreshed -- cve.csv has no
    embedded freshness field, and vulscan's own update.sh just overwrites it)
    and the newest CVE id it actually contains. Either one being old makes it
    stale; `note` says in plain words what that means for a scan.
    """
    if not db_path.exists():
        return {"exists": False, "last_updated": None, "age_days": None, "newest_cve_year": None,
                "stale": True,
                "note": f"The CVE database is not installed, so no CVE matching was done -- {VULSCAN_INSTALL_HINT}."}
    mtime = datetime.fromtimestamp(db_path.stat().st_mtime)
    age_days = (datetime.now() - mtime).days
    newest = newest_cve_year(db_path)
    old_content = newest is None or newest < datetime.now().year - STALE_CVE_YEARS
    note = None
    if old_content:
        note = (f"The local CVE list only goes up to {newest}: vulnerabilities published after that are "
                "not matched, so a clean CVE result is not evidence the services are up to date "
                f"({VULSCAN_INSTALL_HINT} to rebuild it from NVD)."
                if newest else f"The local CVE list contains no recognisable CVE ids ({VULSCAN_INSTALL_HINT}).")
    elif age_days > STALENESS_THRESHOLD_DAYS:
        note = f"The local CVE list was last rebuilt {age_days} days ago ({VULSCAN_INSTALL_HINT} to refresh it)."
    return {
        "exists": True,
        "last_updated": mtime.isoformat(timespec="seconds"),
        "age_days": age_days,
        "newest_cve_year": newest,
        "stale": old_content or age_days > STALENESS_THRESHOLD_DAYS,
        "note": note,
    }


def vulscan_installed(vulscan_dir: Path = VULSCAN_DIR) -> bool:
    base = vulscan_dir / "scripts" / "vulscan"
    return (base / "vulscan.nse").is_file() and (base / VULSCAN_DB_FILENAME).is_file()


def install_vulscan(vulscan_dir: Path = VULSCAN_DIR, *, force: bool = False, session: Any = None,
                    progress: Callable[[str], None] | None = None) -> tuple[bool, str]:
    """Install vulscan in the nested layout nmap needs: the script and its licence
    from the vulscan repository, and a CVE list built from NVD's feeds.

    Each part is (re)done only when needed -- the script when it's missing, the
    CVE list when it's missing or stale -- or always with `force`. Nothing in
    place is replaced unless its new version downloaded and validated."""
    dest = vulscan_dir / "scripts" / "vulscan"
    dest.mkdir(parents=True, exist_ok=True)
    done: list[str] = []
    script_missing = not all((dest / name).is_file() for name in VULSCAN_SCRIPT_FILES)
    if force or script_missing:
        ok, message = _install_script_files(dest, session=session)
        if not ok:
            return False, message
        done.append("the vulscan script")
    db = dest / VULSCAN_DB_FILENAME
    if force or check_vulscan_db_staleness(db)["stale"]:
        ok, message = build_cve_csv_from_nvd(db, session=session, progress=progress)
        if not ok:
            return False, message if not done else f"Installed {done[0]}, but: {message}"
        done.append(message)
    if not done:
        newest = newest_cve_year(db)
        return True, f"Already installed and current in {dest} (CVEs up to {newest}); --force rebuilds it."
    return True, f"Installed into {dest}: " + "; ".join(done) + "."


def update_vulscan_db(db_path: Path = VULSCAN_DB_PATH) -> tuple[bool, str]:
    """Rebuild cve.csv from NVD (the "refresh the stale database" path).
    A failed or partial rebuild leaves the existing database untouched."""
    return build_cve_csv_from_nvd(db_path)


def _install_script_files(dest: Path, *, session: Any = None) -> tuple[bool, str]:
    staged: list[tuple[Path, Path]] = []
    try:
        for name in VULSCAN_SCRIPT_FILES:
            tmp = dest / f".{name}.download"
            staged.append((tmp, dest / name))
            ok, message = _download(f"{VULSCAN_REPO_RAW}/{name}", tmp, VULSCAN_SCRIPT_MAX_BYTES, session)
            if not ok:
                return False, f"Download of {name} failed: {message}. Nothing was changed."
        nse = staged[0][0].read_bytes()
        if b"vulscan" not in nse[:4096] or len(nse) < 1024:
            return False, "The downloaded vulscan.nse doesn't look like the vulscan script. Nothing was changed."
        for tmp, final in staged:
            tmp.replace(final)
        staged = []
        return True, "ok"
    finally:
        for tmp, _final in staged:
            tmp.unlink(missing_ok=True)


def _http(session: Any):
    if session is not None:
        return session
    import requests

    return requests


def _download(url: str, out: Path, max_bytes: int, session: Any = None) -> tuple[bool, str]:
    import requests

    try:
        with _http(session).get(url, stream=True, timeout=60) as resp:
            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}"
            size = 0
            with out.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    size += len(chunk)
                    if size > max_bytes:
                        return False, "larger than expected, download stopped"
                    fh.write(chunk)
        return True, "ok"
    except requests.RequestException as e:
        return False, e.__class__.__name__


def iter_nvd_feed(text: Any, chunk_size: int = 1 << 20) -> Iterator[dict[str, Any]]:
    """Yield the items of an NVD 2.0 feed's "vulnerabilities" array one at a time
    from a text stream, so a 300 MB year never sits in memory as one document.
    Raises ValueError on a feed that isn't shaped like one or ends early."""
    decoder = json.JSONDecoder()
    buf = ""
    while True:
        at = buf.find('"vulnerabilities"')
        bracket = buf.find("[", at) if at != -1 else -1
        if bracket != -1:
            pos = bracket + 1
            break
        data = text.read(chunk_size)
        if not data or len(buf) > 1 << 20:
            raise ValueError("not an NVD feed (no vulnerabilities array)")
        buf += data
    eof = False
    skip = re.compile(r"[\s,]*")
    while True:
        pos = skip.match(buf, pos).end()
        if pos < len(buf) and buf[pos] == "]":
            return
        if pos < len(buf):
            try:
                item, pos = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                item = None
            if item is not None:
                yield item
                continue
        if eof:
            raise ValueError("feed ended in the middle of the vulnerabilities array")
        buf = buf[pos:]
        pos = 0
        if len(buf) > 64 << 20:
            raise ValueError("feed item larger than 64 MB")
        data = text.read(chunk_size)
        eof = not data
        buf += data


def nvd_item_to_line(item: dict[str, Any]) -> str | None:
    """One cve.csv line (`CVE-ID;description`) from an NVD feed item, or None for a
    rejected or description-less entry. vulscan splits on ';' and reads line by
    line, so both are removed from the description."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id") or ""
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id) or cve.get("vulnStatus") == "Rejected":
        return None
    descriptions = cve.get("descriptions") or []
    text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    if not text and descriptions:
        text = descriptions[0].get("value")
    if not text or text.startswith("** REJECT"):
        return None
    text = " ".join(text.replace(";", ",").split())
    return f"{cve_id};{text}"


def build_cve_csv_from_nvd(db_path: Path = VULSCAN_DB_PATH, *, session: Any = None,
                           years: Iterable[int] | None = None,
                           progress: Callable[[str], None] | None = None) -> tuple[bool, str]:
    """Build vulscan's cve.csv from NVD's yearly JSON feeds (public data, current
    to the day). Each yearly feed (~2-35 MB compressed) is downloaded to a temp
    file and decompressed and parsed as a stream; the list is written to a temp file and only replaces `db_path` once it has every year
    and passes validation, so an interrupted or failed build changes nothing."""
    years = list(years) if years is not None else list(range(NVD_FIRST_FEED_YEAR, datetime.now().year + 1))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_name(f".{db_path.name}.building")
    total = 0
    try:
        with tmp.open("w", encoding="utf-8") as out:
            for year in years:
                url = NVD_FEED_URL.format(year=year)
                gz_tmp = db_path.with_name(f".nvd-{year}.json.gz")
                try:
                    ok, message = _download(url, gz_tmp, NVD_FEED_MAX_BYTES, session)
                    if not ok:
                        return False, f"Couldn't download the NVD {year} feed ({message}). Nothing was changed."
                    count = 0
                    with gzip.open(gz_tmp, "rt", encoding="utf-8") as feed:
                        for item in iter_nvd_feed(feed):
                            line = nvd_item_to_line(item)
                            if line:
                                out.write(line + "\n")
                                count += 1
                except (OSError, EOFError, ValueError) as e:
                    return False, f"The NVD {year} feed couldn't be read ({e}). Nothing was changed."
                finally:
                    gz_tmp.unlink(missing_ok=True)
                total += count
                if progress:
                    progress(f"{year}: {count:,} CVEs")
        newest = newest_cve_year(tmp)
        if total < MIN_BUILT_CVE_ENTRIES:
            return False, f"Only {total:,} CVEs came back from NVD, fewer than expected. Nothing was changed."
        if newest is None or newest < datetime.now().year - STALE_CVE_YEARS:
            return False, f"The NVD feeds stop at {newest}, which looks incomplete. Nothing was changed."
        tmp.replace(db_path)
        db_path.with_name(VULSCAN_SOURCE_FILENAME).write_text(
            f"cve.csv built by Kratos from NVD's yearly feeds on {datetime.now():%Y-%m-%d}.\n{NVD_NOTICE}\n",
            encoding="utf-8")
        return True, f"CVE list rebuilt from NVD: {total:,} CVEs, up to {newest}"
    finally:
        tmp.unlink(missing_ok=True)


def run_nmap_vulscan(target: str, data_dir: Path, *, use_vulscan: bool = True) -> Path:
    """
    Runs nmap -sV against target with vulscan's CVE-correlation NSE script
    attached -- the SAME -sV version-detection probe run_nmap_scan performs
    (reusing that data shape, not re-inventing a separate detection pass),
    with vulscan layered on top in one nmap invocation rather than a bare
    scan followed by a separate vulscan-only pass. A genuinely single
    shared XML output with run_nmap_scan's own file would need changing
    that function's signature -- out of scope here; this still avoids a
    SECOND, fully independent network scan of the target.

    NMAPDIR is set so vulscan.nse's own nmap.fetchfile("scripts/vulscan/"
    .. db) call can find cve.csv -- required for the lookup to work at
    all.

    use_vulscan=False runs the same -sV probe without the script: used when the
    CVE data isn't installed, so the scan still learns which ports to point
    Nuclei at instead of guessing.
    """
    scans_dir = data_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    out_xml = scans_dir / f"vulscan_{safe_target}_{ts}.xml"

    if use_vulscan and not VULSCAN_NSE_PATH.exists():
        raise RuntimeError(f"vulscan isn't installed ({VULSCAN_NSE_PATH} is missing) -- {VULSCAN_INSTALL_HINT}.")

    env = {**os.environ, "NMAPDIR": str(VULSCAN_DIR)} if use_vulscan else dict(os.environ)
    script = (["--script", str(VULSCAN_NSE_PATH), "--script-args", f"vulscandb={VULSCAN_DB_FILENAME}"]
              if use_vulscan else [])
    cmd = ["nmap", "-sV", "-Pn", *script, "-oX", str(out_xml), target]
    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, text=True, timeout=NMAP_VULSCAN_TIMEOUT_SECONDS)
    except FileNotFoundError as e:
        raise RuntimeError("nmap not found. Install with: sudo apt install nmap") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"nmap+vulscan failed with exit code {e.returncode}: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"nmap+vulscan timed out after {NMAP_VULSCAN_TIMEOUT_SECONDS}s") from e
    return out_xml


_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+")


def parse_vulscan_xml(xml_path: Path) -> list[dict[str, Any]]:
    """
    Extracts vulscan's own script output per open port. A port can carry
    multiple <script> elements (e.g. http-server-header alongside vulscan),
    so this filters by id=="vulscan" specifically rather than taking the
    first <script> child, which would silently pick up the wrong script's
    output. An empty/missing output attribute means vulscan found nothing
    for that port -- nmap's own generic "Bug in vulscan: no string output"
    stderr message is what an empty script-output string looks like at
    that layer; benign, not an error, and not surfaced as one here.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise RuntimeError(f"Failed to parse vulscan XML: {xml_path}") from e

    findings: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            portid = port.get("portid")
            service = port.find("service")
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            for script in port.findall("script"):
                if script.get("id") != "vulscan":
                    continue
                output = (script.get("output") or "").strip()
                if not output:
                    continue
                cve_ids = sorted(set(_CVE_ID_RE.findall(output)))
                findings.append({
                    "source": "vulscan",
                    "host": ip,
                    "port": portid,
                    "product": product,
                    "version": version,
                    "cve_ids": cve_ids,
                    "detail": output,
                })
    return findings


def run_nuclei_scan(target: str, data_dir: Path, tags: str = DEFAULT_NUCLEI_TAGS) -> Path:
    """
    Runs nuclei against target (a bare host/IP, matching run_nmap_scan's own
    target convention, UNLESS it already contains "://" -- pass an explicit
    "https://<host>" target string if the service is known/suspected to be
    TLS-only) with the given tag filter, writing line-delimited JSON (one
    finding per line, nuclei's own -jsonl format).

    Defaults to http:// only, not both schemes, for two reasons: (1) a bare
    "host:port" (no scheme at all) makes nuclei probe HTTPS first and
    silently skip the target entirely as "unresponsive" if only plain HTTP
    is listening, so a bare target is never used here. (2) Explicitly
    probing both http:// and https:// against a target that only speaks
    plain HTTP doesn't fail fast either: the TCP connection to the open
    port succeeds, but the TLS handshake against a non-TLS listener stalls
    rather than failing quickly the way a closed port would -- measured at
    a 2+ minute stall against ~6000 templates on modest hardware. Given the
    project's modest-hardware target, a single verified-fast scheme beats
    defaulting to thoroughness that carries this large a hidden cost.
    """
    scans_dir = data_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    out_jsonl = scans_dir / f"nuclei_{safe_target}_{ts}.jsonl"

    target_url = target if "://" in target else f"http://{target}"
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl", "-o", str(out_jsonl),
        "-tags", tags, "-silent",
    ]
    try:
        # check=False deliberately: nuclei's exit code is not treated as the
        # success/fail signal here -- whether the output file exists (checked
        # by the caller) is more robust than trusting a scanner's own exit
        # code convention, which can vary run to run for reasons unrelated to
        # whether real findings were produced.
        subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT_SECONDS)
    except FileNotFoundError as e:
        raise RuntimeError(
            "nuclei not found (optional: it adds the active web checks). "
            "Install guide: https://github.com/projectdiscovery/nuclei#install-nuclei"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"nuclei scan timed out after {NUCLEI_TIMEOUT_SECONDS}s") from e
    return out_jsonl


def parse_nuclei_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
    """Parses nuclei's -jsonl output (one JSON object per finding: template-id,
    info.name/severity/classification.cve-id, host, matched-at)."""
    import json

    if not jsonl_path.exists():
        return []

    findings: list[dict[str, Any]] = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        classification = info.get("classification") or {}
        cve_id = classification.get("cve-id")
        cve_ids = [cve_id] if isinstance(cve_id, str) else (cve_id if isinstance(cve_id, list) else [])
        findings.append({
            "source": "nuclei",
            "template_id": obj.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "cve_ids": cve_ids,
            "host": obj.get("host"),
            "matched_at": obj.get("matched-at"),
        })
    return findings
