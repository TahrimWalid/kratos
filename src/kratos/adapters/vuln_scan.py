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

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[3]

# ---------------------------------------------------------------------------
# vulscan layout -- see vulscan/README.md for why this exact nested
# scripts/vulscan/ structure is required. A flat directory lets nmap load
# the SCRIPT fine but silently fail to find the DATABASE, since vulscan.nse
# resolves it via nmap.fetchfile("scripts/vulscan/" .. db), a path relative
# to an nmap data-directory root, not to --script.
# ---------------------------------------------------------------------------
VULSCAN_DIR = _REPO_ROOT / "vulscan"
VULSCAN_NSE_PATH = VULSCAN_DIR / "scripts" / "vulscan" / "vulscan.nse"
VULSCAN_DB_PATH = VULSCAN_DIR / "scripts" / "vulscan" / "cve.csv"
VULSCAN_DB_FILENAME = "cve.csv"
VULSCAN_UPDATE_URL = "https://www.computec.ch/projekte/vulscan/download/cve.csv"

# 30 days: vulscan's own upstream mirror isn't a real-time feed either (its
# own update.sh just re-downloads a periodically-refreshed CSV snapshot), so
# "perfectly fresh" isn't achievable regardless of how often Kratos checks.
# 30 days balances "know about anything from the last month" against not
# nagging the operator on every single investigation -- a round, operationally
# reasonable number, not a precisely-derived one, and stated as such rather
# than dressed up as more rigorous than it is.
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


def check_vulscan_db_staleness(db_path: Path = VULSCAN_DB_PATH) -> dict[str, Any]:
    """
    Returns {"exists", "last_updated", "age_days", "stale"}. mtime-based,
    since cve.csv carries no embedded freshness field of its own -- the
    file's mtime is the only signal available, which matches how vulscan's
    own update.sh works (it just overwrites the file, no versioning).
    """
    if not db_path.exists():
        return {"exists": False, "last_updated": None, "age_days": None, "stale": True}
    mtime = datetime.fromtimestamp(db_path.stat().st_mtime)
    age_days = (datetime.now() - mtime).days
    return {
        "exists": True,
        "last_updated": mtime.isoformat(timespec="seconds"),
        "age_days": age_days,
        "stale": age_days > STALENESS_THRESHOLD_DAYS,
    }


def update_vulscan_db(db_path: Path = VULSCAN_DB_PATH) -> tuple[bool, str]:
    """Re-downloads cve.csv from the same upstream mirror vulscan's own
    update.sh uses. Downloads to a temp path first, only replacing the real
    file on a verified-nonempty success -- a failed/partial download must
    never silently truncate or corrupt the existing database.

    A "successful" (HTTP 200, nonzero-byte) download from computec.ch can
    still be a Cloudflare bot-challenge HTML page rather than the real CSV
    -- curl's exit code and a nonzero byte count both look like success
    while the content is garbage. A byte-count-only check would silently
    replace a working 16MB database with a 5KB challenge page, so
    _looks_like_valid_cve_csv below rejects anything that doesn't look
    like actual CVE CSV content before it ever replaces the live file,
    regardless of what curl's exit code claimed.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = db_path.with_suffix(".csv.new")
    try:
        result = subprocess.run(
            ["curl", "-sS", "-m", "60", "-o", str(tmp_path), VULSCAN_UPDATE_URL],
            capture_output=True, text=True, timeout=70,
        )
        if result.returncode != 0 or not tmp_path.exists() or tmp_path.stat().st_size == 0:
            return False, f"Download failed: {result.stderr.strip() or 'empty/missing response'}"
        valid, reason = _looks_like_valid_cve_csv(tmp_path)
        if not valid:
            if _looks_like_cloudflare_challenge(tmp_path):
                return False, (
                    "Update failed: the upstream vulscan mirror (computec.ch) returned a "
                    "Cloudflare bot-challenge page instead of the real database. This is a "
                    "known limitation of the upstream mirror, not a bug in Kratos's update logic "
                    "-- automated curl-based updates will likely keep failing here. The existing "
                    f"database ({db_path.stat().st_size} bytes) was left untouched, exactly as "
                    "intended. If a fresh database is genuinely needed, download cve.csv manually "
                    "(e.g. via a browser session that can pass the challenge) and place it at "
                    f"{db_path}. Working around the bot challenge is out of scope for this tool."
                )
            return False, (
                f"Download completed but content failed validation ({reason}) -- existing "
                f"database left untouched. Downloaded {tmp_path.stat().st_size} bytes."
            )
        tmp_path.replace(db_path)
        return True, f"Updated {db_path} ({db_path.stat().st_size} bytes)"
    except subprocess.TimeoutExpired:
        return False, "Download timed out"
    except FileNotFoundError:
        return False, "curl not found"
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


# The real cve.csv is ~16MB; a bot-challenge/error page is typically a few
# KB. 1MB is a conservative, deliberately generous floor -- real content
# should clear it by more than an order of magnitude, so this only catches
# genuinely wrong content, not normal size variation between snapshots.
_MIN_VALID_CVE_CSV_BYTES = 1_000_000
_CVE_CSV_LINE_RE = re.compile(r"^CVE-\d{4}-\d+;")


def _looks_like_valid_cve_csv(path: Path) -> tuple[bool, str]:
    size = path.stat().st_size
    if size < _MIN_VALID_CVE_CSV_BYTES:
        return False, f"only {size} bytes, expected several MB"
    with path.open("r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
    if "<html" in first_line.lower() or "<!doctype" in first_line.lower():
        return False, "content looks like an HTML page, not CSV"
    if not _CVE_CSV_LINE_RE.match(first_line):
        return False, f"first line doesn't match the expected 'CVE-YYYY-NNNN;...' format: {first_line[:80]!r}"
    return True, "ok"


# The challenge page's <title> is literally "Just a moment...". Kept
# narrow/specific deliberately -- this exists to give a precise, actionable
# message for the one known cause, not to generically guess at every
# possible reason content might fail validation (see the fallback message
# in update_vulscan_db for anything that doesn't match this).
_CLOUDFLARE_CHALLENGE_MARKERS = ("just a moment", "cf-chl", "cloudflare")


def _looks_like_cloudflare_challenge(path: Path) -> bool:
    head = path.read_text(encoding="utf-8", errors="replace")[:4096].lower()
    return any(marker in head for marker in _CLOUDFLARE_CHALLENGE_MARKERS)


def run_nmap_vulscan(target: str, data_dir: Path) -> Path:
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
    all; see vulscan/README.md.
    """
    scans_dir = data_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    out_xml = scans_dir / f"vulscan_{safe_target}_{ts}.xml"

    if not VULSCAN_NSE_PATH.exists():
        raise RuntimeError(
            f"vulscan.nse not found at {VULSCAN_NSE_PATH} -- see vulscan/README.md for the "
            "install step (not bundled in the repo; a periodically-updated local database)."
        )

    env = {**os.environ, "NMAPDIR": str(VULSCAN_DIR)}
    cmd = [
        "nmap", "-sV", "-Pn",
        "--script", str(VULSCAN_NSE_PATH),
        "--script-args", f"vulscandb={VULSCAN_DB_FILENAME}",
        "-oX", str(out_xml),
        target,
    ]
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
        raise RuntimeError("nuclei not found. See README.md Requirements for the install step.") from e
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
