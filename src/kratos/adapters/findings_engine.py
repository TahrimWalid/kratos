"""The rule engine behind `correlate_findings` — no LLM anywhere in it.

This is where raw observations become findings. `find_latest_inputs()`
auto-discovers the newest file in each category under `data_dir` (scans, logs,
context, reports, baseline), and a set of deterministic rules turns them into
findings with stable IDs by area: `NET-*` (network/ports), `AUTH-*` (auth-log
patterns), `CORR-*` (cross-source correlations like an SSH brute-force burst),
`INTEG-*` (file-integrity drift). Each finding carries a severity and its
evidence.

Two things are deliberate and worth knowing:

- **Findings are rule-derived, not model-derived.** The same inputs always
  produce the same findings; there's no prompt in the loop. That's what makes a
  finding something you can trust and reproduce.
- **Offline threat-intel enrichment runs here, unconditionally.** Rather than
  hoping the agent chooses to look up a suspicious IP (LLM tool selection isn't
  reliable enough to gate a real corroboration signal on), the engine checks the
  source IPs behind suspicious findings against the local OTX cache itself — a
  file read, no network, no approval — and raises severity on a known-malicious
  hit. The live/opt-in tier is elsewhere; this is the always-on offline one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from kratos import __version__ as KRATOS_VERSION
from kratos.utils.latest_file import latest_file
from kratos.utils.timeutil import epoch_to_utc_iso, utc_now_iso
from kratos.target_key import target_key



# ---------------------------
# Helpers: find latest files
# ---------------------------
# Kept under its old name: logs_trends and older code import it from here.
_host_key = target_key


_ACTIVE = object()  # find_latest_inputs' default: the active target
_INPUT_FILES_CONSIDERED = 100


def input_hosts(category: str, data: Any) -> set[str] | None:
    """The machine(s) a saved correlation input describes, as comparable host keys
    (see _host_key), or None when the file doesn't say.

    Several machines share one data folder (the configured target, /investigate-host
    on Kratos's own machine, earlier targets), so "the newest file of each kind"
    can describe a different machine than the one being reported on."""
    if not isinstance(data, dict):
        return None
    if data.get("target"):
        return {_host_key(data["target"])}
    if category == "auth_stats":
        source = str(data.get("source") or "")
        if source.startswith("ssh_target_"):
            return {_host_key(source.partition(":")[2])}
        return {"loopback"} if source else None  # parse_auth_log: Kratos's own logs
    if category == "nmap_parsed":
        ips = {_host_key(h.get("ip")) for h in data.get("hosts") or [] if isinstance(h, dict) and h.get("ip")}
        return ips or None
    if category == "system_context":
        return {"loopback"}  # collect_system_context only ever describes Kratos's own host
    return None


def _latest_input_for(dir_path: Path, pattern: str, category: str, active: str) -> Path | None:
    """The newest `pattern` file in `dir_path` describing `active` (a host key);
    with no active target, simply the newest. Files that don't say which machine
    they describe, or can't be read, are skipped while a target is set."""
    try:
        files = sorted(dir_path.glob(pattern), key=lambda f: f.stat().st_mtime, reverse=True)
    except OSError:
        return None
    if not active:
        return files[0] if files else None
    for path in files[:_INPUT_FILES_CONSIDERED]:
        try:
            hosts = input_hosts(category, _read_json(path))
        except (OSError, ValueError):
            continue
        if hosts and active in hosts:
            return path
    return None


def _measured_auth_since(logs_dir: Path, active: str, since_epoch: float) -> tuple[Path, Path | None] | None:
    """The newest EXHAUSTIVE login measurement (measure_auth_activity) for `active`
    saved since `since_epoch`, with its matching patterns file."""
    try:
        files = sorted(logs_dir.glob("auth_stats_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    except OSError:
        return None
    for path in files[:_INPUT_FILES_CONSIDERED]:
        try:
            if path.stat().st_mtime < since_epoch:
                break
            data = _read_json(path)
        except (OSError, ValueError):
            continue
        if not str(data.get("source") or "").startswith("ssh_target_measurement"):
            continue
        hosts = input_hosts("auth_stats", data)
        if active and not (hosts and active in hosts):
            continue
        patterns = path.with_name(path.name.replace("auth_stats_", "auth_patterns_", 1))
        return path, patterns if patterns.exists() else None
    return None


def find_latest_inputs(data_dir: Path, target: Any = _ACTIVE,
                       prefer_measured_since: float | None = None) -> dict[str, Path | None]:
    """The newest input file of each kind describing `target` (default: the active
    target; None: any machine).

    `prefer_measured_since` (an investigation's start time): if login activity was
    MEASURED exhaustively during the investigation, correlate that measurement even
    when a sampled journal read was saved after it. Picking purely by recency let a
    later 500-line sample override the exhaustive count, so one answer said both
    'counted in full' and 'only the newest 500 events analyzed'."""
    scans_dir = data_dir / "scans"
    logs_dir = data_dir / "logs"
    ctx_dir = data_dir / "context"
    reports_dir = data_dir / "reports"
    baseline_dir = data_dir / "baseline"
    if target is _ACTIVE:
        from kratos.kratos_config import get_active_target

        target = get_active_target()
    active = _host_key(target) if target else ""

    def pick(dir_path: Path, pattern: str, category: str) -> Path | None:
        return _latest_input_for(dir_path, pattern, category, active)

    auth_stats = pick(logs_dir, "auth_stats_*.json", "auth_stats")
    auth_patterns = pick(logs_dir, "auth_patterns_*.json", "auth_patterns")
    if prefer_measured_since is not None:
        measured = _measured_auth_since(logs_dir, active, prefer_measured_since)
        if measured is not None:
            auth_stats, auth_patterns = measured[0], measured[1] or auth_patterns
    return {
        "nmap_parsed": pick(scans_dir, "parsed_*.json", "nmap_parsed"),
        "auth_stats": auth_stats,
        "auth_patterns": auth_patterns,
        "system_context": pick(ctx_dir, "system_context_*.json", "system_context"),
        "auth_trends": pick(reports_dir, "auth_trends_*.json", "auth_trends"),
        "file_integrity": pick(baseline_dir, "file_integrity_diff_*.json", "file_integrity"),
        # Filtered by its own loader (_load_recent_privileged_snapshot).
        "privileged_accounts": latest_file(ctx_dir, "privileged_accounts_*.json"),
        # check_log_integrity (0.3): the newest result for this machine; freshness
        # is checked by _load_recent_log_integrity.
        "log_integrity": pick(data_dir / "integrity", "log_integrity_*.json", "log_integrity"),
        # The snapshot checks (persistence, live response, packages, ...): each source's
        # own folder and pattern; its loader checks freshness (SNAPSHOT_SOURCES).
        **{src.category: pick(data_dir / src.folder, src.pattern, src.category) for src in snapshot_sources()},
    }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _extract_sudo_members(sudo_group_line: str | None) -> list[str]:
    # Example: "sudo:x:27:walid000"
    if not sudo_group_line:
        return []
    parts = sudo_group_line.split(":")
    if len(parts) < 4:
        return []
    members = parts[3].strip()
    if not members:
        return []
    return [m.strip() for m in members.split(",") if m.strip()]

def _nmap_has_ssh_exposed(nmap_parsed: dict[str, Any] | None) -> bool:
    if not nmap_parsed or not isinstance(nmap_parsed.get("hosts"), list):
        return False
    for h in nmap_parsed["hosts"]:
        for p in h.get("open_ports", []):
            port = int(p.get("port", 0) or 0)
            svc = (p.get("service") or "").lower()
            if port == 22 or "ssh" in svc:
                return True
    return False

def _context_has_ssh_exposed(system_context: dict[str, Any] | None) -> bool:
    """Check if SSH is running/listening based on system context."""
    if not system_context:
        return False
    ssh_info = system_context.get("ssh", {})
    # SSH is exposed if service is active OR listening on port 22
    if ssh_info.get("service_active"):
        return True
    listening_ports = ssh_info.get("listening_ports", [])
    return 22 in listening_ports or len(listening_ports) > 0

def _bursts_of(auth_patterns: dict[str, Any] | None, event_types: tuple[str, ...]) -> list[dict[str, Any]]:
    if not auth_patterns or not isinstance(auth_patterns.get("bursts"), list):
        return []
    return [b for b in auth_patterns["bursts"] if b.get("event_type") in event_types]


_SCOPE_LABELS = {
    "local_host": "LOCAL KRATOS HOST (not the monitored target)",
}


def _system_context_scope_note(system_context: dict[str, Any] | None) -> str | None:
    """
    One-line evidence tag identifying which host system_context actually
    describes. Older context files (or a manually-constructed dict without a
    'scope' field) have no scope tag -- reported as 'unlabeled/unknown' rather
    than silently assumed to be the target, since collect_system_context has
    only ever inspected Kratos's own local host.
    """
    if not system_context:
        return None
    scope = system_context.get("scope")
    label = _SCOPE_LABELS.get(scope, f"unlabeled/unknown scope ({scope!r})" if scope else "unlabeled/unknown scope")
    return f"system_context scope: {label}"


def _is_service_active(system_context: dict[str, Any] | None, unit_name: str) -> bool:
    if not system_context:
        return False
    services = (system_context.get("services") or {})
    units = services.get("units") or []
    for u in units:
        if not isinstance(u, dict):
            continue
        if u.get("unit") == unit_name and u.get("active") == "active":
            return True
    return False


def _logging_services_assessable(system_context: dict[str, Any] | None) -> bool:
    """Sprint 1 backlog #11: whether we actually have the data to judge logging
    services active/inactive. `_is_service_active` returns False for a missing
    system_context OR a context with no services list — indistinguishable from
    "checked and genuinely off". OBS-001 must fire only when we truly checked,
    so it can't false-positive ("logging appears off") on data we never had
    (e.g. an isolated correlate_findings call with no preceding
    collect_system_context)."""
    if not system_context:
        return False
    services = system_context.get("services") or {}
    return isinstance(services.get("units"), list)


def _auth_failure_count(auth_stats: dict[str, Any] | None) -> int:
    if not auth_stats:
        return 0
    by_type = auth_stats.get("events_by_type") or {}
    return int(by_type.get("sudo_auth_failure", 0)) + int(by_type.get("sudo_pam_auth_failure", 0)) + int(by_type.get("ssh_failed_login", 0))


# ---------------------------
# Findings model
# ---------------------------
@dataclass
class Finding:
    id: str
    title: str
    severity: str          # info | low | medium | high | critical (critical: PKG-* on CISA's exploited list)
    evidence: list[str]
    recommendation: list[str]
    playbooks: list[dict[str, Any]] = field(default_factory=list)
    # Structured attacking source IP(s) behind this finding, most-active first.
    # Populated by _surface_source_ips_in_evidence alongside the human evidence
    # line, so consumers (A2 Piece C output-threading's `top_source_ip` field, an
    # answer that names the attacker) read a real field instead of parsing text.
    source_ips: list[str] = field(default_factory=list)
    # Other rules that matched the SAME evidence and were folded into this finding
    # (see _merge_overlapping). Triggers / pipeline conditions naming one of them
    # still match (finding_ids).
    also_matched: list[str] = field(default_factory=list)
    # When the data this finding was built from was collected (UTC ISO, the newest
    # of its inputs). Lets a view tell "found in this investigation" from "still on
    # record from an earlier check" without guessing.
    collected_at: str | None = None
    # Lifecycle identity (kratos.lifecycle): what one finding of this rule is about
    # on a machine ("" = one finding per rule per machine; a future per-entity rule
    # sets it, e.g. per CVE+package), and the concrete things it names -- source
    # IPs, ports, accounts, paths, CVEs -- sorted and normalised (normalise_entities).
    # A person's decision covers the entities it saw; a new one reopens the finding.
    subject: str = ""
    entities: list[str] = field(default_factory=list)
    # MITRE ATT&CK labels (kratos.attack, the pinned v19 table):
    # [{technique_id, technique, tactic_id, tactic, tactics, version, url}]. Set for
    # every behaviour rule (kratos.attack.mapping); posture rules carry none.
    attack: list[dict[str, Any]] = field(default_factory=list)
    # C.1: the detection rule behind a SIGMA-* finding -- {id, title, author, sigma_id,
    # source_url, license, pack, pack_version}. Every surface shows its author
    # (Detection Rule License 1.1). Empty for Kratos's own rules, and then left out of
    # the finding's dict.
    detection_rule: dict[str, Any] = field(default_factory=dict)


def finding_dict(f: "Finding") -> dict[str, Any]:
    """A finding as a dict (dataclasses.asdict), without an empty detection_rule."""
    d = asdict(f)
    if not d.get("detection_rule"):
        d.pop("detection_rule", None)
    return d


def _normal_ip(value: Any) -> str:
    import ipaddress

    text = str(value).strip()
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text


def normalise_entities(kind: str, values: Any) -> list[str]:
    """Sorted, de-duplicated entities. `kind`: "ip" (compressed form), "cve"
    (upper-case), anything else kept as given (user names and paths are
    case-sensitive on Linux)."""
    out: set[str] = set()
    for v in values or ():
        if v is None or str(v).strip() == "":
            continue
        if kind == "ip":
            out.add(_normal_ip(v))
        elif kind == "cve":
            out.add(str(v).strip().upper())
        else:
            out.add(str(v).strip())
    return sorted(out)


# Which inputs each rule reads (longest prefix wins) -- for collected_at.
_FINDING_INPUTS: dict[str, tuple[str, ...]] = {
    "CORR-SSH-001": ("nmap_parsed", "auth_patterns", "system_context"),
    "CORR-001": ("nmap_parsed", "auth_patterns"),
    "CORR-002": ("auth_patterns", "system_context"),
    "AUTH-TREND-": ("auth_trends",),
    "AUTH-004": ("auth_patterns",),
    "AUTH-": ("auth_stats",),
    "COV-": ("auth_stats",),
    "OBS-": ("auth_stats", "system_context"),
    "NET-": ("nmap_parsed",),
    "CTX-": ("system_context",),
    "ENV-": ("system_context",),
    "INTEG-": ("file_integrity",),
    "PRIV-": ("privileged_accounts",),
    "VULN-": ("vuln_scan",),
    "LOG-": ("log_integrity",),
    "SEAL-": ("log_integrity",),
    # snapshot sources add theirs when they register (register_snapshot_source)
}


def rule_inputs(rule_id: str) -> tuple[str, ...]:
    """The input categories a rule reads (longest matching prefix in _FINDING_INPUTS)."""
    prefix = max((p for p in _FINDING_INPUTS if rule_id.startswith(p)), key=len, default=None)
    return _FINDING_INPUTS[prefix] if prefix else ()


def _stamp_collected_at(findings: list["Finding"], inputs: dict[str, Path | None]) -> None:
    times: dict[str, float] = {}
    for key, path in inputs.items():
        try:
            if path is not None:
                times[key] = Path(path).stat().st_mtime
        except OSError:
            pass
    for f in findings:
        used = [times[k] for k in rule_inputs(f.id) if k in times]
        if used:
            f.collected_at = datetime.fromtimestamp(max(used), timezone.utc).isoformat(timespec="seconds")


def finding_ids(finding: Any) -> set[str]:
    """Every rule id a finding stands for: its own plus any it absorbed. Accepts a
    Finding or its dict form; an old report without also_matched just has its id."""
    get = finding.get if isinstance(finding, dict) else (lambda k, d=None: getattr(finding, k, d))
    ids = {str(get("id") or "")}
    ids.update(str(x) for x in (get("also_matched") or []))
    ids.discard("")
    return ids


_EVENT_WORDS = {
    "ssh_failed_login": "failed SSH logins",
    "sudo_pam_auth_failure": "sudo password failures",
    "sudo_auth_failure": "sudo authentication failures",
}


def _when(value: Any) -> str:
    """An ISO timestamp as '2026-10-04 08:55:24 UTC' (evidence is read by people)."""
    try:
        dt = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return str(value)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _burst_line(b: dict[str, Any]) -> str:
    what = _EVENT_WORDS.get(str(b.get("event_type")), str(b.get("event_type") or "events").replace("_", " "))
    return f"burst of {what}: {b.get('count')} between {_when(b.get('start'))} and {_when(b.get('end'))}"


def _privileged_account_findings(snap: dict[str, Any]) -> list[Finding]:
    """PRIV-001..004 from one list_privileged_accounts snapshot."""
    out: list[Finding] = []
    accounts: dict[str, Any] = snap.get("accounts") or {}
    source = f"From the privileged-accounts check of {snap.get('target', 'the target')} at {_when(snap.get('checked_at', 'unknown'))}"
    gaps = [f"Evidence gap: {g}" for g in (snap.get("evidence_gaps") or [])]

    # PRIV-001: an account that still holds privilege was granted it recently.
    grants: dict[str, list[dict[str, Any]]] = {}
    for g in snap.get("recent_privilege_grants") or []:
        if isinstance(g, dict) and g.get("in_effect") and g.get("user"):
            grants.setdefault(str(g["user"]), []).append(g)
    if grants:
        evidence = [source]
        for user, gs in grants.items():
            for g in gs:
                what = f"added to group '{g['group']}'" if g.get("group") else f"given UID {g.get('uid')}"
                evidence.append(f"{g.get('time')}: '{user}' {what} (logged by {g.get('source')})")
            evidence.append(f"'{user}' currently holds: {', '.join((accounts.get(user) or {}).get('via') or [])}")
        out.append(Finding(
            id="PRIV-001",
            title=f"Recently granted privileged access: {', '.join(sorted(grants))}",
            severity="high",
            evidence=evidence,
            entities=normalise_entities("text", [
                f"{user}:{g['group']}" if g.get("group") else f"{user}:uid{g.get('uid')}"
                for user, gs in grants.items() for g in gs]),
            recommendation=[
                "Confirm with the system's owner that each of these grants was authorized.",
                "If not: remove the access (e.g. `gpasswd -d <user> sudo`), lock the account (`usermod -L <user>`), "
                "and investigate how it was added (who ran the command, from which session).",
                "Review what the account did since the grant (sudo activity, logins).",
            ],
        ))

    # PRIV-002: UID 0 is root; any other UID-0 account is a classic backdoor.
    uid0 = sorted(u for u, a in accounts.items() if isinstance(a, dict) and a.get("uid") == 0 and u != "root")
    if uid0:
        out.append(Finding(
            id="PRIV-002",
            title=f"Non-root account(s) with UID 0: {', '.join(uid0)}",
            severity="high",
            entities=normalise_entities("text", uid0),
            evidence=[source, *[f"'{u}' has UID 0 (full root privileges)" for u in uid0]],
            recommendation=["A second UID-0 account is almost never legitimate -- verify immediately; if "
                            "unauthorized, disable it and investigate how it was created."],
        ))

    # PRIV-003: newly privileged since the last check, with no log event explaining it.
    changed = snap.get("changed_since_last_check") or {}
    unexplained = sorted(u for u in (changed.get("added") or []) if u not in grants and u not in uid0)
    if unexplained:
        out.append(Finding(
            id="PRIV-003",
            title=f"Privileged since the last check: {', '.join(unexplained)}",
            severity="medium",
            entities=normalise_entities("text", unexplained),
            evidence=[source, f"Previous check: {changed.get('previous_snapshot_at')}",
                      *[f"'{u}' now holds: {', '.join((accounts.get(u) or {}).get('via') or [])}" for u in unexplained],
                      *gaps],
            recommendation=["No log entry explains this change -- confirm it was authorized."],
        ))

    # PRIV-004: the inventory itself, so an answer can name who has access.
    if accounts:
        out.append(Finding(
            id="PRIV-004",
            title=f"{len(accounts)} account(s) hold privileged access on the target",
            severity="info",
            entities=normalise_entities("text", [u for u, a in accounts.items() if isinstance(a, dict)]),
            evidence=[source, *[f"{u}: {', '.join(a.get('via') or [])}" for u, a in sorted(accounts.items())
                                if isinstance(a, dict)], *gaps],
            recommendation=["Keep this list minimal; remove access nobody needs."],
        ))
    return out


# ---------------------------
# VULN-*: known vulnerabilities (from a run_vuln_scan snapshot)
# ---------------------------
_VULN_CVES_SHOWN = 8
_VULN_ITEMS_SHOWN = 10
# Nuclei's scale -> this report's (info | low | medium | high).
_NUCLEI_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _cve_sort_key(cve: str) -> tuple[int, int]:
    try:
        _prefix, year, number = cve.split("-", 2)
        return int(year), int(number)
    except ValueError:
        return 0, 0


def _vulnerability_findings(scan: dict[str, Any], package_fixed: dict[str, str] | None = None,
                            package_doubted: dict[str, str] | None = None) -> list[Finding]:
    """VULN-001..003 from one run_vuln_scan snapshot.

    VULN-001 -- vulscan's CVE matches. vulscan matches nmap's product/version
    text against CVE descriptions, so these are leads to verify (distributions
    backport fixes without changing versions), never confirmed vulnerabilities.
    VULN-002 -- Nuclei results, at Nuclei's own severity.
    VULN-003 -- what the scan could NOT check, so a quiet result isn't read as clean.

    `package_fixed` (A.2 cross-check): CVEs the machine's installed packages already
    fix ({cve: explanation}). They stay visible in the evidence, marked as a likely
    wrong network match, and leave the finding's entities -- so a decision is not
    asked about something the distribution already fixed.
    `package_doubted` ({cve: why}): CVEs a package fixes, but the program actually
    listening on the matched port is not from that package -- kept, with the reason.
    """
    package_fixed = package_fixed or {}
    package_doubted = package_doubted or {}
    findings: list[Finding] = []
    target = scan.get("target") or "the target"
    source = f"From the vulnerability scan of {target} at {_when(scan.get('scanned_at')) if scan.get('scanned_at') else 'an unknown time'}"
    items = [x for x in scan.get("findings") or [] if isinstance(x, dict)]

    matches: dict[tuple[str, str], dict[str, Any]] = {}
    for x in items:
        if x.get("source") != "vulscan":
            continue
        cves = [c for c in x.get("cve_ids") or [] if isinstance(c, str) and c.startswith("CVE-")]
        if not cves:
            continue
        key = (str(x.get("host") or target), str(x.get("port") or "?"))
        entry = matches.setdefault(key, {"product": x.get("product"), "version": x.get("version"), "cves": set()})
        entry["cves"].update(cves)
    if matches:
        all_cves = set().union(*(m["cves"] for m in matches.values()))
        evidence = [source,
                    f"{len(matches)} service(s) match {len(all_cves)} known CVE description(s) by product/version"]
        ordered = sorted(matches.items(), key=lambda kv: (kv[0][0], int(kv[0][1]) if kv[0][1].isdigit() else 1 << 20))
        for (host, port), m in ordered[:_VULN_ITEMS_SHOWN]:
            newest = sorted(m["cves"], key=_cve_sort_key, reverse=True)
            name = " ".join(str(v) for v in (m["product"], m["version"]) if v) or "unidentified service"
            more = f" (+{len(newest) - _VULN_CVES_SHOWN} older)" if len(newest) > _VULN_CVES_SHOWN else ""
            evidence.append(f"{host} port {port} {name}: newest matches {', '.join(newest[:_VULN_CVES_SHOWN])}{more}")
        if len(matches) > _VULN_ITEMS_SHOWN:
            evidence.append(f"... and {len(matches) - _VULN_ITEMS_SHOWN} more service(s) (see the scan result)")
        evidence.append("These are text matches, not confirmed vulnerabilities: some will already be fixed in this "
                        "build, and an unlisted CVE can still apply.")
        if scan.get("database_newest_cve_year"):
            evidence.append(f"CVE list used for matching goes up to {scan['database_newest_cve_year']}")
        backported = sorted(c for c in all_cves if c.upper() in package_fixed)
        remaining = sorted(c for c in all_cves if c.upper() not in package_fixed)
        if backported:
            evidence.append(f"{len(backported)} of these CVE(s) are already fixed by the installed packages "
                            "(the distribution's own advisory data, checked on the Kratos machine):")
            evidence += [package_fixed[c.upper()] for c in backported[:_VULN_ITEMS_SHOWN]]
            if len(backported) > _VULN_ITEMS_SHOWN:
                evidence.append(f"... and {len(backported) - _VULN_ITEMS_SHOWN} more already fixed")
        doubted = sorted(c for c in all_cves if c.upper() in package_doubted)
        if doubted:
            evidence.append(f"{len(doubted)} CVE(s) are fixed in an installed package, but that package is not "
                            "what listens on the matched port, so they are kept:")
            evidence += [package_doubted[c.upper()] for c in doubted[:_VULN_ITEMS_SHOWN]]
        findings.append(Finding(
            id="VULN-001",
            title=("Service versions match known CVEs (verify which apply)" if remaining
                   else "Service versions match known CVEs, but the installed packages already fix them"),
            severity="medium" if remaining else "info",
            entities=normalise_entities("cve", remaining),
            evidence=evidence,
            recommendation=[
                "Check each CVE against your distribution's security tracker for the installed package version: "
                "distributions often patch without changing the version number, so many matches may already be fixed.",
                "Apply pending security updates for the matched services; remove or firewall any that don't need "
                "to be reachable.",
            ],
        ))

    active = [x for x in items if x.get("source") == "nuclei"]
    if active:
        def sev(x: dict[str, Any]) -> str:
            return _NUCLEI_SEVERITY.get(str(x.get("severity") or "").lower(), "info")

        active.sort(key=lambda x: _severity_rank(sev(x)), reverse=True)
        worst = sev(active[0])
        real = [x for x in active if sev(x) != "info"]
        evidence = [source, f"{len(active)} result(s) from active checks"
                    + (f", {len(real)} above informational" if real else ", all informational")]
        for x in active[:_VULN_ITEMS_SHOWN]:
            cves = ", ".join(c for c in x.get("cve_ids") or [] if isinstance(c, str))
            evidence.append(f"[{sev(x)}] {x.get('name') or x.get('template_id') or 'unnamed check'}"
                            f" at {x.get('matched_at') or x.get('host') or target}" + (f" ({cves})" if cves else ""))
        if len(active) > _VULN_ITEMS_SHOWN:
            evidence.append(f"... and {len(active) - _VULN_ITEMS_SHOWN} more (see the scan result)")
        findings.append(Finding(
            id="VULN-002",
            title=("Active checks found issues on the target's services" if real
                   else "Active checks reported informational results"),
            severity=worst,
            entities=normalise_entities("text", [x.get("template_id") for x in active]),
            evidence=evidence,
            recommendation=[
                "Confirm each result at the address shown, then fix it as its check describes (update, "
                "reconfigure, or restrict access to the service).",
                "Re-run the vulnerability scan afterwards to confirm the result is gone.",
            ],
        ))

    limits: list[str] = []
    cve_matching = scan.get("cve_matching")
    if cve_matching == "not_installed":
        limits.append("CVE matching was not done: the CVE list isn't installed (`kratos vulscan-install`).")
    elif cve_matching == "failed":
        limits.append("CVE matching was not done: the version scan it relies on failed.")
    elif cve_matching == "done" and scan.get("database_note"):
        limits.append(str(scan["database_note"]))
    active_checks = scan.get("active_checks")
    if active_checks == "not_installed":
        limits.append("Active web checks were skipped: nuclei isn't installed on the Kratos machine.")
    elif active_checks == "failed":
        limits.append("Active web checks failed to run.")
    if cve_matching == "done" and not scan.get("services_checked"):
        limits.append("No open services were detected from the Kratos machine, so there was nothing to match "
                      "(ports may be closed, or filtered between Kratos and the target).")
    if limits:
        found_any = any(f.id in ("VULN-001", "VULN-002") for f in findings)
        findings.append(Finding(
            id="VULN-003",
            title="Vulnerability scan coverage was limited",
            severity="info",
            evidence=[source, *limits,
                      "Issues may exist beyond those listed." if found_any
                      else "A clean vulnerability result here is not evidence the services are up to date."],
            recommendation=["Fix the limits above and re-run the vulnerability scan for full coverage."],
        ))
    return findings


def _severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)


# Plain-language, one-line summary per rule ID, keyed to every id="..."
# literal used by generate_findings() below. Template-based rather than
# LLM-generated -- see docs/DESIGN.md's "Findings and severity" section for
# why. Kept here, next to the rule definitions, so a new id="..." added
# below is a visible, one-line diff away from also getting a template;
# GENERIC_FINDING_SUMMARY is the deliberate fallback for anything missed,
# so a forgotten template is a blander sentence, never a crash or a blank
# summary.
FINDING_SUMMARY_TEMPLATES: dict[str, str] = {
    "NET-001": "No open network ports were found in the latest scan.",
    "NET-002": "Open network ports were found — this is the system's attack surface.",
    "CTX-001": "One or more accounts with admin (sudo) rights were identified.",
    "AUTH-001": "Failed attempts to gain admin (sudo) rights were observed.",
    "AUTH-003": "Admin (sudo) session activity was observed.",
    "OBS-001": "Login failures were seen, but the services that collect logs appear to be off — some activity may be going unrecorded.",
    "AUTH-004": "A burst of login failures was observed in a short window.",
    "CORR-001": "A network-exposed SSH service combined with a burst of failed logins — a pattern consistent with a brute-force attempt.",
    "CORR-002": "A burst of failed admin (sudo) logins concentrated on a single account.",
    "CORR-SSH-001": "SSH is exposed to the network and a burst of failed logins was observed — looks like a brute-force attempt.",
    "AUTH-TREND-001": "Login failures have been trending upward across recent runs.",
    "INTEG-001": "One or more tracked files have changed since the last known-good baseline.",
    "ENV-001": "This looks like a development environment (WSL2), not a production system.",
    "COV-001": "Only part of the requested time window's login activity could be analyzed — the rest is unknown, not clean.",
    "VULN-001": "Some network services' versions match known vulnerabilities (CVEs) — check whether they're patched.",
    "VULN-002": "Active checks found issues on the system's network services.",
    "VULN-003": "The vulnerability check couldn't cover everything — part of it was skipped or limited, so a clean result there isn't proof.",
    "PRIV-001": "An account was recently given admin or root-level access — check that this was intended.",
    "PRIV-002": "An account other than root has user ID 0, which gives it full root powers.",
    "PRIV-003": "An account gained admin or root-level access since Kratos last checked.",
    "PRIV-004": "These accounts can act as root or admin on this machine.",
    "LOG-001": "A log file was cut short, replaced or edited outside normal log rotation — a classic way to hide activity.",
    "LOG-002": "A journal file is missing from the middle of the machine's log history.",
    "LOG-003": "The machine went down without a clean shutdown at least once (crash, power cut or forced restart).",
    "LOG-004": "The login records (wtmp/btmp) look edited: records were zeroed, reordered or removed.",
    "LOG-005": "The audit system (auditd) was stopped, disabled or emptied of its rules.",
    "LOG-006": "The audit system (auditd) is installed on this machine but not running.",
    "SEAL-001": "A sealed journal file failed verification or changed after it was verified — its logs were altered.",
    "SEAL-002": "Journal sealing stopped: newer log files on this machine are no longer sealed.",
    "SEAL-003": "Kratos couldn't verify this machine's sealed journal this time — see why.",
    "PERSIST-001": "Something that can start programs by itself (a scheduled job, a service, a startup file) appeared or changed since Kratos first looked, and no installed package owns it.",
    "PERSIST-002": "A place that starts programs contains a line worth a look — it has the shape attackers use, which normal software sometimes has too.",
    "PERSIST-003": "A program that runs with its owner's powers (setuid/setgid) is installed by no package — a common way to keep root access.",
    "PERSIST-004": "Every program on this machine is made to load an extra library (/etc/ld.so.preload) — how a rootkit hides.",
    "PERSIST-005": "A kernel module that belongs to no installed package is loaded, or the kernel is tainted by one.",
    "PERSIST-006": "An SSH key that can log in is new since Kratos first looked, or has options that make it a quiet way back in.",
    "PERSIST-007": "A file that starts programs no longer matches what its package installed.",
    "PERSIST-008": "A login (PAM) rule points at software no package installed — it can accept a password that was never set.",
    "PERSIST-009": "Part of the persistence check could not be done — those places are unknown, not clean.",
    "LIVE-001": "A running program deleted its own file from disk and is not explained by a package update — a common way malware hides.",
    "LIVE-002": "A process is running from memory or from a just-deleted temporary file, so there is nothing on disk to scan.",
    "LIVE-003": "A process was started with an extra library forced into it (LD_PRELOAD/LD_AUDIT) that no package owns — how a userspace rootkit loads itself.",
    "LIVE-004": "An executable is sitting in a world-writable directory (/tmp, /dev/shm, /var/tmp) — a common place to stage a payload.",
    "LIVE-005": "A network listener is run by a process started from /tmp, from a deleted file, or from a binary no package installed — a likely backdoor.",
    "LIVE-006": "A shell or interpreter was started by a web server or database — the classic web-shell or exploited-service shape.",
    "LIVE-007": "Part of the live-response check could not be done, or a running program needs a restart after an update — context, not a finding of compromise.",
    "PKG-001": "An installed package has known vulnerabilities that an available update fixes.",
    "PKG-002": "Some installed packages have known vulnerabilities their distribution has not released a fix for yet.",
    "PKG-003": "A newer kernel is installed than the one running — the machine needs a reboot for the kernel fixes to apply.",
    "PKG-004": "Part of the package vulnerability check could not be done — those packages are unknown, not safe.",
}

GENERIC_FINDING_SUMMARY = "A security-relevant pattern was detected — see details below."


# ---------------------------
# Core: generate findings
# ---------------------------
# ---------------------------
# Deterministic offline threat-intel corroboration (Option 1, 2026-08-24)
# ---------------------------
# When correlation surfaces a suspicious SOURCE IP (a failed-login / brute-force
# / sudo-failure burst), corroborating that IP against known threat intel must
# NOT depend on the agent LLM remembering to call check_ip_reputation -- that was
# measured unreliable (~25% tool-selection on the eval's A8). The rule engine
# does it itself here, deterministically, using ONLY the OFFLINE local OTX cache
# (a plain file read -- no network call, no approval). The live AbuseIPDB tier is
# untouched and stays approval-gated. Only a real KNOWN-MALICIOUS cache hit
# changes anything (evidence line + severity raised to at least high) -- a miss
# leaves the finding exactly as it was, so there's no "not in cache" noise and no
# risk of a clean lookup reading as reassuring.
_IP_SOURCED_SUSPICIOUS_IDS = {"CORR-SSH-001", "CORR-001", "CORR-002", "AUTH-004"}
_SUSPICIOUS_BURST_TYPES = ("ssh_failed_login", "sudo_pam_auth_failure", "sudo_auth_failure")


def _suspicious_source_ips(auth_patterns: dict[str, Any] | None) -> list[str]:
    if not auth_patterns or not isinstance(auth_patterns.get("bursts"), list):
        return []
    ips: list[str] = []
    for b in auth_patterns["bursts"]:
        if b.get("event_type") in _SUSPICIOUS_BURST_TYPES:
            for entry in b.get("top_source_ips", []) or []:
                ip = entry.get("ip")
                if ip and ip not in ips:
                    ips.append(ip)
    return ips


def _suspicious_source_ip_counts(auth_patterns: dict[str, Any] | None) -> list[tuple[str, int]]:
    if not auth_patterns or not isinstance(auth_patterns.get("bursts"), list):
        return []
    from collections import Counter
    c: Counter = Counter()
    for b in auth_patterns["bursts"]:
        if b.get("event_type") in _SUSPICIOUS_BURST_TYPES:
            for entry in b.get("top_source_ips", []) or []:
                ip = entry.get("ip")
                if ip:
                    c[ip] += int(entry.get("count") or 0)
    # count desc, then IP: ties are ordered the same way every run (source_ips[0] is stable)
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:5]


def _surface_source_ips_in_evidence(
    findings: list["Finding"], auth_patterns: dict[str, Any] | None
) -> None:
    # Put the attacking source IP(s) directly on the finding so the final answer
    # can name them -- the burst carries top_source_ips but the finding text
    # didn't expose it, so the agent knew the burst happened but often couldn't
    # attribute it to an IP. Independent of threat-intel (fires on any burst).
    counts = _suspicious_source_ip_counts(auth_patterns)
    if not counts:
        return
    ordered_ips = [ip for ip, _n in counts]  # most-active first
    summary = ", ".join(f"{ip} ({n} events)" for ip, n in counts)
    for f in findings:
        if f.id in _IP_SOURCED_SUSPICIOUS_IDS:
            f.evidence.append(f"Source IP(s) behind this activity: {summary}.")
            f.source_ips = list(ordered_ips)  # structured, for output-threading / naming


def _enrich_findings_with_offline_reputation(
    findings: list["Finding"], auth_patterns: dict[str, Any] | None
) -> None:
    ips = _suspicious_source_ips(auth_patterns)
    if not ips:
        return
    try:
        from kratos.adapters.threat_intel import lookup_ip_cache
    except Exception:  # noqa: BLE001 -- enrichment must never break correlation
        return
    malicious: dict[str, dict[str, Any]] = {}
    for ip in ips:
        try:
            r = lookup_ip_cache(ip)  # OFFLINE: reads only the local OTX cache file
        except Exception:  # noqa: BLE001
            r = None
        if r:
            malicious[ip] = r
    if not malicious:
        return
    for f in findings:
        if f.id not in _IP_SOURCED_SUSPICIOUS_IDS:
            continue
        for ip, r in malicious.items():
            pulses = r.get("pulses") or []
            names = ", ".join(str(p.get("pulse_name")) for p in pulses[:3] if p.get("pulse_name"))
            f.evidence.append(
                f"Threat-intel corroboration (offline OTX cache): source IP {ip} is KNOWN-MALICIOUS"
                + (f" -- {names}" if names else "")
                + " -- this corroborates a real attack; treat with raised confidence/severity."
            )
        if _severity_rank(f.severity) < _severity_rank("high"):
            f.severity = "high"


_AUTH_DERIVED_PREFIXES = ("AUTH-", "CORR-", "OBS-")


_COVERAGE_SOURCES = {"sshd": "SSH log", "sudo": "sudo log"}


def _coverage_phrase(ident: str, cov: dict[str, Any]) -> str:
    """One partial-coverage fact in words. A measurement counts EVERYTHING the logs
    hold, so its gap is that the logs don't reach back far enough -- not that only
    the newest events were read (which is what a sampled journal read means)."""
    oldest = _when(cov.get("oldest_returned")) if cov.get("oldest_returned") else "an unknown point"
    if ident == "measurement":
        return f"the target's logs only go back to {oldest}, so nothing earlier could be counted"
    return (f"{_COVERAGE_SOURCES.get(ident, ident)}: only the newest {cov.get('returned')} entries were read, "
            f"nothing before {oldest}")


_MERGE_LABELS = {"CORR-001": "exposed SSH with a burst", "AUTH-004": "the burst itself"}


def _merge_overlapping(findings: list[Finding], auth_patterns: dict[str, Any] | None) -> None:
    """One SSH brute-force burst used to read as three problems: CORR-SSH-001 (high),
    CORR-001 (medium) and AUTH-004 (info) all describe the same failed-login burst on an
    exposed SSH. CORR-001's conditions are a subset of CORR-SSH-001's, and AUTH-004 is
    the burst itself; both fold into CORR-SSH-001 (highest severity kept, rule ids kept
    in also_matched). AUTH-004 stays separate when it also covers sudo bursts, which
    CORR-SSH-001 does not."""
    main = next((f for f in findings if f.id == "CORR-SSH-001"), None)
    if main is None:
        return
    absorb = ["CORR-001"]
    if not _bursts_of(auth_patterns, ("sudo_pam_auth_failure", "sudo_auth_failure")):
        absorb.append("AUTH-004")
    merged = [f for rule in absorb for f in findings if f.id == rule]  # stable: absorb order
    if not merged:
        return
    for f in merged:
        findings.remove(f)
        if _severity_rank(f.severity) > _severity_rank(main.severity):
            main.severity = f.severity
        for ip in f.source_ips:
            if ip not in main.source_ips:
                main.source_ips.append(ip)
        for line in f.evidence:  # e.g. a threat-intel corroboration only the absorbed one had
            if "reputation" in line.lower() and line not in main.evidence:
                main.evidence.append(line)
        main.also_matched.append(f.id)
    main.evidence.append("One finding for this burst -- also matched: " + ", ".join(
        f"{i} ({_MERGE_LABELS.get(i, 'same evidence')})" for i in main.also_matched))


def _stamp_source_ip_entities(findings: list[Finding], auth_patterns: dict[str, Any] | None) -> None:
    """IP-sourced findings' entities: EVERY suspicious source IP behind the bursts (not
    just the top five in source_ips), so a new attacker is a new entity even when it
    isn't among the most active."""
    ips = normalise_entities("ip", _suspicious_source_ips(auth_patterns))
    for f in findings:
        if f.id in _IP_SOURCED_SUSPICIOUS_IDS:
            f.entities = normalise_entities("ip", [*ips, *f.source_ips])


def _disclose_partial_auth_coverage(findings: list[Finding], auth_stats: dict[str, Any] | None) -> None:
    """If the target auth fetch was truncated (the requested window held more
    entries than were fetched -- docs/time_window_design.md step 1), say so on
    every auth-derived finding AND emit COV-001, so that an absence of auth
    findings can never read as "the whole window was clean" when only its newest
    part was actually analyzed."""
    coverage = (auth_stats or {}).get("coverage") or {}
    partial = {ident: cov for ident, cov in coverage.items() if isinstance(cov, dict) and cov.get("truncated")}
    if not partial:
        return
    detail = "; ".join(_coverage_phrase(ident, cov) for ident, cov in sorted(partial.items()))
    note = f"Coverage: partial -- {detail}"
    for f in findings:
        if f.id.startswith(_AUTH_DERIVED_PREFIXES) and note not in f.evidence:
            f.evidence.append(note)
    requested = (_when(auth_stats["since_utc"]) if auth_stats.get("since_utc")
                 else auth_stats.get("since") or "the start of the logs")
    findings.append(
        Finding(
            id="COV-001",
            title="Authentication data covers only part of the requested time window",
            severity="info",
            evidence=[f"Requested window start: {requested}", note],
            recommendation=[
                "Treat the absence of auth findings before the coverage start as UNKNOWN, not clean.",
                "Re-run with a narrower time window to analyze the uncovered part.",
            ],
        )
    )


def _stamp_attack_labels(findings: list[Finding]) -> None:
    """ATT&CK labels from the one mapping (kratos.attack.mapping): a finding keeps
    any its builder set for its own item (PERSIST-*, LOG-*), gains its rule's
    labels otherwise (INTEG-001 by which file changed), and gains those of every
    rule it absorbed (_merge_overlapping). Posture rules add none."""
    from kratos.attack import labels_for_finding

    for f in findings:
        merged: dict[str, dict[str, Any]] = {}
        for lab in [*f.attack, *labels_for_finding(f.id, f.entities),
                    *(lab for other in f.also_matched for lab in labels_for_finding(other))]:
            if isinstance(lab, dict) and lab.get("technique_id"):
                merged.setdefault(str(lab["technique_id"]), lab)
        f.attack = list(merged.values())


def _time_window_note(window: dict[str, Any] | None) -> str:
    """The log window a count or burst list covers, said once in plain words.
    `window` is the auth_stats data of that read (its since/since_utc/until_utc)."""
    if not window:
        return "Time window: not recorded for these logs"
    since_value = window.get("since")
    note = (
        f"Time window: {since_value}" if since_value
        else "Time window: none asked for (the newest log entries were read)"
    )
    if window.get("since_utc"):
        note += f" ({_when(window['since_utc'])}"
        note += f" to {_when(window['until_utc'])})" if window.get("until_utc") else " to now)"
    return note


def generate_findings(
    nmap_parsed: dict[str, Any] | None,
    auth_stats: dict[str, Any] | None,
    auth_patterns: dict[str, Any] | None,
    system_context: dict[str, Any] | None,
    auth_trends: dict[str, Any] | None = None,
    file_integrity: dict[str, Any] | None = None,
    privileged_accounts: dict[str, Any] | None = None,
    vuln_scan: dict[str, Any] | None = None,
    auth_patterns_window: dict[str, Any] | None = None,
    log_integrity: dict[str, Any] | None = None,
    snapshots: dict[str, dict[str, Any] | None] | None = None,
    package_fixed_cves: dict[str, str] | None = None,
    package_doubted_cves: dict[str, str] | None = None,
) -> list[Finding]:
    """`auth_patterns_window`: the auth_stats data saved WITH the burst list (same
    read), so a burst finding states the window its count covers. Without it the
    auth_stats argument is assumed to be that read."""
    findings: list[Finding] = []
    burst_window_note = _time_window_note(
        auth_patterns_window if auth_patterns_window is not None else auth_stats)

    # 1) Network exposure (Nmap)
    if nmap_parsed and isinstance(nmap_parsed.get("hosts"), list):
        hosts = nmap_parsed["hosts"]
        open_ports_total = sum(len(h.get("open_ports", [])) for h in hosts)

        if open_ports_total == 0:
            findings.append(
                Finding(
                    id="NET-001",
                    title="No open TCP ports detected in latest scan",
                    severity="info",
                    evidence=[
                        "From the latest port scan",
                        "Open ports found: 0",
                    ],
                    recommendation=[
                        "If this is expected (local dev machine), no action needed.",
                        "If services should be reachable, verify firewall/service configuration and rescan.",
                    ],
                )
            )
        else:
            # Basic service hints (thesis-safe; not claiming exploitation)
            exposed = []
            ports = []
            for h in hosts:
                for p in h.get("open_ports", []):
                    svc = p.get("service") or "unknown"
                    exposed.append(f"{h.get('ip','?')} {p.get('protocol','tcp')}/{p.get('port')} ({svc})")
                    ports.append(f"{p.get('port')}/{p.get('protocol') or 'tcp'}")

            sev = "medium"
            # If SSH exposed, keep medium (could be high in real environments, but thesis-safe defaults)
            if any("(ssh)" in e or " ssh" in e for e in exposed):
                sev = "medium"

            findings.append(
                Finding(
                    id="NET-002",
                    title="Open ports detected (attack surface present)",
                    severity=sev,
                    entities=normalise_entities("text", ports),
                    evidence=[
                        "From the latest port scan",
                        f"Open ports found: {open_ports_total}",
                        "Exposed endpoints:",
                        *exposed[:10],
                    ],
                    recommendation=[
                        "Validate each exposed service is necessary.",
                        "Restrict access using firewall rules or bind services to trusted interfaces.",
                        "Keep exposed services updated and use strong authentication (especially SSH).",
                    ],
                )
            )

    # 2) Privilege context (sudo group)
    if system_context:
        sudo_line = (system_context.get("users") or {}).get("sudo_group")
        members = _extract_sudo_members(sudo_line)

        if members:
            findings.append(
                Finding(
                    id="CTX-001",
                    title="Sudo-capable users identified",
                    severity="info",
                    evidence=[
                        _system_context_scope_note(system_context),
                        f"sudo group line: {sudo_line}",
                        f"sudo members: {', '.join(members)}",
                    ],
                    recommendation=[
                        "Keep sudo membership minimal and reviewed.",
                        "Ensure sudo users use strong passwords and (if possible) MFA on the host environment.",
                    ],
                )
            )

    # 3) Auth behavior: sudo auth failures + bursts
    if auth_stats:
        by_type = auth_stats.get("events_by_type") or {}
        sudo_fail_count = int(by_type.get("sudo_auth_failure", 0))
        sudo_pam_fail_count = int(by_type.get("sudo_pam_auth_failure", 0))

        # Real fix (2026-07-17): auth_stats['since'] is only ever populated
        # for target-fetched data (agent/tools.py::_persist_target_auth_
        # correlation_data now stamps whatever `since` the model's
        # read_journalctl call used, or None if unstated) -- absent
        # entirely for locally-parsed auth_stats (parse_auth_log has no
        # time-window concept). Either way, state it plainly in the
        # evidence rather than letting a reader (human or the model itself)
        # silently assume these counts are scoped to whatever the
        # investigation goal asked about -- without this, a final answer
        # can confidently claim "in the last 24 hours" about a count that
        # was actually an unscoped snapshot.
        time_window_note = _time_window_note(auth_stats)
        # Partial coverage is stated once per finding by _disclose_partial_auth_coverage
        # ("Coverage: partial -- ..."), not repeated in this line.

        if (sudo_fail_count + sudo_pam_fail_count) > 0:
            findings.append(
                Finding(
                    id="AUTH-001",
                    title="Sudo authentication failures observed",
                    severity="low",
                    entities=normalise_entities("text", [
                        u.get("user") for key in ("top_sudo_auth_fail_users", "top_sudo_pam_auth_fail_users")
                        for u in auth_stats.get(key) or [] if isinstance(u, dict)]),
                    evidence=[
                        f"sudo password failures: {sudo_pam_fail_count}",
                        f"sudo authentication failures: {sudo_fail_count}",
                        "From the latest read of the login logs",
                        time_window_note,
                    ],
                    recommendation=[
                        "If this was a mistyped password, no action needed.",
                        "If unexpected, review sudo usage and ensure passwords are not being guessed.",
                        "Consider enabling stronger authentication or tightening sudo policy if failures repeat.",
                    ],
                    playbooks=[
                        {
                            "title": "Confirm if failures were accidental",
                            "commands": [
                                "grep -n 'authentication failure' /var/log/auth.log | tail -n 40",
                                "history | tail -n 50",
                            ],
                            "notes": [
                                "If it was a mistyped password, no action needed. If unexpected, investigate.",
                            ],
                        },
                    ],
                )
            )

        sudo_open = int(by_type.get("sudo_session_open", 0))
        sudo_close = int(by_type.get("sudo_session_close", 0))

        if (sudo_open + sudo_close) > 0:
            findings.append(
                Finding(
                    id="AUTH-003",
                    title="Sudo session activity observed",
                    severity="info",
                    entities=normalise_entities("text", [
                        u.get("user") for u in auth_stats.get("top_sudo_users") or [] if isinstance(u, dict)]),
                    evidence=[
                        f"sudo sessions opened: {sudo_open}",
                        f"sudo sessions closed: {sudo_close}",
                        "From the latest read of the login logs",
                        time_window_note,
                    ],
                    recommendation=[
                        "If this corresponds to expected admin tasks (updates/installs), no action needed.",
                        "If unexpected, review who initiated privileged actions and when they occurred.",
                    ],
                )
            )

    # Check for auth failures with inactive logging services. Only assess this
    # when system_context actually carries a services list (#11) -- otherwise
    # "inactive" is unverifiable and OBS-001 would false-positive on missing data.
    failures = _auth_failure_count(auth_stats)
    if failures > 0 and _logging_services_assessable(system_context):
        rsyslog_ok = _is_service_active(system_context, "rsyslog.service")
        journald_ok = _is_service_active(system_context, "systemd-journald.service")

        if not (rsyslog_ok or journald_ok):
            obs_001_evidence = [
                f"auth failure events = {failures}",
                "rsyslog.service active = false",
                "systemd-journald.service active = false",
                f"context snapshot = {(system_context or {}).get('collected_at', 'unknown')}",
            ]
            scope_note = _system_context_scope_note(system_context)
            if scope_note:
                obs_001_evidence.append(scope_note)
            findings.append(
                Finding(
                    id="OBS-001",
                    title="Authentication failures detected but log collection services appear inactive",
                    severity="medium",
                    evidence=obs_001_evidence,
                    recommendation=[
                        "Verify that system logging is enabled (rsyslog or journald) so security-relevant events are recorded.",
                        "If this is an embedded/stripped environment, document logging limitations in the deployment section.",
                    ],
                    playbooks=[
                        {
                            "title": "Check logging service status",
                            "commands": [
                                "systemctl status rsyslog --no-pager",
                                "systemctl status systemd-journald --no-pager",
                            ],
                            "notes": [
                                "If both are inactive, visibility is reduced and security events may not be recorded.",
                            ],
                        },
                        {
                            "title": "Inspect recent logging errors",
                            "commands": [
                                "journalctl -xe --no-pager | tail -n 80",
                                "journalctl -u rsyslog --since '30 minutes ago' --no-pager",
                                "journalctl -u systemd-journald --since '30 minutes ago' --no-pager",
                            ],
                            "notes": [
                                "Look for service crashes, permission issues, disk full, or configuration failures.",
                            ],
                        },
                    ],
                )
            )

    # Bursts (patterns)
    if auth_patterns and isinstance(auth_patterns.get("bursts"), list):
        bursts = auth_patterns["bursts"]
        # only report bursts we care about
        relevant = [
            b for b in bursts
            if b.get("event_type") in ("sudo_pam_auth_failure", "sudo_auth_failure", "ssh_failed_login")
        ]
        if relevant:
            # If we have bursts, raise severity
                        findings.append(
                Finding(
                    id="AUTH-004",
                    title="Burst activity detected in authentication failures",
                    severity="info",
                    evidence=[
                        *(["From the latest read of the login logs"] if auth_patterns.get("source_events_file") else []),
                        f"Bursts found: {len(relevant)}",
                        burst_window_note,
                        *[_burst_line(b) for b in relevant[:5]],
                    ],
                    recommendation=[
                        "Investigate the time window(s) shown in the evidence.",
                        "For SSH bursts: consider rate-limiting, disabling password auth, or restricting by IP.",
                        "For sudo failure bursts: review local user activity and consider tightening sudo policy if unexpected.",
                    ],
                )
            )

    # ---------------------------
    # Correlation rules (Sprint next)
    # ---------------------------

    # CORR-001: SSH exposed + SSH failed-login burst
    ssh_exposed = _nmap_has_ssh_exposed(nmap_parsed)
    ssh_bursts = _bursts_of(auth_patterns, ("ssh_failed_login",))

    if ssh_exposed and ssh_bursts:
        findings.append(
            Finding(
                id="CORR-001",
                title="SSH exposure correlated with failed-login burst activity",
                severity="medium",
                evidence=[
                    "SSH appears exposed in latest scan (port 22 and/or ssh service detected).",
                    f"Bursts of failed SSH logins: {len(ssh_bursts)}",
                    burst_window_note,
                    *[_burst_line(b) for b in ssh_bursts[:3]],
                ],
                recommendation=[
                    "If SSH must remain exposed: disable password authentication, use key-based auth, and restrict by IP if possible.",
                    "Consider rate-limiting / lockout controls (e.g., fail2ban) and monitor authentication logs.",
                    "Re-run scans and confirm only required services are exposed.",
                ],
            )
        )

    # CORR-002: Sudo failure bursts + single sudo user
    sudo_members: list[str] = []
    if system_context:
        sudo_line = (system_context.get("users") or {}).get("sudo_group")
        sudo_members = _extract_sudo_members(sudo_line)

    sudo_fail_bursts = _bursts_of(auth_patterns, ("sudo_pam_auth_failure", "sudo_auth_failure"))

    if sudo_fail_bursts and len(sudo_members) == 1:
        findings.append(
            Finding(
                id="CORR-002",
                title="Privileged authentication bursts observed on a single sudo user",
                severity="medium",
                evidence=[
                    _system_context_scope_note(system_context),
                    f"sudo group members = {', '.join(sudo_members)}",
                    f"Bursts of sudo failures: {len(sudo_fail_bursts)}",
                    burst_window_note,
                    *[_burst_line(b) for b in sudo_fail_bursts[:3]],
                ],
                recommendation=[
                    "Verify whether these failures match expected admin activity (mistyped password) in the shown time window.",
                    "If unexpected, review local user activity and consider tightening sudo policy.",
                    "Ensure the sudo user has strong authentication and avoid unnecessary sudo attempts.",
                ],
                playbooks=[
                    {
                        "title": "Review sudo activity around the burst window",
                        "commands": [
                            "grep -n 'sudo' /var/log/auth.log | tail -n 60",
                            "journalctl _COMM=sudo --since '2 hours ago' --no-pager | tail -n 80",
                        ],
                        "notes": [
                            "Confirm whether the failures match expected admin activity (mistypes) or look suspicious.",
                        ],
                    },
                    {
                        "title": "Check who has sudo access",
                        "commands": [
                            "getent group sudo",
                            "sudo -l",
                        ],
                        "notes": [
                            "Keep sudo membership minimal and reviewed.",
                        ],
                    },
                ],
            )
        )

    # CORR-SSH-001: SSH open + failed-login burst => HIGH
    # Check exposure from both nmap and system context
    ssh_from_nmap = _nmap_has_ssh_exposed(nmap_parsed)
    ssh_from_context = False
    ssh_ports = []
    
    if system_context and "ssh" in system_context:
        ssh_ctx = system_context["ssh"]
        if ssh_ctx.get("listening_ports"):
            ssh_from_context = True
            ssh_ports = ssh_ctx.get("listening_ports", [])
    
    ssh_exposed = ssh_from_nmap or ssh_from_context
    ssh_failed_bursts = _bursts_of(auth_patterns, ("ssh_failed_login",))
    
    if ssh_exposed and len(ssh_failed_bursts) > 0:
        # Build evidence based on what detected SSH
        evidence = []
        if ssh_from_nmap and ssh_from_context:
            exposure_msg = f"ssh exposed (nmap + context), ports: {ssh_ports if ssh_ports else [22]}"
        elif ssh_from_nmap:
            exposure_msg = "ssh exposed (nmap scan detected port 22 open)"
        else:
            exposure_msg = f"ssh exposed (context: listening on ports {ssh_ports})"
        
        evidence.append(exposure_msg)
        if ssh_from_context:
            # system_context's "ssh" info reflects whatever host
            # collect_system_context inspected (Kratos's own local host as of
            # this writing) -- flag that explicitly whenever it contributed
            # to this SSH-exposure verdict, so "context: listening on ports"
            # is never mistaken for the monitored target's own SSH exposure.
            scope_note = _system_context_scope_note(system_context)
            if scope_note:
                evidence.append(f"NOTE: the 'context' exposure signal above is from {scope_note}")
        evidence.append(f"Bursts of failed SSH logins: {len(ssh_failed_bursts)}")
        # right under the count: the live view shows only the first few evidence lines
        evidence.append(burst_window_note)
        
        # Summarize burst evidence (keep it minimal)
        b0 = ssh_failed_bursts[0]
        evidence.append("for example, " + _burst_line({**b0, "count": b0.get("count", 0)}))
        
        findings.append(
            Finding(
                id="CORR-SSH-001",
                title="SSH exposed with failed-login burst activity observed",
                severity="high",
                evidence=evidence,
                recommendation=[
                    "Confirm SSH is required on this host.",
                    "Restrict SSH access (firewall, allowlist, or bind to trusted interface/VPN).",
                    "Prefer key-based authentication; disable password auth if possible.",
                    "Monitor for continued failed logins and consider rate limiting (e.g., Fail2ban).",
                ],
                playbooks=[
                    {
                        "title": "Inspect recent SSH authentication activity",
                        "commands": [
                            "journalctl _COMM=sshd --since '2 hours ago' --no-pager | tail -n 120",
                            "grep -n 'Failed password' /var/log/auth.log | tail -n 80",
                            "grep -n 'Failed publickey' /var/log/auth.log | tail -n 80",
                        ],
                        "notes": [
                            "Confirm whether failures are expected (testing) or suspicious (repeated / unknown IPs)."
                        ],
                    },
                    {
                        "title": "Verify SSH exposure and listeners",
                        "commands": [
                            "ss -lntp | grep ':22 '",
                            "sudo ufw status verbose || true",
                            "systemctl status sshd --no-pager || systemctl status ssh --no-pager",
                        ],
                        "notes": [
                            "If SSH is not needed publicly, restrict access."
                        ],
                    }
                ]
            )
        )

    # AUTH-TREND-001: Increasing authentication failures trend
    if auth_trends:
        summary = auth_trends.get("summary", {})
        if summary.get("trigger_auth_trend_001") is True:
            direction = summary.get("direction", "unknown")
            delta = summary.get("delta", 0)
            files_compared = summary.get("files_compared", 0)
            first_val = summary.get("first_value", 0)
            last_val = summary.get("last_value", 0)
            
            findings.append(
                Finding(
                    id="AUTH-TREND-001",
                    title="Increasing authentication failures observed across recent runs",
                    severity="medium",
                    evidence=[
                        f"direction = {direction}",
                        f"delta = {delta} (from {first_val} to {last_val})",
                        f"files compared = {files_compared}",
                        f"trend source: {auth_trends.get('generated_at', 'unknown')}",
                    ],
                    recommendation=[
                        "Verify whether admin activity or testing caused the increase.",
                        "Review auth logs around the newest run timestamps to identify patterns.",
                        "If SSH bursts exist, consider rate-limiting or disabling password authentication.",
                        "Monitor for continued escalation in future runs.",
                    ],
                )
            )

    # INTEG-001: File/config integrity changes (from check_file_integrity's baseline diff)
    if file_integrity and isinstance(file_integrity.get("diff"), dict):
        diff = file_integrity["diff"]
        changed = diff.get("changed") or []
        added = diff.get("added") or []
        removed = diff.get("removed") or []

        if changed or added or removed:
            evidence = [f"Checked {_when(file_integrity.get('checked_at', 'unknown'))} against the saved baseline "
                        f"'{file_integrity.get('baseline_name', 'default')}'"]
            if changed:
                evidence.append(f"Files changed: {len(changed)}")
                evidence.extend(f"  changed: {c.get('path')}" for c in changed[:10])
            if added:
                evidence.append(f"Files added: {len(added)}")
                evidence.extend(f"  added: {a.get('path')}" for a in added[:10])
            if removed:
                evidence.append(f"Files removed: {len(removed)}")
                evidence.extend(f"  removed: {r.get('path')}" for r in removed[:10])

            findings.append(
                Finding(
                    id="INTEG-001",
                    title="Tracked file(s) changed since baseline",
                    severity="medium",
                    entities=normalise_entities("path", [x.get("path") for x in (*changed, *added, *removed)
                                                         if isinstance(x, dict)]),
                    evidence=evidence,
                    recommendation=[
                        "Confirm whether this change was an authorized/expected admin action.",
                        "If unexpected, treat as a possible tampering or persistence indicator and investigate further (recent auth activity, running processes).",
                        "Re-baseline (check_file_integrity) once the change is confirmed legitimate, so future diffs are measured from the new known-good state.",
                    ],
                )
            )

    # PRIV-*: privileged access on the target (from list_privileged_accounts)
    if privileged_accounts:
        findings.extend(_privileged_account_findings(privileged_accounts))

    # VULN-*: known vulnerabilities on the target's services (from run_vuln_scan)
    if vuln_scan:
        findings.extend(_vulnerability_findings(vuln_scan, package_fixed_cves or {}, package_doubted_cves or {}))

    # LOG-* / SEAL-*: logs cleared or edited, journal sealing (from check_log_integrity)
    if log_integrity:
        findings.extend(_log_integrity_findings(log_integrity))

    # The snapshot checks, in registration order: PERSIST-* (where someone could keep
    # access, A.1), LIVE-* (what is running right now, A.5), PKG-* (vulnerable packages, A.2)
    for src in snapshot_sources():
        doc = (snapshots or {}).get(src.category)
        if doc:
            findings.extend(src.build(doc))

    # 4) Environment note (WSL)
    if system_context:
        rel = (system_context.get("os") or {}).get("release", "")
        if "WSL" in rel or "microsoft" in rel.lower():
            findings.append(
                Finding(
                    id="ENV-001",
                    title="Environment appears to be WSL2 (development context)",
                    severity="info",
                    evidence=[_system_context_scope_note(system_context), f"kernel release: {rel}"],
                    recommendation=[
                        "Expect some differences: services and log formats under WSL2 differ from a standard Linux host.",
                        "For conclusions about a real server, investigate the server itself rather than a WSL2 environment.",
                    ],
                )
            )

    # Surface the attacking source IP(s) on IP-sourced findings so the answer
    # can attribute the activity, then deterministically corroborate them against
    # the offline threat-intel cache (Option 1). Both are independent of whether
    # the agent chose to call check_ip_reputation.
    _surface_source_ips_in_evidence(findings, auth_patterns)
    _enrich_findings_with_offline_reputation(findings, auth_patterns)
    _merge_overlapping(findings, auth_patterns)
    _stamp_source_ip_entities(findings, auth_patterns)
    _disclose_partial_auth_coverage(findings, auth_stats)
    _stamp_attack_labels(findings)

    # Sort by severity (high -> info)
    findings.sort(key=lambda f: _severity_rank(f.severity), reverse=True)
    return findings


# ---------------------------
# Auto-discovered input staleness (Sprint 3 cleanup, 2026-07-16)
# ---------------------------
# Reference pattern: adapters/vuln_scan.py::check_vulscan_db_staleness /
# STALENESS_THRESHOLD_DAYS -- same non-blocking, mtime-based, "round number,
# stated as such" philosophy, applied here to a different question (spread
# BETWEEN several auto-discovered inputs' timestamps, not one file's age
# against now).
#
# find_latest_inputs() picks the latest file per category independently,
# with no check on how far apart those files actually are -- left
# unguarded, a stale nmap scan or system-context snapshot from days earlier
# can silently correlate against same-day auth data with no warning at all.
# Not cosmetic: correlate_findings's own value proposition is corroborating
# a finding ACROSS data types (e.g. CORR-SSH-001 combines "SSH is exposed"
# with "a failed-login burst happened"), which only means what it claims if
# those inputs are roughly contemporaneous -- a stale
# nmap/context input mixed with fresh auth data can make a finding look
# corroborated when it's really "exposed at some point in the past, burst
# happening now," a materially weaker claim.
#
# A single, uniform threshold (not category-aware): auth data is
# effectively continuous while nmap/context data changes far less often, but
# there's no real usage data yet to calibrate a per-category-pair matrix
# against, and the codebase's own precedent (vulscan's threshold) is a
# single round number stated as operationally reasonable, not precisely
# derived -- matching that rather than inventing new machinery. 24 hours:
# short enough to catch the real multi-day-stale scenario that surfaced
# this, long enough that a single investigation collecting different
# categories a few hours apart (normal, not a problem) doesn't get flagged.
STALENESS_SPREAD_THRESHOLD_HOURS = 24

# A privileged-accounts snapshot only feeds findings while it is this fresh:
# it is produced on demand, and an old "X was just added to sudo" must not keep
# re-firing in every later investigation.
PRIVILEGED_SNAPSHOT_MAX_AGE_HOURS = 24


# A vulnerability-scan snapshot feeds findings under the same rule: the newest
# scan OF THE ACTIVE TARGET, and only while it's under a day old.
VULN_SCAN_MAX_AGE_HOURS = 24
_VULN_SCAN_GLOB = "vuln_scan_*.json"
_VULN_SCAN_FILES_CONSIDERED = 200
def _snapshot_time(data: dict[str, Any], key: str, path: Path) -> float:
    # epoch_of handles a trailing "Z" (Python 3.10's fromisoformat does not), so an old
    # snapshot is not mistaken for a fresh one by falling back to the file's mtime.
    from kratos.utils.timeutil import epoch_of

    e = epoch_of(data.get(key))
    return e if e is not None else path.stat().st_mtime


def _load_recent_vuln_scan(scans_dir: Path) -> tuple[dict[str, Any] | None, Path | None]:
    """The newest run_vuln_scan snapshot of the active target, if it's fresh.

    Several targets can share one data folder, so only scans of THIS target
    count, and the newest of those -- by the time it recorded, since copying
    or restoring a data folder resets file times -- decides alone: if it's
    stale, an even older scan is not used instead. Unreadable or malformed
    files are skipped, a scan dated more than an hour in the future is
    distrusted, and with no active target set the newest scan is used, as for
    the privileged-accounts snapshot."""
    try:
        files = sorted(scans_dir.glob(_VULN_SCAN_GLOB), key=lambda f: f.stat().st_mtime, reverse=True)
    except OSError:
        return None, None
    from kratos.kratos_config import get_active_target

    active = _host_key(get_active_target())
    best: tuple[float, dict[str, Any], Path] | None = None
    for path in files[:_VULN_SCAN_FILES_CONSIDERED]:
        try:
            data = _read_json(path)
            when = _snapshot_time(data, "scanned_at", path) if isinstance(data, dict) else None
        except (OSError, ValueError):
            continue
        if when is None or not data.get("target") or not isinstance(data.get("findings", []), list):
            continue
        if active and _host_key(data["target"]) != active:
            continue
        if best is None or when > best[0]:
            best = (when, data, path)
    if best is None:
        return None, None
    age = datetime.now().timestamp() - best[0]
    if age > VULN_SCAN_MAX_AGE_HOURS * 3600 or age < -3600:
        return None, None
    return best[1], best[2]


def _load_recent_privileged_snapshot(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = _read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        captured = datetime.fromisoformat(str(data.get("checked_at"))).timestamp()
    except ValueError:
        captured = path.stat().st_mtime
    if datetime.now().timestamp() - captured > PRIVILEGED_SNAPSHOT_MAX_AGE_HOURS * 3600:
        return None
    # A snapshot of a DIFFERENT machine must never feed this target's report.
    from kratos.kratos_config import get_active_target

    active = (get_active_target() or "").strip().lower()
    snap_host = str(data.get("target") or "").rpartition("@")[2].strip().lower()
    if active and snap_host and snap_host != active:
        return None
    return data


LOG_INTEGRITY_MAX_AGE_HOURS = 24


def _load_recent_log_integrity(path: Path | None) -> dict[str, Any] | None:
    """The newest check_log_integrity result for the active machine, if it is less
    than LOG_INTEGRITY_MAX_AGE_HOURS old (find_latest_inputs already picked a file
    describing this machine)."""
    if path is None:
        return None
    try:
        data = _read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("checks"), dict):
        return None
    when = data.get("checked_at_epoch")
    if not isinstance(when, (int, float)):
        try:
            when = path.stat().st_mtime
        except OSError:
            return None
    age = datetime.now().timestamp() - float(when)
    if age > LOG_INTEGRITY_MAX_AGE_HOURS * 3600 or age < -3600:
        return None
    return data


def _log_integrity_findings(data: dict[str, Any]) -> list[Finding]:
    """LOG-001..005 and SEAL-001..003 from one check_log_integrity result."""
    from kratos.attack import labels

    checks = data.get("checks") or {}
    when = f"Checked {_when(data['checked_at'])}" if data.get("checked_at") else "From the latest log integrity check"
    out: list[Finding] = []

    def items(cid: str) -> list[dict[str, Any]]:
        c = checks.get(cid) or {}
        return [i for i in c.get("items") or [] if isinstance(i, dict)]

    def cov(cid: str) -> str:
        return f"What was checked: {(checks.get(cid) or {}).get('coverage') or 'not recorded'}"

    # A person's decision on a tamper finding covers the incidents they saw, not the
    # next one (lifecycle: a new entity reopens a decided finding). Checks that
    # report an incident ONCE, at the check that noticed it (file state, auditd),
    # name it by what changed plus that check's time; checks that keep reporting
    # the same evidence every run (zeroed wtmp records, a changed archive) name it
    # by something stable to it (record number, the file's fingerprint).
    detected = f"detected {_when(data['checked_at'])}" if data.get("checked_at") else ""

    def incident(what: Any) -> str | None:
        if what is None or str(what).strip() == "":
            return None
        return f"{str(what).strip()} ({detected})" if detected else str(what).strip()

    file_items = items("file_state")
    logs = [i for i in file_items if not i.get("login_record")]
    if logs:
        out.append(Finding(
            id="LOG-001", title="Log file cut short, replaced or edited outside log rotation", severity="high",
            entities=normalise_entities("path", [incident(i.get("path")) for i in logs]), attack=labels("LOG-001"),
            evidence=[when, *[f"{i.get('path')}: {i.get('detail')}" for i in logs[:10]], cov("file_state")],
            recommendation=[
                "Treat the affected log as unreliable for the time before the change, and find out who could write it "
                "(root or the log's owner) and when -- check sudo, auditd and login activity around then.",
                "Compare with any copy kept off the machine (central log server, backups, a sealed journal).",
                "If this was a deliberate admin action, record the decision on this finding so it stops alerting.",
            ],
        ))
    gaps = items("journal")
    if gaps:
        out.append(Finding(
            id="LOG-002", title="Journal file missing from the middle of the log history", severity="high",
            entities=normalise_entities("text", [f"{g.get('after')}..{g.get('before')}" for g in gaps]),
            attack=labels("LOG-002"),
            evidence=[when, *[str(g.get("detail")) for g in gaps[:5]], cov("journal")],
            recommendation=[
                "journald only removes the OLDEST files on its own; a missing file between two that remain was "
                "deleted by someone with root access. Find out who and when.",
                "The time range shown has no journal on this machine -- use other sources (auditd, a central log "
                "server) for that period.",
            ],
        ))
    boots = items("boots")
    if boots:
        out.append(Finding(
            id="LOG-003", title="Machine went down without a clean shutdown", severity="low",
            entities=normalise_entities("text", [b.get("boot_id") for b in boots]),
            evidence=[when, *[str(b.get("detail")) for b in boots[:5]], cov("boots"),
                      "This is context, not proof of tampering: a crash or power cut does the same."],
            recommendation=["If nobody restarted it on purpose, find out why it went down (hardware, kernel, power, "
                            "or someone forcing a reboot to cut logging short)."],
        ))
    login_items = items("login_records")
    shrunk = [i for i in file_items if i.get("login_record")]
    if login_items or shrunk:
        sev = "high" if login_items else "medium"
        lines = [f"{i.get('file')}: record {i.get('record')} {'is all zeros' if i.get('kind') == 'zeroed' else 'is out of time order'}"
                 for i in login_items[:10]]
        lines += [f"{i.get('path')}: {i.get('detail')}" for i in shrunk[:5]]
        out.append(Finding(
            id="LOG-004", title="Login records (wtmp/btmp) look edited", severity=sev,
            entities=normalise_entities("path", [f"/var/log/{i.get('file')} record {i.get('record')} "
                                                 f"({'zeroed' if i.get('kind') == 'zeroed' else 'out of order'})"
                                                 for i in login_items]
                                        + [incident(i.get("path")) for i in shrunk]),
            attack=labels("LOG-004"),
            evidence=[when, *lines, *(checks.get("login_records") or {}).get("evidence", [])[:3], cov("login_records")],
            recommendation=[
                "Zeroed or reordered login records are what log wipers leave behind to hide a login. Treat the login "
                "history (last, lastb) as incomplete and look at sshd/auth logs for the same period.",
            ],
        ))
    audit_items = items("auditd")
    changes = [i for i in audit_items if i.get("severity") == "high"]
    if changes:
        out.append(Finding(
            id="LOG-005", title="auditd was stopped, disabled or emptied of its rules", severity="high",
            attack=labels("LOG-005"),
            entities=normalise_entities("text", [incident(i.get("kind")) for i in changes]),
            evidence=[when, *(checks.get("auditd") or {}).get("evidence", [])[:8], cov("auditd")],
            recommendation=[
                "Restart auditd and reload its rules (sudo systemctl start auditd; sudo augenrules --load), then "
                "find out who stopped it: its own log (read_host_logs source auditd) records DAEMON_END and "
                "CONFIG_CHANGE with the user.",
            ],
        ))
    elif any(i.get("kind") == "not_running" for i in audit_items):
        # A state, not an incident: closes on its own once auditd runs again.
        out.append(Finding(
            id="LOG-006", title="auditd is installed but not running", severity="info",
            evidence=[when, *(checks.get("auditd") or {}).get("evidence", [])[:3], cov("auditd")],
            recommendation=["Start and enable auditd if you rely on it for a record of what runs on this machine "
                            "(sudo systemctl enable --now auditd)."],
        ))
    out.extend(_seal_findings(data.get("seal"), when))
    return out


def _seal_findings(seal: dict[str, Any] | None, when: str) -> list[Finding]:
    from kratos.attack import labels

    if not isinstance(seal, dict):
        return []
    out: list[Finding] = []
    failed = [f for f in seal.get("failed") or [] if isinstance(f, dict)]
    changed = [f for f in seal.get("changed_archives") or [] if isinstance(f, dict)]
    if failed or changed:
        out.append(Finding(
            id="SEAL-001", title="Sealed journal failed verification or changed after it was verified",
            severity="high", attack=labels("SEAL-001"),
            entities=normalise_entities("text", [
                f"{f.get('name')} (sha256 {str(f['sha256'])[:12]})" if f.get("sha256") else f.get("name")
                for f in failed + changed]),
            evidence=[when, *[f"{f.get('name')}: {f.get('detail')}" for f in failed[:5]],
                      *[f"{f.get('name')}: verified earlier with a different hash -- the archived file was altered"
                        for f in changed[:5]]],
            recommendation=["The journal's own seal shows its entries were altered after they were written. Treat "
                            "the affected period as tampered; investigate who had root access then."],
        ))
    unsealed = [f for f in seal.get("unsealed_after_setup") or [] if isinstance(f, dict)]
    if unsealed:
        out.append(Finding(
            id="SEAL-002", title="Journal sealing stopped on this machine", severity="medium",
            attack=labels("SEAL-002"), entities=normalise_entities("text", [f.get("name") for f in unsealed]),
            evidence=[when, *[f"{f.get('name')}: written after sealing was set up, but not sealed" for f in unsealed[:5]]],
            recommendation=["Sealing was turned off or its key removed on the machine (sudo journalctl "
                            "--setup-keys re-creates it -- then give Kratos the new verification key)."],
        ))
    note = seal.get("unverifiable")
    if note:
        out.append(Finding(
            id="SEAL-003", title="Sealed journal could not be verified this time", severity="info",
            evidence=[when, str(note)],
            recommendation=["See the reason above; nothing here says the logs were altered."],
        ))
    return out


# A persistence snapshot feeds findings while it is this fresh (same rule as the
# privileged-accounts and log-integrity snapshots): the places an intruder keeps
# access in are a state, but a month-old inventory must not keep re-firing as if
# it were today's.
PERSISTENCE_MAX_AGE_HOURS = 24


def _load_recent_persistence(path: Path | None) -> dict[str, Any] | None:
    """The newest persistence check of the active machine, if it is less than
    PERSISTENCE_MAX_AGE_HOURS old (find_latest_inputs already picked a file
    describing this machine)."""
    if path is None:
        return None
    try:
        data = _read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("signals"), list):
        return None
    captured = _snapshot_time(data, "checked_at", path)
    if datetime.now().timestamp() - captured > PERSISTENCE_MAX_AGE_HOURS * 3600:
        return None
    return data


def _persist_kwargs(sig: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    """The shared Finding fields for one judged persistence signal. The rule id is
    passed as a literal by each builder below (the lifecycle-completeness scan in
    tests/test_lifecycle_rules.py reads literal Finding(id=...) calls)."""
    target = doc.get("target") or "the target"
    via = str(doc.get("via") or "ssh")
    how = ("read through the machine's sub-agent (as root)" if via == "subagent"
           else f"read over SSH as uid {doc.get('reader_uid')}" if doc.get("reader_uid") not in (None, 0)
           else "read over SSH")
    evidence = [f"From the persistence check of {target} at {_when(doc.get('checked_at', 'unknown'))} ({how})",
                *[str(line) for line in sig.get("evidence") or []]]
    if str(sig.get("rule")) != "PERSIST-009" and doc.get("coverage_gaps"):
        evidence.append("Not everything could be checked -- see PERSIST-009 for what was not read.")
    return {"title": str(sig.get("title") or sig.get("rule")), "severity": str(sig.get("severity") or "info"),
            "evidence": evidence, "recommendation": [str(r) for r in sig.get("recommendation") or []],
            "entities": normalise_entities("path", sig.get("entities") or []),
            "attack": [dict(a) for a in sig.get("attack") or [] if isinstance(a, dict)]}


def _persistence_findings(doc: dict[str, Any]) -> list[Finding]:
    """PERSIST-001..009 from one persistence snapshot (A.1).

    The judging happened when the inventory was read (kratos.persist.judge) and its
    result is in the snapshot, so a later correlation of the same snapshot says
    exactly the same thing. Here each judged signal only becomes a Finding; one
    literal-id builder per rule, so the lifecycle-completeness scan sees every id."""
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for s in doc.get("signals") or []:
        if isinstance(s, dict) and str(s.get("rule", "")).startswith("PERSIST-"):
            by_rule.setdefault(s["rule"], []).append(s)
    out: list[Finding] = []
    for s in by_rule.get("PERSIST-001", []):
        out.append(Finding(id="PERSIST-001", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-002", []):
        out.append(Finding(id="PERSIST-002", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-003", []):
        out.append(Finding(id="PERSIST-003", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-004", []):
        out.append(Finding(id="PERSIST-004", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-005", []):
        out.append(Finding(id="PERSIST-005", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-006", []):
        out.append(Finding(id="PERSIST-006", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-007", []):
        out.append(Finding(id="PERSIST-007", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-008", []):
        out.append(Finding(id="PERSIST-008", **_persist_kwargs(s, doc)))
    for s in by_rule.get("PERSIST-009", []):
        out.append(Finding(id="PERSIST-009", **_persist_kwargs(s, doc)))
    return out


# A live-response snapshot feeds findings while it is this fresh: what is running
# "right now" is only true for a while, so a day-old read must not keep re-firing.
LIVE_MAX_AGE_HOURS = 24


def _load_recent_live(path: Path | None) -> dict[str, Any] | None:
    """The newest live-response read of the active machine, if it is less than
    LIVE_MAX_AGE_HOURS old (find_latest_inputs already picked a file describing
    this machine)."""
    if path is None:
        return None
    try:
        data = _read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("signals"), list):
        return None
    captured = _snapshot_time(data, "checked_at", path)
    if datetime.now().timestamp() - captured > LIVE_MAX_AGE_HOURS * 3600:
        return None
    return data


def _live_kwargs(sig: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    """The shared Finding fields for one judged live-response signal. The rule id is
    passed as a literal by each builder below (the lifecycle-completeness scan in
    tests/test_lifecycle_rules.py reads literal Finding(id=...) calls)."""
    target = doc.get("target") or "the target"
    via = str(doc.get("via") or "ssh")
    how = ("read through the machine's sub-agent (as root)" if via == "subagent"
           else f"read over SSH as uid {doc.get('reader_uid')}" if doc.get("reader_uid") not in (None, 0)
           else "read over SSH")
    evidence = [f"From the live-response check of {target} at {_when(doc.get('checked_at', 'unknown'))} ({how})",
                *[str(line) for line in sig.get("evidence") or []]]
    if str(sig.get("rule")) != "LIVE-007" and doc.get("coverage_gaps"):
        evidence.append("Not everything could be checked -- see LIVE-007 for what was not read.")
    return {"title": str(sig.get("title") or sig.get("rule")), "severity": str(sig.get("severity") or "info"),
            "evidence": evidence, "recommendation": [str(r) for r in sig.get("recommendation") or []],
            "entities": normalise_entities("process", sig.get("entities") or []),
            "attack": [dict(a) for a in sig.get("attack") or [] if isinstance(a, dict)]}


def _live_response_findings(doc: dict[str, Any]) -> list[Finding]:
    """LIVE-001..007 from one live-response snapshot (A.5).

    The judging happened when the read was taken (kratos.live.judge) and its result
    is in the snapshot, so a later correlation of the same snapshot says exactly the
    same thing. One literal-id builder per rule, so the lifecycle-completeness scan
    sees every id."""
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for s in doc.get("signals") or []:
        if isinstance(s, dict) and str(s.get("rule", "")).startswith("LIVE-"):
            by_rule.setdefault(s["rule"], []).append(s)
    out: list[Finding] = []
    for s in by_rule.get("LIVE-001", []):
        out.append(Finding(id="LIVE-001", **_live_kwargs(s, doc)))
    for s in by_rule.get("LIVE-002", []):
        out.append(Finding(id="LIVE-002", **_live_kwargs(s, doc)))
    for s in by_rule.get("LIVE-003", []):
        out.append(Finding(id="LIVE-003", **_live_kwargs(s, doc)))
    for s in by_rule.get("LIVE-004", []):
        out.append(Finding(id="LIVE-004", **_live_kwargs(s, doc)))
    for s in by_rule.get("LIVE-005", []):
        out.append(Finding(id="LIVE-005", **_live_kwargs(s, doc)))
    for s in by_rule.get("LIVE-006", []):
        out.append(Finding(id="LIVE-006", **_live_kwargs(s, doc)))
    for s in by_rule.get("LIVE-007", []):
        out.append(Finding(id="LIVE-007", **_live_kwargs(s, doc)))
    return out


# A package result feeds findings while it is this fresh (the check re-reads every
# six hours by default): an old inventory must not keep describing today's machine.
PACKAGES_MAX_AGE_HOURS = 24


def _load_recent_packages(path: Path | None) -> dict[str, Any] | None:
    """The newest package check of the active machine, if it is less than
    PACKAGES_MAX_AGE_HOURS old (find_latest_inputs already picked a file describing
    this machine)."""
    if path is None:
        return None
    try:
        data = _read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("signals"), list):
        return None
    captured = _snapshot_time(data, "checked_at", path)
    if datetime.now().timestamp() - captured > PACKAGES_MAX_AGE_HOURS * 3600:
        return None
    return data


def _pkg_kwargs(sig: dict[str, Any]) -> dict[str, Any]:
    """The shared Finding fields for one package signal. The rule id is passed as a
    literal by each builder below (the lifecycle-completeness scan reads literal
    Finding(id=...) calls)."""
    kind = "cve" if str(sig.get("rule")) == "PKG-001" else "text"   # PKG-002: package:CVE, PKG-003: a kernel
    return {"title": str(sig.get("title") or sig.get("rule")), "severity": str(sig.get("severity") or "info"),
            "evidence": [str(x) for x in sig.get("evidence") or []],
            "recommendation": [str(r) for r in sig.get("recommendation") or []],
            "subject": str(sig.get("subject") or ""),
            "entities": normalise_entities(kind, sig.get("entities") or [])}


def _package_findings(doc: dict[str, Any]) -> list[Finding]:
    """PKG-001..004 from one package check (A.2). Matching and scoring happened when
    the check ran (kratos.pkgvuln.record), so re-correlating the same result says
    exactly the same thing. PKG-001 carries the package as its subject -- one finding
    per package -- and its CVEs as entities, so a new CVE for an already-decided
    package reopens it. PKG-002 (no fix yet) is one finding per machine whose
    entities are package:CVE pairs."""
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for s in doc.get("signals") or []:
        if isinstance(s, dict) and str(s.get("rule", "")).startswith("PKG-"):
            by_rule.setdefault(s["rule"], []).append(s)
    out: list[Finding] = []
    for s in by_rule.get("PKG-001", []):
        out.append(Finding(id="PKG-001", **_pkg_kwargs(s)))
    for s in by_rule.get("PKG-002", []):
        out.append(Finding(id="PKG-002", **_pkg_kwargs(s)))
    for s in by_rule.get("PKG-003", []):
        out.append(Finding(id="PKG-003", **_pkg_kwargs(s)))
    for s in by_rule.get("PKG-004", []):
        out.append(Finding(id="PKG-004", **_pkg_kwargs(s)))
    return out


@dataclass(frozen=True)
class SnapshotSource:
    """One check that saves a judged snapshot the findings engine turns into findings
    (phase A audit: each feature used to add the same five hand-wired pieces here).

    `category`: the input category -- find_latest_inputs key, lifecycle covering input,
    collection check input. `folder`/`pattern`: where its files live under the data
    folder. `rule_prefix`: the rules it raises (``PERSIST-``). `load(path)`: the snapshot
    if it is recent enough, else None. `build(doc)`: its findings -- each Finding(id=...)
    a literal, in a module the lifecycle completeness test scans. `closes_findings(doc)`:
    whether this read is complete enough to say one of its findings is gone.
    `blind(doc)`: (rule, entity) -> why the read could not have seen it, or None.
    """
    category: str
    folder: str
    pattern: str
    rule_prefix: str
    load: Callable[[Path | None], dict[str, Any] | None]
    build: Callable[[dict[str, Any]], list[Finding]]
    closes_findings: Callable[[dict[str, Any]], bool]
    blind: Callable[[dict[str, Any]], Callable[[str, str], str | None] | None] | None = None


SNAPSHOT_SOURCES: dict[str, SnapshotSource] = {}


def register_snapshot_source(src: SnapshotSource) -> None:
    """Add (or replace) a snapshot source; its rules read its category."""
    SNAPSHOT_SOURCES[src.category] = src
    _FINDING_INPUTS[src.rule_prefix] = (src.category,)


def snapshot_sources() -> list[SnapshotSource]:
    """Every registered snapshot source, in registration order (findings order)."""
    return list(SNAPSHOT_SOURCES.values())


def _persistence_blind(doc: dict[str, Any]) -> Any:
    from kratos.persist.record import entity_blind
    return entity_blind(doc)


def _live_blind(doc: dict[str, Any]) -> Any:
    from kratos.live.record import entity_blind
    return entity_blind(doc)


register_snapshot_source(SnapshotSource(
    category="persistence", folder="persistence", pattern="persistence_*.json", rule_prefix="PERSIST-",
    load=lambda path: _load_recent_persistence(path), build=lambda doc: _persistence_findings(doc),
    # an unfinished read, or one that could not tell which files came from a package (A.1 §7)
    closes_findings=lambda doc: bool(doc.get("complete")) and bool((doc.get("ownership") or {}).get("source"))
    and not (doc.get("ownership") or {}).get("error"),
    blind=_persistence_blind))
register_snapshot_source(SnapshotSource(
    category="live_response", folder="live", pattern="live_response_*.json", rule_prefix="LIVE-",
    load=lambda path: _load_recent_live(path), build=lambda doc: _live_response_findings(doc),
    closes_findings=lambda doc: bool(doc.get("complete")), blind=_live_blind))
register_snapshot_source(SnapshotSource(
    category="packages", folder="packages", pattern="packages_*.json", rule_prefix="PKG-",
    load=lambda path: _load_recent_packages(path), build=lambda doc: _package_findings(doc),
    closes_findings=lambda doc: bool(doc.get("complete"))))


# C.1: SIGMA-* findings from the detection pass (kratos.detect), and DETECT-001, its
# note of what the rules could not check on the machine.
from kratos.detect import findings as _detect_findings  # noqa: E402

register_snapshot_source(SnapshotSource(
    category="detections", folder="detect/results", pattern="detections_*.json", rule_prefix="SIGMA-",
    load=_detect_findings.load_recent, build=_detect_findings.build,
    closes_findings=_detect_findings.closes_findings))
_FINDING_INPUTS["DETECT-"] = ("detections",)
_FINDING_INPUTS["KRATOS-"] = ("detections",)      # Kratos's own detection rules (kratos-linux pack)


def _staleness_warning(inputs: dict[str, Path | None], auto_discovered_keys: set[str]) -> str | None:
    """
    None if fewer than 2 auto-discovered inputs are present (nothing to
    compare), or if the spread between the oldest and newest auto-discovered
    input is within STALENESS_SPREAD_THRESHOLD_HOURS. Explicitly-pinned
    inputs (in `inputs` but not in `auto_discovered_keys`) are never
    considered here -- an explicit path is the caller's own informed choice,
    not something this warning second-guesses (see module docstring above).
    """
    mtimes: dict[str, float] = {}
    for key in auto_discovered_keys:
        path = inputs.get(key)
        if path is not None:
            mtimes[key] = path.stat().st_mtime

    if len(mtimes) < 2:
        return None

    newest_key = max(mtimes, key=lambda k: mtimes[k])
    oldest_key = min(mtimes, key=lambda k: mtimes[k])
    spread_hours = (mtimes[newest_key] - mtimes[oldest_key]) / 3600
    if spread_hours <= STALENESS_SPREAD_THRESHOLD_HOURS:
        return None

    # Rendered as absolute UTC instants (the spread itself is tz-independent,
    # since it's a difference of epoch mtimes) so the warning reads
    # consistently no matter which machine/timezone produced or reads it.
    newest_ts = epoch_to_utc_iso(mtimes[newest_key])
    oldest_ts = epoch_to_utc_iso(mtimes[oldest_key])
    return (
        f"Auto-discovered inputs span {spread_hours:.1f}h (> {STALENESS_SPREAD_THRESHOLD_HOURS}h "
        f"threshold): '{newest_key}' is from {newest_ts}, '{oldest_key}' is from {oldest_ts}. This "
        "correlation mixes fresher and staler data -- treat any finding that depends on the older "
        "input(s) as reflecting that input's collection time, not necessarily the current state."
    )


def _report_verdicts(data_dir: Path, finding_dicts: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """{(rule id, normalised subject): latest triage verdict dict} for the report's
    findings (B.1). Best-effort: a verdict lookup never breaks a report."""
    from kratos.lifecycle.keys import normalise_subject

    try:
        from kratos.triage import store as _ts
    except Exception:  # noqa: BLE001
        return {}
    keys = [str(f.get("finding_key") or "") for f in finding_dicts if f.get("finding_key")]
    try:
        stored = _ts.latest_verdicts(Path(data_dir), keys)
    except Exception:  # noqa: BLE001
        return {}
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for f in finding_dicts:
        vr = stored.get(str(f.get("finding_key") or ""))
        if vr is not None:
            out[(str(f.get("id") or ""), normalise_subject(f.get("subject") or ""))] = {**vr.verdict.as_dict(),
                                                                                           "at": vr.at}
    return out


# ---------------------------
# Report writing
# ---------------------------
def _paired_auth_stats(patterns_path: Path | None, stats_path: Path | None,
                       stats: dict[str, Any] | None) -> dict[str, Any] | None:
    """The auth_stats saved by the same read as `patterns_path` (auth_patterns_X.json
    pairs with auth_stats_X.json). The burst list and the stats can come from different
    reads (each kind is picked by recency on its own), so the window a burst count
    covers is taken from its own pair, never assumed from the other file."""
    if patterns_path is None:
        return None
    pair = patterns_path.with_name(patterns_path.name.replace("auth_patterns_", "auth_stats_", 1))
    if stats_path is not None and pair == stats_path:
        return stats or {}
    if not pair.exists():
        return {}
    try:
        return _read_json(pair)
    except (OSError, ValueError):
        return {}


def write_findings_report(
    data_dir: Path,
    nmap_parsed_file: Path | None = None,
    auth_stats_file: Path | None = None,
    auth_patterns_file: Path | None = None,
    system_context_file: Path | None = None,
    auth_trends_file: Path | None = None,
    file_integrity_file: Path | None = None,
    prefer_measured_since: float | None = None,
) -> tuple[Path, Path]:
    """
    Generate findings report. `prefer_measured_since`: see find_latest_inputs.

    Input resolution is PER-ARGUMENT, not all-or-nothing: for each of
    nmap_parsed_file, auth_stats_file, auth_patterns_file, system_context_file
    -- an explicitly-provided value is used EXACTLY as given and is never
    silently swapped for an auto-discovered file. Only arguments left as None
    are auto-discovered via find_latest_inputs(data_dir), independently of
    whether sibling arguments were also given. If an explicitly-provided path
    does not exist on disk, that specific input is recorded in the written
    report's "input_errors" (and left out of "missing_inputs"/the generated
    findings for that input) rather than silently falling back to a different
    file for that slot.

    auth_trends_file and file_integrity_file keep different semantics from
    the core four above: when all four core fields are given explicitly (the
    "transaction" pattern `kratos run` uses), an omitted auth_trends_file /
    file_integrity_file means "none for this report" -- not "please look one
    up" -- since `kratos run`'s legacy pipeline never generates either of
    these. When called with those four omitted (the plain `findings-generate`
    / agent-loop pattern), a None auth_trends_file / file_integrity_file IS
    auto-discovered like the others, preserving that existing behavior.
    """
    explicit = {
        "nmap_parsed": nmap_parsed_file,
        "auth_stats": auth_stats_file,
        "auth_patterns": auth_patterns_file,
        "system_context": system_context_file,
    }
    auto = find_latest_inputs(data_dir, prefer_measured_since=prefer_measured_since)

    inputs: dict[str, Path | None] = {}
    input_errors: dict[str, str] = {}
    auto_discovered_keys: set[str] = set()
    for key, explicit_value in explicit.items():
        if explicit_value is None:
            inputs[key] = auto.get(key)
            if inputs[key] is not None:
                auto_discovered_keys.add(key)
            continue
        path = Path(explicit_value)
        if path.exists():
            inputs[key] = path
        else:
            input_errors[key] = f"Explicit path does not exist: {path}"
            inputs[key] = None

    all_required_explicit = all(v is not None for v in explicit.values())

    def _resolve_optional(key: str, explicit_value: Path | None) -> None:
        if explicit_value is not None:
            path = Path(explicit_value)
            if path.exists():
                inputs[key] = path
            else:
                input_errors[key] = f"Explicit path does not exist: {path}"
                inputs[key] = None
        elif all_required_explicit:
            inputs[key] = None
        else:
            inputs[key] = auto.get(key)
            if inputs[key] is not None:
                auto_discovered_keys.add(key)

    _resolve_optional("auth_trends", auth_trends_file)
    _resolve_optional("file_integrity", file_integrity_file)

    missing = [k for k, v in inputs.items() if v is None and k not in input_errors]
    staleness_warning = _staleness_warning(inputs, auto_discovered_keys)
    # Optional and on-demand, so never "missing" and never part of the
    # cross-input staleness spread -- each is limited to a fresh snapshot of the
    # active target on its own, so it's considered even when the core inputs
    # were passed explicitly.
    privileged = _load_recent_privileged_snapshot(auto.get("privileged_accounts"))
    inputs["privileged_accounts"] = auto.get("privileged_accounts") if privileged else None
    vuln_scan, vuln_scan_path = _load_recent_vuln_scan(data_dir / "scans")
    inputs["vuln_scan"] = vuln_scan_path
    log_integrity = _load_recent_log_integrity(auto.get("log_integrity"))
    inputs["log_integrity"] = auto.get("log_integrity") if log_integrity else None
    snapshots: dict[str, dict[str, Any] | None] = {}
    for src in snapshot_sources():
        doc = src.load(auto.get(src.category))
        snapshots[src.category] = doc
        inputs[src.category] = auto.get(src.category) if doc else None
    live_doc = snapshots.get("live_response")      # the package cross-check reads these two by name
    packages_doc = snapshots.get("packages")
    package_fixed: dict[str, str] = {}
    package_doubts: dict[str, str] = {}
    if packages_doc and vuln_scan:
        try:
            from kratos.pkgvuln import crosscheck as _pkg_crosscheck
            from kratos.pkgvuln import inventory_store as _pkg_inventory

            scan_cves = {c for x in vuln_scan.get("findings") or [] if isinstance(x, dict)
                         and x.get("source") == "vulscan" for c in x.get("cve_ids") or [] if isinstance(c, str)}
            fixers: dict[str, set[str]] = {}
            package_fixed = _pkg_crosscheck.fixed_by_packages(data_dir, packages_doc, scan_cves, fixers=fixers)
            if package_fixed and live_doc and packages_doc.get("inventory_id"):
                package_doubts = _pkg_crosscheck.listener_doubts(
                    packages_doc, _pkg_inventory.get(data_dir, int(packages_doc["inventory_id"])), vuln_scan,
                    live_doc, fixers)
                for cve in package_doubts:
                    package_fixed.pop(cve, None)
        except Exception:  # noqa: BLE001 -- the cross-check only refines VULN-001; never lose the report
            import logging

            logging.getLogger(__name__).exception("package cross-check failed; VULN-001 left as matched")
    # We allow partial reports; still generate report but mark missing/errored inputs.
    nmap_parsed = _read_json(inputs["nmap_parsed"]) if inputs["nmap_parsed"] else None
    auth_stats = _read_json(inputs["auth_stats"]) if inputs["auth_stats"] else None
    auth_patterns = _read_json(inputs["auth_patterns"]) if inputs["auth_patterns"] else None
    system_context = _read_json(inputs["system_context"]) if inputs["system_context"] else None
    auth_trends = _read_json(inputs["auth_trends"]) if inputs["auth_trends"] else None
    file_integrity = _read_json(inputs["file_integrity"]) if inputs["file_integrity"] else None

    findings = generate_findings(
        nmap_parsed, auth_stats, auth_patterns, system_context, auth_trends, file_integrity, privileged,
        vuln_scan=vuln_scan,
        auth_patterns_window=_paired_auth_stats(inputs["auth_patterns"], inputs["auth_stats"], auth_stats),
        log_integrity=log_integrity,
        snapshots=snapshots,
        package_fixed_cves=package_fixed,
        package_doubted_cves=package_doubts,
    )
    _stamp_collected_at(findings, inputs)
    from kratos.kratos_config import get_active_target

    report_target = _host_key(get_active_target()) or None
    finding_dicts = [finding_dict(f) for f in findings]
    lifecycle_summary, lifecycle_error = None, None
    try:
        finding_dicts, lifecycle_summary = _apply_lifecycle(
            finding_dicts, data_dir=data_dir, target=report_target or "unknown", inputs=inputs,
            auth_stats=auth_stats, snapshots=snapshots,
            patterns_stats=_paired_auth_stats(inputs["auth_patterns"], inputs["auth_stats"], auth_stats))
    except Exception as e:  # noqa: BLE001 -- a lifecycle failure must never lose the report
        import logging

        logging.getLogger(__name__).exception("finding lifecycle failed; writing the report without it")
        finding_dicts = [finding_dict(f) for f in findings]
        lifecycle_error = f"{type(e).__name__}: {e}"

    # Environment detection
    env_label = "linux"
    if system_context:
        rel = (system_context.get("os") or {}).get("release", "")
        if "WSL" in rel or "microsoft" in rel.lower():
            env_label = "wsl2"

    report_obj = {
        # Absolute UTC instant -- a findings report is a stored, later-read
        # artifact whose "when" must survive being read on a different
        # machine / in a different timezone than the one that produced it.
        "generated_at": utc_now_iso(),
        "tool": {"name": "kratos", "version": KRATOS_VERSION},
        "environment": {"label": env_label},
        # Explicit, report-level flag for which host system_context describes --
        # a findings report must never present local-Kratos-host state as if
        # it were the monitored target's state without this being visible.
        "system_context_scope": (system_context or {}).get("scope") if system_context else None,
        "inputs": {k: (v.name if v else None) for k, v in inputs.items()},
        "missing_inputs": missing,
        "input_errors": input_errors,
        "staleness_warning": staleness_warning,
        "target": report_target,
        "findings": finding_dicts,
    }
    if lifecycle_summary is not None:
        report_obj["lifecycle"] = lifecycle_summary
    else:
        report_obj["lifecycle_error"] = lifecycle_error

    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_json = reports_dir / f"findings_{ts}.json"
    out_md = reports_dir / f"findings_{ts}.md"

    out_json.write_text(json.dumps(report_obj, indent=2), encoding="utf-8")

    # Markdown report (thesis/demo friendly)
    md_lines: list[str] = []
    md_lines.append(f"# Kratos Findings Report\n")
    md_lines.append(f"- Generated at: {report_obj['generated_at']}")
    md_lines.append(f"- Inputs:")
    for k, v in report_obj["inputs"].items():
        md_lines.append(f"  - {k}: {v}")
    if missing:
        md_lines.append(f"\n> Note: Missing inputs: {', '.join(missing)}\n")
    if staleness_warning:
        md_lines.append(f"\n> **Staleness warning**: {staleness_warning}\n")

    if lifecycle_summary is not None:
        md_lines.extend(_lifecycle_markdown(finding_dicts, lifecycle_summary))
    elif lifecycle_error:
        md_lines.append(f"\n> Finding history unavailable for this report: {lifecycle_error}\n")

    md_lines.append("\n## Findings\n")
    if not findings:
        md_lines.append("_No findings generated._")
    else:
        verdicts = _report_verdicts(data_dir, finding_dicts)
        from kratos.lifecycle.keys import normalise_subject as _ns_md
        for f in findings:
            md_lines.append(f"### [{f.severity.upper()}] {f.id} — {f.title}\n")
            if f.attack:
                from kratos.attack import format_label
                md_lines.append("**ATT&CK**: " + "; ".join(f"[{format_label(a)}]({a.get('url')})" for a in f.attack)
                                + "\n")
            if f.detection_rule:   # C.1: the Sigma rule's author goes with its finding (DRL 1.1)
                dr = f.detection_rule
                if dr.get("sigma_id"):
                    md_lines.append(f"**Rule**: {dr.get('title')} by {dr.get('author')} — SigmaHQ "
                                    f"[{dr.get('sigma_id')}]({dr.get('source_url')}), {dr.get('license') or 'DRL-1.1'}\n")
                else:
                    md_lines.append(f"**Rule**: {dr.get('title')} — Kratos's own detection rule\n")
            vr = verdicts.get((f.id, _ns_md(getattr(f, "subject", "") or "")))
            if vr is not None:   # B.1: the latest triage verdict on record for this finding
                from kratos.triage.verdict import aged_tag
                md_lines.append(f"**Verdict** (Kratos re-check): {aged_tag(vr)} — {vr['sentence']}\n")
            md_lines.append("**Evidence**")
            for e in f.evidence:
                md_lines.append(f"- {e}")
            md_lines.append("\n**Recommendations**")
            for r in f.recommendation:
                md_lines.append(f"- {r}")
            
            # Add playbooks section if present
            if f.playbooks:
                md_lines.append("\n**Playbooks (verification steps)**")
                for pb in f.playbooks:
                    md_lines.append(f"- **{pb['title']}**")
                    for cmd in pb.get('commands', []):
                        md_lines.append(f"  - `{cmd}`")
                    for note in pb.get('notes', []):
                        md_lines.append(f"  - {note}")
            
            md_lines.append("")

    out_md.write_text("\n".join(md_lines).strip() + "\n", encoding="utf-8")
    if lifecycle_summary is not None:
        try:
            from kratos.lifecycle import migrate as _lc_migrate

            _lc_migrate.record_written_report(data_dir, out_json, report_target)
        except Exception:  # noqa: BLE001 -- bookkeeping only; the import skips lifecycle reports anyway
            pass

    return out_json, out_md


def _apply_lifecycle(finding_dicts: list[dict[str, Any]], *, data_dir: Path, target: str,
                     inputs: dict[str, Path | None], auth_stats: dict[str, Any] | None,
                     patterns_stats: dict[str, Any] | None,
                     snapshots: dict[str, dict[str, Any] | None] | None = None,
                     ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The lifecycle layer (kratos.lifecycle) over this report's findings."""
    from kratos import run_context
    from kratos.lifecycle import apply as _lc_apply, coverage as _lc_coverage, migrate as _lc_migrate

    _lc_migrate.ensure_imported(data_dir)
    incomplete = _lc_coverage.incomplete_auth_inputs({"auth_stats": auth_stats, "auth_patterns": patterns_stats})
    # A snapshot read that could not see everything it covers (did not finish, could not
    # tell which files came from a package, no vulnerability data) cannot say one of its
    # findings is gone; and a finding about something in its blind spots stays open
    # (an SSH login can't open /root/.ssh or read another user's processes).
    blind: dict[str, Any] = {}
    for src in snapshot_sources():
        doc = (snapshots or {}).get(src.category)
        if doc is None:
            continue
        if not src.closes_findings(doc):
            incomplete = set(incomplete) | {src.category}
        if src.blind is not None and (fn := src.blind(doc)) is not None:
            blind[src.category] = fn
    run = run_context.current()
    cov = _lc_coverage.for_report(inputs, target=target, run=run, incomplete=incomplete, blind=blind)
    return _lc_apply.apply_run(finding_dicts, target=target, coverage=cov, run=run, data_dir=data_dir)


def _lifecycle_markdown(findings: list[dict[str, Any]], summary: dict[str, Any]) -> list[str]:
    """New / Still open / Fixed since last run / hidden count, ahead of the full list."""
    from kratos.lifecycle import apply as _lc_apply, keys as _lc_keys

    by_key = {f.get("finding_key"): f for f in findings if f.get("finding_key")}

    def line(key: str) -> str:
        f = by_key.get(key)
        if f is None:
            return f"- `{_lc_keys.short(key)}`"
        change = f" ({f['change']})" if f.get("change") in ("reopened", "recurred") else ""
        return f"- [{str(f.get('severity', '')).upper()}] {f.get('id')} — {f.get('title')}{change} `{_lc_keys.short(key)}`"

    out = ["", f"**{_lc_apply.footer_line(summary)}**", ""]
    out.append("## New")
    out.extend([line(k) for k in summary["new"]] or ["_Nothing new._"])
    out.append("\n## Still open")
    out.extend([line(k) for k in summary["still_open"]] or ["_None._"])
    out.append("\n## Fixed since last run")
    out.extend([line(k) for k in summary["fixed"]] or ["_None._"])
    if summary.get("not_rechecked"):
        out.append(f"\n_Not rechecked in this run: {len(summary['not_rechecked'])} earlier finding(s)._")
    if summary.get("expired_this_run"):
        out.append(f"\n_Decisions that expired this run: {len(summary['expired_this_run'])}._")
    out.append(f"\nHidden by your decisions: {summary.get('hidden_total', 0)} "
               "(see `kratos findings list --state decided`)")
    return out
