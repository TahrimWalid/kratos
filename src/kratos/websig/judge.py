"""Web-server signals, judged on Kratos from what it already collected (no read of its own).

WEB-001 -- a web server's worker processes keep crashing. A crash burst of PHP or web
server workers (the kernel's "segfault at ..." / "general protection fault" lines, and
Apache's "child pid N exit signal Segmentation fault") is what memory-corruption bugs
look like while someone probes them: an attacker's crafted requests crash workers until
one lands. A lone crash is usually a buggy extension, so only a burst counts.

WEB-002 -- PHP is served to the network, but Kratos can't check it for known
vulnerabilities: it comes from outside the distribution (a PPA such as Ondřej Surý's, a
vendor repository, a hand-installed package), so the distribution's advisories don't
cover it -- and, worse, its upstream branch may be past its security support. PHP from
the distribution itself is checked by the package check (PKG-*); for it this says
nothing beyond a digest line.

Pure functions: inputs are plain dicts, output is signal dicts the findings engine
turns into findings.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterable

BURST_WINDOW_SECONDS = 600          # crashes this close together are one burst
BURST_MIN = 3                        # a burst has at least this many crashes
BURST_HIGH = 10                      # ... this many: high
MAX_BURSTS_SHOWN = 5

# Worker program -> the family a burst is counted for. The kernel's process name is
# at most 15 characters ("php-fpm8.3", "apache2", "httpd").
_FAMILIES = (
    ("php", re.compile(r"^(php(-fpm|-cgi)?[0-9.]*|php[0-9.]+(-fpm|-cgi)|lsphp[0-9.]*)$")),
    ("apache", re.compile(r"^(apache2?|httpd)$")),
    ("nginx", re.compile(r"^nginx$")),
    ("lighttpd", re.compile(r"^lighttpd$")),
)
FAMILY_WORDS = {"php": "PHP", "apache": "Apache", "nginx": "nginx", "lighttpd": "lighttpd"}

# Programs that serve web pages, by executable name.
_WEB_SERVERS = re.compile(r"^(apache2|httpd|nginx|lighttpd|caddy|lshttpd|litespeed|openlitespeed|"
                          r"php-fpm[0-9.]*|php[0-9.]*-fpm|php[0-9.]*|lsphp[0-9.]*|frankenphp)$")
# Ports a web server answers on, for a listener whose program Kratos couldn't see.
WEB_PORTS = (80, 443, 8000, 8080, 8443, 8888)

# PHP's own packages, by name: php8.3, php8.3-fpm, php-fpm, libapache2-mod-php8.1, php81-php-fpm ...
_PHP_PACKAGE = re.compile(r"^(php([0-9.]+)?(-(fpm|cgi|cli|common))?|libapache2-mod-php([0-9.]+)?|"
                          r"php[0-9]{2}(-php)?(-(fpm|cli|common))?|php[0-9]{2})$")
_BRANCH = re.compile(r"^(?:\d+:)?(\d+)\.(\d+)(?:\.(\d+))?")

# PHP's upstream security support, by branch (php.net/supported-versions, eol.php). A
# branch not listed has no known end date: nothing is said about it.
PHP_SECURITY_END = {
    "5.6": date(2018, 12, 31), "7.0": date(2019, 1, 10), "7.1": date(2019, 12, 1), "7.2": date(2020, 11, 30),
    "7.3": date(2021, 12, 6), "7.4": date(2022, 11, 28), "8.0": date(2023, 11, 26), "8.1": date(2025, 12, 31),
    "8.2": date(2026, 12, 31), "8.3": date(2027, 12, 31), "8.4": date(2028, 12, 31), "8.5": date(2029, 12, 31),
}


def family_of(name: str | None, provider: str | None = None) -> str | None:
    n = (name or "").strip()
    for family, rx in _FAMILIES:
        if rx.match(n):
            return family
    if provider == "apache":             # Apache's own error log names no program
        return "apache"
    return None


@dataclass(frozen=True)
class Crash:
    ts: float
    name: str
    pid: int | None
    provider: str
    message: str = ""


def bursts(crashes: Iterable[Crash]) -> dict[str, list[list[Crash]]]:
    """{family: [burst, ...]}: runs of worker crashes no more than BURST_WINDOW_SECONDS
    apart, with at least BURST_MIN crashes. The same crash seen twice (the kernel line
    and Apache's own line for one pid) counts once."""
    by_family: dict[str, list[Crash]] = {}
    seen: set[tuple[str, int, int]] = set()
    for c in sorted(crashes, key=lambda c: c.ts):
        family = family_of(c.name, c.provider)
        if family is None:
            continue
        if c.pid is not None:
            key = (family, c.pid, int(c.ts) // 5)
            if key in seen:
                continue
            seen.add(key)
        by_family.setdefault(family, []).append(c)
    out: dict[str, list[list[Crash]]] = {}
    for family, items in by_family.items():
        runs: list[list[Crash]] = []
        for c in items:
            if runs and c.ts - runs[-1][-1].ts <= BURST_WINDOW_SECONDS:
                runs[-1].append(c)
            else:
                runs.append([c])
        kept = [r for r in runs if len(r) >= BURST_MIN]
        if kept:
            out[family] = kept
    return out


def _hhmm(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def burst_signals(found: dict[str, list[list[Crash]]], *, target: str, source_note: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for family, runs in sorted(found.items()):
        word = FAMILY_WORDS[family]
        biggest = max(len(r) for r in runs)
        total = sum(len(r) for r in runs)
        names = sorted({c.name for r in runs for c in r if c.name})
        evidence = []
        for r in sorted(runs, key=lambda r: r[0].ts, reverse=True)[:MAX_BURSTS_SHOWN]:
            pids = sorted({c.pid for c in r if c.pid is not None})
            shown = ", ".join(str(p) for p in pids[:8]) + (f" (+{len(pids) - 8} more)" if len(pids) > 8 else "")
            evidence.append(f"{len(r)} crashes between {_hhmm(r[0].ts)} and {_hhmm(r[-1].ts)}"
                            + (f", worker pids {shown}" if shown else ""))
        if len(runs) > MAX_BURSTS_SHOWN:
            evidence.append(f"... and {len(runs) - MAX_BURSTS_SHOWN} earlier burst(s)")
        sample = next((c.message for r in runs for c in reversed(r) if c.message), "")
        if sample:
            evidence.append(f"One of them: {sample[:200]}")
        evidence.append(source_note)
        out.append({
            "rule": "WEB-001", "severity": "high" if biggest >= BURST_HIGH else "medium", "subject": family,
            "title": f"{word} workers on {target} crashed in bursts ({total} crashes)",
            "entities": [f"{family}@{datetime.fromtimestamp(r[0].ts, timezone.utc).strftime('%Y-%m-%dT%H:%M')}"
                         for r in runs],
            "programs": names, "evidence": evidence,
            "recommendation": [
                "Look at the web server's access log for the requests just before each burst (same minutes): "
                "repeated crashes while one client sends unusual requests is how attacks on memory-corruption "
                "bugs in PHP or the web server look.",
                f"Update {word} (and its modules/extensions) to a version with current security fixes.",
                "Check for new files in the web root and new programs started by the web server's user around "
                "those times (Kratos's persistence and running-process checks look at both).",
            ]})
    return out


# ------------------------------------------------------------------ PHP exposure (WEB-002)
def _loopback(address: str | None) -> bool | None:
    if not address:
        return None
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def exposed_web(listeners: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Listeners that answer the network and serve web pages: a known web server on a
    non-loopback address, or a program Kratos couldn't see on a common web port."""
    out = []
    for item in listeners or []:
        if not isinstance(item, dict) or not isinstance(item.get("port"), int):
            continue
        if str(item.get("proto") or "") != "tcp" or _loopback(item.get("address")) is not False:
            continue
        exe = str(item.get("exe") or "")
        prog = exe.rsplit("/", 1)[-1]
        if item.get("seen") and _WEB_SERVERS.match(prog):
            out.append({"port": item["port"], "program": prog})
        elif not item.get("seen") and item["port"] in WEB_PORTS:
            out.append({"port": item["port"], "program": None})
    return sorted(out, key=lambda x: x["port"])


def php_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for p in packages or []:
        name = str(p.get("name") or "")
        if not _PHP_PACKAGE.match(name):
            continue
        m = _BRANCH.match(str(p.get("version") or ""))
        out.append({"name": name, "version": str(p.get("version") or ""),
                    "branch": f"{m.group(1)}.{m.group(2)}" if m else None})
    return out


def exposure_signal(*, target: str, listeners: list[dict[str, Any]] | None, packages: list[dict[str, Any]] | None,
                    outside: dict[str, dict[str, Any]], origins_checked: bool, distro: str,
                    today: date) -> tuple[dict[str, Any] | None, str | None]:
    """(WEB-002 signal or None, a digest line or None). `outside`: name -> {origin,
    kind} for packages from outside the distribution (kratos.pkgvuln.origin)."""
    if listeners is None or packages is None:
        return None, None
    web = exposed_web(listeners)
    php = php_packages(packages)
    if not web or not php:
        return None, None
    ports = ", ".join(str(w["port"]) for w in web)
    servers = sorted({w["program"] for w in web if w["program"]})
    serving = f"{', '.join(servers) or 'a web server'} on port(s) {ports}"
    unchecked = [p for p in php if p["name"] in outside]
    branches = sorted({p["branch"] for p in php if p["branch"]})
    if not unchecked:
        if not origins_checked:
            return None, (f"PHP ({', '.join(branches) or 'installed'}) is served to the network by {serving}; "
                          "where it came from couldn't be told, so it was matched as the distribution's")
        return None, (f"PHP ({', '.join(branches) or 'installed'}, the distribution's own, checked against its "
                      f"advisories) is served to the network by {serving}")
    origins = sorted({str(outside[p["name"]].get("origin") or "") for p in unchecked} - {""})
    ub = sorted({p["branch"] for p in unchecked if p["branch"]})
    ended = [(b, PHP_SECURITY_END[b]) for b in ub if b in PHP_SECURITY_END and PHP_SECURITY_END[b] < today]
    evidence = [
        f"A web server answers the network: {serving}.",
        f"PHP {', '.join(ub) or ''} comes from outside {distro or 'the distribution'} "
        f"({'; '.join(origins) or 'an unknown repository'}): {', '.join(p['name'] + ' ' + p['version'] for p in unchecked[:6])}"
        + (f" (+{len(unchecked) - 6} more)" if len(unchecked) > 6 else "") + ".",
        f"{distro or 'The distribution'}'s security advisories don't cover these packages, so Kratos's package "
        "check could not tell whether this PHP has known vulnerabilities.",
    ]
    for b, end in ended:
        evidence.append(f"PHP {b} stopped getting security fixes from the PHP project on {end.isoformat()}.")
    recommendation = [
        "Keep this PHP updated from the repository it came from, and follow that repository's and php.net's "
        "security announcements -- nobody else is tracking its vulnerabilities for you.",
    ]
    if ended:
        recommendation.insert(0, f"Move to a PHP branch that still gets security fixes (see "
                                 f"https://www.php.net/supported-versions.php); PHP {', '.join(b for b, _ in ended)} "
                                 "no longer does.")
    signal = {
        "rule": "WEB-002", "severity": "medium" if ended else "low", "subject": "php",
        "title": (f"PHP served to the network on {target} is not covered by the package check"
                  + (f" and PHP {', '.join(b for b, _ in ended)} is past its security support" if ended else "")),
        "entities": [f"php{b}" for b in ub] or ["php"], "evidence": evidence, "recommendation": recommendation,
        "ports": [w["port"] for w in web],
    }
    line = (f"PHP {', '.join(ub)} from outside the distribution (not checked) is served to the network by {serving}"
            + (f"; PHP {', '.join(b for b, _ in ended)} is past its security support" if ended else ""))
    return signal, line
