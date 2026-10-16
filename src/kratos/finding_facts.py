"""What a serious finding is, in words and facts Kratos can stand behind.

One place for three users that must agree (phase A audit):

* the model's first-turn digest (`model_line`) -- only Kratos-written words and values
  that were validated on the way in (IP addresses, process ids, CVE ids, package names):
  never a path, command line or account name written on the machine;
* the answer's findings block, written by Kratos, not the model (`answer_block`) --
  every open HIGH/CRITICAL finding with the fact that matters, shown to the person on
  every surface (terminal, TUI, MCP, report, notification);
* Guard 12 in the agent loop (`left_out`) -- which serious findings, or which of their
  facts, the model's analysis leaves out.
"""
from __future__ import annotations

import ipaddress
import posixpath
import re
from typing import Any, Iterable

SERIOUS = ("critical", "high")
DECIDED_STATES = frozenset({"risk_accepted", "false_positive", "out_of_scope"})
MALICIOUS_MARK = "KNOWN-MALICIOUS"
BLOCK_MAX = 6

# Fixed descriptions for the rules whose titles name things from the machine (accounts,
# paths) -- the model reads these instead of the title. Kratos's words only.
RULE_TEXT: dict[str, str] = {
    "PRIV-001": "an account was recently given privileged (sudo/admin) access",
    "PRIV-002": "a non-root account has UID 0 (full root powers)",
    "PRIV-003": "an account became privileged since Kratos last checked",
    "PRIV-004": "the accounts that hold privileged access (an inventory)",
    "PERSIST-001": "a place that starts programs (boot, login, schedule) changed since Kratos first looked",
    "PERSIST-002": "a place that starts programs holds something worth a look",
    "PERSIST-003": "a setuid/setgid program that no package installed",
    "PERSIST-004": "every program is made to load an extra library (/etc/ld.so.preload)",
    "PERSIST-005": "a kernel module from outside the system's packages is loaded",
    "PERSIST-006": "a new or unusual SSH key can log in",
    "PERSIST-007": "a file that starts programs differs from what its package installed",
    "PERSIST-008": "a login (PAM) rule points at software no package installed",
    "PERSIST-009": "what the persistence check could not read",
    "LIVE-001": "a running process whose program file was deleted from disk",
    "LIVE-002": "a process running from memory or from a deleted temporary file",
    "LIVE-003": "a process made to load an extra library (LD_PRELOAD/LD_AUDIT)",
    "LIVE-004": "an executable file in a world-writable folder (/tmp, /dev/shm, /var/tmp)",
    "LIVE-005": "a network listener run by a suspicious process",
    "LIVE-006": "a shell or interpreter started by a network service",
    "LIVE-007": "what the live-response check could not read",
    "PKG-001": "an installed package with fixable known vulnerabilities",
    "PKG-002": "installed packages with known vulnerabilities and no fix yet",
    "PKG-003": "a newer kernel is installed than the one running (reboot pending)",
    "PKG-004": "what the package check could not cover",
}

_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,99}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_WORD_RE = re.compile(r"[a-z][a-z-]{3,}")
_STOPWORDS = frozenset({"with", "from", "that", "this", "were", "have", "been", "into", "than", "more",
                        "some", "only", "they", "there", "their", "which", "while"})


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text))
    except ValueError:
        return False
    return True


def serious(findings: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Open (not decided by a person) HIGH/CRITICAL findings, critical first."""
    out = [f for f in findings or [] if isinstance(f, dict)
           and str(f.get("severity") or "").lower() in SERIOUS
           and str(f.get("state") or "") not in DECIDED_STATES]
    return sorted(out, key=lambda f: (0 if str(f.get("severity")).lower() == "critical" else 1, str(f.get("id"))))


def describe(f: dict[str, Any]) -> str:
    """The rule in Kratos's words (RULE_TEXT), else the finding's own title."""
    return RULE_TEXT.get(str(f.get("id") or ""), str(f.get("title") or ""))


def _process(entity: str) -> tuple[str, str] | None:
    """`exe|pid|start` -> (program, pid)."""
    parts = entity.rsplit("|", 2)
    if len(parts) == 3 and parts[1].isdigit():
        return parts[0].removesuffix(" (deleted)"), parts[1]
    return None


def ips(f: dict[str, Any]) -> list[str]:
    return [e for e in (str(x) for x in f.get("entities") or []) if is_ip(e)][:3]


def known_malicious(f: dict[str, Any]) -> bool:
    return any(MALICIOUS_MARK in str(ev) for ev in f.get("evidence") or [])


def safe_facts(f: dict[str, Any]) -> list[str]:
    """Validated facts only -- for the model's digest."""
    facts = [f"source {ip}" + (" (known-malicious in the threat-intel cache)" if known_malicious(f) else "")
             for ip in ips(f)]
    pids = [p[1] for p in (_process(str(e)) for e in f.get("entities") or []) if p]
    if pids:
        facts.append("pid " + ", ".join(pids[:3]))
    subject = str(f.get("subject") or "")
    if subject and _PACKAGE_RE.match(subject):
        facts.append(f"package {subject}")
    cves = [e for e in (str(x) for x in f.get("entities") or []) if _CVE_RE.match(e)]
    if cves:
        facts.append(", ".join(cves[:2]) + (f" (+{len(cves) - 2})" if len(cves) > 2 else ""))
    return facts


def _display_entity(entity: str) -> tuple[str, list[str]]:
    """(how the person sees an entity, the words that count as the answer naming it)."""
    e = str(entity)
    proc = _process(e)
    if proc:
        exe, pid = proc
        base = posixpath.basename(exe) if exe.startswith("/") else exe
        return f"{exe} (pid {pid})", [t for t in (base, pid) if len(t) >= 2]
    if "#" in e and e.startswith("/"):
        path = e.split("#", 1)[0]
        return path, [posixpath.basename(path) or path]
    head, sep, _rest = e.partition(":")
    if sep and not head.upper().startswith("CVE") and not is_ip(e):
        return e, [head]
    return e, [e]


def _paraphrased(answer_lower: str, f: dict[str, Any]) -> bool:
    """Most (60%) of the title's or the rule description's content words appear."""
    for text in (str(f.get("title") or ""), RULE_TEXT.get(str(f.get("id") or ""), "")):
        words = {w for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS}
        if words and sum(1 for w in words if w in answer_lower) / len(words) >= 0.6:
            return True
    return False


def _named(answer: str, f: dict[str, Any]) -> bool:
    ids = [str(f.get("id") or "")] + [str(x) for x in f.get("also_matched") or []]
    if any(i and re.search(rf"\b{re.escape(i)}\b", answer) for i in ids):
        return True
    title = str(f.get("title") or "").strip().lower()
    return bool(title) and title in answer.lower()


def missing_from(answer: str, f: dict[str, Any]) -> list[str]:
    """What of serious finding `f` the answer leaves out: its attacker addresses, the
    known-malicious match, or -- when there is no address -- the finding itself (its
    id, title, a paraphrase of it, or its program/file/package)."""
    low = (answer or "").lower()
    missing = [f"source {ip}" for ip in ips(f) if ip.lower() not in low]
    if known_malicious(f) and "malicious" not in low:
        missing.append("known-malicious in the threat-intel cache")
    if not ips(f):
        others = [str(e) for e in f.get("entities") or [] if not is_ip(str(e))]
        subject = str(f.get("subject") or "")
        tokens = [t for e in others[:5] for t in _display_entity(e)[1]] + ([subject] if subject else [])
        if not (_named(answer or "", f) or _paraphrased(low, f) or any(t.lower() in low for t in tokens)):
            missing.append("not discussed")
    return missing


def left_out(answer: str, findings: Iterable[dict[str, Any]] | None) -> list[tuple[dict[str, Any], list[str]]]:
    return [(f, m) for f in serious(findings) if (m := missing_from(answer, f))]


def model_line(f: dict[str, Any]) -> str:
    """One digest line: `CORR-SSH-001 (high): what it is -- validated facts`."""
    facts = safe_facts(f)
    return f"{f.get('id')} ({str(f.get('severity')).lower()}): {describe(f)}" + (f" -- {'; '.join(facts)}" if facts else "")


def answer_block(findings: Iterable[dict[str, Any]] | None, analysis: str) -> str:
    """The findings block Kratos puts at the top of an answer ('' when nothing serious
    is open). Every open HIGH/CRITICAL finding with its facts; one the analysis below
    doesn't discuss is marked so."""
    from kratos import untrusted

    items = serious(findings)
    if not items:
        return ""
    lines = ["Kratos found (checked by Kratos itself -- not written by the model):"]
    for f in items[:BLOCK_MAX]:
        facts = [ip_fact for ip_fact in (f"source {ip}" + (", known-malicious in the threat-intel cache"
                                                          if known_malicious(f) else "") for ip in ips(f))]
        if not ips(f):
            shown = [_display_entity(str(e))[0] for e in (f.get("entities") or [])[:2]]
            subject = str(f.get("subject") or "")
            facts += shown or ([f"package {subject}"] if subject else [])
        detail = "; ".join(untrusted.for_display(x)[:120] for x in facts)
        missing = missing_from(analysis, f)
        mark = " (not discussed below)" if "not discussed" in missing else \
            (" (" + ", ".join(m for m in missing) + " -- not in the analysis below)" if missing else "")
        title = untrusted.for_display(str(f.get("title") or describe(f)))[:110]
        lines.append(f"  - {str(f.get('severity')).upper()} {f.get('id')} {title}"
                     + (f" -- {detail}" if detail else "") + mark)
    if len(items) > BLOCK_MAX:
        lines.append(f"  - and {len(items) - BLOCK_MAX} more serious finding(s): /findings lists them all")
    return "\n".join(lines) + "\n\n"
