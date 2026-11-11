"""HASH-001 / HASH-002 / HASH-003 from one reputation check (E.4 §3.7).

New findings come only from strong evidence:

- HASH-001 -- a file whose SHA-256 is in the MalwareBazaar set is on the machine
  (high) or running (critical). One finding per path; the entity is
  `path#sha256[:12]`, so a replaced file is a new entity.
- HASH-002 -- an `unknown` program or script (ELF or #!) in a place Kratos already
  watches that is packed (a closed marker list) or has high byte entropy (medium,
  "worth a look"). Never for a file a package owns, nor a known-good one.
- HASH-003 -- a run note: how many candidates were not checked and why, with the fix.

Everything else a reputation says is an annotation on the findings that already exist
(kratos.hashdb.annotate), and never changes their severity.

Paths, owners and MalwareBazaar's signature name come from the machine or a third party:
they go in evidence lines only (masked), never in a title.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from kratos.events import redact
from kratos.hashdb import reputation as R

MAX_EVIDENCE = 40


def _m(text: Any) -> str:
    out, _ = redact.mask(str(text or ""))
    return out


def entity(path: str, sha256: str) -> str:
    return f"{path}#{sha256[:12]}"


def _file_lines(c: dict[str, Any], fact: dict[str, Any], rep: R.Reputation) -> list[str]:
    lines = [f"  file: {_m(c.get('image_of') or c['path'])}" + (f" (running image read through {c['path']})"
                                                                 if c.get("image_of") else "")]
    if fact.get("status") == "ok":
        lines.append(f"  size {fact.get('size')} bytes, mode {fact.get('mode')}, owner uid {fact.get('uid')}")
        lines.append(f"  sha256 {fact.get('sha256')}")
    elif c.get("sha256"):
        lines.append(f"  sha256 {c['sha256']} (as the earlier read saw it)")
    if c.get("uses"):
        lines.append("  how it is used: " + _m("; ".join(c["uses"])[:300]))
    if rep.package:
        lines.append(f"  owned by package: {_m(rep.package)}")
    if c.get("changed_since_snapshot"):
        lines.append("  changed since Kratos last saw it (the hash differs from the earlier read)")
    return lines


def judge(chosen: list[dict[str, Any]], facts: dict[int, dict[str, Any]], reps: list[R.Reputation],
          *, over_cap: int, target: str, via: str | None,
          datasets_note: str) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for i, (c, rep) in enumerate(zip(chosen, reps)):
        fact = facts.get(i) or {}
        sha = fact.get("sha256") or c.get("sha256") or ""
        if rep.verdict == "known_bad":
            running = bool(c.get("running"))
            hit = rep.known_bad or {}
            ev = _file_lines(c, fact, rep)
            ev.append("  MalwareBazaar lists this exact file (SHA-256 match in the offline set" +
                      (f", fetched {rep.sources[0].get('date')}" if rep.sources and rep.sources[0].get("date") else "")
                      + ")")
            if hit.get("first_seen"):
                ev.append(f"  first seen by MalwareBazaar: {_m(hit['first_seen'])[:40]}")
            if hit.get("signature"):
                ev.append(f"  MalwareBazaar's family name for it (third-party data): {_m(hit['signature'])[:120]!r}")
            if running:
                ev.append(f"  running now: pid {', '.join(str(p) for p in c['running'][:10])}")
            if rep.note:
                ev.append("  " + _m(rep.note))
            rec = ["Treat the machine as possibly compromised: find how the file arrived (its time stamp, the "
                   "logins and downloads around then) before removing it.",
                   "Keep a copy of the file (for analysis) somewhere it can't run, then remove it and anything that "
                   "starts it."]
            if running:
                rec.insert(1, "Stop the process (Kratos never does this itself), after noting its network "
                              "connections and open files.")
            if rep.package:
                rec.append(f"The file belongs to an installed package: reinstall the package from the distribution "
                           f"and check where it came from (the package itself may be compromised).")
            signals.append({"rule": "HASH-001", "severity": "critical" if running else "high",
                            "title": ("A program MalwareBazaar lists as malware is running" if running else
                                      "A file MalwareBazaar lists as malware is on the machine"),
                            "subject": c.get("image_of") or c["path"], "evidence": ev[:MAX_EVIDENCE],
                            "recommendation": rec, "entities": [entity(c.get("image_of") or c["path"], sha)]})
        elif (rep.verdict == "unknown" and not rep.package and fact.get("status") == "ok"
              and fact.get("type") in ("elf32", "elf64", "script") and (rep.packed or rep.high_entropy)):
            why = []
            if rep.packed:
                why.append(f"packed ({', '.join(fact.get('packers') or [])} marker in its first 64 KiB)")
            if rep.high_entropy:
                why.append(f"high byte entropy ({fact.get('entropy'):.2f} bits per byte over its first MiB)")
            ev = _file_lines(c, fact, rep) + ["  why it stands out: " + "; ".join(why),
                                              ("  reputation: unknown " + (rep.note or "")).rstrip()]
            signals.append({"rule": "HASH-002", "severity": "medium",
                            "title": "An unknown program that is packed or encrypted, in a place Kratos watches",
                            "subject": c.get("image_of") or c["path"], "evidence": ev[:MAX_EVIDENCE],
                            "recommendation": [
                                "Find out what the program is and who put it there; packers are used to hide "
                                "malware, but some legitimate tools ship packed.",
                                "If nobody knows it, keep a copy where it can't run and look it up "
                                "(`kratos hash lookup <sha256> --online` sends only that one hash, when you ask)."],
                            "entities": [entity(c.get("image_of") or c["path"], fact.get("sha256") or "")]})
    reasons = Counter(rep.reason or "read_failed" for rep in reps if rep.verdict == "not_checked")
    if over_cap:
        reasons["over_cap"] += over_cap
    if reasons or datasets_note:
        lines = [f"From the file-reputation check of {target}" + (f" (read {'through the sub-agent' if via == 'subagent' else 'over SSH'})" if via else "")]
        for key, n in reasons.most_common():
            what, fix = R.REASONS.get(key, (key, ""))
            lines.append(f"  {n} file(s) not checked: {what}" + (f" -- {fix}" if fix else ""))
        if datasets_note:
            lines.append("  " + datasets_note)
        signals.append({"rule": "HASH-003", "severity": "info", "title": "What the file-reputation check could not do",
                        "subject": "", "evidence": lines, "recommendation": [], "entities": []})
    return signals
