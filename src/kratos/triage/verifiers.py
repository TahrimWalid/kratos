"""The built-in verifiers (docs/phaseB/B.1 §5.1).

Each re-checks a finding with a fresh, narrow read and returns a Verdict. The
backbone is `_condition_verdict`: force the collection check(s) whose inputs
cover the rule, run one correlation, and see whether the same finding (by
finding_key) is still there. On top of that:

- occurrences (a failed-login burst) are re-checked against the logs for the
  time they happened, not the current moment (§3.3): an ended burst that is
  still in the logs is *reproduced*, and a source fail2ban has since banned is
  *partly*;
- an exposed port is re-probed from Kratos's own vantage with nmap (`partly`
  when it is listening but filtered from here, never claimed to be the public
  internet's view -- §4 non-goal);
- a network-scan CVE (VULN-001) is re-checked offline against a fresh package
  inventory (the same backport cross-check A.2 already uses), not by re-running
  the network scan.

Rules with no safe fresh re-read declare a NoVerifier reason instead, so the
completeness test can require every rule to be accounted for.
"""
from __future__ import annotations

from typing import Any

from kratos import finding_facts
from kratos.triage.context import VerifyContext
from kratos.triage.registry import NoVerifier, Verifier, register_no_verifier, register_verifier
from kratos.triage.verdict import Verdict, VerifyCheck


# --------------------------------------------------------------------------- helpers
def _covering_checks(rule_id: str) -> list[str]:
    """The collection checks whose inputs refresh what this rule reads to be gone."""
    from kratos.adapters.findings_engine import rule_inputs
    from kratos.collect import checks as _checks  # noqa: F401 -- register the built-ins
    from kratos.collect.registry import checks as registered_checks
    from kratos.lifecycle.rules import rule_info

    info = rule_info(rule_id)
    needed = set(info.covering_inputs if info else rule_inputs(rule_id))
    return [c.name for c in registered_checks() if needed & set(c.inputs)]


def _checks_run(report: Any, names: list[str]) -> tuple[VerifyCheck, ...]:
    out: list[VerifyCheck] = []
    for o in getattr(report, "checks", None) or []:
        if o.name in names:
            out.append(VerifyCheck(name=o.name, transport=getattr(report, "transport", "") or "",
                                   read_seconds=0.0))
    if not out:                       # the read never ran (disabled / no target)
        out = [VerifyCheck(name=n, transport=getattr(report, "transport", "") or "") for n in names]
    return tuple(out)


def _blocked_reason(report: Any, names: list[str]) -> str | None:
    """A plain reason the fresh read could not be trusted, or None when it ran clean."""
    disabled = getattr(report, "disabled_reason", None)
    if disabled:
        return str(disabled)
    outcomes = [o for o in getattr(report, "checks", None) or [] if o.name in names]
    if not outcomes:
        return "the fresh read did not run"
    bad = [o for o in outcomes if o.status != "ok"]
    if bad:
        reasons = [o.reason or o.summary or (o.gaps[0] if o.gaps else o.name) for o in bad]
        return "; ".join(dict.fromkeys(reasons))     # de-duped, order kept
    return None


def _facts(finding: dict[str, Any]) -> tuple[str, ...]:
    return tuple(finding_facts.safe_facts(finding))


def _fresh_report(ctx: VerifyContext, check_names: list[str]) -> Any:
    """The report to judge against: the collection Kratos just ran (reuse mode, the
    automatic pass) or a narrow fresh re-collection (on demand)."""
    if ctx.reuse and ctx.report is not None:
        return ctx.report
    return ctx.recollect(tuple(check_names))


def _condition_verdict(ctx: VerifyContext, check_names: list[str], *,
                       reproduced_sentence: str, gone_sentence: str) -> Verdict:
    """Force a fresh collection read and judge by whether the finding is still there."""
    if not check_names:
        return Verdict("couldnt_check", "No fresh read covers this finding.",
                       detail="no collection check refreshes what this rule reads")
    report = _fresh_report(ctx, check_names)
    checks = _checks_run(report, check_names)
    fresh = ctx.fresh_finding(report)
    if fresh is not None:
        return Verdict("reproduced", reproduced_sentence, checks=checks, evidence=_facts(fresh))
    blocked = _blocked_reason(report, check_names)
    if blocked is None:
        return Verdict("not_reproduced", gone_sentence, checks=checks)
    return Verdict("couldnt_check", "Kratos could not complete a fresh read of this.",
                   detail=blocked, checks=checks)


# --------------------------------------------------------------------------- conditions
def _verify_packages(ctx: VerifyContext) -> Verdict:
    v = _condition_verdict(
        ctx, _covering_checks(ctx.rule_id),
        reproduced_sentence="A fresh package read still shows this -- the fix is not installed yet.",
        gone_sentence="A fresh package read no longer shows this -- it looks fixed. Retest to confirm.")
    if ctx.rule_id == "PKG-003" and v.verdict == "reproduced":
        return Verdict("reproduced", "A newer kernel is still installed than the one running -- a reboot is "
                       "still pending.", checks=v.checks, evidence=v.evidence)
    return v


def _verify_privileged(ctx: VerifyContext) -> Verdict:
    return _condition_verdict(
        ctx, _covering_checks(ctx.rule_id),
        reproduced_sentence="A fresh privileged-accounts read still shows this access.",
        gone_sentence="A fresh privileged-accounts read no longer shows this -- the access may have been removed.")


def _verify_persistence(ctx: VerifyContext) -> Verdict:
    return _condition_verdict(
        ctx, _covering_checks(ctx.rule_id),
        reproduced_sentence="A fresh persistence read still finds this, same place and content.",
        gone_sentence="A fresh persistence read no longer finds this -- it may have been removed.")


def _verify_live(ctx: VerifyContext) -> Verdict:
    sentence_live = ("A fresh live-response read still finds this running the same way."
                     if ctx.rule_id != "LIVE-004" else "A fresh read still finds this file in the folder.")
    gone_live = ("A fresh live-response read no longer finds this -- the process is gone (it was seen earlier; "
                 "the dropped file, if any, is LIVE-004)." if ctx.rule_id != "LIVE-004"
                 else "A fresh read no longer finds this file -- it may have been removed.")
    return _condition_verdict(ctx, _covering_checks(ctx.rule_id),
                              reproduced_sentence=sentence_live, gone_sentence=gone_live)


def _verify_integrity(ctx: VerifyContext) -> Verdict:
    return _condition_verdict(
        ctx, _covering_checks(ctx.rule_id),
        reproduced_sentence="A fresh re-hash still differs from the recorded baseline.",
        gone_sentence="A fresh re-hash matches the baseline again.")


def _verify_log(ctx: VerifyContext) -> Verdict:
    return _condition_verdict(
        ctx, _covering_checks(ctx.rule_id),
        reproduced_sentence="A fresh log-integrity / sealing read still shows this.",
        gone_sentence="A fresh log-integrity / sealing read no longer shows this.")


def _verify_vuln_scan(ctx: VerifyContext) -> Verdict:
    return _condition_verdict(
        ctx, _covering_checks(ctx.rule_id),
        reproduced_sentence="A fresh vulnerability scan still reports this.",
        gone_sentence="A fresh vulnerability scan no longer reports this.")


# --------------------------------------------------------------------------- NET: reachability from Kratos
def _verify_net(ctx: VerifyContext) -> Verdict:
    """Re-probe with nmap (reuses the ports check, which scans with -Pn) and
    re-correlate. Reachability is from KRATOS'S vantage, said plainly -- never a
    claim about the public internet (§4 non-goal)."""
    report = _fresh_report(ctx, ["ports"])
    checks = _checks_run(report, ["ports"])
    fresh = ctx.fresh_finding(report)
    if fresh is not None:
        return Verdict("reproduced", "nmap from Kratos still reaches this -- the port is open from here.",
                       checks=checks, evidence=_facts(fresh),
                       detail="")
    blocked = _blocked_reason(report, ["ports"])
    if blocked is None:
        return Verdict("not_reproduced", "nmap from Kratos no longer reaches this port. Note: this is Kratos's "
                       "own vantage, not the public internet. Retest to confirm.", checks=checks)
    return Verdict("couldnt_check", "Kratos could not complete a fresh port scan.", detail=blocked, checks=checks)


# --------------------------------------------------------------------------- occurrences: auth bursts
def _rolling_hours_since(ctx: VerifyContext) -> int:
    """A rolling window (hours) that comfortably covers the finding's own time: from
    when it was first seen to now, capped to 30 days, floored at 2 h."""
    import datetime as _dt

    first = str(ctx.finding.get("first_seen") or "")
    try:
        when = _dt.datetime.fromisoformat(first.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        when = ctx.now - 48 * 3600
    hours = int((ctx.now - when) / 3600) + 2
    return max(2, min(hours, 30 * 24))


def _verify_auth(ctx: VerifyContext) -> Verdict:
    """Re-measure the finding's window with measure_auth_activity (§3.3): an ended
    burst still in the logs is reproduced; a source fail2ban now bans is partly; if
    the logs for that time are gone, couldn't check.

    In reuse mode (the automatic pass) Kratos already measured the last 24 h as part of
    collection seconds earlier, so the verdict is read from that collection rather than
    measuring a second time."""
    if ctx.reuse and ctx.report is not None:
        return _condition_verdict(
            ctx, ["auth_activity"],
            reproduced_sentence="The burst is still in the logs Kratos just collected.",
            gone_sentence="No failed-login burst in the logs Kratos just collected -- no recurrence. Retest to confirm.")
    hours = _rolling_hours_since(ctx)
    res = ctx.dispatch("measure_auth_activity",
                       {"window": {"kind": "rolling", "amount": hours, "unit": "hour"}})
    inner = res.get("result") if isinstance(res, dict) else None
    checks = (VerifyCheck(name="measure_auth_activity", transport=""),)
    # The dispatch wrapper says "ok" when the tool ran; the measurement's own status says
    # whether it read anything. A failed read is "couldn't check" -- never "not reproduced"
    # (Phase B audit: an SSH failure used to read as "no burst -- looks fixed").
    failed_read = (not isinstance(inner, dict) or res.get("status") != "ok"
                   or str(inner.get("status") or "ok").lower() == "error" or not isinstance(inner.get("counts"), dict))
    if failed_read:
        reason = str((inner if isinstance(inner, dict) and inner.get("observation") else res or {}).get("observation")
                     or "the measurement did not run")[:160]
        return Verdict("couldnt_check", "Kratos could not re-measure the sign-in activity for that window.",
                       detail=reason, checks=checks)
    window = inner.get("window") if isinstance(inner.get("window"), dict) else {}
    counts = inner.get("counts") if isinstance(inner.get("counts"), dict) else {}
    failed = int(counts.get("ssh_failed_login") or 0)
    bursts = inner.get("bursts") if isinstance(inner.get("bursts"), list) else []
    want_ips = set(finding_facts.ips(ctx.finding))
    source_ips = {str(s.get("ip")) for s in inner.get("failed_login_sources") or [] if isinstance(s, dict)}
    seen_sources = sorted(want_ips & source_ips) if want_ips else []
    fail2ban = inner.get("fail2ban") if isinstance(inner.get("fail2ban"), dict) else {}
    bans = int(fail2ban.get("bans") or 0)
    coverage = window.get("coverage_percent")
    present = bool(bursts) or failed > 0 or bool(seen_sources)
    label = window.get("label") or f"the last {hours} h"
    if present:
        evidence = [f"{failed} failed SSH login(s) in {label}"]
        if seen_sources:
            evidence.append("same source(s): " + ", ".join(seen_sources))
        elif want_ips:
            evidence.append("the finding's source(s) were not among the current failures")
        if bans and (seen_sources or not want_ips):
            return Verdict("partly", "The burst is still in the logs, but fail2ban has since banned the source -- "
                           "the risk is lower now.", detail="source now banned by fail2ban",
                           checks=checks, evidence=tuple(evidence + [f"{bans} fail2ban ban(s) in the window"]))
        return Verdict("reproduced", f"The burst is still in the logs for {label}"
                       + (", from the same source." if seen_sources else "."),
                       checks=checks, evidence=tuple(evidence))
    if isinstance(coverage, (int, float)) and coverage < 100 and (window.get("problems") or window.get("truncated")):
        return Verdict("couldnt_check", "The logs for that time are no longer fully there, so Kratos can't say "
                       "the burst is gone.", detail="the logs for that time are no longer there", checks=checks)
    return Verdict("not_reproduced", f"No failed-login burst in the logs for {label} -- no recurrence. "
                   "Retest to confirm.", checks=checks)


# --------------------------------------------------------------------------- VULN-001: offline package cross-check
def _verify_vuln001(ctx: VerifyContext) -> Verdict:
    """Re-check a network-scan CVE offline against a fresh package inventory (A.2's
    backport cross-check) instead of re-running the network scan."""
    from kratos.pkgvuln.crosscheck import fixed_by_packages

    cves = [str(e).upper() for e in ctx.finding.get("entities") or [] if str(e).upper().startswith("CVE-")]
    if not cves:
        return Verdict("couldnt_check", "This network finding names no CVE to re-check against the packages.",
                       detail="no CVE id on the finding")
    report = _fresh_report(ctx, ["packages"])
    checks = _checks_run(report, ["packages"])
    blocked = _blocked_reason(report, ["packages"])
    doc = _latest_packages_doc(ctx.data_dir, ctx.target)
    if doc is None:
        return Verdict("couldnt_check", "Kratos has no fresh package inventory to cross-check against.",
                       detail=blocked or "no package inventory", checks=checks)
    fixers: dict[str, set[str]] = {}
    try:
        fixed = fixed_by_packages(ctx.data_dir, doc, cves, fixers)
    except Exception:  # noqa: BLE001 -- a cross-check failure is "couldn't check", never a crash
        return Verdict("couldnt_check", "The package cross-check could not run.",
                       detail="the vulnerability index or inventory could not be read", checks=checks)
    all_fixed = all(c in fixed for c in cves)
    some_fixed = any(c in fixed for c in cves)
    if all_fixed:
        first = next(iter(fixed.values()), "")
        return Verdict("partly", "The installed packages already carry a backported fix for this -- the network "
                       "match is likely a false alarm.", detail="distro backported the fix",
                       checks=checks, evidence=(first,) if first else ())
    if some_fixed:
        return Verdict("partly", "Some of these CVEs are fixed by the installed packages (backported); the rest "
                       "are not.", detail="some backported, some not", checks=checks,
                       evidence=tuple(sorted(c for c in cves if c in fixed))[:3])
    return Verdict("reproduced", "No installed package fixes these CVEs -- the network finding stands.",
                   checks=checks, evidence=tuple(cves[:3]))


def _latest_packages_doc(data_dir: Any, target: str) -> dict[str, Any] | None:
    from pathlib import Path

    from kratos.adapters.findings_engine import find_latest_inputs
    from kratos.target_key import target_key

    try:
        found = find_latest_inputs(Path(data_dir), target)
        path = found.get("packages")
        if path is None:
            return None
        import json

        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) and target_key(doc.get("target") or target) == target_key(target) else doc
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- registration
register_verifier(Verifier(rules=("PKG-",), cost="quick", verify=_verify_packages,
                           label="a fresh package read"))
register_verifier(Verifier(rules=("PRIV-001", "PRIV-002", "PRIV-003"), cost="quick", verify=_verify_privileged,
                           label="a fresh privileged-accounts read"))
register_verifier(Verifier(rules=("PERSIST-001", "PERSIST-002", "PERSIST-003", "PERSIST-004", "PERSIST-005",
                                  "PERSIST-006", "PERSIST-007", "PERSIST-008"),
                           cost="quick", verify=_verify_persistence, label="a fresh persistence read"))
register_verifier(Verifier(rules=("LIVE-",), cost="quick", verify=_verify_live,
                           label="a fresh live-response read"))
register_verifier(Verifier(rules=("LOG-001", "LOG-002", "LOG-003", "LOG-004", "LOG-005", "LOG-006",
                                  "SEAL-001", "SEAL-002"),
                           cost="quick", verify=_verify_log, label="a fresh log-integrity / sealing read"))
register_verifier(Verifier(rules=("AUTH-001", "AUTH-003", "AUTH-004", "AUTH-TREND-001",
                                  "CORR-001", "CORR-002", "CORR-SSH-001"),
                           cost="quick", verify=_verify_auth, label="re-measured sign-in activity"))
register_verifier(Verifier(rules=("VULN-001",), cost="quick", verify=_verify_vuln001,
                           label="an offline package cross-check"))
# slow -- on request only (/verify), never in the auto budget
register_verifier(Verifier(rules=("NET-",), cost="slow", verify=_verify_net,
                           label="an nmap reachability probe from Kratos"))
register_verifier(Verifier(rules=("INTEG-001",), cost="slow", verify=_verify_integrity,
                           label="a fresh re-hash of the critical files"))
register_verifier(Verifier(rules=("VULN-002",), cost="slow", verify=_verify_vuln_scan,
                           label="a fresh vulnerability scan"))

# No safe fresh re-read: these describe Kratos's own host context (collected only for
# the machine Kratos runs on), so a verifier would need a whole fresh host run -- not a
# narrow re-read. They are posture/context, re-read by investigating the host again.
register_no_verifier(NoVerifier(
    rules=("CTX-001", "ENV-001", "OBS-001"),
    reason="describes Kratos's own host context; re-read it by investigating the Kratos host again, not by a "
           "narrow per-finding re-check"))
register_no_verifier(NoVerifier(
    rules=("SIGMA-", "KRATOS-"),
    # short: it is shown as the answer's "[couldn't check: ...]" tag. A rule match is an event in
    # stored log lines (the finding names them); a fresh read can't make it happen again.
    reason="a rule match can't be re-read; its log lines are kept (events --rule)"))
register_no_verifier(NoVerifier(
    rules=("HUNT-001",),
    # short, shown as the answer's "[couldn't check: ...]" tag: the sighting is in Kratos's stored
    # records (the finding names them); a fresh read of the machine can't make it happen again.
    reason="a past sighting in stored records can't be re-read; `kratos hunt <address>` shows them"))
register_no_verifier(NoVerifier(
    rules=("DETECT-002",),
    reason="the watcher reports its own state every minute; /subagent shows it live"))
register_no_verifier(NoVerifier(
    rules=("PRIV-004",),
    reason="an inventory of who holds privileged access, not a risk in itself; re-read it on demand with /verify "
           "(the PRIV-001/002/003 findings it summarises are each verified)"))
