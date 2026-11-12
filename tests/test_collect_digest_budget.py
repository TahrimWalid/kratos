"""The collection digest stays within its size on a FULL collection (every check, many
findings): the check lines are shortened to fit the room left over, each keeps its
conclusion (its first clause), and the findings block and the closing line are never cut.

Before this, an over-size digest shortened every line to 160 characters and then cut the
whole text at the cap -- dropping the findings block, the closing line and the persistence
line's setuid conclusion (the G1 "any non-standard SUID files?" answers said Kratos couldn't
check)."""
from __future__ import annotations

from kratos.collect import checks as _register_checks  # noqa: F401 -- registers every check
from kratos.collect import registry
from kratos.collect.digest import DIGEST_CAP, build_digest
from kratos.collect.runner import CheckOutcome, CollectionReport

TARGET = "192.0.2.10"


def _conclusion(summary: str) -> str:
    """A summary's first clause: up to the first '; ' outside brackets."""
    depth = 0
    for i, ch in enumerate(summary):
        depth += ch in "([" and 1 or (-1 if ch in ")]" and depth else 0)
        if ch == ";" and not depth and summary[i + 1:i + 2] == " ":
            return summary[:i]
    return summary


def _busy_summaries() -> dict[str, str]:
    """A busy machine read by every check (a brute force with a login, vulnerable packages, a
    container port past the firewall, failed hardening checks, ...): each line from its own
    summary function where it has one, otherwise in the exact shape its runner writes."""
    from kratos.compliance import record as comp
    from kratos.containers import packages as cpkg
    from kratos.containers import record as cont
    from kratos.hashdb import record as hashrec
    from kratos.live import record as live
    from kratos.persist import record as persist
    from kratos.pkgvuln import record as pkg
    from kratos.sshguess import record as guess
    from kratos.websig import record as web

    comp_checks = ([{"status": "fail"}] * 49) + ([{"status": "pass"}] * 94) + ([{"status": "unknown"}] * 33)
    return {
        "ports": "3 open port(s): 22/tcp ssh, 80/tcp http, 443/tcp https",
        "auth_activity": "1,204 failed SSH login(s) from 37 address(es) in 4 burst(s); 12 accepted login(s); only "
                         "83.3% of the 24 h is covered by the logs; the rest is unknown, not clean",
        "log_integrity": "something looks off in: boot history",
        "privileged_accounts": "2 account(s) hold privileged access; first look, nothing to compare with",
        "config_audit": "failing: SSH password login; 7 of 8 settings are fine",
        "log_sync": "48,213 new log event(s); 7 log(s) up to date",
        "vuln_scan": "2 possible issue(s) on network services; the CVE list is out of date",
        "yara_sweep": "no malware signature matched",
        "file_integrity": "no change since the baseline",
        "persistence": persist.summary_line({
            "counts": {"items": 553, "suid": 18}, "areas_checked": ["cron", "systemd", "suid"],
            "complete": False, "blind": {"unread_paths": ["/root/.ssh"]}, "baseline": {"first_look": True},
            "signals": [{"rule": "PERSIST-009"}]}),
        "persistence_verify": persist.summary_line({
            "counts": {"items": 553, "suid": 18}, "areas_checked": ["cron", "systemd", "suid"],
            "complete": False, "blind": {"unread_paths": ["/root/.ssh"]}, "baseline": {"first_look": False},
            "verify": {"requested": True, "done": True}, "signals": [{"rule": "PERSIST-009"}]}),
        "live_response": live.summary_line({"counts": {"processes": 231}, "signals": [{"rule": "LIVE-007"}]}),
        "packages": pkg.summary_line({
            "complete": True, "act_now_packages": ["openssh-server"],
            "counts": {"packages": 1874, "vulnerable_packages": 23},
            "outside_distribution": [{"name": "php8.3"}], "kernel": {"pending": True}, "index_stale_days": 10}),
        "detect": "no new matches in 48,213 new log event(s); 3 of them Kratos's own commands, set aside; rules "
                  "run on the logs Kratos collected (on schedule, not continuously)",
        "web_signals": web.summary_line({"signals": [], "crashes_seen": 0}),
        "ssh_guess": guess.summary_line({"hits": [{"severity": "critical"}]}),
        "containers": cont.summary_line({
            "engines_found": ["docker"], "counts": {"running": 4}, "via": "ssh",
            "signals": [{"rule": "CONT-004", "severity": "high", "ports": [{"host_port": 8000, "proto": "tcp"}]}]}),
        "container_packages": cpkg.summary_line({
            "counts": {"images": 4, "vulnerable_packages": 12, "not_checked": 0},
            "images": [{"status": "ok", "matched": True}] * 4}),
        "hash_reputation": hashrec.summary_line({
            "counts": {"package": 902, "known_good": 40, "unknown": 17}, "signals": []}),
        "hardening": comp.summary_line({"checks": comp_checks, "signals": [{
            "severity": "low", "entities": [f"logindefs.check_{i:02d}" for i in range(49)]}]}),
        "baseline": _baseline_line(),
        **_code_lines(worst=False),
    }


def _code_lines(worst: bool) -> dict[str, str]:
    """E.7a: the code-folder and code lines (no machine text in either)."""
    from kratos.code import record as code

    sigs = [{"rule": r} for r in (("CODE-001", "CODE-002", "CODE-003", "CODE-004", "CODE-005") if worst
                                  else ("CODE-003",))]
    roots = [{"counts": {"files": 50_000 if worst else 412}}] * (20 if worst else 2)
    return {"code_roots": code.summary_roots({"roots": [{"status": "confirmed"}] * (20 if worst else 2)
                                              + [{"status": "candidate"}] * (9 if worst else 1)}),
            "code": code.summary_code({"roots": roots, "signals": sigs})}


def _baseline_line() -> str:
    """E.3: the longest the baseline line gets -- deviations, kinds learned, learning and not learnable."""
    from kratos.baseline import record as base

    dims = {n: {"status": st} for n, st in (("login_source", "active"), ("login_time", "active"),
                                            ("login_method", "active"), ("sudo_use", "active"),
                                            ("listener", "learning"), ("outbound", "learning"),
                                            ("program", "not_learnable"))}
    return base.summary_line({"dims": dims, "deviations": [{}] * 5, "learn_days": 14})


def _worst_case_summaries() -> dict[str, str]:
    """Every check reporting the most it can at once (far past anything seen on a real machine):
    even the conclusions don't all fit, so the longest are shortened -- the size, the findings
    block and the closing line still hold."""
    from kratos.compliance import record as comp
    from kratos.containers import packages as cpkg
    from kratos.containers import record as cont
    from kratos.hashdb import record as hashrec
    from kratos.live import record as live
    from kratos.persist import record as persist
    from kratos.pkgvuln import record as pkg
    from kratos.sshguess import record as guess
    from kratos.websig import record as web

    comp_checks = ([{"status": "fail"}] * 49) + ([{"status": "pass"}] * 94) + ([{"status": "unknown"}] * 33)
    return {
        "ports": "6 open port(s): 22/tcp ssh, 80/tcp http, 443/tcp https, 3306/tcp mysql, 5432/tcp postgresql, "
                 "8080/tcp http-proxy (+3 more)",
        "auth_activity": "1,204 failed SSH login(s) from 37 address(es) in 4 burst(s); 12 accepted login(s); only "
                         "83.3% of the 24 h is covered by the logs; the rest is unknown, not clean",
        "log_integrity": "something looks off in: log files, journal files, boot history, login records",
        "privileged_accounts": "4 account(s) hold privileged access, 1 new and 0 gone since the last check; 2 recent "
                               "grant(s); some account-change history is missing",
        "config_audit": "failing: SSH root login, SSH password login, firewall; warning: automatic updates; "
                        "5 of 9 settings are fine",
        "log_sync": "48,213 new log event(s); 5 log(s) up to date; catching up on journal, auth; could not sync "
                    "audit",
        "vuln_scan": "7 possible issue(s) on network services; the CVE list is out of date",
        "yara_sweep": "2 file(s) matched a malware signature",
        "file_integrity": "3 changed, 1 added, 0 removed since the baseline",
        "persistence": persist.summary_line({
            "counts": {"items": 553, "suid": 18}, "areas_checked": ["cron", "systemd", "suid"],
            "complete": False, "blind": {"unread_paths": ["/root/.ssh"]}, "baseline": {"first_look": True},
            "signals": [{"rule": "PERSIST-009"}]}),
        "persistence_verify": "412 packaged file(s) compared with their packages; 2 changed since installed",
        "live_response": live.summary_line({"counts": {"processes": 231},
                                            "signals": [{"rule": "LIVE-001"}, {"rule": "LIVE-005"}]}),
        "packages": pkg.summary_line({
            "complete": True, "act_now_packages": ["openssh-server", "sudo", "linux-image-generic", "glibc"],
            "counts": {"packages": 1874, "vulnerable_packages": 23},
            "outside_distribution": [{"name": n} for n in ("php8.3", "nginx", "redis", "mongodb")],
            "kernel": {"pending": True}, "index_stale_days": 10}),
        "detect": "3 new match(es) of 2 rule(s): SIGMA-1a2b3c4d, KRATOS-0007; 1,204 of them Kratos's own "
                  "commands, set aside; rules run on the logs Kratos collected (on schedule, not continuously)",
        "web_signals": web.summary_line({"signals": [], "crashes_seen": 0,
                                         "exposure_line": "PHP 8.1 from outside the distribution served on 80/tcp"}),
        "ssh_guess": guess.summary_line({"hits": [{"severity": "critical"}, {"severity": "high"}]}),
        "containers": cont.summary_line({
            "engines_found": ["docker"], "counts": {"running": 9}, "via": "ssh",
            "signals": [{"rule": "CONT-004", "severity": "high",
                         "ports": [{"host_port": p, "proto": "tcp"} for p in (8000, 9443, 5000, 6379, 27017)]},
                        {"rule": "CONT-001"}, {"rule": "CONT-002"}, {"rule": "CONT-006"}]}),
        "container_packages": cpkg.summary_line({
            "counts": {"images": 9, "vulnerable_packages": 41, "not_checked": 2},
            "images": [{"status": "ok", "matched": True}] * 6 + [{"status": "ok", "matched": False}]}),
        "hash_reputation": hashrec.summary_line({
            "counts": {"package": 902, "known_bad": 1, "package_modified": 2, "known_good": 40, "unknown": 17},
            "signals": [{"rule": "HASH-001"}, {"rule": "HASH-002"}]}),
        "hardening": comp.summary_line({"checks": comp_checks, "signals": [{
            "severity": "medium", "entities": [f"logindefs.check_{i:02d}" for i in range(49)]}]}),
        "baseline": _baseline_line(),
        **_code_lines(worst=True),
    }


def _findings() -> list[dict]:
    serious = [
        {"id": "CORR-SSH-001", "severity": "critical", "title": "Brute force with a successful login",
         "evidence": ["Top source IPs: 203.0.113.7 (812), 198.51.100.23 (301), 203.0.113.99 (91)"]},
        {"id": "CORR-SSH-002", "severity": "critical", "title": "Login after password guessing",
         "evidence": ["Source IP: 203.0.113.7"]},
        {"id": "HASH-001", "severity": "high", "title": "A known-bad program", "subject": "/tmp/.x"},
        {"id": "LIVE-001", "severity": "high", "title": "A running program was deleted",
         "entities": ["/usr/bin/x|4242|98765"]},
        {"id": "CONT-004", "severity": "high", "title": "Published port reachable despite the firewall",
         "entities": ["port:8000/tcp", "port:9443/tcp"]},
    ] + [{"id": "PKG-001", "severity": "high", "title": "Fixable vulnerabilities", "subject": name,
          "entities": [f"CVE-2026-{1000 + i}", f"CVE-2026-{2000 + i}", f"CVE-2026-{3000 + i}"]}
         for i, name in enumerate(("openssh-server", "sudo", "glibc", "openssl", "curl", "nginx"))]
    lower = []
    for i, rid in enumerate(("PKG-002", "NET-002", "COMP-001", "LOG-003", "AUTH-003", "COV-001", "DETECT-001",
                             "LIVE-007", "PERSIST-009", "PKG-004", "PRIV-004", "WEB-002", "CONT-001",
                             "CONT-002", "CONT-006", "LOG-001", "PRIV-001", "SIGMA-1a2b3c4d", "KRATOS-0007")):
        for j in range(1 + i % 3):
            lower.append({"id": rid, "severity": ("medium", "low", "info")[(i + j) % 3],
                          "title": "A lower-severity finding with a fairly long title for the digest"})
    return serious + lower


def _full_report(summaries: dict[str, str] | None = None) -> CollectionReport:
    summaries = summaries or _busy_summaries()
    names = list(registry._CHECKS)
    assert set(summaries) == set(names), "the test must cover every registered check"
    outcomes = [CheckOutcome(name=n, label=registry.get(n).label, cost=registry.get(n).cost, status="ok",
                             source="fresh", summary=summaries[n], age_seconds=5.0 if i % 4 else 7200.0,
                             finding_ids=["PKG-001", "PKG-002", "COMP-001"])
                for i, n in enumerate(names)]
    findings = _findings()
    return CollectionReport(target=TARGET, target_key=TARGET, transport="ssh", checks=outcomes,
                            correlation={"findings": findings})


def test_a_full_collection_stays_within_the_digest_size():
    d = build_digest(_full_report())
    assert len(d) <= DIGEST_CAP
    assert d.endswith("you don't need to repeat these checks.")     # the last-resort cut was not reached


def test_every_check_line_keeps_its_conclusion():
    report = _full_report()
    d = build_digest(report)
    for o in report.checks:
        if not registry.get(o.name).digest:
            continue
        conclusion = _conclusion(o.summary)
        assert conclusion in d, f"{o.name}: conclusion lost: {conclusion!r}"


def test_a_check_marked_out_of_the_digest_has_no_line_and_code_carries_the_waiting_count():
    d = build_digest(_full_report())
    assert not registry.get("code_roots").digest
    assert not any(line.startswith("code folders") for line in d.splitlines())
    assert any(line.startswith("code:") for line in d.splitlines())


def test_the_findings_block_and_the_closing_line_are_whole():
    d = build_digest(_full_report())
    lines = d.splitlines()
    assert "Findings on record (correlate_findings already ran):" in lines
    assert lines[-1] == ("Use your tools to look deeper where the question needs it; you don't need to repeat "
                         "these checks.")
    for fid in ("CORR-SSH-001", "CORR-SSH-002", "HASH-001", "LIVE-001", "CONT-004", "PKG-001"):
        assert fid in d                          # every serious finding is still named


def test_the_persistence_line_leads_with_the_setuid_conclusion_in_160_characters():
    report = _full_report()
    line = next(x for x in build_digest(report).splitlines() if x.startswith("persistence"))
    assert line.split(": ", 1)[1].startswith(
        "18 setuid/setgid programs, all matched to the system's packages (where it could read), no listing tool "
        "needed")
    assert len(line) <= 160


def test_even_the_worst_case_keeps_the_size_the_findings_block_and_the_closing_line():
    report = _full_report(_worst_case_summaries())
    d = build_digest(report)
    lines = d.splitlines()
    assert len(d) <= DIGEST_CAP
    assert "Findings on record (correlate_findings already ran):" in lines
    assert lines[-1].startswith("Use your tools to look deeper")
    for fid in ("CORR-SSH-001", "CORR-SSH-002", "HASH-001", "LIVE-001", "CONT-004", "PKG-001"):
        assert fid in d
    from kratos.collect.registry import get
    for o in report.checks:                                                      # a line for every check
        if not get(o.name).digest:
            continue
        assert any(x.startswith(get(o.name).short + (" (" if o.age_seconds >= 3600 else ":")) for x in lines), o.name


def test_a_semicolon_inside_brackets_does_not_split_a_clause():
    from kratos.collect.digest import _clauses

    assert _clauses("Act: openssh on m (exploited, automatable; listening on 0.0.0.0:22); 12 packages") == [
        "Act: openssh on m (exploited, automatable; listening on 0.0.0.0:22)", "12 packages"]
