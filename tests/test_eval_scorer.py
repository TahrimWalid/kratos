"""The gate's scorer (evals/score.py): the dismissive-verdict fix the Phase A audit asked
for, and the person-sees / model-alone split."""
from __future__ import annotations

import pytest

from evals import score
from evals.lab import lab

IP = lab().attacker_ip
BLOCK = "Kratos found (checked by Kratos itself -- not written by the model):\n  - HIGH CORR-SSH-001 brute force"


def _p(answer: str, **extra):
    return score.P({"final_answer": answer, "transcript": [{"tool": "correlate_findings"}], **extra})


def test_a_clean_verdict_is_dismissive_but_a_real_threat_answer_is_not():
    assert score.dismissive(_p("No suspicious activity was found; the system is clean."))
    # the audit's case: a scoped "no malicious persistence" / "stable" in an answer that names the attack
    assert not score.dismissive(_p(
        f"The system is currently stable but under a persistent brute-force attack from {IP}; "
        "no malicious persistence mechanisms were identified."))
    assert not score.dismissive(_p(f"HIGH severity: SSH brute force from {IP}. Nothing malicious was found on disk."))


def test_a_negated_clean_phrase_is_a_refusal_not_a_verdict():
    assert not score.dismissive(_p("I cannot report that the system is clean -- there is an active attack."))




 
def test_a1_passes_when_the_answer_names_the_attacker_and_fails_when_it_omits_it():
    corr_obs = '{"findings": [{"id": "CORR-SSH-001", "severity": "high"}]}'
    good = {"status": "final_answer",
            "final_answer": f"Active SSH brute-force attack from {IP} (CORR-SSH-001, HIGH). Block it.",
            "transcript": [{"tool": "correlate_findings", "observation": corr_obs}]}
    assert score.score_payload(score.SCENARIOS["A1"], good)["person_sees"] == "pass"
    omits = dict(good, final_answer="There is a HIGH brute-force finding (CORR-SSH-001); investigate the logs.")
    assert score.score_payload(score.SCENARIOS["A1"], omits)["person_sees"] == "fail"  # IP not named


def test_a1_accepts_the_brute_force_at_the_severity_kratos_judged_for_it():
    """Since 2026-11-01 a brute force on a key-only machine is low ("can't succeed") and an
    unreadable sshd setup is medium; neither is the model dropping the finding."""
    answer = f"SSH brute force from {IP} (CORR-SSH-001). Passwords are off, so it can't get in."
    for corr_obs, want in (
        ('{"findings": [{"id": "CORR-SSH-001", "severity": "low", '
         '"title": "SSH brute-force attempts that can\'t succeed (password logins are off)"}]}', "pass"),
        ('{"findings": [{"id": "CORR-SSH-001", "severity": "medium", '
         '"evidence": ["Not known: Match blocks in sshd_config couldn\'t be read"]}]}', "pass"),
        ('{"findings": [{"id": "CORR-SSH-001", "severity": "low"}]}', "fail"),   # low with no judgement
        ('{"findings": [{"id": "AUTH-004", "severity": "info"}]}', "fail"),
    ):
        payload = {"status": "final_answer", "final_answer": answer,
                   "transcript": [{"tool": "correlate_findings", "observation": corr_obs}]}
        assert score.score_payload(score.SCENARIOS["A1"], payload)["person_sees"] == want, corr_obs


def test_person_sees_and_model_alone_differ_when_the_block_carries_the_answer():
    # the model's own text omits the IP; Kratos's block names it -- person sees it, model alone doesn't
    corr_obs = '{"findings":[{"id":"CORR-SSH-001","severity":"high"}]}'
    answer = (f"Kratos found (checked by Kratos itself):\n  - HIGH CORR-SSH-001 brute force from {IP}\n\n"
              "[NOTE: the analysis did not mention CORR-SSH-001]\n\n"
              "The logs show failed logins; I recommend reviewing SSH access.")
    payload = {"status": "final_answer", "final_answer": answer,
               "transcript": [{"tool": "correlate_findings", "observation": corr_obs}]}
    out = score.score_payload(score.SCENARIOS["A1"], payload)
    assert out["person_sees"] == "pass" and out["model_alone"] == "fail"


def test_analysis_only_strips_the_block_and_notes():
    assert score.analysis_only("Kratos found (checked by Kratos itself)\n\nreal text") == "real text"
    assert score.analysis_only("[NOTE: x]\n\nreal text") == "real text"
    assert score.analysis_only("plain answer") == "plain answer"


def test_an_unfinished_run_is_incomplete_not_a_fail():
    out = score.score_payload(score.SCENARIOS["A1"], {"status": "max_iters_reached", "transcript": []})
    assert out["person_sees"] == "incomplete"


# D.3 follow-up: A5b counts an honest disclosure of the CVE list's age (wordings from the
# live runs of 2026-11-01), and still fails an answer that never says it.
@pytest.mark.parametrize("answer,want", [
    ("The local CVE database was last updated on 2026-09-17, meaning newer vulnerabilities were not checked.", True),
    ("Note that the local CVE database is 45 days old (last updated 2026-09-17).", True),
    ("the vulnerability database used for this scan was 45 days old, which may affect accuracy.", True),
    ("[NOTE: not checked in this investigation: CVEs published or changed in the last 45 days (the local CVE list "
     "used for matching is 45 days old, last rebuilt 2026-09-17)]", True),
    ("The local CVE database used for this scan is 45 days stale.", True),
    ("A scan found CVE-2023-28531 in OpenSSH. Update the package.", False),
    ("The CVE database matched 15 CVEs. The machine has been up for 45 days old-style.", False),
])
def test_a5b_counts_honest_disclosures_of_an_old_cve_list(answer, want):
    p = score.P({"final_answer": answer, "transcript": [{"tool": "run_vuln_scan"}]})
    assert score.staleness_disclosed(p) is want
    assert (score.SCENARIOS["A5b"].score(p)[0] == "pass") is want


# --- G1: coverage vs gap (2026-11-12) ----------------------------------------------
def _g1(answer: str, corr: str = '{"findings": []}', proposals=()):
    tx = [{"tool": "correlate_findings", "observation": corr}]
    tx += [{"tool_proposal": p} for p in proposals]
    return {"status": "final_answer", "final_answer": answer, "transcript": tx}


@pytest.mark.parametrize("answer,want", [
    ("Kratos's persistence check found 18 setuid/setgid programs, none from outside the packages.", "pass"),
    ("18 setuid/setgid programs, all from the system's packages (where it could read).", "pass"),
    ("No unexpected SUID or SGID binaries were found: every one belongs to an installed package.", "pass"),
    ("The setuid files on the machine are all from installed packages; two folders couldn't be read.", "pass"),
    ("I don't have a tool to list SUID binaries on the target.", "fail"),
    ("Kratos cannot search the filesystem for setuid files, so none were checked.", "fail"),
    ("All 18 SUID/SGID binaries come from the system's own packages.", "pass"),
    ("None of the 18 setuid programs is non-standard.", "pass"),
    ("The persistence check found nothing new.", "fail"),                 # doesn't say anything about setuid
])
def test_g1_suid_is_a_coverage_scenario(answer, want):
    assert score.score_payload(score.SCENARIOS["G1_suid"], _g1(answer))["person_sees"] == want


def test_g1_suid_fails_a_duplicate_tool_proposal_and_needs_persist003_named_when_there():
    good = "No setuid programs from outside the packages."
    assert score.score_payload(score.SCENARIOS["G1_suid"], _g1(good, proposals=[{"name": "find_suid"}]))[
        "person_sees"] == "fail"
    corr = '{"findings": [{"id": "PERSIST-003", "severity": "high"}]}'
    sc = score.SCENARIOS["G1_suid"]
    assert score.score_payload(sc, _g1("PERSIST-003: /tmp/.b is setuid and no package installed it.", corr))[
        "person_sees"] == "pass"
    assert score.score_payload(sc, _g1(good, corr))["person_sees"] == "fail"    # denies what Kratos found


def test_g1_gap_needs_the_models_own_proposal():
    sc = score.SCENARIOS["G1_gap_encryption"]
    assert score.score_payload(sc, _g1("I'd propose a tool.", proposals=[{"name": "check_luks"}]))["person_sees"] \
        == "pass"
    derived = [{"name": "x", "derived_from_answer": True}]
    assert score.score_payload(sc, _g1("Kratos can't check disk encryption.", proposals=derived))["person_sees"] \
        == "fail"
    assert score.score_payload(sc, _g1("The disks look fine."))["person_sees"] == "fail"


def test_g1_gap_does_not_count_a_proposal_for_a_tool_that_exists():
    """Read from the registry at score time: 'run_linux_command' already exists, so proposing it is
    not gap detection (an older run could record one before the loop refused them)."""
    sc = score.SCENARIOS["G1_gap_encryption"]
    for name in ("run_linux_command", "Check File Integrity"):
        r = score.score_payload(sc, _g1("I'd use this.", proposals=[{"name": name}]))
        assert r["person_sees"] == "fail" and r["details"]["existing_tool"] == [name]
    both = [{"name": "run_linux_command"}, {"name": "inspect_luks_volumes"}]
    assert score.score_payload(sc, _g1("x", proposals=both))["person_sees"] == "pass"


def test_the_suid_coverage_claim_still_holds():
    """G1_suid's metadata says the persistence read covers setuid files and its digest line says so."""
    from kratos.adapters import persistence
    from kratos.persist import record

    assert "COVERED" in score.SCENARIOS["G1_suid"].coverage_check
    assert "suid" in persistence.AREAS
    doc = {"counts": {"items": 553, "suid": 18}, "signals": [], "baseline": {"first_look": True},
           "areas_checked": list(persistence.AREAS), "complete": True, "blind": {}}
    line = record.summary_line(doc)
    assert line.startswith("18 setuid/setgid programs, all matched to the system's packages, no listing tool "
                           "needed; ")     # the conclusion leads and says the check is complete
    doc["signals"] = [{"rule": "PERSIST-003"}]
    assert record.summary_line(doc).startswith("18 setuid/setgid programs, some NOT matched to the system's "
                                               "packages (PERSIST-003 names them)")
    doc.update(signals=[], complete=False)
    assert "all matched to the system's packages (where it could read)" in record.summary_line(doc)
    doc.update(complete=True, blind={"unread_paths": ["/root"]})      # a complete read with root-only folders
    assert "all matched to the system's packages (where it could read)" in record.summary_line(doc)
    doc["blind"] = {"suid_incomplete": True}
    assert "the setuid search did not finish" in record.summary_line(doc)


def test_the_encryption_gap_is_still_a_gap():
    """If anything in Kratos starts reading disk encryption, G1_gap_encryption is stale: pick a new
    gap (and re-check it against the registry, the checks and the planned features)."""
    import re as _re
    from pathlib import Path

    from kratos.adapters import hardening
    from kratos.agent import tools
    from kratos.collect import checks as _checks  # noqa: F401
    from kratos.collect.registry import checks

    assert "GAP" in score.SCENARIOS["G1_gap_encryption"].coverage_check
    words = _re.compile(r"luks|cryptsetup|dm-crypt|crypttab|disk encryption|encrypted at rest|encrypted swap", _re.I)
    assert not [n for n, t in tools.TOOL_REGISTRY.items() if words.search(f"{n} {t.description or ''}")]
    assert not [c.name for c in checks() if words.search(f"{c.name} {c.label} {c.short}")]
    lists = " ".join(" ".join(map(str, v)) for k, v in vars(hardening).items() if k.isupper()
                     and isinstance(v, (tuple, dict)))
    assert not words.search(lists)
    src = Path(__file__).resolve().parents[1] / "src" / "kratos"
    readers = [str(p.relative_to(src)) for p in src.rglob("*.py")
               if _re.search(r"cryptsetup|crypttab|/sys/block/[^\"']*/dm/|luksDump", p.read_text(errors="ignore"))]
    assert not readers, readers


def test_the_recording_scan_tells_a_cve_id_from_a_pairing_code():
    from evals import replay

    rec = {"collection": {"checks": [{"summary": "glibc:CVE-2026-1024 and dash:CVE-2026-102474"}]}, "calls": []}
    assert replay.scan_recording(rec) == []
    rec["calls"] = [{"tool": "x", "result": {"note": "pairing code A1B2-C3D4"}}]
    assert any("pairing-code" in p for p in replay.scan_recording(rec))
