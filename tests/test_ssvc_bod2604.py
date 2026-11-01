"""CISA BOD 26-04's remediation timeline beside the SSVC decision: the table row for
row against CERT/CC's copy of CISA's Table 1, where each input comes from (CISA's
values or CISA's missing-data rules -- never Kratos's CVSS estimate; the machine's
public exposure), and every surface that shows it. Fixtures only -- no network, no SSH."""
from __future__ import annotations

import csv
import itertools
from pathlib import Path

import pytest

from kratos import finding_facts
from kratos.assets import store as AS
from kratos.ssvc import attach as AT
from kratos.ssvc import bod2604 as B
from kratos.ssvc import exposure as X
from kratos.ssvc import inputs as I
from kratos.ssvc import present
from tests.test_ssvc_findings import HOST, ME, SSHD, _findings, _live, _utc, idx  # noqa: F401 -- fixtures

CSV = Path(__file__).parent / "fixtures" / "bod_26_04" / "cisa_bod_26_04_1_0_0.csv"
_WORDS = {"3 days & forensic investigation": B.FORENSIC, "3 days": B.DAYS_3, "14 days": B.DAYS_14,
          "60 days": B.DAYS_60, "fix on system upgrade": B.UPGRADE}


# ------------------------------------------------------------------ the table
def test_the_table_matches_cisas_row_for_row():
    with CSV.open(newline="") as fh:
        published = {(r[1], r[2], r[3], r[4]): _WORDS[r[5]] for r in list(csv.reader(fh))[1:]}
    assert len(published) == 16 and B.TABLE == published


def test_every_combination_of_the_four_inputs_has_a_timeline():
    for combo in itertools.product(("no", "yes"), ("no", "yes"), ("no", "yes"), ("partial", "total")):
        assert B.timeline(*combo) in B.TIMELINES
    with pytest.raises(KeyError):
        B.timeline("maybe", "no", "no", "partial")


def _cve(cve="CVE-2026-0001", *, kev=False, auto=None, impact=None, source=I.CISA):
    def inp(v):
        return I.Input(v, source if v else I.NOT_ASSESSED)
    expl = I.Input("active", I.KEV, "2026-10-01") if kev else I.Input("none", I.NOT_ASSESSED)
    return I.CveInputs(cve, expl, inp(auto), inp(impact), kev=kev)


EXPOSED = {"value": "yes", "source": B.MEASURED, "date": "", "note": ""}
INTERNAL = {"value": "no", "source": B.MEASURED, "date": "", "note": ""}


def test_missing_automatable_and_impact_follow_cisas_rule_not_kratoss_cvss_estimate():
    # no CISA assessment: the directive counts them as "no" and "total"
    d = B.for_cve(_cve(), INTERNAL)
    assert d["inputs"]["automatable"]["value"] == "no" and d["inputs"]["automatable"]["source"] == B.CISA_RULE
    assert d["inputs"]["technical_impact"]["value"] == "total"
    assert d["timeline"] == B.UPGRADE                            # no/no/no/total
    # an SSVC input estimated from CVSS is not CISA's value: the rule applies
    est = B.for_cve(_cve(auto="yes", impact="partial", source=I.ESTIMATE), EXPOSED)
    assert est["inputs"]["automatable"] == {"value": "no", "source": B.CISA_RULE, "date": "",
                                            "note": est["inputs"]["automatable"]["note"]}
    assert est["timeline"] == B.DAYS_14                          # no/yes/no/total
    # CISA's own values are used as given
    cisa = B.for_cve(_cve(kev=True, auto="yes", impact="total"), EXPOSED)
    assert cisa["timeline"] == B.FORENSIC and cisa["inputs"]["in_kev"]["date"] == "2026-10-01"


def test_a_finding_takes_its_most_urgent_cve():
    b = B.for_finding([_cve("CVE-2026-0001", auto="no", impact="partial"),
                       _cve("CVE-2026-0002", kev=True, auto="no", impact="partial")], INTERNAL)
    assert b["timeline"] == B.DAYS_14 and b["cve"] == "CVE-2026-0002"
    assert b["counts"] == {B.UPGRADE: 1, B.DAYS_14: 1} and b["table"] == B.TABLE_VERSION
    assert B.for_finding([], INTERNAL) is None


# ------------------------------------------------------------------ Publicly Exposed
def test_publicly_exposed_is_the_persons_setting_then_measured_then_cisas_rule():
    internet = {"value": X.INTERNET, "reason": "0.0.0.0:22 ...", "measured_at": "2026-11-01T10:00:00+00:00"}
    network = {"value": X.NETWORK, "reason": "private only"}
    unknown = {"value": X.UNKNOWN, "reason": "no read"}
    assert B.publicly_exposed(override="private", measured=[internet])["value"] == "no"
    assert B.publicly_exposed(override="internet", measured=[network])["source"] == B.PERSON
    got = B.publicly_exposed(override=None, measured=[network, internet])
    assert got["value"] == "yes" and got["source"] == B.MEASURED and got["date"].startswith("2026-11-01")
    assert B.publicly_exposed(override=None, measured=[network])["value"] == "no"
    # nothing measured: CISA's rule -- public if the machine uses a publicly routable address
    rule = B.publicly_exposed(override=None, measured=[unknown], addresses=["web.example.com", "203.0.113.7"])
    assert rule["value"] == "yes" and rule["source"] == B.CISA_RULE and "203.0.113.7" in rule["note"]
    internal = B.publicly_exposed(override=None, measured=[unknown], addresses=["10.0.0.5", "100.64.0.7"])
    assert internal["value"] == "no" and internal["source"] == B.CISA_RULE and "/assets" in internal["note"]


# ------------------------------------------------------------------ on findings (end to end)
def test_kev_cve_on_an_internet_facing_machine_gets_3_days_and_a_forensic_check(idx):
    by, _ = _findings(idx, _live([SSHD]))
    s = by[("PKG-001", "openssh")].ssvc
    b = s["bod_26_04"]
    # CVE-2024-6387: KEV, CISA said not automatable / total, sshd listens on a public address
    assert b["timeline"] == B.FORENSIC and b["cve"] == "CVE-2024-6387"
    inp = b["inputs"]
    assert (inp["in_kev"]["value"], inp["publicly_exposed"]["value"], inp["automatable"]["value"],
            inp["technical_impact"]["value"]) == ("yes", "yes", "no", "total")
    assert inp["automatable"]["source"] == I.CISA and inp["publicly_exposed"]["source"] == B.MEASURED
    assert s["outcome"] == "attend"                       # the SSVC decision is unchanged beside it


def test_exposure_is_the_machines_so_a_package_that_isnt_running_still_counts(idx):
    by, _ = _findings(idx, _live([SSHD]))
    curl = by[("PKG-001", "curl")].ssvc
    assert curl["exposure"]["value"] == "not running"     # Kratos's own, per-package fact
    b = curl["bod_26_04"]                                 # CISA's asset-level input
    assert b["inputs"]["publicly_exposed"]["value"] == "yes"
    assert b["inputs"]["automatable"]["source"] == B.CISA_RULE    # Kratos estimated it; CISA didn't assess
    assert b["timeline"] == B.DAYS_14                     # no KEV, exposed, no, total


def test_a_machine_with_nothing_listening_is_not_publicly_exposed(idx):
    by, _ = _findings(idx, _live([{**SSHD, "address": "127.0.0.1"}]))
    b = by[("PKG-001", "openssh")].ssvc["bod_26_04"]
    assert b["inputs"]["publicly_exposed"]["value"] == "no" and b["timeline"] == B.DAYS_14


def test_the_persons_setting_decides_publicly_exposed(idx):
    AS.update(idx, HOST, ME, exposure_override="private")
    by, _ = _findings(idx, _live([SSHD]))
    b = by[("PKG-001", "openssh")].ssvc["bod_26_04"]
    assert b["inputs"]["publicly_exposed"]["source"] == B.PERSON and b["timeline"] == B.DAYS_14


def test_without_a_running_process_read_cisas_rule_uses_the_machines_address(idx):
    by, _ = _findings(idx, None, target="203.0.113.9")
    b = by[("PKG-001", "openssh")].ssvc["bod_26_04"]
    assert b["inputs"]["publicly_exposed"]["source"] == B.CISA_RULE and b["timeline"] == B.FORENSIC
    by, _ = _findings(idx, None)                          # HOST is a private address
    assert by[("PKG-001", "openssh")].ssvc["bod_26_04"]["inputs"]["publicly_exposed"]["value"] == "no"


def test_vuln001_on_a_scan_that_reached_a_public_address_is_publicly_exposed(tmp_path):
    from kratos.adapters import findings_engine as FE

    f = FE.Finding(id="VULN-001", title="t", severity="high", evidence=[], recommendation=[], subject="",
                   entities=["CVE-2026-0001"])
    scan = {"scanned_at": "2026-11-01T10:00:00+00:00", "findings": [
        {"source": "vulscan", "port": 443, "host": "203.0.113.7", "cve_ids": ["CVE-2026-0001"]}]}
    AT.attach([f], data_dir=tmp_path, target="web.example.com", packages_doc=None, live_doc=None, vuln_scan=scan)
    b = f.ssvc["bod_26_04"]
    assert b["inputs"]["publicly_exposed"]["value"] == "yes" and b["inputs"]["publicly_exposed"]["source"] == B.MEASURED
    assert b["timeline"] == B.DAYS_14                     # no index: not in KEV; CISA's rule: no / total


# ------------------------------------------------------------------ what the person sees
def _with_bod(**over):
    s = {"outcome": "attend", "label": "Attend", "cve": "CVE-2024-6387", "inputs": {
        "exploitation": {"value": "active", "source": "kev"}, "automatable": {"value": "no", "source": "cisa-adp"},
        "technical_impact": {"value": "total", "source": "cisa-adp"},
        "mission_wellbeing": {"value": "medium", "assumed": True}}, "exposure": {"value": "internet"}}
    s["bod_26_04"] = B.for_finding([_cve("CVE-2024-6387", kev=True, auto="no", impact="total")], EXPOSED)
    s.update(over)
    return s


def test_detail_lines_show_the_timeline_its_inputs_scope_and_clock():
    lines = present.detail_lines(_with_bod())
    text = "\n".join(lines)
    assert "CISA BOD 26-04 deadline: 3 days + forensic check (binding on U.S. federal agencies; a guide for " \
           "everyone else; worst CVE CVE-2024-6387)" in text
    assert "In KEV: yes [CISA's exploited list (KEV), 2026-10-01]" in text
    assert "Publicly exposed: yes [measured by Kratos]" in text and "whichever comes first" in text
    assert lines[0].startswith("SSVC decision: Attend")    # beside the decision, never in place of it


def test_a_cisa_rule_input_says_why_in_the_detail():
    b = B.for_finding([_cve()], B.publicly_exposed(override=None, measured=[], addresses=["10.0.0.5"]))
    text = "\n".join(B.detail_lines(b))
    assert "counts a missing value as \"total\"" in text and "say so in /assets" in text


def test_one_line_and_the_answer_block_carry_it_but_the_models_facts_dont():
    s = _with_bod()
    assert present.one_line(s).endswith("; exposure internet; CISA BOD 26-04: 3 days + forensic check")
    f = {"id": "PKG-001", "severity": "critical", "subject": "openssh", "entities": ["CVE-2024-6387"],
         "title": "openssh: 1 fixable known vulnerability", "ssvc": s}
    assert "exposure internet; CISA BOD 26-04: 3 days + forensic check" in finding_facts.answer_block([f], "")
    assert "BOD" not in finding_facts.model_line(f) and "BOD" not in AT.short_line(s)


def test_a_decision_stored_before_this_change_shows_no_timeline():
    s = _with_bod()
    s.pop("bod_26_04")
    assert not any("BOD" in line for line in present.detail_lines(s)) and "BOD" not in present.one_line(s)
