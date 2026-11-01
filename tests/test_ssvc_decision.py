"""D.3: CISA's SSVC tree, the per-CVE inputs, Mission & Well-being, and the decision.

The tree rows pinned by hand below were read off the CISA SSVC Guide (November
2022), Table 9 -- the same decisions as its Figure 1 -- not copied from any other
table.
"""
from __future__ import annotations

import itertools

import pytest

from kratos.ssvc import decide as D
from kratos.ssvc import inputs as I
from kratos.ssvc import mission as M
from kratos.ssvc import tree as T


# ------------------------------------------------------------------ tree
def test_every_combination_has_exactly_one_outcome():
    keys = [r[:4] for r in T.rows()]
    assert len(keys) == len(set(keys)) == 36
    for combo in itertools.product(T.EXPLOITATION, T.AUTOMATABLE, T.TECHNICAL_IMPACT, T.MISSION_WELLBEING):
        assert T.outcome(*combo) in T.OUTCOMES
    assert set(T.TABLE) == set(itertools.product(T.EXPLOITATION, T.AUTOMATABLE, T.TECHNICAL_IMPACT,
                                                 T.MISSION_WELLBEING))


# (row number in the guide's Table 9, exploitation, automatable, technical impact, mission & well-being, decision)
HAND_CHECKED = [
    (1, "none", "no", "partial", "low", "track"),
    (6, "none", "no", "total", "high", "track*"),
    (9, "none", "yes", "partial", "high", "attend"),
    (11, "none", "yes", "total", "medium", "track"),
    (15, "poc", "no", "partial", "high", "track*"),
    (17, "poc", "no", "total", "medium", "track*"),
    (18, "poc", "no", "total", "high", "attend"),
    (23, "poc", "yes", "total", "medium", "track*"),
    (28, "active", "no", "total", "low", "track"),
    (29, "active", "no", "total", "medium", "attend"),
    (30, "active", "no", "total", "high", "act"),
    (31, "active", "yes", "partial", "low", "attend"),
    (35, "active", "yes", "total", "medium", "act"),
    (36, "active", "yes", "total", "high", "act"),
]


@pytest.mark.parametrize("row,e,a,t,m,want", HAND_CHECKED)
def test_hand_checked_rows_match_the_cisa_guide(row, e, a, t, m, want):
    assert T.outcome(e, a, t, m) == want
    assert T.rows()[row - 1] == (e, a, t, m, want)


def test_outside_values_raise_instead_of_guessing():
    with pytest.raises(KeyError):
        T.outcome("likely", "yes", "total", "high")


# ------------------------------------------------------------------ mission
@pytest.mark.parametrize("crit,wb,want", [
    ("low", "minimal", "low"), ("low", "material", "medium"), ("low", "irreversible", "high"),
    ("medium", "minimal", "medium"), ("medium", "material", "medium"), ("medium", "irreversible", "high"),
    ("high", "minimal", "high"), ("high", "material", "high"), ("high", "irreversible", "high"),
    ("critical", "minimal", "high"), ("critical", "material", "high"), ("critical", "irreversible", "high"),
])
def test_every_criticality_and_wellbeing_cell(crit, wb, want):
    m = M.mission(crit, wb)
    assert m.value == want and not m.assumed and m.criticality == crit


def test_unset_criticality_is_assumed_medium_and_labelled():
    m = M.mission(None)
    assert m.assumed and m.criticality == "medium" and m.value == "medium"
    assert "criticality not set -- assumed medium" in m.text()


# ------------------------------------------------------------------ inputs
CISA_ROW = {"exploitation": "poc", "automatable": "no", "technical_impact": "total",
            "assessed_at": "2024-07-02T13:18:34Z"}


def test_cisa_values_are_used_with_their_date():
    ci = I.for_cve("CVE-2024-6387", cisa=CISA_ROW, kev=None, cvss={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert ci.exploitation == I.Input("poc", I.CISA, "2024-07-02T13:18:34Z")
    assert ci.automatable.value == "no" and ci.automatable.source == I.CISA      # CISA wins over the CVSS estimate
    assert ci.technical_impact.source == I.CISA


def test_kev_makes_exploitation_active_even_over_an_older_cisa_assessment():
    ci = I.for_cve("CVE-2024-6387", cisa=CISA_ROW, kev={"date_added": "2024-07-10", "known_ransomware": "Known"},
                   cvss=None)
    assert ci.exploitation.value == "active" and ci.exploitation.source == I.KEV and "said poc" in ci.exploitation.note
    assert ci.ransomware and ci.kev


def test_no_cisa_entry_estimates_from_cvss_and_says_so():
    ci = I.for_cve("CVE-2026-0001", cisa=None, kev=None,
                   cvss={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, epss=0.7)
    assert ci.exploitation == I.Input("none", I.NOT_ASSESSED, "", ci.exploitation.note)   # never guessed from EPSS
    assert ci.automatable.value == "yes" and ci.automatable.source == I.ESTIMATE
    assert ci.technical_impact.value == "total" and ci.technical_impact.source == I.ESTIMATE
    assert ci.epss == 0.7 and ci.enough


@pytest.mark.parametrize("vector,auto,impact", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "yes", "total"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "no", "total"),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "no", "partial"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "no", "total"),        # scope changed with high impact
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", "no", "partial"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "yes", "total"),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N", "no", "partial"),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "yes", "total"),
])
def test_cvss_estimate_rule(vector, auto, impact):
    assert I.estimate_automatable(vector) == auto
    assert I.estimate_technical_impact(vector) == impact


def test_no_cvss_and_no_cisa_is_not_enough_data_never_an_outcome():
    ci = I.for_cve("CVE-2026-0002", cisa=None, kev={"date_added": "2026-01-01"}, cvss=None)
    d = D.decide(ci, M.mission("high"))
    assert d.outcome is None and d.label == "not enough data (Exploitation: active)"
    s = D.for_finding([ci], M.mission("high"))
    assert s["outcome"] is None and s["label"].startswith("not enough data") and s["tree"] == T.TREE_VERSION


# ------------------------------------------------------------------ decision
def test_finding_takes_its_worst_cve_and_lists_each():
    kev = I.for_cve("CVE-2024-6387", cisa=None, kev={"date_added": "2024-07-10"},
                    cvss={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    quiet = I.for_cve("CVE-2023-0001", cisa={"exploitation": "none", "automatable": "no",
                                              "technical_impact": "partial", "assessed_at": "2024-01-01"},
                      kev=None, cvss=None)
    s = D.for_finding([quiet, kev], M.mission("high"))
    assert s["outcome"] == "act" and s["cve"] == "CVE-2024-6387" and s["label"] == "Act"
    assert [c["cve"] for c in s["cves"]] == ["CVE-2024-6387", "CVE-2023-0001"]
    assert s["counts"] == {"act": 1, "track": 1}
    assert set(s["inputs"]) == {"exploitation", "automatable", "technical_impact", "mission_wellbeing"}
    assert all(s["inputs"][k]["source"] for k in ("exploitation", "automatable", "technical_impact"))
    assert s["definition"].startswith("The vulnerability requires attention from supervisory and leadership")
    # the same CVE on a low-criticality machine: CISA's tree gives Attend, not Act
    assert D.for_finding([kev], M.mission("low"))["outcome"] == "attend"


def test_summary_words_name_estimates_and_assumptions():
    ci = I.for_cve("CVE-2026-0001", cisa=None, kev=None, cvss={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    words = D.summary_words(D.for_finding([ci], M.mission(None)))
    assert words == ("no known exploitation (not assessed), automatable (estimated from CVSS), total impact "
                     "(estimated from CVSS), mission medium (criticality not set -- assumed medium)")
