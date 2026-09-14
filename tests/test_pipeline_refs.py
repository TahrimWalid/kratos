"""A2 Piece C -- bounded step-output threading (agent/pipeline_refs.py).

Security-boundary + logic coverage: references are STRUCTURED objects (never a
string template / eval), validated against a whitelist at save time and resolved
fail-safe at run time.
"""
from __future__ import annotations

import pytest

from kratos.agent import pipeline_refs as R
from kratos.agent.pipeline import PipelineStep, StepResult
from kratos.agent.tools import TOOL_REGISTRY


# --------------------------------------------------------------------------- #
# Shape helpers
# --------------------------------------------------------------------------- #
def test_is_reference():
    assert R.is_reference({"from": "c", "field": "top_source_ip"})
    assert not R.is_reference("1.2.3.4")
    assert not R.is_reference({"from": "c"})            # missing field
    assert not R.is_reference({"field": "x"})           # missing from
    assert not R.is_reference(3)


def test_normalize_reference_and_bad_shapes():
    assert R.normalize_reference({"from": " c ", "field": " ip ", "select": "first"}) == {
        "from": "c", "field": "ip", "select": "first"}
    with pytest.raises(R.RefError):
        R.normalize_reference({"from": "", "field": "x"})
    with pytest.raises(R.RefError):
        R.normalize_reference({"from": "c", "field": 5})
    with pytest.raises(R.RefError):
        R.normalize_reference({"from": "c", "field": "x", "select": "middle"})


def test_describe_reference_plain_language():
    d = R.describe_reference({"from": "correlate", "field": "top_source_ip"})
    assert "top source IP" in d and "correlate" in d and "{" not in d
    d2 = R.describe_reference({"from": "c", "field": "finding_ids", "select": "first"})
    assert "first match" in d2


# --------------------------------------------------------------------------- #
# Extractors (grounded in the REAL result shapes)
# --------------------------------------------------------------------------- #
def test_extractors_read_real_result_shapes():
    correlate = {"findings": [
        {"id": "CORR-SSH-001", "severity": "high", "source_ips": ["203.0.113.7", "198.51.100.2"]},
        {"id": "NET-002", "severity": "medium"}], "count": 2}
    fw = R.FIELD_WHITELIST["correlate_findings"]
    assert fw["top_source_ip"].extract(correlate) == "203.0.113.7"
    assert fw["finding_count"].extract(correlate) == 2
    assert fw["worst_severity"].extract(correlate) == "high"
    assert fw["finding_ids"].extract(correlate) == ["CORR-SSH-001", "NET-002"]
    # nmap
    nfw = R.FIELD_WHITELIST["run_nmap_scan"]
    assert nfw["open_port_count"].extract({"open_ports_total": 3}) == 3
    assert nfw["host_count"].extract({"host_count": 1}) == 1
    # missing -> None (fail-safe upstream)
    assert fw["top_source_ip"].extract({"findings": [{"id": "x"}]}) is None


def test_top_source_ip_field_validates_ip():
    spec = R.FIELD_WHITELIST["correlate_findings"]["top_source_ip"]
    assert spec.validate("8.8.8.8") is True
    assert spec.validate("not an ip!!") is False


# --------------------------------------------------------------------------- #
# Save-time validation
# --------------------------------------------------------------------------- #
_PRIOR = [("correlate", "correlate_findings")]  # one prior step labeled 'correlate'


def _validate(ref, prior=_PRIOR, tool="check_ip_reputation", arg="ip"):
    R.validate_reference(R.normalize_reference(ref), prior_steps=prior,
                         consumer_tool=tool, consumer_arg=arg, registry=TOOL_REGISTRY)


def test_validate_ok_scalar_pair():
    _validate({"from": "correlate", "field": "top_source_ip"})  # no raise


def test_validate_by_index():
    _validate({"from": "1", "field": "top_source_ip"})


def test_validate_forward_or_unknown_from_rejected():
    with pytest.raises(R.RefError):
        _validate({"from": "later", "field": "top_source_ip"})
    with pytest.raises(R.RefError):
        _validate({"from": "2", "field": "top_source_ip"})       # no 2nd prior step


def test_validate_unknown_field_rejected():
    with pytest.raises(R.RefError):
        _validate({"from": "correlate", "field": "nope"})


def test_validate_type_mismatch_rejected():
    with pytest.raises(R.RefError):
        _validate({"from": "correlate", "field": "finding_count"})   # int -> str ip


def test_validate_list_to_scalar_requires_select():
    with pytest.raises(R.RefError):
        _validate({"from": "correlate", "field": "finding_ids"})     # list -> scalar, no select
    _validate({"from": "correlate", "field": "finding_ids", "select": "first"})  # ok


def test_validate_ambiguous_label_rejected():
    prior = [("dup", "correlate_findings"), ("dup", "run_nmap_scan")]
    with pytest.raises(R.RefError):
        R.validate_reference(R.normalize_reference({"from": "dup", "field": "top_source_ip"}),
                             prior_steps=prior, consumer_tool="check_ip_reputation",
                             consumer_arg="ip", registry=TOOL_REGISTRY)


def test_validate_registry_none_skips_type_check():
    # Without a registry, structural checks still run but the consumer-type check
    # is deferred (save uses the registry; load does not).
    R.validate_reference(R.normalize_reference({"from": "correlate", "field": "finding_count"}),
                         prior_steps=_PRIOR, consumer_tool="check_ip_reputation",
                         consumer_arg="ip", registry=None)  # no raise (type check skipped)


def test_compatible_fields_for_ip_arg():
    fields = dict((f, needs) for f, _l, needs in R.compatible_fields("str", "correlate_findings"))
    assert "top_source_ip" in fields and fields["top_source_ip"] is False
    assert "worst_severity" in fields
    assert fields.get("finding_ids") is True         # list[str] -> scalar str needs first
    assert "finding_count" not in fields             # int, not str
    assert R.compatible_fields("str", "run_nmap_scan") == []  # nmap exposes only ints


# --------------------------------------------------------------------------- #
# Run-time resolution (fail-safe)
# --------------------------------------------------------------------------- #
def _result(tool, label, status="ok", result=None):
    return StepResult(step=PipelineStep(tool=tool, label=label), status=status, result=result or {})


def test_resolve_success_by_label_and_index():
    results = [_result("correlate_findings", "correlate",
                       result={"findings": [{"id": "X", "severity": "high", "source_ips": ["9.9.9.9"]}]})]
    ok, val, reason = R.resolve_reference({"from": "correlate", "field": "top_source_ip"}, results)
    assert ok and val == "9.9.9.9" and reason is None
    ok2, val2, _ = R.resolve_reference({"from": "1", "field": "top_source_ip"}, results)
    assert ok2 and val2 == "9.9.9.9"


def test_resolve_producer_not_ok_fails_safe():
    results = [_result("correlate_findings", "correlate", status="skipped")]
    ok, val, reason = R.resolve_reference({"from": "correlate", "field": "top_source_ip"}, results)
    assert not ok and val is None and "wasn't produced" in reason


def test_resolve_missing_value_fails_safe():
    results = [_result("correlate_findings", "correlate", result={"findings": [{"id": "x"}]})]
    ok, _v, reason = R.resolve_reference({"from": "correlate", "field": "top_source_ip"}, results)
    assert not ok and "no 'top_source_ip'" in reason


def test_resolve_invalid_ip_value_fails_safe():
    results = [_result("correlate_findings", "correlate",
                       result={"findings": [{"id": "x", "source_ips": ["garbage!!"]}]})]
    ok, _v, reason = R.resolve_reference({"from": "correlate", "field": "top_source_ip"}, results)
    assert not ok and "isn't valid" in reason


def test_resolve_list_select_first():
    results = [_result("correlate_findings", "correlate",
                       result={"findings": [{"id": "A"}, {"id": "B"}]})]
    ok, val, _ = R.resolve_reference({"from": "correlate", "field": "finding_ids", "select": "first"}, results)
    assert ok and val == "A"


def test_resolve_step_args_mixes_literals_and_refs():
    results = [_result("correlate_findings", "correlate",
                       result={"findings": [{"id": "x", "source_ips": ["1.1.1.1"]}]})]
    resolved, skip = R.resolve_step_args(
        {"ip": {"from": "correlate", "field": "top_source_ip"}, "extra": "literal"}, results)
    assert skip is None and resolved == {"ip": "1.1.1.1", "extra": "literal"}


def test_resolve_step_args_skips_on_unresolved():
    results = [_result("correlate_findings", "correlate", status="error")]
    resolved, skip = R.resolve_step_args({"ip": {"from": "correlate", "field": "top_source_ip"}}, results)
    assert resolved is None and skip and "wasn't produced" in skip
