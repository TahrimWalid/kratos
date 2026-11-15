"""E.7b review tables (kratos.review.store §5.2): runs, slices, candidates, and the
per-Kratos verdict cache. Fails on old code."""
from __future__ import annotations

from kratos.review import store as ST


def _run(dd, **kw):
    base = dict(target_key="tk1", machine="web1", root="/srv/flask", profile="local-qwen",
                verifier_profile="", destination="local", mask_mode="standard", estimate_usd=0.5,
                agreed_usd=2.0, est_calls=12, est_tokens=40000, reproduction=True, logic_version="v1")
    base.update(kw)
    return ST.create_run(dd, **base)


def test_run_roundtrip_and_counts(tmp_path):
    rid = _run(tmp_path)
    r = ST.get_run(tmp_path, rid)
    assert r["state"] == "running" and r["root"] == "/srv/flask" and r["reproduction"] == 1
    ST.finish_run(tmp_path, rid, state="done", actual_usd=0.37,
                  counts={"reviewed": 10, "cached": 2, "dropped_cap": 1})
    r = ST.get_run(tmp_path, rid)
    assert r["state"] == "done" and abs(r["actual_usd"] - 0.37) < 1e-9
    assert r["counts"]["dropped_cap"] == 1 and r["finished_at"] is not None


def test_runs_listing_filters(tmp_path):
    a = _run(tmp_path, root="/srv/flask")
    b = _run(tmp_path, root="/var/www", target_key="tk1")
    _run(tmp_path, target_key="tk2", root="/srv/flask")
    rows = ST.runs(tmp_path, "tk1")
    assert {x["id"] for x in rows} == {a, b}
    only = ST.runs(tmp_path, "tk1", root="/var/www")
    assert [x["id"] for x in only] == [b]


def test_slices_and_ledger_state(tmp_path):
    rid = _run(tmp_path)
    ST.add_slices(tmp_path, rid, "tk1", [
        {"slice_sha": "a" * 64, "context_sha": "c" * 64, "file": "app.py", "span": (5, 9),
         "function": "ping", "class": "exec", "exposure": "internet", "drift": True, "served": "executed",
         "part": 0, "nbytes": 120},
    ])
    rows = ST.slices(tmp_path, rid)
    assert len(rows) == 1 and rows[0]["drift"] == 1 and rows[0]["exposure"] == "internet"
    ST.set_ledger_state(tmp_path, rid, "a" * 64, "exec", "verdict_reached")
    assert ST.slices(tmp_path, rid)[0]["ledger_state"] == "verdict_reached"


def test_candidate_reason_capped(tmp_path):
    rid = _run(tmp_path)
    ST.add_candidate(tmp_path, rid, slice_sha="a" * 64, cls="exec", file="app.py", line=7,
                     reason="x" * 999, call_ids=["c1", "c2"])
    c = ST.candidates(tmp_path, rid)[0]
    assert len(c["reason"]) == 500 and c["line"] == 7


def test_verdict_cache_put_get_and_idempotent(tmp_path):
    key = "ckey-1"
    ST.put_verdict(tmp_path, cache_key=key, slice_sha="a" * 64, context_sha="c" * 64, cls="exec",
                   logic_version="v1", hunter_model="", verifier_model="", verdict="confirmed",
                   strength="direct", evidence="req -> os.system at L5", question="")
    v = ST.get_verdict(tmp_path, key)
    assert v["verdict"] == "confirmed" and v["strength"] == "direct"
    # Re-putting the same key updates in place, not a second row.
    ST.put_verdict(tmp_path, cache_key=key, slice_sha="a" * 64, context_sha="c" * 64, cls="exec",
                   logic_version="v1", hunter_model="", verifier_model="", verdict="needs_validation",
                   strength="", evidence="", question="reproduction is off")
    v = ST.get_verdict(tmp_path, key)
    assert v["verdict"] == "needs_validation"
    assert ST.get_verdict(tmp_path, "missing") is None


def test_fix_added_lines_capped(tmp_path):
    ST.put_verdict(tmp_path, cache_key="k2", slice_sha="a" * 64, context_sha="c" * 64, cls="exec",
                   logic_version="v1", hunter_model="m", verifier_model="m", verdict="confirmed",
                   strength="reproduced", evidence="canary reached", question="",
                   fix_words="use shlex.quote", fix_added="z" * 9999, fix_check="checked")
    v = ST.get_verdict(tmp_path, "k2")
    assert len(v["fix_added"]) == 4000 and v["fix_check"] == "checked"


def test_mark_stale_running(tmp_path):
    rid = _run(tmp_path)
    ST.mark_stale_running(tmp_path)
    assert ST.get_run(tmp_path, rid)["state"] == "incomplete"


def test_get_run_on_empty_dir(tmp_path):
    assert ST.get_run(tmp_path, 1) is None
    assert ST.runs(tmp_path, "tk1") == []
