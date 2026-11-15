"""E.7b prepare/plan (§3.2): slice -> enrich -> rank -> cache-split -> batch -> estimate -> a
plan held in memory with a TTL and a send-time hash recheck."""
from __future__ import annotations

import hashlib

from kratos.review import plan as PLAN
from kratos.review.profiles import ReviewProfile

APP = '''
import os, flask
app = flask.Flask(__name__)
@app.route("/ping")
def ping():
    host = flask.request.args.get("host")
    os.system("ping -c1 " + host)
    return "ok"
'''


def _profile():
    return ReviewProfile(name="local-model", model="local-model", base_url="http://127.0.0.1:11434/v1",
                         api_key="x", local=True)


def _build(tmp_path, *, git_status=None, serving=None, now=0.0, fresh=False):
    sha = hashlib.sha256(APP.encode()).hexdigest()
    files = {"app.py": {"status": "ok", "data": APP.encode(), "sha256": sha}}
    return PLAN.build_plan(
        tmp_path, machine="m1", target_key="tk1", root="/srv/app", root_id=1, files=files,
        read_info={"via": "ssh"}, file_hashes={"app.py": sha}, all_sizes={"app.py": len(APP)},
        git_status=git_status or {}, serving_cfg=None, open_advisories=[], local_addresses=[],
        root_serving=serving or [{"address": "203.0.113.1", "pid": 9}], profile=_profile(),
        verifier=None, mask_mode="off", reproduction=True, window_tokens=32000, fresh=fresh, now=now)


def test_slices_and_enrichment(tmp_path):
    plan = _build(tmp_path, git_status={"app.py": "modified"})
    assert plan.to_review, "a route reaching os.system should slice"
    sl = plan.to_review[0]
    assert sl.drift is True                       # app.py is modified on the server
    assert sl.served == "executed"                # a route handler
    assert sl.exposure == "internet"              # serving on a public address
    assert plan.estimate.hunter_calls >= 1
    summary = plan.consent_summary()
    assert summary["slices_to_send"] == len(plan.to_review)
    assert summary["destination"] == "local"
    assert "Secrets are always removed" in summary["line"]
    assert summary["reproduction"] is True


def test_reduction_measured(tmp_path):
    plan = _build(tmp_path)
    assert plan.reduction() > 0


def test_ttl_expiry(tmp_path):
    plan = _build(tmp_path, now=1000.0)
    assert PLAN.get_plan(plan.plan_id, now=1000.0) is plan
    # default review.plan_ttl_minutes = 10 -> expires at 1600s.
    assert PLAN.get_plan(plan.plan_id, now=1000.0 + 11 * 60) is None


def test_hash_recheck_drops_changed(tmp_path):
    plan = _build(tmp_path)
    sha = plan.file_hashes["app.py"]
    kept, dropped = PLAN.recheck_hashes(plan, {"app.py": sha})
    assert dropped == 0 and len(kept) == len(plan.to_review)
    kept2, dropped2 = PLAN.recheck_hashes(plan, {"app.py": "changed"})
    assert kept2 == [] and dropped2 == len(plan.to_review)


def test_cache_split(tmp_path):
    from kratos.review import cache as CACHE
    from kratos.review.verdict import Verdict
    plan = _build(tmp_path)
    sl = plan.to_review[0]
    CACHE.store_verdict(tmp_path, Verdict("rejected", question="guarded"), slice_sha=sl.sha256,
                        context_sha=sl.context_sha256, cls=sl.cls, hunter_model="local-model",
                        verifier_model="local-model")
    plan2 = _build(tmp_path)
    assert any(c["slice"].sha256 == sl.sha256 for c in plan2.cached)
    assert all(s.sha256 != sl.sha256 for s in plan2.to_review)
    # --fresh ignores the cache.
    plan3 = _build(tmp_path, fresh=True)
    assert any(s.sha256 == sl.sha256 for s in plan3.to_review)
