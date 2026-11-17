"""E.7b B.1 verifier (§3.12): REVIEW-001/002 re-check re-reads E.7a's stored inventory hash --
unchanged -> reproduced ("code unchanged since review"); changed/gone -> couldnt_check ("review it
again"); no new read, no model call."""
from __future__ import annotations


from kratos import authz
from kratos.code import roots as R
from kratos.code import store as CS
from kratos.review import store as RST
from kratos.review import triage as RT
from kratos.triage.context import VerifyContext

M = "192.0.2.200"
OWNER = authz.owner_actor("cli")
TK = None


def _setup(tmp_path, sha):
    from kratos.target_key import target_key
    global TK
    TK = target_key(M)
    R.add(tmp_path, M, "/srv/app", actor=OWNER)
    R.confirm(tmp_path, M, "/srv/app", actor=OWNER)
    root = CS.roots(tmp_path, M)[0]
    CS.replace_files(tmp_path, root["id"], "current", [{"relpath": "app.py", "size": 10, "sha256": sha}])
    run_id = RST.create_run(tmp_path, target_key=TK, machine=M, root="/srv/app", profile="p",
                            verifier_profile="p", destination="local", mask_mode="off", estimate_usd=0,
                            agreed_usd=0, est_calls=0, est_tokens=0, reproduction=False, logic_version="1")
    RST.add_slices(tmp_path, run_id, TK, [{"slice_sha": "deadbeef" * 8, "context_sha": "c", "file": "app.py",
                                           "span": (1, 5), "function": "ping", "class": "exec", "file_sha": sha}])
    return run_id


def _ctx(tmp_path):
    finding = {"id": "REVIEW-001", "target_key": TK, "subject": "/srv/app app.py exec",
               "entities": ["app.py:ping:exec", "deadbeefdeadbeef"]}
    return VerifyContext(finding=finding, target=M, data_dir=tmp_path)


def test_unchanged_code_reproduced(tmp_path):
    _setup(tmp_path, "a" * 64)
    v = RT._verify(_ctx(tmp_path))
    assert v.verdict == "reproduced" and "unchanged" in v.sentence


def test_changed_code_couldnt_check(tmp_path):
    _setup(tmp_path, "a" * 64)
    # the inventory now shows a different hash than the review recorded.
    root = CS.roots(tmp_path, M)[0]
    CS.replace_files(tmp_path, root["id"], "current", [{"relpath": "app.py", "size": 10, "sha256": "b" * 64}])
    v = RT._verify(_ctx(tmp_path))
    assert v.verdict == "couldnt_check" and "changed" in v.detail


def test_file_gone_couldnt_check(tmp_path):
    _setup(tmp_path, "a" * 64)
    root = CS.roots(tmp_path, M)[0]
    CS.replace_files(tmp_path, root["id"], "current", [])     # file removed from the inventory
    v = RT._verify(_ctx(tmp_path))
    assert v.verdict == "couldnt_check"
