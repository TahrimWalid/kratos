"""E.7a security review: the root-run sub-agent's code reads can't be pointed at an arbitrary
folder or at a credential store. Before the fix a core (or anyone holding the link) could send
`code_inventory root=/home/<user>` and then `code_read purpose=secrets paths=[.aws/credentials]`
and get the file back."""
from __future__ import annotations

import base64
import hashlib
import os
import struct

import pytest

from kratos.adapters import code_facts as CF
from kratos.code import gitread as G
from kratos.subagent import reads as R

_REAL_LISTENER_CWDS = getattr(R, "_code_listener_cwds", None)


def b(v: str) -> str:
    return base64.b64encode(v.encode()).decode()


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.setattr(CF, "NEVER_UNDER", tuple(x for x in CF.NEVER_UNDER if x != "/tmp"))
    monkeypatch.setattr(R, "CODE_ROOTS_FILE", str(tmp_path / "no-such-code-roots"), raising=False)
    monkeypatch.setattr(R, "_code_config_paths", lambda: set(), raising=False)
    monkeypatch.setattr(R, "_code_listener_cwds", lambda: set(), raising=False)
    monkeypatch.setattr(R, "_CODE_EVIDENCE", [0.0, frozenset()], raising=False)
    monkeypatch.setattr(R, "_CODE_MOUNTS", {}, raising=False)
    R._CODE_LISTED.clear()
    yield
    R._CODE_LISTED.clear()


def _home(tmp_path):
    home = tmp_path / "home" / "alice"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text("[default]\n")
    (home / ".docker").mkdir()
    (home / ".docker" / "config.json").write_text("{}\n")
    (home / "notes.txt").write_text("private\n")
    (home / ".netrc").write_text("machine x\n")
    return home


@pytest.mark.parametrize("rel", [".aws/credentials", ".docker/config.json", "app/.kube/config", "web/.ssh/config",
                                 "x/.gnupg/pubring.txt", ".netrc", "app/.pgpass", ".git-credentials", ".my.cnf",
                                 "secrets/db.txt", "a/.config/gcloud/credentials.db"])
@pytest.mark.parametrize("purpose", list(CF.PURPOSES))
def test_a_credential_store_is_never_read_for_any_purpose(rel, purpose):
    assert CF.is_credential_rel(rel.encode())
    assert CF.purpose_allows(purpose, rel.encode(), 10) is not None


def test_app_settings_files_are_still_scanned():
    for rel in (".env", "wp-config.php", "config/settings.py", "app/.npmrc"):
        assert not CF.is_credential_rel(rel.encode())
        assert CF.purpose_allows("secrets", rel.encode(), 10) is None


def test_the_reported_exploit_is_refused(tmp_path):
    home = _home(tmp_path)
    inv = R.run_probe("code_inventory", {"root": b(str(home))})
    assert inv["status"] == "refused" and "code-roots" in inv["reason"]
    req = {"root": b(str(home)), "purpose": "secrets",
           "paths": [b(".aws/credentials"), b(".docker/config.json"), b("notes.txt")]}
    got = R.run_probe("code_read", req)
    out = got["data"]["stdout"] if got["status"] == "ok" else got["reason"]
    assert "\tok\t" not in out and "W2RlZmF1bHRd" not in out           # base64 of "[default]" never sent


def test_even_an_allowed_root_never_lists_or_reads_its_credential_stores(tmp_path, monkeypatch):
    home = _home(tmp_path)
    allow = tmp_path / "code-roots"
    allow.write_text(f"# the admin's list\n{home}\n")
    allow.chmod(0o644)
    monkeypatch.setattr(R, "CODE_ROOTS_FILE", str(allow), raising=False)
    inv = R.run_probe("code_inventory", {"root": b(str(home))})
    assert inv["status"] == "ok", inv
    parsed = CF.parse_inventory(inv["data"]["stdout"])
    assert set(parsed["files"]) == {"notes.txt"}
    assert {s["path"] for s in parsed["skipped"] if s["reason"] == "credential"} == {".aws", ".docker", ".netrc"}
    got = R.run_probe("code_read", {"root": b(str(home)), "purpose": "secrets",
                                    "paths": [b(".aws/credentials"), b(".netrc")]})
    out = got.get("data", {}).get("stdout", "") if got["status"] == "ok" else got["reason"]
    assert "W2RlZmF1bHRd" not in out and "\tok\t" not in out


def test_an_untrusted_code_roots_file_is_ignored(tmp_path, monkeypatch):
    home = _home(tmp_path)
    allow = tmp_path / "code-roots"
    allow.write_text(f"{home}\n")
    allow.chmod(0o666)
    monkeypatch.setattr(R, "CODE_ROOTS_FILE", str(allow), raising=False)
    got = R.run_probe("code_inventory", {"root": b(str(home))})
    assert got["status"] == "refused" and "writable by group or others" in got["reason"]
    allow.chmod(0o644)
    assert R.load_code_roots_file(str(allow)) == ([str(home)], [])
    allow.write_text("/etc\n/\nrelative/path\n")
    paths, problems = R.load_code_roots_file(str(allow))
    assert paths == [] and len(problems) == 3


def test_config_evidence_allows_the_folder_and_inside_it_not_its_parent(tmp_path, monkeypatch):
    app = tmp_path / "srv" / "app"
    (app / "public").mkdir(parents=True)
    monkeypatch.setattr(R, "_code_config_paths", lambda: {str(app)})   # e.g. `root /srv/app;`
    assert R.code_root_refusal(str(app)) is None
    assert R.code_root_refusal(str(app / "public")) is None
    assert R.code_root_refusal(str(app.parent)) is not None
    assert R.code_root_refusal(str(tmp_path / "srv" / "app2")) is not None    # a prefix is not "inside"


def test_config_path_tokens(tmp_path, monkeypatch):
    text = ('server {\n  root /srv/site/public;\n  # root /srv/commented;\n  location / { proxy_pass '
            'http://127.0.0.1:8000/x; }\n  include /etc/nginx/x.conf;\n}\n')
    found = set()
    for line in text.splitlines():
        if not line.lstrip().startswith("#"):
            found.update(R._CODE_PATH_RE.findall(line))
    clean = {p for p in (R._code_clean(x) for x in found) if p}
    assert clean == {"/srv/site/public"}


def test_container_mount_evidence(tmp_path):
    src = tmp_path / "srv" / "compose" / "html"
    src.mkdir(parents=True)
    R._CODE_MOUNTS[str(src)] = __import__("time").time()
    assert R.code_root_refusal(str(src)) is None


def test_listener_working_folders_from_proc(tmp_path):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (proc / "net" / "tcp").write_text(hdr + "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 "
                                      "00000000  1000        0 4242 1 0000 100 0 0 10 0\n"
                                      "   1: 00000000:0016 0A000001:C350 01 00000000:00000000 00:00000000 "
                                      "00000000  1000        0 5151 1 0000 100 0 0 10 0\n")
    for pid, ppid, cwd, sock in (("100", "1", "/srv/node-app", "4242"), ("200", "100", "/srv/child", None),
                                 ("300", "1", "/home/alice", "5151")):
        d = proc / pid
        (d / "fd").mkdir(parents=True)
        (d / "stat").write_text(f"{pid} (x) S {ppid} 0 0\n")
        os.symlink(cwd, d / "cwd")
        if sock:
            os.symlink(f"socket:[{sock}]", d / "fd" / "3")
    (proc / "1" / "fd").mkdir(parents=True)
    (proc / "1" / "stat").write_text("1 (init) S 0 0 0\n")
    os.symlink("/srv/init-cwd", proc / "1" / "cwd")
    # 4242 listens: pid 100's folder and its parent's (pid 1); 5151 is an outgoing connection
    assert _REAL_LISTENER_CWDS(proc=str(proc)) == {"/srv/node-app", "/srv/init-cwd"}


def _index(entries):
    body = b"DIRC" + struct.pack(">II", 2, len(entries))
    for path, oid in entries:
        e = struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 1) + oid + struct.pack(">H", len(path))
        e += path.encode() + b"\x00"
        while len(e) % 8:
            e += b"\x00"
        body += e
    return body + hashlib.sha1(body).digest()


def test_a_tracked_credential_file_the_walk_left_out_is_not_called_deleted():
    oid = bytes.fromhex(G.blob_id(b"x\n", "sha1"))
    src = G.DictSource({"HEAD": b"ref: refs/heads/main\n", "config": b"",
                        "index": _index([(".netrc", oid), ("app.py", oid)])})
    recs = CF.compute_git(src, {"app.py": (0o100644, oid.hex())}, {}, {}, [".netrc"], complete_walk=True,
                          max_files=100, max_pack_bytes=1 << 20)
    assert not any(r.startswith("D\tdeleted") for r in recs), recs
    recs = CF.compute_git(src, {"app.py": (0o100644, oid.hex())}, {}, {}, [], complete_walk=True,
                          max_files=100, max_pack_bytes=1 << 20)
    assert any(r.startswith("D\tdeleted") and ".netrc" in r for r in recs), recs   # without the skip: "deleted"
