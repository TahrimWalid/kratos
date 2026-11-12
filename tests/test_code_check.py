"""E.7a end to end on real folders: the code check over both transports (the real SSH scripts run
locally, the real agent functions), CODE-001..006 and their severities, the no-git baseline,
deploy grouping and accept-state, and that a secret's value is stored nowhere."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from kratos.adapters import code_facts as CF
from kratos.code import record as REC
from kratos.code import roots as R
from kratos.code import store as S
from kratos.lifecycle.decide import Actor

FIX = Path(__file__).parent / "fixtures" / "gitread"
M = "192.0.2.30"
OWNER = Actor(user="owner", interface="cli", user_id="owner")
# built at test time so no secret-shaped literal sits in the repository
SECRET_AWS = "AKIA" + "Q" * 4 + "EXAMPLE" + "7" * 5
SECRET_PW = "pw-" + "planted" + "-4f2a91c3"


@pytest.fixture(autouse=True)
def _tmp_allowed(monkeypatch):
    monkeypatch.setattr(CF, "NEVER_UNDER", tuple(x for x in CF.NEVER_UNDER if x != "/tmp"))


def ssh_run(script: str) -> str:
    return subprocess.run(["sh", "-s"], input=script.encode(), capture_output=True, timeout=120,
                          env={"PATH": os.environ["PATH"], "LC_ALL": "C"}).stdout.decode("utf-8", "replace")


class Transport:
    """The two ways a read reaches Kratos, over real local folders."""

    def __init__(self, kind: str):
        self.kind = kind
        self.reads: list[tuple[str, int]] = []

    def inv(self, raw: bytes, **kw):
        if self.kind == "ssh":
            out = CF.parse_inventory(ssh_run(CF.build_inventory_script(raw, max_files=kw["max_files"],
                                                                       max_depth=kw["max_depth"], seconds=kw["seconds"],
                                                                       skip=kw["skip"])))
        else:
            out = CF.parse_inventory(CF.inventory_output(raw, max_files=kw["max_files"], max_depth=kw["max_depth"],
                                                         seconds=kw["seconds"], skip=kw["skip"])["stdout"])
        out["via"] = self.kind
        return out

    def read(self, raw: bytes, purpose: str, paths: list[bytes], *, budget_bytes: int):
        self.reads.append((purpose, len(paths)))
        if self.kind == "ssh":
            out = CF.parse_read(ssh_run(CF.build_read_script(raw, purpose, paths, budget_bytes=budget_bytes)), len(paths))
        else:
            out = CF.parse_read(CF.read_output(raw, purpose, paths, budget_bytes=budget_bytes)["stdout"], len(paths))
        out["via"] = self.kind
        return out


def nginx_facts(root: Path) -> dict:
    conf = (f"http {{ server {{ listen 80; root {root}; location ~ \\.php$ {{ fastcgi_pass unix:/run/php.sock; }} "
            f"location ~ /\\.git {{ deny all; }} }} }}")
    return {"configs": {"/etc/nginx/nginx.conf": {"status": "ok", "text": conf}}, "units": {}, "complete": True,
            "via": "ssh"}


def setup_root(dd: Path, root: Path) -> None:
    REC.run_roots(dd, M, fetch=lambda: nginx_facts(root), live={"listeners": []}, containers={})
    R.add(dd, M, str(root), actor=OWNER)


def run(dd: Path, t: Transport, scanner=None) -> dict:
    return REC.run_code(dd, M, fetch_inv=t.inv, fetch_read=t.read, scanner=scanner or (lambda root: []))


def sigs(doc: dict, rule: str) -> list[dict]:
    return [s for s in doc["signals"] if s["rule"] == rule]


def extract(tmp: Path, name: str, dest: str) -> Path:
    with tarfile.open(FIX / "repos.tar.gz") as tar:
        tar.extractall(tmp / "x", filter="tar")
    target = tmp / dest
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(tmp / "x" / name), target)
    return target


# ----------------------------------------------------------------------------- git drift
@pytest.mark.parametrize("kind", ["ssh", "agent"])
def test_ignored_but_served_shell_and_modified_file(tmp_path, kind):
    dd = tmp_path / "data"
    root = extract(tmp_path, "ignored_served_shell", "srv/shop")
    (root / "index.php").write_text("<?php edited on the server;\n")
    setup_root(dd, root)
    doc = run(dd, Transport(kind))
    c1 = sigs(doc, "CODE-001")
    assert [s["subject"].split("|")[1] for s in c1] == ["uploads/cmd.php"] and c1[0]["severity"] == "high"
    c2 = {s["subject"].split("|")[1]: s for s in sigs(doc, "CODE-002")}
    assert c2["index.php"]["severity"] == "high"                  # an executed served script
    assert all("uploads/avatar.png" not in s["subject"] for s in doc["signals"])
    assert doc["roots"][0]["git"]["head"]["commit"]
    assert all("CODE" not in s["title"] and str(root) not in s["title"] for s in doc["signals"])   # no machine text


@pytest.mark.parametrize("kind", ["ssh", "agent"])
def test_staged_shell(tmp_path, kind):
    dd = tmp_path / "data"
    root = extract(tmp_path, "staged_new", "srv/app")
    setup_root(dd, root)
    doc = run(dd, Transport(kind))
    c2 = {s["subject"].split("|")[1]: s for s in sigs(doc, "CODE-002")}
    assert c2["uploads/s.php"]["severity"] == "high"
    assert "never committed" in " ".join(c2["uploads/s.php"]["evidence"])


def test_gitdir_outside_root(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "wt"
    root.mkdir(parents=True)
    (root / ".git").write_text("gitdir: /opt/elsewhere/.git/worktrees/wt\n")
    (root / "a.php").write_text("<?php 1;\n")
    setup_root(dd, root)
    doc = run(dd, Transport("agent"))
    assert any("pointing to git metadata outside this folder" in g for g in doc["coverage_gaps"])
    assert doc["roots"][0]["baseline"]["first"]                  # compared with Kratos's own baseline instead


def test_index_corrupt_fallback(tmp_path):
    dd = tmp_path / "data"
    root = extract(tmp_path, "clean", "srv/c")
    (root / ".git" / "index").write_bytes(b"DIRC\x00\x00\x00\x09\x00\x00\x00\x00" + b"\x00" * 20)
    setup_root(dd, root)
    doc = run(dd, Transport("ssh"))
    assert any("git index not readable (version 9)" in g for g in doc["coverage_gaps"])
    assert doc["roots"][0]["baseline"]["first"]


# ----------------------------------------------------------------------------- no git
def test_deploy_grouping_and_accept(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "plain"
    (root / "web").mkdir(parents=True)
    (root / "web" / "index.php").write_text("<?php 1;\n")
    setup_root(dd, root)
    t = Transport("agent")
    first = run(dd, t)
    assert first["roots"][0]["baseline"]["first"] and not sigs(first, "CODE-001")
    (root / "web" / "shell.php").write_text("<?php // fixture\n")
    (root / "web" / "index.php").write_text("<?php 2;\n")
    doc = run(dd, t)
    assert sigs(doc, "CODE-001")[0]["severity"] == "high"
    assert sigs(doc, "CODE-002")[0]["severity"] == "high"
    for i in range(30):
        (root / "web" / f"page{i}.php").write_text(f"<?php {i};\n")
    doc = run(dd, t)
    grouped = sigs(doc, "CODE-002")
    assert len(grouped) == 1 and grouped[0]["subject"].endswith("|*") and not sigs(doc, "CODE-001")
    R.accept_state(dd, M, str(root), actor=OWNER)
    doc = run(dd, t)
    assert not sigs(doc, "CODE-001") and not sigs(doc, "CODE-002")
    assert [e["kind"] for e in S.events(dd, S.roots(dd, M)[0]["id"])][-1] == "accepted_state"


def test_root_gone_and_unreadable(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "gone"
    root.mkdir(parents=True)
    setup_root(dd, root)
    root.rmdir()
    doc = run(dd, Transport("ssh"))
    assert any("no longer there" in g for g in doc["coverage_gaps"]) and sigs(doc, "CODE-006")
    assert S.roots(dd, M)[0]["gone_since"] is not None
    assert not doc["complete"]


def test_unreadable_root_wording(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "locked"
    root.mkdir(parents=True)
    setup_root(dd, root)

    def inv(raw, **kw):
        return CF.parse_inventory("R\tunreadable\t-\t-\t-\t-\nEND\n")
    doc = REC.run_code(dd, M, fetch_inv=inv, fetch_read=None, scanner=lambda r: [])
    assert any("this login can't read the folder -- the sub-agent can" in g for g in doc["coverage_gaps"])


def test_old_agent_degrades(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult

    dd = tmp_path / "data"
    root = tmp_path / "srv" / "o"
    root.mkdir(parents=True)
    setup_root(dd, root)
    old = SSHResult(ok=False, returncode=-1, stdout="", via="subagent", stderr=(
        "via the sub-agent: this box runs sub-agent 0.13.0; the code_inventory read needs 0.14.0 or newer -- update "
        "the agent (`g` in /subagent, select the box)."))
    doc = REC.run_code(dd, M, fetch_inv=lambda raw, **kw: old, fetch_read=None, scanner=lambda r: [])
    assert any("too old for code checks -- update the agent" in g for g in doc["coverage_gaps"])
    assert doc["roots"][0]["status"] == "old_agent"


def test_unconfirmed_candidates_are_listed_never_read(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "cand"
    root.mkdir(parents=True)
    REC.run_roots(dd, M, fetch=lambda: nginx_facts(root), live={"listeners": []}, containers={})
    t = Transport("ssh")
    called = []
    doc = REC.run_code(dd, M, fetch_inv=lambda raw, **kw: called.append(raw), fetch_read=t.read, scanner=None)
    assert called == [] and t.reads == []
    assert any("no person has confirmed" in g for g in doc["coverage_gaps"])


# ----------------------------------------------------------------------------- secrets, deps, yara
def test_secret_never_stored(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "s"
    (root / "web").mkdir(parents=True)
    (root / "web" / "config.js").write_text(f'const k = "{SECRET_AWS}";\n')
    (root / ".env").write_text(f"DB_PASSWORD={SECRET_PW}\nAPI_KEY={SECRET_PW}\n")
    (root / "web" / "server.pem").write_text("not read\n")
    setup_root(dd, root)
    doc = run(dd, Transport("ssh"))
    c4 = {s["subject"].split("|")[1]: s for s in sigs(doc, "CODE-004")}
    assert c4["web/config.js"]["severity"] == "high"              # served as a static file
    assert c4[".env"]["severity"] == "high"                       # the whole folder is served: .env is downloadable
    fps = [e.split("#")[1] for e in c4[".env"]["entities"]]
    assert len(fps) == 2 and fps[0] == fps[1]                     # the same secret twice: one fingerprint
    assert "private-key file" in " ".join(c4["web/server.pem"]["evidence"])
    # the value is nowhere: result file, database, evidence ledger
    blobs = [Path(doc["file"]).read_bytes()]
    for p in dd.rglob("*"):
        if p.is_file():
            blobs.append(p.read_bytes())
    for b in blobs:
        assert SECRET_AWS.encode() not in b and SECRET_PW.encode() not in b
    conn = sqlite3.connect(dd / "kratos.db")
    dump = "\n".join(conn.iterdump())
    conn.close()
    assert SECRET_AWS not in dump and SECRET_PW not in dump


def test_yara_match_and_scan_gap(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "y"
    root.mkdir(parents=True)
    (root / "eicar.txt").write_text("x\n")
    setup_root(dd, root)
    doc = run(dd, Transport("agent"), scanner=lambda r: [{"file": f"{r}/eicar.txt", "rule": "EICAR_Test_File"}])
    c5 = sigs(doc, "CODE-005")
    assert c5 and c5[0]["severity"] == "high" and c5[0]["subject"].endswith("|eicar.txt")
    doc = run(dd, Transport("agent"), scanner=lambda r: "YARA not run: the yara program is not installed")
    assert any("yara program is not installed" in g for g in doc["coverage_gaps"])


def test_vulnerable_dependency_and_missing_ecosystem(tmp_path):
    dd = tmp_path / "data"
    root = tmp_path / "srv" / "d"
    root.mkdir(parents=True)
    (root / "requirements.txt").write_text("flask==2.0.1\n")
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/lodash": {"version": "4.17.20"}}}))
    setup_root(dd, root)
    from tests.test_code_deps import _rec
    from kratos.pkgvuln import index as I
    from kratos.pkgvuln import update as U
    from kratos.pkgvuln.ecosystems import parse_selector

    path = I.path_for(dd)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    I.create_schema(conn)
    U._Writer(conn, [parse_selector("pypi")]).apply("PyPI", _rec(
        "PYSEC-2021-1", "PyPI", "Flask", [{"introduced": "0"}, {"fixed": "2.0.2"}], kind="ECOSYSTEM"))
    conn.execute("INSERT OR REPLACE INTO info (key, value) VALUES ('built_at', ?)", (json.dumps(time.time()),))
    conn.commit()
    conn.close()
    doc = run(dd, Transport("ssh"))
    c3 = sigs(doc, "CODE-003")
    assert len(c3) == 1 and c3[0]["entities"] == ["PYSEC-2021-1"] and c3[0]["subject"].endswith("|PyPI:flask")
    assert any("npm advisories not downloaded: `kratos vulndb-update --for-roots`" in g for g in doc["coverage_gaps"])
    assert S.ecosystems_seen(dd) == ["PyPI", "npm"]
