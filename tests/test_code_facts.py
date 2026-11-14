"""E.7a reads (`code_roots_facts`, `code_inventory`, `code_read`): the SSH scripts (GNU tools
with gawk / mawk / BusyBox awk, and a full BusyBox userland) and the agent's reads print the
same records; nothing is followed, executed or read outside the closed rules."""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from kratos.adapters import code_facts as CF
from tests._logsources_util import awks

AWKS = awks()
TOOLS = ("sh", "base64", "date", "id", "stat", "grep", "head", "find", "sha256sum", "sha1sum", "cat", "readlink",
         "tr", "wc", "ls", "xargs", "printf", "pwd", "cut", "sort")
FIX = Path(__file__).parent / "fixtures" / "gitread"


def _busybox() -> str:
    return (os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox")
            or str(Path("~/.local/bin/busybox").expanduser()))


@pytest.fixture(autouse=True)
def _tmp_allowed(monkeypatch):
    """Test trees live under /tmp, which the never-list refuses on a real machine."""
    monkeypatch.setattr(CF, "NEVER_UNDER", tuple(x for x in CF.NEVER_UNDER if x != "/tmp"))


def _bindir(base: Path, awk: str, all_busybox: bool = False) -> Path:
    b = base / f"bin_{awk}_{int(all_busybox)}"
    b.mkdir(parents=True, exist_ok=True)
    for t in TOOLS:
        src = _busybox() if all_busybox else shutil.which(t)
        if src and not (b / t).exists():
            os.symlink(src, b / t)
    if not (b / "awk").exists():
        os.symlink(_busybox() if awk == "busybox" else shutil.which(awk), b / "awk")
    return b


def run_ssh(script: str, b: Path) -> str:
    r = subprocess.run([str(b / "sh"), "-s"], input=script.encode(), capture_output=True,
                       env={"PATH": str(b), "LC_ALL": "C"}, timeout=120)
    return r.stdout.decode("utf-8", "replace")


def tree(base: Path) -> Path:
    r = base / "srv" / "site"
    (r / "web" / "uploads").mkdir(parents=True)
    (r / "web" / "index.php").write_text("<?php echo 1;\n")
    (r / "web" / "uploads" / "a b.php").write_text("<?php // fixture\n")
    (r / "web" / "uploads" / "nl\nname.php").write_text("<?php // newline name\n")
    (r / "web" / "uploads" / "tab\tname.txt").write_text("t\n")
    (r / "web" / "uploads" / "‮evil.txt").write_text("rtl\n")
    (r / "run.sh").write_text("#!/bin/sh\n")
    (r / "run.sh").chmod(0o755)
    (r / "link").symlink_to("/etc/passwd")
    (r / "web" / "lnk.php").symlink_to("/etc/passwd")
    (r / "dirlink").symlink_to("/etc")
    (r / "node_modules" / "x").mkdir(parents=True)
    (r / "node_modules" / "x" / "a.js").write_text("a\n")
    (r / "node_modules" / ".package-lock.json").write_text('{"packages":{}}')
    (r / "vendor" / "composer").mkdir(parents=True)
    (r / "vendor" / "composer" / "installed.json").write_text('{"packages":[]}')
    (r / ".venv" / "lib" / "python3.12" / "site-packages" / "flask-3.0.0.dist-info").mkdir(parents=True)
    (r / ".venv" / "lib" / "python3.12" / "site-packages" / "flask-3.0.0.dist-info" / "METADATA").write_text(
        "Name: flask\nVersion: 3.0.0\n")
    (r / "id_rsa").write_text("not read\n")
    (r / ".env").write_text("SECRET_KEY=x\n")
    # credential stores inside a code folder: never listed, hashed or read (review finding)
    (r / ".aws").mkdir()
    (r / ".aws" / "credentials").write_text("[default]\n")
    (r / "web" / ".docker").mkdir()
    (r / "web" / ".docker" / "config.json").write_text("{}\n")
    (r / "secrets").mkdir()
    (r / "secrets" / "db.txt").write_text("x\n")
    (r / ".netrc").write_text("machine x\n")
    (r / "web" / ".pgpass").write_text("x\n")
    os.link(r / "run.sh", r / "hard.sh")
    d = r
    for i in range(25):
        d = d / f"d{i}"
    d.mkdir(parents=True)
    (d / "deep.txt").write_text("deep\n")
    return r


def _same(a: dict, b: dict) -> None:
    assert a["root"]["status"] == b["root"]["status"] == "ok"
    assert a["files"] == b["files"]
    assert a["links"] == b["links"]
    assert sorted(a["skipped"], key=lambda s: s["path"]) == sorted(b["skipped"], key=lambda s: s["path"])
    assert a["gitfiles"] == b["gitfiles"]
    assert a["totals"] == b["totals"]
    assert (a["git"], a["format"]) == (b["git"], b["format"])


@pytest.mark.parametrize("awk", AWKS)
def test_inventory_parity_ssh_and_agent(tmp_path, awk):
    r = tree(tmp_path)
    root = os.fsencode(str(r))
    ssh = CF.parse_inventory(run_ssh(CF.build_inventory_script(root), _bindir(tmp_path, awk)))
    agent = CF.parse_inventory(CF.inventory_output(root, git=False)["stdout"])
    _same(ssh, agent)
    names = set(ssh["files"])
    assert "web/uploads/nl\nname.php" in names and "web/uploads/tab\tname.txt" in names
    assert "web/uploads/‮evil.txt" in names
    assert ssh["links"] == {"link": "/etc/passwd", "dirlink": "/etc", "web/lnk.php": "/etc/passwd"}  # never walked
    assert not any(n.startswith(("dirlink/", "node_modules/x")) for n in names)  # nothing behind a link or in deps
    assert {"node_modules/.package-lock.json", "vendor/composer/installed.json",
            ".venv/lib/python3.12/site-packages/flask-3.0.0.dist-info/METADATA"} <= names
    assert ssh["files"]["hard.sh"]["status"] == "hardlink" and ssh["files"]["hard.sh"]["sha256"] is None
    assert ssh["totals"].get("depth_capped") == "1" and not ssh["complete"]
    assert {s["path"]: s["count"] for s in ssh["skipped"]}["node_modules"] == 2
    creds = {".aws", "web/.docker", "secrets", ".netrc", "web/.pgpass"}
    assert {s["path"] for s in ssh["skipped"] if s["reason"] == "credential"} == creds
    assert not any(CF.is_credential_rel(os.fsencode(n)) for n in names)


def test_inventory_parity_full_busybox_userland(tmp_path):
    if not Path(_busybox()).exists():
        pytest.skip("no busybox")
    r = tree(tmp_path)
    root = os.fsencode(str(r))
    ssh = CF.parse_inventory(run_ssh(CF.build_inventory_script(root), _bindir(tmp_path, "busybox", True)))
    agent = CF.parse_inventory(CF.inventory_output(root, git=False)["stdout"])
    _same(ssh, agent)


@pytest.mark.parametrize("name", ["modified", "sha256_drift", "packed_ref_delta", "ignored_served_shell"])
def test_git_listing_and_blob_ids_agree_with_the_agent(tmp_path, name):
    with tarfile.open(FIX / "repos.tar.gz") as tar:
        tar.extractall(tmp_path, filter="tar")
    root = os.fsencode(str(tmp_path / name))
    ssh = CF.parse_inventory(run_ssh(CF.build_inventory_script(root), _bindir(tmp_path, "gawk" if shutil.which("gawk")
                                                                            else "mawk")))
    agent = CF.parse_inventory(CF.inventory_output(root)["stdout"])
    _same(ssh, agent)
    assert ssh["git"] == "dir" and all(f["blob"] for f in ssh["files"].values() if f["status"] == "ok")
    assert agent["git_state"] is not None and ssh["git_state"] is None      # the agent compares on the machine


def test_root_refusals_and_status(tmp_path):
    with pytest.raises(CF.RequestError):
        CF.check_root(b"/etc/nginx")
    with pytest.raises(CF.RequestError):
        CF.check_root(b"/srv/../etc")
    with pytest.raises(CF.RequestError):
        CF.check_root(b"/home/u/.ssh/x")
    (tmp_path / "real").mkdir()
    (tmp_path / "lnk").symlink_to(tmp_path / "real")
    b = _bindir(tmp_path, AWKS[0])
    for p, want in ((tmp_path / "lnk", "symlink"), (tmp_path / "nope", "missing")):
        root = os.fsencode(str(p))
        assert CF.parse_inventory(run_ssh(CF.build_inventory_script(root), b))["root"]["status"] == want
        assert CF.parse_inventory(CF.inventory_output(root)["stdout"])["root"]["status"] == want


def test_file_changed_mid_walk_is_skipped_and_counted(tmp_path, monkeypatch):
    r = tmp_path / "srv" / "x"
    r.mkdir(parents=True)
    (r / "a.php").write_text("<?php 1;")
    real = CF._hash_fd

    def swap(fd, size, fmt):
        (r / "a.php").write_text("<?php changed while read, longer;")
        return real(fd, size, fmt)
    monkeypatch.setattr(CF, "_hash_fd", swap)
    inv = CF.parse_inventory(CF.inventory_output(os.fsencode(str(r)))["stdout"])
    assert inv["files"]["a.php"]["status"] == "changed" and inv["files"]["a.php"]["sha256"] is None


def test_paginate_splits_and_marks_the_last_page():
    lines = "\n".join(f"F\tn\tf{i}\t1\t644\t0\t0\t{i}\t1\t{'a' * 64}\t-\tok" for i in range(5000)) + "\nEND\n"
    pages = CF.paginate(lines, page_bytes=100_000)
    assert len(pages) > 1 and pages[-1].rstrip().endswith("P\tlast")
    assert all(p.rstrip().endswith("P\tmore") for p in pages[:-1])
    assert all(len(p.encode()) <= 100_000 for p in pages)
    joined = CF.parse_inventory("".join(pages))
    assert len(joined["files"]) == 5000 and joined["complete"]


@pytest.mark.parametrize("awk", AWKS)
def test_content_read_parity_and_rules(tmp_path, awk):
    r = tree(tmp_path)
    root = os.fsencode(str(r))
    rels = [b"web/index.php", b".env", b"web/uploads/a b.php", b"missing.php", b"hard.sh", b"web/lnk.php"]
    with pytest.raises(CF.RequestError):                         # a private-key file is never read
        CF.build_read_script(root, "secrets", [b"id_rsa"], budget_bytes=10_000)
    with pytest.raises(CF.RequestError):
        CF.build_read_script(root, "deps", [b"web/index.php"], budget_bytes=10_000)
    ssh = CF.parse_read(run_ssh(CF.build_read_script(root, "secrets", rels, budget_bytes=10_000),
                                _bindir(tmp_path, awk)), len(rels))
    agent = CF.parse_read(CF.read_output(root, "secrets", rels, budget_bytes=10_000)["stdout"], len(rels))
    assert ssh["files"] == agent["files"]
    st = {i: f["status"] for i, f in ssh["files"].items()}
    assert st == {0: "ok", 1: "ok", 2: "ok", 3: "missing", 4: "hardlink", 5: "link"}
    assert ssh["files"][0]["data"] == b"<?php echo 1;\n"


def test_agent_read_refuses_files_its_walk_did_not_list(tmp_path):
    r = tree(tmp_path)
    out = CF.parse_read(CF.read_output(os.fsencode(str(r)), "secrets", [b".env"], budget_bytes=10_000,
                                       listed=lambda root, rel: None)["stdout"], 1)
    assert out["files"][0]["status"] == "not_listed" and out["files"][0]["data"] is None


def test_review_purpose_only_reads_source_extensions(tmp_path):
    assert CF.purpose_allows("review", b"app.py", 10) is None
    assert CF.purpose_allows("review", b".env", 10) is not None
    assert CF.purpose_allows("review", b"x.py", CF.REVIEW_MAX_BYTES + 1) == "too_large"
    with pytest.raises(CF.RequestError):
        CF.build_read_script(b"/srv/site", "review", [b"settings.yml"], budget_bytes=1000)


def test_budget_stops_reading(tmp_path):
    r = tree(tmp_path)
    out = CF.parse_read(CF.read_output(os.fsencode(str(r)), "secrets", [b"web/index.php", b".env"],
                                       budget_bytes=15)["stdout"], 2)
    assert out["files"][0]["status"] == "ok" and out["files"][1]["status"] == "budget"


@pytest.mark.parametrize("awk", AWKS)
def test_roots_facts_parity_and_key_files_skipped(tmp_path, awk):
    base = tmp_path / "m"
    (base / "etc/nginx/sites-available").mkdir(parents=True)
    (base / "etc/nginx/sites-enabled").mkdir(parents=True)
    (base / "etc/nginx/ssl").mkdir(parents=True)
    (base / "etc/nginx/nginx.conf").write_text("http { include /etc/nginx/sites-enabled/*; }\n")
    (base / "etc/nginx/sites-available/site").write_text("server { root /var/www/site; }\n")
    (base / "etc/nginx/sites-enabled/site").symlink_to(base / "etc/nginx/sites-available/site")
    (base / "etc/nginx/sites-enabled/out").symlink_to("/etc/passwd")
    (base / "etc/nginx/sites-enabled/server.pem").write_text("-----BEGIN PRIVATE KEY----- not read\n")
    (base / "etc/systemd/system").mkdir(parents=True)
    (base / "etc/systemd/system/app.service").write_text("[Service]\nWorkingDirectory=/srv/app\nExecStart=/srv/app/run\n")
    (base / "etc/systemd/system/other.service").write_text("[Service]\nExecStart=/bin/true\n")
    ssh = CF.parse_roots_facts(run_ssh(CF.build_roots_script(str(base)), _bindir(tmp_path, awk)), str(base))
    agent = CF.parse_roots_facts(CF.roots_facts_output(str(base))["stdout"], str(base))
    assert ssh["configs"] == agent["configs"] and ssh["units"] == agent["units"]
    c = ssh["configs"]
    assert c["/etc/nginx/sites-enabled/site"]["status"] == "ok"
    assert "root /var/www/site" in c["/etc/nginx/sites-enabled/site"]["text"]
    assert c["/etc/nginx/sites-enabled/out"]["status"] == "outside"
    key = c["/etc/nginx/sites-enabled/server.pem"]
    assert key["status"] == "skipped" and key["text"] is None
    assert list(ssh["units"]) == ["/etc/systemd/system/app.service"]


# ----------------------------------------------------------------------------- never executes
_SHIPPED = [Path(CF.__file__), Path(CF.__file__).parent.parent / "code" / "gitread.py",
            Path(CF.__file__).parent.parent / "code" / "reads.py"]


def test_git_never_executed():
    """No read starts git, a package manager or an interpreter: neither the SSH scripts nor
    the agent's Python (scan of the shipped files' code; text that is only shown to a person
    -- the fix commands in kratos.code.judge -- is not part of any read)."""
    banned = re.compile(r"(?<![\w./-])(git|pip3?|npm|npx|yarn|pnpm|composer|bundle|gem|cargo|go|python3?|node|php|"
                        r"ruby|perl)(?=\s|$|['\"`;|&)])")
    scripts = [CF._ROOTS_SH, CF._INV_SH, CF._READ_SH, CF._BINARY_SH]
    for s in scripts:
        code_lines = [ln for ln in s.splitlines() if not ln.strip().startswith("#")]
        for ln in code_lines:
            words = re.sub(r"'[^']*'|\"[^\"]*\"", "", ln)
            assert not banned.search(words), f"a read script starts a program it must not: {ln!r}"
    for path in _SHIPPED:
        tree_ = ast.parse(path.read_text())
        for node in ast.walk(tree_):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                    "run", "Popen", "call", "check_call", "check_output", "system", "popen", "execv", "execvp"):
                raise AssertionError(f"{path.name}:{node.lineno} starts a process")
            if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                mods = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) else [])
                assert "subprocess" not in mods, f"{path.name} imports subprocess"


def test_hostile_git_config_never_runs(tmp_path):
    with tarfile.open(FIX / "repos.tar.gz") as tar:
        tar.extractall(tmp_path, filter="tar")
    root = tmp_path / "hostile_config"
    before = set(os.listdir(root))
    inv = CF.parse_inventory(CF.inventory_output(os.fsencode(str(root)))["stdout"])
    assert inv["git_state"]["head"]["commit"]
    assert set(os.listdir(root)) == before


def test_records_never_carry_a_tab_or_newline_from_a_name():
    for raw in (b"a\tb", b"a\nb", b"\xff\xfe", b"plain/name.py", b""):
        f, e = CF.enc(raw)
        assert "\t" not in e and "\n" not in e
        assert CF.dec(f, e) == raw


def test_inventory_pages_through_the_sub_agent(tmp_path, monkeypatch):
    """The agent route of fetch_code_inventory: pages joined, a lost page restarts once."""
    from kratos.adapters import ssh_remote
    from kratos.subagent import routing

    r = tree(tmp_path)
    full = CF.inventory_output(os.fsencode(str(r)), git=False)["stdout"]
    pages = CF.paginate(full, page_bytes=600)
    assert len(pages) > 2
    calls = []

    def agent_read(link, probe, params):
        calls.append(params["page"])
        if params["page"] == 2 and calls.count(2) == 1:
            return {"status": "ok", "data": {"stdout": "M\tpage_lost\t1\nEND\n", "returncode": 0}}
        return {"status": "ok", "data": {"stdout": pages[params["page"]], "returncode": 0}}

    link = routing.Link(host="192.0.2.40", target_id="tgt_x", mode=routing.MODE_SUBAGENT, name="lab")
    monkeypatch.setattr(routing, "active_link", lambda: link)
    monkeypatch.setattr(routing, "agent_read", agent_read)
    inv = ssh_remote.fetch_code_inventory(os.fsencode(str(r)), max_files=CF.MAX_FILES, max_depth=CF.MAX_DEPTH,
                                          seconds=60, skip=CF.SKIP_DIRS, max_pack_mb=16)
    assert isinstance(inv, dict) and inv["via"] == "subagent"
    assert inv["files"] == CF.parse_inventory(full)["files"]
    assert calls[:3] == [0, 1, 2] and calls[3] == 0              # restarted from page 0 after the lost page
