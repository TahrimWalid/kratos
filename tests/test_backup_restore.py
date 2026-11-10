"""Checking and restoring a backup (kratos.backup.verify / restore / archive): two verify
depths, the drill, a careful restore, and every hostile archive refused before anything is
written (docs/phaseD/D.8 §3.8, §3.9, §7)."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import sqlite3
import tarfile
from pathlib import Path

import _backup_helpers as H
import pytest

from kratos.backup import agefmt as A
from kratos.backup import archive as AR
from kratos.backup import create as CR
from kratos.backup import inuse
from kratos.backup import restore as RS
from kratos.backup import store as BR
from kratos.backup import verify as V


@pytest.fixture
def made(tmp_path):
    r = H.home(tmp_path, "old")
    H.seed(r)
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    return r, ident, res


# --- verify ----------------------------------------------------------------------------
def test_quick_verify_needs_no_secret_and_catches_bit_rot(made, tmp_path):
    _r, _ident, res = made
    assert V.quick(res.file).ok
    copy = tmp_path / "drive"
    copy.mkdir()
    (copy / res.file.name).write_bytes(res.file.read_bytes())
    (copy / res.sidecar.name).write_bytes(res.sidecar.read_bytes())
    bad = bytearray((copy / res.file.name).read_bytes())
    bad[len(bad) // 2] ^= 0x01
    (copy / res.file.name).write_bytes(bytes(bad))
    c = V.quick(copy / res.file.name)
    assert not c.ok and any("damaged" in p for p in c.problems)


def test_quick_verify_catches_truncation(made, tmp_path):
    _r, _ident, res = made
    cut = tmp_path / res.file.name
    cut.write_bytes(res.file.read_bytes()[:-100])
    (tmp_path / res.sidecar.name).write_bytes(res.sidecar.read_bytes())
    c = V.quick(cut)
    assert not c.ok and any("truncated" in p for p in c.problems)


def test_full_verify_checks_every_file_and_key(made):
    r, ident, res = made
    c = V.full(res.file, [ident], data_dir=r.data)
    assert c.ok, c.problems
    assert os.listdir(r.data / ".backup-work") == []


def test_full_verify_with_the_wrong_key_says_so(made):
    r, _ident, res = made
    c = V.full(res.file, [H.identity()], data_dir=r.data)
    assert not c.ok and any("wrong key" in p for p in c.problems)


def test_full_verify_names_the_chunk_a_flipped_byte_is_in(made, tmp_path):
    r, ident, res = made
    data = bytearray(res.file.read_bytes())
    _h, hlen = A.read_header_only(open(res.file, "rb"))
    pos = hlen + A.NONCE_LEN + 5        # inside chunk 0
    data[pos] ^= 1
    bad = tmp_path / "bad.age"
    bad.write_bytes(bytes(data))
    c = V.full(bad, [ident], data_dir=r.data)
    assert not c.ok and any("chunk 0" in p for p in c.problems)


def test_the_drill_restores_into_a_scratch_home_and_removes_it(made):
    r, ident, res = made
    d = V.drill(res.file, [ident], data_dir=r.data, actor=H.CLI)
    assert d.ok, (d.problems, d.doctor[-10:])
    assert d.restored_files == res.manifest["totals"]["files"]
    assert os.listdir(r.data / ".backup-work") == []
    assert BR.last(r.data, "drill")["file"] == str(res.file)


def test_the_drill_fails_honestly_on_a_damaged_backup(made, tmp_path):
    r, ident, res = made
    data = bytearray(res.file.read_bytes())
    data[-30] ^= 1
    bad = tmp_path / "bad.age"
    bad.write_bytes(bytes(data))
    d = V.drill(bad, [ident], data_dir=r.data, actor=H.CLI)
    assert not d.ok and BR.last(r.data, "drill", outcome="failed")


# --- restore ---------------------------------------------------------------------------
def test_restore_onto_a_fresh_home_brings_everything_back(made, tmp_path):
    r, ident, res = made
    new = H.home(tmp_path, "new")
    out = RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    old_files = H.all_files(r.state)
    new_files = H.all_files(new.state)
    for rel, data in old_files.items():
        if rel.startswith("data/kratos.db") or rel.startswith("data/.backup-work") or rel.startswith("data/locks"):
            continue
        assert new_files.get(rel) == data, rel
    with sqlite3.connect(new.data / "kratos.db") as c:
        assert c.execute("SELECT COUNT(*) FROM host_events").fetchone()[0] == 20
        assert c.execute("SELECT COUNT(*) FROM goal_history").fetchone()[0] == 1
    for p in new.state.rglob("*"):
        if p.is_file() and ".pre-restore-" not in str(p) and "locks" not in p.parts:
            assert p.stat().st_mode & 0o077 == 0, p
    assert out.files == res.manifest["totals"]["files"]
    assert BR.last(new.data, "restore")


def test_restore_refuses_a_home_that_holds_data(made, tmp_path):
    r, ident, res = made
    with pytest.raises(RS.RestoreError, match="already holds data"):
        RS.restore(res.file, [ident], roots=r, actor=H.CLI, accept_signer=H.signer_of(res.file))


def test_replace_backs_up_first_and_moves_aside_deleting_nothing(made, tmp_path):
    r, ident, res = made
    before = H.all_files(r.state)
    (r.data / "sessions" / "newer.json").write_text("made after the backup")
    before = H.all_files(r.state)
    out = RS.restore(res.file, [ident], roots=r, actor=H.CLI, accept_signer=H.signer_of(res.file), replace=True)
    assert out.pre_backup and Path(out.pre_backup).exists()
    aside = [Path(b) for _a, b in out.moved_aside]
    kept = {}
    for p in aside:
        for f, data in (H.all_files(p).items() if p.is_dir() else [("", p.read_bytes())]):
            kept[(p.name, f)] = data
    # every file there before is still somewhere: restored in place, or moved aside
    for rel, data in before.items():
        if "/.backup-work/" in rel or rel.startswith("data/locks") or "-wal" in rel or "-shm" in rel:
            continue
        name = rel.split("/")
        here = (r.state / rel)
        assert (here.exists() and (rel.startswith("data/kratos.db") or here.read_bytes() == data)) or any(
            v == data for v in kept.values()), rel
    assert (r.data / "sessions" / "newer.json").exists() is False
    assert any(v == b"made after the backup" for v in kept.values())


def test_restore_refuses_while_something_holds_the_data(made, tmp_path):
    _r, ident, res = made
    new = H.home(tmp_path, "new")
    import subprocess
    import sys

    holder = subprocess.Popen([sys.executable, "-c", "import sys,time; sys.path.insert(0,'src');"
                               "from kratos.backup import inuse; inuse.hold(sys.argv[1], 't'); print('held',"
                               "flush=True); time.sleep(30)", str(new.data)], stdout=subprocess.PIPE,
                              cwd=str(Path(__file__).parents[1]))
    try:
        assert holder.stdout.readline().strip() == b"held"
        with pytest.raises(RS.RestoreError, match="using this data"):
            RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    finally:
        holder.kill()
        holder.wait()


def test_a_process_cant_start_while_a_restore_holds_the_data(tmp_path):
    r = H.home(tmp_path)
    fd = inuse.exclusive(r.data)
    try:
        with pytest.raises(inuse.InUseError, match="restore is running"):
            inuse.hold(r.data, "the app")
    finally:
        inuse.release(fd)


def test_restore_refuses_while_the_listener_is_running(made, tmp_path):
    _r, ident, res = made
    new = H.home(tmp_path, "new")
    from kratos.storage.subagent_store import SubAgentStore

    SubAgentStore(new.data / "kratos.db").register_listener("l1", pid=4242, host="192.0.2.1", port=8765, mode="service", build="b")
    with pytest.raises(RS.RestoreError, match="agent listener"):
        RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))


def test_restore_is_cli_only(made, tmp_path):
    _r, ident, res = made
    new = H.home(tmp_path, "new")
    with pytest.raises(RS.RestoreError, match="command line"):
        RS.restore(res.file, [ident], roots=new, actor=H.TUI, accept_signer=H.signer_of(res.file))


def _crafted_manifest(files, version="0.1.0"):
    return {"format": "kratos-backup/1", "kratos_version": version, "files": files,
            "totals": {"files": len(files), "bytes": sum(f["size"] for f in files)}}


def _entry(name, data, kind="file"):
    return {"path": name, "category": "sessions", "kind": kind, "size": len(data), "mode": 0o600,
            "sha256": hashlib.sha256(data).hexdigest(), "mtime": 0}


def test_a_newer_backup_is_refused_with_the_version_needed(tmp_path):
    ident = H.identity()
    data = b"{}"
    f = H.craft(tmp_path / "n.age", ident.recipient(), [H.reg("data/sessions/a.json", data)],
                _crafted_manifest([_entry("data/sessions/a.json", data)], version="99.0"))
    new = H.home(tmp_path, "new")
    with pytest.raises(RS.RestoreError, match="Kratos 99.0"):
        RS.restore(f, [ident], roots=new, actor=H.CLI, accept_unsigned=True)


def test_an_older_database_is_migrated_on_restore(tmp_path):
    """A kratos.db holding only an old store (no events component yet) gets every component."""
    ident = H.identity()
    old = tmp_path / "old.db"
    with sqlite3.connect(old) as c:
        c.execute("CREATE TABLE schema_versions (component TEXT PRIMARY KEY, version INTEGER NOT NULL, updated_at TEXT)")
        c.execute("CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT, updated_by TEXT)")
        c.execute("INSERT INTO schema_versions VALUES ('settings', 1, 'x')")
    data = old.read_bytes()
    f = H.craft(tmp_path / "o.age", ident.recipient(), [H.reg("data/kratos.db", data)],
                _crafted_manifest([_entry("data/kratos.db", data, kind="db")]))
    new = H.home(tmp_path, "new")
    RS.restore(f, [ident], roots=new, actor=H.CLI, accept_unsigned=True)
    with sqlite3.connect(new.data / "kratos.db") as c:
        comps = {r[0] for r in c.execute("SELECT component FROM schema_versions")}
    assert {"events", "backup", "authz", "outbox", "settings"} <= comps


def _special(name, kind, linkname=""):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.linkname = linkname
    return ti, None


HOSTILE = {
    "symlink to authorized_keys": ([_special("data/sessions/a.json", tarfile.SYMTYPE, "/home/x/.ssh/authorized_keys")],
                                   None),
    "hard link": ([_special("data/sessions/a.json", tarfile.LNKTYPE, "config/.env")], None),
    "parent escape": ([H.reg("data/../../.bashrc", b"evil")], None),
    "absolute": ([H.reg("/etc/cron.d/x", b"evil")], None),
    "device": ([_special("data/sessions/dev", tarfile.CHRTYPE)], None),
    "fifo": ([_special("data/sessions/fifo", tarfile.FIFOTYPE)], None),
    "folder entry": ([_special("data/sessions", tarfile.DIRTYPE)], None),
    "not in manifest": ([H.reg("data/sessions/a.json", b"ok"), H.reg("data/sessions/b.json", b"extra")],
                        [_entry("data/sessions/a.json", b"ok")]),
    "size mismatch": ([H.reg("data/sessions/a.json", b"longer than listed")], [_entry("data/sessions/a.json", b"x")]),
    "hash mismatch": ([H.reg("data/sessions/a.json", b"abc")], [_entry("data/sessions/a.json", b"abd")]),
    "outside the data categories": ([H.reg("data/locks/x", b"x")], None),
    "unknown root": ([H.reg("home/x/.bashrc", b"x")], None),
    "missing member": ([H.reg("data/sessions/a.json", b"ok")],
                       [_entry("data/sessions/a.json", b"ok"), _entry("data/sessions/c.json", b"zz")]),
    "duplicate": ([H.reg("data/sessions/a.json", b"ok"), H.reg("data/sessions/a.json", b"ok")],
                  [_entry("data/sessions/a.json", b"ok")]),
    "control character": ([H.reg("data/sessions/a\x1b[2J.json", b"x")], None),
}


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_every_hostile_archive_is_refused_and_nothing_is_written(case, tmp_path):
    members, entries = HOSTILE[case]
    ident = H.identity()
    manifest = None if entries is None else _crafted_manifest(entries)
    if manifest is None:
        manifest = _crafted_manifest([_entry(ti.name, d) if d is not None else
                                      {"path": "data/sessions/z.json", "category": "sessions", "kind": "file",
                                       "size": 0, "mode": 0o600, "sha256": hashlib.sha256(b"").hexdigest(),
                                       "mtime": 0} for ti, d in members])
        if any(not _ok_path(e["path"]) for e in manifest["files"]):
            manifest = _crafted_manifest([_entry("data/sessions/z.json", b"")])
    f = H.craft(tmp_path / "evil.age", ident.recipient(), members, manifest)
    new = H.home(tmp_path, "new")
    before = H.all_files(new.state)
    with pytest.raises((AR.ArchiveError, RS.RestoreError)):
        RS.restore(f, [ident], roots=new, actor=H.CLI, accept_unsigned=True)
    after = {k: v for k, v in H.all_files(new.state).items() if "/locks/" not in k}
    assert {k: v for k, v in after.items() if "kratos.db" not in k} == {k: v for k, v in before.items()
                                                                       if "kratos.db" not in k and "/locks/" not in k}
    assert not (new.data / "sessions").exists()
    assert not list((new.data / ".backup-work").iterdir())
    assert not (tmp_path / ".bashrc").exists()
    out = tmp_path / "x"
    with pytest.raises((AR.ArchiveError, RS.RestoreError)):
        RS.stage(f, [ident], out)
    assert not out.exists()


def _ok_path(p):
    try:
        AR.check_path(p)
        return True
    except AR.ArchiveError:
        return False


def test_a_manifest_that_is_not_first_is_refused(tmp_path):
    ident = H.identity()
    f = H.craft(tmp_path / "e.age", ident.recipient(), [H.reg("data/sessions/a.json", b"x")], manifest_first=False)
    with pytest.raises(AR.ArchiveError, match="manifest"):
        RS.stage(f, [ident], tmp_path / "out")


def test_an_oversized_total_is_refused_before_writing(tmp_path, monkeypatch):
    ident = H.identity()
    data = b"x" * 1000
    f = H.craft(tmp_path / "e.age", ident.recipient(), [H.reg("data/sessions/a.json", data)])
    import shutil as _sh

    monkeypatch.setattr(_sh, "disk_usage", lambda p: _sh._ntuple_diskusage(10**9, 10**9, 100))
    with pytest.raises(RS.RestoreError, match="free space"):
        RS.stage(f, [ident], tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_extracting_writes_only_into_the_folder_given(made, tmp_path):
    _r, ident, res = made
    st = RS.stage(res.file, [ident], tmp_path / "look")
    assert (tmp_path / "look" / "config" / ".env").exists() and st.files == res.manifest["totals"]["files"]


# --- the agents and the CA after a restore -----------------------------------------------
def test_agents_that_dial_this_computer_wait_and_others_get_an_upgrade_installer(made, tmp_path, monkeypatch):
    r, ident, res = made
    m = dict(res.manifest)
    m["agents"] = [{"target_id": "t1", "name": "web-01", "dials": "192.0.2.1"},
                   {"target_id": "t2", "name": "db-01", "dials": "198.51.100.200", "port": 8772}]
    new = H.home(tmp_path, "new")
    RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    monkeypatch.setattr(RS, "_local_addresses", lambda: {"192.0.2.1"})
    rows, written = RS.agent_step(new, m, hub_address="192.0.2.99")
    by = {x["name"]: x for x in rows}
    assert by["web-01"]["same"] is True and "installer" not in by["web-01"]
    assert by["db-01"]["same"] is False and by["db-01"]["new_address"] == "192.0.2.99"
    script = Path(by["db-01"]["installer"]).read_text()
    from kratos.subagent import tls

    pins = tls.load_keys(new.data).pins()
    assert "192.0.2.99" in script and all(p in script for p in pins) and "8772" in script
    assert Path(by["db-01"]["installer"]).stat().st_mode & 0o777 == 0o600
    assert pins == tls.load_keys(r.data).pins()          # the same keys: no re-pairing


def test_a_tpm_ca_key_restores_into_file_mode_without_a_tpm(tmp_path, monkeypatch):
    from kratos.sshca import ca as _ca
    from kratos.sshca import store as _st

    r = H.home(tmp_path, "old")
    H.seed(r)
    ca = r.data / "ssh-ca"
    ca.mkdir(mode=0o700)
    (ca / "user_ca-abc.cred").write_bytes(b"SEALED")
    _st.record_ca_key(r.data, fingerprint="SHA256:x", kind="user", role="active", mode="tpm",
                      public_key="ssh-ed25519 AAAA kratos", key_ref="user_ca-abc")
    plain = b"PLAIN-CA-" + b"q" * 30
    monkeypatch.setattr(_ca, "_unseal_private", lambda dd, p: plain)
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    new = H.home(tmp_path, "new")
    monkeypatch.setattr(_ca, "has_tpm2", lambda: False)
    out = RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    assert (new.data / "ssh-ca" / "user_ca-abc").read_bytes() == plain
    assert (new.data / "ssh-ca" / "user_ca-abc").stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(new.data / "kratos.db") as c:
        assert c.execute("SELECT mode FROM ssh_ca_keys WHERE key_ref='user_ca-abc'").fetchone()[0] == "file"
    assert any("TPM-sealed" in n for n in out.notes)


def test_a_tpm_ca_key_is_sealed_again_without_touching_disk(tmp_path, monkeypatch):
    from kratos.sshca import ca as _ca
    from kratos.sshca import store as _st

    r = H.home(tmp_path, "old")
    H.seed(r)
    (r.data / "ssh-ca").mkdir(mode=0o700)
    (r.data / "ssh-ca" / "user_ca-abc.cred").write_bytes(b"SEALED")
    _st.record_ca_key(r.data, fingerprint="SHA256:x", kind="user", role="active", mode="tpm",
                      public_key="ssh-ed25519 AAAA kratos", key_ref="user_ca-abc")
    plain = b"PLAIN-CA-" + b"w" * 30
    monkeypatch.setattr(_ca, "_unseal_private", lambda dd, p: plain)
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    sealed = []
    monkeypatch.setattr(_ca, "has_tpm2", lambda: True)
    monkeypatch.setattr(_ca, "_seal_private", lambda dd, p, b: (sealed.append(b), (p.with_name(p.name + ".cred"))
                                                                .write_bytes(b"NEWSEAL")))
    new = H.home(tmp_path, "new")
    RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    assert sealed == [plain]
    for f in new.state.rglob("*"):
        if f.is_file():
            assert plain not in f.read_bytes(), f


def test_a_without_secrets_restore_says_what_to_redo(tmp_path):
    r = H.home(tmp_path, "old")
    H.seed(r)
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[], without_secrets=True)
    out = RS.restore(res.file, [ident], roots=H.home(tmp_path, "new"), actor=H.CLI, accept_signer=H.signer_of(res.file))
    assert any("pair your agents again" in n for n in out.notes)


# --- every store migrates ---------------------------------------------------------------
def test_every_migrated_store_is_listed():
    from kratos.backup import stores

    src = Path(__file__).parents[1] / "src" / "kratos"
    users = set()
    for p in src.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if "migrate_once(" in text and p.name != "migrations.py":
            tree = ast.parse(text)
            if any(isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "COMPONENT" for t in n.targets)
                   for n in tree.body):
                users.add(".".join(("kratos",) + p.relative_to(src).with_suffix("").parts))
    assert users <= set(stores.MIGRATED), sorted(users - set(stores.MIGRATED))


def test_newer_components_are_reported():
    from kratos.backup import stores

    assert stores.newer_components({"events": 999}) == {"events": (999, stores.known_versions()["events"])}
    assert stores.newer_components({"events": 1}) == {}


def test_check_path_rules():
    for good in ("data/kratos.db", "data/sessions/s 1.json", "state/kept_tools/t.py", "config/.env",
                 "state/tests/self_write_harnesses/test_x.py"):
        AR.check_path(good)
    for bad in ("data", "data/", "/data/x", "data/../x", "data/./x", "config/other", "state/llm/models/../x",
                "data/kratos-subagent-install-x.sh", "data/.backup-work/x", "data/a\\b", ""):
        with pytest.raises(AR.ArchiveError):
            AR.check_path(bad)


def test_manifest_schema_is_closed():
    good = _crafted_manifest([_entry("data/sessions/a.json", b"x")])
    AR.validate_manifest(good)
    for mutate in (lambda m: m.update(format="other"), lambda m: m.update(kratos_version="1; rm"),
                   lambda m: m["files"][0].update(size=-1), lambda m: m["files"][0].update(sha256="x"),
                   lambda m: m["files"][0].update(kind="exec"), lambda m: m["totals"].update(bytes=5),
                   lambda m: m["files"].append(dict(m["files"][0]))):
        m = json.loads(json.dumps(good))
        mutate(m)
        with pytest.raises(AR.ArchiveError):
            AR.validate_manifest(m)


def test_certificates_are_rebound_to_this_computers_address(tmp_path, monkeypatch):
    from kratos.sshca import store as _st

    r = H.home(tmp_path, "new")
    H.seed(r, with_keys=False, events=0)
    _st.upsert_enrolment(r.data, "192.0.2.20", login="ubuntu", principal="kratos-x", principal_mode="machine",
                         actor="t", apparent_address="198.51.100.1")
    _st.upsert_enrolment(r.data, "192.0.2.21", login="ubuntu", principal="kratos-y", principal_mode="machine",
                         actor="t", apparent_address="192.0.2.5")
    monkeypatch.setattr(RS, "_outgoing_address", lambda host: "192.0.2.5")
    notes = RS.ssh_certificate_step(r, local={"192.0.2.5"})
    assert _st.get_enrolment(r.data, "192.0.2.20").apparent_address == "192.0.2.5"
    assert _st.get_enrolment(r.data, "192.0.2.21").apparent_address == "192.0.2.5"   # already right: untouched
    assert len(notes) == 1 and "now bound to 192.0.2.5" in notes[0] and "ssh-ca verify 192.0.2.20" in notes[0]


def test_a_restore_holds_messages_that_were_still_waiting_instead_of_sending_them_again(made, tmp_path):
    """Audit D: messages pending at backup time may have been sent by the old computer since;
    ntfy, syslog and email can't drop a repeat, so a restore holds them for the person."""
    import sqlite3 as _sq

    from kratos.outbox import store as OS

    r, ident, _res = made
    with OS.opened(r.data) as conn:
        for i, status in enumerate(("pending", "failed", "delivered")):
            OS.enqueue(conn, channel="ntfy", kind="alert", message_id=f"m{i}", payload={"text": "x"},
                       summary=f"alert {i}")
            conn.execute("UPDATE outbox SET status = ? WHERE message_id = ?", (status, f"m{i}"))
        OS.acquire_lease(conn, holder="old-computer", label="listener", pid=1, host="old", ttl=3600)
        conn.commit()
        conn.execute("INSERT INTO channels (name, kind, config, scopes, format, filters, created_at, created_by, "
                     "updated_at, updated_by) VALUES ('rx', 'webhook', ?, '[\"alerts\"]', 'kratos', '{}', 0, 't', 0, "
                     "'t')", ('{"url": "https://127.0.0.1:18443/hook"}',))
        conn.commit()
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk2", roots=r, copy_to=[])
    new = H.home(tmp_path, "new")
    out = RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    conn = _sq.connect(new.data / "kratos.db")
    rows = dict(conn.execute("SELECT message_id, status FROM outbox").fetchall())
    assert rows == {"m0": "dead", "m1": "dead", "m2": "delivered"}
    why = conn.execute("SELECT last_error FROM outbox WHERE message_id = 'm0'").fetchone()[0]
    assert "held after a restore" in why and "kratos outbox retry" in why
    assert conn.execute("SELECT expires_at FROM outbox_lease").fetchone()[0] == 0
    assert any("2 message(s)" in n and "held, not re-sent" in n for n in out.notes)
    assert any("rx (127.0.0.1)" in n for n in out.notes)
