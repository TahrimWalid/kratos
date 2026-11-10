"""Making a backup (kratos.backup.create): consistent under live writes, nothing plaintext
outside the work folder, only `.partial` after a crash (docs/phaseD/D.8 §7)."""
from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

import _backup_helpers as H
import pytest

from kratos.backup import agefmt as A
from kratos.backup import archive as AR
from kratos.backup import create as CR
from kratos.backup import store as BR


def _make(tmp_path, **kw):
    r = H.home(tmp_path)
    H.seed(r)
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[], **kw)
    return r, ident, res


def _members(path, ident):
    with AR.opened(path, [ident]) as ar:
        m = ar.read_manifest()
        out = {mem.path: mem.read_all() for mem in ar.members()}
        ar.finish()
    return m, out


def test_a_backup_holds_every_planned_file_with_its_hash(tmp_path):
    r, ident, res = _make(tmp_path)
    m, files = _members(res.file, ident)
    assert m["format"] == "kratos-backup/1" and m["lock"]["mode"] == "recipients"
    assert set(files) == {e["path"] for e in m["files"]}
    assert files["config/.env"] == (r.config / ".env").read_bytes()
    assert files["state/kept_tools/tool_x.py"] == b"X = 1\n"
    assert m["keys"]["agent_link"]["pins"] and m["keys"]["signing"]
    assert m["keys"]["fss_machines"] == ["192.0.2.10"]
    db = m["databases"][0]
    assert db["integrity"] == "ok" and db["tables"]["host_events"] == 20 and "events" in db["schema_versions"]


def test_the_sidecar_is_checkable_with_sha256sum(tmp_path):
    _r, _i, res = _make(tmp_path)
    out = subprocess.run(["sha256sum", "-c", res.sidecar.name], cwd=res.file.parent, capture_output=True, text=True)
    assert out.returncode == 0 and ": OK" in out.stdout
    text = res.sidecar.read_text()
    assert "alice" not in text and "192.0.2" not in text           # nothing personal
    assert oct(res.file.stat().st_mode & 0o777) == "0o600"


def test_the_run_is_recorded_without_secrets(tmp_path):
    r, ident, res = _make(tmp_path)
    row = BR.last(r.data, "create")
    assert row["sha256"] == res.sha256 and row["size"] == res.size and row["actor"] == "tester"
    assert row["recipients"] and all(x.startswith("age:") for x in row["recipients"])
    dump = json.dumps(BR.runs(r.data))
    assert "AGE-SECRET-KEY" not in dump and str(ident.recipient()) not in dump


def test_nothing_plaintext_is_left_behind(tmp_path):
    r, ident, res = _make(tmp_path)
    assert os.listdir(r.data / ".backup-work") == []
    secret = (r.config / ".env").read_bytes()
    keyfile = next((r.data / "subagent-tls").glob("key-*.pem")).read_bytes()
    for root in (tmp_path / "bk",):
        for name in os.listdir(root):
            data = (root / name).read_bytes()
            assert secret not in data and keyfile not in data and b"alice" not in data


def test_the_destination_can_not_be_the_data_folder(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    H.set_recipient(r, H.identity())
    with pytest.raises(CR.BackupError, match="inside Kratos's data folder"):
        CR.create(r.data, actor=H.CLI, dest=r.data / "backups", roots=r, copy_to=[])


def test_no_key_set_up_is_a_plain_refusal(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    with pytest.raises(CR.BackupError, match="key new"):
        CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])


def test_a_scheduled_backup_refuses_a_passphrase(tmp_path):
    r = H.home(tmp_path)
    with pytest.raises(CR.BackupError, match="scheduled"):
        CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, passphrase="x" * 20, scheduled=True)


def test_passphrase_backup_has_one_scrypt_stanza(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, passphrase="correct horse staple battery",
                    copy_to=[])
    h, _ = A.read_header_only(open(res.file, "rb"))
    assert [s.args[0] for s in h.stanzas] == [b"scrypt"]
    with pytest.raises(Exception):
        CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, passphrase="short", copy_to=[])


def test_without_secrets_withholds_tokens_and_leaves_no_trace_in_the_copy(tmp_path):
    from kratos.storage.subagent_store import SubAgentStore

    r = H.home(tmp_path)
    H.seed(r)
    st = SubAgentStore(r.data / "kratos.db")
    code = st.create_pairing_code("web-01")["code"]
    token = "tok-" + "q" * 40
    with sqlite3.connect(r.data / "kratos.db") as c:
        c.execute("INSERT INTO subagent_targets (target_id, name, token, paired_at) VALUES ('t1','web-01',?, '2026')",
                  (token,))
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[], without_secrets=True)
    m, files = _members(res.file, ident)
    assert "config/.env" not in files and not any(p.startswith("data/subagent-tls") for p in files)
    db = files["data/kratos.db"]
    assert token.encode() not in db and code.encode() not in db
    with sqlite3.connect(r.data / "kratos.db") as c:   # the live database keeps both
        assert c.execute("SELECT COUNT(*) FROM subagent_pairing_codes WHERE code=?", (code,)).fetchone()[0] == 1
    assert m["databases"][0]["scrubbed"] == ["subagent_targets.token", "subagent_pairing_codes.rows"]


def test_excluding_a_trigger_guarded_table_empties_it_in_the_copy_only(tmp_path):
    r = H.home(tmp_path)
    H.seed(r)
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[], exclude=("host_events",))
    m, files = _members(res.file, ident)
    assert m["databases"][0]["tables"]["host_events"] == 0
    with sqlite3.connect(r.data / "kratos.db") as c:      # the live database is untouched
        assert c.execute("SELECT COUNT(*) FROM host_events").fetchone()[0] == 20
    copy = tmp_path / "copy.db"
    copy.write_bytes(files["data/kratos.db"])
    with sqlite3.connect(copy) as c:                       # the append-only trigger is back in the copy
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_schema WHERE type='trigger'")}
    assert "host_events_append_only" in names


def test_a_copy_taken_under_live_writes_is_one_point_in_time(tmp_path):
    """A writer inserts PAIRS of rows in one transaction the whole time; the copy never
    holds half a pair, passes integrity_check, and its count is a real moment."""
    r = H.home(tmp_path)
    H.seed(r, events=0)
    db = r.data / "kratos.db"
    with sqlite3.connect(db) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE IF NOT EXISTS pairs (n INTEGER, half INTEGER)")
    stop = threading.Event()

    def writer():
        conn = sqlite3.connect(db, isolation_level=None, timeout=30)
        n = 0
        while not stop.is_set():
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO pairs VALUES (?, 1)", (n,))
            conn.execute("INSERT INTO pairs VALUES (?, 2)", (n,))
            conn.execute("COMMIT")
            n += 1
        conn.close()

    t = threading.Thread(target=writer)
    t.start()
    try:
        time.sleep(0.2)
        infos = []
        for i in range(3):
            out = tmp_path / f"c{i}.db"
            infos.append((out, CR.copy_database(db, out)))
    finally:
        stop.set()
        t.join()
    for out, info in infos:
        with sqlite3.connect(out) as c:
            halves = c.execute("SELECT half, COUNT(*) FROM pairs GROUP BY half").fetchall()
        assert info["integrity"] == "ok"
        assert len({cnt for _h, cnt in halves}) == 1 and info["tables"]["pairs"] % 2 == 0
        assert info["tables"]["pairs"] > 0


def test_disk_full_while_writing_leaves_no_file(tmp_path, monkeypatch):
    r = H.home(tmp_path)
    H.seed(r)
    H.set_recipient(r, H.identity())

    def full(self, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(CR._HashingFile, "write", full)
    with pytest.raises(OSError):
        CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    assert os.listdir(tmp_path / "bk") == []
    assert BR.last(r.data, "create", outcome="failed")["error"] == "no space left on the disk"
    assert os.listdir(r.data / ".backup-work") == []


_KILL = r"""
import os, signal, sys, tarfile
sys.path.insert(0, {tests!r})
import _backup_helpers as H
from kratos.backup import create as CR
from kratos.backup.plan import Roots
from pathlib import Path
stage = sys.argv[1]
r = Roots(Path({data!r}), Path({home!r}), Path({home!r}))
def progress(st, text):
    if st == stage:
        os.kill(os.getpid(), signal.SIGKILL)
if stage == "mid":
    real = tarfile.TarFile.addfile
    n = [0]
    def addfile(self, *a, **k):
        n[0] += 1
        if n[0] == 4:
            os.kill(os.getpid(), signal.SIGKILL)
        return real(self, *a, **k)
    tarfile.TarFile.addfile = addfile
CR.create(r.data, actor=H.CLI, dest=Path({dest!r}), roots=r, copy_to=[], progress=progress)
"""


@pytest.mark.parametrize("stage", ["database", "files", "encrypt", "mid"])
def test_a_kill_at_each_stage_leaves_only_partial_and_the_next_run_sweeps_it(tmp_path, stage):
    r = H.home(tmp_path)
    H.seed(r)
    H.set_recipient(r, H.identity())
    dest = tmp_path / "bk"
    script = _KILL.format(tests=str(Path(__file__).parent), data=str(r.data), home=str(r.state), dest=str(dest))
    proc = subprocess.run([sys.executable, "-c", script, stage], capture_output=True, timeout=120)
    assert proc.returncode == -9, proc.stderr.decode()[-500:]
    left = os.listdir(dest) if dest.exists() else []
    assert not any(n.endswith(".age") for n in left)          # never a final name
    assert all(n.endswith(".age.partial") for n in left)
    res = CR.create(r.data, actor=H.CLI, dest=dest, roots=r, copy_to=[])
    names = sorted(os.listdir(dest))
    assert names == sorted([res.file.name, res.sidecar.name])
    assert os.listdir(r.data / ".backup-work") == []
    if left:
        assert any("unfinished" in w for w in res.warnings)


def test_two_backups_at_once_refuse_the_second(tmp_path):
    from kratos.backup import inuse

    r = H.home(tmp_path)
    H.seed(r)
    H.set_recipient(r, H.identity())
    fd = inuse.backup_lock(r.data)
    try:
        with pytest.raises(CR.BackupError, match="another backup"):
            CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    finally:
        inuse.release(fd)


def test_a_tpm_sealed_ca_key_is_unsealed_in_memory_only(tmp_path, monkeypatch):
    from kratos.sshca import ca as _ca

    r = H.home(tmp_path)
    H.seed(r)
    ca = r.data / "ssh-ca"
    ca.mkdir(mode=0o700)
    (ca / "user_ca-abc.cred").write_bytes(b"SEALED-BLOB")
    plain = b"-----BEGIN OPENSSH PRIVATE KEY-----\nPLAIN-CA-KEY-" + b"k" * 40 + b"\n"
    monkeypatch.setattr(_ca, "_unseal_private", lambda dd, p: plain if p.name == "user_ca-abc" else b"")
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    for root, _d, files in os.walk(tmp_path):
        for f in files:
            p = Path(root) / f
            if p != res.file:
                assert plain not in p.read_bytes(), p
    m, files = _members(res.file, ident)
    assert files["data/ssh-ca/user_ca-abc"] == plain
    assert "data/ssh-ca/user_ca-abc.cred" not in files
    assert [e for e in m["files"] if e["path"] == "data/ssh-ca/user_ca-abc"][0]["sealed_from"] == "tpm"


def test_the_tar_holds_regular_files_only(tmp_path):
    import gzip

    _r, ident, res = _make(tmp_path)
    plain = io.BytesIO(A.decrypt_bytes(res.file.read_bytes(), [ident]))
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=plain), mode="r|") as tar:
        names = []
        for ti in tar:
            assert ti.isreg() and ti.mode == 0o600 and ti.uid == 0
            names.append(ti.name)
    assert names[0] == "MANIFEST.json"


def test_backup_names_are_utc_whatever_the_zone(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "Pacific/Kiritimati")
    time.tzset()
    try:
        stamp = CR.utc_stamp(0)
        assert stamp == "19700101T000000Z"
        assert CR.utc_iso(0) == "1970-01-01T00:00:00Z"
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()


def test_the_manifest_records_the_name_an_agent_dials_not_where_it_arrived(tmp_path):
    from kratos.storage.subagent_store import SubAgentStore

    r = H.home(tmp_path)
    H.seed(r)
    st = SubAgentStore(r.data / "kratos.db")
    code = st.create_pairing_code("web-01", core_host="core.example.test")["code"]
    with sqlite3.connect(r.data / "kratos.db") as c:
        c.execute("INSERT INTO subagent_targets (target_id, name, token, paired_at, core_addr) "
                  "VALUES ('t1','web-01','tok-x','2026','192.0.2.1')")
        c.execute("UPDATE subagent_pairing_codes SET used_at='2026', used_by_target_id='t1' WHERE code=?", (code,))
    st.register_listener("l1", pid=1, host="192.0.2.1", port=8772, mode="process", build="b")
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    a = res.manifest["agents"][0]
    assert a["dials"] == "core.example.test" and a["arrived_at"] == "192.0.2.1" and a["port"] == 8772
