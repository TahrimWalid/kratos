"""The evidence ledger (D.6 §3.1): hashes taken when a file is written, chained so any
edit, deletion, insertion or reordering of a row is detected, signed once a day."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from kratos import evidence
from kratos.evidence import ledger as L

DAY = 86400.0
T0 = 1_780_000_000.0   # a fixed instant (2026-05-28)


def _write(data_dir: Path, rel: str, text: str) -> Path:
    p = data_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _fill(data_dir: Path, n: int = 5, *, start: float = T0) -> list[L.LedgerEntry]:
    out = []
    for i in range(n):
        p = _write(data_dir, f"persistence/persistence_{i}.json", json.dumps({"i": i}))
        e = evidence.record(p, data_dir=data_dir, category="persistence", machine="10.0.0.5", read="persistence",
                            transport="ssh", run_id=f"run{i}", now=start + i)
        assert e is not None
        out.append(e)
    return out


def _raw(data_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir / "kratos.db")
    for verb in ("update", "delete"):
        conn.execute(f"DROP TRIGGER IF EXISTS evidence_ledger_no_{verb}")   # what someone editing by hand does
    return conn


def test_record_takes_the_hash_and_source_when_the_file_is_written(tmp_path):
    p = _write(tmp_path, "scans/parsed_1.json", '{"hosts": []}')
    e = evidence.record(p, data_dir=tmp_path, category="open_ports", machine="ubuntu@10.0.0.5", read="run_nmap_scan",
                        transport="network scan from this computer", now=T0)
    assert e.path == "scans/parsed_1.json" and e.size == len('{"hosts": []}')
    import hashlib
    assert e.sha256 == hashlib.sha256(b'{"hosts": []}').hexdigest()
    assert e.machine == "10.0.0.5" and e.read == "run_nmap_scan" and e.build
    assert e.prev_hash == L.GENESIS and e.seq == 1
    # editing the file afterwards doesn't change what was recorded
    p.write_text("tampered", encoding="utf-8")
    rep = L.verify_chain(tmp_path)
    assert rep.chain_ok and rep.changed == ["scans/parsed_1.json"] and not rep.ok


def test_record_refuses_a_file_outside_the_evidence_folders_and_never_raises(tmp_path, caplog):
    p = _write(tmp_path, "presets/x.toml", "x")
    assert evidence.record(p, data_dir=tmp_path, category="x") is None
    assert evidence.record(tmp_path / "scans/missing.json", data_dir=tmp_path, category="x") is None
    assert "not recorded" in caplog.text
    assert L.entries(tmp_path) == []


def test_the_run_and_machine_default_from_the_run_scope(tmp_path):
    from kratos import kratos_config, run_context

    p = _write(tmp_path, "live/live_response_1.json", "{}")
    with run_context.run_scope("cli", target="10.0.0.9") as ctx:
        e = evidence.record(p, data_dir=tmp_path, category="live_response", now=T0)
    assert e.machine == "10.0.0.9" and e.run_id == ctx.run_id
    p2 = _write(tmp_path, "live/live_response_2.json", "{}")
    with run_context.run_scope("cli", target="10.0.0.9"), kratos_config.pinned_target("10.0.0.7"):
        assert evidence.record(p2, data_dir=tmp_path, category="live_response", now=T0 + 1).machine == "10.0.0.7"


def test_transport_noted_by_the_read_is_recorded(tmp_path):
    from kratos.evidence.transport import note_transport

    p = _write(tmp_path, "persistence/p.json", "{}")
    note_transport("10.0.0.5", "agent")
    assert evidence.record(p, data_dir=tmp_path, category="persistence", machine="10.0.0.5", now=T0).transport == "agent"


def test_a_clean_chain_verifies(tmp_path):
    _fill(tmp_path)
    rep = L.verify_chain(tmp_path)
    assert rep.ok and rep.rows == 5 and rep.head_seq == 5 and not rep.missing


@pytest.mark.parametrize("how", ["edit", "delete", "insert", "reorder", "edit_hash_too"])
def test_the_chain_detects_tampering(tmp_path, how):
    _fill(tmp_path)
    conn = _raw(tmp_path)
    if how == "edit":
        conn.execute("UPDATE evidence_ledger SET sha256 = ? WHERE seq = 3", ("0" * 64,))
    elif how == "edit_hash_too":
        # rewrite row 3 consistently with its own prev -- the row after it no longer follows
        row = conn.execute("SELECT * FROM evidence_ledger WHERE seq = 3").fetchone()
        cols = [d[0] for d in conn.execute("SELECT * FROM evidence_ledger").description]
        d = dict(zip(cols, row))
        d["sha256"] = "f" * 64
        d["detail"] = None
        conn.execute("UPDATE evidence_ledger SET sha256 = ?, entry_hash = ? WHERE seq = 3",
                     (d["sha256"], L.chain_hash(d["prev_hash"], d)))
    elif how == "delete":
        conn.execute("DELETE FROM evidence_ledger WHERE seq = 2")
    elif how == "insert":
        row = conn.execute("SELECT * FROM evidence_ledger WHERE seq = 2").fetchone()
        conn.execute("UPDATE evidence_ledger SET seq = seq + 100 WHERE seq >= 3")
        vals = list(row)
        vals[0] = 3
        vals[3] = "a" * 64
        conn.execute(f"INSERT INTO evidence_ledger VALUES ({','.join('?' * len(vals))})", vals)
    elif how == "reorder":
        a = conn.execute("SELECT * FROM evidence_ledger WHERE seq = 2").fetchone()
        b = conn.execute("SELECT * FROM evidence_ledger WHERE seq = 3").fetchone()
        conn.execute("DELETE FROM evidence_ledger WHERE seq IN (2, 3)")
        for seq, row in ((2, b), (3, a)):
            vals = list(row)
            vals[0] = seq
            conn.execute(f"INSERT INTO evidence_ledger VALUES ({','.join('?' * len(vals))})", vals)
    conn.commit()
    conn.close()
    rep = L.verify_chain(tmp_path)
    assert not rep.chain_ok, how
    assert rep.problems


def test_the_ledger_refuses_updates_and_deletes_through_sql(tmp_path):
    _fill(tmp_path, 2)
    conn = sqlite3.connect(tmp_path / "kratos.db")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE evidence_ledger SET size = 1 WHERE seq = 1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM evidence_ledger WHERE seq = 1")


def test_a_daily_checkpoint_signs_the_previous_days_head(tmp_path):
    first = _fill(tmp_path, 3, start=T0)
    nxt = _write(tmp_path, "persistence/next.json", "{}")
    e = evidence.record(nxt, data_dir=tmp_path, category="persistence", machine="10.0.0.5", now=T0 + DAY)
    cps = L.entries(tmp_path, kind="checkpoint")
    assert len(cps) == 1 and cps[0].detail["signs_seq"] == first[-1].seq
    assert cps[0].detail["head"] == first[-1].entry_hash and e.seq == cps[0].seq + 1
    # one checkpoint per day, not per write
    again = _write(tmp_path, "persistence/again.json", "{}")
    evidence.record(again, data_dir=tmp_path, category="persistence", machine="10.0.0.5", now=T0 + DAY + 5)
    assert len(L.entries(tmp_path, kind="checkpoint")) == 1
    rep = L.verify_chain(tmp_path)
    assert rep.ok and rep.checkpoints == 1


def test_a_forged_checkpoint_signature_is_reported(tmp_path):
    _fill(tmp_path, 2)
    nxt = _write(tmp_path, "persistence/next.json", "{}")
    evidence.record(nxt, data_dir=tmp_path, category="persistence", now=T0 + DAY)
    cp = L.entries(tmp_path, kind="checkpoint")[0]
    # a new key: the old checkpoint no longer verifies with any key Kratos holds
    import shutil

    shutil.rmtree(tmp_path / "signing")
    from kratos import signing

    signing.load_key(tmp_path)
    rep = L.verify_chain(tmp_path)
    assert any(f"row {cp.seq}: checkpoint signature" in p for p in rep.problems)


def test_a_rotated_key_still_verifies_old_checkpoints(tmp_path):
    from kratos import signing

    _fill(tmp_path, 2)
    evidence.record(_write(tmp_path, "persistence/n.json", "{}"), data_dir=tmp_path, category="persistence",
                    now=T0 + DAY)
    signing.rotate(tmp_path)
    assert L.verify_chain(tmp_path).ok


def test_checkpoint_now_signs_the_head_once(tmp_path):
    _fill(tmp_path, 2)
    cp = L.checkpoint_now(tmp_path, now=T0 + 10)
    assert cp is not None and cp.detail["signs_seq"] == 2
    assert L.checkpoint_now(tmp_path, now=T0 + 11) is None
    assert L.verify_chain(tmp_path).ok


def test_a_file_written_without_a_row_is_reported_as_unrecorded(tmp_path):
    import os

    _fill(tmp_path, 1, start=1000.0)
    stray = _write(tmp_path, "context/privileged_accounts_x.json", "{}")
    os.utime(stray, (2000.0, 2000.0))
    old = _write(tmp_path, "context/old.json", "{}")
    os.utime(old, (500.0, 500.0))        # predates the ledger: not "unrecorded", just pre-ledger
    rep = L.verify_chain(tmp_path)
    assert rep.unrecorded == ["context/privileged_accounts_x.json"]


def test_a_missing_file_is_reported(tmp_path):
    _fill(tmp_path, 2)
    (tmp_path / "persistence/persistence_0.json").unlink()
    rep = L.verify_chain(tmp_path)
    assert rep.missing == ["persistence/persistence_0.json"] and rep.chain_ok


def test_a_file_replaced_in_place_is_checked_against_its_newest_row(tmp_path):
    p = _write(tmp_path, "containers/containers_m.json", "v1")
    evidence.record(p, data_dir=tmp_path, category="containers", now=T0)
    p.write_text("v2", encoding="utf-8")
    evidence.record(p, data_dir=tmp_path, category="containers", now=T0 + 1)
    assert L.verify_chain(tmp_path).ok
    assert len(L.entries(tmp_path)) == 2 and L.latest_for_paths(tmp_path, ["containers/containers_m.json"])[
        "containers/containers_m.json"].seq == 2


def test_many_writers_at_once_keep_one_unbroken_chain(tmp_path):
    errors: list[BaseException] = []

    def work(k: int) -> None:
        try:
            for i in range(10):
                p = _write(tmp_path, f"logs/auth_stats_{k}_{i}.json", f"{k}-{i}")
                assert evidence.record(p, data_dir=tmp_path, category="auth_stats", machine=f"10.0.0.{k}") is not None
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=work, args=(k,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    rep = L.verify_chain(tmp_path)
    assert rep.ok and rep.rows == 80
