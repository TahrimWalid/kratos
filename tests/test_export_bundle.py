"""Incident bundles (D.6): verifiable with stock OpenSSH and coreutils; any changed byte in
an evidence file, the manifest, SHA256SUMS or the ledger excerpt fails verification;
hashes are the ones taken at collection, and say so when they aren't."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import _export_fixture as FX
from kratos import evidence
from kratos.evidence import ledger as L
from kratos.export import archive, create as C, manifest as M, verify as V
from kratos.export.scope import ExportError, ExportRequest, plan
from kratos.lifecycle.decide import Actor

ME = Actor(user="alice", interface="cli")
HAVE_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
HAVE_SHA256SUM = shutil.which("sha256sum") is not None


def _make(d: Path, *, variant="full", machines=(FX.M1,), **kw):
    info = FX.build(d)
    now = info["now"]
    req = ExportRequest(machines=list(machines), start=now - 86400, end=now + 60, variant=variant, **kw)
    return info, C.create(d, req, ME)


def _ssh_verify(bundle: Path, signers: Path | None = None, namespace="kratos-export",
                signed: str = "manifest.json") -> subprocess.CompletedProcess:
    with open(bundle / signed, "rb") as fh:
        return subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers or bundle / "allowed_signers"),
                               "-I", "kratos", "-n", namespace, "-s", str(bundle / f"{signed}.sig")],
                              stdin=fh, capture_output=True, text=True)


def _stock_pair_passes(bundle: Path) -> bool:
    """The two commands VERIFY.txt gives a responder."""
    return _ssh_verify(bundle, signed="SHA256SUMS").returncode == 0 and _sums(bundle).returncode == 0


def _sums(bundle: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=bundle, capture_output=True, text=True)


@pytest.fixture
def made(tmp_path):
    return _make(tmp_path / "data")


def test_the_bundle_holds_what_the_spec_lists(made):
    _info, r = made
    names = {p.name for p in r.bundle.iterdir()}
    assert {"manifest.json", "manifest.json.sig", "allowed_signers", "SHA256SUMS", "SHA256SUMS.sig", "report.html",
            "case.jsonld",
            "VERIFY.txt", "evidence", "ledger.ndjson"} <= names
    man = json.loads((r.bundle / "manifest.json").read_text())
    kinds = {f["kind"] for f in man["files"]}
    assert {"evidence", "events", "event_index", "generated", "report", "ledger"} <= kinds
    assert man["signing_key"]["fingerprint"] == r.fingerprint
    assert man["machines"][0]["shown"] == FX.M1
    assert r.archive and r.archive.is_file() and r.archive_sha256


@pytest.mark.skipif(not (HAVE_SSH_KEYGEN and HAVE_SHA256SUM), reason="needs OpenSSH and coreutils")
def test_stock_openssh_and_coreutils_verify_the_bundle(made):
    _info, r = made
    sig = _ssh_verify(r.bundle)
    assert sig.returncode == 0, sig.stderr
    assert 'Good "kratos-export" signature for kratos' in (sig.stdout + sig.stderr)
    assert r.fingerprint in sig.stdout + sig.stderr
    s = _sums(r.bundle)
    assert s.returncode == 0, s.stdout + s.stderr
    assert _ssh_verify(r.bundle, signed="SHA256SUMS").returncode == 0
    assert V.verify(r.bundle).ok
    assert "SHA256SUMS.sig < SHA256SUMS" in (r.bundle / "VERIFY.txt").read_text()


@pytest.mark.skipif(not HAVE_SSH_KEYGEN, reason="needs OpenSSH")
def test_a_wrong_namespace_or_key_fails_with_openssh(made, tmp_path):
    from kratos import signing
    from kratos.export import sshsig

    _info, r = made
    assert _ssh_verify(r.bundle, namespace="git").returncode != 0
    other = tmp_path / "other"
    signing.load_key(other)
    signers = tmp_path / "signers"
    signers.write_text(sshsig.allowed_signers_line(signing.public_key_openssh(other)))
    assert _ssh_verify(r.bundle, signers=signers).returncode != 0


def _flip(p: Path) -> None:
    b = bytearray(p.read_bytes())
    i = len(b) // 2
    b[i] = (b[i] + 1) % 256 if b[i] not in (0x0A,) else 0x41
    p.write_bytes(bytes(b))


def _every_file(bundle: Path) -> list[str]:
    return sorted(p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file())


@pytest.mark.skipif(not HAVE_SHA256SUM, reason="needs coreutils")
def test_one_changed_byte_in_any_file_fails_verification(tmp_path):
    _info, r = _make(tmp_path / "data")
    pristine = tmp_path / "pristine"
    shutil.copytree(r.bundle, pristine)
    files = _every_file(r.bundle)
    assert len(files) >= 10
    for rel in files:
        work = tmp_path / "work"
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(pristine, work)
        _flip(work / rel)
        rep = V.verify(work)
        assert not rep.ok, rel
        if HAVE_SSH_KEYGEN:
            assert not _stock_pair_passes(work), rel          # the responder's two commands catch it
        if rel == M.MANIFEST:
            assert not rep.signature_ok
        elif rel in (M.SUMS, M.SUMS_SIG):
            assert not rep.sums_signature_ok or not rep.sums_ok
        elif rel != M.SIGNATURE:
            assert _sums(work).returncode != 0, rel
            assert any(rel in p for p in rep.problems), (rel, rep.problems)


@pytest.mark.skipif(not (HAVE_SSH_KEYGEN and HAVE_SHA256SUM), reason="needs OpenSSH and coreutils")
def test_a_changed_file_with_a_regenerated_sha256sums_still_fails_the_stock_commands(made):
    """Signing only the manifest let this through: edit an evidence file, rewrite SHA256SUMS to
    match, and both commands passed. SHA256SUMS is signed now."""
    _info, r = made
    man = json.loads((r.bundle / "manifest.json").read_text())
    ev = next(f for f in man["files"] if f["kind"] == "evidence")
    _flip(r.bundle / ev["path"])
    (r.bundle / M.SUMS).write_text(M.sums_text(r.bundle))
    assert _sums(r.bundle).returncode == 0                      # the rewritten list matches the files...
    assert _ssh_verify(r.bundle, signed="SHA256SUMS").returncode != 0   # ...but its signature doesn't
    assert not _stock_pair_passes(r.bundle)
    rep = V.verify(r.bundle)
    assert not rep.ok and not rep.sums_signature_ok and any(ev["path"] in p for p in rep.problems)


def test_kratos_verify_names_the_changed_evidence_file(made):
    _info, r = made
    man = json.loads((r.bundle / "manifest.json").read_text())
    ev = next(f for f in man["files"] if f["kind"] == "evidence" and f["hashed_at"] == "collection")
    _flip(r.bundle / ev["path"])
    rep = V.verify(r.bundle)
    msgs = [p for p in rep.problems if ev["path"] in p]
    assert msgs and any("recorded when it collected it" in p for p in msgs)


def test_a_reordered_ledger_excerpt_fails(made):
    _info, r = made
    p = r.bundle / M.LEDGER
    lines = p.read_text().splitlines()
    assert len(lines) >= 2
    lines[0], lines[1] = lines[1], lines[0]
    p.write_text("\n".join(lines) + "\n")
    rep = V.verify(r.bundle)
    assert not rep.ok and rep.ledger_ok is False


def test_a_rewritten_ledger_row_in_the_excerpt_fails_even_with_sums_redone(made):
    """Someone who edits the excerpt and regenerates SHA256SUMS still breaks the signed head."""
    _info, r = made
    p = r.bundle / M.LEDGER
    rows = [json.loads(x) for x in p.read_text().splitlines()]
    full = next(x for x in rows if x.get("full") and x["kind"] == "file")
    full["sha256"] = "0" * 64
    p.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in rows))
    (r.bundle / M.SUMS).write_text(M.sums_text(r.bundle))
    rep = V.verify(r.bundle)
    assert rep.ledger_ok is False and not rep.ok


def test_hashes_are_the_collection_time_ones_and_pre_ledger_files_say_so(made):
    info, r = made
    man = json.loads((r.bundle / "manifest.json").read_text())
    by_src = {f.get("source_path"): f for f in man["files"] if f.get("source_path")}
    rel_pers = info["pers"].relative_to(info["pers"].parents[1]).as_posix()
    rec = L.latest_for_paths(info["pers"].parents[1], [rel_pers])[rel_pers]
    assert by_src[rel_pers]["hashed_at"] == "collection" and by_src[rel_pers]["sha256"] == rec.sha256
    assert by_src[rel_pers]["ledger_seq"] == rec.seq
    old = by_src["context/system_context_20260101_000000.json"]
    assert old["hashed_at"] == "export" and "predates Kratos's evidence ledger" in old["warning"]
    html = (r.bundle / "report.html").read_text()
    assert "predates Kratos" in html


def test_a_file_changed_after_collection_is_exported_with_a_warning_not_as_collection_time(tmp_path):
    d = tmp_path / "data"
    info = FX.build(d)
    info["pers"].write_text('{"edited": true}', encoding="utf-8")
    now = info["now"]
    r = C.create(d, ExportRequest(machines=[FX.M1], start=now - 86400, end=now + 60), ME)
    man = json.loads((r.bundle / "manifest.json").read_text())
    f = next(x for x in man["files"] if x.get("source_path", "").startswith("persistence/")
             and x["machine"] == FX.M1)
    assert f["hashed_at"] == "export" and "no longer matches" in f["warning"]
    assert any("changed since collection" in w for w in r.warnings)


def test_only_the_chosen_machines_files_are_in_it(made):
    info, r = made
    man = json.loads((r.bundle / "manifest.json").read_text())
    srcs = {f.get("source_path") for f in man["files"]}
    assert info["pers2"].name not in " ".join(s for s in srcs if s)
    assert all(f.get("machine") in (None, FX.M1) for f in man["files"])


def test_events_are_the_stores_canonical_documents_with_a_line_index(made):
    _info, r = made
    man = json.loads((r.bundle / "manifest.json").read_text())
    evf = next(f for f in man["files"] if f["kind"] == "events")
    lines = (r.bundle / evf["path"]).read_text().splitlines()
    assert len(lines) == evf["events"] == 13
    assert all(json.loads(x)["host"] for x in lines)
    assert V.verify(r.bundle, data_dir=Path(str(r.bundle).split("/exports/")[0])).local_ok is True


def test_the_export_is_in_the_ledger_and_the_export_records(made):
    _info, r = made
    d = Path(str(r.bundle).split("/exports/")[0])
    rows = C.list_exports(d)
    assert rows and rows[0]["export_id"] == r.export_id and rows[0]["by"] == "alice"
    assert rows[0]["manifest_sha256"] == r.manifest_sha256 and rows[0]["archive_sha256"] == r.archive_sha256
    assert rows[0]["fingerprint"] == r.fingerprint
    assert L.verify_chain(d).ok


def test_the_archive_is_deterministic(made, tmp_path):
    _info, r = made
    a1 = archive.write(r.bundle, tmp_path / "a1.tar.gz", mtime=1_700_000_000)
    a2 = archive.write(r.bundle, tmp_path / "a2.tar.gz", mtime=1_700_000_000)
    assert a1 == a2
    import tarfile

    with tarfile.open(tmp_path / "a1.tar.gz") as t:
        members = t.getmembers()
        assert all(m.uid == 0 and m.gid == 0 and m.mtime == 1_700_000_000 for m in members)
        assert [m.name for m in members] == sorted(m.name for m in members)


def test_the_event_cap_stops_with_a_stated_cut(tmp_path):
    from kratos import settings_store

    d = tmp_path / "data"
    info = FX.build(d)
    settings_store.set("export.max_events", 1000, data_dir=d, actor="test")
    now = info["now"]
    req = ExportRequest(machines=[FX.M1], start=now - 86400, end=now + 60)
    p = plan(d, req)
    p.max_events = 5   # below the setting's floor, to cut the small fixture
    p.events = [type(e)(e.machine, e.dataset, e.count, min(e.count, 5)) for e in p.events]
    r = C.create(d, req, ME, plan=p)
    man = json.loads((r.bundle / "manifest.json").read_text())
    assert man["cuts"] and man["cuts"][0]["included"] == 5 and man["cuts"][0]["in_window"] == 13
    assert "Cut:" in (r.bundle / "report.html").read_text()


def test_an_export_while_events_are_written_holds_a_consistent_snapshot(tmp_path):
    from kratos.events.store import EventStore

    d = tmp_path / "data"
    info = FX.build(d)
    now = info["now"]
    req = ExportRequest(machines=[FX.M1], start=now - 86400, end=now + 60)
    p = plan(d, req)
    EventStore(d / "kratos.db").add(FX._events(FX.M1, now + 1, n=4))   # "log sync" writes after the plan
    p_new = evidence.record(FX._write(d, "persistence/persistence_late.json", {"target": FX.M1}), data_dir=d,
                            category="persistence", machine=FX.M1)
    r = C.create(d, req, ME, plan=p)
    man = json.loads((r.bundle / "manifest.json").read_text())
    evf = next(f for f in man["files"] if f["kind"] == "events")
    assert evf["events"] == 13 and man["events_upto_row"] == p.events_upto_row
    assert not any((f.get("source_path") or "").endswith("persistence_late.json") for f in man["files"])
    assert man["ledger"]["head_seq"] < p_new.seq


def test_an_export_is_refused_inside_a_tool_call(tmp_path):
    from kratos import settings_store

    d = tmp_path / "data"
    info = FX.build(d)
    now = info["now"]
    with settings_store.tool_call_scope("run_linux_command"):
        with pytest.raises(ExportError, match="person's action"):
            C.create(d, ExportRequest(machines=[FX.M1], start=now - 86400, end=now), ME)


def test_no_registered_tool_can_export():
    import inspect

    from kratos.agent.tools import TOOL_REGISTRY

    for name, tool in TOOL_REGISTRY.items():
        src = inspect.getsource(inspect.getmodule(tool.handler))
        assert "kratos.export" not in src and "export.create" not in src, name


def test_a_group_export_states_an_unreachable_machine_s_gaps(tmp_path):
    """A fleet run that couldn't read M2 during the window: its gap is in the manifest and report."""
    from kratos.fleet import record as FR

    d = tmp_path / "data"
    info = FX.build(d)
    now = info["now"]
    from kratos.storage.sqlite_files import connect_store
    from kratos.storage.migrations import migrate_once

    c = connect_store(d / "kratos.db")
    migrate_once(c, d / "kratos.db", FR.COMPONENT, FR.STEPS)
    c.execute("INSERT INTO fleet_runs (run_id, kind, question, group_ref, actor, interface, source, status, "
              "started_at) VALUES ('fr1', 'question', 'who gained sudo?', '@web', 'alice', 'cli', 'cli', "
              "'final_answer', ?)", (now - 600,))
    for m, outcome, reason in ((FX.M1, "ok", None), (FX.M2, "unreachable", "ssh: connection timed out")):
        c.execute("INSERT INTO fleet_run_machines (run_id, machine, outcome, reason) VALUES ('fr1', ?, ?, ?)",
                  (m, outcome, reason))
    c.close()
    r = C.create(d, ExportRequest(machines=[FX.M1, FX.M2], start=now - 86400, end=now + 60, group="web"), ME)
    man = json.loads((r.bundle / "manifest.json").read_text())
    m2 = next(m for m in man["machines"] if m["shown"] == FX.M2)
    assert any("unreachable" in g and "connection timed out" in g for g in m2["gaps"])
    html = (r.bundle / "report.html").read_text()
    assert "unreachable" in html and "connection timed out" in html


def test_verify_against_another_kratos_is_a_note_not_a_failure(made, tmp_path):
    _info, r = made
    rep = V.verify(r.bundle, data_dir=tmp_path / "elsewhere")
    assert rep.ok and rep.local_ok is None


def test_a_rewritten_local_ledger_is_caught_on_the_kratos_that_signed(made):
    import sqlite3

    _info, r = made
    d = Path(str(r.bundle).split("/exports/")[0])
    conn = sqlite3.connect(d / "kratos.db")
    conn.execute("DROP TRIGGER evidence_ledger_no_update")
    man = json.loads((r.bundle / "manifest.json").read_text())
    head = man["ledger"]["head_seq"]
    conn.execute("UPDATE evidence_ledger SET entry_hash = ? WHERE seq = ?", ("f" * 64, head))
    conn.commit()
    conn.close()
    rep = V.verify(r.bundle, data_dir=d)
    assert rep.local_ok is False and not rep.ok


def test_sshsig_reads_a_signature_made_by_openssh(tmp_path):
    if not HAVE_SSH_KEYGEN:
        pytest.skip("needs OpenSSH")
    from kratos.export import sshsig

    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    msg = tmp_path / "m"
    msg.write_bytes(b"hello\n")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", "kratos-export", str(msg)], check=True)
    pub = (tmp_path / "k.pub").read_text()
    p = sshsig.verify(b"hello\n", (tmp_path / "m.sig").read_text(), allowed_public_keys=[pub])
    assert p.namespace == "kratos-export"
    with pytest.raises(sshsig.SignatureError):
        sshsig.verify(b"hello!\n", (tmp_path / "m.sig").read_text())


def test_time_taken_is_small_for_a_small_incident(made):
    _info, r = made
    assert r.seconds < 30
