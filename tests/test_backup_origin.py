"""Who made a backup (kratos.backup.origin), and a drill that never runs what a backup brings.

age encrypts to a PUBLIC key, so anyone who knows a recipient key can make a file that opens
with the matching secret key. These tests build such a forgery the way an attacker would --
their own Kratos, the victim's public backup key, a kept tool that runs on import -- and check
that a drill and a restore refuse it, that a drill never imports kept tools or loads the
restored .env, and that the person's own backups still drill and restore everywhere."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import _backup_helpers as H
import pytest

from kratos.backup import create as CR
from kratos.backup import origin as O
from kratos.backup import restore as RS
from kratos.backup import verify as V


def _plant_kept_tool(roots, marker: Path) -> None:
    kt = roots.state / "kept_tools"
    kt.mkdir(parents=True, exist_ok=True)
    (kt / "innocent_looking.py").write_text(f"open({str(marker)!r}, 'w').write('ran')\n")
    (kt / "metadata.json").write_text(json.dumps({"innocent_looking": {
        "source_file": "innocent_looking.py", "requires_approval": False, "kept_at": "2026-01-01T00:00:00Z"}}))


@pytest.fixture
def victim(tmp_path):
    r = H.home(tmp_path, "victim")
    H.seed(r)
    ident = H.identity()
    H.set_recipient(r, ident)
    return r, ident


@pytest.fixture
def forged(tmp_path, victim):
    """A backup made on the ATTACKER's own Kratos, encrypted to the victim's public key."""
    vroots, vident = victim
    a = H.home(tmp_path, "attacker")
    H.seed(a)
    marker = tmp_path / "attacker_code_ran"
    _plant_kept_tool(a, marker)
    (a.config / ".env").write_text("LLM_MODEL=attacker-model\n")
    H.set_recipient(a, vident)            # the victim's PUBLIC key is all it takes
    res = CR.create(a.data, actor=H.CLI, dest=tmp_path / "dropbox", roots=a, copy_to=[])
    return res, marker, O.signer_fingerprint(a.data)


def test_every_backup_is_signed_and_verify_says_whether_this_kratos_signed_it(victim, tmp_path):
    r, ident = victim
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    side = res.sidecar.read_text()
    assert "# signer: SHA256:" in side and "# signature: " in side
    c = V.quick(res.file, data_dir=r.data)
    assert c.ok and c.origin.status == "this"
    assert any("signed by this Kratos" in n for n in c.notes)


def test_a_drill_refuses_a_backup_signed_by_another_kratos(victim, forged):
    vroots, vident = victim
    res, marker, attacker_fp = forged
    d = V.drill(res.file, [vident], data_dir=vroots.data, actor=H.CLI)
    assert not d.ok and any(attacker_fp in p and "--signer" in p for p in d.problems)
    assert not marker.exists()


def test_a_restore_refuses_a_backup_signed_by_another_kratos_and_writes_nothing(tmp_path, victim, forged):
    _vroots, vident = victim
    res, marker, attacker_fp = forged
    new = H.home(tmp_path, "new")
    with pytest.raises(RS.RestoreError, match="signed by " + attacker_fp.replace("+", r"\+")):
        RS.restore(res.file, [vident], roots=new, actor=H.CLI)
    with pytest.raises(RS.RestoreError, match="not by"):
        RS.restore(res.file, [vident], roots=new, actor=H.CLI, accept_signer="SHA256:" + "A" * 43)
    assert not (new.state / "kept_tools").exists() and not (new.config / ".env").exists()
    assert not marker.exists()


def test_a_forged_backup_with_no_sidecar_is_refused_unless_the_person_says_so(tmp_path, victim, forged):
    vroots, vident = victim
    res, marker, _fp = forged
    res.sidecar.unlink()
    d = V.drill(res.file, [vident], data_dir=vroots.data, actor=H.CLI)
    assert not d.ok and any("not signed" in p and "--unsigned-ok" in p for p in d.problems)
    with pytest.raises(RS.RestoreError, match="not signed"):
        RS.restore(res.file, [vident], roots=H.home(tmp_path, "new"), actor=H.CLI)
    assert not marker.exists()


def test_a_sidecar_whose_signature_was_swapped_is_invalid(victim, forged, tmp_path):
    vroots, vident = victim
    res, _marker, _fp = forged
    own = CR.create(vroots.data, actor=H.CLI, dest=tmp_path / "own", roots=vroots, copy_to=[])
    # the forger copies a REAL sidecar's signature lines onto the forged file's hash
    real = {ln.split(": ", 1)[0]: ln for ln in own.sidecar.read_text().splitlines() if ln.startswith("# sig")}
    lines = [real.get(ln.split(": ", 1)[0], ln) for ln in res.sidecar.read_text().splitlines()]
    res.sidecar.write_text("\n".join(lines) + "\n")
    c = V.quick(res.file, data_dir=vroots.data)
    assert not c.ok and c.origin.status == "bad"
    d = V.drill(res.file, [vident], data_dir=vroots.data, actor=H.CLI)
    assert not d.ok and any("INVALID" in p for p in d.problems)


def test_a_drill_the_person_accepts_still_never_runs_the_backups_kept_tools(victim, forged):
    """Even past the signer check, the health check imports nothing from the backup."""
    vroots, vident = victim
    res, marker, attacker_fp = forged
    d = V.drill(res.file, [vident], data_dir=vroots.data, actor=H.CLI, accept_signer=attacker_fp)
    assert d.restored_files > 0
    assert not marker.exists(), "the drill imported a kept tool from the backup"


def test_the_drills_health_check_runs_isolated_without_the_backups_settings(victim, tmp_path, monkeypatch):
    r, ident = victim
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    seen = {}

    def fake_run(argv, env=None, cwd=None, **kw):
        home = Path(env["KRATOS_HOME"])
        seen.update(argv=argv, env=env, env_file=(home / ".env").exists(),
                    kept=(home / "kept_tools").exists())
        return subprocess.CompletedProcess(argv, 0, b"PASS fine\n", b"")

    monkeypatch.setattr(V.subprocess, "run", fake_run)
    monkeypatch.setenv("PYTHONPATH", "/somewhere")
    d = V.drill(res.file, [ident], data_dir=r.data, actor=H.CLI)
    assert d.ok, d.problems
    assert seen["argv"][:2] == [sys.executable, "-I"]
    assert seen["env"]["KRATOS_NO_KEPT_TOOLS"] == "1" and "PYTHONPATH" not in seen["env"]
    assert seen["kept"] and not seen["env_file"]


def test_kratos_no_kept_tools_keeps_main_from_importing_them(tmp_path):
    home = tmp_path / "h"
    marker = tmp_path / "ran"
    (home / "data").mkdir(parents=True)
    _plant_kept_tool(H.Roots(home / "data", home, home), marker)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("KRATOS_", "LLM_"))}
    env.update(KRATOS_HOME=str(home), KRATOS_NO_KEPT_TOOLS="1")
    out = subprocess.run([sys.executable, "-m", "kratos.cli.app", "--help"], env=env, capture_output=True,
                         timeout=120)
    assert out.returncode == 0 and not marker.exists()


def test_the_persons_own_backup_restores_on_a_new_computer_with_the_key_file(victim, tmp_path):
    """The signer line the key file carries is read when the whole file is piped in."""
    r, ident = victim
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    fp = O.signer_fingerprint(r.data)
    key_file = f"# public key: {ident.recipient()}\n# {O.SIGNER_LINE}: {fp}\n{ident.secret}\n"
    assert O.fingerprint_in(key_file) == fp
    home = tmp_path / "fresh"
    (home / "data").mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("KRATOS_", "LLM_", "XDG_"))}
    env.update(KRATOS_HOME=str(home), NO_COLOR="1")
    out = subprocess.run([sys.executable, "-m", "kratos.cli.app", "backup", "restore", str(res.file), "--yes",
                          "--no-wait"], env=env, input=key_file.encode(), capture_output=True, timeout=300)
    assert out.returncode == 0, out.stdout.decode() + out.stderr.decode()
    assert (home / "data" / "kratos.db").exists()
    only_secret = subprocess.run([sys.executable, "-m", "kratos.cli.app", "backup", "restore", str(res.file),
                                  "--yes", "--no-wait"], env={**env, "KRATOS_HOME": str(tmp_path / "fresh2")},
                                 input=ident.secret.encode(), capture_output=True, timeout=300)
    assert only_secret.returncode == 2 and b"--signer" in only_secret.stderr
