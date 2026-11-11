"""`kratos backup` end to end, who may use it, prune, schedule, copies, keys, the doctor
rows and `/backup` (docs/phaseD/D.8 §3.10–§3.13, §5.2, §7 Permissions / Deletion scan)."""
from __future__ import annotations

import ast
import asyncio
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import _backup_helpers as H
import pytest

from kratos import authz, settings_store
from kratos.backup import copies as CP
from kratos.backup import create as CR
from kratos.backup import keys as K
from kratos.backup import prune as PR
from kratos.backup import schedule as SC
from kratos.backup import status as ST
from kratos.backup import store as BR
from kratos.lifecycle.decide import Actor

SRC = Path(__file__).parents[1] / "src" / "kratos"


def _cli(home: Path, *argv: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("KRATOS_", "LLM_"))}
    env.update(KRATOS_HOME=str(home), NO_COLOR="1")
    return subprocess.run([sys.executable, "-m", "kratos.cli.app", *argv], env=env, input=stdin,
                          capture_output=True, timeout=300, cwd=str(home))


def test_the_cli_round_trip_key_create_verify_drill_restore(tmp_path):
    home = tmp_path / "h1"
    home.mkdir()
    assert _cli(home, "init").returncode == 0
    key = tmp_path / "usb" / "key.txt"
    key.parent.mkdir()
    out = _cli(home, "backup", "key", "new", "--write-to", str(key))
    assert out.returncode == 0, out.stderr
    assert key.stat().st_mode & 0o777 == 0o600 and "AGE-SECRET-KEY-1" in key.read_text()
    assert "AGE-SECRET-KEY" not in out.stdout.decode()      # shown only at a terminal, never in a log
    dry = _cli(home, "backup", "create", "--dry-run", "--dest", str(tmp_path / "bk"))
    assert dry.returncode == 0 and b"never backed up" in dry.stdout and not (tmp_path / "bk").exists()
    made = _cli(home, "backup", "create", "--dest", str(tmp_path / "bk"))
    assert made.returncode == 0, made.stderr
    f = next((tmp_path / "bk").glob("*.age"))
    assert _cli(home, "backup", "verify", str(f)).returncode == 0
    assert _cli(home, "backup", "verify", str(f), "--full", stdin=key.read_bytes()).returncode == 0
    drill = _cli(home, "backup", "drill", str(f), stdin=key.read_bytes())
    assert drill.returncode == 0 and b"Drill PASSED" in drill.stdout, drill.stdout + drill.stderr
    status = _cli(home, "backup", "status").stdout.decode()
    assert "restore drill" in status and "last successful drill" in status
    new = tmp_path / "h2"
    new.mkdir()
    r = _cli(new, "backup", "restore", str(f), "--yes", stdin=key.read_bytes())
    assert r.returncode == 0, r.stdout + r.stderr
    assert (new / ".env").exists() and (new / "data" / "kratos.db").exists()
    again = _cli(new, "backup", "restore", str(f), "--yes", stdin=key.read_bytes())
    assert again.returncode == 2 and b"already holds data" in again.stderr


def test_key_new_away_from_a_terminal_needs_a_file(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    out = _cli(home, "backup", "key", "new")
    assert out.returncode == 2 and b"--write-to" in out.stderr


def test_the_secret_key_is_refused_inside_kratoss_folders(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    out = _cli(home, "backup", "key", "new", "--write-to", str(home / "data" / "k.txt"))
    assert out.returncode == 2 and b"inside Kratos" in out.stderr


# --- who may --------------------------------------------------------------------------
def test_backup_code_is_unreachable_from_mcp_chat_and_model_tools():
    """No network door or agent tool imports kratos.backup (and so none can make, restore or
    prune a backup); the CLI and the TUI are the only callers."""
    offenders = []
    for p in SRC.rglob("*.py"):
        rel = str(p.relative_to(SRC))
        if rel.startswith(("backup/", "cli/", "tui_mk2/")) or rel in ("agent/doctor.py",):
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            if any(m == "kratos.backup" or m.startswith("kratos.backup.") for m in mods):
                offenders.append(rel)
    # The test's own conftest guard is not in src; doctor reads status only.
    assert offenders == [], offenders


def test_no_registered_tool_reaches_backup():
    from kratos.agent.tools import TOOL_REGISTRY

    for name, tool in TOOL_REGISTRY.items():
        mod = getattr(tool.handler, "__module__", "") or ""
        assert not mod.startswith("kratos.backup"), name


def test_backup_is_refused_inside_a_tool_call(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    H.set_recipient(r, H.identity())
    with settings_store.tool_call_scope("evil"):
        with pytest.raises(CR.BackupError, match="agent tools"):
            CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])


@pytest.mark.parametrize("role", ["viewer", "investigator"])
def test_viewers_and_investigators_are_refused(tmp_path, role):
    from kratos.authz import users as U

    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    u = U.add_user(r.data, f"u-{role}", role, H.CLI)
    person = Actor(user=u.name, interface="cli", user_id=u.user_id)
    with pytest.raises(CR.BackupError, match="refused"):
        CR.create(r.data, actor=person, dest=tmp_path / "bk", roots=r, passphrase="x" * 20, copy_to=[])


def test_network_actors_are_refused_admin_or_not(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    net = Actor(user="token:abc", interface="serve", user_id="owner", credential="token:abc")
    with pytest.raises(CR.BackupError, match="refused"):
        CR.create(r.data, actor=net, dest=tmp_path / "bk", roots=r, passphrase="x" * 20, copy_to=[])


def test_every_action_is_in_the_audit_trail(tmp_path):
    from kratos.authz import audit as AU

    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    H.set_recipient(r, H.identity())
    CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    rows = AU.query(r.data)
    assert any(x["action"] == authz.P.BACKUP_MANAGE and x["result"] == "allowed" for x in rows)


def test_prune_is_cli_only_preview_first_and_recorded(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    H.set_recipient(r, H.identity())
    dest = tmp_path / "bk"
    made = []
    for i in range(3):
        made.append(CR.create(r.data, actor=H.CLI, dest=dest, roots=r, copy_to=[]).file)
        os.utime(made[-1], None)
    other = dest / "my-notes.txt"
    other.write_text("not a backup")
    # another Kratos home sharing the folder (audit D): its backups are never this home's to prune
    r2 = H.home(tmp_path, "second")
    H.seed(r2, with_keys=False, events=0)
    H.set_recipient(r2, H.identity())
    theirs = CR.create(r2.data, actor=H.CLI, dest=dest, roots=r2, copy_to=[]).file
    stray = dest / "kratos-backup-20200101T000000Z.age"
    stray.write_bytes(b"no sidecar")
    plan = PR.plan(dest, 1, data_dir=r.data)
    assert plan.remove == sorted(made)[:2] and all(p.exists() for p in made)   # a preview removes nothing
    assert sorted(plan.others) == sorted([theirs, stray])
    with pytest.raises(PR.PruneError, match="command line"):
        PR.apply(r.data, plan, actor=H.TUI)
    done = PR.apply(r.data, plan, actor=H.CLI)
    assert len(done["removed"]) == 2 and sorted(dest.iterdir()) == sorted(
        [sorted(made)[2], sorted(made)[2].with_name(sorted(made)[2].name + ".sha256"), other, theirs,
         theirs.with_name(theirs.name + ".sha256"), stray])
    with sqlite3.connect(r.data / "kratos.db") as c:
        assert c.execute("SELECT category, items FROM data_prunes").fetchall() == [("backups", 2)]
    assert BR.last(r.data, "prune")
    with pytest.raises(PR.PruneError):
        PR.plan(dest, 0, data_dir=r.data)


def test_there_is_no_automatic_keep_setting():
    assert not [s.key for s in settings_store.specs() if s.key == "backup.keep"]


# --- schedule / notifications ---------------------------------------------------------
def test_schedule_needs_a_key_and_writes_a_persistent_timer(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    with pytest.raises(SC.ScheduleError, match="backup key"):
        SC.set_schedule(r.data, "daily", actor=H.CLI)
    H.set_recipient(r, H.identity())
    out = SC.set_schedule(r.data, "daily", actor=H.CLI, copy_to=[str(tmp_path / "usb")], bin_path="/x/kratos")
    timer = Path(out["timer"]).read_text()
    service = Path(out["service"]).read_text()
    assert "Persistent=true" in timer and "OnCalendar=*-*-* 0" in timer
    assert f"--data-dir {r.data.resolve()} backup create --scheduled" in service
    assert any("enable --now kratos-backup.timer" in c for c in out["commands"])
    assert ST.summary(r.data)["schedule"] == "daily"
    assert SC.set_schedule(r.data, "off", actor=H.CLI)["cadence"] == "off"


def test_a_scheduled_failure_goes_out_through_the_outbox(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("kratos.outbox.alerts.enqueue_alert", lambda text, sev, **k: seen.append((text, sev, k)) or
                        {"status": "queued"})
    SC.notify(tmp_path, "Kratos's scheduled backup FAILED: no space left on the disk.", severity="critical")
    assert seen and seen[0][2]["source"] == "schedule" and seen[0][2]["name"] == "backup"
    assert SC.reason_word(OSError(28, "No space left on device")) == "no space left on the disk"
    assert "/" not in SC.reason_word(RuntimeError("could not open /home/alice/x"))


# --- copies ----------------------------------------------------------------------------
def test_a_folder_copy_is_verified_by_hash(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    H.set_recipient(r, H.identity())
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[str(tmp_path / "usb")])
    c = res.copies[0]
    assert c["ok"] and c["verified"] == "sha256"
    assert (tmp_path / "usb" / res.file.name).read_bytes() == res.file.read_bytes()
    assert (tmp_path / "usb" / res.sidecar.name).exists()


def test_a_copy_into_the_data_folder_is_refused(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    H.set_recipient(r, H.identity())
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[str(r.data / "copies")])
    assert not res.copies[0]["ok"] and "data folder" in res.copies[0]["error"]


@pytest.mark.parametrize("bad", ["sftp://host/x", "sftp://bob@host/a;b", "sftp://bob@host/../x", "sftp://bob@-o/x",
                                 "sftp://bob@host/-rf", "relative/folder", "sftp://bob:pw@host/x",
                                 "sftp://bob@host/x?y=1"])
def test_bad_copy_targets_are_refused(bad):
    with pytest.raises(ValueError):
        CP.parse_target(bad)


def test_sftp_uses_a_fixed_batch_file_and_no_shell(tmp_path, monkeypatch):
    seen = []

    class Done:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(argv, **kw):
        seen.append((argv, kw))
        batch = Path(argv[argv.index("-b") + 1]).read_text()
        if "get " in batch:
            back = batch.split("get ")[1].split()[1]
            Path(back).write_bytes(side.read_bytes())
            d = Done()
            d.stdout = f"-rw------- 1 u u {f.stat().st_size} Nov 10 x {f.name}\n".encode()
            return d
        return Done()

    monkeypatch.setattr(CP.subprocess, "run", fake_run)
    f = tmp_path / "kratos-backup-20261110T000000Z.age"
    f.write_bytes(b"x" * 100)
    side = f.with_name(f.name + ".sha256")
    side.write_text("h")
    out = CP.copy("sftp://bob@backup.example.com/srv/k", f, side, "h", data_dir=tmp_path / "d", work=tmp_path / "w")
    assert out["ok"], out
    argv, kw = seen[0]
    assert argv[:2] == ["sftp", "-b"] and "BatchMode=yes" in argv and argv[-1] == "bob@backup.example.com"
    assert "shell" not in kw
    batch = Path(argv[2]).read_text().splitlines()
    assert batch == ["-mkdir /srv/k", f"put {f} /srv/k/{f.name}.partial", f"put {side} /srv/k/{side.name}",
                     f"rename /srv/k/{f.name}.partial /srv/k/{f.name}"]


# --- keys ------------------------------------------------------------------------------
def test_recipients_are_public_keys_only_at_most_five(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    ids = [H.identity() for _ in range(6)]
    for i in ids[:5]:
        K.add_recipient(r.data, str(i.recipient()), actor="t")
    with pytest.raises(K.KeyError_, match="at most 5"):
        K.add_recipient(r.data, str(ids[5].recipient()), actor="t")
    with sqlite3.connect(r.data / "kratos.db") as c:
        assert "AGE-SECRET-KEY" not in str(c.execute("SELECT * FROM app_settings").fetchall())
    with pytest.raises(K.KeyError_):
        K.add_recipient(r.data, ids[0].secret, actor="t")         # a secret key is not a recipient
    K.remove_recipient(r.data, K.fingerprint(str(ids[0].recipient())), actor="t")
    assert len(K.recipients(r.data)) == 4


def test_passphrase_rules_and_the_generated_words():
    with pytest.raises(K.KeyError_):
        K.check_passphrase("short one")
    words = K.generate_passphrase().split()
    assert len(words) == 6 and all(w in set(K.word_list()) for w in words)
    assert len(K.word_list()) == 2048


def test_reading_an_identity_file_or_a_passphrase():
    ident = H.identity()
    got = K.read_identities(f"# created: x\n# public key: {ident.recipient()}\n{ident.secret}\n")
    assert len(got) == 1 and str(got[0].recipient()) == str(ident.recipient())
    pp = K.read_identities("a long enough passphrase\n")
    assert pp[0].__class__.__name__ == "ScryptIdentity"
    with pytest.raises(K.KeyError_, match="post-quantum"):
        K.read_identities("AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR")


# --- doctor rows -------------------------------------------------------------------------
def test_doctor_warns_until_a_backup_and_a_drill_exist(tmp_path):
    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    rows = {x["check"]: x for x in ST.doctor_rows(r.data)}
    assert rows["backup lock"]["status"] == "warn" and rows["last backup"]["status"] == "warn"
    ident = H.identity()
    H.set_recipient(r, ident)
    settings_store.set("backup.destination", str(tmp_path / "bk"), data_dir=r.data, actor="t")
    res = CR.create(r.data, actor=H.CLI, roots=r, copy_to=[])
    rows = {x["check"]: x for x in ST.doctor_rows(r.data)}
    assert rows["backup lock"]["status"] == "pass" and rows["last backup"]["status"] == "pass"
    assert rows["restore drill"]["status"] == "warn" and "backup on same disk" in rows
    assert "backup folder" in rows and "Kratos deletes none" in rows["backup folder"]["detail"]
    from kratos.backup import verify as V

    assert V.drill(res.file, [ident], data_dir=r.data, actor=H.CLI).ok
    rows = {x["check"]: x for x in ST.doctor_rows(r.data)}
    assert rows["restore drill"]["status"] == "pass"


def test_doctor_shows_the_backup_rows(tmp_path):
    from kratos.agent import doctor

    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    checks = doctor.run_diagnostics(r.data, offline=True)
    names = {c["check"] for c in checks}
    assert {"backup lock", "last backup"} <= names and "LLM endpoint" not in " ".join(names)


# --- /backup -----------------------------------------------------------------------------
def test_the_backup_screen_sets_up_a_key_and_backs_up(tmp_path, monkeypatch):
    from textual.app import App

    from kratos.tui_mk2.screens import backup as SB

    r = H.home(tmp_path)
    H.seed(r, with_keys=False, events=0)
    settings_store.set("backup.destination", str(tmp_path / "bk"), data_dir=r.data, actor="t")
    shown = []

    class Host(App):
        def on_mount(self):
            self.push_screen(SB.BackupScreen(r.data))

    async def go():
        app = Host()
        async with app.run_test(size=(160, 40)) as pilot:
            async def answer(modal):
                shown.append(modal)
                if modal.__class__.__name__ == "CommandModal":
                    return None
                return modal._command_secret if False else shown[0]._command[-6:]

            monkeypatch.setattr(app, "push_screen_wait", answer)
            await pilot.press("k")
            for _ in range(100):
                await pilot.pause()
                if K.recipients(r.data):
                    break
            assert K.recipients(r.data)
            signer_line, secret = shown[0]._command.split("\n")
            assert secret.startswith("AGE-SECRET-KEY-1")
            from kratos.backup import origin as O

            assert O.fingerprint_in(signer_line) == O.signer_fingerprint(r.data)   # the box is a key file
            assert secret not in str(BR.runs(r.data)) and secret not in str(K.recipients(r.data))
            await pilot.press("n")
            for _ in range(300):
                await pilot.pause()
                if BR.last(r.data, "create"):
                    break
            assert BR.last(r.data, "create")["interface"] == "tui"
            text = str(app.screen.query_one("#bk-hints").render())
            assert "kratos backup restore" in text

    asyncio.run(go())


def test_after_a_restore_the_old_computers_backups_dont_count(tmp_path):
    from kratos.backup import restore as RS

    old = H.home(tmp_path, "old")
    H.seed(old, with_keys=False, events=0)
    ident = H.identity()
    H.set_recipient(old, ident)
    res = CR.create(old.data, actor=H.CLI, dest=tmp_path / "bk", roots=old, copy_to=[])
    new = H.home(tmp_path, "new")
    RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    rows = {x["check"]: x for x in ST.doctor_rows(new.data)}
    assert rows["last backup"]["detail"] == "none made yet" and "restored from" in rows
    assert "backup on same disk" not in rows


def test_subagent_install_records_the_address_the_agent_will_dial(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    out = _cli(home, "subagent-install", "--core-host", "core.example.test", "--name", "web-01", "--out",
               str(tmp_path / "i.sh"))
    assert out.returncode == 0, out.stderr
    with sqlite3.connect(home / "data" / "kratos.db") as c:
        assert c.execute("SELECT core_host FROM subagent_pairing_codes").fetchall() == [("core.example.test",)]


def test_a_hostile_backup_gets_a_plain_message_not_a_traceback(tmp_path):
    ident = H.identity()
    import tarfile as _tf

    ti = _tf.TarInfo("data/sessions/x.json")
    ti.type = _tf.SYMTYPE
    ti.linkname = "/etc/passwd"
    f = H.craft(tmp_path / "evil.age", ident.recipient(), [(ti, None)],
                {"format": "kratos-backup/1", "kratos_version": "0.1.0", "files": [],
                 "totals": {"files": 0, "bytes": 0}})
    home = tmp_path / "h"
    home.mkdir()
    unsigned = _cli(home, "backup", "restore", str(f), "--yes", stdin=ident.secret.encode())
    assert unsigned.returncode == 2 and b"not signed" in unsigned.stderr and b"Traceback" not in unsigned.stderr
    out = _cli(home, "backup", "restore", str(f), "--yes", "--unsigned-ok", stdin=ident.secret.encode())
    assert out.returncode == 2 and b"Traceback" not in out.stderr and b"can't be trusted" in out.stderr
    wrong = _cli(home, "backup", "restore", str(f), "--yes", "--unsigned-ok", stdin=H.identity().secret.encode())
    assert wrong.returncode == 2 and b"doesn't open this backup" in wrong.stderr


def test_subagent_install_says_the_port_to_listen_on_when_it_isnt_the_default(tmp_path):
    """Audit D: the "make sure this core is listening" hint left out --port, so following it
    started a listener the new agent never dials."""
    home = tmp_path / "h"
    home.mkdir()
    out = _cli(home, "subagent-install", "--core-host", "core.example.test", "--core-port", "8774", "--name",
               "web-02", "--out", str(tmp_path / "i.sh"))
    assert out.returncode == 0, out.stderr
    assert "kratos subagent-serve --host core.example.test --port 8774" in out.stdout.decode()


def test_a_machine_can_be_linked_to_its_sub_agent_from_the_command_line(tmp_path):
    """Audit D: only the app's /target link could tie an address to a paired agent, so a
    headless install had no way to read a box through its sub-agent."""
    from kratos.storage.subagent_store import SubAgentStore
    from kratos.subagent import routing

    home = tmp_path / "h"
    (home / "data").mkdir(parents=True)
    store = SubAgentStore(home / "data" / "kratos.db")
    store.redeem_pairing_code(store.create_pairing_code(name="web-01")["code"], "a1", "web-01", "0.11.1")
    assert _cli(home, "subagent-link", "192.0.2.40").stdout.decode().count("reached over SSH") == 1
    bad = _cli(home, "subagent-link", "192.0.2.40", "nope")
    assert bad.returncode == 2 and b"paired: web-01" in bad.stderr
    ok = _cli(home, "subagent-link", "192.0.2.40", "web-01")
    assert ok.returncode == 0 and b"through its sub-agent only (web-01)" in ok.stdout
    link = store.get_link("192.0.2.40")
    assert link is not None and link["mode"] == routing.MODE_SUBAGENT
    assert _cli(home, "subagent-link", "192.0.2.40", "--remove").returncode == 0
    assert store.get_link("192.0.2.40") is None
