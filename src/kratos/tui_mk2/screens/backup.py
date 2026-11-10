"""`/backup`: backups from the app (docs/phaseD/D.8 §5.2).

The status first -- lock mode, last backup, last successful drill, the same-disk warning,
the schedule, what isn't covered -- then the actions: `n` back up now (live progress:
database copy → files → encrypt → copies), `d` drill a backup, `k` set up a backup key
(the secret shown once in a click-to-copy box, then a confirmation that it was saved),
`s` schedule. Restore is not here: the app holds the data open, so restore is
`kratos backup restore` on the command line (the screen says so).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeStatic as Static
from kratos.untrusted_rich import SafeText as Text

_STYLE = {"pass": T.SAFE, "warn": T.ATTENTION, "fail": T.CRITICAL, "info": T.TEXT_MUTED}


class BackupScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("n", "create", "back up now", show=True),
        Binding("d", "drill", "drill", show=True),
        Binding("k", "key", "set up key", show=True),
        Binding("s", "schedule", "schedule", show=True),
        Binding("r", "refresh", "refresh", show=True),
    ]
    CSS = """
    BackupScreen { padding: 1 2; }
    BackupScreen #bk-status { height: auto; }
    BackupScreen #bk-log { height: 1fr; padding-top: 1; }
    BackupScreen #bk-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._busy = False
        self._lines: list[Text] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="bk-status")
            with VerticalScroll(id="bk-log"):
                yield Static(id="bk-log-text")
            yield Static(Text("n back up now · d drill · k backup key · s schedule · r refresh · esc back\n"
                              "Restoring is done on the command line: kratos backup restore <file>\n"
                              "(the app holds the data open, so it can't restore over itself).", style=T.TEXT_DIM),
                         id="bk-hints")

    def on_mount(self) -> None:
        self.action_refresh()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        from kratos.backup import status as ST

        rows = ST.doctor_rows(self._data_dir)
        s = ST.summary(self._data_dir)
        t = Text()
        t.append("Backups", style=f"bold {T.ACCENT}")
        t.append(f"   to {s['destination']} · schedule {s['schedule']}", style=T.TEXT_DIM)
        if s["copy_targets"]:
            t.append(" · copied to " + ", ".join(s["copy_targets"]), style=T.TEXT_DIM)
        for r in rows:
            t.append(f"\n{r['status'].upper():<5} ", style=_STYLE.get(r["status"], T.TEXT))
            t.append(f"{r['check']}: ", style=T.TEXT)
            t.append(r["detail"], style=T.TEXT_MUTED)
            if r.get("fix") and r["status"] in ("warn", "fail"):
                t.append(f"\n      → {r['fix']}", style=T.TEXT_DIM)
        self.query_one("#bk-status", Static).update(t)

    def _log(self, text: str, style: str = T.TEXT) -> None:
        self._lines.append(Text(text, style=style))
        self._lines = self._lines[-200:]
        out = Text()
        for i, line in enumerate(self._lines):
            if i:
                out.append("\n")
            out.append_text(line)
        self.query_one("#bk-log-text", Static).update(out)

    def _actor(self) -> Actor:
        return Actor.current("tui")

    # ------------------------------------------------------------------ create
    def action_create(self) -> None:
        if self._busy:
            return
        from kratos.backup import keys as K

        if not K.recipients(self._data_dir):
            self._log("No backup key yet: press k to set one up (a passphrase backup is made with "
                      "`kratos backup create --passphrase`).", T.ATTENTION)
            return
        self._busy = True
        self._log("Backing up ...", T.ACCENT)
        self._create_worker()

    @work(thread=True, exclusive=True)
    def _create_worker(self) -> None:
        from kratos.backup import create as CR

        def progress(stage: str, text: str) -> None:
            self.app.call_from_thread(self._log, f"  {stage}: {text}", T.TEXT_MUTED)

        try:
            res = CR.create(self._data_dir, actor=self._actor(), progress=progress)
        except Exception as e:  # noqa: BLE001 -- shown in plain words
            self.app.call_from_thread(self._log, f"Backup failed: {e}", T.CRITICAL)
        else:
            self.app.call_from_thread(self._log, f"Backup written: {res.file} ({res.size // 1024} KB, "
                                                 f"{res.seconds:.1f} s)", T.SAFE)
            for c in res.copies:
                self.app.call_from_thread(self._log, f"  copy -> {c['target']}: " + (
                    "verified" if c.get("ok") else f"FAILED: {c.get('error')}"), T.SAFE if c.get("ok") else T.CRITICAL)
            for w in res.warnings:
                self.app.call_from_thread(self._log, f"  ! {w}", T.ATTENTION)
            self.app.call_from_thread(self._log, "  Next: press d to drill it (proves it restores).", T.TEXT_DIM)
        finally:
            self._busy = False
            self.app.call_from_thread(self.action_refresh)

    # ------------------------------------------------------------------ drill
    @work
    async def action_drill(self) -> None:
        if self._busy:
            return
        from kratos.backup import status as ST

        files = list(reversed(ST.backup_files(ST.destination(self._data_dir))))[:20]
        if not files:
            self._log("No backup in the backup folder yet: press n to make one.", T.ATTENTION)
            return
        pick = await self.app.push_screen_wait(ListPickerModal("Drill which backup?", [(p, p.name) for p in files],
                                                               subtitle="↑↓ pick · enter · esc cancel"))
        if pick is None:
            return
        secret = await self.app.push_screen_wait(PromptModal(
            "The backup's secret key (or its passphrase)",
            hint="AGE-SECRET-KEY-1… -- used for this drill only, never stored", password=True))
        if not secret:
            return
        from kratos.backup import keys as K

        try:
            ids = K.read_identities(secret)
        except K.KeyError_ as e:
            self._log(f"Not drilled: {e}", T.CRITICAL)
            return
        del secret
        self._busy = True
        self._log(f"Drilling {pick.name} ...", T.ACCENT)
        self._drill_worker(pick, ids)

    @work(thread=True, exclusive=True)
    def _drill_worker(self, path: Path, ids: list[Any]) -> None:
        from kratos.backup import verify as V

        try:
            r = V.drill(path, ids, data_dir=self._data_dir, actor=self._actor(),
                        progress=lambda t: self.app.call_from_thread(self._log, f"  {t}", T.TEXT_MUTED))
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._log, f"Drill failed: {e}", T.CRITICAL)
        else:
            if r.ok:
                self.app.call_from_thread(self._log, f"Drill PASSED ({r.restored_files} files restored into a scratch "
                                                     f"home and checked, {r.seconds:.1f} s). This backup is verified.",
                                          T.SAFE)
            else:
                for p in r.problems:
                    self.app.call_from_thread(self._log, f"Drill FAILED: {p}", T.CRITICAL)
        finally:
            ids.clear()
            self._busy = False
            self.app.call_from_thread(self.action_refresh)

    # ------------------------------------------------------------------ key
    @work
    async def action_key(self) -> None:
        from kratos.backup import keys as K
        from kratos.backup.create import BackupError, _authorize

        try:
            _authorize(self._actor(), self._data_dir, "backup key new")
        except BackupError as e:
            self._log(str(e), T.CRITICAL)
            return
        if len(K.recipients(self._data_dir)) >= 5:
            self._log("A backup can be opened by at most 5 keys; remove one with `kratos backup key remove`.",
                      T.ATTENTION)
            return
        ident = K.new_identity()
        await self.app.push_screen_wait(CommandModal(
            ident.secret, title="Your backup key -- shown this one time",
            note="Keep it OFF this computer: a password manager, a printout or a USB stick. Kratos keeps only the "
                 "public half, so nothing here can open a backup. Anyone holding this key can open every backup -- "
                 "and a backup can act as this Kratos to your agents and sign SSH certificates for your machines."))
        typed = await self.app.push_screen_wait(PromptModal(
            "Confirm you saved it", hint="Type the key's last 6 characters (esc: nothing is set up)"))
        if not typed or typed.strip().upper() != ident.secret[-6:]:
            self._log("Not set up: the confirmation didn't match. Press k to start again.", T.ATTENTION)
            return
        try:
            K.add_recipient(self._data_dir, str(ident.recipient()), actor="tui:backup key new")
        except K.KeyError_ as e:
            self._log(f"Not set up: {e}", T.CRITICAL)
            return
        self._log(f"Backups are now encrypted to {K.fingerprint(str(ident.recipient()))}.", T.SAFE)
        self.action_refresh()

    # ------------------------------------------------------------------ schedule
    @work
    async def action_schedule(self) -> None:
        from kratos.backup import schedule as SC

        pick = await self.app.push_screen_wait(ListPickerModal("Back up on a timer", [
            ("daily", "daily (recommended)"), ("weekly", "weekly"), ("off", "off")], subtitle="enter · esc cancel"))
        if pick is None:
            return
        copy_to = None
        if pick != "off":
            typed = await self.app.push_screen_wait(PromptModal(
                "Copy each backup to (optional)",
                hint="a folder on another disk (/mnt/usb/kratos) or sftp://user@host/path; empty: keep it here"))
            if typed is None:
                return
            copy_to = [typed.strip()] if typed.strip() else []
        try:
            out = SC.set_schedule(self._data_dir, pick, actor=self._actor(), copy_to=copy_to)
        except Exception as e:  # noqa: BLE001
            self._log(f"Not scheduled: {e}", T.CRITICAL)
            return
        title = "Install the backup timer" if pick != "off" else "Remove the backup timer"
        await self.app.push_screen_wait(CommandModal("\n".join(out["commands"]), title=title,
                                                     note="Kratos doesn't run systemctl itself: run these in a "
                                                          "terminal."))
        if pick != "off" and not out.get("copy_targets"):
            ok = await self.app.push_screen_wait(ConfirmModal(
                "No copy target", "The scheduled backups stay on this computer's disk -- a lost disk loses them "
                "too. Add a copy target later with `kratos backup schedule daily --copy-to …`.", yes_label="ok"))
            del ok
        self.action_refresh()
