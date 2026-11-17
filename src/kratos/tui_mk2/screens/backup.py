"""`/backup`: backups from the app (docs/phaseD/D.8 §5.2).

The status first -- lock mode, last backup, last successful drill, the same-disk warning,
the schedule, what isn't covered -- then the actions: `n` back up now (live progress:
database copy → files → encrypt → copies), `d` drill a backup, `k` set up a backup key
(the secret shown once in a click-to-copy box, then a confirmation that it was saved),
`s` schedule. Restore is not here: the app holds the data open, so restore is
`kratos backup restore` on the command line (the screen says so).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, title_row
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text

_STYLE = {"pass": T.SAFE, "warn": T.ATTENTION, "fail": T.CRITICAL, "info": T.TEXT_MUTED}
_ORDER = {"fail": 0, "warn": 1, "pass": 2, "info": 3}
RESTORE_NOTE = ("Restoring is done on the command line: kratos backup restore <file> "
                "(the app holds the data open, so it can't restore over itself).")
# The status rows are shared with `kratos backup status` and /doctor, so they name CLI commands.
# On this screen a key does each of these; only restore (and prune) stay on the command line.
_KEY_FOR = [
    (re.compile(r"`kratos backup key new`"), "press k"),
    (re.compile(r"`kratos backup create`, then `kratos backup drill <file>`"), "press n, then d"),
    (re.compile(r"(run )?`kratos backup create`( by hand)?"), "press n"),
    (re.compile(r"`kratos backup drill [^`]*`"), "press d"),
    (re.compile(r"`kratos backup schedule daily --copy-to /mnt/usb/kratos` or\s*--copy-to sftp://user@host/path"),
     "press s and give a copy target (another disk, or sftp://user@host/path)"),
]


def screen_fix(text: str) -> str:
    for pattern, words in _KEY_FOR:
        text = pattern.sub(words, text)
    return text


class BackupScreen(Screen):
    _ALL_KEYS = ("↑↓ select · n back up now · d drill a backup · k set up a backup key\n"
                 "s schedule · r refresh · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("n", "create", "back up now", show=True),
        Binding("d", "drill", "drill", show=True),
        Binding("k", "key", "set up key", show=True),
        Binding("s", "schedule", "schedule", show=True),
        Binding("r", "refresh", "refresh", show=True),
    ]
    # A2: title row, the status checks as a table (worst first), a detail pane for the
    # selected check with what to press, the log of what you ran, and a key bar.
    CSS = layout_css("BackupScreen", "bk")

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._busy = False
        self._lines: list[Text] = []
        self._rows: list[dict[str, str]] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="bk-banner")
            yield DataTable(id="bk-table", cursor_type="row")
            yield Static(id="bk-detail")
            with VerticalScroll(id="bk-log"):
                yield Static(id="bk-log-text")
            yield Static(key_bar([("n", "back up now"), ("d", "drill"), ("k", "key"), ("s", "schedule"),
                                  ("?", "all keys"), ("esc", "back")]), id="bk-hints")

    def on_mount(self) -> None:
        self._log(RESTORE_NOTE, T.TEXT_DIM)
        self.action_refresh()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.action_refresh)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{RESTORE_NOTE}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("Backups — all keys", body))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        try:
            detail = self.query_one("#bk-detail", Static)
            table = self.query_one("#bk-table", DataTable)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        if not self._rows or table.cursor_row is None:
            detail.update(Text("", style=T.TEXT_MUTED))
            return
        r = self._rows[min(table.cursor_row, len(self._rows) - 1)]
        out = Text()
        out.append(f"{r['status'].upper():<5} ", style=f"bold {_STYLE.get(r['status'], T.TEXT)}")
        out.append(r["check"], style=f"bold {T.TEXT_BRIGHT}")
        out.append(f"\n{r['detail']}", style=T.TEXT)
        if r.get("fix") and r["status"] in ("warn", "fail"):
            out.append(f"\n→ {screen_fix(r['fix'])}", style=T.ATTENTION)
        elif r.get("fix"):
            out.append(f"\n{screen_fix(r['fix'])}", style=T.TEXT_DIM)
        detail.update(out)

    def action_refresh(self) -> None:
        from kratos.backup import status as ST

        rows = sorted(ST.doctor_rows(self._data_dir), key=lambda r: _ORDER.get(r["status"], 9))
        s = ST.summary(self._data_dir)
        summary = f"schedule {s['schedule']}" + (" · copied to " + ", ".join(s["copy_targets"])
                                                  if s["copy_targets"] else "")
        problems = sum(1 for r in rows if r["status"] in ("warn", "fail"))
        dest = Path(s["destination"])
        try:
            dest_words = "~/" + str(dest.relative_to(Path.home()))     # short, so the title stays on one line
        except ValueError:
            dest_words = str(dest)
        self.query_one("#bk-banner", Static).update(title_row(
            "Backups", dest_words, summary,
            note=f"{problems} to look at" if problems else "", note_style=T.ATTENTION))
        table = self.query_one("#bk-table", DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        columns = ("", "check", "detail")
        table.add_columns(*columns)
        self._rows = rows
        cells = [[Text(r["status"].upper(), style=_STYLE.get(r["status"], T.TEXT)), r["check"], r["detail"]]
                 for r in rows]
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(2, 20), (1, 12)], headers=columns):
            table.add_row(*row)
        if rows:
            table.move_cursor(row=min(cursor or 0, len(rows) - 1))
        self._show_detail()

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
            self._log("No backup key yet: press k to set one up (a passphrase backup is made on the command "
                      "line: `kratos backup create --passphrase`).", T.ATTENTION)
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
        pick = await self.app.push_screen_wait(ListPickerModal("Drill which backup?", [(p, p.name) for p in files]))
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
        from kratos.backup import origin

        signer = origin.signer_fingerprint(self._data_dir, create=True)
        await self.app.push_screen_wait(CommandModal(
            f"# {origin.SIGNER_LINE}: {signer}\n{ident.secret}", title="Your backup key -- shown this one time",
            note="Keep both lines OFF this computer: a password manager, a printout or a USB stick. Kratos keeps "
                 "only the public half, so nothing here can open a backup. Anyone holding this key can open every "
                 "backup -- and a backup can act as this Kratos to your agents and sign SSH certificates for your "
                 "machines. The first line is the fingerprint this Kratos signs backups with: a restore on a new "
                 "computer checks it."))
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
            ("daily", "daily (recommended)"), ("weekly", "weekly"), ("off", "off")]))
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
                "too. Add a copy target later: press s again and give one.", yes_label="ok"))
            del ok
        self.action_refresh()
