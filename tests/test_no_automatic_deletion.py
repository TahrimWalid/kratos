"""Kratos deletes no stored data on its own (docs/phaseB/B.5 §3.1, §5.2).

Every `unlink` / `rmtree` / `remove` / `rmdir` / `truncate` call and every SQL
DELETE FROM / DROP TABLE / VACUUM statement in src/kratos is listed below with a
one-line reason. A new one fails this test until it is reviewed and listed: a temp
file it just created, the person's own command, a migration, a rebuild of public
data -- or a decision recorded for the owner.
"""
from __future__ import annotations

import _deletion_scan

TEMP = "a temporary file this function created moments ago (atomic write / download / scratch)"
PERSON = "the person's own delete command (the screen or CLI asked for it)"
LIST = "list.remove on an in-memory list, not stored data"
PUBLIC = "rebuild of public, regenerable vulnerability data (kratos vulndb-update)"

# (file under src/kratos, function, kind) -> why it is allowed
ALLOWED: dict[tuple[str, str, str], str] = {
    # in-memory lists
    ("adapters/findings_engine.py", "_merge_overlapping", "remove"): LIST,
    ("adapters/live_response.py", "_denied_dirs", "remove"): LIST + " (os.walk's dirs list)",
    ("pkgvuln/update.py", "_Writer.apply", "remove"): "calls _Writer.remove (its DELETE is listed)",
    ("pkgvuln/update.py", "_Writer.note_unparsed", "remove"): "calls _Writer.remove (its DELETE is listed)",
    ("pkgvuln/update.py", "_update_osv_incremental", "remove"): "calls _Writer.remove (its DELETE is listed)",
    ("tui_mk2/table_fit.py", "_clip", "truncate"): "Rich Text.truncate -- shortens text on screen",
    # temp files and scratch folders
    ("adapters/network_capture.py", "capture_traffic", "unlink"): TEMP + " (the pcap after it is parsed)",
    ("adapters/threat_intel.py", "update_threat_intel_cache", "unlink"): TEMP,
    ("adapters/vuln_scan.py", "_install_script_files", "unlink"): TEMP,
    ("adapters/vuln_scan.py", "build_cve_csv_from_nvd", "unlink"): TEMP,
    ("agent/presets.py", "_atomic_write", "unlink"): TEMP,
    ("agent/schedules.py", "_atomic_write", "unlink"): TEMP,
    ("agent/self_write_loop.py", "_atomic_write_metadata", "unlink"): TEMP,
    ("agent/triggers.py", "_atomic_write", "unlink"): TEMP,
    ("logsources/seal.py", "verify", "rmtree"): TEMP + " (the journal copy it verified)",
    ("logsources/seal.py", "_copy_and_verify", "unlink"): TEMP,
    ("paths.py", "write_private_text", "unlink"): TEMP,
    ("trace/recorder.py", "Trace._write", "unlink"): TEMP,
    ("trace/recorder.py", "Trace.finish", "unlink"): "the run record's own .partial copy, once the finished file is written",
    ("subagent/local_reads.py", "LocalReadServer.start", "unlink"): "a stale socket left by a listener that died",
    ("subagent/local_reads.py", "LocalReadServer.close", "unlink"): "this listener's own socket on shutdown",
    # the person's own commands
    ("agent/presets.py", "delete_preset", "unlink"): PERSON,
    ("agent/schedules.py", "delete_schedule", "unlink"): PERSON,
    ("agent/triggers.py", "delete_trigger", "unlink"): PERSON,
    ("logsources/seal.py", "remove_key", "unlink"): PERSON + " (`kratos seal remove-key`)",
    ("timewin/snapshots.py", "apply_retention", "unlink"): PERSON + " (`kratos snapshots prune --apply`)",
    ("dataprune.py", "_delete_files", "unlink"): PERSON + " (`kratos data prune --apply`)",
    ("dataprune.py", "_delete_files", "rmdir"): PERSON + " (the empty date folder that prune just emptied)",
    ("dataprune.py", "apply_prune", "DELETE FROM"): PERSON + " (`kratos data prune --apply`)",
    ("storage/subagent_store.py", "SubAgentStore.cancel_pairing_code", "DELETE FROM"): PERSON,
    ("storage/subagent_store.py", "SubAgentStore.forget_target", "DELETE FROM"): PERSON + " (forget an unpaired machine)",
    ("storage/subagent_store.py", "SubAgentStore.remove_link", "DELETE FROM"): PERSON + " (/target unlink)",
    ("storage/whitelist_store.py", "WhitelistStore.delete_user_entry", "DELETE FROM"): PERSON,
    ("storage/whitelist_store.py", "WhitelistStore.clear_maintainer_override", "DELETE FROM"): PERSON,
    ("collect/sync/cursors.py", "delete_cursors", "DELETE FROM"):
        "resets one log source's read position (called by nothing automatically)",
    # current state replaced, not history
    ("budget/ledger.py", "BudgetLedger.state_delete", "DELETE FROM"):
        "clears a flag (a pause being resumed), not a ledger row",
    ("storage/whitelist_store.py", "WhitelistStore.record_push_ack", "DELETE FROM"):
        "the agent accepted the allowlist: the 'refused' state it replaces is current state, not history",
    ("collect/sync/cursors.py", "add_span", "DELETE FROM"):
        "merges overlapping coverage spans into one row (the merged row covers them; nothing is lost)",
    ("timewin/snapshots.py", "reindex", "DELETE FROM"): "drops index rows for snapshot files that are already gone",
    # public data rebuilds
    ("pkgvuln/update.py", "_Writer.remove", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_Writer.clear_top", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_update_osv_full", "unlink"): TEMP,
    ("pkgvuln/update.py", "_modified_index", "unlink"): TEMP,
    ("pkgvuln/update.py", "_note_seen_modified", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_update_osv_incremental", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_update_osv_incremental", "unlink"): TEMP,
    ("pkgvuln/update.py", "_update_kev", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_update_kev", "unlink"): TEMP,
    ("pkgvuln/update.py", "_update_epss", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_update_epss", "unlink"): TEMP,
    ("pkgvuln/update.py", "_nvd_feed", "unlink"): TEMP,
    ("pkgvuln/update.py", "_build", "unlink"): TEMP,
    ("pkgvuln/update.py", "_build", "rmtree"): TEMP,
    ("pkgvuln/update.py", "_build", "DELETE FROM"): PUBLIC,
    ("pkgvuln/update.py", "_build", "VACUUM"): PUBLIC + " (compacts the new file before it replaces the old one)",
    # Found by this scan on main (B.5 Handoff): automatic, bounded housekeeping kept as is
    # and listed in kratos.datainv so the person sees it -- the owner decides.
    ("storage/subagent_store.py", "SubAgentStore.record_telemetry", "DELETE FROM"):
        "OWNER DECISION: live-status buffer, newest 500 telemetry rows per machine (~4 h)",
    ("storage/subagent_store.py", "SubAgentStore._add_event", "DELETE FROM"):
        "OWNER DECISION: connection history, newest 200 events per machine",
    ("storage/subagent_store.py", "SubAgentStore.create_pairing_code", "DELETE FROM"):
        "OWNER DECISION: unused pairing codes (secrets) a week after they expired",
}


def _found() -> dict[tuple[str, str, str], list[int]]:
    out: dict[tuple[str, str, str], list[int]] = {}
    for f, fn, kind, line in _deletion_scan.scan():
        out.setdefault((f, fn, kind), []).append(line)
    return out


def test_every_deletion_in_the_code_is_reviewed():
    found = _found()
    new = {k: v for k, v in found.items() if k not in ALLOWED}
    assert not new, (
        "code that deletes something and is not on the reviewed list in this test (Kratos deletes no stored "
        "data on its own; add it with a one-line reason only if it is a temp file, the person's own command, "
        f"a migration or public data): {new}")


def test_the_allowlist_has_no_stale_entries():
    found = _found()
    stale = [k for k in ALLOWED if k not in found]
    assert not stale, f"allowlist entries that no longer match any code (remove them): {stale}"


def test_every_allowlist_entry_has_a_reason():
    assert all(isinstance(r, str) and len(r.strip()) > 10 for r in ALLOWED.values())


def test_the_scan_catches_a_new_deletion(tmp_path):
    pkg = tmp_path / "kratos"
    pkg.mkdir()
    (pkg / "cleanup.py").write_text(
        "import os, shutil\n"
        "def tidy(data_dir):\n"
        "    (data_dir / 'reports' / 'old.json').unlink()\n"
        "    shutil.rmtree(data_dir / 'traces')\n"
        "    os.remove('x')\n"
        "class Store:\n"
        "    def prune(self, conn):\n"
        "        conn.execute(f'DELETE FROM {self.table} WHERE ts < ?', (1,))\n"
        "        conn.execute('''\n      delete from host_events where ts < ?''', (1,))\n"
        "        conn.execute('VACUUM')\n"
        "MESSAGE = 'entries were removed (vacuum or rotation)'\n")
    got = {(f, fn, k) for f, fn, k, _ in _deletion_scan.scan(pkg)}
    assert got == {("cleanup.py", "tidy", "unlink"), ("cleanup.py", "tidy", "rmtree"),
                   ("cleanup.py", "tidy", "remove"), ("cleanup.py", "Store.prune", "DELETE FROM"),
                   ("cleanup.py", "Store.prune", "VACUUM")}
