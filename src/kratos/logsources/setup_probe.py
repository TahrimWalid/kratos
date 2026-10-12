"""Setup-probe rows for the 0.3 log sources (adapters/ssh_remote.run_target_probe_checks).

A fixed, read-only sh fragment, built from the source table: for each source,
whether the SSH user can read it on this machine (PASS), can't (FAIL, with the
exact setup fix), or it isn't present (UNKNOWN); auditd's status through the
two allowed `sudo -n auditctl` lines; whether the journal is kept on disk. The
machine-id it prints is used Kratos-side for the sealing row (`sealing_row`):
the verification key never goes to the machine -- only the comparison happens
here.
"""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from kratos.logsources import catalog


def _source_case(src: catalog.Source) -> str:
    lines = ["case \"$FAMILY\" in"]
    for family in catalog.FAMILIES:
        files = " ".join(shlex.quote(f.path) for f in src.files.get(family, ()))
        journal = "1" if src.journal.get(family) else "0"
        gap = src.gaps.get(family, "")
        fix = src.access_for(family) or "add the SSH user to the adm group"
        lines.append(f"{family}) kr_probe_src {shlex.quote(src.name)} {journal} {shlex.quote(gap)} "
                     f"{shlex.quote(fix)} {files} ;;")
    lines.append("*) printf 'log_source_%s\\tUNKNOWN\\tunknown distribution\\n' " + shlex.quote(src.name) + " ;;")
    lines.append("esac")
    return "\n".join(lines)


_FN = r'''
KR_CT=$(systemd-detect-virt -c 2>/dev/null || echo none)
KR_J=0
if groups | tr ' ' '\n' | grep -qx systemd-journal || sudo -n journalctl -n 1 >/dev/null 2>&1; then KR_J=1; fi
kr_probe_src() {  # name has_journal gap fix files...
  _n=$1; _hj=$2; _gap=$3; _fix=$4; shift 4
  _read=""; _unread=""; _any=0
  for _f in "$@"; do
    if [ -e "$_f" ]; then _any=1
      if [ -r "$_f" ] && [ ! -L "$_f" ]; then _read="$_read $_f"; else _unread="$_unread $_f"; fi
    elif [ -d "${_f%/*}" ] && [ ! -x "${_f%/*}" ]; then _any=1; _unread="$_unread $_f"
    fi
  done
  if [ -n "$_gap" ] && [ "$_any" = 0 ] && [ "$_hj" = 0 ]; then printf 'log_source_%s\tUNKNOWN\tNot on this machine: %s\n' "$_n" "$_gap"; return; fi
  if [ "$_n" = firewall ] && [ "$KR_CT" != none ] && [ -n "$KR_CT" ]; then
    printf 'log_source_firewall	WARN	This is a container (%s): the kernel writes firewall log lines on the host, not here -- read them on the host
' "$KR_CT"; return
  fi
  if [ "$_hj" = 1 ] && [ "$KR_J" = 1 ]; then
    if [ -n "$_unread" ]; then printf 'log_source_%s\tWARN\tJournal readable; not readable:%s (fix: %s)\n' "$_n" "$_unread" "$_fix"
    else printf 'log_source_%s\tPASS\tReadable (journal%s)\n' "$_n" "${_read:+ +$_read}"; fi
    return
  fi
  if [ -n "$_read" ] && [ -z "$_unread" ]; then printf 'log_source_%s\tPASS\tReadable:%s\n' "$_n" "$_read"; return; fi
  if [ -n "$_unread" ]; then printf 'log_source_%s\tFAIL\tNot readable:%s (fix: %s)\n' "$_n" "$_unread" "$_fix"; return; fi
  if [ "$_hj" = 1 ]; then printf 'log_source_%s\tFAIL\tIts journal isn'"'"'t readable (fix: add the SSH user to systemd-journal)\n' "$_n"; return; fi
  printf 'log_source_%s\tUNKNOWN\tNot present on this machine\n' "$_n"
}
'''


def probe_script() -> str:
    parts = [catalog.FAMILY_SH, _FN]
    parts += [_source_case(s) for s in catalog.SOURCES.values()]
    parts.append(r'''
if ! command -v auditctl >/dev/null 2>&1 && [ ! -x /sbin/auditctl ] && [ ! -x /usr/sbin/auditctl ]; then
  printf 'audit_status\tUNKNOWN\tauditd is not installed -- no record of programs run on this machine\n'
elif sudo -n auditctl -s >/dev/null 2>&1 && sudo -n auditctl -l >/dev/null 2>&1; then
  printf 'audit_status\tPASS\tsudo -n auditctl -s / -l work\n'
else
  printf 'audit_status\tFAIL\tCannot read auditd status -- add the two auditctl sudo lines from the checklist (step 3)\n'
fi
if [ -d /var/log/journal ]; then printf 'journal_persistent\tPASS\tThe journal is kept on disk (/var/log/journal)\n'
elif command -v journalctl >/dev/null 2>&1; then printf 'journal_persistent\tWARN\tThe journal is kept in memory only (lost at reboot; sealing needs it on disk -- checklist step 7)\n'
fi
printf 'machine_id\tINFO\t%s\n' "$(head -c 64 /etc/machine-id 2>/dev/null)"
''')
    return "\n".join(parts) + "\n"


def sealing_row(data_dir: Path | None, target: str, machine_id: str | None) -> dict[str, str]:
    """The Kratos-side sealing row: a key on file for this machine, bound to the
    same machine-id the machine reports now."""
    from kratos.logsources import seal

    if data_dir is None:
        return {"check": "sealing", "status": "UNKNOWN", "detail": "Kratos doesn't know its data folder here"}
    doc = seal.load_key(data_dir, target)
    if doc is None:
        return {"check": "sealing", "status": "INFO",
                "detail": "Not set up (recommended): /target seal -- lets Kratos prove the journal wasn't edited"}
    if doc.get("machine_id") and machine_id and doc["machine_id"] != machine_id:
        return {"check": "sealing", "status": "FAIL",
                "detail": "The key on file belongs to a different machine-id (reinstalled?) -- set up sealing again"}
    last = seal.latest_summary(data_dir, target) or {}
    return {"check": "sealing", "status": "PASS",
            "detail": f"Verification key on file; last check: {last.get('status', 'not yet')}"}


def finish_rows(rows: list[dict[str, Any]], data_dir: Path | None, target: str) -> list[dict[str, Any]]:
    """Replace the raw machine_id row with the sealing row."""
    mid = next((r["detail"].strip() for r in rows if r.get("check") == "machine_id"), None)
    out = [r for r in rows if r.get("check") != "machine_id"]
    out.append(sealing_row(data_dir, target, mid or None))
    return out
