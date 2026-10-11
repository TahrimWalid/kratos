"""Software installs, upgrades and removals.

    dpkg.log:          2026-10-11 17:17:54 install sl:amd64 <none> 5.02-1
                       2026-10-11 17:20:00 upgrade sudo:amd64 1.9.9-1ubuntu2.6 1.9.9-1ubuntu2.7
    apt history.log:   Start-Date / Commandline / Requested-By / Install|Upgrade|Remove|Purge / End-Date blocks
    dnf.rpm.log:       2026-10-11T17:19:25+0000 SUBDEBUG Installed: tree-1.8.0-10.el9.x86_64
    dnf.log:           2026-10-11T17:19:24+0000 DDEBUG Command: dnf -y -q install tree
"""
from __future__ import annotations

import re
from typing import Any

from kratos.logsources.parsers import Parsed

_DPKG = re.compile(r"^\S+ \S+ (?P<op>install|upgrade|remove|purge) (?P<pkg>\S+) (?P<old>\S+) (?P<new>\S+)")
_DNF_RPM = re.compile(r"^\S+ \S+ (?P<op>Installed|Upgrade|Upgraded|Erased|Erase|Removed|Downgrade|Downgraded|"
                      r"Reinstalled|Reinstall|Obsoleted): (?P<nevra>\S+)")
_DNF_CMD = re.compile(r"^\S+ \S+ Command: (?P<cmd>.*?)\s*$")
_DPKG_OPS = {"install": "package_installed", "upgrade": "package_upgraded", "remove": "package_removed",
             "purge": "package_removed"}
_DNF_OPS = {"Installed": "package_installed", "Upgrade": "package_upgraded", "Erased": "package_removed",
            "Erase": "package_removed", "Removed": "package_removed", "Downgrade": "package_downgraded",
            "Reinstalled": "package_reinstalled", "Reinstall": "package_reinstalled"}
_APT_LISTS = ("Install", "Upgrade", "Remove", "Purge", "Downgrade", "Reinstall")
_REQUESTED_BY = re.compile(r"^(?P<user>\S+) \((?P<uid>\d+)\)$")


def _split_nevra(nevra: str) -> tuple[str, str | None]:
    """tree-1.8.0-10.el9.x86_64 -> (tree, 1.8.0-10.el9)."""
    base = nevra.rsplit(".", 1)[0] if re.search(r"\.(x86_64|aarch64|noarch|i686|s390x|ppc64le|src)$", nevra) else nevra
    parts = base.rsplit("-", 2)
    if len(parts) == 3:
        return parts[0], f"{parts[1]}-{parts[2]}"
    return base, None


def _apt_packages(value: str) -> list[str]:
    """'sl:amd64 (5.02-1), libfoo:amd64 (1.0, 1.1)' -> ['sl', 'libfoo']"""
    names = []
    for item in re.finditer(r"(?:^|\),\s*)(?P<name>[^\s(,]+) \(", value):
        names.append(item.group("name").split(":", 1)[0])
    return names


def _apt_block(rec: Any) -> Parsed | None:
    lines = rec.text.split("\x1f")
    fields: dict[str, str] = {}
    for ln in lines:
        key, sep, val = ln.partition(": ")
        if sep:
            fields[key.strip()] = val.strip()
    pkgs: dict[str, list[str]] = {k: _apt_packages(fields[k]) for k in _APT_LISTS if k in fields}
    if not pkgs and "Commandline" not in fields:
        return None
    summary = "; ".join(f"{k}: {', '.join(v[:10])}{' ...' if len(v) > 10 else ''}" for k, v in pkgs.items() if v)
    every = [p for v in pkgs.values() for p in v]
    out: dict[str, Any] = {"process_command_line": fields.get("Commandline")}
    if m := _REQUESTED_BY.match(fields.get("Requested-By", "")):
        out.update(user_name=m.group("user"), user_id=m.group("uid"))
    if len(every) == 1:
        out["package_name"] = every[0]
    return Parsed(ts=rec.ts, action="package_transaction", provider="apt", message=summary or fields.get("Commandline"),
                  original=rec.text.replace("\x1f", "\n"), fields={k: v for k, v in out.items() if v},
                  log_file_path=rec.path, zone_assumed=rec.zone_assumed)


def to_parsed(rec: Any) -> Parsed | None:
    if rec.kind != "file":
        return None
    text = rec.text
    if text.startswith("Start-Date:"):
        return _apt_block(rec)
    if m := _DPKG.match(text):
        name, _, _arch = m.group("pkg").partition(":")
        version = m.group("new") if m.group("op") in ("install", "upgrade") else m.group("old")
        return Parsed(ts=rec.ts, action=_DPKG_OPS[m.group("op")], provider="dpkg", message=text, original=text,
                      fields={k: v for k, v in {"package_name": name, "package_version":
                              None if version == "<none>" else version}.items() if v},
                      log_file_path=rec.path, zone_assumed=rec.zone_assumed)
    if m := _DNF_RPM.match(text):
        if m.group("op") in ("Upgraded", "Downgraded", "Obsoleted"):
            return None  # the old side of an upgrade; the new side is its own line
        name, version = _split_nevra(m.group("nevra"))
        return Parsed(ts=rec.ts, action=_DNF_OPS[m.group("op")], provider="dnf", message=text, original=text,
                      fields={k: v for k, v in {"package_name": name, "package_version": version}.items() if v},
                      log_file_path=rec.path)
    if m := _DNF_CMD.match(text):
        return Parsed(ts=rec.ts, action="package_command", provider="dnf", message=text, original=text,
                      fields={"process_command_line": m.group("cmd"),
                              "process_name": m.group("cmd").split(None, 1)[0] if m.group("cmd").strip() else None}
                      if m.group("cmd").strip() else {}, log_file_path=rec.path)
    return None


def parse(read: Any) -> list[Parsed]:
    return [p for p in (to_parsed(r) for r in read.records) if p is not None]
