"""Load each machine's newest stored evidence for an attack-path build (E.1 §5.1).

**No machine is read here.** Every value comes from what D.2-E.7a already stored in
``kratos.db`` and the per-machine snapshot files under the data folder. A machine whose
newest reading is older than ``paths.max_input_age_hours`` is marked ``stale`` and is
counted as a coverage gap (never read to fill it); a machine with nothing stored is
``unread``. Each machine is pinned while its evidence is loaded, so a loader that checks
the active target reads the right machine.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos import kratos_config
from kratos.attackpaths import settings as S
from kratos.target_key import target_key


def _epoch_of(doc: dict[str, Any]) -> float | None:
    """When a snapshot was taken (its own stamp, UTC epoch), or None."""
    from kratos.utils.timeutil import epoch_of

    for key in ("checked_at_epoch", "checked_at", "taken_at", "scanned_at"):
        e = epoch_of(doc.get(key))
        if e is not None and e > 0:
            return e
    return None


def _read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class MachineInputs:
    target_key: str
    label: str = ""
    # evidence, each possibly None/empty when not stored or too old
    asset: Any = None                                   # assets.Asset | None
    findings: list[dict[str, Any]] = field(default_factory=list)   # open_verified findings
    live: dict[str, Any] | None = None                  # live-response snapshot (listeners, outbound, ...)
    key_identities: tuple[str, ...] = ()                # persistence baseline "user:fingerprint"
    privileged: dict[str, Any] | None = None            # privileged-accounts snapshot (accounts)
    containers: dict[str, Any] | None = None            # container snapshot
    code_roots: list[dict[str, Any]] = field(default_factory=list)   # confirmed code roots
    # coverage facts
    newest_epoch: float | None = None
    data_age_hours: float | None = None
    transport: str = "unknown"                          # ssh | agent | subagent | cert | unknown
    reader_root: bool = False                           # the newest live read ran as root (sees everything)
    ssh_only: bool = False                              # read over SSH only -> root-owned things invisible
    stale: bool = False                                 # older than max_input_age_hours
    unread: bool = False                                # nothing stored at all

    def has_data(self) -> bool:
        return not self.unread and not self.stale


def _transport_of(data_dir: Path, mk: str, live: dict[str, Any] | None) -> tuple[str, bool]:
    """(transport label, read-over-ssh-only). The newest live read's ``via`` is the ground
    truth for how this machine was last read; its ``reader_uid`` tells root from SSH user."""
    via = str((live or {}).get("via") or "").lower()
    reader_uid = (live or {}).get("reader_uid")
    root = reader_uid == 0
    if via in ("agent", "subagent"):
        return "subagent", False
    if via == "scan":
        return "scan", False
    # Fall back to the configured link when no live read says.
    try:
        from kratos.subagent import routing

        link = routing.link_for(mk, data_dir)
        if link is not None and getattr(link, "mode", "") == routing.MODE_SUBAGENT:
            return "subagent", False
    except Exception:  # noqa: BLE001 -- transport is best-effort, never fatal
        pass
    if via == "ssh":
        return "ssh", not root
    return "unknown", False


def load_machine(data_dir: Path, mk: str, *, now: float, max_age_hours: int) -> MachineInputs:
    """Everything stored about one machine, read-free. Pins the machine while loading."""
    from kratos.adapters.findings_engine import find_latest_inputs
    from kratos.assets import store as assets
    from kratos.code import store as code_store
    from kratos.lifecycle import query as lc_query
    from kratos.persist import baseline as persist_baseline

    mk = target_key(mk)
    mi = MachineInputs(target_key=mk)
    with kratos_config.pinned_target(mk):
        try:
            mi.asset = assets.get(data_dir, mk)
        except Exception:  # noqa: BLE001
            mi.asset = None
        try:
            mi.findings = lc_query.list_findings(data_dir, target=mk, state="open_verified")
        except Exception:  # noqa: BLE001
            mi.findings = []
        paths_map = find_latest_inputs(data_dir, target=mk)
        mi.live = _read_json(paths_map.get("live_response"))
        mi.privileged = _read_json(paths_map.get("privileged_accounts"))
        mi.containers = _read_json(paths_map.get("containers"))
        try:
            base = persist_baseline.load(data_dir, mk)
            mi.key_identities = tuple(base.keys) if base is not None else ()
        except Exception:  # noqa: BLE001
            mi.key_identities = ()
        try:
            mi.code_roots = [r for r in code_store.roots(data_dir, mk, status="confirmed")]
        except Exception:  # noqa: BLE001
            mi.code_roots = []

    # newest stamp across everything stored about the machine
    stamps: list[float] = []
    for doc in (mi.live, mi.privileged, mi.containers):
        if isinstance(doc, dict):
            e = _epoch_of(doc)
            if e is not None:
                stamps.append(e)
    try:
        base = persist_baseline.load(data_dir, mk)
        if base is not None and base.taken_at:
            stamps.append(float(base.taken_at))
    except Exception:  # noqa: BLE001
        pass
    for r in mi.code_roots:
        ca = r.get("checked_at_epoch") or r.get("confirmed_at")
        if isinstance(ca, (int, float)) and ca > 0:
            stamps.append(float(ca))
    from kratos.utils.timeutil import epoch_of

    for f in mi.findings:
        for k in ("last_seen", "last_checked"):
            e = epoch_of(f.get(k))
            if e is not None and e > 0:
                stamps.append(e)

    mi.transport, mi.ssh_only = _transport_of(data_dir, mk, mi.live)
    mi.reader_root = (mi.live or {}).get("reader_uid") == 0
    if not stamps and not mi.findings and mi.asset is None:
        mi.unread = True
        return mi
    if stamps:
        mi.newest_epoch = max(stamps)
        mi.data_age_hours = max(0.0, (now - mi.newest_epoch) / 3600.0)
        if mi.data_age_hours > max_age_hours:
            mi.stale = True
    elif not mi.findings:
        # an asset row but nothing read
        mi.unread = True
    return mi


def label_for(data_dir: Path, mk: str, asset: Any) -> str:
    """A machine's display label: its role, else its target_key (a hostname/address form)."""
    role = getattr(asset, "role", "") if asset is not None else ""
    return str(role).strip() or mk


def load_group(data_dir: Path, machines: list[str], *, now: float | None = None,
               max_age_hours: int | None = None) -> dict[str, MachineInputs]:
    """Load every machine in a resolved group, read-free, keyed by target_key."""
    now = time.time() if now is None else now
    cap = max_age_hours if max_age_hours is not None else int(S.get(S.MAX_INPUT_AGE_HOURS, data_dir))
    out: dict[str, MachineInputs] = {}
    for mk in machines:
        mi = load_machine(data_dir, mk, now=now, max_age_hours=cap)
        mi.label = label_for(data_dir, mi.target_key, mi.asset)
        out[mi.target_key] = mi
    return out
