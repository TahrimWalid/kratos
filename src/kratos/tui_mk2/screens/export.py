"""`/export`: make an incident bundle from the TUI (D.6).

Pick the machines (this one, a group, or a list), the period, full or redacted, and
whether to add a written summary (the model, which holds no tools; its cost estimate is
shown first). The size estimate and every cut are shown before anything is written;
`y` makes it. The result names the bundle folder, its archive hash and the signing-key
fingerprint, and puts the two OpenSSH/coreutils commands in a copy-safe box.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from kratos.lifecycle.decide import Actor
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, ListPickerModal, PromptModal

PERIODS = [
    ("1d", "the last 24 hours"),
    ("3d", "the last 3 days"),
    ("7d", "the last 7 days"),
    ("30d", "the last 30 days"),
    ("all", "everything Kratos holds"),
    ("custom", "another start (e.g. 2026-11-01, '12 hours ago')"),
]
VARIANTS = [
    ("full", "full — everything as collected (for your own team)"),
    ("redacted", "redacted — names, addresses and accounts replaced, secrets removed (to send outside)"),
]


def _machine_choices(data_dir: Path, active: str | None) -> list[tuple[Any, str]]:
    from kratos.fleet import groups as G

    out: list[tuple[Any, str]] = []
    if active:
        out.append((("machines", [active]), f"this machine ({active})"))
    try:
        for g in G.list_groups(data_dir):
            out.append((("group", g.name), f"group @{g.name} ({len(g.members)} machine(s))"))
    except Exception:  # noqa: BLE001 -- no groups yet
        pass
    out.append((("group", "all"), "every machine (@all)"))
    out.append((("ask", None), "other machines (type them)"))
    return out


async def export_flow(app: Any, data_dir: Path, *, active: str | None, run_create: Any, emit: Any) -> None:
    """The questions, then ``run_create(req, plan)`` (a worker) does the export."""
    from kratos.export import narrative as N
    from kratos.export import settings as ES
    from kratos.export.scope import ExportRequest, plan
    from kratos.fleet import groups as G
    from kratos.hunt.front import HuntUsageError, time_bound
    from kratos.target_key import target_key

    pick = await app.push_screen_wait(ListPickerModal("Export which machines?", _machine_choices(data_dir, active),
                                                      subtitle="↑↓ pick · enter · esc cancel"))
    if pick is None:
        return
    kind, value = pick
    group = None
    if kind == "machines":
        machines = [target_key(m) for m in value]
    elif kind == "group":
        try:
            res = G.resolve(data_dir, value)
        except Exception as e:  # noqa: BLE001
            emit(f"Not exported: {e}")
            return
        machines, group = res.machines, res.name
    else:
        typed = await app.push_screen_wait(PromptModal("Machines (comma separated)", "10.0.0.5, web-01"))
        if not typed:
            return
        machines = [target_key(m) for m in typed.split(",") if target_key(m)]
    if not machines:
        emit("Not exported: no machine chosen.")
        return

    period = await app.push_screen_wait(ListPickerModal("Which period?", PERIODS, subtitle="the bundle holds what "
                                                        "Kratos collected in it"))
    if period is None:
        return
    if period == "custom":
        typed = await app.push_screen_wait(PromptModal("Start of the period", "2026-11-01, '12 hours ago', 3d"))
        if not typed:
            return
        period = typed
    try:
        start = None if period == "all" else time_bound(period)
    except HuntUsageError as e:
        emit(f"Not exported: {e}")
        return
    variant = await app.push_screen_wait(ListPickerModal("Full or redacted?", VARIANTS))
    if variant is None:
        return
    req = ExportRequest(machines=machines, start=start, end=time.time(), variant=variant, group=group)
    try:
        p = plan(data_dir, req)
    except Exception as e:  # noqa: BLE001
        emit(f"Not exported: {e}")
        return
    cap = float(ES.get(ES.NARRATIVE_MAX_USD, data_dir))
    est = "x" * (2000 + sum(len(v) for v in p.findings.values()) * 400 + len(machines) * 1500)
    _tok, cost, model = N.estimate(est, data_dir)
    cost_s = f"about ${cost:.3f}" if cost is not None else "cost unknown (no rate set)"
    want = await app.push_screen_wait(ConfirmModal(
        "Add a written summary?",
        f"A model ({model}) that holds no tools reads the collected facts and writes a summary per machine; Kratos "
        f"checks each part against that machine's evidence. {cost_s}; skipped above ${cap:.2f} "
        "(export.narrative_max_usd).", yes_label="add it", no_label="no summary"))
    req.narrative = bool(want)
    ok = await app.push_screen_wait(ConfirmModal("Make this export?", "\n".join(p.summary_lines()),
                                                 yes_label="export", no_label="cancel"))
    if not ok:
        emit("Not exported.")
        return
    run_create(req, p)


def show_result(app: Any, r: Any) -> None:
    cmd = (f"cd {r.bundle}\n"
           "ssh-keygen -Y verify -f allowed_signers -I kratos -n kratos-export -s manifest.json.sig < manifest.json\n"
           "sha256sum -c SHA256SUMS")
    note = (f"Signed by {r.fingerprint} (the 'signing key' /doctor shows). "
            + (f"Archive SHA-256: {r.archive_sha256} -- note it down or send it separately from the file. "
               if r.archive_sha256 else "")
            + "Anyone can run these two commands on any computer with OpenSSH.")
    app.push_screen(CommandModal(cmd, title="Bundle made — check it anywhere", note=note))


def actor() -> Actor:
    return Actor.current("tui")
