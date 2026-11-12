"""What a person sees of a machine's baseline (TUI /baseline, `kratos baseline show`, MCP and
chat): per kind of normal, its learning status, the most usual things with their weights,
today's deviations, and people's decisions. Read-only; scoped to the person's machines.

A deviation's group context ("usual for this account on db-02") names only machines the
reader may see; any other is "a machine outside your access" (D.7: a viewer never learns a
machine outside their scope through an aggregate).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos.baseline import buckets as B
from kratos.baseline import dims as D
from kratos.baseline import learn as L
from kratos.baseline import record
from kratos.baseline import store as S
from kratos.target_key import target_key

TOP_N = 10
STATUS_WORDS = {"active": "learned", "learning": "still learning", "frozen": "frozen",
                "not_learnable": "not learnable here"}


class ViewError(ValueError):
    """Refused or unknown; nothing was read."""


def _iso(ts: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat(timespec="seconds") if ts else None
    except (TypeError, ValueError, OverflowError):
        return None


def resolve(data_dir: Path | str, actor: Any, machine: str | None) -> tuple[str, Any]:
    """(target_key, scope) after `baseline.read` for this machine; refused outside scope."""
    from kratos import authz

    if not machine:
        # The active machine is the Kratos host's own default: only a person at the Kratos host
        # gets it implicitly. A network door must name one of the caller's machines (naming the
        # default in a refusal would tell an out-of-scope reader it exists).
        if getattr(actor, "interface", None) not in ("tui", "cli"):
            raise ViewError("which machine? (name one of your machines)")
        from kratos.kratos_config import get_active_target

        machine = get_active_target()
    if not machine:
        raise ViewError("which machine?")
    try:
        p = authz.require(actor, authz.P.BASELINE_READ, machine, data_dir=data_dir, obj="baseline view")
    except authz.Denied as e:
        raise ViewError(str(e)) from None
    return target_key(machine), p.scope


def view(data_dir: Path | str, machine: str, *, scope: Any = None, dim: str | None = None,
         now: float | None = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    tk = target_key(machine)
    now = time.time() if now is None else now
    st = L.Settings.load(data_dir)
    doc = record.load(record.path_for(data_dir, tk)) or {}
    out: dict[str, Any] = {"machine": tk, "checked_at": doc.get("checked_at"), "zone": doc.get("zone"),
                           "learn_days": st.learn_days, "dims": [], "deviations": [], "decisions": [],
                           "history": [], "frozen": False}
    if not (Path(data_dir) / "kratos.db").exists():
        return out
    accounts = record.local_accounts(data_dir, tk)
    with S.opened(data_dir) as conn:
        profiles = S.current_profiles(conn, tk)
        for d in D.DIMS:
            if dim and d.name != dim:
                continue
            p = profiles.get(d.name)
            status = (doc.get("dims") or {}).get(d.name) or {}
            row: dict[str, Any] = {"name": d.name, "rule": d.rule, "label": d.label,
                                   "status": status.get("status") or ("learning" if p else "not_learnable"),
                                   "learned_days": status.get("learned_days", 0),
                                   "covered_days": status.get("covered_days", 0),
                                   "learning": status.get("learning"), "reason": status.get("reason") or
                                   ("" if p else "nothing learned yet (no collection has run the baseline check)"),
                                   "evicted": int(p["evicted"]) if p else 0, "held_back": int(p["held_back"]) if p
                                   else 0, "generation": int(p["generation"]) if p else 0, "top": []}
            if p is not None:
                out["frozen"] = out["frozen"] or bool(p["frozen"])
                ents = [L.Entry.from_row(r) for r in S.entries(conn, tk, d.name, int(p["generation"]))]
                live = [e for e in ents if e.live and e.evicted_at is None]
                hl = st.half_life_days * L.DAY
                live.sort(key=lambda e: (-L.decayed(e, now, hl), e.subject, e.key))
                row["entries"] = len(live)
                row["top"] = [{"subject": e.subject, "key": e.key, "weight": round(L.decayed(e, now, hl), 1),
                               "count": e.count, "first_seen": _iso(e.first_seen), "last_seen": _iso(e.last_seen),
                               "accepted": bool(e.accepted_at), "held": sum(int(c) for c, _ in e.held.values()),
                               # a deleted (or renamed) account's entries are kept, marked
                               "gone": bool(accounts) and d.subject_word in ("account", "user")
                               and e.subject not in accounts}
                              for e in live[:TOP_N]]
            out["dims"].append(row)
        for h in S.history(conn, tk):
            if dim and h["dim"] != dim:
                continue
            out["history"].append({"dim": h["dim"], "generation": int(h["generation"]), "started": _iso(h["started_at"]),
                                   "ended": _iso(h["ended_at"]), "tz": h["tz"], "note": h["note"]})
        for r in S.decisions(conn, tk, limit=20):
            out["decisions"].append({"at": _iso(r["at"]), "kind": r["kind"], "dim": r["dim"], "subject": r["subject"],
                                     "key": r["key"], "by": r["actor"], "via": r["interface"], "reason": r["reason"]})
        for dv in doc.get("deviations") or []:
            if not isinstance(dv, dict) or (dim and dv.get("dim") != dim):
                continue
            item = {k: dv.get(k) for k in ("rule", "dim", "subject", "key", "kind", "severity", "machine_time",
                                           "usual", "learned", "held")}
            det = dv.get("detail") or {}
            item["address"] = det.get("address")
            if det.get("usual_elsewhere"):
                item["usual_on"] = _usual_on(conn, data_dir, tk, dv, scope)
            out["deviations"].append(item)
    out["note"] = ("'Still learning' means no deviation can be reported yet -- not that nothing unusual happened. "
                   "A baseline never lowers or closes any other finding.")
    return out


def _usual_on(conn, data_dir: Path, tk: str, dv: dict[str, Any], scope: Any) -> dict[str, Any]:
    try:
        from kratos.fleet import groups as G

        names = G.groups_of(data_dir, tk)
        with G.opened(data_dir) as gconn:
            members = sorted({target_key(m) for g in names for m in G._members(gconn, g)} - {tk})
    except Exception:  # noqa: BLE001
        members = []
    found = S.entries_elsewhere(conn, str(dv.get("dim")), str(dv.get("subject")), str(dv.get("key")), members)
    visible = [m for m in found if scope is None or scope.allows(m)]
    return {"machines": visible, "outside_your_access": len(found) - len(visible)}


def to_text(v: dict[str, Any]) -> str:
    """Plain text for the CLI and chat (no markup)."""
    lines = [f"What's normal on {v['machine']}" + (" -- FROZEN (deviations raised, nothing learned)" if v.get("frozen")
                                                   else "") + (f" (machine zone {v['zone']})" if v.get("zone") else "")]
    if v.get("checked_at"):
        lines.append(f"Last baseline run: {v['checked_at']}")
    for d in v.get("dims") or []:
        word = STATUS_WORDS.get(d["status"], d["status"])
        extra = (f" ({d['learned_days']} days, {d['covered_days']} covered)" if d["status"] == "active" else
                 f" ({d['learning']})" if d["status"] == "learning" and d.get("learning") else
                 f": {d['reason']}" if d.get("reason") else "")
        lines.append(f"\n{d['rule']}  {d['label']}: {word}{extra}")
        for t in d.get("top") or []:
            mark = ("  [accepted as normal]" if t["accepted"] else "") + \
                ("  [account no longer on the machine]" if t.get("gone") else "")
            lines.append(f"    {t['subject']}: {t['key']}  weight {t['weight']}  x{t['count']}  last "
                         f"{(t['last_seen'] or '')[:16]}{mark}")
        if d.get("evicted"):
            lines.append(f"    ({d['evicted']} rarely used thing(s) set aside to stay within the limit)")
        if d.get("held_back"):
            lines.append(f"    ({d['held_back']} observation(s) held back near an open serious finding)")
    devs = v.get("deviations") or []
    lines.append("\nDeviations today: " + (str(len(devs)) if devs else "none"))
    for dv in devs:
        lines.append(f"  {dv['rule']} ({dv['severity']}) {dv['subject']}: {dv['key']} -- {dv['machine_time']}")
        if dv.get("usual"):
            lines.append("      usual: " + "; ".join(dv["usual"]))
        u = dv.get("usual_on")
        if u:
            where = ", ".join(u["machines"])
            if u.get("outside_your_access"):
                where = (where + ", " if where else "") + f"{u['outside_your_access']} machine(s) outside your access"
            lines.append(f"      first time here, usual on: {where}")
    if v.get("history"):
        lines.append("\nEarlier profiles (kept as history):")
        for h in v["history"]:
            lines.append(f"  {h['dim']} #{h['generation']} {h['started'][:10] if h['started'] else ''} to "
                         f"{(h['ended'] or '')[:10]}: {h['note']}")
    if v.get("decisions"):
        lines.append("\nDecisions:")
        for r in v["decisions"][:10]:
            what = f" {r['subject']}: {r['key']}" if r.get("subject") else ""
            lines.append(f"  {(r['at'] or '')[:16]} {r['kind']}{what} by {r['by']} ({r['via']}) -- {r['reason']}")
    lines.append("\n" + v.get("note", ""))
    return "\n".join(lines)


def compact(v: dict[str, Any]) -> dict[str, Any]:
    """For MCP: statuses, the top 5 per kind, today's deviations."""
    return {"machine": v["machine"], "frozen": v.get("frozen"), "zone": v.get("zone"),
            "kinds": [{"rule": d["rule"], "kind": d["name"], "status": d["status"], "learned_days": d["learned_days"],
                       "covered_days": d["covered_days"], "learning": d.get("learning"), "reason": d.get("reason"),
                       "usual": [{"subject": t["subject"], "key": t["key"], "weight": t["weight"]}
                                 for t in (d.get("top") or [])[:5]]} for d in v.get("dims") or []],
            "deviations_today": v.get("deviations") or [], "note": v.get("note")}


def class_words(cls: str) -> str:
    return B.CLASS_WORDS.get(cls, cls)
