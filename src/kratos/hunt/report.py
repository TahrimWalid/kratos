"""A hunt's report in plain words (C.3 §3.5) -- the same text on every surface.

Order: what was hunted and where; per indicator, the machines where it was FOUND
(per source: how many, first and last seen, per day) and the newest hits; where it
was NOT found -- always as "not found in what Kratos holds for <machine>"; then the
coverage, machine by machine, from Kratos's own records; then what to do next.

Machine text in hits is already cleaned (search.py); this module adds no model text.
A result too big to list (an account like `root`, a machine's own address) is shown
as counts with a hint to narrow the hunt.
"""
from __future__ import annotations

from kratos.hunt.coverage import fmt
from kratos.hunt.search import HuntResult, IndicatorResult

REPORT_HITS = 20
PER_DAY_SHOWN = 10
_SOURCE_WORDS = {"kratos.auth": "sign-ins and sudo", "kratos.cron": "cron", "kratos.systemd": "services",
                 "kratos.firewall": "firewall", "kratos.auditd": "audit log", "kratos.package": "package changes",
                 "kratos.web": "web server", "detections": "detections (rule matches)"}


def _source(name: str) -> str:
    base = name.split(" (")[0]
    words = _SOURCE_WORDS.get(base)
    return f"{name} -- {words}" if words else name


def _window(r: HuntResult) -> str:
    a, b = r.window
    if a is None and b is None:
        return "everything Kratos holds"
    return f"from {fmt(a) if a else 'the beginning'} to {fmt(b) if b else 'now'}"


def _per_day(counts: dict[str, int]) -> str:
    days = sorted(counts.items())
    shown = days[-PER_DAY_SHOWN:]
    more = f" (+{len(days) - len(shown)} earlier day(s))" if len(days) > len(shown) else ""
    return ", ".join(f"{d}: {n:,}" for d, n in shown) + more


def _indicator_lines(res: IndicatorResult, r: HuntResult) -> list[str]:
    ind = res.indicator
    out = [f"== {ind.label} {ind.value} =="]
    hit_machines = res.machines_hit()
    for m in hit_machines:
        out.append(f"FOUND on {m}:")
        for s in sorted((s for s in res.summaries if s.machine == m), key=lambda s: s.first or 0):
            note = f" [{s.note}]" if s.note else ""
            out.append(f"  {_source(s.source)}: {s.count:,} -- first {fmt(s.first)}, last {fmt(s.last)}{note}")
            if s.per_day and len(s.per_day) > 1:
                out.append(f"      per day: {_per_day(s.per_day)}")
        for f in (f for f in res.findings if f.get("machine") == m):
            out.append(f"  finding {f['key']}  {str(f['severity']).upper()} {f['rule']} ({f['state']}): "
                       f"{str(f['title'])[:110]}")
        for h in [h for h in res.snapshot_hits if h.machine == m][:10]:
            pre = " (matched on the first digits Kratos kept)" if h.prefix_only else ""
            out.append(f"  {h.label} of {fmt(h.ts)}: {h.where}{pre}")
    empty = {c.machine for c in r.coverage if not c.holds_anything}
    for m in r.machines:
        if m in hit_machines:
            continue
        if m in empty:
            out.append(f"NOT SEARCHED on {m}: Kratos holds nothing from it for this period")
        else:
            out.append(f"not found on {m} -- in what Kratos holds for it (see what was searched below)")
    if res.too_many:
        out.append(f"{res.total_events:,} matching events -- too many to list. Narrow the hunt: a shorter window "
                   "(--since 24h), one machine (--machine), a single address instead of a network.")
    elif res.hits:
        out.append(f"Newest matching events ({min(len(res.hits), REPORT_HITS)} of {res.total_events:,}):")
        for h in res.hits[:REPORT_HITS]:
            fields = ", ".join(f"{k}={v}" for k, v in h.fields.items() if k != "event.outcome")
            rule = f" rule {h.rule['id']} \"{h.rule['name'][:60]}\" by {h.rule['author'][:60]}" if h.rule else ""
            how = {"text": " (in the log text)", "column": " (not yet in the search index)"}.get(h.via, "")
            excerpt = f" -- {h.excerpt}" if h.excerpt else ""
            out.append(f"  {fmt(h.ts)}  {h.machine}  {h.dataset}{how}{rule}  {fields}{excerpt}")
        if res.total_events > REPORT_HITS:
            out.append(f"  ... {res.total_events - REPORT_HITS:,} more (`kratos hunt ... --json` lists up to "
                       f"{len(res.hits)})")
    for t in res.text_scans:
        if t.total == 0:
            continue
        state = (f"searched {t.searched:,} of {t.total:,} events" + ("" if t.stopped_at is None else
                 f" -- the time limit stopped it at {fmt(t.stopped_at)}; older text was NOT searched"))
        out.append(f"  log text on {t.machine}, {fmt(t.start)} to {fmt(t.end)}: {state}")
    return out


def render(r: HuntResult) -> str:
    """The whole report, as plain text (Kratos-written; machine values cleaned)."""
    names = ", ".join(f"{x.indicator.label} {x.indicator.value}" for x in r.indicators)
    head = [f"Hunt for {names}",
            f"Searched {len(r.machines)} machine(s): {', '.join(r.machines) or 'none'} -- {_window(r)} -- "
            f"{r.finished - r.started:.1f} s, no model call, nothing sent to any machine."]
    if not r.machines:
        head.append("Kratos holds nothing from any machine yet: nothing could be searched.")
    if not r.index.get("done"):
        head.append(f"The search index is still being built ({r.index.get('remaining', 0):,} older stored events "
                    "not indexed yet -- they were searched by their main fields only). `kratos hunt index` "
                    "finishes it.")
    body: list[str] = []
    for res in r.indicators:
        body += [""] + _indicator_lines(res, r)
    cov = ["", "What was searched (from Kratos's own records):"]
    for c in r.coverage:
        cov.append(f"  {c.machine}:")
        cov += [f"    {line}" for line in c.lines()]
    found = any(x.found for x in r.indicators)
    nxt = ["", "Next:"]
    if found:
        nxt.append("  Look at the newest hits above; `/findings` for what Kratos already reported about them.")
    nxt.append("  \"Not found\" covers only the stretches listed above -- a gap, an unsynced log or a pruned "
               "period is unknown, not clean.")
    if any(not s.spans for c in r.coverage for s in c.synced) or any(not c.synced for c in r.coverage):
        nxt.append("  To hold every log line from now on: keep log sync on (`/collect`), and watch a machine "
                   "continuously with its agent (`w` in /subagent).")
    return "\n".join(head + body + cov + nxt)


def short_answer(r: HuntResult) -> str:
    """One line: found where, or not found (qualified)."""
    parts = []
    for res in r.indicators:
        ms = res.machines_hit()
        if ms:
            parts.append(f"{res.indicator.value}: found on {', '.join(ms)}")
        else:
            parts.append(f"{res.indicator.value}: not found in what Kratos holds for {len(r.machines)} machine(s)")
    return "; ".join(parts)
