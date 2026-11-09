"""The bundle's ``report.html``: one self-contained page that opens offline.

Two parts, never mixed:

- **Observed** -- only what Kratos collected: per-machine coverage and gaps, the
  timeline (saved reads, events, finding changes), findings with their evidence lines,
  the evidence files with their hashes and where each hash comes from.
- **Analysis** -- Kratos's rule-made decisions (labelled as rules: severity, lifecycle
  state, re-check verdict, SSVC decision, ATT&CK labels) and, when asked for, the
  summary a model wrote (labelled, with the checks it passed).

Every text from a machine is cleaned (``untrusted.for_display``), its web addresses
defanged and HTML-escaped. No script, no external resource, no link: a strict
Content-Security-Policy says so to the browser too.
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any

from kratos import untrusted

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

STYLE = """
:root{--fg:#1d2433;--muted:#5b6474;--line:#d9dee7;--bg:#ffffff;--panel:#f6f8fb;--high:#b42318;
--med:#b54708;--low:#175cd3;--ok:#067647;--warn:#b54708}
@media (prefers-color-scheme: dark){:root{--fg:#e6e9ef;--muted:#a0a8b8;--line:#2d3442;--bg:#11151c;
--panel:#181d26;--high:#f97066;--med:#fdb022;--low:#84adff;--ok:#47cd89;--warn:#fdb022}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 8px;padding-top:8px;border-top:2px solid var(--line)}
h3{font-size:16px;margin:20px 0 6px}.muted{color:var(--muted)}
.part{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-top:40px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0}
th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}td.mono,code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
font-size:12.5px;word-break:break-all}
.sev-critical,.sev-high{color:var(--high);font-weight:600}.sev-medium{color:var(--med);font-weight:600}
.sev-low{color:var(--low)}.tag{display:inline-block;border:1px solid var(--line);border-radius:10px;
padding:0 7px;font-size:12px;margin:0 4px 2px 0}.warn{color:var(--warn)}.ok{color:var(--ok)}
pre{white-space:pre-wrap;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px;
font-size:12.5px}ul{margin:4px 0 4px 20px;padding:0}
"""


_SCHEME_RE = re.compile(r"(?i)\b(https?|ftps?)://")


def esc(s: Any, *, max_len: int | None = None) -> str:
    """Machine text for HTML: cleaned, web addresses defanged, escaped."""
    text = untrusted.for_display("" if s is None else s, max_len=max_len)
    text = untrusted._MD_URL_RE.sub(lambda m: untrusted._md_defang(m.group(1)), text)
    # any scheme the pattern above missed (inside <...>, after a bracket): never a live address
    text = _SCHEME_RE.sub(lambda m: m.group(1)[0] + "xx" + m.group(1)[3:] + "[:]//", text)
    return html.escape(text, quote=True)


def _fmt(t: Any) -> str:
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return esc(t or "")


def _sev(s: str) -> str:
    s = (s or "").lower()
    return f'<span class="sev-{esc(s)}">{esc(s or "?")}</span>'


def _rows(head: list[str], rows: list[list[str]]) -> str:
    th = "".join(f"<th>{h}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def _verify_box(manifest: dict[str, Any]) -> str:
    fp = esc(manifest["signing_key"]["fingerprint"])
    return f"""<div class="panel"><b>Check this bundle on any computer with OpenSSH</b> (no Kratos needed), in the
bundle folder:<pre>ssh-keygen -Y verify -f allowed_signers -I kratos -n kratos-export -s SHA256SUMS.sig &lt; SHA256SUMS
sha256sum -c SHA256SUMS</pre>
The first must say <i>Good "kratos-export" signature</i> with key <code>{fp}</code> -- compare it with the
fingerprint Kratos's <code>/doctor</code> shows ("signing key"); the bundle's own <code>allowed_signers</code>
file only proves the bundle wasn't changed after this key signed it. The second must say OK for every file. Together they prove no file changed since Kratos signed the bundle;
<code>manifest.json</code> (signed on its own too, <code>manifest.json.sig</code>) holds each evidence file's hash
as Kratos recorded it when it collected the file.</div>"""


def render(manifest: dict[str, Any], collected: Any, *, narrative: dict[str, Any] | None = None,
           timeline_rows: int = 2000) -> str:
    scope = manifest["scope"]
    win = scope["window"]
    variant = manifest["variant"]
    parts: list[str] = []
    w = parts.append

    w(f"<h1>Kratos incident bundle</h1><div class='muted'>{esc(manifest['export_id'])} -- made "
      f"{esc(manifest['created_at'])} by {esc(manifest['created_by'].get('user'))} "
      f"({esc(manifest['created_by'].get('interface'))}), Kratos {esc(manifest['kratos_build'])}</div>")
    w("<div class='panel'>"
      f"<b>Machines:</b> {', '.join(esc(m['shown']) for m in manifest['machines'])}"
      + (f" (group <code>{esc(scope.get('group'))}</code>)" if scope.get("group") else "")
      + f"<br><b>Period:</b> {esc(win.get('start') or 'the beginning')} to {esc(win.get('end'))}"
      f"<br><b>Variant:</b> {esc(variant)}"
      + (" -- names, addresses and accounts are replaced by placeholders (one map for the whole bundle, not "
         "included); secrets are removed. Hashes are of the redacted files; each file also lists its original's "
         "hash." if variant == "redacted" else "")
      + f"<br><b>Signed by:</b> <code>{esc(manifest['signing_key']['fingerprint'])}</code> (namespace "
        "<code>kratos-export</code>)"
      + f"<br><b>Evidence ledger head:</b> row {esc(manifest['ledger']['head_seq'])}, "
        f"<code>{esc(manifest['ledger']['head_hash'])}</code>"
      + (" <span class='ok'>(chain verified when exporting)</span>" if manifest['ledger'].get('chain_verified')
         else " <span class='warn'>(chain problems when exporting -- see the manifest)</span>")
      + "</div>")
    w(_verify_box(manifest))
    for c in manifest.get("cuts") or []:
        w(f"<p class='warn'><b>Cut:</b> {esc(c['machine'])} {esc(c['dataset'])}: {esc(c['included'])} of "
          f"{esc(c['in_window'])} events (left out from {esc(c['left_out_from'])}) -- {esc(c['why'])}</p>")
    for wline in manifest.get("warnings") or []:
        w(f"<p class='warn'>{esc(wline)}</p>")

    # ------------------------------------------------------------------ observed
    w("<div class='part'>Part 1 -- Observed: only what Kratos collected</div>")
    w("<h2>Coverage per machine</h2><p class='muted'>What Kratos holds from each machine for this period, and every "
      "gap. A period Kratos couldn't read is never \"nothing found\".</p>")
    for shown, cov in collected.coverage.items():
        w(f"<h3>{esc(shown)}</h3><ul>" + "".join(f"<li>{esc(s)}</li>" for s in cov.get("statement") or [])
          + "</ul>")
        gaps = cov.get("gaps") or []
        if gaps:
            w("<div class='panel'><b class='warn'>Gaps</b><ul>" + "".join(f"<li>{esc(g)}</li>" for g in gaps)
              + "</ul></div>")
        else:
            w("<p class='muted'>No gap recorded for this period.</p>")

    rows = sorted((r for r in collected.timeline if isinstance(r.get("at"), (int, float))), key=lambda r: r["at"])
    w(f"<h2>Timeline</h2><p class='muted'>{len(rows):,} entries: saved reads, a sample of events (the full events "
      "are in the bundle), finding changes.</p>")
    shown_rows = rows[:timeline_rows]
    w(_rows(["When (UTC)", "Machine", "What", "In the bundle"],
            [[_fmt(r["at"]), esc(r["machine"]), f"<span class='tag'>{esc(r['kind'])}</span>{esc(r['what'], max_len=300)}",
              f"<span class='mono'>{esc(r.get('ref'))}</span>"] for r in shown_rows]))
    if len(rows) > timeline_rows:
        w(f"<p class='warn'>The timeline shows the first {timeline_rows:,} of {len(rows):,} entries "
          "(export.timeline_rows).</p>")

    w("<h2>Findings and their evidence</h2>")
    if not any(collected.findings.values()):
        w("<p class='muted'>No finding in scope for this period.</p>")
    for shown, fs in collected.findings.items():
        w(f"<h3>{esc(shown)} -- {len(fs)} finding(s)</h3>")
        for f in fs:
            ev = "".join(f"<li>{esc(e, max_len=600)}</li>" for e in f.get("evidence") or [])
            w(f"<div class='panel'><b>{esc(f['rule_id'])}</b> {esc(f['title'])}<br>"
              f"<span class='muted'>first seen {esc(f['first_seen'])}, last seen {esc(f['last_seen'])}, seen "
              f"{esc(f['times_seen'])} time(s); key <code>{esc(f['finding_key'][:16])}</code></span>"
              + (f"<ul>{ev}</ul>" if ev else "<p class='muted'>no evidence lines stored</p>") + "</div>")

    w("<h2>Evidence files</h2><p class='muted'><b>collection</b>: the hash Kratos's evidence ledger recorded when "
      "it wrote the file (and the file still matches it). <b>export</b>: the hash was taken when exporting -- the "
      "file predates the evidence ledger, or no longer matches what the ledger recorded (said next to it). "
      "<b>generated</b>: written from Kratos's database when exporting.</p>")
    frows = []
    for f in manifest["files"]:
        if f["kind"] in ("report",):
            continue
        frows.append([f"<span class='mono'>{esc(f['path'])}</span>", esc(f.get("machine") or ""),
                      esc(f.get("category") or f["kind"]),
                      esc(f.get("collected_at") or ""),
                      esc(f["hashed_at"]) + (f"<br><span class='warn'>{esc(f['warning'])}</span>"
                                             if f.get("warning") else ""),
                      f"<span class='mono'>{esc(f['sha256'])}</span>"
                      + (f"<br><span class='muted'>original: {esc(f['original_sha256'])}</span>"
                         if f.get("original_sha256") else ""),
                      esc(" / ".join(x for x in (f.get("read"), f.get("transport")) if x))])
    w(_rows(["File", "Machine", "What", "Collected", "Hash taken at", "SHA-256", "Read / transport"], frows))

    # ------------------------------------------------------------------ analysis
    w("<div class='part'>Part 2 -- Analysis</div>")
    w("<h2>Kratos's rule-made decisions</h2><p class='muted'>Computed by Kratos's rules from the evidence above -- "
      "never set by a model. The state is the finding's lifecycle state (people decide accept / false positive); "
      "the verdict is Kratos's own re-check.</p>")
    drows = []
    for shown, fs in collected.findings.items():
        for f in fs:
            v = f.get("verdict") or {}
            drows.append([esc(shown), f"<b>{esc(f['rule_id'])}</b>", _sev(f["severity"]), esc(f["state"]),
                          esc(v.get("verdict") or "not re-checked") + (f"<br><span class='muted'>{esc(v.get('sentence'))}</span>" if v.get("sentence") else ""),
                          esc(f.get("ssvc_decision") or "") + (f"<br><span class='muted'>{esc(f.get('ssvc_line'))}</span>"
                                                               if f.get("ssvc_line") else ""),
                          "".join(f"<span class='tag'>{esc(a.get('id'))} {esc(a.get('name'))}</span>"
                                  for a in f.get("attack") or [])])
    w(_rows(["Machine", "Rule", "Severity", "State", "Re-check verdict", "SSVC decision", "ATT&CK"], drows)
      if drows else "<p class='muted'>No finding in scope.</p>")

    w("<h2>Written summary</h2>")
    if narrative and narrative.get("text"):
        w("<div class='panel'><b>Written by a model that held no tools</b> -- it read the facts above as data and "
          "wrote text only. Each machine's part was held to Kratos's answer checks against that machine's own "
          f"evidence. Model: {esc(narrative.get('model'))}.</div>")
        w(f"<pre>{esc(narrative['text'])}</pre>")
        for n in narrative.get("notes") or []:
            w(f"<p class='warn'>{esc(n)}</p>")
    else:
        w(f"<p class='muted'>{esc((narrative or {}).get('skipped') or 'No written summary was asked for.')}</p>")

    body = "\n".join(parts)
    return (f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<meta name=\"referrer\" content=\"no-referrer\"><title>Kratos incident bundle</title>"
            f"<style>{STYLE}</style></head><body><main>\n{body}\n</main></body></html>\n")
