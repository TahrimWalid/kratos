"""CODE-001..006 from one machine's code check (E.7a §3.9). Pure: judged on Kratos from the
saved per-root results; titles carry no machine text (paths are in evidence and subject).

| Rule | When | Severity |
|---|---|---|
| CODE-001 | an untracked (or, without git, new) script / executable in a confirmed root | high: an executed extension in a PHP/CGI-served folder, or a known-bad file (E.4); medium otherwise |
| CODE-002 | a tracked file changed (modified, staged-not-committed, mode change), or changed without git | high: an executed served script; medium: code; low: docs / config with no code extension |
| CODE-003 | a vulnerable dependency (per root + package; entities = advisory ids) | A.2's priority rules; SSVC from the serving process's exposure |
| CODE-004 | a secret in deployed code / config | medium; high when the file is served as a static file |
| CODE-005 | a web-shell / malware YARA rule matches a file | high |
| CODE-006 | run note: unconfirmed candidates, unreadable roots, caps hit, git not readable, ecosystems not downloaded, old agent | info |
"""
from __future__ import annotations

import posixpath
from typing import Any

from kratos.code import webconf as W

SCRIPT_EXTS = W.EXEC_EXTS + (".py", ".sh", ".bash", ".rb", ".js", ".mjs", ".cjs", ".jsp", ".jspx", ".asp", ".aspx",
                             ".ashx", ".asmx", ".cfm", ".lua", ".war", ".so", ".elf")
BEHAVIOUR_FILES = (".htaccess", ".user.ini", "web.config")
CODE_EXTS = SCRIPT_EXTS + (".html", ".htm", ".twig", ".tpl", ".erb", ".inc", ".java", ".go", ".rs", ".ts", ".c",
                           ".vue", ".svelte", ".jinja", ".j2", ".mako")
MAX_FILES_SHOWN = 10
MAX_SIGNALS_PER_ROOT = 200
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def is_script(rel: str, mode: str | None) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if name.endswith(SCRIPT_EXTS) or name in BEHAVIOUR_FILES:
        return True
    try:
        return bool(int(mode or "0", 8) & 0o111)
    except ValueError:
        return False


def is_code(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return name.endswith(CODE_EXTS) or name in BEHAVIOUR_FILES


def _sha12(f: dict[str, Any] | None) -> str:
    return str((f or {}).get("sha256") or "")[:12] or "unhashed"


def _where(served: dict[str, Any]) -> str:
    return str(served.get("how") or "")


def _signal(rule: str, severity: str, title: str, subject: str, entities: list[str], evidence: list[str],
            recommendation: list[str], **extra: Any) -> dict[str, Any]:
    return {"rule": rule, "severity": severity, "title": title, "subject": subject, "entities": entities,
            "evidence": evidence, "recommendation": recommendation, **extra}


_SAFE_GIT = ("git --no-pager -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat "
             "-c diff.external= ")


def _fix_restore(root: str, rel: str, git: bool) -> list[dict[str, str]]:
    if git:
        return [{"label": "Look at what changed (on the machine; the options keep a planted git config from running "
                          "anything)",
                 "command": f"cd {_q(root)} && {_SAFE_GIT}diff --no-ext-diff --no-textconv -- {_q(rel)}"},
                {"label": "Put the committed version back (read .git/config first: a filter there would run)",
                 "command": f"cd {_q(root)} && {_SAFE_GIT}checkout -- {_q(rel)}"}]
    return [{"label": "Compare with your deployment source and redeploy", "command": f"ls -la {_q(root + '/' + rel)}"}]


def _q(s: str) -> str:
    import shlex

    return shlex.quote(s)


def judge_root(r: dict[str, Any], cfg: W.Config, *, known_bad: set[str] | None = None,
               group_after: int = 20) -> list[dict[str, Any]]:
    """Signals for one confirmed root's result (kratos.code.record)."""
    root = r["path"]
    out: list[dict[str, Any]] = []
    files = r.get("files") or {}
    known_bad = known_bad or set()
    app_root = bool(r.get("app_served"))

    def served(rel: str) -> dict[str, Any]:
        v = W.decide(cfg, root, rel)
        if not v["served"] and not v["executed"] and app_root:
            v = {"served": False, "executed": False, "app": True,
                 "how": "in the folder an app works in (not served directly; Kratos does not follow imports)"}
        return v

    git = r.get("git") or {}
    drift = git.get("drift") or []
    has_git = bool(git) and not git.get("unusable")
    # ---- CODE-001 / CODE-002 from git drift
    new_files: list[tuple[str, str]] = []          # (rel, why)
    changed: list[tuple[str, str]] = []
    if has_git:
        ignored = set(git.get("ignored") or [])
        for d in drift:
            cls, rel = d["class"], d["path"]
            if cls == "untracked":
                new_files.append((rel, "not in the git checkout (untracked)" + (
                    " -- added with intent-to-add" if d.get("detail") == "intent-to-add" else "")))
            elif cls in ("modified", "mode_change"):
                changed.append((rel, "changed on the server since it was checked out" if cls == "modified"
                                else f"its mode changed on the server ({d.get('detail')})"))
            elif cls == "staged":
                changed.append((rel, f"staged in git but never committed ({d.get('detail')})"))
        for rel in ignored:
            v = served(rel)
            f = files.get(rel) or {}
            if is_script(rel, f.get("mode")) and (v["served"] or v["executed"]):
                new_files.append((rel, "untracked and matched by .gitignore -- but a script in a served folder"))
    else:
        bl = r.get("baseline") or {}
        if not bl.get("first"):
            new_files += [(rel, "new since the state you accepted (no git here)") for rel in bl.get("added") or []]
            changed += [(rel, "changed since the state you accepted (no git here)") for rel in bl.get("changed") or []]
    if not has_git and len(new_files) + len(changed) > group_after:
        items = sorted(new_files + changed, key=lambda x: (not served(x[0])["executed"], x[0]))
        ev = [f"Folder: {root}", f"{len(new_files)} new and {len(changed)} changed file(s) since the state accepted "
              f"{r.get('accepted_at') or 'at the first read'} -- probably a deploy:"]
        ev += [f"  {rel} -- {why}" for rel, why in items[:MAX_FILES_SHOWN]]
        if len(items) > MAX_FILES_SHOWN:
            ev.append(f"  ... and {len(items) - MAX_FILES_SHOWN} more (`kratos code status` lists them)")
        out.append(_signal("CODE-002", "medium", "Many files in a code folder changed at once (a deploy?)",
                           f"{root}|*", [f"*#{len(items)}:{_digest(items)}"], ev,
                           ["If this was your deploy, accept the new state so later changes stand out: "
                            f"`kratos code accept-state {root}` (or `a` in /code).",
                            "If it was not, compare the folder with your deployment source."]))
        new_files, changed = [], []
    for rel, why in new_files:
        f = files.get(rel) or {}
        if not is_script(rel, f.get("mode")):
            continue
        v = served(rel)
        bad = f.get("sha256") in known_bad
        sev = "high" if (v["executed"] or bad) else "medium"
        ev = [f"Folder: {root}", f"File: {rel}", f"Why: {why}", f"How it is reached: {_where(v)}",
              f"SHA-256: {f.get('sha256') or 'not read'}"]
        if bad:
            ev.append("Its SHA-256 is in MalwareBazaar's known-malware set (E.4).")
        out.append(_signal("CODE-001", sev, "A script or program was added to a code folder outside its deploy",
                           f"{root}|{rel}", [f"{rel}#{_sha12(f)}"], ev,
                           ["Look at the file. If you didn't put it there, treat it as a possible web shell: take "
                            "the site offline, keep a copy for evidence, remove it, and look for how it got in.",
                            "If it belongs there, commit it (git) or accept the folder's state."],
                           fix=[{"label": "Look at the file (on the machine)",
                                 "command": f"ls -la {_q(root + '/' + rel)} && head -c 2000 {_q(root + '/' + rel)}"}],
                           served=v))
    for rel, why in changed:
        f = files.get(rel) or {}
        v = served(rel)
        if v["executed"] and is_script(rel, f.get("mode")):
            sev = "high"
        elif is_code(rel) or is_script(rel, f.get("mode")):
            sev = "medium"
        else:
            sev = "low"
        if f.get("sha256") in known_bad:
            sev = "high"
        ev = [f"Folder: {root}", f"File: {rel}", f"Why: {why}", f"How it is reached: {_where(v)}",
              f"SHA-256 now: {f.get('sha256') or 'not read'}"]
        out.append(_signal("CODE-002", sev, "A deployed file differs from what was committed or accepted",
                           f"{root}|{rel}", [f"{rel}#{_sha12(f)}"], ev,
                           ["Find out who changed it. An edit on a server is how a web shell is often hidden in "
                            "an existing file.", "Restore it from git or your deployment source if it wasn't you."],
                           fix=_fix_restore(root, rel, has_git), served=v))
    # ---- CODE-003 dependencies
    for hit in (r.get("deps") or {}).get("hits") or []:
        advs = hit.get("advisories") or []
        if not advs:
            continue
        sev = max((a.get("severity") or "low" for a in advs), key=lambda s: RANK[s])
        ids = sorted({a["osv_id"] for a in advs})
        cves = sorted({c for a in advs for c in a.get("cves") or []})
        fixed = sorted({a["fixed_in"] for a in advs if a.get("fixed_in")})
        ev = [f"Folder: {root}", f"Package: {hit['package']} {hit['version']} ({hit['ecosystem']})"
              + (" -- installed" if hit.get("installed") else ""),
              f"Found in: {', '.join(hit.get('source_files') or [])[:300]}",
              f"Advisories: {', '.join(ids[:10])}" + (f" (+{len(ids) - 10} more)" if len(ids) > 10 else "")]
        if cves:
            ev.append(f"CVEs: {', '.join(cves[:10])}")
        if any(a.get("rating") == "malicious" for a in advs):
            ev.append("OSV lists this package version as MALICIOUS (a malware report, not a bug).")
        kev = [a["osv_id"] for a in advs if a.get("kev")]
        if kev:
            ev.append("CISA lists a CVE of it as exploited in the wild: " + ", ".join(kev[:5]))
        rec = [f"Upgrade {hit['package']} to {fixed[-1]} or later" + (" and redeploy" if not hit.get("installed")
                                                                       else "") if fixed
               else f"No fixed version of {hit['package']} is published yet: limit what reaches it, or replace it."]
        out.append(_signal("CODE-003", sev, "A dependency of deployed code has a known vulnerability",
                           f"{root}|{hit['ecosystem']}:{hit['package']}", ids, ev, rec,
                           ssvc_inputs=[i for a in advs for i in a.get("ssvc_inputs") or []][:20],
                           package=hit["package"], ecosystem=hit["ecosystem"], version=hit["version"],
                           fix=_dep_fix(root, hit, fixed)))
    # ---- CODE-004 secrets
    by_file: dict[str, list[dict[str, Any]]] = {}
    for h in r.get("secrets") or []:
        by_file.setdefault(h["rel"], []).append(h)
    for rel, hits in sorted(by_file.items()):
        f = files.get(rel) or {}
        v = served(rel)
        static = v["served"] and not v["executed"]
        sev = "high" if static else "medium"
        kinds = sorted({h["kind"] for h in hits})
        ev = [f"Folder: {root}", f"File: {rel}", f"How it is reached: {_where(v)}"]
        ev += [f"Line {h['line']}: {h['kind']}" + (f" (fingerprint {h['fingerprint']})" if h["fingerprint"] else "")
               for h in hits[:MAX_FILES_SHOWN]]
        ev.append("The value is never stored or shown: the fingerprint lets you see the same secret elsewhere.")
        if static:
            ev.append("This file is served as a static file: anyone who can reach the site may be able to download it.")
        out.append(_signal("CODE-004", sev, "A secret is stored in deployed code or config",
                           f"{root}|{rel}", sorted(f"{h['kind']}#{h['fingerprint'] or _sha12(f)}" for h in hits),
                           ev, ["Rotate the secret (make a new one and revoke this one) -- treat it as exposed.",
                                "Move it out of the code folder: an environment variable or a secrets store, "
                                "outside any served folder."], kinds=kinds, served=v))
    # ---- CODE-005 YARA
    for m in r.get("yara") or []:
        f = files.get(m["rel"]) or {}
        out.append(_signal("CODE-005", "high", "A file in a code folder matches a web-shell or malware rule",
                           f"{root}|{m['rel']}", [f"{m['rel']}#{_sha12(f)}"],
                           [f"Folder: {root}", f"File: {m['rel']}", f"Rule: {m['rule']}",
                            f"How it is reached: {_where(served(m['rel']))}"],
                           ["Take the site offline or block the file, keep a copy for evidence, remove it, and find "
                            "how it got there (look at the web server's access log for requests to it)."]))
    return out[:MAX_SIGNALS_PER_ROOT]


def _digest(items: list[tuple[str, str]]) -> str:
    import hashlib

    return hashlib.sha256("\n".join(sorted(r for r, _w in items)).encode("utf-8", "surrogateescape")).hexdigest()[:12]


def _dep_fix(root: str, hit: dict[str, Any], fixed: list[str]) -> list[dict[str, str]]:
    if not fixed:
        return []
    pkg, ver, eco = hit["package"], fixed[-1], hit["ecosystem"]
    folder = posixpath.dirname((hit.get("source_files") or [""])[0])
    where = _q(root + ("/" + folder if folder else ""))
    cmd = {"PyPI": f"cd {where} && pip install --upgrade '{pkg}>={ver}'  # then update the lockfile",
           "npm": f"cd {where} && npm install {pkg}@{ver}",
           "Packagist": f"cd {where} && composer require {pkg}:^{ver}",
           "Go": f"cd {where} && go get {pkg}@v{ver.lstrip('v')} && go mod tidy",
           "RubyGems": f"cd {where} && bundle update {pkg}",
           "crates.io": f"cd {where} && cargo update -p {pkg} --precise {ver}"}.get(eco)
    return [{"label": f"Upgrade {pkg} (in your project, then redeploy)", "command": cmd}] if cmd else []


def run_note(target: str, notes: list[str]) -> dict[str, Any] | None:
    if not notes:
        return None
    return _signal("CODE-006", "info", "What the code checks could not cover", "", [],
                   [n for n in notes[:40]] + ([f"... and {len(notes) - 40} more"] if len(notes) > 40 else []),
                   ["See `kratos code status` for each folder."])
