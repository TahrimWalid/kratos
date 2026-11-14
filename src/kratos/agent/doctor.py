"""
Self-diagnostic for Kratos (/doctor) -- one place to answer "is my setup
actually working?" instead of finding out mid-investigation.

Aggregates checks Kratos already knows how to run: the LLM endpoint's
reachability, the .env profile's sanity, the active backend's cost/privacy
posture, the target's reachability + setup probe, and kept-tool integrity. Pure
of any UI -- returns a list of {check, status, detail} dicts (same shape as
run_config_audit_checks / run_target_probe_checks), so the mk2 TUI, a future
home-screen entry, or the classic CLI can all render it. Statuses:
"pass" | "fail" | "warn" | "info".

Does REAL network/SSH work (endpoint probe, target SSH), so callers run it off
the event loop (mk2 uses a thread worker). Every section is isolated in its own
try/except: one failing check reports itself and never aborts the rest.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import time

Check = dict[str, str]


def _row(check: str, status: str, detail: str, fix: str = "") -> Check:
    row: Check = {"check": check, "status": status, "detail": detail}
    if fix:
        row["fix"] = fix  # an actionable next step, shown under a warn/fail row
    return row


def _is_local_url(url: str) -> bool:
    u = (url or "").lower()
    return any(h in u for h in ("127.0.0.1", "localhost", "::1", "0.0.0.0"))


def _check_llm_endpoint(out: list[Check]) -> None:
    from kratos.llm_config import get_active_llm_api_key, get_active_llm_base_url, get_active_llm_model
    from kratos.llm_interface import check_endpoint_reachable

    base = get_active_llm_base_url()
    model = get_active_llm_model()
    reachable, detail = check_endpoint_reachable(base, get_active_llm_api_key())
    if reachable:
        out.append(_row("LLM endpoint", "pass", f"{model} reachable at {base}"))
    elif _is_local_url(base):
        out.append(_row("LLM endpoint", "fail", f"{model} @ {base} — {detail or 'unreachable'}",
                        fix="start your local model server (e.g. `kratos llm-serve`, or `ollama serve`), "
                            "or switch to a reachable backend with /model."))
    else:
        out.append(_row("LLM endpoint", "fail", f"{model} @ {base} — {detail or 'unreachable'}",
                        fix="check LLM_BASE_URL / LLM_API_KEY in .env (or /model to switch profiles); "
                            "a 401/403 usually means a bad or missing key."))


def _check_env_profile(out: list[Check]) -> None:
    from kratos.adapters.llm_profiles import list_candidate_profiles, validate_profile
    from kratos.llm_config import ENV_FILE_PATH

    _cands, current = list_candidate_profiles(ENV_FILE_PATH)
    if current is None:
        out.append(_row(".env profile", "warn", "no active LLM profile detected in .env",
                        fix="set LLM_BASE_URL / LLM_API_KEY / LLM_MODEL in .env, or run /model to pick one."))
        return
    problems = validate_profile(current)
    if problems:
        out.append(_row(".env profile", "fail", "; ".join(problems),
                        fix="fill in the placeholder/empty value(s) in .env, or switch profiles with /model."))
    else:
        out.append(_row(".env profile", "pass", f"{current.model} — no placeholder/empty values"))


def _check_files(out: list[Check]) -> None:
    from kratos import kratos_config as _kc
    from kratos import paths as _paths
    from kratos.llm_config import ENV_FILE_PATH

    if ENV_FILE_PATH.exists():
        mode = ENV_FILE_PATH.stat().st_mode & 0o777
        if mode & 0o077:
            out.append(_row("settings file", "warn",
                            f"{ENV_FILE_PATH} can be read by other users (mode {mode:o}) and may hold API keys",
                            fix=f"chmod 600 {ENV_FILE_PATH}"))
        else:
            out.append(_row("settings file", "info", str(ENV_FILE_PATH)))
    else:
        out.append(_row("settings file", "warn", f"not created yet ({ENV_FILE_PATH}) — built-in defaults apply",
                        fix="run `kratos init` to create it, or add a model under Settings > Models."))
    data_dir = _kc.get_active_data_dir() or _paths.default_data_dir()
    out.append(_row("data folder", "info", f"{data_dir}  ({_paths.layout_note()})"))


def _check_vulscan(out: list[Check]) -> None:
    from kratos.adapters import vuln_scan

    if not vuln_scan.vulscan_installed():
        out.append(_row("CVE list (vulscan)", "warn",
                        "not installed — the vulnerability scan skips CVE matching",
                        fix="run `kratos vulscan-install` on this machine."))
        return
    status = vuln_scan.check_vulscan_db_staleness()
    if status["note"]:
        out.append(_row("CVE list (vulscan)", "warn", status["note"],
                        fix="run `kratos vulscan-install` to rebuild it from NVD (a couple of minutes)."))
    else:
        out.append(_row("CVE list (vulscan)", "pass", f"CVEs up to {status['newest_cve_year']}"))


def _check_backend(out: list[Check]) -> None:
    from kratos.llm_config import get_active_llm_base_url

    if _is_local_url(get_active_llm_base_url()):
        out.append(_row("backend", "info", "local · free · private (nothing leaves this host)"))
    else:
        out.append(_row("backend", "info", "cloud API · sends prompts to a third party · usage-billed"))


def _check_target(out: list[Check]) -> None:
    from kratos.adapters.ssh_remote import run_target_probe_checks
    from kratos.adapters.target_setup import check_label
    from kratos.kratos_config import get_active_target

    target = get_active_target()
    if not target:
        out.append(_row("active target", "warn", "none set yet — there is no machine to investigate",
                        fix="set one with /target <host> (or KRATOS_SSH_HOST for command-line runs)."))
        return
    out.append(_row("active target", "info", target))
    via_agent = _check_transport(out, target)
    if via_agent is False:
        return  # linked to a sub-agent that can't be read right now -- said why above
    probe = run_target_probe_checks()
    if isinstance(probe, list):
        if not probe:
            out.append(_row("target setup", "warn", "probe returned no checks",
                            fix="re-run /target verify; if it stays empty, the target may be unreachable."))
            return
        for c in probe:
            raw = str(c.get("status", "")).upper()
            # INFO is a fact (e.g. the target's timezone), not something to fix.
            status = ("pass" if raw in ("PASS", "OK") else "fail" if raw == "FAIL"
                      else "info" if raw == "INFO" else "warn")
            out.append(_row(f"target · {check_label(c.get('check', '?'))}", status, c.get("detail", "")))
    elif getattr(probe, "via", "ssh") == "subagent":
        detail = (getattr(probe, "stderr", "") or "read failed").strip()
        out.append(_row("target reachable", "fail", f"{target}: {detail[:200]}",
                        fix="open /subagent to see why the box's agent isn't answering."))
    else:
        # SSHResult -> couldn't even connect (port 22 blocked, wrong host, key).
        detail = (getattr(probe, "stderr", "") or getattr(probe, "stdout", "") or "connection failed").strip()
        out.append(_row("target reachable", "fail", f"{target}: {detail[:140] or 'unreachable'}",
                        fix="confirm the host/IP with /target, that port 22 is open, and that the SSH key "
                            "(SSH_TARGET_KEY_PATH) is authorized on the target."))


def _check_transport(out: list[Check], target: str) -> bool | None:
    """How the target is reached. None = over SSH (no link); True = through a
    sub-agent that can be read; False = linked, but the sub-agent path is
    broken right now (each reason reported with its fix)."""
    from kratos import kratos_config as _kc
    from kratos.subagent import routing
    from kratos.subagent.local_reads import listener_status

    data_dir = _kc.get_active_data_dir()
    link = routing.link_for(target, data_dir)
    if link is None:
        out.append(_row("target transport", "info", "over SSH"))
        return None
    how = routing.MODE_LABELS[link.mode]
    if link.revoked:
        out.append(_row("target transport", "fail", f"linked to sub-agent {link.label}, which was unpaired",
                        fix="pair the box again from /subagent, or switch with /target link."))
        return False
    out.append(_row("target transport", "info", f"{how} ({link.label})"))
    status = listener_status(data_dir) if data_dir is not None else None
    if status is None:
        from kratos.subagent.core_listener import listener_running

        detail = ("a Kratos listener is running but can't serve investigation reads (an older build, or a "
                  "different data folder)" if listener_running() else "no Kratos listener is running")
        from kratos.subagent.core_listener import restart_listener_command

        fix = (f"restart it: {restart_listener_command()}" if listener_running()
               else "open /subagent to start one in this window, or install the always-on listener there (L).")
        out.append(_row("sub-agent reads", "fail", detail, fix=fix))
        return False if link.mode == routing.MODE_SUBAGENT else None
    live = (status.get("live") or {}).get(link.target_id)
    if live is None:
        out.append(_row("sub-agent reads", "warn", f"{link.label}'s agent isn't connected right now",
                        fix="see /subagent for why it dropped; it reconnects by itself once the box is up."))
        return False if link.mode == routing.MODE_SUBAGENT else None
    if not live.get("reads"):
        out.append(_row("sub-agent reads", "fail",
                        f"{link.label} runs agent {live.get('agent_version') or '?'}, too old for investigations",
                        fix="in /subagent select it and press g to update it (it keeps its pairing); it needs 0.3.0+."))
        return False if link.mode == routing.MODE_SUBAGENT else None
    from kratos.subagent.status import agent_outdated

    if agent_outdated(live.get("agent_version")):
        from kratos.subagent.agent import AGENT_VERSION

        out.append(_row("sub-agent reads", "warn",
                        f"{link.label} connected, but runs agent {live.get('agent_version')}; this Kratos ships "
                        f"{AGENT_VERSION}",
                        fix="in /subagent select it and press g to update it (it keeps its pairing)."))
        return True
    out.append(_row("sub-agent reads", "pass",
                    f"{link.label} connected (agent {live.get('agent_version')}, {len(live.get('read_probes') or [])} "
                    f"reads; listener: {status.get('mode')})"))
    return True


def _check_kept_tools(out: list[Check]) -> None:
    from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

    meta = _read_metadata(KEPT_TOOLS_DIR)
    if not meta:
        out.append(_row("kept tools", "info", "none kept yet"))
        return
    missing = [
        name for name, m in meta.items()
        if not (KEPT_TOOLS_DIR / ((m or {}).get("source_file") or f"{name}.py")).exists()
    ]
    if missing:
        out.append(_row("kept tools", "fail", f"metadata references missing file(s): {', '.join(missing)}",
                        fix="restore the missing file(s) in kept_tools/, or remove their stale entries from "
                            "kept_tools/metadata.json so startup doesn't fail."))
    else:
        out.append(_row("kept tools", "pass", f"{len(meta)} kept, all source files present"))


def _check_build(out: list[Check]) -> None:
    from kratos.utils.build_info import RUNNING_BUILD, display_build, newer_build_on_disk

    disk = newer_build_on_disk()
    if disk is None:
        out.append(_row("Kratos build", "info", f"running {display_build(RUNNING_BUILD)} (matches the code on disk)"))
    else:
        out.append(_row("Kratos build", "warn",
                        f"running {display_build(RUNNING_BUILD)}, but the code on disk changed ({display_build(disk)})",
                        fix="quit and run `kratos` again to use the code on disk."))


# When each Python release stops getting security fixes from python.org (the
# release-schedule PEPs give the month: end of that month). A release not listed
# has no known end yet.
PYTHON_SECURITY_END = {
    (3, 8): (2024, 10, 31), (3, 9): (2025, 10, 31), (3, 10): (2026, 10, 31), (3, 11): (2027, 10, 31),
    (3, 12): (2028, 10, 31), (3, 13): (2029, 10, 31), (3, 14): (2030, 10, 31),
}
PYTHON_WARN_DAYS = 90


def python_support(version: tuple[int, int], today: date, *, from_distribution: bool) -> Check:
    """The doctor row for the Python running Kratos. A distribution's own Python
    keeps getting security fixes from the distribution after python.org stops, so
    that is said instead of a warning."""
    name = f"Python {version[0]}.{version[1]}"
    end = PYTHON_SECURITY_END.get(tuple(version[:2]))
    if end is None:
        return _row("Python", "info", f"{name} (no end of support announced)")
    end_day = date(*end)
    left = (end_day - today).days
    if from_distribution:
        if left < 0:
            return _row("Python", "info", f"{name}: python.org stopped its security fixes on {end_day.isoformat()}; "
                                          "this is your distribution's Python, which keeps getting fixes from the "
                                          "distribution while that release is supported")
        return _row("Python", "pass", f"{name} (your distribution's; python.org fixes until {end_day.isoformat()})")
    if left < 0:
        return _row("Python", "warn", f"{name} stopped getting security fixes on {end_day.isoformat()}",
                    fix="install Kratos under a newer Python (3.11 or later) -- see SECURITY.md.")
    if left <= PYTHON_WARN_DAYS:
        return _row("Python", "warn", f"{name} stops getting security fixes on {end_day.isoformat()} "
                                      f"({left} days)", fix="plan a move to Python 3.11 or later.")
    return _row("Python", "pass", f"{name} (security fixes until {end_day.isoformat()})")


def _check_python(out: list[Check]) -> None:
    import sys

    base = getattr(sys, "base_prefix", sys.prefix)
    out.append(python_support(sys.version_info[:2], date.today(),
                              from_distribution=base == "/usr"))   # a venv over the system Python included


def _check_notifications(out: list[Check]) -> None:
    from kratos.agent.notify import notify_config_status

    status, detail = notify_config_status()
    if status == "off":
        out.append(_row("notifications", "info", detail,
                        fix="add that line to .env and subscribe to the topic in the ntfy app to get alerts."))
    elif status == "bad":
        out.append(_row("notifications", "fail", detail, fix="set KRATOS_NTFY_TOPIC in .env to a topic of your own."))
    elif status == "warn":
        out.append(_row("notifications", "warn", detail,
                        fix="self-host ntfy (KRATOS_NTFY_BASE_URL) or set KRATOS_NTFY_TOKEN."))
    else:
        out.append(_row("notifications", "pass", detail))


def _check_delivery(out: list[Check], data_dir: Path) -> None:
    """D.4: which process delivers the outbox, and each channel's last success / error /
    dead letters. Never shows a channel secret."""
    from kratos.outbox.health import doctor_rows

    for r in doctor_rows(data_dir):
        out.append(_row(r["check"], r["status"], r["detail"], fix=r.get("fix") or ""))


def _check_evidence(out: list[Check], data_dir: Path) -> None:
    """D.6: the evidence ledger's hash chain (rows, signed checkpoints). Files are compared
    with their recorded hashes by `kratos evidence verify` (it reads every file)."""
    from kratos.evidence import ledger as L

    rep = L.verify_chain(data_dir, check_files=False)
    if rep.rows == 0:
        out.append(_row("evidence ledger", "info", "no evidence file recorded yet (rows start with the next read)"))
        return
    if rep.problems:
        out.append(_row("evidence ledger", "fail", f"hash chain BROKEN: {rep.problems[0]}"
                        + (f" (+{len(rep.problems) - 1} more)" if len(rep.problems) > 1 else ""),
                        "kratos evidence verify   (every problem, and every file against its hash)"))
        return
    out.append(_row("evidence ledger", "pass", f"{rep.rows} row(s), chain intact, {rep.checkpoints} signed daily "
                                             f"checkpoint(s); head row {rep.head_seq} {rep.head_hash[:12]}...",
                    "kratos evidence verify   (also checks every file against the hash taken when it was written)"))


_SECTIONS = (
    ("Kratos build", _check_build),
    ("Python", _check_python),
    ("notifications", _check_notifications),
    ("LLM endpoint", _check_llm_endpoint),
    (".env profile", _check_env_profile),
    ("backend", _check_backend),
    ("target", _check_target),
    ("kept tools", _check_kept_tools),
    ("files", _check_files),
    ("CVE list", _check_vulscan),
)


def _check_history(out: list[Check], data_dir: Path) -> None:
    """How far back 'state as of' questions can reach (docs/time_window_design.md §17):
    the oldest saved observation per category, and what a retention prune would remove."""
    from kratos.timewin.snapshots import horizon, plan_retention

    hz = horizon(data_dir)
    if not hz:
        out.append(_row("history", "info", "no saved scans/snapshots yet -- past-state questions can't be answered"))
        return
    for cat, h in sorted(hz.items()):
        n = h["count"]
        out.append(_row(f"history: {cat}", "info",
                        f"back to {h['oldest'][:10]} ({n} snapshot{'s' if n != 1 else ''}, newest {h['newest'][:10]})"))
    plan = plan_retention(data_dir)
    if plan["delete"]:
        out.append(_row("history: retention", "info",
                        f"{len(plan['delete'])} old snapshots ({plan['delete_bytes'] / 1e6:.1f} MB) are past the retention "
                        "policy; nothing is deleted automatically", "kratos snapshots prune   (preview)  /  --apply"))


def _check_stored_data(out: list[Check], data_dir: Path) -> None:
    """What Kratos keeps on this computer (kratos.datainv): total size, the biggest kind."""
    from kratos import datainv

    s = datainv.summary(data_dir)
    detail = f"{datainv.human_size(s['total_bytes'])} kept (data folder {data_dir}, kept tools, CVE list)"
    if s["biggest"]:
        detail += f"; biggest: {s['biggest']} ({datainv.human_size(s['biggest_bytes'])})"
    out.append(_row("stored data", "info", detail + f". {datainv.NOTHING_DELETED}",
                    "`kratos data` lists every kind, where it is and whether it is personal data"))
    _check_disk_growth(out, data_dir)
    _check_trace_export(out, data_dir)


def _check_disk_growth(out: list[Check], data_dir: Path) -> None:
    """When the data folder's disk fills at the last 7 days' rate (Phase D README §3)."""
    from kratos import diskgrowth

    diskgrowth.record_sample(data_dir)
    p = diskgrowth.project(data_dir)
    status = {"measuring": "info"}.get(p.status, p.status)
    fix = ("make room on that disk, move the data folder (KRATOS_HOME) to a bigger one, or remove old data "
           "yourself with `kratos data prune` (preview first)") if p.status in ("warn", "fail") else ""
    out.append(_row("disk growth", status, p.text, fix))


def _check_trace_export(out: list[Check], data_dir: Path) -> None:
    """Whether run records leave this computer (the optional OpenTelemetry copy)."""
    import importlib.util
    import os

    from kratos import settings_store
    from kratos.trace import settings as TS

    if not settings_store.get(TS.OTEL_EXPORT, data_dir=data_dir):
        out.append(_row("run records", "info", "kept on this computer only (`kratos trace list`); the "
                        "OpenTelemetry copy is off"))
        return
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if importlib.util.find_spec("opentelemetry.sdk") is None:
        out.append(_row("run records", "warn", "the OpenTelemetry copy is on but the extra isn't installed — "
                        "nothing is sent", "pip install 'kratos[otel]', or turn it off in Settings → General"))
    elif not endpoint:
        out.append(_row("run records", "warn", "the OpenTelemetry copy is on but OTEL_EXPORTER_OTLP_ENDPOINT "
                        "isn't set — nothing is sent", "set it to your collector's address, or turn the copy off"))
    else:
        out.append(_row("run records", "info", f"a copy of each run's timings and token counts (never tool "
                        f"results or prompts) is sent to {endpoint}"))


def _check_privacy(out: list[Check], data_dir: Path) -> None:
    """What reaches the model (kratos.privacy): masked or not, and why."""
    from kratos.privacy import mode as PM

    mode = PM.current_mode(data_dir=data_dir)
    detail = "sent to the model: " + PM.describe_mode(data_dir=data_dir)
    if mode == "off" and PM.stored_mode(data_dir=data_dir) == "off" and \
            not PM.endpoint_is_local(_active_base_url(), data_dir=data_dir):
        out.append(_row("model privacy", "warn", detail, "Settings → General → What the model sees"))
    else:
        out.append(_row("model privacy", "info", detail))


def _check_chat_server(out: list[Check], data_dir: Path) -> None:
    """`kratos serve`: running or not, where, how many tokens; a warning when it listens
    beyond this machine (tokens in clear text without a TLS proxy)."""
    from kratos.serve import status as _status

    st = _status.read(data_dir)
    detail = "chat server: " + _status.summary(data_dir)
    host = str(st.get("host") or "")
    if st.get("running") and host and not _loopback(host):
        out.append(_row("chat server", "warn", detail + " -- reachable beyond this machine; tokens travel in "
                        "clear text unless a TLS reverse proxy is in front", "GUIDE \"Remote access\""))
    else:
        out.append(_row("chat server", "info", detail))


def _check_users(out: list[Check], data_dir: Path) -> None:
    """D.7: users by role, tokens per user (never-expiring / expiring soon), shared-gateway
    tokens and whether their JWT secret is set, schedules/triggers whose user can't run,
    and the last refusals."""
    from kratos import settings_store
    from kratos.authz import audit as AU
    from kratos.authz import openwebui
    from kratos.authz import settings as AS
    from kratos.authz import users as U
    from kratos.serve import store as SS

    users = U.list_users(data_dir)
    by_role: dict[str, int] = {}
    for u in users:
        if not u.disabled:
            by_role[u.role] = by_role.get(u.role, 0) + 1
    disabled = sum(1 for u in users if u.disabled)
    out.append(_row("users", "info", ", ".join(f"{n} {r}" for r, n in sorted(by_role.items()))
                    + (f", {disabled} disabled" if disabled else "") + " (the owner is an admin)"))
    live = [t for t in SS.list_tokens(data_dir) if not t.get("revoked_at")]
    now = time.time()
    warn_s = settings_store.get(AS.EXPIRY_WARN_DAYS, data_dir=data_dir) * 86400
    names = {u.user_id: u.name for u in users}
    per_user: dict[str, int] = {}
    for t in live:
        per_user[names.get(t.get("user_id") or "owner", "?")] = per_user.get(names.get(t.get("user_id") or "owner",
                                                                                         "?"), 0) + 1
    never = [t["name"] for t in live if t.get("expires_at") is None]
    soon = [t["name"] for t in live if t.get("expires_at") is not None and now < float(t["expires_at"]) < now + warn_s]
    expired = [t["name"] for t in live if t.get("expires_at") is not None and float(t["expires_at"]) <= now]
    detail = ("tokens: " + ", ".join(f"{n} {w}" for w, n in sorted(per_user.items()))) if live else "no tokens"
    if never:
        detail += f"; never expire: {', '.join(never[:5])}"
    status = "warn" if soon or expired else "info"
    if soon:
        detail += f"; expire soon: {', '.join(soon[:5])}"
    if expired:
        detail += f"; expired: {', '.join(expired[:5])}"
    out.append(_row("tokens", status, detail, "kratos tokens rotate <id>" if status == "warn" else ""))
    for t in (x for x in live if x.get("kind") == "gateway"):
        has = bool(openwebui.read_secret(data_dir, t["token_id"]))
        maps = len(U.list_mappings(data_dir))
        out.append(_row("shared Open WebUI", "info" if has else "fail",
                        f"gateway token {t['name']}: JWT secret {'set' if has else 'MISSING (every request refused)'}"
                        f", {maps} mapped user(s). The token and its secret together can act as every mapped user "
                        "-- keep both private.", "" if has else "kratos tokens rotate " + t["token_id"]))
    blocked = _blocked_unattended(data_dir, {u.user_id: u for u in users})
    if blocked:
        out.append(_row("schedules and triggers", "warn", "; ".join(blocked[:4]), "kratos users run-as ... or /users"))
    refusals = AU.recent_refusals(data_dir, limit=3)
    if refusals:
        out.append(_row("last refusals", "info", "; ".join(
            f"{time.strftime('%m-%d %H:%M', time.localtime(r['at']))} {r['user_name'] or r['user_id'] or 'nobody'}: "
            f"{r['action']} ({(r['reason'] or '')[:80]})" for r in refusals)))


def _blocked_unattended(data_dir: Path, users: dict) -> list[str]:
    """Schedules and triggers that would refuse now (D.7 §3.9): their user is gone,
    disabled, may not investigate, or may no longer see the schedule's machine. Read
    only -- nothing is recorded in the audit trail by looking."""
    from kratos import authz
    from kratos.agent import schedules, triggers

    out = []
    for kind, items in (("schedule", schedules.list_schedules(data_dir)[0]),
                        ("trigger", triggers.list_triggers(data_dir)[0])):
        for it in items:
            uid = getattr(it, "run_as", "owner") or "owner"
            u = users.get(uid)
            if u is None:
                out.append(f"{kind} {it.name} runs as {uid}, who no longer exists -- it refuses")
                continue
            if u.disabled:
                out.append(f"{kind} {it.name} runs as {u.name}, who is disabled -- it refuses")
                continue
            if u.is_owner:
                continue
            if not authz.P.allowed(u.role, authz.P.INVESTIGATE):
                out.append(f"{kind} {it.name} runs as {u.name}, a {u.role}, who may not investigate -- it refuses")
                continue
            target = getattr(it, "target", None)
            if target and not str(target).startswith("@"):
                try:
                    p = authz.principal_of(authz.unattended_actor(kind, it.name, uid), data_dir=data_dir)
                except authz.Denied as e:
                    out.append(f"{kind} {it.name}: {e.reason} -- it refuses")
                    continue
                if not p.scope.allows(target):
                    out.append(f"{kind} {it.name} runs as {u.name}, who may no longer see {target} -- it refuses")
    return out


def _loopback(host: str) -> bool:
    import ipaddress

    h = host.strip().strip("[]").lower()
    try:
        return h == "localhost" or ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _active_base_url() -> str:
    from kratos.llm_config import get_active_llm_base_url

    return get_active_llm_base_url()


def _check_budget(out: list[Check], data_dir: Path) -> None:
    """Spending limits (kratos.budget): today's spend against them, paused sources."""
    from kratos.budget.report import doctor_row

    status, detail = doctor_row(data_dir)
    out.append(_row("budget", status, detail,
                    "Settings → Budget (limits, paused sources, prices)" if status == "warn" else ""))


def _check_collection(out: list[Check], data_dir: Path) -> None:
    """What Kratos checks by itself (kratos.collect): last run per check, logs catching up."""
    from kratos.collect.report import doctor_row

    status, detail = doctor_row(data_dir)
    out.append(_row("collection", status, detail,
                    "run /collect (or `kratos collect`) to refresh them" if status == "warn" else ""))


def _check_vulndb(out: list[Check], data_dir: Path) -> None:
    """The package-vulnerability data (kratos.pkgvuln.index): present, which releases, how old."""
    from kratos import settings_store
    from kratos.pkgvuln import index as vindex
    from kratos.pkgvuln import settings as vsettings

    st = vindex.status(data_dir)
    if not st.present:
        out.append(_row("vulnerability data", "warn", "not downloaded — installed packages aren't checked for "
                        "known vulnerabilities", fix="run `kratos vulndb-update` (it downloads the data for the "
                        "distributions of the machines Kratos has checked)."))
        return
    age = st.age_days() or 0.0
    limit = settings_store.get(vsettings.MAX_AGE_DAYS, data_dir=data_dir)
    detail = f"{', '.join(st.selectors) or 'no release'}; updated {age:.0f} day(s) ago"
    stale = [n for n, info in st.sources.items() if n in ("kev", "epss", "nvd") and info.get("fetched_at")
             and (time.time() - float(info["fetched_at"])) / 86400 > limit]
    if age > limit or stale:
        out.append(_row("vulnerability data", "warn", detail + (f"; stale: {', '.join(stale)}" if stale else ""),
                        fix="run `kratos vulndb-update`."))
    else:
        out.append(_row("vulnerability data", "pass", detail))


def _check_code(out: list[Check], data_dir: Path) -> None:
    """E.7a: code folders per machine (confirmed / waiting for a person), the language-ecosystem
    advisories they need, and YAML support for pnpm lockfiles."""
    from kratos.code import store as CS
    from kratos.code.deps import yaml_safe
    from kratos.pkgvuln import index as vindex

    roots = CS.all_roots(data_dir)
    if not roots:
        out.append(_row("code folders", "info", "none found yet (a code check finds the folders a machine serves; "
                        "`/code` or `kratos code roots`)"))
        return
    by: dict[str, list[int]] = {}
    for r in roots:
        c = by.setdefault(r["target_key"], [0, 0, 0])
        c[0 if r["status"] == "confirmed" else 1 if r["status"] == "candidate" else 2] += 1
    detail = "; ".join(f"{m}: {c[0]} confirmed, {c[1]} to confirm" for m, c in sorted(by.items())[:6])
    waiting = sum(c[1] for c in by.values())
    out.append(_row("code folders", "warn" if waiting else "pass", detail,
                    fix="confirm or ignore them in /code (or `kratos code confirm|ignore`)" if waiting else ""))
    seen = CS.ecosystems_seen(data_dir)
    if seen:
        st = vindex.status(data_dir)
        held = {s.lower() for s in st.selectors} if st.present else set()
        missing = [e for e in seen if e.lower() not in held]
        if missing:
            out.append(_row("code advisories", "warn", f"not downloaded for {', '.join(missing)} -- those dependencies "
                            "aren't checked", fix="run `kratos vulndb-update --for-roots`."))
        else:
            out.append(_row("code advisories", "pass", f"{', '.join(seen)}; updated {st.age_days() or 0:.0f} day(s) ago"))
    if not yaml_safe.available():
        out.append(_row("pnpm lockfiles", "info", "not read: YAML support isn't installed",
                        fix="pip install 'kratos-security-assistant[code]'"))


def _check_hashdb(out: list[Check], data_dir: Path) -> None:
    """E.4: the file-reputation datasets (age, size, licence) and what the last checks couldn't look at."""
    import json as _json

    from kratos.hashdb import circl, malwarebazaar
    from kratos.hashdb import datasets as D
    from kratos.hashdb import record as HR
    from kratos.hashdb import settings as S

    for ds, warn in ((malwarebazaar.DATASET, S.MB_WARN_DAYS), (circl.DATASET, S.CIRCL_WARN_DAYS)):
        row = D.get(data_dir, ds.name)
        if D.installed_path(data_dir, ds) is None:
            if ds.name == "malwarebazaar":
                fix = ("store your free abuse.ch key (`kratos hashdb-key set malwarebazaar`), then run "
                       "`kratos hashdb-update --malwarebazaar`" if not D.read_key(data_dir, ds.name)
                       else "run `kratos hashdb-update --malwarebazaar`")
                detail = "known-bad hash set: not set up (needs a free abuse.ch key)"
            else:
                fix, detail = ("optional: `kratos hashdb-update --circl` (about 1 GB)",
                               "known-good filter: not downloaded (package checksums are used instead)")
            if row and row.last_error:
                detail += f"; last attempt failed: {row.last_error[:120]}"
            out.append(_row(ds.label, "info", detail, fix=fix))
            continue
        age = row.age_days() if row else 0.0
        detail = f"{row.size / 1e6:.0f} MB, fetched {age:.0f} day(s) ago; licence: {row.licence}"
        if age > warn:
            out.append(_row(ds.label, "warn", detail + f" -- older than {warn} days (still used)",
                            fix=f"run `{ds.update_hint}`"))
        else:
            out.append(_row(ds.label, "pass", detail))
    unchecked, machines = 0, 0
    folder = Path(data_dir) / HR.FOLDER
    for f in sorted(folder.glob(HR.PATTERN)) if folder.is_dir() else []:
        try:
            doc = _json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        machines += 1
        c = doc.get("counts") or {}
        unchecked += int(c.get("not_checked") or 0) + int(c.get("over_cap") or 0)
    if machines:
        out.append(_row("file reputation", "warn" if unchecked else "pass",
                        f"last checks on {machines} machine(s): {unchecked} file(s) not checked"
                        + (" (each machine's HASH-003 says why)" if unchecked else "")))


def _check_compliance(out: list[Check], data_dir: Path) -> None:
    """E.2: the vendored ComplianceAsCode mapping, and when each machine's hardening facts were last read."""
    import json as _json
    import time as _time

    from kratos.compliance import cac
    from kratos.compliance import record as CR
    from kratos.compliance import settings as CS

    out.append(_row("compliance mapping", "pass",
                    f"{cac.mapping_version()}, BSD-3-Clause (ids only); CIS products: {', '.join(cac.products())}"))
    max_age = float(CS.get(CS.MAX_AGE_HOURS, data_dir))
    folder = Path(data_dir) / CR.FOLDER
    rows = []
    for f in sorted(folder.glob(CR.PATTERN)) if folder.is_dir() else []:
        try:
            doc = _json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        read = doc.get("read_at_epoch")
        age = (_time.time() - float(read)) / 3600 if read else None
        rows.append((str(doc.get("target") or "?"), age, doc.get("via") or ""))
    if not rows:
        out.append(_row("hardening reads", "info", "no machine's hardening facts read yet",
                        fix="they are read with every check of a machine (`kratos collect <machine>`)"))
        return
    stale = [m for m, age, _v in rows if age is None or age > max_age]
    detail = "; ".join(f"{m}: {('%.0f h ago' % age) if age is not None else 'never'} ({v})" for m, age, v in rows[:8])
    if len(rows) > 8:
        detail += f"; +{len(rows) - 8} more"
    out.append(_row("hardening reads", "warn" if stale else "pass",
                    detail + (f" -- {len(stale)} older than {max_age:g} h: their controls show 'not checked'"
                              if stale else ""),
                    fix="run a check of those machines (`kratos collect <machine>`)" if stale else ""))


def _check_detection(out: list[Check], data_dir: Path) -> None:
    """C.1: the rule pack, the rules on, and when each machine was last checked by them."""
    from kratos.detect import pack as P
    from kratos.detect import store as ST
    from kratos.utils.timeutil import epoch_to_utc_iso

    loaded = P.load(data_dir)
    rules = sum(len(lp.pack.rules) for lp in loaded.loaded)
    off = ST.disabled_everywhere(data_dir)
    packs = ", ".join(f"{lp.pack_id} v{lp.version}" for lp in loaded.loaded)
    runs = ST.last_runs_by_target(data_dir)
    if runs:
        when = "; ".join(f"{t} {epoch_to_utc_iso(r.finished_at or r.started_at)}"
                         + ("" if r.status == "ok" else f" ({r.status})") for t, r in sorted(runs.items())[:5])
        detail = f"{packs}: {rules - len(off)} of {rules} rules on; last run per machine: {when}"
    else:
        detail = f"{packs}: {rules - len(off)} of {rules} rules on; not run on any machine yet"
    detail += " -- on collected logs, on schedule (not continuously)"
    if loaded.refused:
        out.append(_row("detection rules", "warn", detail + f"; {len(loaded.refused)} imported pack(s) refused: "
                        + "; ".join(r.reason for r in loaded.refused)[:200],
                        fix="re-import the rules (kratos detect import) or remove the file from detect/packs"))
        return
    out.append(_row("detection rules", "pass" if runs else "info", detail))
    _check_watch(out, data_dir)


def _check_watch(out: list[Check], data_dir: Path) -> None:
    """C.2: continuous detection per watched machine, and whether alerts reach the person
    while Kratos is closed (that needs the always-on listener)."""
    from kratos.detect import live as L

    watched = L.watched_targets(data_dir)
    if not watched:
        out.append(_row("continuous detection", "info", "off on every machine -- detection rules run on schedule "
                        "only", fix="to watch a machine with a sub-agent as its logs are written: /subagent, select "
                        "it, press w"))
        return
    lines, bad = [], []
    for st in watched:
        h = L.health(data_dir, st["target_id"])
        name = st.get("machine") or st["target_id"]
        if h.healthy:
            lines.append(f"{name}: watching")
        else:
            bad.append(f"{name}: NOT running ({h.reasons[0][1][:120]})")
    try:
        from kratos.storage.subagent_store import SubAgentStore
        from kratos.subagent.status import LISTENER_STALE_AFTER_SECONDS

        listeners = SubAgentStore(data_dir / "kratos.db").live_listeners(LISTENER_STALE_AFTER_SECONDS)
    except Exception:  # noqa: BLE001
        listeners = []
    service = any(x.get("mode") == "service" for x in listeners)
    detail = "; ".join(bad + lines)
    if bad:
        out.append(_row("continuous detection", "warn", detail, fix="open /subagent and select the machine: it says "
                        "why the watcher isn't running (DETECT-002 has the same)"))
    elif not service:
        out.append(_row("continuous detection", "warn", detail + " -- but no always-on listener is running, so "
                        "alerts stop when Kratos is closed", fix="install it: /subagent, press l"))
    else:
        out.append(_row("continuous detection", "pass", detail + "; the always-on listener delivers alerts while "
                        "Kratos is closed"))


def _check_agent_link(out: list[Check], data_dir: Path) -> None:
    """C.4: are the agent link keys usable, and which paired agents are encrypted."""
    from kratos.storage.subagent_store import SubAgentStore
    from kratos.subagent import tls

    st = tls.status(data_dir, SubAgentStore(data_dir / "kratos.db"))
    if st.get("error"):
        out.append(_row("agent link", "fail", f"encryption keys unusable: {st['error']}",
                        fix="restore the subagent-tls folder from your copy, or fix its permissions"))
        return
    agents = st.get("agents") or []
    keys = st.get("keys")
    if keys is None and not agents:
        out.append(_row("agent link", "info", "no agents paired; the encryption keys are made when the listener "
                        "first starts"))
        return
    pinned = [a for a in agents if a["link_mode"] == tls.LINK_TLS]
    plain = [a for a in agents if a["link_mode"] == tls.LINK_PLAIN]
    pins = f"pin set {keys['version']} (active {keys['active'][:12]}…, backup {keys['backup'][:12]}…)" if keys else ""
    detail = (f"TLS with pinned keys, {pins}; {len(pinned)} of {len(agents)} agent(s) encrypted"
              + (f", {len(plain)} plaintext" if plain else "")
              + f"; require encryption {'on' if st['require'] else 'off'}")
    if plain and st["require"]:
        out.append(_row("agent link", "fail", detail + " -- the plaintext ones are refused",
                        fix="update each (/subagent, select it, press g)"))
    elif plain:
        out.append(_row("agent link", "warn", detail,
                        fix="update each plaintext agent (/subagent, press g), then turn on 'require encryption'"))
    else:
        out.append(_row("agent link", "pass", detail))


def _check_ssh_certificates(out: list[Check], data_dir: Path) -> None:
    """D.1: the CA mode and fingerprint, whether it is locked, machines by enrolment
    state, and any machine still accepting the old key."""
    from kratos.sshca import ca as _ca
    from kratos.sshca import store as _castore

    try:
        ca = _ca.active_user_ca(data_dir)
    except Exception as e:  # noqa: BLE001
        out.append(_row("ssh certificates", "fail", f"CA folder unusable: {e}",
                        fix="restore the ssh-ca folder from your copy, or fix its permissions"))
        return
    if ca is None:
        out.append(_row("ssh certificates", "info",
                        "not set up -- Kratos uses the long-lived SSH key on every machine. "
                        "Set up with `kratos ssh-ca setup` and enrol a machine."))
        return
    if not _ca.is_unlocked(data_dir):
        out.append(_row("ssh certificates", "fail",
                        f"CA locked (mode {ca.mode}); scheduled runs can't sign for enrolled machines",
                        fix="unlock it with `kratos ssh-ca unlock`"))
    else:
        nxt = _castore.ca_key(data_dir, kind="user", role="next")
        rot = f"; rotation in progress (next {nxt.fingerprint[:16]}…)" if nxt else ""
        out.append(_row("ssh certificates", "pass",
                        f"user CA {ca.fingerprint[:20]}… mode {ca.mode}{rot}"))
    enrolments = _castore.list_enrolments(data_dir)
    if not enrolments:
        out.append(_row("ssh certificates", "info", "no machines enrolled yet"))
        return
    by_state: dict[str, int] = {}
    still_old_key = []
    for enr in enrolments:
        by_state[enr.state] = by_state.get(enr.state, 0) + 1
        if enr.state == "cert":
            still_old_key.append(enr.host)
    summary = ", ".join(f"{n} {s}" for s, n in sorted(by_state.items()))
    out.append(_row("ssh certificates", "pass", f"enrolled machines: {summary}"))
    if still_old_key:
        out.append(_row("ssh certificates", "warn",
                        "still accepting the old key (not certificate-only yet): " + ", ".join(still_old_key),
                        fix="remove the old key on each, then `kratos ssh-ca verify <machine> --finish`"))


_NETWORK_SECTIONS = ("LLM endpoint", "target")


def _check_backups(out: list[Check], data_dir: Path) -> None:
    from kratos.backup import status as backup_status

    for row in backup_status.doctor_rows(data_dir):
        out.append(_row(row["check"], row["status"], row["detail"], row.get("fix", "")))


def run_diagnostics(data_dir: Path | None = None, *, offline: bool = False) -> list[Check]:
    """Run every diagnostic section, isolated so one failure can't abort the
    rest. Returns the flat list of {check, status, detail} rows. With `data_dir`, also
    reports the saved-history horizon. `offline` skips the sections that reach the
    network or a machine (the model endpoint, the target) -- a backup drill runs it on a
    restored copy."""
    out: list[Check] = []
    sections = [s for s in _SECTIONS if not (offline and s[0] in _NETWORK_SECTIONS)]
    if offline:
        out.append(_row("offline", "info", "the model endpoint and the target were not contacted (--offline)"))
    if data_dir is not None:
        sections.append(("model privacy", lambda o: _check_privacy(o, Path(data_dir))))
        sections.append(("chat server", lambda o: _check_chat_server(o, Path(data_dir))))
        sections.append(("users", lambda o: _check_users(o, Path(data_dir))))
        sections.append(("budget", lambda o: _check_budget(o, Path(data_dir))))
        sections.append(("delivery", lambda o: _check_delivery(o, Path(data_dir))))
        sections.append(("evidence ledger", lambda o: _check_evidence(o, Path(data_dir))))
        sections.append(("collection", lambda o: _check_collection(o, Path(data_dir))))
        sections.append(("detection rules", lambda o: _check_detection(o, Path(data_dir))))
        sections.append(("agent link", lambda o: _check_agent_link(o, Path(data_dir))))
        sections.append(("ssh certificates", lambda o: _check_ssh_certificates(o, Path(data_dir))))
        sections.append(("vulnerability data", lambda o: _check_vulndb(o, Path(data_dir))))
        sections.append(("file reputation", lambda o: _check_hashdb(o, Path(data_dir))))
        sections.append(("code folders", lambda o: _check_code(o, Path(data_dir))))
        sections.append(("compliance", lambda o: _check_compliance(o, Path(data_dir))))
        sections.append(("history", lambda o: _check_history(o, Path(data_dir))))
        sections.append(("stored data", lambda o: _check_stored_data(o, Path(data_dir))))
        sections.append(("backups", lambda o: _check_backups(o, Path(data_dir))))
    for name, fn in sections:
        try:
            fn(out)
        except Exception as e:  # noqa: BLE001 -- a broken check reports itself, never aborts
            out.append(_row(name, "fail", f"check errored: {type(e).__name__}: {e}"))
    return out


def summarize(checks: list[Check]) -> tuple[int, int, int]:
    """(passes, warnings, failures) -- 'info' rows aren't counted either way."""
    p = sum(1 for c in checks if c["status"] == "pass")
    w = sum(1 for c in checks if c["status"] == "warn")
    f = sum(1 for c in checks if c["status"] == "fail")
    return p, w, f
