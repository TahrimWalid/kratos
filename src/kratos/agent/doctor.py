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

from pathlib import Path

from typing import Any

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


def _check_backend(out: list[Check]) -> None:
    from kratos.llm_config import get_active_llm_base_url

    if _is_local_url(get_active_llm_base_url()):
        out.append(_row("backend", "info", "local · free · private (nothing leaves this host)"))
    else:
        out.append(_row("backend", "info", "cloud API · sends prompts to a third party · usage-billed"))


def _check_target(out: list[Check]) -> None:
    from kratos.adapters.ssh_remote import run_target_probe_checks
    from kratos.kratos_config import get_active_target

    target = get_active_target()
    out.append(_row("active target", "info", target or "(none set — use /target)"))
    probe = run_target_probe_checks()
    if isinstance(probe, list):
        if not probe:
            out.append(_row("target setup", "warn", "probe returned no checks",
                            fix="re-run /target verify; if it stays empty, the target may be unreachable."))
            return
        for c in probe:
            raw = str(c.get("status", "")).upper()
            status = "pass" if raw in ("PASS", "OK") else "fail" if raw == "FAIL" else "warn"
            out.append(_row(f"target · {c.get('check', '?')}", status, c.get("detail", "")))
    else:
        # SSHResult -> couldn't even connect (port 22 blocked, wrong host, key).
        detail = (getattr(probe, "stderr", "") or getattr(probe, "stdout", "") or "connection failed").strip()
        out.append(_row("target reachable", "fail", f"{target}: {detail[:140] or 'unreachable'}",
                        fix="confirm the host/IP with /target, that port 22 is open, and that the SSH key "
                            "(SSH_TARGET_KEY_PATH) is authorized on the target."))


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


_SECTIONS = (
    ("Kratos build", _check_build),
    ("LLM endpoint", _check_llm_endpoint),
    (".env profile", _check_env_profile),
    ("backend", _check_backend),
    ("target", _check_target),
    ("kept tools", _check_kept_tools),
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
        out.append(_row(f"history: {cat}", "info", f"back to {h['oldest'][:10]} ({h['count']} snapshots, newest {h['newest'][:10]})"))
    plan = plan_retention(data_dir)
    if plan["delete"]:
        out.append(_row("history: retention", "info",
                        f"{len(plan['delete'])} old snapshots ({plan['delete_bytes'] / 1e6:.1f} MB) are past the retention "
                        "policy; nothing is deleted automatically", "kratos snapshots prune   (preview)  /  --apply"))


def run_diagnostics(data_dir: Path | None = None) -> list[Check]:
    """Run every diagnostic section, isolated so one failure can't abort the
    rest. Returns the flat list of {check, status, detail} rows. With `data_dir`, also
    reports the saved-history horizon."""
    out: list[Check] = []
    sections = list(_SECTIONS)
    if data_dir is not None:
        sections.append(("history", lambda o: _check_history(o, Path(data_dir))))
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
