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

from typing import Any

Check = dict[str, str]


def _row(check: str, status: str, detail: str) -> Check:
    return {"check": check, "status": status, "detail": detail}


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
    else:
        out.append(_row("LLM endpoint", "fail", f"{model} @ {base} — {detail or 'unreachable'}"))


def _check_env_profile(out: list[Check]) -> None:
    from kratos.adapters.llm_profiles import list_candidate_profiles, validate_profile
    from kratos.llm_config import ENV_FILE_PATH

    _cands, current = list_candidate_profiles(ENV_FILE_PATH)
    if current is None:
        out.append(_row(".env profile", "warn", "no active LLM profile detected in .env"))
        return
    problems = validate_profile(current)
    if problems:
        out.append(_row(".env profile", "fail", "; ".join(problems)))
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
            out.append(_row("target setup", "warn", "probe returned no checks"))
            return
        for c in probe:
            raw = str(c.get("status", "")).upper()
            status = "pass" if raw in ("PASS", "OK") else "fail" if raw == "FAIL" else "warn"
            out.append(_row(f"target · {c.get('check', '?')}", status, c.get("detail", "")))
    else:
        # SSHResult -> couldn't even connect (port 22 blocked, wrong host, key).
        detail = (getattr(probe, "stderr", "") or getattr(probe, "stdout", "") or "connection failed").strip()
        out.append(_row("target reachable", "fail", f"{target}: {detail[:140] or 'unreachable'}"))


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
        out.append(_row("kept tools", "fail", f"metadata references missing file(s): {', '.join(missing)}"))
    else:
        out.append(_row("kept tools", "pass", f"{len(meta)} kept, all source files present"))


_SECTIONS = (
    ("LLM endpoint", _check_llm_endpoint),
    (".env profile", _check_env_profile),
    ("backend", _check_backend),
    ("target", _check_target),
    ("kept tools", _check_kept_tools),
)


def run_diagnostics() -> list[Check]:
    """Run every diagnostic section, isolated so one failure can't abort the
    rest. Returns the flat list of {check, status, detail} rows."""
    out: list[Check] = []
    for name, fn in _SECTIONS:
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
