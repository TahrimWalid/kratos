"""The two deployed-code collection checks (E.7a §3.11).

- `code_roots` (quick, fresh 6 h): which folders serve code -- candidates only; nothing in a
  folder is read until a person confirms it.
- `code` (slow, fresh `collect.ttl.code_minutes`, default 6 h): every confirmed folder --
  inventory, git drift, dependencies, secrets, web-shell YARA. Runs after the running-process
  and container reads, and after `code_roots`, when the same collection runs them."""
from __future__ import annotations

from kratos.code import record
from kratos.code import settings as _settings  # noqa: F401 -- registers code.* settings
from kratos.collect.registry import Check, CheckContext, CheckResult, register


def _run_roots(ctx: CheckContext) -> CheckResult:
    doc = record.run_roots(ctx.data_dir, ctx.target)
    gaps = [f"code folders: {n}" for n in doc.get("notes") or [] if "too old" in n or "failed" in n]
    status = "ok" if doc.get("complete") else "partial"
    if gaps and any("too old" in g for g in gaps) and not doc.get("roots"):
        status = "not_supported"
    return CheckResult(status, record.summary_roots(doc), gaps, detail=str(doc.get("file")))


def _run_code(ctx: CheckContext) -> CheckResult:
    doc = record.run_code(ctx.data_dir, ctx.target)
    gaps = [f"code: {g}" for g in (doc.get("coverage_gaps") or [])[:6]]
    status = "ok" if doc.get("complete") or not doc.get("roots") else "partial"
    return CheckResult(status, record.summary_code(doc), gaps, detail=str(doc.get("file")))


register(Check(
    name="code_roots", cost="quick", ttl_setting="collect.ttl.code_roots_minutes", default_ttl_minutes=360,
    run=_run_roots, inputs=(), transports=frozenset({"ssh", "agent"}), budget_seconds=60.0,
    label="where the machine serves code from", order=93, short="code folders",
    after=("live_response", "containers"), digest=False))
register(Check(
    name="code", cost="slow", ttl_setting="collect.ttl.code_minutes", default_ttl_minutes=360,
    run=_run_code, inputs=("code",), transports=frozenset({"ssh", "agent"}), budget_seconds=900.0,
    label="the code the machine serves (drift, dependencies, secrets)", order=94, short="code",
    after=("live_response", "containers", "code_roots", "hash_reputation")))
