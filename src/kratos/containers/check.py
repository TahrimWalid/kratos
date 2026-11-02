"""The collection checks (A.0 §5.3) for containers (D.5): `containers` (quick -- the
engines' API, /proc, the firewall rules, and one TCP connect per port the firewall
model says bypasses the firewall) and `container_packages` (slow -- each running image's
package database, through the sub-agent). No tool joins the model's list."""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.containers import packages, record
from kratos.containers import settings as _settings  # noqa: F401 -- registers containers.*


def _run_containers(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    if doc.get("status") != "ok":
        return CheckResult("failed", "could not be checked", ["containers: could not be checked"],
                           detail=str(doc.get("observation") or "")[:300])
    if not doc.get("engines_found"):
        return CheckResult("ok", "no container engine found", [], detail=str(doc.get("file")))
    gaps = [f"containers: {g}" for g in doc.get("coverage_gaps") or []]
    status = "ok" if doc.get("complete") and not gaps else "partial"
    return CheckResult(status, record.summary_line(doc), gaps, detail=str(doc.get("file")))


def _run_container_packages(ctx: CheckContext) -> CheckResult:
    doc = packages.run(ctx.data_dir, ctx.target)
    if doc.get("status") != "ok":
        return CheckResult("failed", "could not be checked", ["packages inside containers: could not be checked"],
                           detail=str(doc.get("observation") or "")[:300])
    if doc.get("note") == "no container engine found":
        return CheckResult("ok", "no container engine found", [], detail=str(doc.get("file")))
    gaps = [g if g.startswith(("packages inside containers", "image ")) else f"packages inside containers: {g}"
            for g in doc.get("coverage_gaps") or [] if g != packages.IMAGE_ORIGIN_NOTE]
    status = "ok" if doc.get("complete") and not gaps else "partial"
    return CheckResult(status, packages.summary_line(doc), gaps, detail=str(doc.get("file")))


register(Check(
    name="containers", cost="quick", ttl_setting="collect.ttl.containers_minutes", default_ttl_minutes=60,
    run=_run_containers, inputs=("containers",), transports=frozenset({"ssh", "agent", "local"}),
    budget_seconds=60.0, label="containers and published ports", order=47, short="containers"))
register(Check(
    name="container_packages", cost="slow", ttl_setting="collect.ttl.container_packages_minutes",
    default_ttl_minutes=360, run=_run_container_packages, inputs=("container_packages",),
    transports=frozenset({"ssh", "agent", "local"}), budget_seconds=150.0,
    label="packages inside running containers", order=62, short="container packages", after=("containers",)))
