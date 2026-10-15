"""The collection check (A.0 §5.3): `packages`.

A.2 adds no tool to the model's list (docs/phaseA/README.md §4.1/§4.2): Kratos
reads the installed packages itself, as part of collection, matches them offline,
and the model reasons over the digest line and the PKG-* findings
`correlate_findings` raises from the saved result.

`packages` is a quick check: the read is one package-manager listing (well under
a second on the lab machines) and matching is local. Re-read when its result is
over six hours old -- or sooner after `kratos vulndb-update`, which marks it stale.
"""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.pkgvuln import record
from kratos.pkgvuln import settings as _settings  # noqa: F401 -- registers vulndb.* settings

CHECK_NAME = "packages"


def _run_packages(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    if doc.get("status") != "ok":
        return CheckResult("failed", "could not be checked",
                           ["installed packages: could not be checked"],
                           detail=str(doc.get("observation") or "")[:300])
    gaps = [f"packages: {g}" for g in doc.get("coverage_gaps") or []]
    status = "ok" if doc.get("complete") and not gaps else "partial"
    return CheckResult(status, record.summary_line(doc), gaps, tools=[], detail=f"{doc.get('file')}")


register(Check(
    name=CHECK_NAME, cost="quick", ttl_setting="collect.ttl.packages_minutes", default_ttl_minutes=360,
    run=_run_packages, inputs=("packages",), transports=frozenset({"ssh", "agent"}),
    budget_seconds=40.0, label="vulnerable packages", order=55, short="packages"))
