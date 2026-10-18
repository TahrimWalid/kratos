"""`kratos-eval` -- the regression gate's command line (docs/phaseB/B.4 §5.3).

    kratos-eval list
    kratos-eval record  --scenarios A1,A8 [-n 1]      live runs -> recordings (needs the lab)
    kratos-eval run     --mode replay|live --scenarios A1,.. -n 5 [--out results.json]
    kratos-eval compare <base.json> <branch.json>     apply the gate rule, print the table
    kratos-eval gate    --mode replay|live [-n 5]      run this branch + compare vs the baseline
    kratos-eval baseline --accept <results.json>       save the baseline for its model
    kratos-eval smoke                                  replay+score+gate with a scripted model (no key)

Results and recordings are data, kept out of the repo (KRATOS_EVAL_RESULTS, default
~/kratos_eval_artifacts/gate); recordings committed under evals/replay/recordings/ hold
lab data only. The gate decides on "person sees"; see evals/gate.py for the rule.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from evals import gate, replay, score

RECORDINGS = Path(__file__).resolve().parent / "replay" / "recordings"
BASELINES = Path(__file__).resolve().parent / "baselines"


def results_dir() -> Path:
    d = Path(os.environ.get("KRATOS_EVAL_RESULTS") or (Path.home() / "kratos_eval_artifacts" / "gate"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _model() -> str:
    from kratos import llm_config
    return llm_config.get_active_llm_model()


def _commit() -> str:
    import subprocess
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              cwd=Path(__file__).resolve().parents[1]).stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def _select(names: str | None) -> list[score.Scenario]:
    if not names or names == "ALL":
        return list(score.SCENARIOS.values())
    out, unknown = [], []
    for n in names.split(","):
        n = n.strip()
        (out.append(score.SCENARIOS[n]) if n in score.SCENARIOS else unknown.append(n))
    if unknown:
        raise SystemExit(f"unknown scenario(s): {', '.join(unknown)}")
    return out


# --------------------------------------------------------------------------- one run

def replay_summary(tracker: Any) -> dict[str, Any]:
    """What a replay run hit, as stored with its payload. A model step with no tool
    name is recorded as None, so the lists are sorted as text."""
    return {"hits": tracker.hits, "arg_mismatches": sorted(set(tracker.arg_mismatches), key=str),
            "not_recorded": sorted(set(tracker.not_recorded), key=str),
            "left_recording": tracker.left_recording}


def _run_once(sc: score.Scenario, *, mode: str, data_dir: Path, mask_mode: str | None = None) -> dict[str, Any]:
    """Run one investigation (live or replay) and return its payload (status,
    final_answer, tools_called, transcript, run_id). `mask_mode`: what the model
    is sent (kratos.privacy) for this run, set in its own data folder; None keeps
    the default ('auto')."""
    from kratos import kratos_config, settings_store
    from kratos.agent.loop import run_agent
    from kratos.run_context import run_scope

    kratos_config.set_active_data_dir(data_dir)
    if mask_mode:
        from kratos.privacy.mode import MODE_KEY
        settings_store.set(MODE_KEY, mask_mode, data_dir=data_dir, actor="kratos-eval")
    if mode == "replay":
        rec_path = RECORDINGS / f"{sc.id}.json"
        if not rec_path.is_file():
            return {"status": "no_recording", "final_answer": None, "tools_called": [], "transcript": []}
        recording = json.loads(rec_path.read_text(encoding="utf-8"))
        kratos_config.set_active_target(recording.get("target") or "10.0.0.0")
        with replay.install(recording) as tracker, run_scope("cli"):
            payload = run_agent(sc.goal, data_dir, max_iters=sc.max_iters or 8)
        payload["replay"] = replay_summary(tracker)
        return payload
    # live
    from evals import harness_bridge
    from evals.lab import lab

    setup, teardown, extras = harness_bridge.setup_teardown(sc.id)
    kratos_config.set_active_target(lab().target)
    ctx = {"data_dir": data_dir}
    if extras.get("needs_baseline"):
        harness_bridge.seed_baseline(data_dir)
    setup_err = None
    try:
        setup(ctx)
    except Exception as e:  # noqa: BLE001 -- a half-done setup is logged, never crashes the batch
        import traceback
        setup_err = traceback.format_exc()
        print(f"    setup error: {e}", file=sys.stderr)
    try:
        with run_scope("cli"):
            payload = run_agent(sc.goal, data_dir, max_iters=sc.max_iters or extras.get("max_iters") or 8)
    finally:
        try:
            teardown(ctx)
        except Exception as e:  # noqa: BLE001
            print(f"    teardown error: {e}", file=sys.stderr)
    payload["setup_error"] = setup_err
    return payload


def _read_trace(data_dir: Path, run_id: str | None) -> dict[str, Any] | None:
    if not run_id:
        return None
    from kratos.trace import store
    for p in store.trace_files(data_dir):
        if p.name.startswith(run_id) and p.suffix == ".json":
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
    return None


# --------------------------------------------------------------------------- commands

def cmd_run(mode: str, scenarios: str | None, n: int, out: Path | None, mask_mode: str | None = None) -> int:
    import tempfile

    sel = _select(scenarios)
    runs: dict[str, list[dict[str, Any]]] = {}
    existing = json.loads(out.read_text()) if (out and out.is_file()) else {}
    runs.update(existing.get("scenarios", {}))
    base = Path(tempfile.mkdtemp(prefix="kratos-eval-"))
    try:
        for sc in sel:
            have = runs.setdefault(sc.id, [])
            for k in range(len(have), n):
                dd = base / f"{sc.id}_{k}"
                dd.mkdir(parents=True, exist_ok=True)
                t0 = time.time()
                payload = _run_once(sc, mode=mode, data_dir=dd, mask_mode=mask_mode)
                scored = score.score_payload(sc, payload)
                scored.update(id=sc.id, run=k + 1, elapsed=round(time.time() - t0, 1),
                              status=payload.get("status"), replay=payload.get("replay"))
                have.append(scored)
                print(f"  {sc.id:<16} run {k + 1}/{n}  person={scored['person_sees']} "
                      f"model_alone={scored['model_alone']}  {scored['elapsed']}s", flush=True)
                if out:
                    _write_results(out, mode, runs, mask_mode)
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)
    if out:
        _write_results(out, mode, runs, mask_mode)
        print(f"\nwrote {out}")
    return 0


def _write_results(out: Path, mode: str, runs: dict[str, list[dict]], mask_mode: str | None = None) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"model": _model(), "mode": mode, "mask_mode": mask_mode or "auto",
                               "commit": _commit(), "scenarios": runs}, indent=2), encoding="utf-8")


def as_baseline(doc: dict[str, Any]) -> dict[str, Any]:
    """A baseline file as is, or a results file (`kratos-eval run --out`) read as one --
    so two runs on the same commit (masking off vs standard) compare directly."""
    rows = {}
    for sid, value in (doc.get("scenarios") or {}).items():
        if isinstance(value, dict):
            rows[sid] = value
            continue
        rows[sid] = {"person_pass": sum(1 for s in value if s["person_sees"] == "pass"),
                     "n": sum(1 for s in value if s["person_sees"] in ("pass", "fail")),
                     "model_alone_pass": sum(1 for s in value if s["model_alone"] == "pass")}
    return {**doc, "scenarios": rows}


def cmd_record(scenarios: str | None, n: int) -> int:

    sel = _select(scenarios)
    RECORDINGS.mkdir(parents=True, exist_ok=True)
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="kratos-eval-rec-"))
    written = 0
    for sc in sel:
        for _ in range(n):   # the last clean run wins
            dd = base / f"{sc.id}_{int(time.time())}"
            dd.mkdir(parents=True, exist_ok=True)
            payload = _run_once(sc, mode="live", data_dir=dd)
            trace = _read_trace(dd, payload.get("run_id"))
            if trace is None:
                print(f"  {sc.id}: no trace (recording needs trace.enabled); skipped", file=sys.stderr)
                break
            rec = replay.recording_from_trace(trace, sc.id, sc.goal)
            problems = replay.scan_recording(rec)
            if problems:
                print(f"  {sc.id}: NOT saved -- {'; '.join(problems)}", file=sys.stderr)
                break
            (RECORDINGS / f"{sc.id}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
            written += 1
            print(f"  {sc.id}: recorded {len(rec['calls'])} tool call(s) (target {rec.get('target')})")
    import shutil
    shutil.rmtree(base, ignore_errors=True)
    print(f"\n{written} recording(s) under {RECORDINGS}")
    return 0


def _load_baseline() -> dict[str, Any]:
    p = BASELINES / f"{_model()}.json"
    if not p.is_file():
        raise SystemExit(f"no baseline for model {_model()!r} ({p}); make one with `kratos-eval baseline --accept`")
    return json.loads(p.read_text(encoding="utf-8"))


def _print_report(rep: gate.GateReport) -> None:
    for ln in rep.lines:
        print(ln)
    for w in rep.model_alone_warnings:
        print(f"  warning (model alone): {w}")
    print(f"\ngate: {'PASS' if rep.passed else 'FAIL'}")
    for f in rep.hard_failures:
        print(f"  hard: {f}")
    for r in rep.scored_regressions:
        print(f"  regression: {r['id']} {r['rate']}% vs baseline {r['baseline_rate']}%")


def cmd_compare(base_file: Path, branch_file: Path, *, reran: bool = False) -> int:
    baseline = as_baseline(json.loads(base_file.read_text(encoding="utf-8")))
    branch = json.loads(branch_file.read_text(encoding="utf-8"))
    kinds = {sid: sc.kind for sid, sc in score.SCENARIOS.items()}
    results = gate.results_from_runs(branch.get("scenarios", {}), kinds)
    rep = gate.decide(results, baseline, reran=reran)
    _print_report(rep)
    return 0 if rep.passed else 1


def cmd_gate(mode: str, scenarios: str | None, n: int, mask_mode: str | None = None) -> int:
    baseline = _load_baseline()
    out = results_dir() / f"branch_{mode}_{int(time.time())}.json"
    cmd_run(mode, scenarios, n, out, mask_mode)
    branch = json.loads(out.read_text(encoding="utf-8"))
    kinds = {sid: sc.kind for sid, sc in score.SCENARIOS.items()}
    rep = gate.decide(gate.results_from_runs(branch["scenarios"], kinds), baseline)
    if rep.needs_rerun:
        print(f"\nre-running at N={gate.RERUN_N}: {', '.join(rep.needs_rerun)}")
        cmd_run(mode, ",".join(rep.needs_rerun), gate.RERUN_N, out, mask_mode)
        branch = json.loads(out.read_text(encoding="utf-8"))
        rep = gate.decide(gate.results_from_runs(branch["scenarios"], kinds), baseline, reran=True)
    _print_report(rep)
    return 0 if rep.passed else 1


def cmd_baseline(results_file: Path) -> int:
    branch = json.loads(results_file.read_text(encoding="utf-8"))
    rows = {}
    for sid, scored in branch.get("scenarios", {}).items():
        rows[sid] = {"person_pass": sum(1 for s in scored if s["person_sees"] == "pass"),
                     "n": sum(1 for s in scored if s["person_sees"] in ("pass", "fail")),
                     "model_alone_pass": sum(1 for s in scored if s["model_alone"] == "pass")}
    BASELINES.mkdir(parents=True, exist_ok=True)
    p = BASELINES / f"{branch.get('model') or _model()}.json"
    p.write_text(json.dumps({"model": branch.get("model"), "commit": branch.get("commit"),
                             "accepted_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "scenarios": rows}, indent=2),
                 encoding="utf-8")
    print(f"wrote baseline {p} ({len(rows)} scenarios)")
    return 0


def cmd_list() -> int:
    for sid, sc in score.SCENARIOS.items():
        print(f"{sid:<16} {sc.kind:<7} {sc.goal[:70]}")
    return 0


def cmd_smoke() -> int:
    from evals import smoke
    return smoke.run()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kratos-eval", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("smoke")
    for name in ("run", "gate"):
        p = sub.add_parser(name)
        p.add_argument("--mode", choices=["replay", "live"], default="replay")
        p.add_argument("--scenarios", default="ALL")
        p.add_argument("-n", type=int, default=5)
        p.add_argument("--mask-mode", choices=["auto", "off", "standard", "strict"], default=None,
                       help="What the model is sent (privacy.mask_mode) in each run; default: auto")
        if name == "run":
            p.add_argument("--out", type=Path, default=None)
    rec = sub.add_parser("record")
    rec.add_argument("--scenarios", default="ALL")
    rec.add_argument("-n", type=int, default=1)
    cmp_ = sub.add_parser("compare")
    cmp_.add_argument("base", type=Path)
    cmp_.add_argument("branch", type=Path)
    cmp_.add_argument("--reran", action="store_true")
    bl = sub.add_parser("baseline")
    bl.add_argument("--accept", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "list":
        return cmd_list()
    if a.cmd == "smoke":
        return cmd_smoke()
    if a.cmd == "run":
        return cmd_run(a.mode, a.scenarios, a.n, a.out, a.mask_mode)
    if a.cmd == "gate":
        return cmd_gate(a.mode, a.scenarios, a.n, a.mask_mode)
    if a.cmd == "record":
        return cmd_record(a.scenarios, a.n)
    if a.cmd == "compare":
        return cmd_compare(a.base, a.branch, reran=a.reran)
    if a.cmd == "baseline":
        return cmd_baseline(a.accept)
    return 2


if __name__ == "__main__":
    sys.exit(main())
