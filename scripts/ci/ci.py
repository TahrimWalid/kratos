#!/usr/bin/env python3
"""Kratos CI: one job list (scripts/ci/jobs.toml), run two ways.

    ci.py list                     the jobs
    ci.py workflow [--write]       print (or write) .github/workflows/ci.yml, generated from jobs.toml
    ci.py local [-j N] [job ...]   run jobs here, each in a fresh container (docker), with a summary

`local` packs the working tree (tracked files plus new, not-ignored ones -- what a
push would carry), mounts it read-only into the job's image, unpacks a writable
copy inside, and runs the job's apt / setup / run steps exactly as the workflow
does. Logs go to $KRATOS_CI_LOGS (default: a folder under /tmp). Exit status is
non-zero when any job fails.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

REPO = Path(__file__).resolve().parents[2]
JOBS_FILE = REPO / "scripts" / "ci" / "jobs.toml"
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"

# Pinned by commit; the comment names the release. Update both together.
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1"


@dataclass
class Job:
    name: str
    image: str
    apt: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    setup: list[str] = field(default_factory=list)
    run: list[str] = field(default_factory=list)
    user: str = ""     # run the `run` steps as this unprivileged user (setup stays root)

    @property
    def id(self) -> str:
        return self.name.replace(".", "-")

    def apt_script(self) -> list[str]:
        if not self.apt:
            return []
        return ["apt-get update -qq",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
                + " ".join(self.apt) + " >/dev/null"]

    def run_script(self) -> list[str]:
        """The `run` steps -- as `user` when set: tests that check file permissions
        mean nothing as root, and a developer runs them as themselves."""
        if not self.user:
            return list(self.run)
        u = self.user
        return ([f"id -u {u} >/dev/null 2>&1 || useradd -m {u}",
                 "cat > /tmp/ci-run.sh <<'CI_RUN_EOF'"] + self.run + ["CI_RUN_EOF",
                f"chown -R {u} .",
                f"runuser -u {u} -- env HOME=/home/{u} sh -e /tmp/ci-run.sh"])


def load_jobs(path: Path = JOBS_FILE) -> list[Job]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    d = data.get("defaults", {})
    jobs = []
    for j in data["job"]:
        env = dict(d.get("env", {}))
        env.update(j.get("env", {}))
        jobs.append(Job(name=j["name"], image=j["image"], apt=list(j.get("apt", d.get("apt", []))),
                        env={k: str(v) for k, v in env.items()}, setup=list(j.get("setup", [])),
                        run=list(j.get("run", [])), user=str(j.get("user", d.get("user", "")))))
    names = [j.name for j in jobs]
    if len(set(names)) != len(names):
        raise SystemExit(f"duplicate job names in {path}")
    return jobs


# --------------------------------------------------------------------------- workflow

def _block(lines: list[str], indent: int) -> str:
    pad = " " * indent
    return "\n".join(pad + ln for ln in lines)


def render_workflow(jobs: list[Job]) -> str:
    out = [
        "# GENERATED from scripts/ci/jobs.toml by `python scripts/ci/ci.py workflow --write` -- do not edit.",
        "# The same jobs run locally, in containers: scripts/ci/run_local.sh",
        "name: ci",
        "",
        "on:",
        "  push:",
        "  pull_request:",
        "",
        "permissions:",
        "  contents: read",
        "",
        "concurrency:",
        "  group: ci-${{ github.ref }}",
        "  cancel-in-progress: true",
        "",
        "jobs:",
    ]
    for j in jobs:
        out += [
            f"  {j.id}:",
            f"    name: {j.name}",
            "    runs-on: ubuntu-24.04",
            "    timeout-minutes: 45",
            f"    container: {j.image}",
        ]
        if j.env:
            out.append("    env:")
            out += [f"      {k}: {_yaml_str(v)}" for k, v in sorted(j.env.items())]
        out += [
            "    defaults:",
            "      run:",
            "        shell: sh -e {0}",
            "    steps:",
            f"      - uses: {CHECKOUT}",
            "        with:",
            "          persist-credentials: false",
        ]
        for title, lines in (("System packages", j.apt_script()), ("Install", j.setup), ("Run", j.run_script())):
            if lines:
                out += [f"      - name: {title}", "        run: |", _block(lines, 10)]
    return "\n".join(out) + "\n"


def _yaml_str(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------- local runner

def job_script(j: Job) -> str:
    """The whole job as one sh script, run inside the container."""
    lines = ["set -e", "mkdir -p /work", "tar -xf /ci/src.tar -C /work", "cd /work"]
    for title, steps in (("system packages", j.apt_script()), ("install", j.setup), ("run", j.run_script())):
        if steps:
            lines.append(f"echo '::: {title}'")
            lines += steps
    return "\n".join(lines) + "\n"


def pack_worktree(dest: Path) -> int:
    files = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=REPO,
                           capture_output=True, check=True).stdout.split(b"\0")
    n = 0
    with tarfile.open(dest, "w") as tar:
        for raw in files:
            if not raw:
                continue
            rel = raw.decode()
            p = REPO / rel
            if p.is_file() or p.is_symlink():
                tar.add(p, arcname=rel, recursive=False)
                n += 1
    return n


def run_local_job(j: Job, tarball: Path, logs: Path) -> tuple[str, int, float, Path]:
    log = logs / f"{j.name}.log"
    script = job_script(j)
    argv = ["docker", "run", "--rm", "--name", f"kratos-ci-{j.id}-{os.getpid()}",
            "-v", f"{tarball}:/ci/src.tar:ro",
            "-v", "kratos-ci-pip-cache:/root/.cache/pip"]
    for k, v in sorted(j.env.items()):
        argv += ["-e", f"{k}={v}"]
    argv += [j.image, "sh", "-ec", script]
    t0 = time.monotonic()
    with log.open("w", encoding="utf-8") as fh:
        fh.write(f"$ {shlex.join(argv[:-1])} <script>\n{script}\n")
        fh.flush()
        rc = subprocess.run(argv, stdout=fh, stderr=subprocess.STDOUT).returncode
    return j.name, rc, time.monotonic() - t0, log


def _tail(log: Path, n: int = 3) -> str:
    try:
        lines = [ln for ln in log.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    except OSError:
        return ""
    return " | ".join(lines[-n:])[-200:]


def cmd_local(names: list[str], parallel: int) -> int:
    jobs = load_jobs()
    if names:
        unknown = sorted(set(names) - {j.name for j in jobs})
        if unknown:
            print(f"unknown job(s): {', '.join(unknown)}; known: {', '.join(j.name for j in jobs)}")
            return 2
        jobs = [j for j in jobs if j.name in names]
    logs = Path(os.environ.get("KRATOS_CI_LOGS") or tempfile.mkdtemp(prefix="kratos-ci-logs-"))
    logs.mkdir(parents=True, exist_ok=True)
    tarball = logs / "src.tar"
    n = pack_worktree(tarball)
    print(f"packed {n} files from the working tree; logs in {logs}", flush=True)
    results = []
    with cf.ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        futs = {pool.submit(run_local_job, j, tarball, logs): j for j in jobs}
        for fut in cf.as_completed(futs):
            name, rc, secs, log = fut.result()
            results.append((name, rc, secs, log))
            print(f"  {'PASS' if rc == 0 else 'FAIL'}  {name:<18} {secs:6.0f}s", flush=True)
    order = {j.name: i for i, j in enumerate(jobs)}
    results.sort(key=lambda r: order[r[0]])
    print("\njob                 result   time  last lines")
    for name, rc, secs, log in results:
        print(f"{name:<19} {'pass' if rc == 0 else 'FAIL':<6} {secs:6.0f}s  {_tail(log)}")
    failed = [r for r in results if r[1] != 0]
    print(f"\n{len(results) - len(failed)}/{len(results)} jobs passed")
    tarball.unlink(missing_ok=True)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    w = sub.add_parser("workflow")
    w.add_argument("--write", action="store_true")
    loc = sub.add_parser("local")
    loc.add_argument("-j", "--parallel", type=int, default=2)
    loc.add_argument("jobs", nargs="*")
    a = ap.parse_args(argv)
    if a.cmd == "list":
        for j in load_jobs():
            print(f"{j.name:<19} {j.image}")
        return 0
    if a.cmd == "workflow":
        text = render_workflow(load_jobs())
        if a.write:
            WORKFLOW.parent.mkdir(parents=True, exist_ok=True)
            WORKFLOW.write_text(text, encoding="utf-8")
            print(f"wrote {WORKFLOW.relative_to(REPO)}")
        else:
            sys.stdout.write(text)
        return 0
    return cmd_local(a.jobs, a.parallel)


if __name__ == "__main__":
    sys.exit(main())
