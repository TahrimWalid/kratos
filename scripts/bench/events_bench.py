"""Event store benchmark (docs: phase 0, feature 0.2, §8).

Generates synthetic events across 3 machines with realistic cardinality
(~5,000 source IPs, 200 users, 300 programs, 30 days), inserts them in batches
the way reads do, then times 200 random queries of each indexed kind (time,
source IP, user, process, SHA-256), each with limit=100 and a 24-hour window.

    .venv/bin/python scripts/bench/events_bench.py                 # 1,000,000 events
    .venv/bin/python scripts/bench/events_bench.py --events 100000 --full-indexes

Writes only to a fresh temporary folder (or --dir), never to kratos.db.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kratos.events import store as S
from kratos.events.model import Event, event_id

UTC = timezone.utc
TARGETS = ("10.136.28.168", "web-01.example.com", "loopback")
DAYS = 30
BATCH = 5_000
KINDS = ("time", "ip", "user", "process", "sha256")


def _full_index_step(conn):
    """The spec's original indexes (full, hash index without ts), for comparison."""
    S._step_1(conn)
    for name, cols in (("host_events_ip", "target, source_ip, ts"), ("host_events_user", "target, user_name, ts"),
                       ("host_events_proc", "target, process_name, ts"), ("host_events_sha256", "target, file_sha256")):
        conn.execute(f"DROP INDEX IF EXISTS {name}")
        conn.execute(f"CREATE INDEX {name} ON host_events({cols})")


class Pools:
    def __init__(self, rng: random.Random):
        self.ips = [f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}" for _ in range(5_000)]
        self.users = [f"user{i:03d}" for i in range(200)]
        self.procs = ["sshd", "sshd-session", "sudo", "cron", "systemd", "kernel"] + [f"svc{i:03d}" for i in range(294)]
        self.hashes = [f"{rng.getrandbits(256):064x}" for _ in range(2_000)]


def _event(rng: random.Random, pools: Pools, target: str, ts: datetime, created: datetime) -> Event:
    kind = rng.random()
    ip = user = sha = None
    if kind < 0.45:      # auth: failed/successful logins with a source IP and user
        dataset, action, outcome = "kratos.auth", rng.choice(("ssh_failed_login", "ssh_success_login")), None
        ip, user, proc = rng.choice(pools.ips), rng.choice(pools.users), rng.choice(pools.procs[:2])
        cat, typ = ("authentication",), ("start",)
        outcome = "failure" if action == "ssh_failed_login" else "success"
    elif kind < 0.55:    # sudo
        dataset, action, outcome = "kratos.auth", "sudo_command", "success"
        user, proc, cat, typ = rng.choice(pools.users), rng.choice(pools.procs), ("process",), ("start",)
    else:                # general journal lines
        dataset, action, outcome, proc, cat, typ = "kratos.journal", None, None, rng.choice(pools.procs), (), ("info",)
    if rng.random() < 0.01:
        sha = rng.choice(pools.hashes)
    msg = f"{action or 'line'} {user or ''} {ip or ''} {rng.getrandbits(48):012x}"
    return Event(timestamp=ts, created=created, event_id=event_id(target, dataset, ts, proc, msg), kind="event",
                 category=cat, type=typ, action=action, outcome=outcome, dataset=dataset, provider=proc,
                 message=msg, host_name=target, user_name=user, source_ip=ip, process_name=proc,
                 file_sha256=sha, related_ip=(ip,) if ip else (), related_user=(user,) if user else (),
                 transport="ssh", read="bench", run_id=f"{rng.getrandbits(128):032x}", parser="bench/1")


def generate_and_insert(store: S.EventStore, n: int, rng: random.Random, pools: Pools,
                        end: datetime) -> tuple[float, float]:
    """Returns (seconds spent in store.add, seconds building events)."""
    start = end - timedelta(days=DAYS)
    span = (end - start).total_seconds()
    add_s = build_s = 0.0
    made = 0
    while made < n:
        t0 = time.perf_counter()
        batch = []
        for _ in range(min(BATCH, n - made)):
            ts = start + timedelta(seconds=rng.random() * span)
            batch.append(_event(rng, pools, rng.choice(TARGETS), ts.replace(microsecond=rng.randrange(10**6)), end))
        t1 = time.perf_counter()
        store.add(batch)
        t2 = time.perf_counter()
        build_s += t1 - t0
        add_s += t2 - t1
        made += len(batch)
    return add_s, build_s


def run_queries(store: S.EventStore, rng: random.Random, pools: Pools, end: datetime, per_kind: int) -> dict:
    results: dict[str, dict] = {}
    for kind in KINDS:
        times, hits = [], 0
        for _ in range(per_kind):
            target = rng.choice(TARGETS)
            w_end = end - timedelta(seconds=rng.random() * (DAYS - 1) * 86400)
            filters = {"start": w_end - timedelta(hours=24), "end": w_end}
            if kind == "ip":
                filters["source_ip"] = rng.choice(pools.ips)
            elif kind == "user":
                filters["user"] = rng.choice(pools.users)
            elif kind == "process":
                filters["process"] = rng.choice(pools.procs)
            elif kind == "sha256":
                filters["sha256"] = rng.choice(pools.hashes)
            t0 = time.perf_counter()
            out = store.query(target, limit=100, **filters)
            times.append((time.perf_counter() - t0) * 1000)
            hits += len(out)
        q = statistics.quantiles(times, n=100, method="inclusive")
        results[kind] = {"p50_ms": round(q[49], 2), "p95_ms": round(q[94], 2), "p99_ms": round(q[98], 2),
                         "max_ms": round(max(times), 2), "avg_rows": round(hits / per_kind, 1)}
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", type=int, default=1_000_000)
    ap.add_argument("--queries", type=int, default=200, help="per indexed kind")
    ap.add_argument("--full-indexes", action="store_true",
                    help="the original full indexes instead of the store's partial ones, for comparison")
    ap.add_argument("--dir", type=Path, default=None, help="folder for the throwaway database")
    ap.add_argument("--seed", type=int, default=20261011)
    args = ap.parse_args(argv)

    folder = args.dir or Path(tempfile.mkdtemp(prefix="kratos-events-bench-"))
    db = folder / "bench.db"
    if db.exists():
        print(f"{db} exists; use an empty --dir", file=sys.stderr)
        return 1
    if args.full_indexes:
        S.STEPS = (_full_index_step,)
        S.COMPONENT = "events_bench_full_indexes"
    store = S.EventStore(db)
    rng = random.Random(args.seed)
    pools = Pools(rng)
    end = datetime(2026, 10, 11, tzinfo=UTC)
    add_s, build_s = generate_and_insert(store, args.events, rng, pools, end)
    rows = sum(c for _, c in store.targets())
    size = sum(p.stat().st_size for p in folder.glob("bench.db*"))
    queries = run_queries(store, random.Random(args.seed + 1), pools, end, args.queries)
    report = {
        "events_requested": args.events, "rows_stored": rows, "index_variant": "full" if args.full_indexes else "store (partial)",
        "insert_rate_per_s": round(rows / add_s), "insert_seconds": round(add_s, 1),
        "build_seconds": round(build_s, 1), "db_bytes": size,
        "db_mb_per_million": round(size / 1e6 / (rows / 1e6), 1), "queries": queries,
        "worst_p95_ms": max(q["p95_ms"] for q in queries.values()), "db": str(db),
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
