#!/usr/bin/env python3
"""Write a deterministic, realistic history for baselining (E.3) into a SCRATCH Kratos home.

    KRATOS_HOME=<scratch> python scripts/dev/generate_baseline_history.py --home <scratch> \\
        --days 21 --seed 7 --machines 3 --plant all

Per machine: sign-ins (a 9-to-5 account from an office range by key, an admin from a tailnet
and a home range, an automation account every 15 minutes, Kratos's own logins with its key),
sudo use (Kratos's own `sudo -n` reads too), running-process reads four times a day
(listeners and outbound connections), log-sync coverage for every day, the machine's time
zone (one machine is Europe/Helsinki, across the October DST change) and a privileged-
accounts read. Events go through the real classifier and converters into the real event
store, so baselines read exactly what log sync would have stored.

Planted deviations (in the last two days, `--plant`, comma separated or `all`):
  new_source   deploy signs in from a public /24 it never used
  odd_hour     deploy (a weekday 08-18 account) signs in at 03:00 on a weekday
  password     deploy (always by key) signs in by password
  sudo_root    a user who never used sudo runs a shell as root
  listener     a new program listens on tcp/4444
  outbound     a web server connects out to a public address on port 4444

Refuses to write into a data folder that isn't a scratch one (one with a `.scratch-baseline`
marker, or empty). Never touch the real data folder: the owner keeps its history.
Nothing random is used without the seed; the same arguments give the same events.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

PLANTS = ("new_source", "odd_hour", "password", "sudo_root", "listener", "outbound")
MARKER = ".scratch-baseline"
ZONES = ("UTC", "Europe/Helsinki", "UTC", "America/New_York")


def _fp(seed: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(seed.encode()).digest()).decode().rstrip("=")


def machine_address(i: int) -> str:
    return f"10.200.0.{10 + i}"


class Machine:
    def __init__(self, i: int, rng: random.Random, zone: str, own_fp: str, own_user: str):
        self.i, self.rng, self.zone = i, rng, ZoneInfo(zone)
        self.zone_name = zone
        self.target = machine_address(i)
        self.own_fp, self.own_user = own_fp, own_user
        self.user_fp = {u: _fp(f"user-{u}-{i}") for u in ("deploy", "alice", "backup", "carol")}
        self.logins: list[tuple[float, str, str, str]] = []      # ts, user, ip, method
        self.sudo: list[tuple[float, str, str, str]] = []        # ts, user, run_as, command
        self.snapshots: list[tuple[float, list[dict], list[dict]]] = []
        self.planted: list[dict] = []

    # --- normal life --------------------------------------------------------
    def day(self, day_start_local: datetime) -> None:
        rng = self.rng
        weekday = day_start_local.weekday() < 5
        # deploy: weekdays, 08:00-18:59 local, 3-6 sign-ins, office 10.20.0.0/24, by key
        if weekday:
            for _ in range(rng.randint(3, 6)):
                t = day_start_local + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 59))
                self.logins.append((t.timestamp(), "deploy", f"10.20.0.{rng.randint(5, 60)}", "publickey"))
                if rng.random() < 0.3:
                    self.sudo.append((t.timestamp() + 60, "deploy", "root", "/usr/bin/systemctl restart app"))
            if rng.random() < 0.05:          # benign noise: an early start or a late finish
                t = day_start_local + timedelta(hours=rng.choice([6, 7, 19, 20]), minutes=rng.randint(0, 59))
                self.logins.append((t.timestamp(), "deploy", f"10.20.0.{rng.randint(5, 60)}", "publickey"))
        # alice: admin, weekdays 09-17 from the tailnet, some evenings/weekends from home (public)
        if weekday or rng.random() < 0.4:
            for _ in range(rng.randint(1, 3)):
                home = not weekday or rng.random() < 0.25
                hour = rng.randint(18, 21) if home and weekday else rng.randint(9, 17)
                t = day_start_local + timedelta(hours=hour, minutes=rng.randint(0, 59))
                ip = f"198.51.100.{rng.randint(20, 30)}" if home else f"100.100.7.{rng.randint(2, 9)}"
                self.logins.append((t.timestamp(), "alice", ip, "publickey"))
                if rng.random() < 0.6:
                    cmd = rng.choice(["/usr/bin/apt update", "/usr/bin/systemctl status nginx",
                                      "/usr/bin/journalctl -u nginx"])
                    if rng.random() < 0.03:  # benign noise: a tool alice rarely needs
                        cmd = rng.choice(["/usr/bin/tcpdump -i eth0", "/usr/sbin/ufw status", "/usr/bin/du -sh /"])
                    self.sudo.append((t.timestamp() + 90, "alice", "root", cmd))
        # backup: automation every 15 minutes from one address, by key
        for q in range(96):
            t = day_start_local + timedelta(minutes=15 * q, seconds=rng.randint(0, 20))
            self.logins.append((t.timestamp(), "backup", "10.20.1.10", "publickey"))
        # Kratos's own reads: a login and `sudo -n journalctl` every hour
        for h in range(24):
            t = day_start_local + timedelta(hours=h, minutes=2)
            self.logins.append((t.timestamp(), self.own_user, "10.200.0.1", "own"))
            self.sudo.append((t.timestamp() + 5, self.own_user, "root", "/usr/bin/journalctl -o json -n 500"))
        # running-process reads, four a day
        for h in (1, 7, 13, 19):
            t = day_start_local + timedelta(hours=h, minutes=rng.randint(0, 30))
            listeners = [{"port": 22, "proto": "tcp", "address": "0.0.0.0", "seen": True, "exe": "/usr/sbin/sshd"},
                         {"port": 80, "proto": "tcp", "address": "0.0.0.0", "seen": True, "exe": "/usr/sbin/nginx"},
                         {"port": 443, "proto": "tcp", "address": "0.0.0.0", "seen": True, "exe": "/usr/sbin/nginx"},
                         {"port": 5432, "proto": "tcp", "address": "127.0.0.1", "seen": True,
                          "exe": "/usr/lib/postgresql/16/bin/postgres"}]
            outbound = [{"exe": "/usr/bin/python3.12", "remote": "10.20.2.20", "remote_port": 5432, "proto": "tcp"}]
            if rng.random() < 0.3:
                outbound.append({"exe": "/usr/lib/apt/methods/http", "remote": f"203.0.113.{rng.randint(80, 90)}",
                                 "remote_port": 80, "proto": "tcp"})
            self.snapshots.append((t.timestamp(), listeners, outbound))

    # --- plants ---------------------------------------------------------------
    def plant(self, what: str, end: datetime) -> None:
        local_end = end.astimezone(self.zone)
        # one plant per day, counting back from the day before `end` (the daily noise budget
        # would otherwise rank several plants of one day against each other); all inside the
        # last week, which is what a run raises
        d = (local_end - timedelta(days=PLANTS.index(what) + 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        if what == "new_source":
            t = d + timedelta(hours=11, minutes=17)
            self.logins.append((t.timestamp(), "deploy", "192.0.2.77", "publickey"))
            self.planted.append({"plant": what, "rule": "BASE-001", "subject": "deploy", "key": "192.0.2.0/24"})
        elif what == "odd_hour":
            t = d + timedelta(hours=3, minutes=4)
            self.logins.append((t.timestamp(), "deploy", "10.20.0.12", "publickey"))
            self.planted.append({"plant": what, "rule": "BASE-002", "subject": "deploy", "key": "03 weekday"})
        elif what == "password":
            t = d + timedelta(hours=14, minutes=41)
            self.logins.append((t.timestamp(), "deploy", "10.20.0.14", "password"))
            self.planted.append({"plant": what, "rule": "BASE-003", "subject": "deploy", "key": "password"})
        elif what == "sudo_root":
            t = d + timedelta(hours=15, minutes=2)
            self.logins.append((t.timestamp() - 30, "carol", "10.20.0.31", "publickey"))
            self.sudo.append((t.timestamp(), "carol", "root", "/bin/bash"))
            self.planted.append({"plant": what, "rule": "BASE-004", "subject": "carol", "key": "as root: bash"})
        elif what == "listener":
            t = d + timedelta(hours=16, minutes=5)
            self.snapshots.append((t.timestamp(), [
                {"port": 22, "proto": "tcp", "address": "0.0.0.0", "seen": True, "exe": "/usr/sbin/sshd"},
                {"port": 4444, "proto": "tcp", "address": "0.0.0.0", "seen": True, "exe": "/tmp/.x/nc"}], []))
            self.planted.append({"plant": what, "rule": "BASE-005", "subject": "/tmp/.x/nc", "key": "tcp/4444"})
        elif what == "outbound":
            t = d + timedelta(hours=16, minutes=35)
            self.snapshots.append((t.timestamp(), [], [
                {"exe": "/usr/sbin/nginx", "remote": "203.0.113.200", "remote_port": 4444, "proto": "tcp"}]))
            self.planted.append({"plant": what, "rule": "BASE-006", "subject": "/usr/sbin/nginx",
                                 "key": "203.0.113.0/24 port 4444"})


def _login_message(m: Machine, user: str, ip: str, method: str) -> str:
    port = 40000 + int(hashlib.sha256(f"{user}|{ip}".encode()).hexdigest()[:6], 16) % 20000
    if method == "own":
        return f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {m.own_fp}"
    if method == "password":
        return f"Accepted password for {user} from {ip} port {port} ssh2"
    return f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {m.user_fp.get(user, _fp(user))}"


def write(home: Path, machines: list[Machine], end: datetime, days: int, *,
          gaps: list[tuple[float, float]] | None = None, note: str = "generated gap: log sync was not running") -> dict:
    """`gaps`: stretches log sync did not cover (recorded as gaps, not as covered spans)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from kratos.adapters.auth_log_parse import classify_auth_message
    from kratos.collect.sync import cursors
    from kratos.events import converters as C
    from kratos.events.store import EventStore

    data = home / "data"
    store = EventStore(data / "kratos.db")
    counts = {}
    for m in machines:
        ctx = C.ReadContext(target=m.target, transport="ssh", read=C.READ_JOURNAL_AUTH)
        events = []

        def synced(ts: float) -> bool:
            return not any(gs <= ts < ge for gs, ge in gaps or ())

        for ts, user, ip, method in sorted(x for x in m.logins if synced(x[0])):
            msg = _login_message(m, user, ip, method)
            iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            events.append(C.from_auth_event(classify_auth_message(iso, None, "sshd", msg, msg), ctx=ctx))
        for ts, user, run_as, cmd in sorted(x for x in m.sudo if synced(x[0])):
            msg = f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER={run_as} ; COMMAND={cmd}"
            iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            events.append(C.from_auth_event(classify_auth_message(iso, None, "sudo", msg, msg), ctx=ctx))
        for i in range(0, len(events), 5000):
            store.add(events[i:i + 5000])
        start = (end - timedelta(days=days)).timestamp()
        day = 86400
        t = start
        while t < end.timestamp():
            hi = min(t + day, end.timestamp())
            in_gap = any(gs < hi and t < ge for gs, ge in gaps or ())
            cursors.add_span(data, m.target, "auth", t, hi, complete=not in_gap,
                             note=note if in_gap else "generated history")
            t += day
        live = data / "live"
        live.mkdir(parents=True, exist_ok=True)
        for n, (ts, listeners, outbound) in enumerate(sorted(m.snapshots, key=lambda s: s[0])):
            doc = {"target": m.target, "checked_at": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                   "checked_at_epoch": ts, "via": "ssh", "complete": True, "listeners": listeners,
                   "outbound": outbound, "signals": [], "counts": {}}
            stamp = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%d_%H%M%S")
            (live / f"live_response_{stamp}_{m.i:02d}{n:05d}.json").write_text(json.dumps(doc), encoding="utf-8")
        logs = data / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / f"auth_stats_w1_{m.i:02d}_{int(end.timestamp())}.json").write_text(json.dumps({
            "source": f"ssh_target_measurement:{m.own_user}@{m.target}", "measurement": "exhaustive",
            "target_timezone": {"name": m.zone_name, "offset": None}, "total_events": 0, "events_by_type": {}}),
            encoding="utf-8")
        ctxd = data / "context"
        ctxd.mkdir(parents=True, exist_ok=True)
        (ctxd / f"privileged_accounts_{m.i:02d}_{int(end.timestamp())}.json").write_text(json.dumps({
            "status": "ok", "target": m.target, "checked_at": end.isoformat(),
            "privileged_accounts": [{"user": "root"}, {"user": "alice"}, {"user": m.own_user}],
            "accounts": {}, "local_accounts": ["root", "alice", "deploy", "backup", "carol", m.own_user]}),
            encoding="utf-8")
        counts[m.target] = {"logins": len(m.logins), "sudo": len(m.sudo), "snapshots": len(m.snapshots)}
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", required=True, type=Path, help="a scratch KRATOS_HOME (created if missing)")
    ap.add_argument("--days", type=int, default=21)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--machines", type=int, default=3)
    ap.add_argument("--plant", default="all", help="comma-separated plants, 'all' or 'none'")
    ap.add_argument("--end", help="ISO time the history ends (default: now, rounded down to the hour)")
    ap.add_argument("--own-fingerprint", help="the SSH key fingerprint Kratos's own logins use (default: a fixed one)")
    ap.add_argument("--own-user", default="ubuntu")
    ap.add_argument("--gap-days", type=int, default=0, help="leave this many days (ending a week ago) uncovered")
    args = ap.parse_args(argv)
    home = args.home.expanduser().resolve()
    data = home / "data"
    if (data / "kratos.db").exists() and not (home / MARKER).exists():
        print(f"refusing: {data} holds a Kratos database that isn't a generated scratch one", file=sys.stderr)
        return 2
    real = {Path.home() / ".local/share/kratos", Path(__file__).resolve().parents[2] / "data"}
    if data in real:
        print("refusing: that is a real Kratos data folder", file=sys.stderr)
        return 2
    data.mkdir(parents=True, exist_ok=True)
    (home / MARKER).write_text("generated by scripts/dev/generate_baseline_history.py\n", encoding="utf-8")
    plants = PLANTS if args.plant == "all" else () if args.plant == "none" else tuple(
        p.strip() for p in args.plant.split(",") if p.strip())
    bad = [p for p in plants if p not in PLANTS]
    if bad:
        print(f"unknown plant(s): {', '.join(bad)} (known: {', '.join(PLANTS)})", file=sys.stderr)
        return 2
    end = (datetime.fromisoformat(args.end) if args.end else datetime.now(timezone.utc)).astimezone(timezone.utc)
    end = end.replace(minute=0, second=0, microsecond=0)
    own_fp = args.own_fingerprint or _fp("kratos-own-key")
    machines = []
    for i in range(args.machines):
        rng = random.Random(f"{args.seed}:{i}")
        m = Machine(i, rng, ZONES[i % len(ZONES)], own_fp, args.own_user)
        local_end = end.astimezone(m.zone)
        first = (local_end - timedelta(days=args.days)).replace(hour=0, minute=0, second=0, microsecond=0)
        d = first
        while d < local_end - timedelta(days=1):
            m.day(d)
            d = (d + timedelta(days=1, hours=3)).replace(hour=0)   # midnight to midnight across DST
        for p in plants:
            m.plant(p, end)
        machines.append(m)
    gaps = None
    if args.gap_days:
        g_end = end - timedelta(days=7)
        gaps = [((g_end - timedelta(days=args.gap_days)).timestamp(), g_end.timestamp())]
    counts = write(home, machines, end, args.days, gaps=gaps)
    manifest = {"seed": args.seed, "days": args.days, "end": end.isoformat(), "own_fingerprint": own_fp,
                "own_user": args.own_user, "machines": [
                    {"target": m.target, "zone": m.zone_name, **counts[m.target], "planted": m.planted}
                    for m in machines]}
    (home / "baseline_history.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
