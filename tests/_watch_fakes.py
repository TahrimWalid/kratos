"""Fakes for continuous-detection tests (C.2): a stand-in `journalctl` that follows a
data file the test appends JSON entries to, and builders for journal entries and
auditd records. Neutral values only (RFC 5737 addresses, example names)."""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

BOOT = "0123456789abcdef0123456789abcdef"
SEQID = "fedcba9876543210fedcba9876543210"

FAKE_JOURNALCTL = r'''#!{python}
import json, os, sys, time
DATA = {data!r}
args = sys.argv[1:]
with open(DATA + ".argv", "a") as f:
    f.write(json.dumps(args) + "\n")


def entries():
    try:
        with open(DATA) as f:
            return [json.loads(l) for l in f if l.strip()]
    except OSError:
        return []


def seq_of(cursor):
    for part in cursor.split(";"):
        if part.startswith("i="):
            return int(part[2:], 16)
    return -1


if "--follow" not in args:            # the oldest-entry query
    es = [e for e in entries() if "__EXIT__" not in e]
    if es:
        print(json.dumps(es[0]))
    sys.exit(0)
after = since = None
for a in args:
    if a.startswith("--after-cursor="):
        after = seq_of(a.split("=", 1)[1])
if "--since" in args:
    since = float(args[args.index("--since") + 1][1:])
pos = len(entries()) if "--lines" in args else 0
while True:
    es = entries()
    while pos < len(es):
        e = es[pos]
        pos += 1
        if "__EXIT__" in e:
            if e.get("__SEEN__"):
                continue
            sys.stderr.write("journalctl: fake failure\n")
            sys.stderr.flush()
            es[pos - 1]["__SEEN__"] = True
            with open(DATA, "w") as f:
                f.write("".join(json.dumps(x) + "\n" for x in es))
            sys.exit(1)
        if "__RAW__" in e:
            sys.stdout.buffer.write(e["__RAW__"].encode("latin-1"))
            sys.stdout.flush()
            continue
        if after is not None and seq_of(e["__CURSOR"]) <= after:
            continue
        if since is not None and int(e["__REALTIME_TIMESTAMP"]) / 1e6 < since:
            continue
        sys.stdout.write(json.dumps(e) + "\n")
        sys.stdout.flush()
    time.sleep(0.05)
'''


def make_fake_journalctl(tmp_path: Path) -> tuple[Path, Path]:
    """(the fake journalctl, its data file)."""
    data = tmp_path / "journal.jsonl"
    data.write_text("")
    exe = tmp_path / "journalctl"
    exe.write_text(FAKE_JOURNALCTL.format(python=sys.executable, data=str(data)))
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return exe, data


def cursor(i: int, ts: float) -> str:
    return f"s={SEQID};i={i:x};b={BOOT};m={i:x};t={int(ts * 1e6):x};x={i:x}"


def journal_entry(i: int, ts: float, message: str, *, comm: str | None = None, ident: str | None = None,
                  pid: int = 4242, transport: str = "syslog") -> dict:
    e = {"__CURSOR": cursor(i, ts), "__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "MESSAGE": message,
         "_PID": str(pid), "_TRANSPORT": transport, "_BOOT_ID": BOOT, "_HOSTNAME": "host.example"}
    if comm:
        e["_COMM"] = comm
        e["SYSLOG_IDENTIFIER"] = ident or comm
    elif ident:
        e["SYSLOG_IDENTIFIER"] = ident
    return e


def append(data: Path, *entries: dict) -> None:
    with open(data, "a") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def sudo_line(user: str, command: str) -> str:
    return f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"


def failed_ssh(user: str, ip: str, port: int = 40000) -> str:
    return f"Failed password for invalid user {user} from {ip} port {port} ssh2"


def audit_exec(ts: float, serial: int, exe: str, args: list[str], *, pid: int = 3000, ppid: int = 2000,
               auid: int = 1000, ses: int = 7) -> list[str]:
    a = " ".join(f'a{i}="{v}"' for i, v in enumerate(args))
    return [
        f'type=SYSCALL msg=audit({ts:.3f}:{serial}): arch=c000003e syscall=59 success=yes exit=0 ppid={ppid} '
        f'pid={pid} auid={auid} uid=0 gid=0 euid=0 ses={ses} comm="{os.path.basename(exe)}" exe="{exe}" '
        'key="exec"\x1dARCH=x86_64 SYSCALL=execve AUID="alice" UID="root"',
        f"type=EXECVE msg=audit({ts:.3f}:{serial}): argc={len(args)} {a}",
        f'type=CWD msg=audit({ts:.3f}:{serial}): cwd="/root"',
        f"type=PROCTITLE msg=audit({ts:.3f}:{serial}): proctitle={' '.join(args).encode().hex().upper()}",
    ]


def write_audit(path: Path, lines: list[str]) -> None:
    with open(path, "a") as f:
        for line in lines:
            f.write(line + "\n")


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        got = predicate()
        if got:
            return got
        time.sleep(interval)
    raise AssertionError(f"condition not met within {timeout}s")


def fake_journalctls(tmp_path: Path) -> list[int]:
    """PIDs of fake journalctl processes started from `tmp_path` that are still running."""
    out = []
    marker = (str(tmp_path) + "/journalctl").encode()
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as f:
                if marker in f.read():
                    out.append(int(d))
        except OSError:
            continue
    return out
