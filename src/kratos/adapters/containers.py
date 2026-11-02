"""Docker and Podman containers on a Linux machine -- the container read (D.5).

Read-only. What a careful admin would look at, gathered WITHOUT the ``docker``
group and without root-equivalent access for Kratos's own login:

- the container engine's own view (agent only, as root): ``GET`` requests to a
  CLOSED list of API paths over the engine's local Unix socket -- ``/version``,
  ``/info``, ``/containers/json?all=1``, ``/containers/<64-hex id>/json`` and
  ``/networks`` -- for Docker and for Podman's Docker-compatible API (rootful,
  and each rootless user's socket). No other method, path, exec, log stream or
  image pull exists in this file. Each response is capped and its JSON depth
  checked; the agent reduces each inspect document to the facts Kratos judges
  (``distill_container``) before anything leaves the machine -- environment
  variables leave as KEYS only, never values;
- what ``/proc`` and the cgroups show (both transports): which processes belong
  to which container, their user, effective capabilities, and the sockets
  listening inside each container's network namespace. Over SSH this runs as
  the SSH user; a field that login can't read is reported as a gap;
- the firewall rules (``iptables-save``, ``ip6tables-save``, ``nft -j list
  ruleset`` -- fixed, read-only commands): as root on the agent; over SSH only
  through ``sudo -n`` pinned to exactly those argument lists, when the person
  has allowed them (the setup checklist explains the lines);
- each running image's package database, read through ``/proc/<pid>/root`` of
  one of its processes with every path component opened without following a
  link (agent only), printed as the SAME records the host package read prints
  (``adapters/packages.py``), one block per image;
- a container's own log file (Docker ``json-file``, Podman ``k8s-file``), one
  bounded chunk from a remembered position (agent only).

Two producers print the same tab-separated records -- ``build_script()`` (POSIX
sh + awk, for SSH) and ``inventory_output()`` (stdlib Python, for the agent) --
and one parser (``parse_output``) reads both. Nothing is judged here (judging is
``kratos.containers``), and nothing is written on the machine.

Standard library only (Python 3.8): this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import errno
import http.client
import json
import os
import re
import shlex
import socket
import stat
import time
from typing import Any, Callable

try:  # in the agent bundle: sibling modules
    from . import packages as _packages  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- whichever layout is running
    try:
        from kratos.adapters import packages as _packages
    except ImportError:  # run directly
        import packages as _packages  # type: ignore[no-redef]

# --------------------------------------------------------------------------- caps
MAX_CONTAINERS = 200
MAX_IMAGES = 50                       # distinct running images whose packages one collection reads
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # one API response
MAX_TOTAL_BYTES = 20 * 1024 * 1024    # every API response of one read together
MAX_JSON_DEPTH = 32
API_TIMEOUT_SECONDS = 5.0
DEFAULT_BUDGET_SECONDS = 40
PACKAGES_BUDGET_SECONDS = 120
MAX_PROCS = 20000
MAX_LISTENERS = 2000
MAX_MOUNTS = 64
MAX_PORTS = 128
MAX_NETWORKS = 32
MAX_LABELS = 64
MAX_ENV_KEYS = 128
MAX_TEXT = 256                        # one machine-text field (name, label value, path)
FW_OUTPUT_CAP = 2 * 1024 * 1024       # one firewall listing
OUTPUT_CAP_BYTES = 6 * 1024 * 1024
PACKAGES_OUTPUT_CAP = 24 * 1024 * 1024
PKGDB_MAX_BYTES = 64 * 1024 * 1024    # one package database file inside an image
MAX_STATUS_D_FILES = 4000             # distroless images: /var/lib/dpkg/status.d/*
LOG_CHUNK_BYTES = 512 * 1024          # one container-log read
LOG_INITIAL_TAIL_BYTES = 1024 * 1024  # a container's log is first read from this far before its end
LOG_LINE_MAX = 16 * 1024
LOG_OUTPUT_CAP = LOG_CHUNK_BYTES * 2 + 65536

AGENT_FIX = "read this machine through its sub-agent (it reads as root)"

ENGINES = ("docker", "podman", "podman-rootless")
# The engine sockets tried, in order (rootless Podman: each /run/user/<uid>/podman/podman.sock).
DOCKER_SOCKETS = ("/run/docker.sock", "/var/run/docker.sock")
PODMAN_SOCKETS = ("/run/podman/podman.sock",)
RUN_USER = "/run/user"

ID_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# The closed API path list. Nothing else is ever requested.
FIXED_API_PATHS = ("/version", "/info", "/containers/json?all=1", "/networks")
_INSPECT_PATH_RE = re.compile(r"^/containers/([0-9a-f]{64})/json$")
# A process's cgroup line naming a container: Docker (systemd driver: docker-<id>.scope,
# cgroupfs driver: /docker/<id>) and Podman (libpod-<id>.scope; never libpod-conmon-).
_CGROUP_RE = re.compile(r"(docker-|/docker/|libpod-)([0-9a-f]{64})(?:\.scope)?(?:/|$)")
_CAP_RE = re.compile(r"^[0-9a-f]{1,16}$")
_USER_SLICE_RE = re.compile(r"/user@(\d{1,10})\.service/")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_FW_KINDS = ("iptables", "ip6tables", "nft")
# Labels whose values are kept (Compose and image metadata); every other label is sent as a key only.
_LABEL_VALUE_PREFIXES = ("com.docker.compose.", "org.opencontainers.image.", "io.podman.compose.")
_LABEL_VALUE_KEYS = ("maintainer",)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ApiError(Exception):
    """An API call that did not return usable JSON. `kind`: refused | absent | denied |
    timeout | too_big | too_deep | bad_json | status | error."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


def allowed_api_path(path: str) -> bool:
    """True only for the closed list of read-only paths (the container id must be 64 hex)."""
    return isinstance(path, str) and (path in FIXED_API_PATHS or bool(_INSPECT_PATH_RE.match(path)))


def _text(value: Any, cap: int = MAX_TEXT) -> str:
    """Machine text as one safe line: control characters (tabs, newlines) dropped, capped."""
    return _CTRL_RE.sub(" ", str(value if value is not None else ""))[:cap]


# --------------------------------------------------------------------------- engine sockets
def socket_path_ok(candidate: str, run_root: str = "/run") -> tuple[str | None, str | None]:
    """(the real socket path, None) when `candidate` is a Unix socket inside `run_root`
    whose last component is not a symbolic link; (None, why) otherwise. The directory
    part may be a link (/var/run -> /run); the socket itself may not, and may not
    resolve outside `run_root`. `why` starts with "absent" when there is no socket."""
    parent = os.path.realpath(os.path.dirname(candidate))
    real = os.path.join(parent, os.path.basename(candidate))
    root = os.path.realpath(run_root).rstrip("/") + "/"
    if not real.startswith(root):
        return None, f"refused: {candidate} is outside {run_root}"
    try:
        st = os.lstat(real)
    except FileNotFoundError:
        return None, "absent"
    except OSError as e:
        return None, f"refused: {candidate}: {e.strerror or e}"
    if stat.S_ISLNK(st.st_mode):
        return None, f"refused: {candidate} is a symbolic link"
    if not stat.S_ISSOCK(st.st_mode):
        return None, f"refused: {candidate} is not a socket"
    return real, None


def engine_sockets(run_root: str = "/run") -> list[tuple[str, str, str | None, str | None]]:
    """[(engine, candidate path, real path or None, problem or None)] for every candidate
    that exists (an absent one is left out). Rootless Podman sockets must belong to their
    user (or root)."""
    out: list[tuple[str, str, str | None, str | None]] = []
    seen: set[str] = set()

    def add(engine: str, cand: str, owner: int | None = None) -> None:
        real, why = socket_path_ok(cand, run_root)
        if why == "absent":
            return
        if real is not None:
            if real in seen:
                return
            seen.add(real)
            if owner is not None:
                try:
                    uid = os.lstat(real).st_uid
                except OSError:
                    uid = -1
                if uid not in (0, owner):
                    out.append((engine, cand, None, f"refused: {cand} is not owned by its user"))
                    return
        out.append((engine, cand, real, why))

    root = run_root.rstrip("/")
    for c in DOCKER_SOCKETS:
        if c.startswith("/run/"):
            add("docker", root + c[len("/run"):])
        elif run_root == "/run":                     # /var/run/docker.sock (a test root has no /var/run)
            add("docker", c)
    for c in PODMAN_SOCKETS:
        add("podman", root + c[len("/run"):])
    users = os.path.join(root, "user")
    try:
        uids = sorted((int(n) for n in os.listdir(users) if n.isdigit()))
    except OSError:
        uids = []
    for uid in uids[:256]:
        add(f"podman-rootless:{uid}", os.path.join(users, str(uid), "podman", "podman.sock"), owner=uid)
    return out


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._unix_path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self._unix_path)
        except BaseException:
            s.close()
            raise
        self.sock = s


def _depth_ok(data: Any, limit: int = MAX_JSON_DEPTH) -> bool:
    stack = [(data, 1)]
    while stack:
        node, d = stack.pop()
        if d > limit:
            return False
        if isinstance(node, dict):
            stack.extend((v, d + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, d + 1) for v in node)
    return True


class ApiClient:
    """GET-only client for one engine socket, with a per-response and a shared total cap."""

    connection_class = _UnixHTTPConnection

    def __init__(self, socket_path: str, budget: list[int] | None = None, timeout: float = API_TIMEOUT_SECONDS):
        self.socket_path = socket_path
        self.timeout = timeout
        self.budget = budget if budget is not None else [MAX_TOTAL_BYTES]

    def get(self, path: str) -> Any:
        if not allowed_api_path(path):
            raise ApiError("refused", f"{path!r} is not on the read-only path list")
        if self.budget[0] <= 0:
            raise ApiError("too_big", "the read's total response cap was reached")
        cap = min(MAX_RESPONSE_BYTES, self.budget[0])
        conn = self.connection_class(self.socket_path, self.timeout)
        try:
            conn.request("GET", path, headers={"Host": "localhost", "Accept": "application/json"})
            resp = conn.getresponse()
            body = resp.read(cap + 1)
            status = resp.status
        except socket.timeout:
            raise ApiError("timeout", f"no answer within {self.timeout:g}s") from None
        except PermissionError:
            raise ApiError("denied", "permission denied") from None
        except FileNotFoundError:
            raise ApiError("absent", "the socket is gone") from None
        except ConnectionRefusedError:
            raise ApiError("absent", "nothing is listening on the socket (the engine is stopped)") from None
        except (OSError, http.client.HTTPException) as e:
            raise ApiError("error", f"{type(e).__name__}: {e}") from None
        finally:
            conn.close()
        self.budget[0] -= len(body)
        if len(body) > cap:
            raise ApiError("too_big", f"the answer to {path} is over {cap // 1024} KiB")
        if status != 200:
            raise ApiError("status", f"HTTP {status} for {path}")
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except RecursionError:
            raise ApiError("too_deep", f"the answer to {path} is nested too deeply") from None
        except ValueError:
            raise ApiError("bad_json", f"the answer to {path} is not JSON") from None
        if not _depth_ok(data):
            raise ApiError("too_deep", f"the answer to {path} is nested deeper than {MAX_JSON_DEPTH}")
        return data


# --------------------------------------------------------------------------- distillers
def _strs(value: Any, cap: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_text(v) for v in value[:cap] if isinstance(v, (str, int))]


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def distill_version(raw: Any) -> dict[str, Any]:
    raw = _dict(raw)
    comps = [_text(c.get("Name"), 64) for c in raw.get("Components") or [] if isinstance(c, dict)][:8]
    return {"version": _text(raw.get("Version"), 64), "api_version": _text(raw.get("ApiVersion"), 16),
            "components": comps, "os": _text(raw.get("Os"), 32)}


def distill_info(raw: Any) -> dict[str, Any]:
    raw = _dict(raw)
    fw = _dict(raw.get("FirewallBackend"))
    fw_info = {}
    for pair in fw.get("Info") or []:
        if isinstance(pair, list) and len(pair) == 2:
            fw_info[_text(pair[0], 64)] = _text(pair[1], 128)
    return {
        "server_version": _text(raw.get("ServerVersion"), 64),
        "firewall_backend": _text(fw.get("Driver"), 32),
        "firewall_info": dict(list(fw_info.items())[:16]),
        "security_options": _strs(raw.get("SecurityOptions"), 16),
        "logging_driver": _text(raw.get("LoggingDriver"), 32),
        "root_dir": _text(raw.get("DockerRootDir"), MAX_TEXT),
        "storage_driver": _text(raw.get("Driver"), 32),
        "cgroup_version": _text(raw.get("CgroupVersion"), 8),
        "containers": raw.get("Containers") if isinstance(raw.get("Containers"), int) else None,
        "running": raw.get("ContainersRunning") if isinstance(raw.get("ContainersRunning"), int) else None,
    }


def distill_network(raw: Any) -> dict[str, Any] | None:
    raw = _dict(raw)
    nid = str(raw.get("Id") or "")
    if not ID_RE.match(nid):
        return None
    opts = {k: _text(v, 64) for k, v in _dict(raw.get("Options")).items()
            if isinstance(k, str) and k.startswith("com.docker.network.")}
    subnets = [_text(c.get("Subnet"), 64) for c in (_dict(raw.get("IPAM")).get("Config") or [])
               if isinstance(c, dict) and c.get("Subnet")][:8]
    return {"id": nid, "name": _text(raw.get("Name"), 128), "driver": _text(raw.get("Driver"), 32),
            "ipv6": bool(raw.get("EnableIPv6")), "internal": bool(raw.get("Internal")),
            "options": dict(list(opts.items())[:16]), "subnets": subnets}


def _ports(ns: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key, binds in _dict(ns.get("Ports")).items():
        cport, _, proto = str(key).partition("/")
        if not cport.isdigit() or proto not in ("tcp", "udp", "sctp"):
            continue
        for b in binds or []:
            if not isinstance(b, dict) or not str(b.get("HostPort") or "").isdigit():
                continue
            out.append({"proto": proto, "container_port": int(cport), "host_ip": _text(b.get("HostIp"), 64),
                        "host_port": int(b["HostPort"])})
            if len(out) >= MAX_PORTS:
                return out
    return out


def _labels(raw: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in sorted(_dict(raw).items())[:MAX_LABELS]:
        key = _text(k, 128)
        keep = key.startswith(_LABEL_VALUE_PREFIXES) or key in _LABEL_VALUE_KEYS
        out[key] = _text(v) if keep else ""
    return out


def distill_container(raw: Any, engine: str) -> dict[str, Any] | None:
    """The facts Kratos judges, from one inspect document. Environment values never
    leave the machine (keys only); label values only for Compose/image metadata."""
    raw = _dict(raw)
    cid = str(raw.get("Id") or "")
    if not ID_RE.match(cid):
        return None
    hc, cfg, st, ns = (_dict(raw.get(k)) for k in ("HostConfig", "Config", "State", "NetworkSettings"))
    mounts = []
    for m in (raw.get("Mounts") or [])[:MAX_MOUNTS]:
        if isinstance(m, dict):
            mounts.append({"type": _text(m.get("Type"), 16), "source": _text(m.get("Source")),
                           "destination": _text(m.get("Destination")), "rw": bool(m.get("RW"))})
    nets = []
    for name, n in list(_dict(ns.get("Networks")).items())[:MAX_NETWORKS]:
        n = _dict(n)
        nets.append({"name": _text(name, 128), "id": _text(n.get("NetworkID"), 64), "ip": _text(n.get("IPAddress"), 64),
                     "ip6": _text(n.get("GlobalIPv6Address"), 64), "gateway": _text(n.get("Gateway"), 64)})
    env_keys = []
    for e in (cfg.get("Env") or [])[:MAX_ENV_KEYS]:
        if isinstance(e, str):
            env_keys.append(_text(e.split("=", 1)[0], 128))   # the key only -- never the value
    image_id = str(raw.get("Image") or "")
    digest = str(_dict(raw.get("ImageManifestDescriptor")).get("digest") or "")
    pid = st.get("Pid")
    return {
        "id": cid, "engine": engine, "name": _text(str(raw.get("Name") or "").lstrip("/"), 128),
        "image": _text(cfg.get("Image"), MAX_TEXT),
        "image_id": image_id if _SHA256_RE.match(image_id) else "",
        "image_digest": digest if _SHA256_RE.match(digest) else "",
        "state": _text(st.get("Status"), 16), "running": bool(st.get("Running")),
        "pid": pid if isinstance(pid, int) and pid > 0 else None,
        "started_at": _text(st.get("StartedAt"), 40), "created": _text(raw.get("Created"), 40),
        "user": _text(cfg.get("User"), 64),
        "privileged": bool(hc.get("Privileged")),
        "cap_add": _strs(hc.get("CapAdd"), 64), "cap_drop": _strs(hc.get("CapDrop"), 64),
        "security_opt": _strs(hc.get("SecurityOpt"), 16),
        "apparmor": _text(raw.get("AppArmorProfile"), 64),
        "network_mode": _text(hc.get("NetworkMode"), 128), "pid_mode": _text(hc.get("PidMode"), 64),
        "ipc_mode": _text(hc.get("IpcMode"), 64), "uts_mode": _text(hc.get("UTSMode"), 64),
        "userns_mode": _text(hc.get("UsernsMode"), 64),
        "readonly_rootfs": bool(hc.get("ReadonlyRootfs")),
        "devices": len(hc.get("Devices") or []) if isinstance(hc.get("Devices"), list) else 0,
        "mounts": mounts, "ports": _ports(ns), "networks": nets, "labels": _labels(cfg.get("Labels")),
        "env_keys": env_keys,
        "log_driver": _text(_dict(hc.get("LogConfig")).get("Type"), 32),
        "restart": _text(_dict(hc.get("RestartPolicy")).get("Name"), 32),
        "health": _text(_dict(st.get("Health")).get("Status"), 16),
    }


def _engine_kind(version: dict[str, Any], engine: str) -> str:
    if engine.startswith("podman"):
        return engine
    if any("podman" in c.lower() for c in version.get("components") or []):
        return "podman"       # podman-docker's compatibility socket at /run/docker.sock
    return engine


def _record(tag: str, *fields: Any) -> str:
    return "\t".join([tag, *(_text(f, 4096) if not isinstance(f, (int, float)) else str(f) for f in fields)])


def _json_record(tag: str, engine: str, obj: Any) -> str:
    return f"{tag}\t{engine}\t{json.dumps(obj, ensure_ascii=True, separators=(',', ':'), sort_keys=True)}"


def api_records(deadline: float, run_root: str = "/run",
                client_factory: Callable[[str, list[int]], ApiClient] | None = None) -> list[str]:
    """Every engine socket's records: E (engine status), V, I, N, C, and T/G when a cap
    or a failure cut something short."""
    lines: list[str] = []
    budget = [MAX_TOTAL_BYTES]
    factory = client_factory or (lambda path, b: ApiClient(path, b))
    total = 0
    for engine, cand, real, problem in engine_sockets(run_root):
        if real is None:
            lines.append(_record("E", engine, cand, "refused", problem or "refused"))
            continue
        client = factory(real, budget)
        try:
            version = distill_version(client.get("/version"))
        except ApiError as e:
            lines.append(_record("E", engine, cand, e.kind, e.detail))
            continue
        kind = _engine_kind(version, engine)
        lines.append(_record("E", kind, cand, "ok", version.get("version") or ""))
        lines.append(_json_record("V", kind, version))
        try:
            lines.append(_json_record("I", kind, distill_info(client.get("/info"))))
            nets = client.get("/networks")
            for n in (nets if isinstance(nets, list) else [])[:MAX_NETWORKS * 4]:
                d = distill_network(n)
                if d:
                    lines.append(_json_record("N", kind, d))
            listing = client.get("/containers/json?all=1")
        except ApiError as e:
            lines.append(_record("G", "engine", f"{kind}: {e.kind}: {e.detail}"))
            continue
        ids = [str(c.get("Id")) for c in (listing if isinstance(listing, list) else [])
               if isinstance(c, dict) and ID_RE.match(str(c.get("Id") or ""))]
        for cid in ids:
            if total >= MAX_CONTAINERS:
                lines.append(_record("T", "containers", len(ids)))
                break
            if time.monotonic() > deadline:
                lines.append(_record("G", "engine", f"{kind}: out of time after {total} container(s)"))
                break
            try:
                d = distill_container(client.get(f"/containers/{cid}/json"), kind)
            except ApiError as e:
                lines.append(_record("G", "container", f"{kind}: {cid[:12]}: {e.kind}"))
                continue
            if d:
                lines.append(_json_record("C", kind, d))
                total += 1
    return lines


# --------------------------------------------------------------------------- /proc collector
def _read_small(path: str, cap: int = 65536) -> str | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(cap).decode("utf-8", "replace")
    except OSError:
        return None


def _status_fields(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        if k in ("Uid", "CapEff", "PPid"):
            out[k] = v.strip()
    return out


def _listening(table: str, proto: str) -> list[str]:
    out = []
    for line in table.splitlines()[1:]:
        f = line.split()
        if len(f) < 4:
            continue
        state, rem = f[3].upper(), f[2]
        if (proto.startswith("tcp") and state == "0A") or (proto.startswith("udp") and state == "07"
                                                           and rem.rsplit(":", 1)[-1] == "0000"):
            out.append(f[1])
    return out


def hidepid(root: str = "") -> str:
    """The /proc mount's hidepid setting ("0" when none is set)."""
    text = _read_small(f"{root}/proc/self/mountinfo", 262144) or ""
    for line in text.splitlines():
        if " - proc " in line:
            m = re.search(r"hidepid=([a-z0-9]+)", line)
            return m.group(1) if m else "0"
    return "0"


def proc_records(root: str = "", max_procs: int = MAX_PROCS) -> list[str]:
    """P (process in a container), L (a listening socket in its network namespace) and
    PG (a process whose details this reader could not see) records from /proc."""
    lines: list[str] = []
    try:
        pids = sorted(int(n) for n in os.listdir(f"{root}/proc") if n.isdigit())
    except OSError:
        return [_record("G", "proc", "/proc could not be listed")]
    first_pid: dict[str, int] = {}
    for n, pid in enumerate(pids):
        if n >= max_procs:
            lines.append(_record("T", "processes", len(pids)))
            break
        cg = _read_small(f"{root}/proc/{pid}/cgroup", 8192)
        if not cg:
            continue
        m = _CGROUP_RE.search(cg)
        if not m:
            continue
        engine = "podman" if m.group(1) == "libpod-" else "docker"
        cid = m.group(2)
        status = _read_small(f"{root}/proc/{pid}/status")
        if status is None:
            lines.append(_record("PG", pid, cid, "status"))
            continue
        sf = _status_fields(status)
        uid = (sf.get("Uid") or "").split()
        cap = sf.get("CapEff", "")
        comm = (_read_small(f"{root}/proc/{pid}/comm", 64) or "").strip()
        um = _USER_SLICE_RE.search(cg) if engine == "podman" else None
        lines.append(_record("P", pid, engine, cid, uid[1] if len(uid) > 1 else "", cap if _CAP_RE.match(cap) else "",
                             sf.get("PPid", ""), comm, um.group(1) if um else ""))
        first_pid.setdefault(cid, pid)
    listeners = 0
    for cid, pid in sorted(first_pid.items()):
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            table = _read_small(f"{root}/proc/{pid}/net/{proto}", 4 * 1024 * 1024)
            if table is None:
                lines.append(_record("PG", pid, cid, f"net/{proto}"))
                continue
            for addr in _listening(table, proto):
                if listeners >= MAX_LISTENERS:
                    break
                lines.append(_record("L", cid, proto, addr))
                listeners += 1
    return lines


def route_records(root: str = "") -> list[str]:
    """RT records: the interfaces holding a default route (where internet traffic arrives)."""
    out: list[str] = []
    for line in (_read_small(f"{root}/proc/net/route", 262144) or "").splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000" and _IFACE_RE.match(f[0]):
            out.append(_record("RT", 4, f[0]))
    for line in (_read_small(f"{root}/proc/net/ipv6_route", 1024 * 1024) or "").splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo" and _IFACE_RE.match(f[9]):
            out.append(_record("RT", 6, f[9]))
    return sorted(set(out))


def firewall_records(run: Callable[[list[str], float, int], dict[str, Any]]) -> list[str]:
    """FWS / FWL records from the three read-only listings, run as root by the agent."""
    out: list[str] = []
    for kind, argv in (("iptables", ["iptables-save"]), ("ip6tables", ["ip6tables-save"]),
                       ("nft", ["nft", "-j", "list", "ruleset"])):
        try:
            res = run(argv, 20, FW_OUTPUT_CAP)
        except Exception as e:  # noqa: BLE001 -- ProbeMissing / ProbeTimeout from the agent
            name = type(e).__name__
            out.append(_record("FWS", kind, "missing" if "Missing" in name else "error", name))
            continue
        if res.get("returncode") not in (0, None):
            out.append(_record("FWS", kind, "error", _text(res.get("stderr"), 200)))
            continue
        out.append(_record("FWS", kind, "truncated" if res.get("truncated") else "ok", ""))
        for line in str(res.get("stdout") or "").splitlines():
            out.append("FWL\t" + kind + "\t" + line.replace("\t", " "))
    return out


def inventory_output(*, run: Callable[[list[str], float, int], dict[str, Any]], deadline: float,
                     root: str = "", run_root: str = "/run",
                     client_factory: Callable[[str, list[int]], ApiClient] | None = None) -> dict[str, Any]:
    """The agent's container read (as root): engines' API, /proc, routes, firewall."""
    lines = ["CONTINV\t1", _record("M", "reader_uid", os.geteuid() if hasattr(os, "geteuid") else -1),
             _record("M", "hidepid", hidepid(root)), _record("M", "via", "agent")]
    lines += api_records(deadline, run_root, client_factory)
    lines += proc_records(root)
    lines += route_records(root)
    lines += firewall_records(run)
    lines.append("END")
    text = "\n".join(lines) + "\n"
    truncated = len(text.encode()) > OUTPUT_CAP_BYTES
    if truncated:
        text = text.encode()[:OUTPUT_CAP_BYTES].decode("utf-8", "ignore").rsplit("\n", 1)[0] + "\n"
    return {"returncode": 0, "stdout": text, "stderr": "", "truncated": truncated}


# --------------------------------------------------------------------------- SSH script
# The same records, as the SSH user (no sudo except the three firewall listings, and only
# when the person allowed exactly those commands with `sudo -n`). The engine API is NOT
# read over SSH: reaching it needs root-equivalent access, which Kratos never asks for.
_SH = r"""
LC_ALL=C; export LC_ALL
printf 'CONTINV\t1\n'
printf 'M\treader_uid\t%s\n' "$(id -u 2>/dev/null)"
printf 'M\tvia\tssh\n'
_hp=$(grep ' - proc ' @ROOT@/proc/self/mountinfo 2>/dev/null | head -n 1 | grep -o 'hidepid=[a-z0-9]*' | cut -d= -f2)
printf 'M\thidepid\t%s\n' "${_hp:-0}"
for _s in @ROOT@/run/docker.sock @ROOT@/run/podman/podman.sock @ROOT@/run/user/*/podman/podman.sock; do
  [ -S "$_s" ] || continue
  case "$_s" in */podman/podman.sock) case "$_s" in */user/*) _e=podman-rootless ;; *) _e=podman ;; esac ;; *) _e=docker ;; esac
  printf 'E\t%s\t%s\tnot_read\tthe engine API is not read over SSH (it needs root-equivalent access)\n' "$_e" "${_s#@ROOT@}"
done
_cg=$(grep -E '(docker-|/docker/|libpod-)[0-9a-f]{64}' @ROOT@/proc/[0-9]*/cgroup 2>/dev/null | awk @AWKCG@)
_n=0
printf '%s\n' "$_cg" | while IFS="$(printf '\t')" read -r _pid _eng _cid _own; do
  [ -n "$_pid" ] || continue
  _n=$((_n + 1))
  [ "$_n" -gt @MAXPROCS@ ] && { printf 'T\tprocesses\t%s\n' "$_n"; break; }
  _st=@ROOT@/proc/$_pid/status
  if [ ! -r "$_st" ]; then printf 'PG\t%s\t%s\tstatus\n' "$_pid" "$_cid"; continue; fi
  _f=$(awk -F'\t' '$1=="Uid:"{u=$3} $1=="CapEff:"{c=$2} $1=="PPid:"{p=$2} END{print u "\t" c "\t" p}' "$_st" 2>/dev/null)
  _comm=$(tr -d '\t\r\n' < @ROOT@/proc/$_pid/comm 2>/dev/null | cut -c1-64)
  printf 'P\t%s\t%s\t%s\t%s\t%s\t%s\n' "$_pid" "$_eng" "$_cid" "$_f" "$_comm" "$_own"
done
printf '%s\n' "$_cg" | awk -F'\t' 'NF >= 3 && !seen[$3]++ { print $1 "\t" $3 }' | while IFS="$(printf '\t')" read -r _pid _cid; do
  for _p in tcp tcp6 udp udp6; do
    _t=@ROOT@/proc/$_pid/net/$_p
    if [ ! -r "$_t" ]; then printf 'PG\t%s\t%s\tnet/%s\n' "$_pid" "$_cid" "$_p"; continue; fi
    awk -v c="$_cid" -v p="$_p" 'NR > 1 { st = toupper($4); r = $3; sub(/.*:/, "", r)
      if ((p ~ /^tcp/ && st == "0A") || (p ~ /^udp/ && st == "07" && r == "0000")) print "L\t" c "\t" p "\t" $2 }' "$_t" 2>/dev/null
  done
done | head -n @MAXLISTEN@
awk 'NR > 1 && $2 == "00000000" && $8 == "00000000" { print "RT\t4\t" $1 }' @ROOT@/proc/net/route 2>/dev/null | sort -u
awk '$1 == "00000000000000000000000000000000" && $2 == "00" && $10 != "lo" { print "RT\t6\t" $10 }' @ROOT@/proc/net/ipv6_route 2>/dev/null | sort -u
kr_fw() {
  _k=$1; shift; _b=""
  for _d in /usr/sbin /sbin; do [ -x "$_d/$1" ] && { _b="$_d/$1"; break; }; done
  shift
  if [ -z "$_b" ]; then printf 'FWS\t%s\tmissing\t\n' "$_k"; return; fi
  if _o=$(sudo -n "$_b" "$@" 2>/dev/null); then
    printf 'FWS\t%s\tok\t\n' "$_k"
    printf '%s\n' "$_o" | head -c @FWCAP@ | tr '\t' ' ' | awk -v k="$_k" '{ print "FWL\t" k "\t" $0 }'
  else
    printf 'FWS\t%s\tdenied\tsudo -n %s is not allowed for this login\n' "$_k" "$_b"
  fi
}
@FWCALLS@
printf 'END\n'
"""

# Field 1 is "<path>/proc/<pid>/cgroup:<line>"; prints pid, engine, container id (first match per pid).
AWK_CG = r"""
{
  line = $0
  pid = line; sub(/\/cgroup:.*/, "", pid); sub(/.*\/proc\//, "", pid)
  if (pid !~ /^[0-9]+$/ || seen[pid]++) next
  if (match(line, /libpod-[0-9a-f]+/)) { id = substr(line, RSTART + 7, RLENGTH - 7); eng = "podman" }
  else if (match(line, /docker-[0-9a-f]+/)) { id = substr(line, RSTART + 7, RLENGTH - 7); eng = "docker" }
  else if (match(line, /\/docker\/[0-9a-f]+/)) { id = substr(line, RSTART + 8, RLENGTH - 8); eng = "docker" }
  else next
  if (length(id) != 64) { seen[pid] = 0; next }
  owner = ""
  if (eng == "podman" && match(line, /\/user@[0-9]+\.service\//)) owner = substr(line, RSTART + 6, RLENGTH - 15)
  print pid "\t" eng "\t" id "\t" owner
}
"""

# The firewall listings over SSH: exactly these argument lists (the setup checklist's
# sudoers lines pin the same ones).
SUDO_FIREWALL_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("iptables-save", ()), ("ip6tables-save", ()), ("nft", ("-j", "list", "ruleset")),
)


def build_script(root: str = "", firewall: bool = True) -> str:
    """The fixed SSH read. `root` is "" in production; tests point it at a fake tree
    (and switch the sudo firewall reads off)."""
    q = shlex.quote
    calls = "\n".join(f"kr_fw {kind} {q(binary)} {' '.join(q(a) for a in args)}".rstrip()
                      for kind, (binary, args) in zip(_FW_KINDS, SUDO_FIREWALL_COMMANDS)) if firewall else ""
    return (_SH.replace("@AWKCG@", q(AWK_CG))
            .replace("@MAXPROCS@", str(MAX_PROCS)).replace("@MAXLISTEN@", str(MAX_LISTENERS))
            .replace("@FWCAP@", str(FW_OUTPUT_CAP)).replace("@FWCALLS@", calls)
            .replace("@ROOT@", q(root) if root else ""))


# --------------------------------------------------------------------------- parser
def _json_field(raw: str) -> Any:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return data if _depth_ok(data) else None


def parse_output(stdout: str) -> dict[str, Any]:
    """The records as one dict:

    {header, complete, via, reader_uid, hidepid, engines: [{engine, socket, state, detail}],
     versions: {engine: {...}}, infos: {engine: {...}}, networks: {id: {...}},
     containers: {id: {...}}, procs: {pid: {...}}, proc_gaps: [(pid, cid, what)],
     listeners: [{container, proto, local}], routes: {"4": [...], "6": [...]},
     firewall: {kind: {status, detail, text}}, gaps: [...], truncated: {what: count}}

    Nothing here is trusted: container records are re-checked for shape, and a record
    that doesn't parse is dropped and counted."""
    out: dict[str, Any] = {
        "header": False, "complete": False, "via": "", "reader_uid": None, "hidepid": "0",
        "engines": [], "versions": {}, "infos": {}, "networks": {}, "containers": {}, "procs": {},
        "proc_gaps": [], "listeners": [], "routes": {"4": [], "6": []}, "firewall": {}, "gaps": [],
        "truncated": {}, "dropped": 0,
    }
    fw_lines: dict[str, list[str]] = {}
    for line in (stdout or "").splitlines():
        f = line.split("\t")
        tag = f[0]
        if tag == "CONTINV":
            out["header"] = True
        elif tag == "M" and len(f) >= 3:
            if f[1] == "reader_uid":
                out["reader_uid"] = int(f[2]) if f[2].lstrip("-").isdigit() else None
            elif f[1] == "hidepid":
                out["hidepid"] = f[2][:8]
            elif f[1] == "via":
                out["via"] = f[2][:16]
        elif tag == "E" and len(f) >= 5:
            out["engines"].append({"engine": f[1][:40], "socket": f[2][:MAX_TEXT], "state": f[3][:16],
                                   "detail": f[4][:300]})
        elif tag in ("V", "I", "N", "C") and len(f) >= 3:
            data = _json_field("\t".join(f[2:]))
            if not isinstance(data, dict):
                out["dropped"] += 1
                continue
            if tag == "V":
                out["versions"][f[1][:40]] = data
            elif tag == "I":
                out["infos"][f[1][:40]] = data
            elif tag == "N" and ID_RE.match(str(data.get("id") or "")):
                out["networks"][data["id"]] = data
            elif tag == "C" and ID_RE.match(str(data.get("id") or "")):
                data["engine"] = f[1][:40]
                out["containers"][data["id"]] = data
            else:
                out["dropped"] += 1
        elif tag == "P" and len(f) >= 7:
            pid, engine, cid = f[1], f[2], f[3]
            if not pid.isdigit() or not ID_RE.match(cid):
                out["dropped"] += 1
                continue
            cap = f[5].strip()
            out["procs"][int(pid)] = {"engine": engine[:16], "container": cid,
                                      "uid": int(f[4]) if f[4].strip().isdigit() else None,
                                      "capeff": cap if _CAP_RE.match(cap) else None,
                                      "ppid": int(f[6]) if f[6].strip().isdigit() else None,
                                      "comm": _text(f[7] if len(f) > 7 else "", 64),
                                      "rootless_owner": int(f[8]) if len(f) > 8 and f[8].strip().isdigit() else None}
        elif tag == "PG" and len(f) >= 4:
            if f[1].isdigit() and ID_RE.match(f[2]):
                out["proc_gaps"].append((int(f[1]), f[2], f[3][:16]))
        elif tag == "L" and len(f) >= 4:
            if ID_RE.match(f[1]) and f[2] in ("tcp", "tcp6", "udp", "udp6") and re.match(r"^[0-9A-Fa-f]+:[0-9A-Fa-f]{4}$", f[3]):
                out["listeners"].append({"container": f[1], "proto": f[2], "local": f[3]})
        elif tag == "RT" and len(f) >= 3:
            if f[1] in ("4", "6") and _IFACE_RE.match(f[2]) and f[2] not in out["routes"][f[1]]:
                out["routes"][f[1]].append(f[2])
        elif tag == "FWS" and len(f) >= 3:
            if f[1] in _FW_KINDS:
                out["firewall"][f[1]] = {"status": f[2][:16], "detail": (f[3] if len(f) > 3 else "")[:300], "text": ""}
        elif tag == "FWL" and len(f) >= 3:
            if f[1] in _FW_KINDS:
                fw_lines.setdefault(f[1], []).append("\t".join(f[2:]))
        elif tag == "G" and len(f) >= 3:
            out["gaps"].append(f"{f[1][:32]}: {f[2][:300]}")
        elif tag == "T" and len(f) >= 3:
            out["truncated"][f[1][:32]] = int(f[2]) if f[2].isdigit() else 0
        elif tag == "END":
            out["complete"] = True
    for kind, lines in fw_lines.items():
        if kind in out["firewall"]:
            out["firewall"][kind]["text"] = "\n".join(lines)
    return out


# --------------------------------------------------------------------------- packages inside images
_ROOT_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW_DIR = _ROOT_DIR_FLAGS | getattr(os, "O_NOFOLLOW", 0)
_NOFOLLOW_FILE = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)


class RootRefused(Exception):
    """A file inside a container's root that was not read. `status`: missing | symlink |
    not_regular | unreadable | too_big."""

    def __init__(self, status: str, detail: str = ""):
        super().__init__(f"{status}: {detail}" if detail else status)
        self.status = status


def open_root(pid: int, proc: str = "/proc") -> int:
    """A directory descriptor for a process's root (the kernel's own link, /proc/<pid>/root)."""
    if not isinstance(pid, int) or pid <= 0:
        raise RootRefused("missing", "no process")
    try:
        return os.open(f"{proc}/{pid}/root", _ROOT_DIR_FLAGS)
    except OSError as e:
        raise RootRefused("missing" if e.errno == errno.ENOENT else "unreadable", e.strerror or str(e)) from None


def _walk_in_root(root_fd: int, rel: str) -> tuple[int, str]:
    parts = [p for p in rel.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise RootRefused("missing", "not a plain path")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, _NOFOLLOW_DIR, dir_fd=fd)
            except OSError as e:
                raise _root_refusal(e) from None
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def _root_refusal(e: OSError) -> RootRefused:
    if e.errno in (errno.ELOOP, errno.ENOTDIR):
        return RootRefused("symlink", "a symbolic link (not followed out of the container's root)")
    if e.errno == errno.ENOENT:
        return RootRefused("missing")
    return RootRefused("unreadable", e.strerror or str(e))


def open_in_root(root_fd: int, rel: str) -> tuple[int, os.stat_result]:
    """Open a regular file inside a container root without following any link."""
    dir_fd, name = _walk_in_root(root_fd, rel)
    try:
        # Look before opening: a container's root can hold a device node or a FIFO under a
        # package-database name, and opening a device as host root can have side effects
        # (the container's device cgroup doesn't apply to the agent). Regular files only.
        try:
            before = os.lstat(name, dir_fd=dir_fd)
        except OSError as e:
            raise _root_refusal(e) from None
        if stat.S_ISLNK(before.st_mode):
            raise RootRefused("symlink", "a symbolic link (not followed out of the container's root)")
        if not stat.S_ISREG(before.st_mode):
            raise RootRefused("not_regular")
        try:
            fd = os.open(name, _NOFOLLOW_FILE, dir_fd=dir_fd)
        except OSError as e:
            raise _root_refusal(e) from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            os.close(fd)
            raise RootRefused("not_regular", "replaced while it was being opened")
        return fd, st
    finally:
        os.close(dir_fd)


def read_in_root(root_fd: int, rel: str, cap: int = PKGDB_MAX_BYTES) -> bytes:
    fd, st = open_in_root(root_fd, rel)
    try:
        if st.st_size > cap:
            raise RootRefused("too_big", f"{rel} is over {cap // (1024 * 1024)} MiB")
        chunks, left = [], cap + 1
        while left > 0:
            b = os.read(fd, min(left, 1 << 20))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        data = b"".join(chunks)
        if len(data) > cap:
            raise RootRefused("too_big", f"{rel} is over {cap // (1024 * 1024)} MiB")
        return data
    finally:
        os.close(fd)


def list_in_root(root_fd: int, rel: str) -> list[str]:
    dir_fd, name = _walk_in_root(root_fd, rel + "/x")
    try:
        return sorted(os.listdir(dir_fd))
    except OSError as e:
        raise _root_refusal(e) from None
    finally:
        os.close(dir_fd)


def _clean_field(value: str) -> str:
    """A field from a container's own files, made one record field (no tab, no control character)."""
    return _CTRL_RE.sub(" ", str(value))[:MAX_TEXT]


_WANT = {"install": "i", "hold": "h", "deinstall": "r", "purge": "p", "unknown": "u"}
_STATE = {"installed": "i", "config-files": "c", "half-installed": "h", "unpacked": "U",
          "not-installed": "n", "half-configured": "F", "triggers-awaited": "W", "triggers-pending": "t"}


def dpkg_records(text: str) -> list[str]:
    """`D` records (the host read's dpkg-query format) from a dpkg status file."""
    out: list[str] = []
    for stanza in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        last = ""
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t"):
                continue
            k, sep, v = line.partition(":")
            if sep:
                last = k.strip()
                fields[last] = v.strip()
        name = fields.get("Package")
        if not name:
            continue
        status = fields.get("Status", "install ok installed").split()
        abbrev = (_WANT.get(status[0], "u") if status else "u") + (_STATE.get(status[-1], "n") if status else "n")
        src = fields.get("Source", "")
        src_name, src_ver = src, ""
        m = re.match(r"^(\S+)\s*\(([^)]+)\)", src)
        if m:
            src_name, src_ver = m.group(1), m.group(2)
        version = fields.get("Version", "")
        out.append("\t".join(_clean_field(x) for x in ("D", name, version, fields.get("Architecture", ""),
                                                        src_name or name, src_ver or version, abbrev)))
    return out


def apk_records(text: str) -> list[str]:
    """`A` records from Alpine's installed database (the same as packages.AWK_APK prints)."""
    out: list[str] = []
    cur: dict[str, str] = {}

    def flush() -> None:
        if cur.get("P"):
            out.append("\t".join(_clean_field(x) for x in ("A", cur.get("P", ""), cur.get("V", ""), cur.get("A", ""),
                                                            cur.get("o", ""))))
        cur.clear()

    for line in text.splitlines():
        if not line:
            flush()
        elif line[1:2] == ":" and line[0] in "PVAo":
            cur[line[0]] = line[2:]
    flush()
    return out


# rpm header tags (rpmtag.h)
_RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1022: "arch", 1044: "sourcerpm"}


def rpm_header_record(blob: bytes) -> str | None:
    """One `R` record from an rpm header blob (the rpmdb.sqlite Packages table)."""
    if len(blob) < 8:
        return None
    il, dl = int.from_bytes(blob[0:4], "big"), int.from_bytes(blob[4:8], "big")
    if il <= 0 or il > 100000 or 8 + il * 16 + dl > len(blob):
        return None
    store = 8 + il * 16
    vals: dict[str, str] = {}
    for i in range(il):
        off = 8 + i * 16
        tag = int.from_bytes(blob[off:off + 4], "big")
        typ = int.from_bytes(blob[off + 4:off + 8], "big")
        where = int.from_bytes(blob[off + 8:off + 12], "big")
        name = _RPM_TAGS.get(tag)
        if name is None or where >= dl:
            continue
        pos = store + where
        if typ == 6 or typ == 9:                    # STRING / I18NSTRING (first)
            end = blob.find(b"\x00", pos, store + dl)
            if end < 0:
                continue
            vals[name] = blob[pos:end].decode("utf-8", "replace")
        elif typ == 4 and name == "epoch":          # INT32
            vals[name] = str(int.from_bytes(blob[pos:pos + 4], "big"))
    if not vals.get("name") or not vals.get("version"):
        return None
    evr = f"{vals.get('epoch', '(none)')}:{vals['version']}-{vals.get('release', '')}"
    return "\t".join(_clean_field(x) for x in ("R", vals["name"], evr, vals.get("arch", ""), vals.get("sourcerpm", "")))


def rpm_sqlite_records(root_fd: int, rel: str) -> list[str]:
    import sqlite3

    fd, st = open_in_root(root_fd, rel)
    try:
        if st.st_size > PKGDB_MAX_BYTES * 4:
            raise RootRefused("too_big", f"{rel} is too large")
        uri = f"file:/proc/self/fd/{fd}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True, timeout=1)
        try:
            out = []
            for (blob,) in conn.execute("SELECT blob FROM Packages"):
                rec = rpm_header_record(bytes(blob)) if blob else None
                if rec:
                    out.append(rec)
            return out
        finally:
            conn.close()
    finally:
        os.close(fd)


def image_package_lines(root_fd: int) -> tuple[list[str], str]:
    """The package-read records for one container root, and its status:
    ok | no_db (no package database: distroless/static) | old_rpmdb | error."""
    lines = ["PKGINV\t1"]
    for rel in ("etc/os-release", "usr/lib/os-release"):
        try:
            text = read_in_root(root_fd, rel, 65536).decode("utf-8", "replace")
        except RootRefused:
            continue
        for ln in text.splitlines()[:40]:
            if re.match(r"^(ID|ID_LIKE|VERSION_ID|VERSION_CODENAME|PRETTY_NAME)=", ln):
                lines.append("OS\t" + ln.replace("\t", " "))
        break
    found = False
    status = "ok"
    try:
        lines += dpkg_records(read_in_root(root_fd, "var/lib/dpkg/status").decode("utf-8", "replace"))
        found = True
    except RootRefused:
        pass
    try:
        names = list_in_root(root_fd, "var/lib/dpkg/status.d")
    except RootRefused:
        names = []
    for name in names[:MAX_STATUS_D_FILES]:
        if name.startswith(".") or name.endswith(".md5sums"):
            continue
        try:
            lines += dpkg_records(read_in_root(root_fd, f"var/lib/dpkg/status.d/{name}", 1 << 20).decode("utf-8", "replace"))
            found = True
        except RootRefused:
            continue
    if found:
        lines += ["MGR\tdpkg\tok", "POS\t0\t0"]
    for rel in ("lib/apk/db/installed", "usr/lib/apk/db/installed"):
        try:
            lines += apk_records(read_in_root(root_fd, rel).decode("utf-8", "replace"))
        except RootRefused:
            continue
        lines.append("MGR\tapk\tok")
        found = True
        break
    for rel in ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"):
        try:
            lines += rpm_sqlite_records(root_fd, rel)
        except RootRefused:
            continue
        except Exception:  # noqa: BLE001 -- a broken database is a failed manager, not a crash
            lines.append("MGR\trpm\tfailed")
            found = True
            break
        lines.append("MGR\trpm\tok")
        found = True
        break
    else:
        for rel in ("var/lib/rpm/Packages", "usr/lib/sysimage/rpm/Packages"):
            try:
                fd, _st = open_in_root(root_fd, rel)
            except RootRefused:
                continue
            os.close(fd)
            status = "old_rpmdb"
            break
    if not found and status == "ok":
        status = "no_db"
    lines.append("END")
    return lines, status


def packages_output(*, deadline: float, run_root: str = "/run", proc: str = "/proc",
                    client_factory: Callable[[str, list[int]], ApiClient] | None = None) -> dict[str, Any]:
    """The agent's per-image package read: for each distinct image among RUNNING
    containers (at most MAX_IMAGES), one block of package records read through one of
    its processes' root:

        IMG<TAB>image id<TAB>pid<TAB>status   (ok | no_db | old_rpmdb | gone | refused | error)
        ...the host read's records (PKGINV, OS, D/R/A, MGR, END)...
        IMGEND<TAB>image id
    """
    lines = ["CONTPKG\t1"]
    budget = [MAX_TOTAL_BYTES]
    factory = client_factory or (lambda path, b: ApiClient(path, b))
    images: dict[str, int] = {}
    for engine, _cand, real, _problem in engine_sockets(run_root):
        if real is None:
            continue
        client = factory(real, budget)
        try:
            listing = client.get("/containers/json?all=1")
        except ApiError:
            continue
        for c in listing if isinstance(listing, list) else []:
            cid = str(c.get("Id") or "") if isinstance(c, dict) else ""
            if not ID_RE.match(cid) or str(c.get("State") or "") != "running":
                continue
            image_id = str(c.get("ImageID") or "")
            if not _SHA256_RE.match(image_id) or image_id in images:
                continue
            try:
                d = distill_container(client.get(f"/containers/{cid}/json"), engine)
            except ApiError:
                continue
            if d and d.get("pid"):
                images[image_id] = int(d["pid"])
    n = 0
    for image_id, pid in sorted(images.items()):
        if n >= MAX_IMAGES:
            lines.append(_record("T", "images", len(images)))
            break
        if time.monotonic() > deadline:
            lines.append(_record("G", "images", f"out of time after {n} image(s)"))
            break
        n += 1
        try:
            root_fd = open_root(pid, proc)
        except RootRefused as e:
            lines += [_record("IMG", image_id, pid, "gone" if e.status == "missing" else "refused"),
                      _record("IMGEND", image_id)]
            continue
        try:
            body, status = image_package_lines(root_fd)
        except Exception as e:  # noqa: BLE001
            body, status = [], "error"
            lines.append(_record("G", "images", f"{image_id[7:19]}: {type(e).__name__}"))
        finally:
            os.close(root_fd)
        lines.append(_record("IMG", image_id, pid, status))
        lines += body
        lines.append(_record("IMGEND", image_id))
    lines.append("END")
    text = "\n".join(lines) + "\n"
    truncated = len(text.encode()) > PACKAGES_OUTPUT_CAP
    if truncated:
        text = text.encode()[:PACKAGES_OUTPUT_CAP].decode("utf-8", "ignore").rsplit("\n", 1)[0] + "\n"
    return {"returncode": 0, "stdout": text, "stderr": "", "truncated": truncated}


def parse_packages_output(stdout: str) -> dict[str, Any]:
    """{complete, images: {image id: {pid, status, inventory}}, truncated, gaps} -- each
    inventory is packages.parse_output of that image's block (one parser)."""
    out: dict[str, Any] = {"complete": False, "header": False, "images": {}, "truncated": {}, "gaps": []}
    cur: str | None = None
    block: list[str] = []
    for line in (stdout or "").splitlines():
        f = line.split("\t")
        if f[0] == "CONTPKG":
            out["header"] = True
        elif f[0] == "IMG" and len(f) >= 4 and _SHA256_RE.match(f[1]):
            cur, block = f[1], []
            out["images"][cur] = {"pid": int(f[2]) if f[2].isdigit() else None, "status": f[3][:16], "inventory": None}
        elif f[0] == "IMGEND" and cur is not None:
            out["images"][cur]["inventory"] = _packages.parse_output("\n".join(block)) if block else None
            cur = None
        elif cur is not None:
            block.append(line)
        elif f[0] == "T" and len(f) >= 3:
            out["truncated"][f[1][:32]] = int(f[2]) if f[2].isdigit() else 0
        elif f[0] == "G" and len(f) >= 3:
            out["gaps"].append(f"{f[1][:32]}: {f[2][:300]}")
        elif f[0] == "END":
            out["complete"] = True
    return out


# --------------------------------------------------------------------------- container logs
def _engine_client_for(cid: str, run_root: str,
                       client_factory: Callable[[str, list[int]], ApiClient] | None) -> tuple[ApiClient, str, dict[str, Any], dict[str, Any]] | None:
    budget = [MAX_TOTAL_BYTES]
    factory = client_factory or (lambda path, b: ApiClient(path, b))
    for engine, _cand, real, _problem in engine_sockets(run_root):
        if real is None:
            continue
        client = factory(real, budget)
        try:
            raw = client.get(f"/containers/{cid}/json")
            info = distill_info(client.get("/info"))
        except ApiError:
            continue
        if isinstance(raw, dict) and raw.get("Id") == cid:
            return client, engine, raw, info
    return None


def expected_log_path(raw: dict[str, Any], info: dict[str, Any], engine: str) -> tuple[str | None, str]:
    """(the log file path the engine reports, the format) only when it has the shape that
    engine writes: Docker json-file -> <root>/containers/<id>/<id>-json.log; Podman
    k8s-file -> under the storage root, ending /<id>/userdata/ctr.log. Else (None, why)."""
    cid = str(raw.get("Id") or "")
    driver = str(_dict(_dict(raw.get("HostConfig")).get("LogConfig")).get("Type") or "")
    path = str(raw.get("LogPath") or "")
    root = str(info.get("root_dir") or "").rstrip("/")
    if not ID_RE.match(cid):
        return None, "bad id"
    if driver == "json-file":
        if root.startswith("/") and path == f"{root}/containers/{cid}/{cid}-json.log":
            return path, "json-file"
        return None, "the engine reported an unexpected log path"
    if driver == "k8s-file":
        if root.startswith("/") and path.startswith(root + "/") and path.endswith(f"/{cid}/userdata/ctr.log"):
            return path, "k8s-file"
        return None, "the engine reported an unexpected log path"
    if driver == "local":
        return None, "the 'local' log driver's binary format is not read"
    if driver in ("journald", "passthrough", "none", ""):
        return None, f"logs go to {driver or 'nowhere'}, not to a file"
    return None, f"the {driver!r} log driver keeps no file Kratos reads"


def container_log_output(container_id: str, inode: int | None, offset: int, *, run_root: str = "/run",
                         client_factory: Callable[[str, list[int]], ApiClient] | None = None,
                         opener: Callable[[str], tuple[int, os.stat_result]] | None = None) -> dict[str, Any]:
    """One bounded chunk of a container's log file, from a remembered (inode, offset).

        CM<TAB>{name, image, image_id, engine, driver}
        CL<TAB>status<TAB>slot<TAB>inode<TAB>start<TAB>consumed<TAB>size   (slot 0 = current file,
               1 = the rotated .1 file still holding the rest of the followed inode)
        CJ<TAB>raw json-file line   |   CK<TAB>raw k8s-file line (tabs turned to spaces)

    status: read | gone (the container or its file no longer exists) | refused | missing |
    unsupported. The first read (no inode) starts LOG_INITIAL_TAIL_BYTES before the end."""
    if not ID_RE.match(str(container_id or "")):
        return {"returncode": 0, "stdout": "CL\trefused\t0\t-\t0\t0\t0\n", "stderr": "", "truncated": False}
    found = _engine_client_for(container_id, run_root, client_factory)
    if found is None:
        return {"returncode": 0, "stdout": "CL\tgone\t0\t-\t0\t0\t0\n", "stderr": "", "truncated": False}
    _client, engine, raw, info = found
    path, fmt = expected_log_path(raw, info, engine)
    meta = {"name": _text(str(raw.get("Name") or "").lstrip("/"), 128),
            "image": _text(_dict(raw.get("Config")).get("Image")), "image_id": str(raw.get("Image") or "")[:71],
            "engine": engine, "driver": _text(_dict(_dict(raw.get("HostConfig")).get("LogConfig")).get("Type"), 32)}
    lines = [f"CM\t{json.dumps(meta, ensure_ascii=True, sort_keys=True)}"]
    if path is None:
        lines.append(f"CL\tunsupported\t0\t-\t0\t0\t0\t{_text(fmt, 200)}")
        return {"returncode": 0, "stdout": "\n".join(lines) + "\n", "stderr": "", "truncated": False}
    if opener is None:
        try:
            from . import hostfiles as _hf  # type: ignore[attr-defined]
        except ImportError:
            from kratos.logsources import hostfiles as _hf
        opener = _hf.open_log_file
    tag = "CJ" if fmt == "json-file" else "CK"

    def chunk(p: str, slot: int, start_at: int | None) -> bool:
        try:
            fd, st = opener(p)
        except Exception as e:  # noqa: BLE001 -- FileRefused(status) from the hardened opener
            status = getattr(e, "status", "refused")
            lines.append(f"CL\t{'missing' if status == 'missing' else 'refused'}\t{slot}\t-\t0\t0\t0\t{_text(status, 40)}")
            return False
        try:
            if slot == 1 and inode is not None and st.st_ino != inode:
                lines.append(f"CL\tmissing\t1\t{st.st_ino}\t0\t0\t{st.st_size}")
                return False
            size = st.st_size
            if start_at is None:
                start = max(0, size - LOG_INITIAL_TAIL_BYTES)
            else:
                start = min(max(0, start_at), size)
            os.lseek(fd, start, os.SEEK_SET)
            data = os.read(fd, LOG_CHUNK_BYTES)
            if start_at is None and start > 0:          # began mid-line: skip to the next line
                nl = data.find(b"\n")
                skip = nl + 1 if nl >= 0 else len(data)
                data, start = data[skip:], start + skip
            end = data.rfind(b"\n")
            body = data[:end + 1] if end >= 0 else b""
            lines.append(f"CL\tread\t{slot}\t{st.st_ino}\t{start}\t{len(body)}\t{size}")
            for raw_line in body.split(b"\n"):
                if not raw_line:
                    continue
                text = raw_line[:LOG_LINE_MAX].decode("utf-8", "replace").replace("\t", " ").replace("\r", " ")
                lines.append(f"{tag}\t{text}")
            return True
        finally:
            os.close(fd)

    if inode is not None:
        try:
            fd, st = opener(path)
            os.close(fd)
            current_inode = st.st_ino
        except Exception:  # noqa: BLE001
            current_inode = None
        if current_inode is not None and current_inode != inode:
            # the followed file was rotated: finish it from its .1 name, then the new file starts at 0
            chunk(path + ".1", 1, offset)
            lines.append(f"CL\tcurrent\t0\t{current_inode}\t0\t0\t0")
        else:
            chunk(path, 0, offset)
    else:
        chunk(path, 0, None)
    text = "\n".join(lines) + "\n"
    return {"returncode": 0, "stdout": text, "stderr": "", "truncated": len(text) > LOG_OUTPUT_CAP}


def parse_log_output(stdout: str) -> dict[str, Any]:
    """{meta, files: [{status, slot, inode, start, consumed, size, note}], lines: [(format, raw)]}."""
    out: dict[str, Any] = {"meta": {}, "files": [], "lines": []}
    for line in (stdout or "").splitlines():
        f = line.split("\t")
        if f[0] == "CM" and len(f) >= 2:
            data = _json_field("\t".join(f[1:]))
            out["meta"] = data if isinstance(data, dict) else {}
        elif f[0] == "CL" and len(f) >= 7:
            def num(x: str) -> int | None:
                return int(x) if x.isdigit() else None
            out["files"].append({"status": f[1][:16], "slot": num(f[2]) or 0, "inode": num(f[3]),
                                 "start": num(f[4]) or 0, "consumed": num(f[5]) or 0, "size": num(f[6]) or 0,
                                 "note": (f[7] if len(f) > 7 else "")[:200]})
        elif f[0] in ("CJ", "CK") and len(f) >= 2:
            out["lines"].append(("json-file" if f[0] == "CJ" else "k8s-file", "\t".join(f[1:])[:LOG_LINE_MAX]))
    return out
