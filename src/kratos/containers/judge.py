"""Judge a container read: CONT-001..008 (D.5 §3.4). Pure functions -- the input is
the parsed read (adapters.containers.parse_output) plus the reachability confirmations
Kratos made itself; the output is signal dicts the findings engine turns into findings.

Every rule is a setting (ATT&CK Posture, the technique it enables named in the
mapping): Kratos reports what a container was started with, never that it was used.
A setting on a STOPPED container is listed in the container table but raises no
finding -- it can't hand anyone the host until it runs.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from kratos.containers import firewall as F

CIS = "CIS Docker Benchmark v1.7.0"
# The section each rule corresponds to -- numbers only, never the benchmark's text (CIS licence).
CIS_SECTION = {"CONT-001": "5.5", "CONT-002": "5.32", "CONT-003": "5.10 / 5.16 / 5.17", "CONT-004": "5.14",
               "CONT-005": "5.6", "CONT-006": "5.4", "CONT-007": "5.2 / 5.3 / 5.22"}

# CONT-005: host folders whose writable mount gives the container the host (the folder, or a parent of it).
SYSTEM_DIRS = ("/", "/etc", "/root", "/boot", "/usr", "/var/lib/docker", "/proc", "/sys", "/dev")
# CONT-006: capabilities that hand over the host or its kernel. Bit numbers from linux/capability.h.
DANGEROUS_CAPS = {"SYS_ADMIN": 21, "SYS_MODULE": 16, "SYS_PTRACE": 19, "DAC_READ_SEARCH": 2, "NET_ADMIN": 12,
                  "SYS_RAWIO": 17, "BPF": 39}
HIGH_CAPS = ("SYS_ADMIN", "SYS_MODULE")
ALL_CAPS_MASK = (1 << 41) - 1            # CAP_LAST_CAP is 40 on current kernels
# A mounted engine socket (or the folder holding it) is the engine's whole API: root on the host.
_SOCKET_NAMES = ("docker.sock", "podman.sock", "containerd.sock", "crio.sock")
_SOCKET_DIRS = ("/run", "/var/run", "/run/docker", "/var/run/docker", "/run/podman", "/run/containerd")
MAX_CONFIRM = 20                          # TCP connects one collection makes at most


@dataclass
class Judged:
    signals: list[dict[str, Any]] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)       # the container table (TUI / CLI)
    gaps: list[str] = field(default_factory=list)                   # CONT-008's lines, plain words
    port_checks: list[dict[str, Any]] = field(default_factory=list)  # every published port judged
    engines_found: bool = False
    counts: dict[str, int] = field(default_factory=dict)


def norm_cap(name: str) -> str:
    n = str(name or "").strip().upper()
    return n[4:] if n.startswith("CAP_") else n


def caps_from_mask(hexmask: str | None) -> set[str]:
    try:
        mask = int(str(hexmask or ""), 16)
    except ValueError:
        return set()
    return {name for name, bit in DANGEROUS_CAPS.items() if mask >> bit & 1}


def is_full_mask(hexmask: str | None) -> bool:
    try:
        return int(str(hexmask or ""), 16) & ALL_CAPS_MASK == ALL_CAPS_MASK
    except ValueError:
        return False


def compose_of(c: dict[str, Any]) -> dict[str, str] | None:
    labels = c.get("labels") or {}
    project = labels.get("com.docker.compose.project") or labels.get("io.podman.compose.project")
    if not project:
        return None
    files = labels.get("com.docker.compose.project.config_files") or ""
    return {"project": project, "service": labels.get("com.docker.compose.service") or "",
            "file": files.split(",")[0] if files else "", "dir": labels.get("com.docker.compose.project.working_dir") or ""}


def _where(c: dict[str, Any]) -> str:
    comp = compose_of(c)
    base = f"container {c.get('name')}" + (f" (image {c.get('image')})" if c.get("image") else "")
    if comp:
        base += f", Compose project {comp['project']} service {comp['service'] or '?'}"
        if comp["file"]:
            base += f" ({comp['file']})"
    return base


def _image_entity(c: dict[str, Any]) -> str:
    return f"image:{c.get('image_digest') or c.get('image_id') or c.get('image') or '?'}"


def _sig(rule: str, severity: str, c: dict[str, Any], title: str, setting_entities: list[str], evidence: list[str],
         recommendation: list[str], fix: list[dict[str, str]] | None = None, **extra: Any) -> dict[str, Any]:
    evidence = [*evidence, f"Matches {CIS} §{CIS_SECTION[rule]} (section number only)."]
    out = {"rule": rule, "severity": severity, "subject": str(c.get("name") or c.get("id", "")[:12]),
           "title": title, "entities": sorted({_image_entity(c), *setting_entities}),
           "evidence": evidence, "recommendation": recommendation, "fix": fix or [],
           "container": {"id": c.get("id"), "name": c.get("name"), "image": c.get("image"),
                         "compose": compose_of(c)}}
    out.update(extra)
    return out


def _socket_mount(m: dict[str, Any]) -> bool:
    src = str(m.get("source") or "").rstrip("/") or "/"
    return src.rsplit("/", 1)[-1] in _SOCKET_NAMES or src in _SOCKET_DIRS or src.endswith("/podman/podman.sock")


def _system_mount(m: dict[str, Any]) -> str | None:
    if str(m.get("type") or "bind") != "bind" or not m.get("rw"):
        return None
    src = str(m.get("source") or "").rstrip("/") or "/"
    for d in SYSTEM_DIRS:
        if src == d or (src == "/" or d.startswith(src + "/")):
            return d if src != "/" else "/"
    return None


def _settings_signals(c: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    where = _where(c)
    if c.get("privileged"):
        out.append(_sig("CONT-001", "high", c, "A container runs privileged", ["privileged"],
                        [f"{where} was started with --privileged: every capability, every host device, and no "
                         "seccomp or AppArmor/SELinux confinement. A process in it can take over the host."],
                        ["Run it without --privileged (`privileged: false` in Compose); add only the specific "
                         "capability or device it needs (--cap-add / --device).",
                         "If it must stay privileged (some monitoring or hardware tools do), accept the risk with "
                         "a reason and an expiry so it's reviewed again."]))
    socks = [m for m in c.get("mounts") or [] if _socket_mount(m)]
    if socks:
        paths = sorted({str(m.get("source")) for m in socks})
        ro = all(not m.get("rw") for m in socks)
        out.append(_sig("CONT-002", "high", c, "A container can control the container engine (its API socket is mounted inside)", [f"mount:{p}" for p in paths],
                        [f"{where} has {', '.join(paths)} mounted. Whoever controls this container can start a "
                         "privileged container through that API -- root on the host."]
                        + (["The mount is read-only, which does not stop a program from using the API."] if ro else []),
                        ["Remove the socket mount unless the container's purpose is to manage containers.",
                         "If it is (Portainer, Traefik, a CI runner), put a socket proxy that allows only the API "
                         "calls it needs in between, and accept the remaining risk with a reason and an expiry."]))
    shared = [(k, label) for k, label in (("network_mode", "network"), ("pid_mode", "PID"), ("ipc_mode", "IPC"))
              if str(c.get(k) or "") == "host"]
    if shared:
        names = ", ".join(label for _k, label in shared)
        out.append(_sig("CONT-003", "medium", c, f"A container shares the host's {names} namespace",
                        [f"{label.lower()}:host" for _k, label in shared],
                        [f"{where} uses the host's {names} namespace"
                         + (": it can see and signal every host process" if any(k == "pid_mode" for k, _l in shared)
                            else "")
                         + ("; its listening ports are the host's own, with no Docker port mapping in between"
                            if any(k == "network_mode" for k, _l in shared) else "") + "."],
                        ["Drop `--network host` / `--pid host` / `--ipc host` (`network_mode: host` etc. in Compose) "
                         "unless the container really needs it, and publish only the ports it serves."]))
    mounts = [(m, d) for m in c.get("mounts") or [] if (d := _system_mount(m))]
    if mounts:
        srcs = sorted({str(m.get("source")) for m, _d in mounts})
        out.append(_sig("CONT-005", "high", c, "A container can write to host system folders",
                        [f"mount:{s}" for s in srcs],
                        [f"{where} has these host folders mounted writable: "
                         + ", ".join(f"{m.get('source')} -> {m.get('destination')}" for m, _d in mounts)
                         + ". Writing there changes the host itself (its accounts, services, boot or kernel interfaces)."],
                        ["Mount only the files it needs, read-only (`:ro`), or use a named volume.",
                         "Example: `-v /etc/myapp/config.yml:/config.yml:ro` instead of `-v /etc:/host-etc`."]))
    if not c.get("privileged"):
        added = sorted({norm_cap(x) for x in c.get("cap_add") or []})
        danger = sorted(DANGEROUS_CAPS) if "ALL" in added else [x for x in added if x in DANGEROUS_CAPS]
        if danger:
            sev = "high" if any(x in HIGH_CAPS for x in danger) else "medium"
            out.append(_sig("CONT-006", sev, c, "A container was given powerful capabilities: " + ", ".join(danger), [f"cap:{x}" for x in danger],
                            [f"{where} was started with --cap-add " + ", ".join(added) + "."
                             + (" SYS_ADMIN and SYS_MODULE are enough to escape to the host." if sev == "high" else "")],
                            ["Remove the capabilities it doesn't need (`cap_add:` in Compose); start from "
                             "`--cap-drop ALL` and add back only what the program requires."]))
        off = []
        opts = [str(o).lower() for o in c.get("security_opt") or []]
        if any(o.replace(":", "=") in ("seccomp=unconfined",) for o in opts):
            off.append("seccomp")
        if any(o.replace(":", "=") == "apparmor=unconfined" for o in opts) or str(c.get("apparmor") or "") == "unconfined":
            off.append("AppArmor")
        if any(o.replace(":", "=") == "label=disable" for o in opts):
            off.append("SELinux")
        if off:
            out.append(_sig("CONT-007", "medium", c, "A container runs without " + " / ".join(off) + " confinement", [f"confinement:{x.lower()}=off" for x in off],
                            [f"{where} turned off {', '.join(off)} (--security-opt). The default profiles block "
                             "most kernel calls container escapes rely on."],
                            ["Remove `--security-opt seccomp=unconfined` / `apparmor=unconfined` / `label=disable` "
                             "(`security_opt:` in Compose). If one system call is missing, allow just that one in "
                             "a custom profile."]))
    return out


# ------------------------------------------------------------------------- CONT-004
def _network_of(c: dict[str, Any], inv: dict[str, Any]) -> tuple[str | None, str | None, str | None, bool, dict[str, Any]]:
    """(container IPv4, IPv6, bridge interface, network has IPv6, network options) for the
    first network the container is on."""
    for n in c.get("networks") or []:
        net = (inv.get("networks") or {}).get(str(n.get("id") or "")) or {}
        opts = net.get("options") or {}
        bridge = opts.get("com.docker.network.bridge.name") or (
            "docker0" if str(n.get("name")) == "bridge" else ("br-" + str(net.get("id"))[:12] if net.get("id") else None))
        return (str(n.get("ip")) or None, str(n.get("ip6")) or None, bridge, bool(net.get("ipv6")), opts)
    return None, None, None, False, {}


def _loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _fix_iptables(port: int, proto: str, iface: str, families: list[int]) -> dict[str, str]:
    rules = "\n".join([
        "*filter",
        ":DOCKER-USER - [0:0]",
        "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
        f"-A DOCKER-USER -i {iface} -p {proto} -m conntrack --ctorigdstport {port} --ctdir ORIGINAL -j DROP",
        "COMMIT",
    ])
    files = " and ".join(["/etc/ufw/after.rules" if f == 4 else "/etc/ufw/after6.rules" for f in families])
    return {"title": f"Drop outside traffic to {port}/{proto} in DOCKER-USER (iptables backend)",
            "text": f"# Add at the END of {files}, then run: sudo ufw reload\n{rules}"}


def _fix_nftables(port: int, proto: str, iface: str) -> dict[str, str]:
    return {"title": f"Drop outside traffic to {port}/{proto} before Docker's rules (nftables backend)",
            "text": ("# Docker's nftables mode has no DOCKER-USER chain: add your own table (for example in\n"
                     "# /etc/nftables.conf, loaded at boot), then run: sudo nft -f /etc/nftables.conf\n"
                     "table inet kratos-docker-guard {\n"
                     "  chain forward {\n"
                     "    type filter hook forward priority filter - 10; policy accept;\n"
                     f"    iifname \"{iface}\" meta l4proto {proto} ct original proto-dst {port} ct state new drop\n"
                     "  }\n"
                     "}")}


def _fix_bind_local(c: dict[str, Any], p: dict[str, Any]) -> dict[str, str]:
    comp = compose_of(c)
    hp, cp, proto = p["host_port"], p["container_port"], p["proto"]
    suffix = "" if proto == "tcp" else f"/{proto}"
    if comp:
        where = comp["file"] or "the Compose file"
        return {"title": f"Publish {hp} on 127.0.0.1 only, in the Compose file",
                "text": (f"# In {where}, service \"{comp['service']}\":\n"
                         f"    ports:\n      - \"127.0.0.1:{hp}:{cp}{suffix}\"\n"
                         f"# then, in {comp['dir'] or 'the project folder'}: docker compose up -d")}
    return {"title": f"Publish {hp} on 127.0.0.1 only",
            "text": (f"# Re-create the container with the port bound to the loopback address only:\n"
                     f"docker run ... -p 127.0.0.1:{hp}:{cp}{suffix} ... {c.get('image') or 'IMAGE'}")}


def judge_ports(c: dict[str, Any], inv: dict[str, Any], rs: F.Ruleset, *, host_addrs: dict[int, str | None],
                in_iface: dict[int, str | None]) -> list[F.PortJudgement]:
    ip4, ip6, bridge, has6, _opts = _network_of(c, inv)
    # Rootless Podman publishes through a user-space proxy (rootlessport) listening on the
    # machine itself -- no DNAT, so INPUT governs it like any local service (seen on the lab).
    rootless = str(c.get("engine") or "").startswith("podman-rootless")
    out = []
    seen: set[tuple[int, int, str]] = set()
    for p in c.get("ports") or []:
        hip = str(p.get("host_ip") or "")
        if hip and _loopback(hip):
            continue
        fam = 6 if ":" in hip else 4
        key = (fam, int(p["host_port"]), str(p["proto"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(F.judge_port(rs, family=fam, proto=str(p["proto"]), host_port=int(p["host_port"]),
                                container_port=int(p["container_port"]), container_ip=(ip4 if fam == 4 else ip6),
                                bridge=bridge, host_addr=host_addrs.get(fam), in_iface=in_iface.get(fam),
                                forwarded=not rootless and (fam == 4 or has6)))
    return out


def _bypass_signal(c: dict[str, Any], hits: list[F.PortJudgement], confirmed: dict[int, bool | None], *,
                   backend: str, fw_name: str, in_iface: dict[int, str | None], vantage: str,
                   gateway_note: str) -> dict[str, Any]:
    ports = sorted({(j.host_port, j.proto) for j in hits})
    conf_ports = [hp for hp, _p in ports if confirmed.get(hp)]
    sev = "high" if conf_ports else "medium"
    words = ", ".join(f"{hp}/{pr}" for hp, pr in ports)
    fams = sorted({j.family for j in hits})
    ev = [f"{_where(c)} publishes {words} on all addresses ("
          + " and ".join("IPv4" if f == 4 else "IPv6" for f in fams) + ").",
          f"{fw_name} would refuse these ports on INPUT, but Docker forwards published container traffic before "
          "those rules see it" + (f" ({backend} backend)" if backend else "") + "."]
    for j in hits:
        ev.append(f"{j.host_port}/{j.proto} IPv{j.family}: forwarding path ends at '{(j.forward.where if j.forward else '')[:160]}'; "
                  f"INPUT would {j.input.verdict if j.input else '?'} it ('{(j.input.where if j.input else '')[:120]}').")
    for hp, pr in ports:
        state = confirmed.get(hp)
        if state is True:
            ev.append(f"Confirmed: a TCP connection from Kratos ({vantage}) to port {hp} was accepted (no data sent).")
        elif state is False:
            ev.append(f"Not confirmed from Kratos's network position ({vantage}): the connection to {hp} did not "
                      "complete -- the rules allow it, but something between here and there may not.")
        else:
            ev.append(f"{hp}/{pr}: not tried from Kratos (" + ("UDP" if pr == "udp" else "no outside vantage") + ").")
    if gateway_note:
        ev.append(gateway_note)
    fixes = [_fix_bind_local(c, next(p for p in c.get("ports") or [] if int(p["host_port"]) == ports[0][0]))]
    iface = (in_iface.get(4) or in_iface.get(6) or "eth0")
    for hp, pr in ports:
        if backend == "nftables":
            fixes.append(_fix_nftables(hp, pr, iface))
        else:
            fixes.append(_fix_iptables(hp, pr, iface, sorted({j.family for j in hits if j.host_port == hp})))
    rec = ["If only a local reverse proxy should reach it, publish it on 127.0.0.1 (first fix below).",
           "Otherwise filter it where Docker's traffic actually passes: "
           + ("a separate nftables table with a forward chain (second fix)" if backend == "nftables"
              else "the DOCKER-USER chain, for IPv4 and IPv6 (second fix)") + ".",
           "Kratos does not run these -- copy them to a terminal on the machine, then re-check with /retest."]
    return _sig("CONT-004", sev, c, f"A container's published port(s) {words} reachable despite the firewall",
                [f"port:{hp}/{pr}" for hp, pr in ports], ev, rec, fixes,
                ports=[j.as_dict() for j in hits], confirmed=sorted(conf_ports))


def firewall_name(inv: dict[str, Any], decided_by: str = "") -> str:
    """What refused the port on INPUT, in a person's words: the nftables table named by the
    deciding rule, else ufw when ufw's own rules are loaded, else firewalld, else "the firewall"."""
    if decided_by.startswith("table "):
        parts = decided_by.split()
        return f"the nftables firewall (table {parts[2]})" if len(parts) > 2 else "the nftables firewall"
    fw = inv.get("firewall") or {}
    text = " ".join(str((fw.get(k) or {}).get("text") or "")[:400000] for k in ("iptables", "nft"))
    if "-A ufw-user-input" in text or "-A ufw-before-input" in text:
        return "ufw"
    if "firewalld" in text:
        return "firewalld"
    return "the firewall"


def judge(inv: dict[str, Any], *, host_addrs: dict[int, str | None], confirm: Any = None,
          vantage: str = "", local_machine: bool = False) -> Judged:
    """`confirm(port) -> True/False/None` makes the one TCP connect (None: not tried).
    `host_addrs`: the machine's address per family as Kratos reaches it."""
    out = Judged()
    containers = list((inv.get("containers") or {}).values())
    procs = inv.get("procs") or {}
    engines = inv.get("engines") or []
    via = str(inv.get("via") or "")
    out.engines_found = bool(engines or containers or procs)
    infos = inv.get("infos") or {}
    backend = next((str(i.get("firewall_backend") or "") for i in infos.values() if i.get("firewall_backend")), "")
    rs = F.ruleset_from(inv.get("firewall") or {}, backend)
    if not backend:      # over SSH the engine isn't asked; Docker's own rules say which backend it uses
        backend = ("nftables" if any(k[1] in F.DOCKER_NFT_TABLES for k in rs.nft)
                   else "iptables" if any("DOCKER" in (t.get("nat") or {}) for t in rs.ipt.values()) else "")
    routes = inv.get("routes") or {}
    in_iface = {4: (routes.get("4") or [None])[0], 6: (routes.get("6") or [None])[0]}
    fw_read = rs.have_ipt.get(4) or rs.have_nft
    # ---- gaps
    gaps: list[str] = []
    for e in engines:
        if e["state"] == "not_read":
            gaps.append(f"{e['engine']} is installed, but its settings (mounts, privileged flag, published ports) "
                        f"are only readable as root -- {_agent_fix()}; Kratos never asks for the docker group or "
                        "`sudo docker` (both are root on the machine)")
        elif e["state"] != "ok":
            gaps.append(f"{e['engine']} at {e['socket']}: {e['state']} ({e['detail']})")
    for g in inv.get("gaps") or []:
        gaps.append(g)
    owners = sorted({p["rootless_owner"] for p in procs.values() if p.get("rootless_owner") is not None})
    read_ok = {e["engine"].split(":", 1)[1] for e in engines
               if e["engine"].startswith("podman-rootless:") and e["state"] == "ok"}
    if via in ("agent", "subagent"):
        for uid in owners:
            if str(uid) not in read_ok:
                gaps.append(f"rootless Podman containers of user {uid} are running, but that user's Podman API "
                            "socket is off, so their settings could not be read (enable it as that user: "
                            "`systemctl --user enable --now podman.socket`)")
    if out.engines_found and not fw_read:
        statuses = {k: (v or {}).get("status") for k, v in (inv.get("firewall") or {}).items()}
        if via in ("ssh", "local"):
            gaps.append("published ports vs the firewall: can't tell -- the firewall rules are only readable as root "
                        "(allow exactly `iptables-save`, `ip6tables-save` and `nft -j list ruleset` with sudo -- "
                        "the setup checklist has the lines -- or read this machine through its sub-agent)")
        else:
            gaps.append(f"published ports vs the firewall: can't tell -- the firewall rules could not be read ({statuses})")
    if inv.get("hidepid") not in ("0", "", None) and via in ("ssh", "local"):
        gaps.append("/proc hides other users' processes from this login (hidepid), so containers may be missing "
                    f"-- {_agent_fix()}")
    if inv.get("proc_gaps"):
        gaps.append(f"{len(inv['proc_gaps'])} container process detail(s) could not be read by this login")
    for what, n in (inv.get("truncated") or {}).items():
        gaps.append(f"more {what} than one read looks at ({n}); the rest were not checked")
    # ---- per container
    confirm_budget = [MAX_CONFIRM]

    def try_confirm(port: int, proto: str) -> bool | None:
        if confirm is None or proto != "tcp" or local_machine or confirm_budget[0] <= 0:
            return None
        confirm_budget[0] -= 1
        return confirm(port)

    by_name = sorted(containers, key=lambda c: (not c.get("running"), str(c.get("name"))))
    for c in by_name:
        running = bool(c.get("running"))
        sigs = _settings_signals(c) if running else []
        checks = judge_ports(c, inv, rs, host_addrs=host_addrs, in_iface=in_iface) if running and fw_read else []
        out.port_checks += [{"container": c.get("name"), **j.as_dict()} for j in checks]
        hits = [j for j in checks if j.bypass == "yes"]
        unknown = [j for j in checks if j.bypass == "unknown"]
        if hits:
            confirmed = {j.host_port: try_confirm(j.host_port, j.proto) for j in hits}
            _ip4, _ip6, _br, _h6, opts = _network_of(c, inv)
            gw = [f"{k.rsplit('.', 1)[-1]}={v}" for k, v in opts.items() if "gateway_mode" in k and "unprotected" in v
                  or k.endswith("allow_direct_routing")]
            note = ("The network's gateway mode allows direct access to container addresses too: " + ", ".join(gw)
                    if gw else "")
            fw_name = firewall_name(inv, hits[0].input.where if hits[0].input else "")
            sigs.append(_bypass_signal(c, hits, confirmed, backend=backend, fw_name=fw_name, in_iface=in_iface,
                                       vantage=vantage or "this machine", gateway_note=note))
        for j in unknown:
            gaps.append(f"{c.get('name')}: port {j.host_port}/{j.proto} IPv{j.family} vs the firewall: can't tell ({j.why})")
        out.signals += sigs
        out.rows.append(_row(c, sigs, checks))
    # SSH-only view: containers from /proc, with what /proc can show (capabilities), and --
    # when the firewall rules were readable (the pinned sudo lines) -- the published ports
    # from Docker's own NAT rules
    if not containers and procs:
        out.signals += _ssh_cap_signals(procs)
        out.rows += _ssh_rows(procs, inv)
        if fw_read:
            out.signals += _rule_bypass_signals(inv, rs, host_addrs=host_addrs, in_iface=in_iface,
                                                try_confirm=try_confirm, backend=backend, vantage=vantage)
    out.gaps = gaps
    if gaps:
        out.signals.append({"rule": "CONT-008", "severity": "info", "subject": "",
                            "title": "Part of the container check could not be done",
                            "entities": [], "evidence": [*gaps, "What wasn't checked is unknown, not safe."],
                            "recommendation": ["Read this machine through its sub-agent for the engine's own settings "
                                               "and the firewall rules (it reads as root)."]})
    out.counts = {"containers": len(containers) or len({p["container"] for p in procs.values()}),
                  "running": sum(1 for c in containers if c.get("running")) or len({p["container"] for p in procs.values()}),
                  "bypass": sum(1 for s in out.signals if s["rule"] == "CONT-004"),
                  "confirmed": sum(1 for s in out.signals if s["rule"] == "CONT-004" and s["severity"] == "high"),
                  "risky": len({s["subject"] for s in out.signals if s["rule"] in ("CONT-001", "CONT-002", "CONT-003",
                                                                                     "CONT-005", "CONT-006", "CONT-007")})}
    return out


def _rule_bypass_signals(inv: dict[str, Any], rs: F.Ruleset, *, host_addrs: dict[int, str | None],
                         in_iface: dict[int, str | None], try_confirm: Any, backend: str,
                         vantage: str) -> list[dict[str, Any]]:
    """CONT-004 over SSH, from the ports Docker's own NAT rules publish (no engine API). The
    subject is the container's address: its name is only readable through the sub-agent."""
    out = []
    by_ip: dict[str, list[F.PortJudgement]] = {}
    for pp in F.published_from_rules(rs):
        if _loopback(pp["host_ip"]):
            continue
        j = F.judge_port(rs, family=pp["family"], proto=pp["proto"], host_port=pp["host_port"],
                         container_port=pp["container_port"], container_ip=pp["container_ip"] or None,
                         bridge=pp["bridge"], host_addr=host_addrs.get(pp["family"]),
                         in_iface=in_iface.get(pp["family"]), forwarded=True)
        if j.bypass == "yes":
            by_ip.setdefault(pp["container_ip"], []).append(j)
    for ip, hits in sorted(by_ip.items()):
        c = {"id": "", "name": f"at {ip}", "image": "", "image_id": "",
             "ports": [{"proto": j.proto, "container_port": 0, "host_ip": "", "host_port": j.host_port} for j in hits]}
        confirmed = {j.host_port: try_confirm(j.host_port, j.proto) for j in hits}
        sig = _bypass_signal(c, hits, confirmed, backend=backend,
                             fw_name=firewall_name(inv, hits[0].input.where if hits[0].input else ""),
                             in_iface=in_iface, vantage=vantage or "this machine", gateway_note="")
        sig["subject"] = ip
        sig["entities"] = sorted({f"address:{ip}", *(f"port:{j.host_port}/{j.proto}" for j in hits)})
        sig["evidence"].insert(0, f"Read over SSH from Docker's own NAT rules (the pinned, read-only firewall "
                                  f"listings): a container at {ip} is published. Its name, image and settings are "
                                  "only readable through the sub-agent.")
        sig["fix"] = sig["fix"][1:]          # no Compose/run definition is known over SSH
        out.append(sig)
    return out


def _agent_fix() -> str:
    return "read this machine through its sub-agent (it reads as root)"


def _row(c: dict[str, Any], sigs: list[dict[str, Any]], checks: list[F.PortJudgement]) -> dict[str, Any]:
    bypass = {(j.family, j.host_port, j.proto) for j in checks if j.bypass == "yes"}
    ports = []
    for p in c.get("ports") or []:
        hip = str(p.get("host_ip") or "")
        fam = 6 if ":" in hip else 4
        mark = " (reachable despite firewall)" if (fam, int(p["host_port"]), p["proto"]) in bypass else ""
        shown = f"[{hip}]" if fam == 6 else (hip or "*")
        ports.append(f"{shown}:{p['host_port']}->{p['container_port']}/{p['proto']}{mark}")
    return {"id": c.get("id"), "name": c.get("name"), "image": c.get("image"),
            "digest": (c.get("image_digest") or c.get("image_id") or "")[7:19], "user": c.get("user") or "root (default)",
            "running": bool(c.get("running")), "state": c.get("state"), "engine": c.get("engine"),
            "log_driver": c.get("log_driver") or "", "ports": sorted(set(ports)), "risks": sorted({s["rule"] for s in sigs}),
            "compose": compose_of(c), "env_keys": list(c.get("env_keys") or []),
            "labels": dict(c.get("labels") or {}), "mounts": list(c.get("mounts") or []),
            "network_mode": c.get("network_mode"), "cap_add": list(c.get("cap_add") or [])}


def _ssh_cap_signals(procs: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Over SSH there is no inspect document; the effective capabilities /proc shows are the
    one setting Kratos can still judge (CONT-006)."""
    by_cid: dict[str, set[str]] = {}
    full: set[str] = set()
    for p in procs.values():
        cid = p["container"]
        by_cid.setdefault(cid, set()).update(caps_from_mask(p.get("capeff")))
        if is_full_mask(p.get("capeff")):
            full.add(cid)
    out = []
    for cid, caps in sorted(by_cid.items()):
        if not caps:
            continue
        c = {"id": cid, "name": cid[:12], "image": "", "image_id": ""}
        sev = "high" if caps & set(HIGH_CAPS) else "medium"
        ev = [f"Processes of container {cid[:12]} run with these capabilities in effect: {', '.join(sorted(caps))} "
              "(read from /proc over SSH; the container's name and image are only readable through the sub-agent)."]
        if cid in full:
            ev.append("They hold every capability -- this is how a privileged container looks, but whether it was "
                      "started with --privileged can only be read through the sub-agent.")
        out.append(_sig("CONT-006", sev, c, "A container runs with powerful capabilities: " + ", ".join(sorted(caps)), [f"cap:{x}" for x in sorted(caps)], ev,
                        ["Find the container (`docker ps --no-trunc | grep " + cid[:12] + "`) and remove the "
                         "capabilities it doesn't need."]))
    return out


def _ssh_rows(procs: dict[int, dict[str, Any]], inv: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    listen = {}
    for item in inv.get("listeners") or []:
        listen.setdefault(item["container"], []).append(item)
    for p in sorted(procs.values(), key=lambda x: x["container"]):
        r = rows.setdefault(p["container"], {"id": p["container"], "name": p["container"][:12], "image": "?",
                                             "digest": "", "user": "", "running": True, "state": "running",
                                             "engine": p["engine"], "ports": [], "risks": [], "compose": None,
                                             "env_keys": [], "labels": {}, "mounts": [], "network_mode": "",
                                             "cap_add": [], "programs": []})
        if p.get("comm") and p["comm"] not in r["programs"]:
            r["programs"].append(p["comm"])
        if not r["user"] and p.get("uid") is not None:
            r["user"] = f"uid {p['uid']}"
    for cid, r in rows.items():
        from kratos.live.record import proc_net_address

        for it in listen.get(cid, []):
            addr, _, port = it["local"].partition(":")
            r["ports"].append(f"listens {proc_net_address(addr) or '?'}:{int(port, 16)}/{it['proto'].rstrip('6')} "
                              "(inside the container)")
    return list(rows.values())
