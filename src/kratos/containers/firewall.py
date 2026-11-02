"""A minimal firewall model -- just enough to answer "does traffic from the internet reach
this published container port, and would the firewall have refused it on INPUT?" (D.5 §3.3).

The model walks ONE hypothetical packet through the rules and returns a verdict:

- ``accept`` -- every rule it met was understood, and none dropped it;
- ``drop``   -- a rule it understood drops (or rejects) it;
- ``unknown`` -- it met a rule it can't evaluate that could decide the packet.

Anything the model doesn't understand is ``unknown`` ("can't tell"), never ``accept``.

Two rule sources:

- ``iptables-save`` output (both the legacy and the nf_tables flavour print the same
  text). The walk follows the built-in chain from the top, into user chains (jumps and
  gotos), honours RETURN, non-terminating targets (LOG, NFLOG, ...) and the chain policy;
- ``nft -j list ruleset``: every base chain of type ``filter`` on the hook in question.
  Tables iptables-nft maintains (``filter``, ``mangle``, ``raw``, ``nat``, ``security`` in
  the ``ip``/``ip6`` families) are left to the iptables walk, and Docker's own table
  (``docker-bridges``) is Docker's: it accepts the published traffic Kratos asks about.

On a netfilter hook every base chain sees the packet in turn: ``accept`` only ends one
chain, ``drop`` is final. So a packet passes the hook when no chain drops it -- whatever
their priorities -- and the combined verdict is the worst of the chains'.

The packet: a new TCP/UDP connection from an address on the public internet
(``INTERNET_SOURCE_V4``/``_V6``), arriving on the interface that holds the default route.
Before Docker's DNAT it is addressed to the machine's published port; after it, to the
container's address and port, with the original destination in conntrack -- exactly what
``-m conntrack --ctorigdstport`` and ``ct original proto-dst`` see.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field, replace
from typing import Any

INTERNET_SOURCE_V4 = "203.0.113.10"       # stands for "an address on the public internet"
INTERNET_SOURCE_V6 = "2001:db8::10"
MAX_DEPTH = 32
IPT_TABLES = ("raw", "mangle", "nat", "filter", "security")
DOCKER_NFT_TABLES = ("docker-bridges",)
_DOCKER_BRIDGE_RE = re.compile(r"^(docker\d+|br-[0-9a-f]{12}|podman\d+|cni-podman\d+)$")
_NON_TERMINATING = frozenset({"LOG", "NFLOG", "ULOG", "TRACE", "MARK", "CONNMARK", "CT", "AUDIT", "TCPMSS",
                              "CHECKSUM", "TOS", "DSCP", "TTL", "HL", "CLASSIFY", "NOTRACK", "SET", "TEE"})

ACCEPT, DROP, UNKNOWN, RETURN = "accept", "drop", "unknown", "return"


@dataclass(frozen=True)
class Packet:
    family: int                      # 4 | 6
    proto: str                       # tcp | udp
    src: str
    dst: str
    dport: int
    in_iface: str | None             # None: not known (no default route was read)
    out_iface: str | None = None     # set after DNAT: the container's bridge
    orig_dst: str | None = None      # conntrack's original destination (the machine's address)
    orig_dport: int | None = None    # ... and port (the published port)
    dst_local: bool = True           # before DNAT the packet is for the machine itself
    sport: int = 40000

    def pre_dnat(self) -> "Packet":
        return replace(self, dst=self.orig_dst or self.dst, dport=self.orig_dport or self.dport,
                       out_iface=None, dst_local=True)


@dataclass
class Decision:
    verdict: str                     # accept | drop | unknown
    where: str = ""                  # the rule (or policy) that decided, in the source's own words
    reason: str = ""                 # for unknown: what could not be evaluated

    def as_dict(self) -> dict[str, str]:
        return {"verdict": self.verdict, "where": self.where, "reason": self.reason}


# =========================================================================== iptables
@dataclass
class IptRule:
    chain: str
    text: str
    conds: list[tuple[str, bool, list[str]]] = field(default_factory=list)   # (option, negated, args)
    target: str | None = None
    goto: bool = False
    bad: str = ""                    # why the rule could not be parsed (the rule is then unknown)


@dataclass
class IptChain:
    name: str
    policy: str | None               # None for a user chain
    rules: list[IptRule] = field(default_factory=list)


# option -> number of arguments
_IPT_OPTS = {"-s": 1, "--source": 1, "-d": 1, "--destination": 1, "-i": 1, "--in-interface": 1,
             "-o": 1, "--out-interface": 1, "-p": 1, "--protocol": 1, "-m": 1, "--match": 1,
             "--dport": 1, "--destination-port": 1, "--sport": 1, "--source-port": 1, "--dports": 1,
             "--sports": 1, "--ports": 1, "--ctstate": 1, "--state": 1, "--ctorigdstport": 1, "--ctorigdst": 1,
             "--ctorigsrc": 1, "--ctdir": 1, "--ctproto": 1, "--dst-type": 1, "--src-type": 1,
             "--limit-iface-in": 0, "--limit-iface-out": 0, "--tcp-flags": 2, "--syn": 0, "--comment": 1,
             "--icmp-type": 1, "--icmpv6-type": 1, "--limit": 1, "--limit-burst": 1, "--hl-eq": 1,
             "--hl-lt": 1, "--hl-gt": 1, "--rt-type": 1, "--rt-segsleft": 1, "-f": 0, "--fragment": 0}


def parse_iptables_save(text: str) -> dict[str, dict[str, IptChain]]:
    tables: dict[str, dict[str, IptChain]] = {}
    cur: dict[str, IptChain] | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            cur = tables.setdefault(line[1:].strip(), {})
        elif line == "COMMIT":
            cur = None
        elif cur is not None and line.startswith(":"):
            parts = line[1:].split()
            if parts:
                cur[parts[0]] = IptChain(parts[0], None if len(parts) < 2 or parts[1] == "-" else parts[1])
        elif cur is not None and line.startswith("-A "):
            rule = _parse_ipt_rule(line)
            chain = cur.setdefault(rule.chain, IptChain(rule.chain, None))
            chain.rules.append(rule)
    return tables


def _parse_ipt_rule(line: str) -> IptRule:
    try:
        toks = shlex.split(line)
    except ValueError:
        parts = line.split()
        return IptRule(chain=parts[1] if len(parts) > 1 else "?", text=line, bad="unparseable quoting")
    rule = IptRule(chain=toks[1] if len(toks) > 1 else "?", text=line)
    i, neg = 2, False
    while i < len(toks):
        t = toks[i]
        if t == "!":
            neg, i = True, i + 1
            continue
        if t in ("-j", "--jump", "-g", "--goto"):
            rule.target = toks[i + 1] if i + 1 < len(toks) else None
            rule.goto = t in ("-g", "--goto")
            break                              # everything after the target is its own options
        n = _IPT_OPTS.get(t)
        if n is None:
            rule.conds.append((t, neg, []))   # an option this model doesn't know -> unknown
            neg, i = False, i + 1
            # skip its arguments (anything up to the next option)
            while i < len(toks) and not toks[i].startswith("-") and toks[i] != "!":
                i += 1
            continue
        rule.conds.append((t, neg, toks[i + 1:i + 1 + n]))
        neg, i = False, i + 1 + n
    return rule


def _in_net(addr: str | None, cidr: str, family: int) -> bool | None:
    if addr is None:
        return None
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if net.version != family or ip.version != family:
        return False
    return ip in net


def _iface_match(name: str | None, pattern: str) -> bool | None:
    if pattern.endswith("+"):
        stem = pattern[:-1]
        if name is not None:
            return name.startswith(stem)
        return False if stem in ("lo", "docker", "br-", "podman", "cni-podman") else None
    if name is not None:
        return name == pattern
    # an unknown incoming interface: it is surely not loopback or a container bridge
    return False if pattern == "lo" or _DOCKER_BRIDGE_RE.match(pattern) else None


def _port_in(port: int | None, spec: str) -> bool | None:
    if port is None:
        return None
    for part in spec.split(","):
        lo, _, hi = part.partition(":")
        try:
            a = int(lo) if lo else 0
            b = int(hi) if hi else (a if not _ else 65535)
        except ValueError:
            return None
        if a <= port <= b:
            return True
    return False


_PROTO_NUM = {"tcp": "6", "udp": "17"}


def _ipt_cond(opt: str, args: list[str], pkt: Packet, modules: set[str]) -> bool | None:
    a = args[0] if args else ""
    if opt in ("-s", "--source"):
        return _in_net(pkt.src, a, pkt.family)
    if opt in ("-d", "--destination"):
        return _in_net(pkt.dst, a, pkt.family)
    if opt in ("-i", "--in-interface"):
        return _iface_match(pkt.in_iface, a)
    if opt in ("-o", "--out-interface"):
        return _iface_match(pkt.out_iface, a) if pkt.out_iface is not None else False
    if opt in ("-p", "--protocol"):
        a = a.lower()
        return a in ("all", "0", pkt.proto, _PROTO_NUM.get(pkt.proto, ""))
    if opt in ("-m", "--match", "--comment", "--limit-iface-in", "--limit-iface-out", "--limit-burst"):
        return True
    if opt in ("--dport", "--destination-port", "--dports"):
        return _port_in(pkt.dport, a)
    if opt in ("--sport", "--source-port", "--sports"):
        return _port_in(pkt.sport, a)
    if opt == "--ports":
        return bool(_port_in(pkt.dport, a)) or bool(_port_in(pkt.sport, a))
    if opt in ("--ctstate", "--state"):
        return "NEW" in a.upper().split(",")
    if opt == "--ctorigdstport":
        return _port_in(pkt.orig_dport, a)
    if opt == "--ctorigdst":
        return _in_net(pkt.orig_dst, a, pkt.family)
    if opt == "--ctorigsrc":
        return _in_net(pkt.src, a, pkt.family)
    if opt == "--ctdir":
        return a.upper() == "ORIGINAL"
    if opt == "--ctproto":
        return a.lower() in (pkt.proto, _PROTO_NUM.get(pkt.proto, ""))
    if opt == "--dst-type":
        types = a.upper().split(",")
        return ("LOCAL" in types and pkt.dst_local) or "UNICAST" in types
    if opt == "--src-type":
        types = a.upper().split(",")
        return "UNICAST" in types
    if opt == "--tcp-flags":
        if pkt.proto != "tcp" or len(args) < 2:
            return False if pkt.proto != "tcp" else None
        mask = set(args[0].upper().split(","))
        comp = set(args[1].upper().split(",")) - {"NONE"}
        if "ALL" in mask:
            mask = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"}
        return ({"SYN"} & mask) == comp
    if opt == "--syn":
        return pkt.proto == "tcp"
    if opt in ("--rt-type", "--rt-segsleft"):
        return False                       # a plain packet carries no IPv6 routing header
    if opt in ("-f", "--fragment"):
        return False
    return None                            # icmp types, limits, hop limits, unknown modules


def _ipt_match(rule: IptRule, pkt: Packet) -> tuple[bool | None, str]:
    """True / False / None (can't tell), and what couldn't be told."""
    if rule.bad:
        return None, rule.bad
    modules: set[str] = set()
    unknown = ""
    for opt, neg, args in rule.conds:
        if opt in ("-m", "--match") and args:
            modules.add(args[0])
        r = _ipt_cond(opt, args, pkt, modules)
        if r is not None and neg:
            r = not r
        if r is False:
            return False, ""
        if r is None and not unknown:
            unknown = f"{opt} {' '.join(args)}".strip()
    return (None, unknown) if unknown else (True, "")


def eval_ipt_chain(tables: dict[str, dict[str, IptChain]], table: str, chain: str, pkt: Packet,
                   _depth: int = 0) -> Decision:
    """The verdict of `chain` (built-in: ending in its policy; user chain: "return")."""
    chains = tables.get(table) or {}
    ch = chains.get(chain)
    if ch is None:
        return Decision(RETURN if _depth else ACCEPT, f"{table}/{chain} (no such chain)")
    if _depth > MAX_DEPTH:
        return Decision(UNKNOWN, f"{table}/{chain}", "the rules jump too deep to follow")
    for rule in ch.rules:
        target = rule.target
        if target is None or target in _NON_TERMINATING:
            continue
        m, why = _ipt_match(rule, pkt)
        if m is False:
            continue
        if target in chains and target not in ("ACCEPT", "DROP", "REJECT", "RETURN"):
            sub = eval_ipt_chain(tables, table, target, pkt, _depth + 1)
            if sub.verdict == RETURN:
                if rule.goto and m is True:
                    return Decision(RETURN if _depth else _policy(ch), sub.where)
                if rule.goto and m is None:
                    return Decision(UNKNOWN, rule.text, f"can't tell whether this rule applies ({why})")
                continue
            if m is True or sub.verdict == UNKNOWN:
                return sub if sub.verdict != UNKNOWN or m is True else Decision(UNKNOWN, rule.text, why or sub.reason)
            return Decision(UNKNOWN, rule.text, f"can't tell whether this rule applies ({why})")
        verdict = {"ACCEPT": ACCEPT, "DROP": DROP, "REJECT": DROP, "RETURN": RETURN}.get(target)
        if verdict is None:
            if m is True:
                return Decision(UNKNOWN, rule.text, f"target {target} is not modelled")
            return Decision(UNKNOWN, rule.text, f"can't tell whether this rule applies ({why})")
        if m is None:
            return Decision(UNKNOWN, rule.text, f"can't tell whether this rule applies ({why})")
        if verdict == RETURN:
            return Decision(RETURN if _depth else _policy(ch), rule.text)
        return Decision(verdict, rule.text)
    if _depth:
        return Decision(RETURN, f"{table}/{chain} (end)")
    return Decision(_policy(ch), f"{table}/{chain} policy {ch.policy or 'ACCEPT'}")


def _policy(ch: IptChain) -> str:
    return DROP if (ch.policy or "ACCEPT").upper() in ("DROP", "REJECT") else ACCEPT


# =========================================================================== nftables
@dataclass
class NftChain:
    family: str
    table: str
    name: str
    hook: str | None
    prio: int | None
    policy: str
    ctype: str
    rules: list[list[dict[str, Any]]] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)


# Transport headers a TCP/UDP packet doesn't carry (an nft match on one of their fields is false).
_OTHER_L4 = frozenset({"icmp", "icmpv6", "sctp", "dccp", "udplite", "igmp", "esp", "ah", "comp", "tcp", "udp"})
_PRIO_NAMES = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}


def parse_nft_json(data: Any) -> dict[tuple[str, str, str], NftChain]:
    chains: dict[tuple[str, str, str], NftChain] = {}
    for item in (data or {}).get("nftables", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        if "chain" in item and isinstance(item["chain"], dict):
            c = item["chain"]
            prio = c.get("prio")
            if isinstance(prio, str):
                prio = _PRIO_NAMES.get(prio)
            key = (str(c.get("family")), str(c.get("table")), str(c.get("name")))
            chains[key] = NftChain(key[0], key[1], key[2], c.get("hook"), prio if isinstance(prio, int) else None,
                                   str(c.get("policy") or "accept"), str(c.get("type") or ""))
        elif "rule" in item and isinstance(item["rule"], dict):
            r = item["rule"]
            key = (str(r.get("family")), str(r.get("table")), str(r.get("chain")))
            ch = chains.get(key)
            if ch is not None and isinstance(r.get("expr"), list):
                ch.rules.append(r["expr"])
                ch.texts.append(str(r.get("comment") or "") or _expr_text(r["expr"]))
    return chains


def _expr_text(exprs: list[dict[str, Any]]) -> str:
    out = []
    for e in exprs[:12]:
        if isinstance(e, dict) and e:
            k = next(iter(e))
            out.append(k if k != "match" else f"match {_short(e[k])}")
    return " ".join(out)[:300]


def _short(m: Any) -> str:
    try:
        left = m.get("left")
        if isinstance(left, dict):
            k = next(iter(left))
            v = left[k]
            name = v.get("key") or v.get("field") if isinstance(v, dict) else k
            return f"{name} {m.get('op')} {m.get('right')}"[:80]
    except Exception:  # noqa: BLE001
        pass
    return "?"


def _nft_value(left: Any, pkt: Packet, pre: bool) -> Any:
    """The packet's value for an expression's left side, or _UNK."""
    if not isinstance(left, dict) or len(left) != 1:
        return _UNK
    kind, spec = next(iter(left.items()))
    if not isinstance(spec, dict):
        return _UNK
    if kind == "meta":
        key = spec.get("key")
        if key in ("iifname", "iif"):
            return pkt.in_iface if pkt.in_iface is not None else _UNK
        if key in ("oifname", "oif"):
            return pkt.out_iface if not pre and pkt.out_iface is not None else ("" if pre else _UNK)
        if key == "l4proto":
            return pkt.proto
        if key == "nfproto":
            return "ipv4" if pkt.family == 4 else "ipv6"
        return _UNK
    if kind == "payload":
        proto, fld = spec.get("protocol"), spec.get("field")
        if proto in ("ip", "ip6"):
            if (proto == "ip") != (pkt.family == 4):
                return _ABSENT
            if fld == "saddr":
                return pkt.src
            if fld == "daddr":
                return pkt.dst
            if fld in ("protocol", "nexthdr"):
                return pkt.proto
            return _UNK
        if proto in _OTHER_L4 and proto != pkt.proto:
            return _ABSENT                      # an ICMP / SCTP / ... header on a TCP or UDP packet
        if proto in ("tcp", "udp", "th"):
            if proto in ("tcp", "udp") and proto != pkt.proto:
                return _ABSENT
            if fld == "dport":
                return pkt.dport
            if fld == "sport":
                return pkt.sport
            return _UNK
        return _UNK
    if kind == "ct":
        key, d = spec.get("key"), spec.get("dir")
        if key == "state":
            return ["new"]
        if key == "direction":
            return "original"
        if key == "proto-dst" and d in ("original", None):
            return pkt.orig_dport if pkt.orig_dport is not None else pkt.dport
        if key == "daddr" and d in ("original", None):
            return pkt.orig_dst or pkt.dst
        if key == "saddr":
            return pkt.src
        if key == "l3proto":
            return "ipv4" if pkt.family == 4 else "ipv6"
        if key == "protocol":
            return pkt.proto
        return _UNK
    return _UNK


class _Sentinel:
    def __init__(self, name: str):
        self.name = name


_UNK = _Sentinel("unknown")
_ABSENT = _Sentinel("absent")       # the header isn't there (an ip6 field on an IPv4 packet)


def _nft_eq(value: Any, right: Any, family: int) -> bool | None:
    if isinstance(right, dict):
        if "prefix" in right and isinstance(right["prefix"], dict):
            return _in_net(str(value), f"{right['prefix'].get('addr')}/{right['prefix'].get('len')}", family)
        if "range" in right and isinstance(right["range"], list) and len(right["range"]) == 2:
            lo, hi = right["range"]
            if isinstance(value, int) and isinstance(lo, int) and isinstance(hi, int):
                return lo <= value <= hi
            return None
        if "set" in right and isinstance(right["set"], list):
            results = [_nft_eq(value, el, family) for el in right["set"]]
            if any(r is True for r in results):
                return True
            return None if any(r is None for r in results) else False
        return None
    if isinstance(right, list):
        if isinstance(value, list):
            return bool(set(map(str, value)) & set(map(str, right)))
        return str(value) in map(str, right)
    if isinstance(right, str) and right.startswith("@"):
        return None                         # a named set: not modelled
    if isinstance(value, list):
        return str(right) in map(str, value)
    if isinstance(right, str) and isinstance(value, str) and ("." in right or ":" in right):
        r = _in_net(value, right, family)
        if r is not None:
            return r
    if isinstance(right, str) and right.endswith("*") and isinstance(value, str):
        return value.startswith(right[:-1])
    return str(value) == str(right)


def _nft_match(m: dict[str, Any], pkt: Packet, pre: bool) -> bool | None:
    value = _nft_value(m.get("left"), pkt, pre)
    op = m.get("op", "==")
    if value is _ABSENT:
        return False
    if value is _UNK:
        # an interface the packet surely doesn't use
        left = m.get("left") or {}
        meta = left.get("meta") if isinstance(left, dict) else None
        right = m.get("right")
        if isinstance(meta, dict) and meta.get("key") in ("iifname", "iif") and isinstance(right, str) \
                and op == "==" and (right == "lo" or _DOCKER_BRIDGE_RE.match(right)):
            return False
        return None
    if op in ("==", "in"):
        return _nft_eq(value, m.get("right"), pkt.family)
    if op == "!=":
        r = _nft_eq(value, m.get("right"), pkt.family)
        return None if r is None else not r
    if op in ("<", ">", "<=", ">=") and isinstance(value, int) and isinstance(m.get("right"), int):
        r = m["right"]
        return {"<": value < r, ">": value > r, "<=": value <= r, ">=": value >= r}[op]
    return None


_NFT_PASSIVE = frozenset({"counter", "log", "comment", "notrack", "mangle", "meta", "ct count"})


def eval_nft_chain(chains: dict[tuple[str, str, str], NftChain], key: tuple[str, str, str], pkt: Packet,
                   pre: bool, _depth: int = 0) -> Decision:
    ch = chains.get(key)
    if ch is None:
        return Decision(UNKNOWN, f"{key[0]} {key[1]} {key[2]}", "a jump to a chain that isn't listed")
    if _depth > MAX_DEPTH:
        return Decision(UNKNOWN, f"{ch.table}/{ch.name}", "the rules jump too deep to follow")
    where = f"table {ch.family} {ch.table} chain {ch.name}"
    for idx, exprs in enumerate(ch.rules):
        text = f"{where}: {ch.texts[idx] if idx < len(ch.texts) else ''}".strip()
        state: bool | None = True
        decided: Decision | None = None
        for e in exprs:
            if not isinstance(e, dict) or len(e) != 1:
                state = None if state else state
                continue
            k, v = next(iter(e.items()))
            if k == "match":
                r = _nft_match(v if isinstance(v, dict) else {}, pkt, pre)
                if r is False:
                    state = False
                    break
                if r is None:
                    state = None
                continue
            if k in _NFT_PASSIVE:
                continue
            if k in ("accept", "drop", "reject", "return"):
                verdict = {"accept": ACCEPT, "drop": DROP, "reject": DROP, "return": RETURN}[k]
                decided = Decision(verdict, text) if state is True else Decision(UNKNOWN, text, "can't tell whether this rule applies")
                break
            if k in ("jump", "goto") and isinstance(v, dict):
                sub = eval_nft_chain(chains, (ch.family, ch.table, str(v.get("target"))), pkt, pre, _depth + 1)
                if sub.verdict == RETURN:
                    if k == "goto" and state is True:
                        decided = Decision(RETURN if _depth else ACCEPT, sub.where)
                        break
                    continue
                decided = sub if state is True else Decision(UNKNOWN, text, "can't tell whether this rule applies")
                break
            # limit, quota, xt (an iptables match inside nft), vmap, queue, set updates, ...
            state = None if state is True else state
            if k in ("limit", "quota", "xt", "meter", "set", "map", "vmap", "queue", "fwd", "dup", "synproxy"):
                continue
        if state is False:
            continue
        if decided is not None:
            if decided.verdict == RETURN:
                return Decision(RETURN if _depth else ACCEPT, text)
            return decided
    if _depth:
        return Decision(RETURN, f"{where} (end)")
    return Decision(DROP if ch.policy == "drop" else ACCEPT, f"{where} policy {ch.policy}")


# =========================================================================== combining
@dataclass
class Ruleset:
    ipt: dict[int, dict[str, dict[str, IptChain]]]          # family -> iptables-save tables
    nft: dict[tuple[str, str, str], NftChain]
    have_ipt: dict[int, bool]
    have_nft: bool
    docker_backend: str = ""                                  # iptables | nftables | ""

    def nft_base_chains(self, family: int, hook: str) -> list[tuple[tuple[str, str, str], NftChain]]:
        fams = ("ip", "inet") if family == 4 else ("ip6", "inet")
        out = []
        for key, ch in self.nft.items():
            if ch.family not in fams or ch.hook != hook or ch.ctype not in ("filter", ""):
                continue
            if ch.table in DOCKER_NFT_TABLES:
                continue
            if self.have_ipt.get(family) and ch.family in ("ip", "ip6") and ch.table in IPT_TABLES:
                continue                      # iptables-nft's own tables: the iptables walk covers them
            out.append((key, ch))
        return sorted(out, key=lambda kv: (kv[1].prio if kv[1].prio is not None else 0, kv[0]))


def ruleset_from(firewall: dict[str, Any], docker_backend: str = "") -> Ruleset:
    import json

    ipt: dict[int, dict[str, dict[str, IptChain]]] = {}
    have_ipt = {4: False, 6: False}
    for family, kind in ((4, "iptables"), (6, "ip6tables")):
        fw = firewall.get(kind) or {}
        if fw.get("status") == "ok" and fw.get("text"):
            ipt[family] = parse_iptables_save(fw["text"])
            have_ipt[family] = True
    nft: dict[tuple[str, str, str], NftChain] = {}
    have_nft = False
    fw = firewall.get("nft") or {}
    if fw.get("status") == "ok" and fw.get("text"):
        try:
            nft = parse_nft_json(json.loads(fw["text"]))
            have_nft = True
        except ValueError:
            nft = {}
    return Ruleset(ipt, nft, have_ipt, have_nft, docker_backend)


def _worst(decisions: list[Decision]) -> Decision:
    for d in decisions:
        if d.verdict == DROP:
            return d
    for d in decisions:
        if d.verdict == UNKNOWN:
            return d
    # several chains accepted: name the last one (the forwarding chain's own rule, not a
    # pre-routing chain's policy)
    return next((d for d in reversed(decisions) if d.verdict == ACCEPT), Decision(ACCEPT, "no rules on this path"))


def hook_verdict(rs: Ruleset, pkt: Packet, hook: str) -> Decision:
    """The packet's verdict through one hook (`forward` after DNAT, or `input`), counting
    the pre-routing chains that run before DNAT too."""
    decisions: list[Decision] = []
    ipt = rs.ipt.get(pkt.family)
    pre = pkt.pre_dnat()
    if ipt is not None:
        for table, chain, p in (("raw", "PREROUTING", pre), ("mangle", "PREROUTING", pre)):
            if chain in (ipt.get(table) or {}):
                decisions.append(eval_ipt_chain(ipt, table, chain, p))
        if hook == "forward":
            for table in ("mangle", "filter", "security"):
                if "FORWARD" in (ipt.get(table) or {}):
                    decisions.append(eval_ipt_chain(ipt, table, "FORWARD", pkt))
        else:
            for table in ("mangle", "filter", "security"):
                if "INPUT" in (ipt.get(table) or {}):
                    decisions.append(eval_ipt_chain(ipt, table, "INPUT", pre))
    if rs.have_nft:
        for key, ch in rs.nft_base_chains(pkt.family, "prerouting"):
            before_dnat = ch.prio is None or ch.prio < _PRIO_NAMES["dstnat"]
            decisions.append(eval_nft_chain(rs.nft, key, pre if before_dnat else pkt, before_dnat))
        for key, _ch in rs.nft_base_chains(pkt.family, hook):
            decisions.append(eval_nft_chain(rs.nft, key, pkt if hook == "forward" else pre, hook != "forward"))
    return _worst([d for d in decisions if d.verdict != RETURN] or [Decision(ACCEPT, "no rules on this path")])


@dataclass
class PortJudgement:
    family: int
    host_port: int
    proto: str
    path: str                        # forwarded | proxied | not_published_here
    forward: Decision | None         # through the forward hook (after Docker's DNAT)
    input: Decision | None           # what the firewall would do to the same port on INPUT
    bypass: str                      # yes | no | unknown
    why: str

    def as_dict(self) -> dict[str, Any]:
        return {"family": self.family, "host_port": self.host_port, "proto": self.proto, "path": self.path,
                "forward": self.forward.as_dict() if self.forward else None,
                "input": self.input.as_dict() if self.input else None, "bypass": self.bypass, "why": self.why}


def judge_port(rs: Ruleset, *, family: int, proto: str, host_port: int, container_port: int,
               container_ip: str | None, bridge: str | None, host_addr: str | None,
               in_iface: str | None, forwarded: bool) -> PortJudgement:
    """Is this published port reachable from the internet although the firewall would
    refuse the same port on INPUT? `forwarded`: the published traffic of this family is
    forwarded to the container (Docker's DNAT) -- False when it is served by Docker's
    userland proxy on the machine itself (an IPv6 binding on a network without IPv6),
    which INPUT governs like any other local service."""
    src = INTERNET_SOURCE_V4 if family == 4 else INTERNET_SOURCE_V6
    host = host_addr or ("198.51.100.1" if family == 4 else "2001:db8::1")
    inp_pkt = Packet(family, proto, src, host, host_port, in_iface)
    readable = bool(rs.have_ipt.get(family) or rs.have_nft)
    if not forwarded:
        inp_p = hook_verdict(rs, replace(inp_pkt, orig_dst=host, orig_dport=host_port), "input") if readable else None
        return PortJudgement(family, host_port, proto, "proxied", None, inp_p, "no",
                             "this family is answered by Docker's proxy on the machine itself, so the firewall's "
                             "INPUT rules apply to it like to any other service")
    if not readable:
        return PortJudgement(family, host_port, proto, "forwarded", None, None, "unknown",
                             "the firewall rules could not be read")
    inp = hook_verdict(rs, replace(inp_pkt, orig_dst=host, orig_dport=host_port), "input")
    if container_ip is None:
        return PortJudgement(family, host_port, proto, "forwarded", None, inp, "unknown",
                             "the container's address on its network was not reported")
    fwd_pkt = Packet(family, proto, src, container_ip, container_port, in_iface, bridge, host, host_port, False)
    fwd = hook_verdict(rs, fwd_pkt, "forward")
    if fwd.verdict == DROP:
        return PortJudgement(family, host_port, proto, "forwarded", fwd, inp, "no",
                             "a rule on the forwarding path drops it")
    if fwd.verdict == UNKNOWN:
        return PortJudgement(family, host_port, proto, "forwarded", fwd, inp, "unknown",
                             f"can't tell what the forwarding rules do with it ({fwd.reason})")
    if inp.verdict == ACCEPT:
        return PortJudgement(family, host_port, proto, "forwarded", fwd, inp, "no",
                             "the firewall allows this port on INPUT too, so it is meant to be open")
    if inp.verdict == UNKNOWN:
        return PortJudgement(family, host_port, proto, "forwarded", fwd, inp, "unknown",
                             f"reachable, but can't tell whether the firewall means to refuse it ({inp.reason})")
    return PortJudgement(family, host_port, proto, "forwarded", fwd, inp, "yes",
                         "the firewall refuses this port on INPUT, but published container traffic is forwarded "
                         "before those rules and nothing on the forwarding path drops it")


# =========================================================================== published ports from Docker's own rules
_TO_DEST = re.compile(r"--to-destination\s+(\[?[0-9A-Fa-f:.]+\]?):(\d{1,5})\b")


def _bridge_of(conds: list[tuple[str, bool, list[str]]]) -> str | None:
    for opt, neg, args in conds:
        if opt in ("-i", "--in-interface") and neg and args and _DOCKER_BRIDGE_RE.match(args[0]):
            return args[0]
    return None


def published_from_rules(rs: Ruleset) -> list[dict[str, Any]]:
    """The ports Docker publishes, read from its own NAT rules (iptables ``-j DNAT
    --to-destination`` in the nat table, or ``dnat`` in the docker-bridges table) --
    what lets a login that may read the firewall rules (the pinned sudo lines) judge the
    bypass without the engine's API. [{family, proto, host_ip, host_port, container_ip,
    container_port, bridge}]"""
    out: list[dict[str, Any]] = []
    for family, tables in rs.ipt.items():
        for chain in (tables.get("nat") or {}).values():
            for rule in chain.rules:
                if rule.target != "DNAT":
                    continue
                m = _TO_DEST.search(rule.text)
                c = {o: (neg, a) for o, neg, a in rule.conds}
                proto = (c.get("-p") or c.get("--protocol") or (False, [""]))[1][0]
                dport = (c.get("--dport") or c.get("--destination-port") or (False, [""]))[1][0]
                if not m or proto not in ("tcp", "udp") or not dport.isdigit():
                    continue
                dst = c.get("-d") or c.get("--destination")
                host_ip = dst[1][0].split("/")[0] if dst and not dst[0] else ("::" if family == 6 else "0.0.0.0")
                out.append({"family": family, "proto": proto, "host_ip": host_ip, "host_port": int(dport),
                            "container_ip": m.group(1).strip("[]"), "container_port": int(m.group(2)),
                            "bridge": _bridge_of(rule.conds)})
    for key, ch in rs.nft.items():
        if ch.table not in DOCKER_NFT_TABLES:
            continue
        for exprs in ch.rules:
            dn = next((e["dnat"] for e in exprs if isinstance(e, dict) and isinstance(e.get("dnat"), dict)), None)
            if not dn or not isinstance(dn.get("port"), int):
                continue
            proto, dport, host_ip, bridge = None, None, None, None
            for e in exprs:
                mm = e.get("match") if isinstance(e, dict) else None
                if not isinstance(mm, dict):
                    continue
                left = mm.get("left") or {}
                pl, meta = left.get("payload") or {}, left.get("meta") or {}
                if pl.get("field") == "dport" and pl.get("protocol") in ("tcp", "udp") and isinstance(mm.get("right"), int):
                    proto, dport = pl["protocol"], mm["right"]
                elif pl.get("field") == "daddr" and isinstance(mm.get("right"), str) and mm.get("op") == "==":
                    host_ip = mm["right"]
                elif meta.get("key") == "iifname" and mm.get("op") == "!=" and isinstance(mm.get("right"), str):
                    bridge = mm["right"]
            if proto is None or dport is None:
                continue
            family = 6 if ch.family == "ip6" else 4
            out.append({"family": family, "proto": proto, "host_ip": host_ip or ("::" if family == 6 else "0.0.0.0"),
                        "host_port": int(dport), "container_ip": str(dn.get("addr") or ""),
                        "container_port": int(dn["port"]), "bridge": bridge})
    seen, uniq = set(), []
    for pp in out:
        k = (pp["family"], pp["proto"], pp["host_ip"], pp["host_port"])
        if k not in seen:
            seen.add(k)
            uniq.append(pp)
    return uniq
