"""Source and peer buckets, without outside data (E.3 §3.2).

No GeoIP, no ASN: a model handed "203.0.113.7" invents a country for it, and a private
address has none (the 2026-09 finding). An address is bucketed by its own shape:

- IPv4 public -> its /24; private (10/8, 172.16/12, 192.168/16), CGNAT and tailnet
  (100.64/10), link-local -> its /24 with that class;
- IPv6 public -> its /48; unique-local (fc00::/7) -> its /64; link-local -> fe80::/10;
- loopback -> one bucket of its own.

The bucket and its class are what is learned and shown; the exact address goes in the
evidence. A bucket that isn't an address (a hostname sshd logged, garbage) is
`unknown:<text>` -- never called public.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

CLASSES = ("public", "private", "tailnet", "link-local", "loopback", "ula", "unknown")
CLASS_WORDS = {"public": "public internet", "private": "private network", "tailnet": "CGNAT / tailnet range",
               "link-local": "link-local", "loopback": "this machine itself", "ula": "IPv6 unique-local",
               "unknown": "not an address"}

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
# Documentation ranges (RFC 5737, RFC 3849) never appear on a real network; they stand for
# "somewhere on the internet" in tests and examples, so they bucket as public. Python's
# ipaddress calls them private, which is why the classes here are spelled out.
_DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                          "2001:db8::/32"))
_ULA = ipaddress.ip_network("fc00::/7")
_V6_LINK = ipaddress.ip_network("fe80::/10")


@dataclass(frozen=True)
class Bucket:
    bucket: str           # "203.0.113.0/24", "fd12:3456:789a:1::/64", "loopback", "unknown:<text>"
    cls: str              # one of CLASSES

    @property
    def label(self) -> str:
        return f"{self.bucket} ({CLASS_WORDS[self.cls]})"

    @property
    def public(self) -> bool:
        return self.cls == "public"


def bucket(value: object) -> Bucket:
    text = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        clean = "".join(ch for ch in text if ch.isprintable())[:64] or "?"
        return Bucket(f"unknown:{clean}", "unknown")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return Bucket("loopback", "loopback")
    if isinstance(ip, ipaddress.IPv4Address):
        net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        if ip in _CGNAT:
            return Bucket(net, "tailnet")
        if ip.is_link_local:
            return Bucket(net, "link-local")
        if any(ip in n for n in _RFC1918):
            return Bucket(net, "private")
        if any(ip in n for n in _DOCUMENTATION) or ip.is_global:
            return Bucket(net, "public")
        return Bucket(net, "private")          # other special-purpose ranges: not the internet
    if ip in _V6_LINK:
        return Bucket("fe80::/10", "link-local")
    if ip in _ULA:
        return Bucket(str(ipaddress.ip_network(f"{ip}/64", strict=False)), "ula")
    if any(ip in n for n in _DOCUMENTATION) or ip.is_global:
        return Bucket(str(ipaddress.ip_network(f"{ip}/48", strict=False)), "public")
    return Bucket(str(ipaddress.ip_network(f"{ip}/64", strict=False)), "private")
