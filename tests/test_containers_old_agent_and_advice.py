"""D.5 seams: an agent older than 0.11.0 gets "update the agent" (nothing is sent), and no
text Kratos ships ever advises the docker group or `sudo docker` (both root on the machine)."""
from __future__ import annotations

import re
from pathlib import Path

from kratos.subagent import protocol as proto
from kratos.subagent import reads

from test_subagent_read_channel import Harness, run

ROOT = Path(__file__).resolve().parents[1]


def test_container_reads_to_a_0_10_agent_are_refused_with_an_update_message(tmp_path, monkeypatch):
    real = proto.build_hello

    def old_hello(*a, **k):
        k["read_probes"] = [p for p in reads.READ_PROBES if not p.startswith("container_")]
        msg = real(*a, **k)
        msg["agent_version"] = "0.10.0"
        return msg

    monkeypatch.setattr(proto, "build_hello", old_hello)
    seen: list[str] = []
    real_run = reads.run_probe
    monkeypatch.setattr(reads, "run_probe", lambda probe, params: seen.append(probe) or real_run(probe, params))

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            for probe, params in (("container_inventory", {}), ("container_packages", {}),
                                  ("container_logs", {"container_id": "a" * 64}),
                                  ("journal_sync", {"match": "container"})):
                out = await h.read(tid, probe, params)
                assert out["status"] == "old_agent", (probe, out)
                assert "0.11.0" in out["reason"] and "`g` in /subagent" in out["reason"]
            assert not any(p.startswith("container_") for p in seen)
        finally:
            await h.stop()
    run(go())


def test_the_new_agent_offers_the_container_reads():
    from kratos.subagent import agent

    assert agent.AGENT_VERSION == "0.11.1"
    assert {"container_inventory", "container_packages", "container_logs"} <= set(reads.READ_PROBES)
    from kratos.subagent.installer import EXTRA_BUNDLE_FILES

    assert EXTRA_BUNDLE_FILES["containers.py"].name == "containers.py"


# Advice to join the docker group or to run docker with sudo, in any text Kratos ships.
_ADVICE = re.compile(r"usermod\s+-a?G\s*\S*docker|gpasswd\s+-a\s+\S+\s+docker|adduser\s+\S+\s+docker|"
                     r"newgrp\s+docker|NOPASSWD:\s*\S*docker|sudo\s+docker\b|sudo\s+podman\b")


def _shipped_texts():
    for p in sorted((ROOT / "src" / "kratos").rglob("*.py")):
        yield p, p.read_text(encoding="utf-8", errors="replace")
    for name in ("README.md", "docs/GUIDE.md", "docs/DESIGN.md", "SECURITY.md"):
        p = ROOT / name
        if p.exists():
            yield p, p.read_text(encoding="utf-8", errors="replace")


def test_nothing_kratos_ships_advises_the_docker_group_or_sudo_docker():
    hits = []
    for p, text in _shipped_texts():
        for m in _ADVICE.finditer(text):
            line = text[text.rfind("\n", 0, m.start()) + 1:text.find("\n", m.end())]
            # the sentences that say Kratos NEVER asks for it are the point, not advice (a sentence
            # may start on the line before)
            context = text[max(0, m.start() - 160):m.end()]
            if re.search(r"\bnever\b|\bnot\b|\bwithout\b|n't\b", context, re.IGNORECASE):
                continue
            hits.append(f"{p.relative_to(ROOT)}: {line.strip()}")
    assert hits == []


def test_the_checklist_pins_exactly_the_three_read_only_listings():
    from kratos.adapters import containers
    from kratos.adapters.target_setup import generate_target_setup_checklist

    text = generate_target_setup_checklist("192.0.2.10")
    lines = [ln for ln in text.splitlines() if "tables-save" in ln or "nft -j" in ln]
    assert [ln.split("NOPASSWD: ", 1)[1] for ln in lines] == [
        '/usr/sbin/iptables-save ""', '/usr/sbin/ip6tables-save ""', "/usr/sbin/nft -j list ruleset"]
    assert "docker" not in " ".join(ln for ln in text.splitlines() if "NOPASSWD" in ln)
    # the SSH script runs exactly what those lines allow
    script = containers.build_script()
    assert "kr_fw iptables iptables-save\n" in script and "kr_fw ip6tables ip6tables-save\n" in script
    assert "kr_fw nft nft -j list ruleset" in script
