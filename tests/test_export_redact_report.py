"""The redacted variant, the HTML report, the CASE/UCO graph and the written summary (D.6)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import _export_fixture as FX
from _untrusted_corpus import CORPUS
from kratos.export import create as C, narrative as N, report_html, verify as V
from kratos.export.scope import ExportRequest
from kratos.lifecycle.decide import Actor

ME = Actor(user="alice", interface="cli")


def _all_text(bundle: Path) -> str:
    out = []
    for p in sorted(bundle.rglob("*")):
        if p.is_file():
            out.append(p.relative_to(bundle).as_posix())
            out.append(p.read_bytes().decode("utf-8", "replace"))
    return "\n".join(out)


@pytest.fixture
def redacted(tmp_path):
    d = tmp_path / "data"
    info = FX.build(d)
    now = info["now"]
    r = C.create(d, ExportRequest(machines=[FX.M1, FX.M2], start=now - 86400, end=now + 60, variant="redacted",
                                  group="web"), ME)
    return d, r


# ---------------------------------------------------------------------------------- redaction
def test_no_real_value_appears_anywhere_in_a_redacted_bundle(redacted):
    _d, r = redacted
    text = _all_text(r.bundle)
    for v in FX.REAL_VALUES:
        hits = [m.start() for m in re.finditer(rf"(?<![\w.-]){re.escape(v)}(?![\w-])", text)]
        assert not hits, (v, text[max(0, hits[0] - 120): hits[0] + 120] if hits else "")


def test_a_redacted_bundle_still_verifies_and_says_how_it_was_redacted(redacted):
    _d, r = redacted
    assert V.verify(r.bundle).ok
    man = json.loads((r.bundle / "manifest.json").read_text())
    assert man["variant"] == "redacted" and man["redaction"]["mode"] == "strict"
    assert {"PUBLIC_IP", "USER"} <= set(man["redaction"]["replaced_kinds"])   # RFC 5737 test addresses read as public
    if shutil.which("ssh-keygen") and shutil.which("sha256sum"):
        with open(r.bundle / "manifest.json", "rb") as fh:
            assert subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(r.bundle / "allowed_signers"), "-I",
                                   "kratos", "-n", "kratos-export", "-s", str(r.bundle / "manifest.json.sig")],
                                  stdin=fh, capture_output=True).returncode == 0
        assert subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=r.bundle).returncode == 0


def test_placeholders_are_the_same_across_files_and_the_map_is_not_included(redacted):
    d, r = redacted
    man = json.loads((r.bundle / "manifest.json").read_text())
    tag = man["redaction"]["placeholder_tag"]
    labels_per_file = {}
    for f in man["files"]:
        if f["kind"] in ("evidence", "events", "generated"):
            labels_per_file[f["path"]] = set(re.findall(rf"\b[A-Z_]+_\d+_{tag}\b", (r.bundle / f["path"]).read_text()))
    # the attacker address shows up under ONE label in every file that has it
    from kratos.privacy.pseudonyms import PseudonymMap

    pm = PseudonymMap.open(f"export:{man['export_id']}", d)
    attacker_labels = {lab for (_k, _m, v), lab in pm.by_key.items() if v == FX.ATTACKER}
    assert len(attacker_labels) == 1
    lab = attacker_labels.pop()
    assert sum(1 for s in labels_per_file.values() if lab in s) >= 3
    # nothing in the bundle maps a placeholder back
    assert FX.ATTACKER not in _all_text(r.bundle)


def test_redacted_hashes_are_of_the_redacted_files_with_the_original_hash_listed(redacted):
    _d, r = redacted
    man = json.loads((r.bundle / "manifest.json").read_text())
    collected = [f for f in man["files"] if f["hashed_at"] == "collection"]
    assert collected and all(f.get("original_sha256") and f["original_sha256"] != f["sha256"] for f in collected)
    assert not any("source_path" in f for f in man["files"])
    rows = [json.loads(x) for x in (r.bundle / "ledger.ndjson").read_text().splitlines()]
    assert not any(x.get("full") for x in rows)          # paths and machine names would show


def test_a_secret_in_evidence_is_removed_in_the_redacted_bundle(tmp_path):
    from kratos import evidence

    d = tmp_path / "data"
    info = FX.build(d)
    token = "ghp_" + "Ab3" * 12          # a token shape, built here (never a real secret in the source)
    p = FX._write(d, "logs/auth_stats_secret.json", {"target": FX.M1, "note": f"token={token}"})
    evidence.record(p, data_dir=d, category="auth_stats", machine=FX.M1)
    r = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=info["now"] + 60,
                                  variant="redacted"), ME)
    assert token not in _all_text(r.bundle)
    man = json.loads((r.bundle / "manifest.json").read_text())
    assert man["redaction"]["secrets_redacted"] >= 1


# ---------------------------------------------------------------------------------- report
def test_the_report_has_no_external_resource_and_a_strict_policy(redacted):
    _d, r = redacted
    html = (r.bundle / "report.html").read_text()
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert not re.search(r"https?://", html)
    assert not re.search(r"<(script|img|iframe|link|object|embed)\b", html, re.IGNORECASE)
    assert not re.search(r"\b(src|href)\s*=", html, re.IGNORECASE)


def test_machine_text_from_the_corpus_is_escaped_in_the_report():
    class Col:
        coverage = {"m": {"statement": list(CORPUS.values()), "gaps": [CORPUS["md_html_script"]]}}
        timeline = [{"at": 1_780_000_000 + i, "machine": "m", "kind": "event", "what": v, "ref": k}
                    for i, (k, v) in enumerate(CORPUS.items())]
        findings = {"m": [{"rule_id": "X-1", "title": CORPUS["md_html_img"], "severity": "high", "state": "open",
                           "first_seen": "a", "last_seen": "b", "times_seen": 1, "finding_key": "k" * 20,
                           "evidence": list(CORPUS.values()), "attack": [], "verdict": None}]}
    man = {"export_id": "e", "created_at": "t", "created_by": {"user": CORPUS["rich_markup_link"], "interface": "cli"},
           "kratos_build": "b", "variant": "full", "scope": {"window": {"start": None, "end": "t"}, "group": None},
           "signing_key": {"fingerprint": "SHA256:x"}, "ledger": {"head_seq": 1, "head_hash": "h",
                                                                 "chain_verified": True},
           "machines": [{"shown": "m"}], "files": [{"path": CORPUS["bidi_override_filename"], "kind": "evidence",
                                                     "sha256": "0" * 64, "hashed_at": "export", "size": 1}],
           "cuts": [], "warnings": []}
    html = report_html.render(man, Col())
    assert "<script" not in html.lower().replace("&lt;script", "") and "<img" not in html.lower()
    assert not re.search(r"https?://", html)
    assert "\x1b" not in html and "‮" not in html
    body = html.split("<main>")[1]
    assert not re.search(r"<(?!/?(h1|h2|h3|div|span|b|i|br|p|ul|li|table|thead|tbody|tr|th|td|code|pre|main|body|html)\b)",
                         body), re.findall(r"<[a-z]+", body)[:20]


def test_observed_part_holds_only_collected_facts(tmp_path):
    d = tmp_path / "data"
    info = FX.build(d)
    narr = "MODEL-WRITTEN-SENTENCE about the incident."

    def chat(_s, _u):
        return json.dumps({"machines": [{"machine": FX.M1, "summary": narr + " CORR-SSH-001 high: brute force "
                                         f"from {FX.ATTACKER}; PERSIST-003 medium."}]})

    r = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=info["now"] + 60, narrative=True),
                 ME, narrative_chat=chat)
    html = (r.bundle / "report.html").read_text()
    observed, analysis = html.split("Part 2 -- Analysis")
    assert narr not in observed and narr in analysis
    assert "Written by a model that held no tools" in analysis
    assert (r.bundle / "narrative.md").is_file()


# ---------------------------------------------------------------------------------- narrative
def _fixture_findings():
    return ({"m1": [{"rule_id": "CORR-SSH-001", "severity": "high", "title": "SSH brute force", "state": "open",
                     "evidence": [f"12 failures from {FX.ATTACKER}"], "attack": [], "verdict": None}]},
            {"m1": {"statement": ["auth log: every line held"], "gaps": []}})


def test_the_summary_model_holds_no_tools(monkeypatch):
    from kratos.agent import loop

    def boom(*a, **k):
        raise AssertionError("a tool was run from the summary step")

    monkeypatch.setattr(loop, "execute_tool_call", boom)
    f, c = _fixture_findings()
    replies = iter([json.dumps({"tool": "run_linux_command", "args": {"command": "id"}}),
                    json.dumps({"tool": "run_linux_command", "machines": [
                        {"machine": "m1", "summary": "CORR-SSH-001 (high): an SSH brute force from "
                                                     f"{FX.ATTACKER}."}]})])
    seen = []

    def chat(system, user):
        seen.append(system)
        return next(replies)

    n = N.write_summary(f, c, data_dir=None, chat=chat)
    assert "run_linux_command" not in seen[0] and "Available tools" not in seen[0]
    assert "holds NO tools" in seen[0] or "hold NO tools" in seen[0]
    assert n.machines["m1"].startswith("CORR-SSH-001")
    assert any("asked for a tool" in x for x in n.notes)


def test_a_summary_contradicting_a_machines_findings_is_sent_back_then_noted():
    f, c = _fixture_findings()
    calls = []

    def chat(system, user):
        calls.append(user)
        return json.dumps({"machines": [{"machine": "m1", "summary": "No suspicious activity was found; the "
                                                                      "machine is clean."}]})

    n = N.write_summary(f, c, data_dir=None, chat=chat)
    assert len(calls) == 2 and "sent back" in calls[1]
    assert "[NOTE" in n.machines["m1"]


def test_a_summary_naming_another_machine_is_sent_back():
    f, c = _fixture_findings()
    f["m2"] = []
    c["m2"] = {"statement": ["nothing"], "gaps": []}
    calls = []

    def chat(system, user):
        calls.append(user)
        if len(calls) == 1:
            return json.dumps({"machines": [{"machine": "m1", "summary": "CORR-SSH-001 high. Same as m2."},
                                            {"machine": "m2", "summary": "No findings in the period."}]})
        return json.dumps({"machines": [{"machine": "m1", "summary": "CORR-SSH-001 (high) brute force."},
                                        {"machine": "m2", "summary": "No findings in the period."}]})

    n = N.write_summary(f, c, data_dir=None, chat=chat)
    assert len(calls) == 2 and "describes another machine" in calls[1]
    assert "m2" not in n.machines["m1"]


def test_the_summary_is_skipped_when_its_estimate_is_above_the_cap(monkeypatch):
    f, c = _fixture_findings()
    monkeypatch.setattr(N, "estimate", lambda prompt, data_dir: (5000, 1.25, "some-model"))
    called = []
    n = N.write_summary(f, c, data_dir=None, chat=lambda s, u: called.append(1) or "{}", max_usd=0.10)
    assert not called and n.skipped and "above export.narrative_max_usd" in n.skipped


def test_the_summary_prompt_frames_machine_text_as_data():
    f, c = _fixture_findings()
    f["m1"][0]["evidence"] = [CORPUS["instruction_ignore_previous"]]
    p = N.facts_prompt(f, c, run_tag="t")
    assert "<<" in p and "data" in p.lower()


# ---------------------------------------------------------------------------------- CASE/UCO
def _case_validate():
    exe = shutil.which("case_validate") or str(Path(__import__("sys").executable).parent / "case_validate")
    return exe if Path(exe).exists() else None


@pytest.mark.skipif(_case_validate() is None, reason="case-utils (the test extra) isn't installed")
@pytest.mark.parametrize("variant", ["full", "redacted"])
def test_the_case_uco_graph_validates(tmp_path, variant):
    from kratos.export import case_uco

    d = tmp_path / "data"
    info = FX.build(d)
    r = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=info["now"] + 60,
                                  variant=variant), ME)
    out = subprocess.run([_case_validate(), "--built-version", f"case-{case_uco.CASE_VERSION}",
                          str(r.bundle / "case.jsonld")], capture_output=True, text=True, timeout=900)
    assert out.returncode == 0, out.stdout[-3000:]
    assert "Conforms: True" in out.stdout
    g = json.loads((r.bundle / "case.jsonld").read_text())
    types = {n["@type"] for n in g["@graph"]}
    assert {"uco-observable:File", "case-investigation:InvestigativeAction",
            "case-investigation:ProvenanceRecord", "uco-tool:Tool", "uco-observable:Device"} <= types


def test_glued_addresses_and_the_exporters_login_are_replaced_too(tmp_path):
    """Found on the lab: nmap's output names its file `nmap_<address>_<time>.xml` ('_' is a word
    character, so the word-bounded address pattern skipped it) and records its command line with
    this computer's home folder; the manifest named the exporting person."""
    from kratos import evidence

    d = tmp_path / "data"
    info = FX.build(d)
    p = FX._write(d, f"scans/parsed_{FX.M1}.json",
                  {"target": FX.M1, "source_file": f"nmap_{FX.M1}_20261109_153201.xml",
                   "args": f"nmap -sV -Pn -oX /home/carol/kratos/data/scans/nmap_{FX.M1}_x.xml {FX.M1}",
                   "note": "path /srv/carol-tools/x and host-web-01.test-alias"})
    evidence.record(p, data_dir=d, category="open_ports", machine=FX.M1)
    # an attacker tried "admin" -- also one of Kratos's own words, so never replaced as a free word
    from datetime import datetime, timezone

    from kratos.adapters.auth_log_parse import classify_auth_message
    from kratos.events import converters as EC
    from kratos.events.store import EventStore

    msg = f"Failed password for invalid user admin from {FX.ATTACKER} port 40999 ssh2"
    ts = datetime.fromtimestamp(info["now"] - 120, timezone.utc).isoformat()
    ctx = EC.ReadContext(target=FX.M1, transport="ssh", read=EC.READ_JOURNAL_AUTH,
                         created=datetime.fromtimestamp(info["now"], timezone.utc), run_id="r2")
    msg2 = f"Connection closed by invalid user admin {FX.ATTACKER} port 40999 [preauth]"
    EventStore(d / "kratos.db").add([EC.from_auth_event(classify_auth_message(ts, FX.M1, "sshd", m, m), ctx=ctx)
                                     for m in (msg, msg2)])
    r = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=info["now"] + 60,
                                  variant="redacted"), Actor(user="carol", interface="cli"))
    text = _all_text(r.bundle)
    assert FX.M1 not in text and "carol" not in text
    assert '"name": "admin"' not in text and '"name":"admin"' not in text and "user admin" not in text
    man = json.loads((r.bundle / "manifest.json").read_text())
    assert man["created_by"]["user"] != "carol" and man["created_by"]["user"].startswith("USER_")


def test_finding_keys_and_event_ids_are_not_copied_into_a_redacted_bundle(tmp_path):
    """Security review (D.6): a finding key is sha256(rule ␟ machine ␟ subject) and an event id a
    hash over the machine name and the line -- unsalted, so a copied one lets a holder test guesses
    of the real machine until one matches. A redacted bundle carries keyed hashes instead; event
    cuts and warnings name the placeholder, not the machine."""
    from kratos.lifecycle import store as LS
    from kratos.storage.sqlite_files import connect_store

    d = tmp_path / "data"
    info = FX.build(d)
    with LS.opened(d) as conn:
        keys = [r["finding_key"] for r in conn.execute("SELECT finding_key FROM finding_records")]
    c = connect_store(d / "kratos.db")
    ids = [r[0] for r in c.execute("SELECT event_id FROM host_events")]
    c.close()
    # found on the lab: copied evidence carries them too (a findings report, detection results)
    from kratos import evidence

    md5_ioc = "d41d8cd98f00b204e9800998ecf8427e"
    p = FX._write(d, "detect/results/detections_x.json", {"target": FX.M1, "finding_key": keys[0],
                                                          "event_ids": ids[:2], "ioc_md5": md5_ioc})
    evidence.record(p, data_dir=d, category="detections_schedule", machine=FX.M1)
    md = FX._write(d, "reports/findings_x.md", "\n".join(f"- [HIGH] X `{k[:12]}`" for k in keys))
    evidence.record(md, data_dir=d, category="findings_report_md", machine=FX.M1)
    from kratos.export.scope import plan

    req = ExportRequest(machines=[FX.M1, FX.M2], start=info["now"] - 86400, end=info["now"] + 60, variant="redacted")
    p = plan(d, req)
    p.events = [type(e)(e.machine, e.dataset, e.count, min(e.count, 2)) for e in p.events]   # force a cut
    r = C.create(d, req, ME, plan=p)
    text = _all_text(r.bundle)
    leaked = [k for k in keys if k[:12] in text] + [i for i in ids if i in text]
    assert keys and ids and not leaked
    assert md5_ioc in text                     # an ordinary hash in the evidence is kept
    man = json.loads((r.bundle / "manifest.json").read_text())
    assert man["cuts"] and all(c["machine"] not in (FX.M1, FX.M2) for c in man["cuts"])
    assert V.verify(r.bundle).ok
    full = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=info["now"] + 60), ME)
    assert any(k[:12] in _all_text(full.bundle) for k in keys)     # the full variant keeps the real keys
