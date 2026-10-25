"""The sub-agent bundle's own tests, runnable with nothing but the standard library.

A monitored machine runs the agent with its system python3 -- as old as 3.8, with no
third-party packages. CI's `agent-bundle` job runs this file there
(`python3.8 -I -S -m unittest`, via scripts/ci/agent_bundle.py check); pytest runs it
too, on the bundle built from the same repository files. unittest only: no pytest,
no kratos import.
"""
from __future__ import annotations

import importlib
import json
import importlib.util
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path


def _bundle_parent() -> str:
    given = os.environ.get("KRATOS_AGENT_BUNDLE_DIR")
    if given:
        return given
    here = Path(__file__).resolve()
    spec = importlib.util.spec_from_file_location("_agent_bundle_builder",
                                                  here.parents[2] / "scripts" / "ci" / "agent_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tmp = tempfile.mkdtemp(prefix="kratos-bundle-test-")
    mod.build(Path(tmp))
    return tmp


_PARENT = _bundle_parent()
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

agent = importlib.import_module("subagent.agent")
ceiling = importlib.import_module("subagent.ceiling")
protocol = importlib.import_module("subagent.protocol")
reads = importlib.import_module("subagent.reads")
signing = importlib.import_module("subagent.signing")


class BundleBasics(unittest.TestCase):
    def test_it_is_the_bundle_not_the_kratos_package(self):
        self.assertTrue(agent.__file__.startswith(_PARENT), agent.__file__)
        if "pytest" not in sys.modules:  # under pytest the suite itself imported kratos
            self.assertNotIn("kratos", sys.modules)

    def test_agent_version_and_command_line(self):
        self.assertRegex(agent.AGENT_VERSION, r"^\d+\.\d+\.\d+$")
        args = agent.build_arg_parser().parse_args(["--core-host", "100.64.0.10", "--core-port", "8765"])
        self.assertEqual(args.core_host, "100.64.0.10")

    def test_every_bundle_module_imports(self):
        pkg = Path(_PARENT) / "subagent"
        for py in sorted(pkg.glob("*.py")):
            if py.stem != "__init__":
                importlib.import_module("subagent." + py.stem)


class Protocol(unittest.TestCase):
    def test_a_frame_round_trips_over_a_socket(self):
        a, b = socket.socketpair()
        try:
            msg = protocol.build_ping(123.5)
            protocol.send_frame_sync(a, msg)
            self.assertEqual(protocol.recv_frame_sync(b), msg)
        finally:
            a.close()
            b.close()

    def test_an_oversized_frame_is_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_frame({"type": "x", "blob": "a" * (protocol.MAX_FRAME_BYTES + 1)})


class Signing(unittest.TestCase):
    def test_a_signed_envelope_verifies_and_a_changed_one_does_not(self):
        key = signing.derive_signing_key("token-123")
        env = {"type": "exec_dispatch", "seq": 7, "action": "fail2ban.ban_ip"}
        env["sig"] = signing.sign_envelope(key, env)
        self.assertTrue(signing.verify_envelope(key, env))
        env["seq"] = 8
        self.assertFalse(signing.verify_envelope(key, env))
        self.assertFalse(signing.verify_envelope(signing.derive_signing_key("other"), dict(env, seq=7)))


class Ceiling(unittest.TestCase):
    def test_a_shell_is_never_within_the_ceiling(self):
        with self.assertRaises(ceiling.CeilingError):
            ceiling.match_argv(["sh", "-c", "id"])

    def test_a_command_line_parses_without_a_shell(self):
        self.assertEqual(ceiling.parse_command_line("adduser --disabled-password alice"),
                         ["adduser", "--disabled-password", "alice"])


class Reads(unittest.TestCase):
    """Each read runs on this Python and answers with a status -- never an exception.
    Reads needing tools the test machine lacks (journalctl, yara) report that."""

    def _status(self, probe, params):
        out = reads.run_probe(probe, params)
        self.assertIsInstance(out, dict)
        self.assertIn(out.get("status"), ("ok", "not_installed", "error", "timed_out", "refused"), out)
        return out

    def test_the_basic_reads_work(self):
        for probe in ("clock", "file_hashes", "processes"):
            self.assertEqual(self._status(probe, {})["status"], "ok", probe)

    def test_the_heavier_reads_answer(self):
        self._status("config_audit", {})
        self._status("privileged_accounts", {"since": time.time() - 86400})
        self._status("measure_auth", {"start": int(time.time()) - 3600, "granularity": 60})
        self._status("journal_fetch", {"lines": 2})

    def test_an_unknown_read_is_unsupported(self):
        self.assertEqual(reads.run_probe("rm_rf", {})["status"], "unsupported")

    def test_bad_parameters_are_refused(self):
        self.assertEqual(reads.run_probe("journal_fetch", {"lines": "all; id"})["status"], "refused")

    def test_the_starter_rules_ship_with_the_bundle(self):
        files = reads.yara_rule_files("bundled")[0]
        self.assertTrue(any(str(p).endswith("MALW_Eicar.yar") for p in files), files)


detect = importlib.import_module("subagent.detect")
_PACKS = Path(__file__).resolve().parents[2] / "src" / "kratos" / "detect" / "packs"


class Detect(unittest.TestCase):
    """The detection evaluator (C.1) runs on the oldest Python an agent may have, and
    judges every shipped rule's samples as core does (tests/test_detect_pack.py)."""

    def _pack(self, rules):
        p = {"format": detect.FORMAT, "format_version": 1, "pack_id": "t", "pack_version": 1, "rules": rules}
        p["sha256"] = detect.pack_digest(p)
        return p

    def test_validate_and_evaluate(self):
        rule = {"id": "SIGMA-0000AAAA", "title": "t", "level": "high", "author": "a", "license": "DRL-1.1",
                "scope": {"datasets": ["kratos.auth"], "where": None},
                "match": {"op": "wildcard", "field": "message", "pattern": "*rm ?-rf*"}}
        pack = detect.load_pack(self._pack([rule]))
        ev = detect.Evaluator(pack)
        hits = ev.evaluate({"event.id": "e1", "event.dataset": "kratos.auth", "message": "x RM --rf /"}, 1.0)
        self.assertEqual([h.rule_id for h in hits], ["SIGMA-0000AAAA"])
        bad = dict(rule, match={"op": "regex", "field": "message", "value": "x"})
        with self.assertRaises(detect.PackError):
            detect.load_pack(self._pack([bad]))

    def test_shipped_pack_samples(self):
        packs = sorted(_PACKS.glob("*.json")) if _PACKS.is_dir() else []
        for path in packs:
            pack = detect.load_pack(detect.parse_pack_bytes(path.read_bytes()))
            self.assertEqual(detect.check_samples(pack), [], path.name)


pinning = importlib.import_module("subagent.pinning")

# Throwaway self-signed certificates (their private keys were discarded) and the
# SHA-256 of each one's SubjectPublicKeyInfo, as `cryptography` computed it.
_CERT_P256 = (
    "MIIBGDCBv6ADAgECAgEBMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC2J1bmRsZSB0ZXN0MB4XDTI2MDEwMTAwMDAw"
    "MFoXDTI2MDEwMjAwMDAwMFowFjEUMBIGA1UEAwwLYnVuZGxlIHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC"
    "AARmp/jccCu+y1rA8XUOMkbMrlL+OFjxwDpSj/h2UnFLOpp5ndKOvLuzP6dPCeRkTKjcCmL07ASvV9oPIKH46agh"
    "MAoGCCqGSM49BAMCA0gAMEUCIBDZpThzR38xN2zYzb/mtzpBmE946OdB5fjTk9dQ5L7dAiEAtCm+4fjNvYqazKxY"
    "Knyt7bmtLqv8E5ca9uciRAC92qw="
)
_PIN_P256 = "e7b51f4dffb9eb593f1a490fec67a7e438a0dc2e065f7fb58a3c91013a67b00a"
_CERT_ED25519 = (
    "MIHYMIGLoAMCAQICAQEwBQYDK2VwMBYxFDASBgNVBAMMC2J1bmRsZSB0ZXN0MB4XDTI2MDEwMTAwMDAwMFoXDTI2"
    "MDEwMjAwMDAwMFowFjEUMBIGA1UEAwwLYnVuZGxlIHRlc3QwKjAFBgMrZXADIQBb194ZACW/2sah6cQ3MAWQ8fxo"
    "Qh0C+/RGFN/RJLSXfDAFBgMrZXADQQDBqDL6UmbwWB/7i8Esr4kiUFrRc3V3RIA6vsmddZTxJEoiKdIidI4GlQct"
    "BJP+7hV1C9DMUm0ZTkS1RpfLdJYO"
)
_PIN_ED25519 = "0ab2e5e543360912846e76201c7968fc5fbeb1ba631607cb690f3acceeb3d028"


class Pinning(unittest.TestCase):
    """The agent's server-key pin check on the oldest supported Python (C.4)."""

    def _der(self, b64):
        import base64

        return base64.b64decode(b64)

    def test_spki_hashes_match_the_known_pins(self):
        self.assertEqual(pinning.spki_sha256(self._der(_CERT_P256)).hex(), _PIN_P256)
        self.assertEqual(pinning.spki_sha256(self._der(_CERT_ED25519)).hex(), _PIN_ED25519)

    def test_damaged_certificates_fail_closed(self):
        der = self._der(_CERT_P256)
        for n in range(len(der)):
            with self.assertRaises(pinning.PinError):
                pinning.spki_der(der[:n])
        with self.assertRaises(pinning.PinError):
            pinning.spki_der(der + b"\x00")
        with self.assertRaises(pinning.PinError):
            pinning.spki_der(b"\x30\x80" + der[2:])

    def test_pin_match_and_pin_sets(self):
        digest = bytes.fromhex(_PIN_P256)
        self.assertTrue(pinning.pin_matches(digest, [_PIN_ED25519, _PIN_P256]))
        self.assertFalse(pinning.pin_matches(digest, [_PIN_ED25519]))
        self.assertEqual(pinning.normalize_pins([_PIN_P256.upper(), _PIN_P256]), [_PIN_P256])
        with self.assertRaises(pinning.PinError):
            pinning.normalize_pins([])

    def test_client_context_builds_on_this_python(self):
        import ssl

        ctx = pinning.client_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_agent_refuses_to_start_with_bad_pins_and_keeps_newer_saved_ones(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state.json"
            with self.assertRaises(pinning.PinError):
                agent.SubAgent("127.0.0.1", 1, state_file=state, server_pins=["nope"], local_allow_file=None)
            a = agent.SubAgent("127.0.0.1", 1, state_file=state, server_pins=[_PIN_P256], server_pins_version=3,
                               local_allow_file=None)
            self.assertEqual(a._pin_version, 3)
            b = agent.SubAgent("127.0.0.1", 1, state_file=state, server_pins=[_PIN_ED25519], server_pins_version=2,
                               local_allow_file=None)
            self.assertEqual((b._pins, b._pin_version), ([_PIN_P256], 3))  # older command line ignored


if __name__ == "__main__":
    unittest.main()


watch = importlib.import_module("subagent.watch")

_FAKE_JOURNALCTL = r'''#!{python}
import json, sys, time
if "--follow" not in sys.argv:
    sys.exit(0)
with open({data!r}) as f:
    for line in f:
        sys.stdout.write(line)
sys.stdout.flush()
time.sleep(30)
'''


class Watch(unittest.TestCase):
    """Continuous detection (C.2) on the oldest Python an agent may have: a journal line and
    an audit event become events and matches, and the watcher follows a journal and spools."""

    def _entry(self, i, ts, msg, comm):
        cur = "s=%s;i=%x;b=%s;m=1;t=%x;x=1" % ("f" * 32, i, "0" * 32, int(ts * 1e6))
        return {"__CURSOR": cur, "__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "MESSAGE": msg, "_COMM": comm,
                "SYSLOG_IDENTIFIER": comm, "_PID": "77", "_TRANSPORT": "syslog"}

    def test_lines_become_events(self):
        v = watch.journal_values(self._entry(1, 1790000000.0, "alice : TTY=pts/0 ; PWD=/ ; USER=root ; "
                                                               "COMMAND=/usr/bin/chattr -i /etc/hostname", "sudo"),
                                 "host.example")
        flat = watch.A.flat(v)
        self.assertEqual(flat["event.action"], "sudo_command")
        self.assertEqual(flat["process.executable"], "/usr/bin/chattr")
        self.assertRegex(flat["event.id"], r"^[0-9a-f]{32}$")
        a = watch.audit_values(['type=SYSCALL msg=audit(1790000000.100:9): syscall=59 success=yes ppid=1 pid=2 '
                                'auid=1000 uid=0 euid=0 ses=3 comm="useradd" exe="/usr/sbin/useradd"',
                                'type=EXECVE msg=audit(1790000000.100:9): argc=2 a0="useradd" a1="eve"'],
                               "/var/log/audit/audit.log", "host.example")
        self.assertEqual(a["process_args"], ("useradd", "eve"))

    def test_follow_and_spool(self):
        tmp = Path(tempfile.mkdtemp())
        data = tmp / "journal.jsonl"
        now = time.time() + 5
        data.write_text(json.dumps(self._entry(
            1, now, "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/chattr -i /etc/hostname", "sudo")) + "\n")
        exe = tmp / "journalctl"
        exe.write_text(_FAKE_JOURNALCTL.replace("{python}", sys.executable).replace("{data!r}", repr(str(data))))
        exe.chmod(0o755)
        packs = sorted(_PACKS.glob("*.json")) if _PACKS.is_dir() else []
        if not packs:
            self.skipTest("no shipped pack in this layout")
        pack = detect.parse_pack_bytes(packs[-1].read_bytes())
        m = watch.WatchManager(str(tmp / "state"), audit_path=str(tmp / "audit.log"), journalctl=str(exe))
        m.apply(watch.validate_push({"enabled": True, "machine": "host.example", "packs": [pack]}, None))
        try:
            end = time.time() + 20
            while time.time() < end and not len(m.spool):
                time.sleep(0.1)
            recs = [r for r, _n in m.spool.items.values()]
            self.assertTrue(recs and recs[0]["rule_id"].startswith("SIGMA-"), recs)
        finally:
            m.stop()
