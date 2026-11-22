"""Evaluate timing benefit and lost-late-evidence trade-off without traffic."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

from scapy.layers.inet import ICMP, IP, TCP

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner import run_scan
from scope import ScopeError
from test_scanner import Clock, FakeTransport, reply
from test_scope import example_scope
import test_cli


class GraceTests(unittest.TestCase):
    def execute(self, grace, respond=None, scope=None):
        clock = Clock()
        transport = FakeTransport(clock, respond)
        result = run_scan(
            scope or example_scope(), "test", response_grace=grace,
            transport_factory=lambda _: transport, clock=clock, sleep=clock.sleep,
            utc=lambda: "2026-11-12T00:00:00+00:00",
            identifiers=lambda index: (40000 + index, 1000 + index),
        )
        return result, transport

    def one_port(self):
        scope = example_scope()
        scope["ports"] = [80]
        return scope

    def test_immediate_replies_save_time_without_changing_states_or_probes(self):
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                transport.schedule(reply(packet), 0.01)
        baseline, _ = self.execute(None, respond)
        shortened, _ = self.execute(0.1, respond)
        self.assertLess(shortened["elapsed_seconds"], baseline["elapsed_seconds"] / 2)
        self.assertEqual(baseline["counts"], shortened["counts"])
        self.assertEqual([r["state"] for r in baseline["results"]],
                         [r["state"] for r in shortened["results"]])
        self.assertIsNone(baseline["parameters"]["response_grace_seconds"])
        self.assertEqual(shortened["parameters"]["response_grace_seconds"], 0.1)

    def test_silence_preserves_full_timeout_and_retry_count(self):
        baseline, _ = self.execute(None)
        shortened, _ = self.execute(0.1)
        self.assertEqual(baseline["elapsed_seconds"], shortened["elapsed_seconds"])
        self.assertEqual(baseline["counts"], shortened["counts"])
        self.assertTrue(all(len(r["attempts"]) == 2 for r in shortened["results"]))

    def test_icmp_alone_does_not_shorten_window(self):
        def respond(transport, packet):
            message = IP(src="172.28.70.1", dst=packet.src) / ICMP(type=3, code=13) / packet.copy()
            transport.schedule(IP(bytes(message)), 0.01)
        result, _ = self.execute(0.1, respond, self.one_port())
        self.assertEqual(result["elapsed_seconds"], 3)
        self.assertEqual(result["results"][0]["state"], "filtered-or-no-response")

    def test_duplicate_replies_do_not_extend_grace(self):
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                for delay in [0.01, 0.09, 0.105]:
                    transport.schedule(reply(packet, "RA"), delay)
        result, _ = self.execute(0.1, respond, self.one_port())
        self.assertAlmostEqual(result["elapsed_seconds"], 0.11)
        self.assertEqual(result["results"][0]["observations"][0]["count"], 3)

    def test_late_conflicting_reply_can_be_missed_by_shorter_run(self):
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                transport.schedule(reply(packet), 0.01)
                transport.schedule(reply(packet, "RA"), 0.2)
        baseline, _ = self.execute(None, respond, self.one_port())
        shortened, _ = self.execute(0.1, respond, self.one_port())
        self.assertTrue(baseline["results"][0]["conflicting_tcp_states"])
        self.assertFalse(shortened["results"][0]["conflicting_tcp_states"])
        self.assertEqual(len(baseline["results"][0]["observations"]), 2)
        self.assertEqual(len(shortened["results"][0]["observations"]), 1)

    def test_prior_probe_replies_remain_matchable_while_next_port_waits(self):
        scope = example_scope()
        scope["ports"] = [80, 443]
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2 and packet[TCP].dport == 80:
                transport.schedule(reply(packet), 0.01)
                transport.schedule(reply(packet, "RA"), 0.2)
        result, _ = self.execute(0.1, respond, scope)
        self.assertTrue(result["results"][0]["conflicting_tcp_states"])
        self.assertEqual(result["results"][1]["state"], "filtered-or-no-response")
        self.assertTrue(all(not a["response_grace_triggered"]
                            for a in result["results"][1]["attempts"]))

    def test_grace_is_capped_by_original_timeout(self):
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                transport.schedule(reply(packet, "RA"), 1.49)
        result, _ = self.execute(0.1, respond, self.one_port())
        self.assertEqual(result["elapsed_seconds"], 1.5)

    def test_grace_mode_keeps_rate_limiting_cleanup(self):
        scope = self.one_port()
        scope["maximum_rate_pps"] = 1
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                transport.schedule(reply(packet), 0.01)
        result, transport = self.execute(0.1, respond, scope)
        self.assertEqual(result["counts"]["rst_sent"], 1)
        self.assertGreaterEqual(transport.sent[1][0] - transport.sent[0][0], 1)

    def test_invalid_grace_fails_before_transport(self):
        for value in [0, -1, 2, True, float("nan"), float("inf")]:
            with self.subTest(value=value):
                with self.assertRaises(ScopeError):
                    self.execute(value)

    def test_cli_dry_run_displays_grace_and_rejects_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory) / "scope.json"
            scope.write_text(json.dumps(example_scope()), encoding="utf-8")
            cli = test_cli.CliTests()
            valid = cli.run_cli("--scope", scope, "--response-grace", "0.1", cwd=directory)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)["parameters"]["response_grace_seconds"], 0.1)
            for value in ["0", "-1", "2", "nan", "inf"]:
                with self.subTest(value=value):
                    result = cli.run_cli("--scope", scope, "--response-grace", value, cwd=directory)
                    self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(Path(directory).iterdir()), [scope])


if __name__ == "__main__":
    unittest.main()
