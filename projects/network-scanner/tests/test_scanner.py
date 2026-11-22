"""Controlled runner tests: fake time and fake transport, never live sockets."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from scapy.layers.inet import ICMP, IP, TCP

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main
from scanner import LiveTransport, ScanError, run_scan
from test_scope import example_scope


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


class FakeTransport:
    source_ip = "172.28.70.2"

    def __init__(self, clock, on_send=None):
        self.clock = clock
        self.on_send = on_send
        self.sent = []
        self.events = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.closed = True

    def send(self, packet):
        self.sent.append((self.clock(), packet.copy()))
        if self.on_send is not None:
            self.on_send(self, packet)

    def schedule(self, packet, delay):
        self.events.append((self.clock() + delay, packet))
        self.events.sort(key=lambda item: item[0])

    def receive(self, timeout):
        deadline = self.clock() + max(0, timeout)
        if self.events and self.events[0][0] <= deadline:
            timestamp, packet = self.events.pop(0)
            self.clock.now = max(self.clock(), timestamp)
            return packet, timestamp
        self.clock.now = deadline
        return None


def reply(probe, flags="SA"):
    return IP(src=probe.dst, dst=probe.src) / TCP(
        sport=probe[TCP].dport, dport=probe[TCP].sport,
        seq=9000, ack=(probe[TCP].seq + 1) % (2 ** 32), flags=flags,
    )


class ScannerTests(unittest.TestCase):
    def execute(self, on_send=None, scope=None):
        scope = example_scope() if scope is None else scope
        clock = Clock()
        transport = FakeTransport(clock, on_send)
        result = run_scan(
            scope, "test-version", transport_factory=lambda _: transport,
            clock=clock, sleep=clock.sleep, utc=lambda: "2026-11-12T00:00:00+00:00",
            identifiers=lambda index: (40000 + index, 1000 + index),
        )
        return result, transport

    def test_silent_ports_retry_twice_and_remain_unresolved(self):
        result, transport = self.execute()
        self.assertEqual(result["counts"]["syn_sent"], 8)
        self.assertEqual(result["counts"]["rst_sent"], 0)
        self.assertTrue(transport.closed)
        self.assertEqual([r["port"] for r in result["results"]], [22, 80, 443, 8080])
        for record in result["results"]:
            self.assertEqual(record["state"], "filtered-or-no-response")
            self.assertEqual(len(record["attempts"]), 2)

    def test_open_closed_duplicates_and_cleanup(self):
        def respond(transport, packet):
            if int(packet[TCP].flags) != 2:
                return
            response = reply(packet, "SA" if packet[TCP].dport == 80 else "RA")
            transport.schedule(response, 0.001)
            transport.schedule(response.copy(), 0.002)
        result, transport = self.execute(respond)
        self.assertEqual(result["counts"]["syn_sent"], 4)
        self.assertEqual(result["counts"]["rst_sent"], 1)
        for record in result["results"]:
            self.assertEqual(record["state"], "open" if record["port"] == 80 else "closed")
            self.assertEqual(len(record["observations"]), 1)
            self.assertEqual(record["observations"][0]["count"], 2)
        reset = [p for _, p in transport.sent if int(p[TCP].flags) == 4][0]
        self.assertEqual(reset[TCP].dport, 80)

    def test_rate_spacing_includes_rst(self):
        scope = example_scope()
        scope["maximum_rate_pps"] = 1
        scope["timeout_seconds"] = 0.01
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                transport.schedule(reply(packet), 0.001)
        _, transport = self.execute(respond, scope)
        times = [timestamp for timestamp, _ in transport.sent]
        self.assertGreater(len(times), 4)
        self.assertTrue(all(b - a >= 1 for a, b in zip(times, times[1:])))

    def test_late_reply_stays_attributed_to_first_attempt(self):
        scope = example_scope()
        scope["ports"] = [80]
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2 and packet[TCP].sport == 40000:
                transport.schedule(reply(packet), 1.6)
        result, _ = self.execute(respond, scope)
        record = result["results"][0]
        self.assertEqual(record["state"], "open")
        self.assertEqual(len(record["attempts"]), 2)
        self.assertEqual(record["observations"][0]["attempt"], 1)
        self.assertEqual(record["attempts"][1]["matched_responses"], 0)

    def test_icmp_is_retained_without_claiming_closed(self):
        scope = example_scope()
        scope["ports"] = [80]
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                message = IP(src="172.28.70.1", dst=packet.src) / ICMP(type=3, code=13) / packet.copy()
                transport.schedule(IP(bytes(message)), 0.01)
        result, _ = self.execute(respond, scope)
        record = result["results"][0]
        self.assertEqual(record["state"], "filtered-or-no-response")
        self.assertEqual(len(record["observations"]), 2)
        self.assertTrue(all(o["icmp_code"] == 13 for o in record["observations"]))

    def test_unrelated_packets_do_not_change_port_state(self):
        scope = example_scope()
        scope["ports"] = [80]
        def respond(transport, packet):
            wrong = reply(packet)
            wrong[TCP].ack = 0
            transport.schedule(wrong, 0.01)
        result, _ = self.execute(respond, scope)
        self.assertEqual(result["results"][0]["observations"], [])
        self.assertEqual(result["counts"]["unmatched_packets"], 2)

    def test_conflicting_tcp_observations_are_preserved(self):
        scope = example_scope()
        scope["ports"] = [80]
        def respond(transport, packet):
            if int(packet[TCP].flags) == 2:
                transport.schedule(reply(packet), 0.01)
                transport.schedule(reply(packet, "RA"), 0.02)
        result, _ = self.execute(respond, scope)
        record = result["results"][0]
        self.assertEqual(record["state"], "open")
        self.assertTrue(record["conflicting_tcp_states"])
        self.assertEqual(len(record["observations"]), 2)

    def test_one_attempt_scope_is_respected(self):
        scope = example_scope()
        scope["maximum_attempts"] = 1
        result, _ = self.execute(scope=scope)
        self.assertEqual(result["counts"]["syn_sent"], 4)

    def test_fixed_observations_and_clocks_produce_deterministic_results(self):
        first, _ = self.execute()
        second, _ = self.execute()
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_send_failure_closes_transport_and_raises(self):
        clock = Clock()
        def fail(transport, packet):
            raise OSError("simulated permission failure")
        transport = FakeTransport(clock, fail)
        with self.assertRaisesRegex(ScanError, "permission failure"):
            run_scan(example_scope(), "test", transport_factory=lambda _: transport,
                     clock=clock, sleep=clock.sleep)
        self.assertTrue(transport.closed)

    def test_invalid_scope_never_opens_transport(self):
        scope = example_scope()
        scope["maximum_attempts"] = 3
        with patch("scanner.LiveTransport") as factory:
            with self.assertRaises(ValueError):
                run_scan(scope, "test", transport_factory=factory)
            factory.assert_not_called()

    def test_missing_interface_fails_before_sockets(self):
        with patch("scanner.get_if_list", return_value=[]), patch("scanner.conf.L3socket") as socket:
            with self.assertRaisesRegex(ScanError, "does not exist"):
                with LiveTransport(example_scope()):
                    self.fail("Must not start")
            socket.assert_not_called()

    def test_cli_execute_uses_runner_and_saves_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            result, _ = self.execute()
            with patch.object(main, "DEFAULT_OUTPUT_DIR", root / "evidence"), \
                    patch("scanner.run_scan", return_value=result) as runner, \
                    contextlib.redirect_stdout(io.StringIO()):
                status = main.main(["--scope", str(scope_path), "--execute", "--output", "result.json"])
            self.assertEqual(status, 0)
            runner.assert_called_once()
            saved = json.loads((root / "evidence" / "result.json").read_text())
            self.assertEqual(saved["mode"], "execute")
            self.assertEqual(len(saved["scope_sha256"]), 64)
            self.assertIn("--execute", saved["command"])

    def test_cli_failed_run_leaves_no_result_or_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            evidence = root / "evidence"
            with patch.object(main, "DEFAULT_OUTPUT_DIR", evidence), \
                    patch("scanner.run_scan", side_effect=ScanError("simulated failure")), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = main.main(["--scope", str(scope_path), "--execute", "--output", "result.json"])
            self.assertEqual(status, 1)
            self.assertEqual(list(evidence.iterdir()), [])

    def test_cli_existing_live_result_prevents_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            evidence = root / "evidence"
            evidence.mkdir()
            output = evidence / "result.json"
            output.write_text("preserve", encoding="utf-8")
            with patch.object(main, "DEFAULT_OUTPUT_DIR", evidence), \
                    patch("scanner.run_scan") as runner, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = main.main(["--scope", str(scope_path), "--execute", "--output", "result.json"])
            self.assertEqual(status, 1)
            runner.assert_not_called()
            self.assertEqual(output.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
