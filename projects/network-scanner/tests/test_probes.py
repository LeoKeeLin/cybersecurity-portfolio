"""Synthetic packet tests. Scapy is required, but no packets are sent."""

from pathlib import Path
import sys
import unittest

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from probes import build_reset, build_syn, interpret_response
from test_scope import example_scope


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.scope = example_scope()
        self.probe = build_syn(self.scope, "172.28.70.2", 40000, 80, 12345)

    def reply(self, flags="SA", ack=12346):
        return IP(src="172.28.70.10", dst="172.28.70.2") / TCP(
            sport=80, dport=40000, seq=67890, ack=ack, flags=flags
        )

    def unreachable(self, probe=None, code=13):
        # ICMP may quote only the original IP header and first 8 TCP bytes.
        # Decode from bytes so this tests Scapy's real IPerror/TCPerror parsing.
        quote = bytes(self.probe if probe is None else probe)[:28]
        packet = IP(src="172.28.70.1", dst="172.28.70.2") / ICMP(
            type=3, code=code
        ) / Raw(quote)
        return IP(bytes(packet))

    def test_syn_construction(self):
        wire = IP(bytes(self.probe))
        self.assertEqual(wire.src, "172.28.70.2")
        self.assertEqual(wire.dst, self.scope["target"])
        self.assertEqual(wire[TCP].sport, 40000)
        self.assertEqual(wire[TCP].dport, 80)
        self.assertEqual(wire[TCP].seq, 12345)
        self.assertEqual(int(wire[TCP].flags), 2)

    def test_out_of_scope_probe_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside the scope"):
            build_syn(self.scope, "172.28.70.2", 40000, 9999, 12345)

    def test_invalid_probe_identifiers_rejected(self):
        for source_port, sequence in [(0, 1), (True, 1), (40000, -1), (40000, 2 ** 32)]:
            with self.subTest(source_port=source_port, sequence=sequence):
                with self.assertRaises(ValueError):
                    build_syn(self.scope, "172.28.70.2", source_port, 80, sequence)

    def test_syn_ack_is_open_including_ecn(self):
        for flags in ["SA", "SAE"]:
            with self.subTest(flags=flags):
                response = IP(bytes(self.reply(flags)))
                self.assertEqual(interpret_response(self.probe, response)["kind"], "open")

    def test_rst_ack_is_closed(self):
        result = interpret_response(self.probe, IP(bytes(self.reply("RA"))))
        self.assertEqual(result["kind"], "closed")

    def test_unrelated_addresses_ports_and_ack_are_ignored(self):
        for layer, field, value in [
            (IP, "src", "172.28.70.3"), (IP, "dst", "172.28.70.3"),
            (TCP, "sport", 443), (TCP, "dport", 40001), (TCP, "ack", 12345),
        ]:
            with self.subTest(field=field):
                response = self.reply()
                setattr(response[layer], field, value)
                self.assertIsNone(interpret_response(self.probe, response))

    def test_unsupported_flags_and_bare_reset_are_ignored(self):
        for flags in ["A", "S", "R", "SAR", "SAF", "F"]:
            with self.subTest(flags=flags):
                self.assertIsNone(interpret_response(self.probe, self.reply(flags)))

    def test_ack_sequence_wraparound(self):
        probe = build_syn(self.scope, "172.28.70.2", 40000, 80, 2 ** 32 - 1)
        self.assertEqual(interpret_response(probe, self.reply(ack=0))["kind"], "open")

    def test_rst_cleanup_tuple_and_sequence(self):
        reset = IP(bytes(build_reset(self.probe, self.reply())))
        self.assertEqual((reset.src, reset.dst), (self.probe.src, self.probe.dst))
        self.assertEqual((reset[TCP].sport, reset[TCP].dport), (40000, 80))
        self.assertEqual(reset[TCP].seq, 12346)
        self.assertEqual(int(reset[TCP].flags), 4)

    def test_cleanup_rejects_closed_or_unmatched_response(self):
        for response in [self.reply("RA"), self.reply(ack=99), None]:
            with self.subTest(response=response):
                with self.assertRaises(ValueError):
                    build_reset(self.probe, response)

    def test_minimum_icmp_quote_matches_and_preserves_codes(self):
        for code in [1, 3, 13]:
            with self.subTest(code=code):
                self.assertEqual(interpret_response(self.probe, self.unreachable(code=code)), {
                    "kind": "icmp-unreachable", "icmp_type": 3,
                    "icmp_code": code, "responder": "172.28.70.1",
                })

    def test_icmp_quoting_different_probe_is_ignored(self):
        for layer, field, value in [(IP, "dst", "172.28.70.3"),
                                    (TCP, "sport", 40001), (TCP, "seq", 999)]:
            with self.subTest(field=field):
                other = self.probe.copy()
                setattr(other[layer], field, value)
                self.assertIsNone(interpret_response(self.probe, self.unreachable(other)))

    def test_missing_non_ip_and_truncated_quotes_are_ignored(self):
        packets = [None, Raw(b"unrelated"),
                   IP(src="172.28.70.1", dst="172.28.70.2") / ICMP(type=3) / Raw(b"short"),
                   IP(src="172.28.70.1", dst="172.28.70.2") / ICMP(type=0)]
        for response in packets:
            with self.subTest(response=response):
                self.assertIsNone(interpret_response(self.probe, response))

    def test_fragmented_reply_ignored(self):
        response = self.reply()
        response[IP].flags = "MF"
        self.assertIsNone(interpret_response(self.probe, response))


if __name__ == "__main__":
    unittest.main()
