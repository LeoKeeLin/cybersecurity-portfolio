"""Offline tests: no Scapy import, network access or live scanning required."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scope import ScopeError, load_scope, validate_scope


def example_scope():
    """Synthetic input for validation tests, not assessment evidence."""
    return {
        "schema": "wqe7002-recon-scope-v1",
        "scope_id": "unit-test-scope",
        "option": "tcp-syn-scan",
        "environment": "isolated-course-lab",
        "interface": "eth0",
        "target": "172.28.70.10",
        "ports": [22, 80, 443, 8080],
        "maximum_rate_pps": 20,
        "maximum_attempts": 2,
        "timeout_seconds": 1.5,
        "capture_point": "unit-test capture point",
        "topology": "unit-test isolated lab",
    }


class ScopeTests(unittest.TestCase):
    def test_valid_scope_is_not_changed(self):
        scope = example_scope()
        original = copy.deepcopy(scope)
        self.assertEqual(validate_scope(scope), original)
        self.assertEqual(scope, original)

    def test_loads_json_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            path.write_text(json.dumps(example_scope()), encoding="utf-8")
            self.assertEqual(load_scope(path), example_scope())

    def test_missing_required_fields(self):
        for field in example_scope():
            with self.subTest(field=field):
                scope = example_scope()
                del scope[field]
                with self.assertRaises(ScopeError):
                    validate_scope(scope)

    def test_wrong_contract_or_placeholder(self):
        for field, value in [("schema", "unknown"), ("option", "device-map"),
                             ("scope_id", "TODO"),
                             ("interface", "<interface>"), ("topology", "")]:
            with self.subTest(field=field, value=value):
                scope = example_scope()
                scope[field] = value
                with self.assertRaises(ScopeError):
                    validate_scope(scope)

    def test_environment_description_is_not_a_fixed_label(self):
        scope = example_scope()
        scope["environment"] = "central-course-lab"
        self.assertEqual(validate_scope(scope)["environment"], "central-course-lab")

    def test_invalid_environment_descriptions(self):
        for value in [None, 42, "", "   ", "TODO", "<environment>"]:
            with self.subTest(value=value):
                scope = example_scope()
                scope["environment"] = value
                with self.assertRaises(ScopeError):
                    validate_scope(scope)

    def test_invalid_targets(self):
        for target in ["host.example", "172.28.70.0/28", "::1", "999.1.1.1",
                       "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"]:
            with self.subTest(target=target):
                scope = example_scope()
                scope["target"] = target
                with self.assertRaises(ScopeError):
                    validate_scope(scope)

    def test_invalid_port_lists(self):
        for ports in [[], [80, 80], [0], [65536], [True], ["80"],
                      "22,80", list(range(1, 32))]:
            with self.subTest(ports=ports):
                scope = example_scope()
                scope["ports"] = ports
                with self.assertRaises(ScopeError):
                    validate_scope(scope)

    def test_rate_retry_and_timeout_bounds(self):
        invalid = {
            "maximum_rate_pps": [0, -1, 21, True, float("inf"), "20"],
            "maximum_attempts": [0, 3, 1.5, True],
            "timeout_seconds": [0, -1, True, float("nan")],
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    scope = example_scope()
                    scope[field] = value
                    with self.assertRaises(ScopeError):
                        validate_scope(scope)

    def test_bad_json_duplicate_keys_and_non_object(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            for text in ['{', '{"target":"a","target":"b"}', '[]']:
                with self.subTest(text=text):
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(ScopeError):
                        load_scope(path)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ScopeError, "Cannot read"):
                load_scope(Path(directory) / "missing.json")


if __name__ == "__main__":
    unittest.main()
