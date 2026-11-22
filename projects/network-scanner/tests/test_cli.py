"""Exercise the real CLI in a separate Python process, without Scapy."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_scope import example_scope


CLI = Path(__file__).resolve().parents[1] / "src" / "main.py"


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments, cwd=None):
        return subprocess.run(
            [sys.executable, "-S", str(CLI), *map(str, arguments)],
            capture_output=True, text=True, cwd=cwd,
        )

    def test_default_mode_displays_plan_without_writing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            output = Path(directory) / "plan.json"
            original = json.dumps(example_scope())
            scope_path.write_text(original, encoding="utf-8")
            result = self.run_cli("--scope", scope_path, cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads(result.stdout)
            self.assertEqual(plan["mode"], "dry-run")
            self.assertEqual(plan["parameters"]["target"], "172.28.70.10")
            self.assertEqual(plan["parameters"]["ports"], [22, 80, 443, 8080])
            self.assertEqual(plan["parameters"]["rate_pps"], 20)
            self.assertIn("No packets sent", result.stdout)
            self.assertEqual(scope_path.read_text(), original)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()), [scope_path])

    def test_invalid_scope_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            output = Path(directory) / "plan.json"
            scope_path.write_text("{}", encoding="utf-8")
            result = self.run_cli("--scope", scope_path, "--output", output, cwd=directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Error:", result.stderr)
            self.assertFalse(output.exists())

    def test_optional_output_can_be_created_and_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            output = Path(directory) / "evidence" / "plan.json"
            for previous in [None, "old output"]:
                if previous is not None:
                    output.write_text(previous, encoding="utf-8")
                result = self.run_cli("--scope", scope_path, "--output", "plan.json", cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(output.read_text())["mode"], "dry-run")
                self.assertIn("Plan saved to", result.stdout)

    def test_output_cannot_replace_scope_including_file_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            scope_path = evidence / "scope.json"
            original = json.dumps(example_scope())
            scope_path.write_text(original, encoding="utf-8")
            (evidence / "symlink.json").symlink_to(scope_path)
            os.link(scope_path, evidence / "hardlink.json")
            for output in ["scope.json", "symlink.json", "hardlink.json"]:
                with self.subTest(output=output):
                    result = self.run_cli("--scope", scope_path, "--output", output, cwd=directory)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Output must not replace the scope file", result.stderr)
                    self.assertEqual(scope_path.read_text(), original)

    def test_nested_directories_are_created_and_output_can_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            output = Path(directory) / "evidence" / "20261112" / "output.json"
            for _ in range(2):
                result = self.run_cli("--scope", scope_path, "--output", "20261112/output.json", cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(output.read_text())["mode"], "dry-run")

    def test_absolute_and_traversal_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            for output in [str(Path(directory) / "outside.json"), "../outside.json",
                           "sub/../../outside.json", "sub/../plan.json", "", ".", "run/",
                           "C:/outside.json", "..\\outside.json"]:
                with self.subTest(output=output):
                    result = self.run_cli("--scope", scope_path, "--output", output, cwd=directory)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Error:", result.stderr)
            self.assertFalse((Path(directory) / "evidence").exists())
            self.assertFalse((Path(directory) / "outside.json").exists())

    def test_symlink_escapes_are_rejected_without_external_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            evidence = root / "evidence"
            evidence.mkdir()
            outside = root / "outside"
            outside.mkdir()
            victim = outside / "keep.json"
            victim.write_text("keep this", encoding="utf-8")
            (evidence / "escape").symlink_to(outside, target_is_directory=True)
            (evidence / "file.json").symlink_to(victim)
            for output in ["escape/new/output.json", "file.json"]:
                result = self.run_cli("--scope", scope_path, "--output", output, cwd=directory)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symbolic links", result.stderr)
            self.assertEqual(victim.read_text(), "keep this")
            self.assertFalse((outside / "new").exists())

    def test_evidence_root_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            (root / "evidence").symlink_to(outside, target_is_directory=True)
            result = self.run_cli("--scope", scope_path, "--output", "plan.json", cwd=directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symbolic link", result.stderr)
            self.assertEqual(list(outside.iterdir()), [])

    def test_required_arguments(self):
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli("--execute").returncode, 2)

    def test_execute_requires_output_before_loading_packet_code(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            result = self.run_cli("--scope", scope_path, "--execute", cwd=directory)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--execute requires --output", result.stderr)
            self.assertFalse((Path(directory) / "evidence").exists())

    def test_bare_filename_creates_evidence_and_can_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            for _ in range(2):
                result = self.run_cli("--scope", scope_path, "--output", "plan.json", cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(str(Path(directory) / "evidence" / "plan.json"), result.stdout)
            output = Path(directory) / "evidence" / "plan.json"
            self.assertEqual(json.loads(output.read_text())["mode"], "dry-run")
            self.assertFalse((Path(directory) / "plan.json").exists())

    def test_dot_relative_path_also_stays_inside_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            result = self.run_cli("--scope", scope_path, "--output", "./plan.json", cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(directory) / "evidence" / "plan.json").exists())
            self.assertFalse((Path(directory) / "plan.json").exists())

    def test_routed_filename_cannot_replace_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            scope_path = evidence / "scope.json"
            original = json.dumps(example_scope())
            scope_path.write_text(original, encoding="utf-8")
            result = self.run_cli("--scope", scope_path, "--output", "scope.json", cwd=directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Output must not replace the scope file", result.stderr)
            self.assertEqual(scope_path.read_text(), original)

    def test_plan_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(json.dumps(example_scope()), encoding="utf-8")
            outputs = []
            for _ in range(2):
                result = self.run_cli("--scope", scope_path, cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(result.stdout)
            self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
