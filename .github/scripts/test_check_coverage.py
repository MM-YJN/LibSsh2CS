"""Regression checks for the CI coverage gate (standard library only)."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from check_coverage import check_coverage


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.report = self.directory / "coverage.cobertura.test.xml"

    def write_report(self, lines="95", branches="90", valid="100"):
        self.report.write_text(
            f'<coverage lines-covered="{lines}" lines-valid="{valid}" '
            f'branches-covered="{branches}" branches-valid="{valid}">'
            '<packages><package name="LibSsh2CS"><classes><class name="Example">'
            '<lines><line number="1" hits="1" /></lines>'
            '</class></classes></package></packages></coverage>',
            encoding="utf-8",
        )

    def test_passing_and_exact_thresholds(self):
        for lines, branches in (("99", "94"), ("95", "90")):
            with self.subTest(lines=lines, branches=branches):
                self.write_report(lines, branches)
                passed, summary = check_coverage(self.directory, 95, 90)
                self.assertTrue(passed)
                self.assertEqual(summary.count("PASS"), 2)

    def test_either_threshold_can_fail_without_rounding(self):
        for lines, branches in (("949999", "900000"), ("950000", "899999")):
            with self.subTest(lines=lines, branches=branches):
                self.write_report(lines, branches, "1000000")
                passed, summary = check_coverage(self.directory, 95, 90)
                self.assertFalse(passed)
                self.assertIn("FAIL", summary)

    def test_report_only_accepts_low_coverage(self):
        self.write_report(lines="1", branches="0")
        passed, summary = check_coverage(self.directory)
        self.assertTrue(passed)
        self.assertEqual(summary.count("REPORT"), 2)
        self.assertEqual(summary.count("Pending"), 2)

    def test_cli_reports_without_thresholds(self):
        self.write_report(lines="1", branches="0")
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("check_coverage.py")),
             str(self.directory)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Pending", result.stdout)
        self.assertNotIn("FAIL", result.stdout)

    def test_merged_report(self):
        self.write_report()
        self.report.rename(self.directory / "Cobertura.xml")
        passed, _ = check_coverage(self.directory)
        self.assertTrue(passed)
        self.write_report()
        with self.assertRaises(ValueError):
            check_coverage(self.directory)

    def test_invalid_thresholds(self):
        self.write_report()
        for threshold in (-1, 101):
            with self.assertRaises(ValueError):
                check_coverage(self.directory, threshold, None)
            with self.assertRaises(ValueError):
                check_coverage(self.directory, None, threshold)

    def test_invalid_counts(self):
        for lines, branches, valid in (
            ("0", "0", "0"), ("101", "90", "100"),
            ("95", "101", "100"), ("-1", "90", "100"),
            ("NaN", "90", "100"), ("95.0", "90", "100"),
            ("", "90", "100"), ("95", "90", ""),
        ):
            with self.subTest(lines=lines, branches=branches, valid=valid):
                self.write_report(lines, branches, valid)
                with self.assertRaises(ValueError):
                    check_coverage(self.directory, 95, 90)

    def test_missing_and_ambiguous_reports(self):
        with self.assertRaises(ValueError):
            check_coverage(self.directory, 95, 90)
        self.write_report()
        (self.directory / "coverage.cobertura.second.xml").write_bytes(
            self.report.read_bytes()
        )
        with self.assertRaises(ValueError):
            check_coverage(self.directory, 95, 90)

    def test_wrong_scope_and_empty_data(self):
        self.write_report()
        original = self.report.read_text(encoding="utf-8")
        for content in (
            original.replace('name="LibSsh2CS"', 'name="Other"'),
            original.replace('</packages>', '<package name="Other" /></packages>'),
            original.replace('<line number="1" hits="1" />', ''),
            original.replace('lines-covered="95"', ''),
            '<coverage />', '<other />',
        ):
            with self.subTest(content=content):
                self.report.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    check_coverage(self.directory, 95, 90)

    def test_cli_exit_codes_and_summary(self):
        summary_path = self.directory / "summary.md"
        for content, expected in ((None, 1), ("passing", 0), ("below", 1), ("<broken", 1)):
            with self.subTest(content=content):
                if content == "passing":
                    self.write_report()
                elif content == "below":
                    self.write_report(lines="94")
                elif content is not None:
                    self.report.write_text(content, encoding="utf-8")
                summary_path.write_text("Existing summary\n", encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(Path(__file__).with_name("check_coverage.py")),
                     str(self.directory), "--line-threshold", "95", "--branch-threshold", "90"],
                    env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary_path)},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                summary = summary_path.read_text(encoding="utf-8")
                self.assertTrue(summary.startswith("Existing summary\n"))
                self.assertIn(result.stdout.strip(), summary)
                self.assertIn("PASS" if expected == 0 else "FAIL", summary)


if __name__ == "__main__":
    unittest.main()
