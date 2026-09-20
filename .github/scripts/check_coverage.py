"""Enforce LibSsh2CS coverage thresholds using a merged Cobertura report."""

import argparse
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def check_coverage(directory, line_threshold, branch_threshold):
    root = ET.parse(directory / "Cobertura.xml").getroot()
    if root.tag != "coverage":
        raise ValueError("Expected a Cobertura coverage root.")
    packages = root.findall("./packages/package")
    if len(packages) != 1 or packages[0].get("name") != "LibSsh2CS":
        raise ValueError("Coverage must contain exactly one package named LibSsh2CS.")
    if not packages[0].findall("./classes/class/lines/line"):
        raise ValueError("LibSsh2CS coverage contains no source lines.")

    rows = []
    passed = True
    for metric, threshold in (("lines", line_threshold), ("branches", branch_threshold)):
        counts = []
        for suffix in ("covered", "valid"):
            value = root.get(f"{metric}-{suffix}", "")
            if not re.fullmatch(r"[0-9]+", value):
                raise ValueError(f"Missing or invalid {metric}-{suffix} count.")
            counts.append(int(value))
        covered, valid = counts
        if valid == 0 or covered > valid:
            raise ValueError(f"Invalid or empty {metric} coverage: {covered}/{valid}.")

        # Compare exact integer counts; rounding is only for display.
        if not 0 <= threshold <= 100:
            raise ValueError("Coverage thresholds must be between 0 and 100.")
        meets_threshold = covered * 100 >= valid * threshold
        passed &= meets_threshold
        result = "PASS" if meets_threshold else "FAIL"
        rows.append(
            f"| {metric.capitalize()} | {covered}/{valid} | "
            f"{covered / valid:.2%} | {threshold}% | {result} |"
        )

    summary = "\n".join([
        "## LibSsh2CS coverage",
        "",
        "| Metric | Covered/valid | Coverage | Minimum | Result |",
        "| --- | --- | --- | --- | --- |",
        *rows,
        "",
    ])
    return passed, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory containing the merged Cobertura.xml report")
    parser.add_argument("--line-threshold", type=int, required=True)
    parser.add_argument("--branch-threshold", type=int, required=True)
    args = parser.parse_args()
    try:
        passed, summary = check_coverage(args.directory, args.line_threshold, args.branch_threshold)
    except (OSError, ET.ParseError, ValueError) as error:
        passed = False
        summary = f"## LibSsh2CS coverage\n\nFAIL: {error}\n"

    print(summary)
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary_path, "a", encoding="utf-8") as output:
            output.write(summary + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
