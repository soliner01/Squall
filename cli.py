# Command line interface entry point. Wires argparse to the scanner and reporter.

import argparse
import sys

from init import version
from scanner import scan
from reporter import print_banner, print_report, write_report

# -h flag details.
def build_parser():
    parser = argparse.ArgumentParser(
        prog="squall",
        description="Squall — static vulnerability scanner for local projects.",
        epilog="Example:  squall my-script",
    )
    parser.add_argument(
        "path",
        help="Path to the project directory (or a single source file) to scan.",
    )
    parser.add_argument(
        "-s", "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Only show findings at or above this severity level.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write findings to a file. Format is inferred from the extension: .json for structured JSON, anything else for plain text. File is written to directory (...)/Squall/Output if no explicit path is provided. WARNING: If a file already exists with the same filename in the target directory, the existing file will be overwritten.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"Squall {version}",
    )
    return parser


# Severity threshold map for the --severity filter.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print_banner()

    try:
        findings = list(scan(args.path))
    except FileNotFoundError as exc:
        print(f"  error: {exc}", file=sys.stderr)
        sys.exit(2)

    # Apply the optional severity floor.
    if args.severity:
        floor = _SEVERITY_RANK[args.severity]
        findings = [
            f for f in findings
            if _SEVERITY_RANK.get(f.severity, 99) <= floor
        ]

    print_report(findings, args.path)

    # If the user asked for a file, write it and confirm on the console.
    if args.output:
        try:
            written = write_report(findings, args.path, args.output)
            print(f"  Report written to {written}")
        except OSError as exc:
            print(f"  Error writing report: {exc}", file=sys.stderr)
            sys.exit(2)

    # Non-zero exit code when issues were found.
    if findings:
        sys.exit(1)
