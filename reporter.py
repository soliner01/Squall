"""Console output formatting.

All of the ANSI color logic and layout lies here. Colors are emitted only when stdout is a TTY; piping to a file or another tool gives clean, uncolored text.
"""

import json
import sys
from pathlib import Path

from rules import SEVERITY_ORDER
from scanner import Finding

# ANSI escape codes. Everything is done with _colorize() so non-TTY output stays clean.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_SEVERITY_COLORS = {
    "critical": "\033[91m",    # bright red
    "high":     "\033[31m",    # red
    "medium":   "\033[33m",    # yellow
    "low":      "\033[36m",    # cyan
    "info":     "\033[90m",    # bright black / gray
}


def _supports_color():
    return sys.stdout.isatty()


def _colorize(text, code):
    if not _supports_color():
        return text
    return f"{code}{text}{_RESET}"


def print_banner():
    """Squall banner"""
    banner = r"""
   ____                     _ _ 
  / ___|  __ _ _   _  __ _ | | |
  \___ \ / _` | | | |/ _` || | |
   ___) | (_| | |_| | (_| || | |
  |____/ \__, |\__,_|\__,_||_|_|
          |_|
"""
    print(_colorize(banner, _DIM))
    print(_colorize("  Static Vulnerability Scanner", _DIM))
    print()
    print(_colorize("  The localized storm that blows down flimsy coding choices.", _DIM))
    print()
    print()


def format_finding(f: Finding):
    # Render a single finding as a multi-line block.
    sev = f.severity.upper()
    sev_label = _colorize(f"[{sev}]", _SEVERITY_COLORS.get(f.severity, ""))
    rule_label = _colorize(f"{f.rule_id}", _DIM)

    # Trim the file path to something readable when it's very long.
    loc = f"{f.file}:{f.line_no}"

    lines = [
        f"  {sev_label} {f.rule_name}  {rule_label}",
        f"    {_colorize(loc, _DIM)}",
        f"    {f.line.strip()[:120]}",
        f"    Description: {f.description}"
    ]
    if f.fix:
        lines.append(f"    {_colorize('Fix: ' + f.fix, _DIM)}")
    return "\n".join(lines)


def print_report(findings, root):
    # Print the full sorted report plus a summary footer.
    # Sort by severity (critical first), then by file/line for stable output.
    findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line_no),
    )

    # Per-finding output ---------------------------------------------------
    if not findings:
        print(_colorize("  No issues found. The wind has passed...", _DIM))
        print()
        return

    for f in findings:
        print(format_finding(f))
        print()

    # Summary footer -------------------------------------------------------
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(_colorize("─" * 50, _DIM))
    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            label = _colorize(sev.upper(), _SEVERITY_COLORS[sev])
            summary_parts.append(f"{counts[sev]} {label}")

    print(f"  {_colorize('Squall', _BOLD)} scanned {root}")
    print(f"  {len(findings)} finding(s): " + "  ".join(summary_parts))
    print()


# -------------------------------------------------------------------------
# File output - plain text and JSON.
#
# These produce uncolored strings so the written file looks clean, in case the file is a .json file.
# -------------------------------------------------------------------------
def _sorted(findings):
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line_no),
    )


def _severity_counts(findings):
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_text_report(findings, root):
    # Plain-text report suitable for a .txt file - no ANSI codes.
    findings = _sorted(findings)

    lines = [f"Squall scan report — {root}", "=" * 50, ""]

    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_name}  ({f.rule_id})")
        lines.append(f"  {f.file}:{f.line_no}")
        lines.append(f"  {f.line.strip()[:120]}")
        if f.fix:
            lines.append(f"  Fix: {f.fix}")
        lines.append("")

    counts = _severity_counts(findings)
    summary_parts = [f"{counts[s]} {s.upper()}" for s in ("critical", "high", "medium", "low", "info") if s in counts]
    lines.append("-" * 50)
    lines.append(f"{len(findings)} finding(s): " + "  ".join(summary_parts))

    return "\n".join(lines) + "\n"


def render_json_report(findings, root):
    # Structured JSON - one object per finding plus a summary block.
    findings = _sorted(findings)
    return json.dumps({
        "scanner": "squall",
        "path": root,
        "summary": {
            "total": len(findings),
            "by_severity": _severity_counts(findings),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "file": f.file,
                "line": f.line_no,
                "code": f.line.strip(),
                "description": f.description,
                "fix": f.fix,
            }
            for f in findings
        ],
    }, indent=2) + "\n"


def write_report(findings, root, output_path):
    """Write findings to output_path, picking the format from the extension.

    .json  -> structured JSON
    *      -> plain text
    Returns the path that was written so the caller can confirm to the user.
    """
    path = Path(output_path)
    
    # If a custom path wasn't provided, route it to the project's Output folder.
    if not path.is_absolute():
        project_output_dir = Path(__file__).resolve().parent / "Output"
        project_output_dir.mkdir(parents=True, exist_ok=True)
        path = project_output_dir / path.name

    if path.suffix.lower() == ".json":
        content = render_json_report(findings, root)
    else:
        content = render_text_report(findings, root)

    path.write_text(content, encoding="utf-8")
    return path

