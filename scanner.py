"""File traversal and per-line pattern matching.

The scanner walks a directory tree, skips the usual noise (bin, obj, .git, node_modules, …), reads each source file line by line, and runs every applicable rule against it.
Findings are returned as a flat list so the reporter can sort and format them however it likes.
"""

from pathlib import Path
from dataclasses import dataclass

from rules import RULES, SUPPORTED_EXTENSIONS


# Directories we never descend into. These are either build output, VCS metadata, or dependency folders where findings are not actionable.
IGNORED_DIRS = {
    ".git", ".svn", ".hg",
    "bin", "obj",
    "node_modules", "bower_components", "jspm_packages",
    "packages",  # NuGet restore target
    ".vs", ".idea",  # IDE state
    "__pycache__", ".pytest_cache", ".mypy_cache",
    "dist", "build", "target",
    ".next", ".nuxt",
}


@dataclass
class Finding:
    # A single hit — one rule fired on one line of one file.
    rule_id: str
    rule_name: str
    severity: str
    file: str
    line_no: int
    line: str
    description: str
    fix: str


def _should_skip_dir(name: str) -> bool:
    # Quick membership check used during the walk.
    return name in IGNORED_DIRS or name.startswith(".")


def _rules_for_extension(ext: str):
    # Return only the rules whose language filter matches this file type.
    return [
        r for r in RULES
        if r["languages"] is None or ext in r["languages"]
    ]


def scan(root: str):
# Look through every folder and file, starting from the root, and report back any security issues found by the defined rules. Files are read line-by-line to ensure there are no issues with file size being too much, as well as to have easy access to line numbers.

    root_path = Path(root).resolve()

    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")
    if not root_path.is_dir():
        # A single file was given, scan it.
        yield from _scan_file(root_path)
        return

    for path in root_path.rglob("*"):
        if not path.is_file():
            continue

        # Skip any file that sits under an ignored directory.
        if any(part in IGNORED_DIRS for part in path.parts):
            continue

        yield from _scan_file(path)


def _scan_file(path: Path):
    # Run applicable rules against a single file.
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return

    rules = _rules_for_extension(ext)
    if not rules:
        return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                for rule in rules:
                    if rule["pattern"].search(line):
                        yield Finding(
                            rule_id=rule["id"],
                            rule_name=rule["name"],
                            severity=rule["severity"],
                            file=str(path),
                            line_no=line_no,
                            line=line.rstrip(),
                            description=rule["description"],
                            fix=rule["fix"],
                        )
    except (OSError, UnicodeDecodeError):
        # If we can't read it, we can't scan it - skip quietly.
        return
