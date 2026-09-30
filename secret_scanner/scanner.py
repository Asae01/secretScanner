from dataclasses import dataclass
from pathlib import Path

from .patterns import PATTERNS

# Folders dont need to scan.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}

# Skip files bigger than 1 MB so scan is fast.
MAX_FILE_SIZE = 1_000_000


@dataclass
class Finding:
    path: Path
    line_number: int
    rule: str


def scan_text(text):
    """Check a block of text. Returns a list of (line_number, rule_name)."""
    results = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule_name, pattern in PATTERNS.items():
            if pattern.search(line):
                results.append((line_number, rule_name))
    return results


def scan_file(path):
    """Scan one file. Returns a list of Finding objects."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return []
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError, OSError):
        return []  # binary or unreadable file, skip it
    return [Finding(path, n, rule) for n, rule in scan_text(text)]


def scan_folder(folder):
    """Walk a folder and yield every Finding."""
    for path in Path(folder).rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield from scan_file(path)