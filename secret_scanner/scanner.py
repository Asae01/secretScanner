from dataclasses import dataclass
from pathlib import Path

from .patterns import PATTERNS
from .entropy import find_high_entropy

# Folders we dont need to scan.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}

# Skip files bigger than 1 MB so it scans fast.
MAX_FILE_SIZE = 1_000_000

# Any line containing this text is skipped (for known-fake data).
IGNORE_MARKER = "secretscanner:ignore"

@dataclass
class Finding:
    path: Path
    line_number: int
    rule: str


@dataclass
class Skipped:
    path: Path
    reason: str


def scan_text(text):
    """Check a block of text. Returns a list of (line_number, rule_name)."""
    results = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue  # this line was marked as safe
        matched = False
        for rule_name, pattern in PATTERNS.items():
            if pattern.search(line):
                results.append((line_number, rule_name))
                matched = True
        if not matched and find_high_entropy(line):
            results.append((line_number, "High-Entropy String"))
    return results


def scan_file(path):
    """Scan one file. Yields Finding objects, or one Skipped if unreadable."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            yield Skipped(path, "file is larger than 1 MB")
            return
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        yield Skipped(path, "could not read as UTF-8 text")
        return
    except OSError:
        yield Skipped(path, "could not open file")
        return

    for line_number, rule in scan_text(text):
        yield Finding(path, line_number, rule)


def scan_folder(folder):
    """Walk a folder and yield every Finding (and every Skipped file)."""
    for path in Path(folder).rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield from scan_file(path)