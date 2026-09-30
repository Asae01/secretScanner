import fnmatch

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

# Users can list paths to skip in this file, inside the folder being scanned.
IGNORE_FILE = ".secretscannerignore"

# Values containing any of these look like documentation, not real secrets.
PLACEHOLDER_MARKERS = (
    "your-", "your_", "your ", "changeme", "change-me", "change_me",
    "example", "placeholder", "xxxx", "<", "redacted", "dummy",
)

# Only the password-style rules get the placeholder check. Key-shaped
# secrets like AWS keys never need it.
PLACEHOLDER_RULES = {"Hardcoded Password", "Unquoted Config Secret"}

@dataclass
class Finding:
    path: Path
    line_number: int
    rule: str


@dataclass
class Skipped:
    path: Path
    reason: str

def looks_like_placeholder(text):
    """True if text contains a marker such as 'changeme' or 'your-'."""
    lowered = text.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)

def scan_text(text):
    """Check a block of text. Returns a list of (line_number, rule_name)."""
    results = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue  # this line was marked as safe
        handled = False
        for rule_name, pattern in PATTERNS.items():
            match = pattern.search(line)
            if not match:
                continue
            handled = True
            if rule_name in PLACEHOLDER_RULES and looks_like_placeholder(match.group(0)):
                continue  # documentation, not a real secret
            results.append((line_number, rule_name))
        if not handled and find_high_entropy(line):
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

def load_ignore_patterns(folder):
    """Read .secretscannerignore from a folder. Returns a list of patterns."""
    path = Path(folder) / IGNORE_FILE
    try:
        # utf-8-sig also accepts files that start with a Windows BOM
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        return []  # no ignore file, or an unreadable one
    patterns = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def is_ignored(relative_path, patterns):
    """Check a path like 'tests/certs/server.key' against ignore patterns."""
    parts = relative_path.split("/")
    for pattern in patterns:
        if pattern.endswith("/"):
            directory = pattern.rstrip("/")
            if "/" in directory:
                if relative_path.startswith(directory + "/"):
                    return True
            elif directory in parts[:-1]:
                return True
        elif "/" in pattern:
            if fnmatch.fnmatchcase(relative_path, pattern):
                return True
        elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


def scan_folder(folder):
    """Walk a folder and yield every Finding (and every Skipped file)."""
    folder = Path(folder)
    ignore_patterns = load_ignore_patterns(folder)
    for path in folder.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(folder)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if is_ignored(relative.as_posix(), ignore_patterns):
            continue
        yield from scan_file(path)