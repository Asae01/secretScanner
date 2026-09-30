import math
import re
from collections import Counter

# Strings shorter than this are too short to judge reliably.
MIN_LENGTH = 24

# Scores at or above this look random. Lower it to catch more (and get
# more false alarms). Raise it to catch less.
THRESHOLD = 4.2

# A quoted run of 24+ characters made of letters, digits, and + / = _ -
CANDIDATE = re.compile(r"[\"']([A-Za-z0-9+/=_-]{24,})[\"']")

# An unquoted value on a KEY=value line, like in a .env file.
UNQUOTED = re.compile(
    r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*([A-Za-z0-9+/=_-]{24,})\s*$"
)


def shannon_entropy(text):
    """Return how random a string looks. 0 means totally predictable."""
    if not text:
        return 0.0
    total = len(text)
    return sum(
        -(count / total) * math.log2(count / total)
        for count in Counter(text).values()
    )


def find_high_entropy(line):
    """Return the strings in a line that look random."""
    candidates = [match.group(1) for match in CANDIDATE.finditer(line)]
    unquoted = UNQUOTED.match(line)
    if unquoted:
        candidates.append(unquoted.group(1))
    return [c for c in candidates if shannon_entropy(c) >= THRESHOLD]