import json
import re
from pathlib import Path

DEFAULT_PATTERNS_FILE = Path(__file__).with_name("patterns.json")


def load_patterns(path=DEFAULT_PATTERNS_FILE):
    """Read rules from a JSON file. Returns {rule name: compiled regex}."""
    with open(path, encoding="utf-8") as f:
        rules = json.load(f)
    return {rule["name"]: re.compile(rule["regex"]) for rule in rules}


PATTERNS = load_patterns()