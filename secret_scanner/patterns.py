import re

PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Hardcoded Password": re.compile(r"(?i)password\s*=\s*['\"][^'\"]+['\"]"),
    "Stripe Secret Key": re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
}