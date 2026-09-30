from secret_scanner.patterns import PATTERNS, load_patterns
from secret_scanner.scanner import Finding, Skipped, scan_file, scan_text
from secret_scanner.entropy import shannon_entropy

# We build fake secrets from pieces so this file never contains a complete
# key-shaped string. That way, scanners (including GitHub's own) won't
# flag our test file as a real leak.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GITHUB_TOKEN = "ghp_" + "a" * 36
FAKE_STRIPE_KEY = "sk_live_" + "a" * 24
FAKE_GOOGLE_KEY = "AIza" + "a" * 35
RANDOM_LOOKING = "aB3xK9mQ2wL7zR5tY8uP1nC4vD6eF0hG"  # secretscanner:ignore


def rules_found(text):
    """Helper: return just the rule names that matched in some text."""
    return [rule for _, rule in scan_text(text)]


def test_detects_aws_key():
    assert "AWS Access Key" in rules_found(f"key = {FAKE_AWS_KEY}")


def test_detects_github_token():
    assert "GitHub Token" in rules_found(f"token: {FAKE_GITHUB_TOKEN}")


def test_detects_hardcoded_password():
    assert "Hardcoded Password" in rules_found('password = "hunter2"')  # secretscanner:ignore


def test_ignores_normal_code():
    assert rules_found("print('hello world')") == []


def test_reports_correct_line_number():
    text = "line one\nline two\n" + 'password = "abc"'  # secretscanner:ignore
    assert scan_text(text)[0][0] == 3


def test_ignore_marker_skips_line():
    text = 'password = "hunter2"  # secretscanner:ignore'
    assert scan_text(text) == []


def test_ignore_marker_only_affects_its_own_line():
    text = 'password = "a"  # secretscanner:ignore\npassword = "b"'
    assert [line for line, _ in scan_text(text)] == [2]


def test_unreadable_file_is_reported(tmp_path):
    bad = tmp_path / "binary.bin"
    bad.write_bytes(b"\xff\xfe\x00\x80\x81")  # not valid UTF-8
    results = list(scan_file(bad))
    assert len(results) == 1
    assert isinstance(results[0], Skipped)


def test_readable_file_is_scanned(tmp_path):
    good = tmp_path / "config.txt"
    good.write_text('password = "hunter2"', encoding="utf-8")  # secretscanner:ignore
    results = list(scan_file(good))
    assert len(results) == 1
    assert isinstance(results[0], Finding)

def test_detects_stripe_key():
    assert "Stripe Secret Key" in rules_found(f"stripe = {FAKE_STRIPE_KEY}")


def test_detects_google_key():
    assert "Google API Key" in rules_found(f"key = {FAKE_GOOGLE_KEY}")


def test_short_stripe_lookalike_is_ignored():
    assert rules_found("sk_live_abc") == []


def test_stripe_test_key_is_ignored():
    assert rules_found("sk_test_" + "a" * 24) == []


def test_patterns_load_from_json():
    assert "AWS Access Key" in PATTERNS
    assert len(PATTERNS) == 8


def test_custom_patterns_file(tmp_path):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        '[{"name": "Demo", "regex": "demo_[0-9]+"}]', encoding="utf-8"
    )
    rules = load_patterns(rules_file)
    assert list(rules) == ["Demo"]
    assert rules["Demo"].search("demo_123")

def test_entropy_of_repeated_text_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0


def test_entropy_of_varied_text_is_high():
    assert shannon_entropy(RANDOM_LOOKING) > 4.5


def test_detects_high_entropy_string():
    assert "High-Entropy String" in rules_found(f'token = "{RANDOM_LOOKING}"')


def test_ignores_low_entropy_string():
    assert rules_found('name = "' + "ab" * 15 + '"') == []


def test_ignores_short_string():
    assert rules_found('id = "aB3xK9mQ2wL7"') == []

def test_detects_unquoted_password_in_env():
    assert "Unquoted Config Secret" in rules_found("DB_PASSWORD=hunter2")


def test_detects_unquoted_token_in_env():
    assert "Unquoted Config Secret" in rules_found(f"API_TOKEN={RANDOM_LOOKING}")


def test_detects_export_prefix():
    assert "Unquoted Config Secret" in rules_found("export API_KEY=abcd1234")


def test_ignores_env_variable_reference():
    assert rules_found("DB_PASSWORD=${DB_PASSWORD}") == []


def test_ignores_env_line_without_secret_name():
    assert rules_found("DB_HOST=localhost") == []


def test_ignores_code_keyword_argument():
    assert rules_found('    password=os.environ["DB_PASS"],') == []


def test_detects_high_entropy_unquoted_value():
    assert "High-Entropy String" in rules_found(f"SESSION={RANDOM_LOOKING}")


def test_ignores_unquoted_low_entropy_value():
    assert rules_found("SESSION=" + "ab" * 15) == []