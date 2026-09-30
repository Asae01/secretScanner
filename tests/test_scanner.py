from secret_scanner.scanner import scan_text

# We build fake secrets from pieces so this file never contains a complete
# key-shaped string. That way, scanners (including GitHub's own) won't
# flag our test file as a real leak.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GITHUB_TOKEN = "ghp_" + "a" * 36


def rules_found(text):
    """Helper: return just the rule names that matched in some text."""
    return [rule for _, rule in scan_text(text)]


def test_detects_aws_key():
    assert "AWS Access Key" in rules_found(f"key = {FAKE_AWS_KEY}")


def test_detects_github_token():
    assert "GitHub Token" in rules_found(f"token: {FAKE_GITHUB_TOKEN}")


def test_detects_hardcoded_password():
    assert "Hardcoded Password" in rules_found('password = "hunter2"')


def test_ignores_normal_code():
    assert rules_found("print('hello world')") == []


def test_reports_correct_line_number():
    text = "line one\nline two\n" + 'password = "abc"'
    assert scan_text(text)[0][0] == 3