from secret_scanner.scanner import Finding, Skipped, scan_file, scan_text

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