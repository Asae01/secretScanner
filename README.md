# secretScanner

[![CI](https://github.com/Asae01/secretScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Asae01/secretScanner/actions/workflows/ci.yml)

A beginner-friendly tool that scans a folder for accidentally exposed
secrets like API keys and passwords, before you push them to GitHub.

## Why this exists

It's easy to paste an API key into a file while testing and forget about
it. If that file gets pushed to a public repo, bots can find the key within
minutes. secretScanner helps you catch these mistakes before that happens.

## Requirements

- Python 3.8 or newer

## Usage

Scan the current folder:

```
python -m secret_scanner
```

Scan a specific folder:

```
python -m secret_scanner path/to/folder
```

The tool prints the file, line number, and type of each possible secret.
It never prints the secret itself.

Example output:

```
.\config.py:12  ->  Hardcoded Password
skipped: .\logo.png (could not read as UTF-8 text)

Done. 1 possible secret(s) found.
1 file(s) skipped because they could not be scanned.
```

The exit code is `1` if any secret is found and `0` if not, so other tools
can use it to block a commit or fail a build. Skipped files do not change
the exit code.

## What it detects

- AWS access keys
- GitHub tokens
- Slack tokens
- Private keys
- Hardcoded passwords
- Stripe live secret keys
- Google API keys

## Skipped files

Files the scanner can't read (binary files, files that aren't UTF-8 text,
files over 1 MB, or files it lacks permission to open) are reported as
`skipped` instead of being ignored silently. Skip messages go to stderr,
separate from the results.

## Ignoring known-fake data

If a line contains fake data on purpose, such as a test password, add
`secretscanner:ignore` to that line and the scanner will skip it:

```
password = "not-a-real-password"  # secretscanner:ignore
```

Only the marked line is skipped. The rest of the file is still scanned.

## Running the tests

```
pip install pytest
python -m pytest
```

## Known limitations

- It only finds secrets that match its patterns, so it can miss others.
- It may flag harmless examples (false positives) unless they are marked
  with `secretscanner:ignore`.

## Contributing

Ideas and new patterns are welcome! Open an issue or a pull request.

## License

MIT