# secretScanner

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

Done. 1 possible secret(s) found.
```

The exit code is `1` if anything is found and `0` if the folder is clean,
so other tools can use it to block a commit or fail a build.

## What it detects

- AWS access keys
- GitHub tokens
- Slack tokens
- Private keys
- Hardcoded passwords

## Running the tests

```
pip install pytest
python -m pytest
```

## Known limitations

- It may flag harmless examples (false positives), such as test data.
- It only finds secrets that match its patterns, so it can miss others.
- Files that can't be read as UTF-8 text are skipped.

## Contributing

Ideas and new patterns are welcome! Open an issue or a pull request.

## License

MIT