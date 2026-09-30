import argparse
import sys

from .scanner import Finding, scan_folder


def main():
    parser = argparse.ArgumentParser(
        prog="secret_scanner",
        description="Scan a folder for accidentally exposed secrets.",
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default=".",
        help="Folder to scan (default: current folder)",
    )
    args = parser.parse_args()

    found = 0
    skipped = 0
    for item in scan_folder(args.folder):
        if isinstance(item, Finding):
            print(f"{item.path}:{item.line_number}  ->  {item.rule}")
            found += 1
        else:
            print(f"skipped: {item.path} ({item.reason})", file=sys.stderr)
            skipped += 1

    print(f"\nDone. {found} possible secret(s) found.")
    if skipped:
        print(f"{skipped} file(s) skipped because they could not be scanned.")
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()