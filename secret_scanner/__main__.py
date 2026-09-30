import argparse
import sys

from .scanner import scan_folder


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

    count = 0
    for finding in scan_folder(args.folder):
        print(f"{finding.path}:{finding.line_number}  ->  {finding.rule}")
        count += 1

    print(f"\nDone. {count} possible secret(s) found.")
    sys.exit(1 if count else 0)


if __name__ == "__main__":
    main()