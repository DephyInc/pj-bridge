#!/usr/bin/env python3
"""
json_to_csv.py

Convert NDJSON (newline-delimited JSON objects) from stdin into CSV on stdout.

Assumptions:
- Each non-empty line on stdin is a JSON object.
- All objects have exactly the same set of keys.
- Nested values are not supported (values must be scalars or simple JSON types).

Usage examples:

  # From a file
  cat data.ndjson | python3 json_to_csv.py > data.csv

  # From the binary file parser
  python3 file_parser.py ... | python3 json_to_csv.py > sensor.csv

  # From the TCP parser
  python3 tcp_parser.py ... | python3 json_to_csv.py
"""

import argparse
import csv
import json
import sys
from typing import List


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Convert NDJSON from stdin into CSV on stdout.")
    ap.add_argument(
        "--no-header",
        action="store_true",
        help="Do not emit a header row (default is to emit headers).",
    )
    ap.add_argument(
        "--delimiter",
        default=",",
        help="CSV delimiter character (default ',').",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    writer = None
    fieldnames: List[str] = []
    line_num = 0

    for raw_line in sys.stdin:
        line_num += 1
        line = raw_line.strip()
        if not line:
            # Skip empty lines
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(
                f"error: invalid JSON on line {line_num}: {e}",
                file=sys.stderr,
            )
            sys.exit(2)

        if not isinstance(obj, dict):
            print(
                f"error: JSON value on line {line_num} is not an object (got {type(obj).__name__})",
                file=sys.stderr,
            )
            sys.exit(2)

        if writer is None:
            # First object defines field order
            fieldnames = list(obj.keys())
            writer = csv.DictWriter(
                sys.stdout,
                fieldnames=fieldnames,
                delimiter=args.delimiter,
                lineterminator="\n",
            )
            if not args.no_header:
                writer.writeheader()
        else:
            # Check that the set of keys matches exactly
            keys = set(obj.keys())
            expected = set(fieldnames)
            if keys != expected:
                missing = expected - keys
                extra = keys - expected
                msg_parts = []
                if missing:
                    msg_parts.append(f"missing fields: {sorted(missing)}")
                if extra:
                    msg_parts.append(f"extra fields: {sorted(extra)}")
                msg = "; ".join(msg_parts)
                print(
                    f"error: inconsistent fields on line {line_num}: {msg}",
                    file=sys.stderr,
                )
                sys.exit(2)

        # DictWriter will output columns in the fieldnames order
        writer.writerow(obj)

    # If there was no input, do nothing and exit successfully
    sys.exit(0)


if __name__ == "__main__":
    main()
