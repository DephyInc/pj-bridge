#!/usr/bin/env python3
"""
derive_struct.py

Parse a C header to derive a Python struct format string and expanded field labels
for a typedef'ed struct.

Assumptions and limits:
- Looks for: typedef struct { ... } <StructName>;
  (also accepts: typedef struct <StructName> { ... } <StructName>;)
- Supports stdint types (int8_t, uint32_t, etc.), float, double, bool, char.
- Supports fixed-size arrays like: float acc[3];
- Rejects pointers, bitfields, and nested structs.
- Does not auto-insert padding. If the device struct is not packed, use --packed false
  and provide explicit padding manually in a later step. Most devices use packed
  for wire I/O.

Output:
- JSON to stdout, for example:
  {
    "struct_fmt": "<Ifff",
    "fields": ["ts_ms","ax","ay","az"],
    "record_size": 16
  }
"""

import argparse
import json
import re
import struct
import sys
from typing import List, Tuple

# Map common C types to Python struct codes.
# char is mapped to signed byte by default. Change to "B" if needed.
CTYPE_MAP = {
    "int8_t": "b",
    "uint8_t": "B",
    "int16_t": "h",
    "uint16_t": "H",
    "int32_t": "i",
    "uint32_t": "I",
    "int64_t": "q",
    "uint64_t": "Q",
    "float": "f",
    "double": "d",
    "bool": "?",
    "char": "b",
}


def strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)  # /* ... */
    code = re.sub(r"//.*?$", "", code, flags=re.M)  # // ...
    return code


def normalize_ws(s: str) -> str:
    return " ".join(s.strip().split())


def parse_declarations(block: str) -> List[Tuple[str, str, int]]:
    """
    Return a list of (ctype, name, array_len) from the struct body block.
    Supports examples:
      uint32_t ts_ms;
      float ax, ay, az;
      float acc[3];
    Rejects pointers.
    """
    decls: List[Tuple[str, str, int]] = []
    # Split declarations by semicolon. Keep it simple and robust to spacing.
    for raw in block.split(";"):
        line = normalize_ws(raw)
        if not line:
            continue
        # Match "<ctype> names..."
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_ \t]*)\s+(.+)$", line)
        if not m:
            continue
        ctype_raw = m.group(1).strip()
        names_raw = m.group(2).strip()

        # Basic pointer rejection
        if "*" in ctype_raw or "*" in names_raw:
            raise ValueError(f"Pointers are not supported in: '{raw.strip()}'")

        # Split by commas to get each name or array
        for namepart in names_raw.split(","):
            namepart = namepart.strip()
            if not namepart:
                continue
            # Array?
            arrm = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]$", namepart)
            if arrm:
                nm = arrm.group(1)
                ln = int(arrm.group(2))
                decls.append((ctype_raw, nm, ln))
            else:
                # Scalar
                nm = namepart
                decls.append((ctype_raw, nm, 1))
    return decls


def derive_struct(
    header_path: str, struct_name: str, endian: str, packed: bool
) -> Tuple[str, List[str]]:
    """
    Return (fmt, labels) for the given typedef struct in header_path.
    Endianness is one of '<', '>', '='.
    If packed is false, a warning is printed; padding is not auto-inserted.
    """
    with open(header_path, "r", encoding="utf-8") as f:
        code = f.read()

    code = strip_comments(code)

    # Accept both:
    #   typedef struct { ... } MyName;
    #   typedef struct MyName { ... } MyName;
    pat = re.compile(
        r"typedef\s+struct(?:\s+"
        + re.escape(struct_name)
        + r")?\s*\{(.*?)\}\s*"
        + re.escape(struct_name)
        + r"\s*;",
        flags=re.S,
    )
    m = pat.search(code)
    if not m:
        raise ValueError(f"Could not find typedef struct {struct_name} in {header_path}")

    body = m.group(1)
    decls = parse_declarations(body)

    fmt_body = ""
    labels: List[str] = []

    for ctype_raw, name, arrlen in decls:
        ctype = normalize_ws(ctype_raw)
        if ctype not in CTYPE_MAP:
            raise ValueError(f"Unsupported C type '{ctype}'. Add a mapping in CTYPE_MAP if needed.")
        code_char = CTYPE_MAP[ctype]
        if arrlen == 1:
            fmt_body += code_char
            labels.append(name)
        else:
            fmt_body += code_char * arrlen
            labels.extend([f"{name}[{i}]" for i in range(arrlen)])

    if not packed:
        print(
            "[warn] packed=false. This script does not auto-insert padding. "
            "If your device struct is not packed, consider packing it on the device.",
            file=sys.stderr,
        )

    fmt = endian + fmt_body
    return fmt, labels


def main():
    ap = argparse.ArgumentParser(
        description="Derive Python struct format and field labels " + "from a C typedef struct."
    )
    ap.add_argument("--header", required=True, help="Path to the C header file")
    ap.add_argument("--struct-name", required=True, help="Name of the typedef struct to parse")
    ap.add_argument(
        "--endian",
        choices=["<", ">", "="],
        default="<",
        help="Endianness for Python struct: '<' little, '>' big, '=' native standard",
    )
    ap.add_argument(
        "--packed",
        type=lambda s: s.lower() in ("1", "true", "yes", "y"),
        default=True,
        help="Assume the device struct is packed (no padding). Default true",
    )
    args = ap.parse_args()

    try:
        fmt, labels = derive_struct(args.header, args.struct_name, args.endian, args.packed)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    out = {
        "struct_fmt": fmt,
        "fields": labels,
        "record_size": struct.calcsize(fmt),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
