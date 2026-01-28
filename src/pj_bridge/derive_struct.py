#!/usr/bin/env python3
"""
derive_struct.py

Parse a C header to derive a Python struct format string and expanded field
labels for a typedef'ed struct.

Assumptions and limits:
- Looks for: typedef struct { ... } <StructName>;
  and also: typedef struct <TagName> { ... } <StructName>;
- Supports stdint types (int8_t, uint32_t, etc.), float, double, bool, char.
- Supports fixed-size arrays like: float acc[3];
- Rejects pointers, bitfields, and nested structs or other non-primitive types.
- Does not auto-insert padding. If the device struct is not packed, use
  --packed false and provide explicit padding manually in a later step.

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
from typing import Dict, List, Tuple

# Map common C types to Python struct codes.
# char is mapped to signed byte by default. Change to "B" if needed.
CTYPE_MAP: Dict[str, str] = {
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
    "HiddenHighLevelControllerOutputData_s": "b",
}


def strip_comments(code: str) -> str:
    """Remove /* ... */ and // ... comments from C code."""
    # Block comments
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    # Line comments (including ///< style)
    code = re.sub(r"//.*?$", "", code, flags=re.M)
    return code


def normalize_ws(s: str) -> str:
    """Normalize whitespace inside a line."""
    return " ".join(s.strip().split())


def parse_declarations(block: str, controller_out_size: int | None = None) -> List[Tuple[str, str, int]]:
    """
    Return a list of (ctype, name, array_len) from the struct body block.

    Supports examples:
      uint32_t ts_ms;
      float ax, ay, az;
      float acc[3];

    Rejects pointers. Assumes no nested structs.
    """
    decls: List[Tuple[str, str, int]] = []

    # Split declarations by semicolon. This is safe enough given our assumptions.
    for raw in block.split(";"):
        line = normalize_ws(raw)
        if not line:
            continue

        # Remove any leading struct keywords
        if line.startswith("struct "):
            line = line[len("struct "):]

        # Match "<ctype> names..."
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_ \t]*)\s+(.+)$", line)
        if not m:
            # Could be something we do not support, just skip.
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
            ln = 1
            arrm = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]$", namepart)
            if arrm:
                nm = arrm.group(1)
                ln = int(arrm.group(2))
            else:
                # Scalar
                nm = namepart
                ln = 1
                if ctype_raw.casefold() == "HiddenHighLevelControllerOutputData_s".casefold():
                    if controller_out_size is None:
                        raise ValueError(f"Must specify controller-out-size if using HiddenHighLevelControllerOutputData_s type")
                    else:
                        ln = controller_out_size
            decls.append((ctype_raw, nm, ln))

    return decls


def find_typedef_struct_body(code: str, struct_name: str) -> str:
    """
    Find the body of `typedef struct { ... } struct_name;` in the given
    preprocessed code.

    Works with:
      typedef struct { ... } Name;
      typedef struct Tag { ... } Name;

    Returns the string inside the braces.
    Raises ValueError if not found.
    """
    idx = 0
    keyword = "typedef struct"

    while True:
        idx = code.find(keyword, idx)
        if idx == -1:
            break

        # Find first '{' after 'typedef struct'
        brace_start = code.find("{", idx)
        if brace_start == -1:
            break

        # Find matching closing brace by counting
        depth = 0
        i = brace_start
        while i < len(code):
            c = code[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1

        if depth != 0:
            # Unbalanced braces, give up on this occurrence.
            idx = brace_start + 1
            continue

        brace_end = i

        # After the closing brace, we expect something like:
        #   } Name;
        # possibly with some whitespace.
        after = code[brace_end + 1 :]

        m = re.match(
            r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
            after,
        )
        if not m:
            # This typedef struct might have some attribute or something else
            # that we do not handle; skip it.
            idx = brace_end + 1
            continue

        name = m.group(1)
        if name == struct_name:
            # Found the struct we want
            return code[brace_start + 1 : brace_end]

        # Move forward and keep searching
        idx = brace_end + 1

    raise ValueError(f"Could not find typedef struct {struct_name} in header")


def derive_struct(
    header_path: str, struct_name: str, endian: str, packed: bool, controller_out_size: int | None = None
) -> Tuple[str, List[str]]:
    """
    Return (fmt, labels) for the given typedef struct in header_path.

    Endianness is one of '<', '>', '='.
    If packed is False, a warning is printed; padding is not auto-inserted.
    """
    with open(header_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Strip comments first to make brace scanning robust
    code = strip_comments(code)

    # Extract only the body of the requested typedef struct
    body = find_typedef_struct_body(code, struct_name)

    # Parse declarations inside the struct
    decls = parse_declarations(body, controller_out_size)

    fmt_body = ""
    labels: List[str] = []

    for ctype_raw, name, arrlen in decls:
        ctype = normalize_ws(ctype_raw)

        if ctype not in CTYPE_MAP:
            raise ValueError(
                f"Unsupported C type '{ctype}' in field '{name}'. "
                "This script currently only supports primitive types. "
                "You may need to extend CTYPE_MAP or avoid nested structs."
            )

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
            "If your device struct is not packed, consider packing it on the device "
            "or inserting padding fields manually.",
            file=sys.stderr,
        )

    fmt = endian + fmt_body
    return fmt, labels


def main() -> None:
    ap = argparse.ArgumentParser(
        description=("Derive Python struct format and field labels " "from a C typedef struct.")
    )
    ap.add_argument("--header", required=True, help="Path to the C header file")
    ap.add_argument(
        "--struct-name",
        required=True,
        help="Name of the typedef struct to parse " "(for example: bendy_sensor_data_t)",
    )
    ap.add_argument(
        "--controller-out-size",
        type=int,
        help="Size of controller output, which is a part of the struct" "(for example: 109)",
    )
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
        fmt, labels = derive_struct(args.header, args.struct_name, args.endian, args.packed, args.controller_out_size if args.controller_out_size else None)
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
