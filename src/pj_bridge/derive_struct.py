#!/usr/bin/env python3
"""
derive_struct.py

Derive a Python 'struct' format string and flattened field labels from a C typedef struct.

Now with two engines:
  1) CLANG AST (recommended): handles nested structs, arrays, enums; optional padding insertion
  2) REGEX fallback (your original): flat structs only, no nesting

Output JSON:
{
  "struct_fmt": "<Ifff",
  "fields": ["ts_ms","ax","ay","az"],
  "record_size": 16
}

Examples:
  # Prefer clang engine automatically (if libclang is available):
  python derive_struct.py --header dsp_messages.h --struct-name MSGFullState --endian "<"

  # Force clang and respect C field offsets (insert 'x' padding as needed):
  python derive_struct.py --header dsp_messages.h --struct-name MSGFullState --endian "<" --mode clang --respect-offsets

  # Force regex engine (flat structs only):
  python derive_struct.py --header telemetry.h --struct-name MyStruct --mode regex
"""

import argparse
import json
import re
import struct as pystruct
import sys
from typing import List, Tuple, Optional

# ---------- Common type map for REGEX fallback ----------
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
    "char": "b",  # change to "B" if you want unsigned char semantics
}


# ---------- Small helpers ----------
def strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)  # /* ... */
    code = re.sub(r"//.*?$", "", code, flags=re.M)  # // ...
    return code


def normalize_ws(s: str) -> str:
    return " ".join(s.strip().split())


# ---------- REGEX fallback (flat structs only) ----------
def parse_declarations(block: str) -> List[Tuple[str, str, int]]:
    """
    Return a list of (ctype, name, array_len) from the struct body block.
    Supports:
      uint32_t ts_ms;
      float ax, ay, az;
      float acc[3];
    Rejects pointers & nested structs.
    """
    decls: List[Tuple[str, str, int]] = []
    for raw in block.split(";"):
        line = normalize_ws(raw)
        if not line:
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_ \t]*)\s+(.+)$", line)
        if not m:
            continue
        ctype_raw = m.group(1).strip()
        names_raw = m.group(2).strip()

        if "*" in ctype_raw or "*" in names_raw:
            raise ValueError(f"Pointers are not supported in: '{raw.strip()}'")

        for namepart in names_raw.split(","):
            namepart = namepart.strip()
            if not namepart:
                continue
            arrm = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]$", namepart)
            if arrm:
                nm = arrm.group(1)
                ln = int(arrm.group(2))
                decls.append((ctype_raw, nm, ln))
            else:
                nm = namepart
                decls.append((ctype_raw, nm, 1))
    return decls


def derive_struct_regex(
    header_path: str, struct_name: str, endian: str, packed: bool
) -> Tuple[str, List[str]]:
    with open(header_path, "r", encoding="utf-8") as f:
        code = f.read()
    code = strip_comments(code)

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
        raise ValueError(
            f"[regex] Could not find typedef struct {struct_name} in {header_path}"
        )

    body = m.group(1)
    decls = parse_declarations(body)

    fmt_body = ""
    labels: List[str] = []
    for ctype_raw, name, arrlen in decls:
        ctype = normalize_ws(ctype_raw)
        if ctype not in CTYPE_MAP:
            raise ValueError(
                f"[regex] Unsupported C type '{ctype}'. Add a mapping in CTYPE_MAP if needed."
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
            "[warn] packed=false. No auto-inserted padding in regex mode.",
            file=sys.stderr,
        )
    fmt = endian + fmt_body
    return fmt, labels


# ---------- CLANG engine (nested structs, arrays, enums, optional padding) ----------
def _load_clang():
    """
    Prefer the PyPI 'libclang' (bundles the shared lib). Fall back to system clang bindings if available.
    """
    try:
        import libclang  # noqa: F401  # ensures bundled lib is on path
        from clang import cindex

        return cindex
    except Exception:
        try:
            from clang import cindex

            return cindex
        except Exception as e:
            raise RuntimeError(
                "Clang not available. Install one of:\n"
                "  pip install libclang ctypeslib2  # bundled libclang\n"
                "or\n"
                "  pip install clang ctypeslib2     # uses system libclang (ensure it's installed)"
            ) from e


# Map a clang built-in to (fmt_char, size). We infer signedness from type spelling where needed.
def _clang_builtin_to_fmt(t):
    kind = (
        t.kind.name
    )  # e.g., 'BOOL', 'SCHAR', 'UCHAR', 'SHORT', 'USHORT', 'INT', 'UINT', 'LONG', 'ULONG', 'LONGLONG', 'ULONGLONG', 'FLOAT', 'DOUBLE'
    # Use size (in bytes) and signedness to choose fmt:
    size = t.get_size()  # bytes
    signed = None
    # Heuristic: many kinds encode signedness in name; else, assume signed for enums/ints unless U... form.
    if "U" in kind:  # UCHAR, USHORT, UINT, ULONG, ULONGLONG
        signed = False
    elif kind in ("CHAR_U",):
        signed = False
    elif kind in ("CHAR_S", "SCHAR"):
        signed = True

    # floats/doubles:
    if kind == "FLOAT" and size == 4:
        return "f", 4
    if kind == "DOUBLE" and size == 8:
        return "d", 8
    if kind == "BOOL" and size == 1:
        return "?", 1

    # integers:
    if size == 1:
        return ("b" if signed is not False else "B"), 1
    if size == 2:
        return ("h" if signed is not False else "H"), 2
    if size == 4:
        return ("i" if signed is not False else "I"), 4
    if size == 8:
        return ("q" if signed is not False else "Q"), 8

    raise ValueError(f"Unsupported builtin kind={kind} size={size}")


def derive_struct_clang(
    header_path: str,
    struct_name: str,
    endian: str,
    respect_offsets: bool,
    clang_args: Optional[List[str]] = None,
) -> Tuple[str, List[str]]:
    """
    Parse header with clang, flatten nested structs/arrays/enums.
    If respect_offsets=True, insert 'x' padding to match C field bit offsets.
    """
    cindex = _load_clang()
    index = cindex.Index.create()

    # Basic args; users can add include paths via --clang-arg
    args = clang_args or []
    tu = index.parse(header_path, args=args)
    if not tu:
        raise RuntimeError("clang could not parse the header")

    # Find the typedef'ed struct 'struct_name'
    target = None
    for cursor in tu.cursor.get_children():
        if cursor.kind.name in ("TYPEDEF_DECL", "STRUCT_DECL"):
            # Try to resolve to record named struct_name
            resolved = (
                cursor.underlying_typedef_type
                if cursor.kind.name == "TYPEDEF_DECL"
                else cursor.type
            )
            rec = resolved.get_declaration()
            if rec and rec.kind.name == "STRUCT_DECL":
                name = rec.spelling or cursor.spelling
                if name == struct_name:
                    target = rec
                    break
    if target is None:
        # also search deeper
        def dfs(cur):
            nonlocal target
            for c in cur.get_children():
                if c.kind.name in ("TYPEDEF_DECL", "STRUCT_DECL"):
                    resolved = (
                        c.underlying_typedef_type
                        if c.kind.name == "TYPEDEF_DECL"
                        else c.type
                    )
                    rec = resolved.get_declaration()
                    if rec and rec.kind.name == "STRUCT_DECL":
                        name = rec.spelling or c.spelling
                        if name == struct_name:
                            target = rec
                            return
                dfs(c)

        dfs(tu.cursor)
        if target is None:
            raise ValueError(
                f"[clang] Could not find typedef struct {struct_name} in {header_path}"
            )

    fmt_parts: List[str] = []
    labels: List[str] = []
    bitpos_so_far = 0  # bits, for padding alignment if respect_offsets

    def add_padding_to(bitpos_target: int):
        nonlocal bitpos_so_far
        if not respect_offsets:
            return
        if bitpos_target < bitpos_so_far:
            # overlapping/bitfield; we don't handle true C bitfields here (emit as storage unit)
            return
        delta_bits = bitpos_target - bitpos_so_far
        if delta_bits <= 0:
            return
        # pad with 'x' bytes
        nbytes = delta_bits // 8
        if nbytes:
            fmt_parts.append("x" * nbytes)
            bitpos_so_far += nbytes * 8

    def flatten(ctype, base_cursor, prefix: str = ""):
        nonlocal bitpos_so_far

        ck = ctype.kind.name

        # Arrays
        if ck == "CONSTANTARRAY":
            elem = ctype.get_array_element_type()
            count = ctype.get_array_size()
            # Align to array storage start if we have offsets
            if respect_offsets and base_cursor is not None:
                add_padding_to(base_cursor.get_field_offsetof())  # bits
            # For arrays of POD, we just repeat flatten without labels suffix if nested struct? We add [i]
            for i in range(count):
                flatten(elem, base_cursor, f"{prefix}[{i}]")
            # Advance cursor by array size
            size_bits = ctype.get_size() * 8
            bitpos_so_far = max(
                bitpos_so_far,
                (base_cursor.get_field_offsetof() if base_cursor else bitpos_so_far)
                + size_bits,
            )
            return

        # Records (struct)
        if ck == "RECORD":
            # Iterate fields in order
            for field in ctype.get_fields():
                field_type = field.type
                field_name = field.spelling or "field"
                name = f"{prefix}{('.' if prefix else '')}{field_name}"

                # Insert padding up to field start
                if respect_offsets:
                    add_padding_to(field.get_field_offsetof())  # bits

                if field_type.kind.name == "RECORD":
                    flatten(field_type, field, name)
                elif field_type.kind.name == "CONSTANTARRAY":
                    # arrays: expand elements with [i]
                    elem = field_type.get_array_element_type()
                    count = field_type.get_array_size()
                    for i in range(count):
                        # Padding to each element boundary is implicit in sequential build;
                        # rely on offsets if needed.
                        flatten(elem, field, f"{name}[{i}]")
                elif field_type.kind.name in ("ENUM",):
                    # Treat enums as signed int of the enum's storage size
                    size = field_type.get_size()
                    if size == 1:
                        fmt_parts.append("b")
                        labels.append(name)
                        bitpos_so_far += 8
                    elif size == 2:
                        fmt_parts.append("h")
                        labels.append(name)
                        bitpos_so_far += 16
                    elif size == 4:
                        fmt_parts.append("i")
                        labels.append(name)
                        bitpos_so_far += 32
                    elif size == 8:
                        fmt_parts.append("q")
                        labels.append(name)
                        bitpos_so_far += 64
                    else:
                        raise ValueError(f"Unsupported enum size {size} for {name}")
                else:
                    # Builtins
                    fmt_char, nbytes = _clang_builtin_to_fmt(field_type)
                    fmt_parts.append(fmt_char)
                    labels.append(name)
                    bitpos_so_far += nbytes * 8
            return

        # Builtin leaf (when called directly, e.g., top-level array element)
        fmt_char, nbytes = _clang_builtin_to_fmt(ctype)
        fmt_parts.append(fmt_char)
        # For anonymous elements in arrays, prefix already contains base name+[i]
        labels.append(prefix if prefix else "field")
        bitpos_so_far += nbytes * 8

    # Kick off on the record itself
    flatten(target.type, target, "")

    fmt = endian + "".join(fmt_parts)
    return fmt, labels


# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(
        description="Derive Python struct format and field labels from a C typedef struct."
    )
    ap.add_argument("--header", required=True, help="Path to the C header file")
    ap.add_argument(
        "--struct-name", required=True, help="Name of the typedef struct to parse"
    )
    ap.add_argument(
        "--endian",
        choices=["<", ">", "="],
        default="<",
        help="Endianness for Python struct: '<' little, '>' big, '=' native standard",
    )
    ap.add_argument(
        "--mode",
        choices=["auto", "clang", "regex"],
        default="auto",
        help="Parsing engine: 'clang' (nested structs), 'regex' (flat only), or 'auto' (prefer clang if available).",
    )
    ap.add_argument(
        "--respect-offsets",
        action="store_true",
        help="(clang only) Insert 'x' padding to match C field offsets.",
    )
    ap.add_argument(
        "--clang-arg",
        action="append",
        default=[],
        help="Additional argument passed to libclang (e.g., -I<include_dir>). Can be repeated.",
    )
    args = ap.parse_args()

    # Choose engine
    use_clang = False
    if args.mode == "clang":
        use_clang = True
    elif args.mode == "regex":
        use_clang = False
    else:  # auto
        try:
            _ = _load_clang()
            use_clang = True
        except Exception:
            use_clang = False

    try:
        if use_clang:
            fmt, labels = derive_struct_clang(
                header_path=args.header,
                struct_name=args.struct_name,
                endian=args.endian,
                respect_offsets=args.respect_offsets,
                clang_args=args.clang_arg or None,
            )
        else:
            fmt, labels = derive_struct_regex(
                header_path=args.header,
                struct_name=args.struct_name,
                endian=args.endian,
                packed=True,  # keep old behavior; padding is user-managed
            )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    out = {
        "struct_fmt": fmt,
        "fields": labels,
        "record_size": pystruct.calcsize(fmt),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
