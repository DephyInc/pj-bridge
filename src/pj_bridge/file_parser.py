#!/usr/bin/env python3
"""
file_parser.py

Parse a binary file containing back-to-back fixed-size records and emit NDJSON
(one JSON object per line) to stdout.

This is designed for circular log files where each record slot on disk is
slightly larger than the struct payload because of a checksum byte.

Example for your case:

- payload_size (struct) = 168 bytes
- slot_size (on disk)   = 169 bytes  (168 + 1 checksum)
- max records           = 600000
- file size             = 600000 * 169 = 101400000 bytes

We rely on derive_struct.py to build the Python struct format string and field list.

Typical usage:

  python3 file_parser.py \
    --input Current.log.2 \
    --control-file Current.control.2 \
    --struct-header bendy_sensor_data.h \
    --struct-name bendy_sensor_data_t \
    --endian "<" \
    --ts-field timestamp \
    --ts-scale 1e-3 \
    --name-prefix "bendy."

You can override the automatic start and record count, for example:

  python3 file_parser.py \
    --input Current.log.2 \
    --control-file Current.control.2 \
    --struct-header bendy_sensor_data.h \
    --struct-name bendy_sensor_data_t \
    --start-index 590000 \
    --records 10000
"""

import argparse
import json
import logging
import struct
import sys
import time
from typing import Dict, Iterable, List, Optional

# Import derive_struct from sibling module or same directory
try:
    from .derive_struct import derive_struct
except ImportError:
    try:
        from derive_struct import derive_struct
    except Exception:
        print("error: could not import derive_struct", file=sys.stderr)
        raise


def parse_control_file(path: str) -> Dict[str, object]:
    """
    Parse a simple key: value control file.

    Example:

      rsize: 168
      wrsize: 169
      max records: 600000
      session name:
      log spec id: 1
      metrics spec id: 1
      write index: 585000
      read index: 590000
    """
    result: Dict[str, object] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")
            val = val.strip()
            result[key] = val

    # Convert known integer fields
    int_keys = [
        "rsize",
        "wrsize",
        "max_records",
        "log_spec_id",
        "metrics_spec_id",
        "write_index",
        "read_index",
    ]
    for k in int_keys:
        if k in result and result[k] != "":
            try:
                result[k] = int(result[k])
            except ValueError:
                # Leave it as string if conversion fails
                pass

    return result


def _decode_record_to_json(
    payload: bytes,
    struct_fmt: str,
    fields: List[str],
    ts_field: Optional[str],
    ts_scale: float,
    name_prefix: Optional[str],
) -> str:
    """Unpack one record payload into JSON string."""
    vals = struct.unpack(struct_fmt, payload)
    data = dict(zip(fields, vals))

    # Compute timestamp (seconds as float)
    if ts_field:
        try:
            t_val = float(data[ts_field]) * ts_scale
        except (KeyError, TypeError, ValueError):
            t_val = time.time()
    else:
        t_val = time.time()

    out = {"t": t_val}
    prefix = name_prefix or ""

    for k, v in data.items():
        if k == ts_field:
            continue
        name = f"{prefix}{k}" if prefix else k
        out[name] = v

    return json.dumps(out, separators=(",", ":"), ensure_ascii=False)


def _iter_circular_payloads(
    buf: bytes,
    slot_size: int,
    payload_size: int,
    start_offset: int,
    n_records: int,
) -> Iterable[bytes]:
    """
    Yield n_records payloads of size payload_size from buf, treating buf as circular.

    Each record on disk occupies slot_size bytes (for example 169), but only the
    first payload_size bytes (for example 168) are the struct payload. The rest
    can be a checksum or padding.

    Wraps around at the end of the buffer. If a record crosses the end,
    it concatenates tail and head.
    """
    total = len(buf)

    if slot_size <= 0:
        raise ValueError("slot_size must be positive")
    if payload_size <= 0:
        raise ValueError("payload_size must be positive")
    if payload_size > slot_size:
        raise ValueError("payload_size cannot exceed slot_size")

    if total == 0:
        return

    # Normalize start_offset into [0, total)
    start_offset = start_offset % total

    for i in range(n_records):
        off = (start_offset + i * slot_size) % total
        end = off + slot_size

        if end <= total:
            # Record does not wrap
            slot = buf[off:end]
        else:
            # Record wraps around end of buffer
            tail = buf[off:total]
            head_len = end - total
            head = buf[0:head_len]
            slot = tail + head

        yield slot[:payload_size]


def run(args) -> None:
    log = logging.getLogger("file_parser")

    # Derive struct format and labels from header
    struct_fmt, fields = derive_struct(
        header_path=args.struct_header,
        struct_name=args.struct_name,
        endian=args.endian,
        packed=True if args.packed else False,
    )

    payload_size = struct.calcsize(struct_fmt)
    if payload_size <= 0:
        raise ValueError("struct.calcsize returned non-positive payload size")

    control = None
    if args.control_file:
        control = parse_control_file(args.control_file)
        log.info("loaded control file %s: %s", args.control_file, control)

    # Decide on slot_size used on disk
    slot_size = payload_size
    if control:
        ctrl_rsize = control.get("rsize")
        ctrl_wrsize = control.get("wrsize")

        if isinstance(ctrl_wrsize, int) and ctrl_wrsize > 0:
            slot_size = ctrl_wrsize
            if isinstance(ctrl_rsize, int) and ctrl_rsize != payload_size:
                log.warning(
                    "rsize from control file (%d) differs from struct size (%d)",
                    ctrl_rsize,
                    payload_size,
                )
        elif isinstance(ctrl_rsize, int) and ctrl_rsize > 0:
            slot_size = ctrl_rsize

    if slot_size < payload_size:
        raise ValueError(
            f"slot_size {slot_size} is smaller than payload_size {payload_size}"
        )

    # Read entire file
    with open(args.input, "rb") as f:
        data = f.read()

    total_bytes = len(data)
    if total_bytes < slot_size:
        raise ValueError(
            f"file too small ({total_bytes} bytes) for even one slot of size {slot_size}"
        )

    # Decide number of records to parse
    if args.records is not None:
        n_records = args.records
    else:
        n_records = None

        # If we have control info with read and write indices, prefer that
        if control:
            max_records = control.get("max_records")
            read_index = control.get("read_index")
            write_index = control.get("write_index")

            if (
                isinstance(max_records, int)
                and max_records > 0
                and isinstance(read_index, int)
                and isinstance(write_index, int)
            ):
                # Number of valid records in the ring buffer
                n_records = (write_index - read_index) % max_records
                if n_records == 0:
                    # Ambiguous full buffer case; fall back to max_records
                    n_records = max_records

        if n_records is None:
            # Fall back to as many full slots as fit in the file
            n_records = total_bytes // slot_size

    if n_records <= 0:
        raise ValueError("number of records to parse must be positive")

    # Do not try to parse more records than can fit in the file
    max_from_file = total_bytes // slot_size
    if n_records > max_from_file:
        log.warning(
            "requested %d records but file only has %d slots, truncating",
            n_records,
            max_from_file,
        )
        n_records = max_from_file

    # Decide starting byte offset
    if args.start_offset is not None:
        # Explicit byte offset overrides everything
        start_offset_bytes = args.start_offset
    else:
        start_offset_bytes = 0

        if args.start_index is not None:
            # Use caller-provided record index
            if control and isinstance(control.get("max_records"), int):
                max_records = control["max_records"]
                idx = args.start_index % max_records
            else:
                idx = args.start_index
            start_offset_bytes = idx * slot_size
        elif control:
            # Default to read_index from control file
            idx = None
            if isinstance(control.get("read_index"), int):
                idx = control["read_index"]
                log.info("using read_index %d from control file as start index", idx)
            elif isinstance(control.get("write_index"), int):
                idx = control["write_index"]
                log.info("using write_index %d from control file as start index", idx)

            if idx is not None:
                if isinstance(control.get("max_records"), int):
                    max_records = control["max_records"]
                    idx = idx % max_records
                start_offset_bytes = idx * slot_size

    # Sanity log
    log.info(
        "file size: %d bytes, slot_size: %d, payload_size: %d, "
        "start_offset_bytes: %d, records: %d",
        total_bytes,
        slot_size,
        payload_size,
        start_offset_bytes,
        n_records,
    )

    # Iterate over records in circular fashion
    flush = not args.no_flush
    count = 0
    for rec in _iter_circular_payloads(
        buf=data,
        slot_size=slot_size,
        payload_size=payload_size,
        start_offset=start_offset_bytes,
        n_records=n_records,
    ):
        try:
            line = _decode_record_to_json(
                payload=rec,
                struct_fmt=struct_fmt,
                fields=fields,
                ts_field=args.ts_field,
                ts_scale=args.ts_scale,
                name_prefix=args.name_prefix,
            )
            print(line, flush=flush)
            count += 1
        except struct.error as e:
            # Malformed record, log and continue
            log.debug("malformed record at index %d skipped: %s", count, e)
            continue

    log.info("finished, emitted %d JSON records", count)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Parse a circular binary file of fixed-size records into JSON "
            "(NDJSON to stdout). Supports payload+checksum slots."
        )
    )

    # File
    ap.add_argument(
        "--input",
        required=True,
        help="Path to binary file containing fixed-size record slots",
    )

    # Optional control file
    ap.add_argument(
        "--control-file",
        default=None,
        help="Path to control file (rsize, wrsize, max records, indices)",
    )

    # Struct derivation
    ap.add_argument("--struct-header", required=True, help="Path to C header")
    ap.add_argument("--struct-name", required=True, help="Typedef struct name")
    ap.add_argument(
        "--endian", choices=["<", ">", "="], default="<", help="Struct endianness"
    )
    ap.add_argument(
        "--packed",
        type=lambda s: s.lower() in ("1", "true", "yes", "y"),
        default=True,
        help="Assume the device struct is packed (no padding). Default true",
    )

    # Circular buffer parameters
    ap.add_argument(
        "--start-offset",
        type=int,
        default=None,
        help=(
            "Starting byte offset in the file. If given, overrides control file and "
            "start-index."
        ),
    )
    ap.add_argument(
        "--start-index",
        type=int,
        default=None,
        help=(
            "Starting record index in the circular buffer. Converted to a byte offset "
            "using slot_size and max_records when available."
        ),
    )
    ap.add_argument(
        "--records",
        type=int,
        default=None,
        help=(
            "Number of records to decode. If omitted, and a control file is provided "
            "with read and write indices, their difference is used. Otherwise the "
            "maximum number of full slots in the file is used."
        ),
    )

    # Timestamp and naming
    ap.add_argument(
        "--ts-field",
        default=None,
        help="Field with device time (for example: timestamp or ts_ms)",
    )
    ap.add_argument(
        "--ts-scale",
        type=float,
        default=1e-3,
        help="Scale device time to seconds (default assumes ms)",
    )
    ap.add_argument(
        "--name-prefix",
        default=None,
        help="Optional prefix for field names, for example 'bendy.'",
    )

    # Output
    ap.add_argument(
        "--no-flush",
        action="store_true",
        help="Do not flush stdout on each line (useful for very large outputs)",
    )

    return ap.parse_args()


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> None:
    _setup_logging()
    try:
        run(parse_args())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
