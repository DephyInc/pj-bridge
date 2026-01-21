#!/usr/bin/env python3
"""
stream_parser.py

Connect to a delimiter-framed stream and output NDJSON (one JSON object per line).

Framing supported (default and recommended):
  [ 0xDE 0xAD 0xBE 0xEF ][ COUNT:1 byte ][ MSG_ID: 2 bytes][ PAYLOAD ] * COUNT

Where PAYLOAD is a fixed-size packed C struct derived from your header file.

Examples:

  python3 _parser.py \
    --host 192.168.1.91 \
    --port 5000 \
    --delimiter 0xDEADBEEF \
    --struct-header /path/to/telemetry.h \
    --struct-name MyStruct \
    --endian "<" \
    --ts-field ts_ms \
    --ts-scale 1e-3 \
    --name-prefix "device_a."

Notes:
  - Prints one JSON per line to stdout (NDJSON). Flushes by default unless --no-flush.
  - Reconnects on TCP errors.
  - If your device struct is not packed, add packing on the device or extend the fmt
    with explicit padding.
"""

import argparse
import json
import logging
import socket
import struct
import sys
import time
from typing import List, Optional, Tuple

# Import derive_struct from sibling module
try:
    from .derive_struct import derive_struct
except Exception:
    print(
        "error: could not import derive_struct.",
        file=sys.stderr,
    )
    raise


def parse_hex_u32(s: str) -> bytes:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 8:
        raise ValueError("delimiter must be exactly 4 bytes (8 hex chars)")
    val = int(s, 16)
    return val.to_bytes(4, byteorder="big")


def connect_tcp(host: str, port: int, retry_sec: float, recv_buf: int) -> socket.socket:
    log = logging.getLogger("pj_bridge")
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(1.5)
            s.connect((host, port))
            if recv_buf > 0:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buf)
                except OSError as e:
                    log.debug("SO_RCVBUF not applied: %s", e)
            print(f"[TCP] connected to {host}:{port}", file=sys.stderr)
            return s
        except Exception as e:
            print(f"[TCP] connect failed: {e}. retry in {retry_sec}s", file=sys.stderr)
            time.sleep(retry_sec)


class DelimitedRecordParser:
    """
    Parses a stream framed by a 4-byte delimiter.
    Two modes:
      - counted batches: [DELIM][COUNT][PAYLOAD]*COUNT
      - single payload:  [DELIM][PAYLOAD]               (fallback if --no-counted-batch)

    DELIM is typically 0xDEADBEEF.
    """

    def __init__(
        self,
        struct_fmt: str,
        fields: List[str],
        ts_field: Optional[str],
        ts_scale: float,
        name_prefix: Optional[str],
        delimiter: bytes,
        counted_batch: bool = True,
        max_frames_per_batch: int = 64,
    ):
        self.struct_fmt = struct_fmt
        self.fields = fields
        self.ts_field = ts_field
        self.ts_scale = ts_scale
        self.name_prefix = name_prefix or ""
        self.delim = delimiter
        self.counted_batch = counted_batch
        self.max_frames_per_batch = max_frames_per_batch

        self.rec_size = struct.calcsize(self.struct_fmt)
        dummy = b"\x00" * self.rec_size
        if len(struct.unpack(self.struct_fmt, dummy)) != len(self.fields):
            raise ValueError("fields do not match struct format item count")

    def _decode_payload_to_json(self, payload: bytes) -> str:
        vals = struct.unpack(self.struct_fmt, payload)
        data = dict(zip(self.fields, vals))

        # timestamp (seconds as float)
        if self.ts_field:
            try:
                t_val = float(data[self.ts_field]) * self.ts_scale
            except (KeyError, TypeError, ValueError):
                t_val = time.time()
        else:
            t_val = time.time()

        out = {"t": t_val}
        for k, v in data.items():
            if k == self.ts_field:
                continue
            name = f"{self.name_prefix}{k}" if self.name_prefix else k
            out[name] = v
        return json.dumps(out, separators=(",", ":"), ensure_ascii=False)

    def parse_buffer(self, buf: bytes) -> Tuple[List[str], bytes]:
        """
        Scan the buffer for frames and return (list_of_json_strings, leftover_bytes).
        Robust to split delimiters and partial batches across chunks.
        """
        msgs: List[str] = []
        d = self.delim
        dlen = len(d)
        log = logging.getLogger("pj_bridge")

        i = 0
        blen = len(buf)

        while True:
            pos = buf.find(d, i)
            if pos < 0:
                # Keep tail to catch split delimiter across boundaries
                keep_from = max(blen - (dlen - 1), 0)
                return msgs, buf[keep_from:]

            # We found a delimiter at pos
            after_delim = pos + dlen

            if self.counted_batch:
                # Need at least 1 byte COUNT + 2 bytes message_id
                header_size = 1 + 2  # COUNT + message_id

                if after_delim + header_size > blen:
                    # Not enough data yet; keep from this delimiter
                    return msgs, buf[pos:]

                count = buf[after_delim]

                # Read 2-byte message_id (little-endian unsigned)
                msg_id_offset = after_delim + 1
                message_id = struct.unpack_from("<H", buf, msg_id_offset)[0]

                # Sanity check
                if count == 0:
                    # Skip delimiter + COUNT + message_id
                    i = after_delim + header_size
                    continue

                if count > self.max_frames_per_batch:
                    log.debug(
                        "batch count %d > max_frames_per_batch %d; skipping",
                        count,
                        self.max_frames_per_batch,
                    )
                    i = pos + 1
                    continue

                # Total bytes needed after COUNT + message_id
                total_payload_bytes = count * self.rec_size
                end_needed = after_delim + header_size + total_payload_bytes

                if end_needed > blen:
                    # Wait for more data; keep from this delimiter
                    return msgs, buf[pos:]

                # Decode each payload
                start_payloads = after_delim + header_size
                offset = start_payloads

                for _ in range(count):
                    payload = buf[offset : offset + self.rec_size]
                    try:
                        json_msg = self._decode_payload_to_json(payload)

                        # Attach message_id
                        obj = json.loads(json_msg)
                        obj["message_id"] = message_id
                        msgs.append(json.dumps(obj, separators=(",", ":")))

                    except (struct.error, ValueError) as e:
                        log.debug("malformed record skipped: %s", e)

                    offset += self.rec_size

                # Advance i past the whole batch
                i = end_needed
                # Continue scanning for the next delimiter
                continue
            else:
                # Single payload mode: [DELIM][PAYLOAD]
                start_payload = after_delim
                end_payload = start_payload + self.rec_size
                if end_payload <= blen:
                    payload = buf[start_payload:end_payload]
                    try:
                        msgs.append(self._decode_payload_to_json(payload))
                    except (struct.error, ValueError) as e:
                        log.debug("malformed record skipped: %s", e)
                    i = end_payload
                    continue
                else:
                    # Not enough bytes yet
                    return msgs, buf[pos:]


def file_reader_to_stdout(
    path: str,
    read_bytes: int,
    parser: DelimitedRecordParser,
):
    """
    Read binary data from file, parse frames, write JSON lines to stdout.
    """
    leftover = b""
    log = logging.getLogger("pj_bridge")

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(read_bytes)
                if not chunk:
                    break

                buf = leftover + chunk
                msgs, leftover = parser.parse_buffer(buf)

                for m in msgs:
                    sys.stdout.write(m)
                    sys.stdout.write("\n")

        sys.stdout.flush()
        log.info("file processing completed: %s", path)

    except Exception as e:
        log.error("file reader failed: %s", e)
        sys.exit(1)


def run(args):
    # Derive struct format and labels from header
    struct_fmt, fields = derive_struct(
        header_path=args.struct_header,
        struct_name=args.struct_name,
        endian=args.endian,
        packed=True if args.packed else False,
    )

    delimiter = parse_hex_u32(args.delimiter)
    parser = DelimitedRecordParser(
        struct_fmt=struct_fmt,
        fields=fields,
        ts_field=args.ts_field,
        ts_scale=args.ts_scale,
        name_prefix=args.name_prefix,
        delimiter=delimiter,
        counted_batch=(not args.no_counted_batch),
        max_frames_per_batch=args.max_frames_per_batch,
    )

    leftover = b""
    flush = not args.no_flush
    log = logging.getLogger("pj_bridge")

    while True:
        s = connect_tcp(args.host, args.port, args.retry_sec, args.recv_bytes)
        try:
            while True:
                try:
                    chunk = s.recv(args.recv_bytes)
                    if not chunk:
                        raise ConnectionError("EOF")
                    buf = leftover + chunk
                    msgs, leftover = parser.parse_buffer(buf)
                    for m in msgs:
                        print(m, flush=flush)
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[TCP] error: {e}. reconnecting...", file=sys.stderr)
            try:
                s.close()
            except OSError as e_close:
                log.debug("socket close failed: %s", e_close)
            except Exception as e_close:
                log.warning("unexpected error on socket close: %s", e_close)
            time.sleep(args.retry_sec)


def parse_args():
    ap = argparse.ArgumentParser(
        description="Parse a delimiter + count framed binary stream into JSON "
        + "(NDJSON to stdout)."
    )

    # Input source (mutually exclusive)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--host", help="Device host, e.g. 192.168.1.91")
    src.add_argument("--file", help="Path to local .bin file with captured stream")

    # TCP (short flags)
    ap.add_argument("--port", type=int, default=5000, help="Device TCP port")
    ap.add_argument("--recv-bytes", type=int, default=8192, help="recv() size")
    ap.add_argument("--retry-sec", type=float, default=2.0, help="reconnect delay")

    # Framing
    ap.add_argument("--delimiter", default="0xDEADBEEF", help="4-byte delimiter in hex")
    ap.add_argument(
        "--no-counted-batch",
        action="store_true",
        help="Disable [DELIM][COUNT][PAYLOAD]*COUNT parsing; " + "use single [DELIM][PAYLOAD] mode",
    )
    ap.add_argument(
        "--max-frames-per-batch",
        type=int,
        default=64,
        help="Sanity cap for COUNT to ignore corrupted batches",
    )

    # Struct derivation
    ap.add_argument("--struct-header", required=True, help="Path to C header")
    ap.add_argument("--struct-name", required=True, help="Typedef struct name")
    ap.add_argument("--endian", choices=["<", ">", "="], default="<")
    ap.add_argument(
        "--packed",
        type=lambda s: s.lower() in ("1", "true", "yes", "y"),
        default=True,
        help="Assume the device struct is packed (no padding). Default true",
    )

    # Timestamp and naming
    ap.add_argument("--ts-field", default=None, help="Field with device time (e.g. ts_ms)")
    ap.add_argument(
        "--ts-scale",
        type=float,
        default=1e-3,
        help="Scale device time to seconds (ms default)",
    )
    ap.add_argument("--name-prefix", default=None, help="Optional prefix, e.g. 'device_a.'")

    # Output
    ap.add_argument("--no-flush", action="store_true", help="Do not flush stdout on each line")

    return ap.parse_args()


def _setup_logging():
    logging.basicConfig(
        level=logging.INFO,  # change to DEBUG to see skipped-record details
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main():
    _setup_logging()


    args = parse_args()

    # 🚨 FILE MODE: stdout only, no asyncio, no WS
    if args.file:
        # Derive struct layout from the header
        struct_fmt, fields = derive_struct(
            header_path=args.struct_header,
            struct_name=args.struct_name,
            endian=args.endian,
            packed=True if args.packed else False,
        )

        delimiter = parse_hex_u32(args.delimiter)
        parser = DelimitedRecordParser(
            struct_fmt=struct_fmt,
            fields=fields,
            ts_field=args.ts_field,
            ts_scale=args.ts_scale,
            name_prefix=args.name_prefix,
            delimiter=delimiter,
            counted_batch=(not args.no_counted_batch),
            max_frames_per_batch=args.max_frames_per_batch,
        )
        file_reader_to_stdout(
            path=args.file,
            read_bytes=args.recv_bytes,
            parser=parser,
        )
        return

    # 🌐 TCP MODE
    try:
        run(parse_args())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
