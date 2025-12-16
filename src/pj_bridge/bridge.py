#!/usr/bin/env python3
"""
bridge.py

All-in-one bridge:
- Connect to a delimiter + count framed TCP binary stream
- Derive struct layout from a C header
- Parse each record into JSON
- Forward JSON to PlotJuggler's WebSocket Server over WebSocket

Relies on local modules:
  - derive_struct.py: derive_struct(header_path, struct_name, endian, packed)
  - tcp_parser.py: DelimitedRecordParser, parse_hex_u32, connect_tcp
  - socket_client.py: ws_sender(ws_url, queue, retry_sec)

Example:

  python3 bridge.py \
    --host 192.168.1.91 \
    --port 5000 \
    --delimiter 0xDEADBEEF \
    --struct-header /path/to/telemetry.h \
    --struct-name MyRecord \
    --endian "<" \
    --ts-field ts_ms \
    --ts-scale 1e-3 \
    --name-prefix "device_a." \
    --ws-url ws://127.0.0.1:9871
"""

import argparse
import asyncio
import logging
import socket
import sys

# Local deps
try:
    from .derive_struct import derive_struct
except Exception:
    print(
        "error: could not import derive_struct. Ensure derive_struct.py is present.",
        file=sys.stderr,
    )
    raise

try:
    from .tcp_parser import DelimitedRecordParser, connect_tcp, parse_hex_u32
except Exception:
    print(
        "error: could not import from tcp_parser. Ensure tcp_parser.py is present.",
        file=sys.stderr,
    )
    raise

try:
    from .socket_client import ws_sender
except Exception:
    print("error: could not import ws_sender from socket_client.py.", file=sys.stderr)
    raise


async def tcp_reader_to_queue(
    host: str,
    port: int,
    recv_bytes: int,
    retry_sec: float,
    parser: DelimitedRecordParser,
    q: asyncio.Queue,
):
    """
    Receive raw bytes from the device, parse into JSON strings, enqueue them.
    Reconnects on errors. Uses a background thread to avoid blocking the event loop.
    """
    leftover = b""
    loop = asyncio.get_running_loop()

    while True:
        s = connect_tcp(host, port, retry_sec, recv_bytes)
        try:
            while True:
                try:
                    chunk = await loop.run_in_executor(None, s.recv, recv_bytes)
                    if not chunk:
                        raise ConnectionError("EOF")
                    buf = leftover + chunk
                    msgs, leftover = parser.parse_buffer(buf)
                    for m in msgs:
                        # backpressure: drop oldest if queue grows too large
                        if q.qsize() > 10000:
                            try:
                                _ = q.get_nowait()
                            except asyncio.QueueEmpty:
                                pass
                        await q.put(m)
                except socket.timeout:
                    continue
        except Exception:
            try:
                s.close()
            except OSError as e:
                logging.getLogger("pj_bridge").debug("socket close failed: %s", e)
            except Exception as e:
                logging.getLogger("pj_bridge").warning("unexpected error on socket close: %s", e)

            await asyncio.sleep(retry_sec)


def parse_args():
    ap = argparse.ArgumentParser(
        description="Bridge a delimiter+count framed TCP binary stream to PlotJuggler"
        + " via WebSocket JSON."
    )

    # Device TCP (short flags)
    ap.add_argument("--host", required=True, help="Device host, e.g. 192.168.1.91")
    ap.add_argument("--port", type=int, default=5000, help="Device TCP port, e.g. 5000")
    ap.add_argument("--recv-bytes", type=int, default=8192, help="TCP recv() size")
    ap.add_argument("--retry-sec", type=float, default=2.0, help="Reconnect delay")

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
    ap.add_argument("--ts-scale", type=float, default=1e-3, help="Scale device time to seconds")
    ap.add_argument("--name-prefix", default=None, help="Optional prefix, e.g. 'device_a.'")

    # PlotJuggler WebSocket Server
    ap.add_argument(
        "--ws-url",
        default="ws://127.0.0.1:9871",
        help="PJ WebSocket Server URL (default ws://127.0.0.1:9871)",
    )

    return ap.parse_args()


async def main_async():
    args = parse_args()

    # Derive struct layout from the header
    struct_fmt, fields = derive_struct(
        header_path=args.struct_header,
        struct_name=args.struct_name,
        endian=args.endian,
        packed=True if args.packed else False,
    )

    # Build record parser (counted-batch by default)
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

    # Queue between TCP reader and WS sender
    q: asyncio.Queue = asyncio.Queue(maxsize=20000)

    # Tasks: TCP ingest -> q, WS sender <- q
    tasks = [
        asyncio.create_task(
            tcp_reader_to_queue(
                host=args.host,
                port=args.port,
                recv_bytes=args.recv_bytes,
                retry_sec=args.retry_sec,
                parser=parser,
                q=q,
            )
        ),
        asyncio.create_task(ws_sender(args.ws_url, q, args.retry_sec)),
    ]

    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def _setup_logging():
    logging.basicConfig(
        level=logging.INFO,  # change to DEBUG to see skipped-record details
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main():
    _setup_logging()
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
