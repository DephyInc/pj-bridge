#!/usr/bin/env python3
"""
socket_client.py

Read NDJSON lines (one JSON object per line) from stdin or a file and forward
each line to PlotJuggler's WebSocket Server as a text message.

Typical usage with your tcp_parser:
  python3 tcp_parser.py ... | python3 socket_client.py --ws-url ws://127.0.0.1:9871

Or from a saved file:
  python3 socket_client.py --input data.ndjson --ws-url ws://127.0.0.1:9871
"""

import argparse
import asyncio
import json
import sys
from typing import Optional

try:
    import websockets
except ImportError:
    print("error: please 'pip install websockets'", file=sys.stderr)
    sys.exit(1)


async def producer(input_path: Optional[str], q: asyncio.Queue, validate: bool, strip: bool):
    """
    Read NDJSON lines from stdin or a file and enqueue them.
    """
    loop = asyncio.get_running_loop()

    async def read_stream(stream):
        while True:
            line = await loop.run_in_executor(None, stream.readline)
            if not line:
                break
            if strip:
                line = line.strip()
                if not line:
                    continue
            if validate:
                try:
                    _ = json.loads(line)
                except Exception:
                    # Skip invalid lines but keep going
                    print(f"[socket_client] skipped invalid JSON: {line[:120]}", file=sys.stderr)
                    continue
            # backpressure control
            if q.qsize() > 10000:
                try:
                    _ = q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await q.put(line)

    if input_path and input_path != "-":
        with open(input_path, "r", encoding="utf-8") as f:
            await read_stream(f)
    else:
        await read_stream(sys.stdin)

    # signal completion
    await q.put(None)


async def ws_sender(ws_url: str, q: asyncio.Queue, retry_sec: float):
    """
    Connect to PlotJuggler WS server and forward queued messages.
    Reconnect on failure. Stops when producer sends None.
    """
    pending = []
    while True:
        try:
            async with websockets.connect(ws_url, max_queue=None) as ws:
                print(f"[socket_client] connected to {ws_url}", file=sys.stderr)
                # flush any pending first
                for msg in pending:
                    await ws.send(msg)
                pending.clear()
                while True:
                    item = await q.get()
                    if item is None:
                        return
                    try:
                        await ws.send(item)
                    except Exception as e:
                        # keep unsent item for next connect
                        pending.append(item)
                        raise e
        except Exception as e:
            print(f"[socket_client] WS error: {e}. reconnect in {retry_sec}s", file=sys.stderr)
            await asyncio.sleep(retry_sec)


def parse_args():
    ap = argparse.ArgumentParser(
        description="Forward NDJSON lines to PlotJuggler WebSocket Server."
    )
    ap.add_argument("--ws-url", default="ws://127.0.0.1:9871",
                    help="PlotJuggler WebSocket Server URL (default ws://127.0.0.1:9871)")
    ap.add_argument("--input", default="-",
                    help="NDJSON input file. Use '-' for stdin (default)")
    ap.add_argument("--retry-sec", type=float, default=2.0,
                    help="Reconnect delay on WS errors")
    ap.add_argument("--no-validate", action="store_true",
                    help="Do not JSON-validate each line")
    ap.add_argument("--no-strip", action="store_true",
                    help="Do not strip whitespace; keep lines verbatim")
    return ap.parse_args()


async def main_async():
    args = parse_args()
    q: asyncio.Queue = asyncio.Queue(maxsize=20000)
    tasks = [
        asyncio.create_task(
            producer(
                input_path=args.input,
                q=q,
                validate=not args.no_validate,
                strip=not args.no_strip,
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


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
