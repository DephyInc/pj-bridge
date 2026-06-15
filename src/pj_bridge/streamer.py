#!/usr/bin/env python3
"""
streamer.py

In-process library API for bridging an arbitrary byte source into PlotJuggler.

The CLI tools (``bridge.py``, ``stream_parser.py``) read from TCP or a file.
This module exposes the same parse-and-forward pipeline as an importable class
so a host application (e.g. a GUI reading a serial port) can supply its own
byte source via a simple ``read_fn`` callable:

    from pj_bridge import PlotJugglerStreamer

    streamer = PlotJugglerStreamer(
        read_fn=lambda: ser.read(max(1, ser.in_waiting)),
        struct_header="telemetry.h",
        struct_name="MyRecord",
        ts_field="timestamp",
    )
    streamer.start()
    ...
    streamer.stop()

``read_fn`` is any blocking callable returning ``bytes`` (``b""`` when idle); it
runs in a worker thread so it never blocks the event loop. Records are parsed
with :class:`DelimitedRecordParser` and forwarded to PlotJuggler's WebSocket
Server via :func:`ws_sender`.
"""

import asyncio
import contextlib
import logging
import threading
from typing import Any, Callable, Optional

from .derive_struct import derive_struct
from .socket_client import ws_sender
from .stream_parser import DelimitedRecordParser

log = logging.getLogger("pj_bridge")

DEFAULT_WS_URL = "ws://127.0.0.1:9871"
DEFAULT_DELIMITER = b"\xde\xad\xbe\xef"  # 0xDEADBEEF

# Match the backpressure / queue bounds used by bridge.tcp_reader_to_queue.
_MAX_QUEUE = 20000
_BACKPRESSURE_HIGH_WATER = 10000


async def source_reader_to_queue(
    read_fn: Callable[[], bytes],
    parser: DelimitedRecordParser,
    q: "asyncio.Queue[Any]",
    *,
    stop_event: threading.Event,
    ignore_errors: bool = True,
) -> None:
    """Read bytes from ``read_fn``, parse into JSON, and enqueue for ``ws_sender``.

    Generalizes ``bridge.tcp_reader_to_queue`` to any blocking ``read_fn`` (run
    in a thread-pool executor). Returns when ``stop_event`` is set or ``read_fn``
    raises, and always enqueues a ``None`` sentinel on exit so ``ws_sender``
    finishes cleanly. Applies the same drop-oldest backpressure as the TCP path.
    """
    loop = asyncio.get_running_loop()
    leftover = b""
    try:
        while not stop_event.is_set():
            try:
                chunk = await loop.run_in_executor(None, read_fn)
            except Exception as e:
                log.warning("source read failed: %s", e)
                break
            if not chunk:
                # read_fn returned idle (e.g. serial read timeout); yield and
                # re-check stop_event rather than spin.
                await asyncio.sleep(0.001)
                continue
            msgs, leftover = parser.parse_buffer(leftover + chunk, ignore_errors)
            for m in msgs:
                if q.qsize() > _BACKPRESSURE_HIGH_WATER:
                    with contextlib.suppress(asyncio.QueueEmpty):
                        q.get_nowait()
                await q.put(m)
    finally:
        await q.put(None)


class PlotJugglerStreamer:
    """Parse a delimiter-framed byte source and forward records to PlotJuggler.

    Owns a background thread running an asyncio event loop with two tasks: a
    reader (``read_fn`` -> :class:`DelimitedRecordParser` -> queue) and
    :func:`ws_sender` (queue -> PlotJuggler WebSocket Server). Construct, then
    :meth:`start` / :meth:`stop`.
    """

    def __init__(
        self,
        read_fn: Callable[[], bytes],
        *,
        struct_header: str,
        struct_name: str,
        ws_url: str = DEFAULT_WS_URL,
        controller_out_size: Optional[int] = None,
        delimiter: bytes = DEFAULT_DELIMITER,
        endian: str = "<",
        packed: bool = True,
        ts_field: Optional[str] = "timestamp",
        ts_scale: float = 1e-3,
        name_prefix: Optional[str] = None,
        counted_batch: bool = True,
        max_frames_per_batch: int = 64,
        retry_sec: float = 2.0,
        on_connect: Optional[Callable[[], None]] = None,
        on_disconnect: Optional[Callable[[], None]] = None,
    ) -> None:
        struct_fmt, fields = derive_struct(
            header_path=str(struct_header),
            struct_name=struct_name,
            controller_out_size=controller_out_size,
            endian=endian,
            packed=packed,
        )
        self._parser = DelimitedRecordParser(
            struct_fmt=struct_fmt,
            fields=fields,
            ts_field=ts_field,
            ts_scale=ts_scale,
            name_prefix=name_prefix,
            delimiter=delimiter,
            counted_batch=counted_batch,
            max_frames_per_batch=max_frames_per_batch,
        )
        self._read_fn = read_fn
        self._ws_url = ws_url
        self._retry_sec = retry_sec
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the streaming thread. No-op if already running."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="pj-streamer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the streaming thread to stop and wait up to ``timeout`` seconds."""
        self._stop_event.set()
        t = self._thread
        if t is not None:
            t.join(timeout)
        self._thread = None

    def _run(self) -> None:
        try:
            asyncio.run(self._run_async())
        except Exception as e:  # pragma: no cover - defensive; thread top-level
            log.error("PlotJuggler streamer crashed: %s", e)

    async def _run_async(self) -> None:
        q: "asyncio.Queue[Any]" = asyncio.Queue(maxsize=_MAX_QUEUE)
        reader = asyncio.create_task(
            source_reader_to_queue(self._read_fn, self._parser, q, stop_event=self._stop_event)
        )
        sender = asyncio.create_task(
            ws_sender(
                self._ws_url,
                q,
                self._retry_sec,
                on_connect=self._on_connect,
                on_disconnect=self._on_disconnect,
            )
        )

        # The reader exits promptly once stop_event is set and enqueues the
        # None sentinel. If PlotJuggler's server is up, the sender drains the
        # sentinel and returns; if it is down (stuck reconnecting), it never
        # sees the sentinel, so cancel it after a short flush window.
        await reader
        try:
            await asyncio.wait_for(sender, timeout=1.0)
        except asyncio.TimeoutError:
            sender.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sender
