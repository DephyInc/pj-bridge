"""Unit tests for pj_bridge.streamer (no sockets, no PlotJuggler, no hardware)."""

import asyncio
import json
import struct
import threading
import unittest

from pj_bridge.stream_parser import DelimitedRecordParser
from pj_bridge.streamer import source_reader_to_queue

DELIM = b"\xde\xad\xbe\xef"  # 0xDEADBEEF

# One record: uint32 timestamp (ms) + float value.
_FMT = "<If"
_FIELDS = ["timestamp", "value"]


def _make_batch(msg_id, records):
    """Frame a counted batch: [DELIM][COUNT:1][msg_id:2 LE][record]*COUNT."""
    payload = b"".join(struct.pack(_FMT, ts, val) for ts, val in records)
    return DELIM + bytes([len(records)]) + struct.pack("<H", msg_id) + payload


def _make_parser():
    return DelimitedRecordParser(
        struct_fmt=_FMT,
        fields=_FIELDS,
        ts_field="timestamp",
        ts_scale=1e-3,
        name_prefix=None,
        delimiter=DELIM,
        counted_batch=True,
        max_frames_per_batch=64,
    )


class _FakeSource:
    """Returns queued chunks then b"" forever, mimicking an idle serial read."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __call__(self):
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class SourceReaderTest(unittest.IsolatedAsyncioTestCase):
    async def test_parses_records_and_stops_cleanly(self):
        parser = _make_parser()
        b1 = _make_batch(1, [(1000, 1.5)])
        b2 = _make_batch(2, [(2000, 2.5)])
        # A batch is only emitted once the *next* delimiter bounds it, so a
        # trailing DELIM is needed to flush the final batch.
        src = _FakeSource([b1, b2, DELIM])
        q: asyncio.Queue = asyncio.Queue()
        stop = threading.Event()

        task = asyncio.create_task(source_reader_to_queue(src, parser, q, stop_event=stop))

        m1 = json.loads(await asyncio.wait_for(q.get(), 2.0))
        m2 = json.loads(await asyncio.wait_for(q.get(), 2.0))

        stop.set()
        # Drain to the None sentinel that the reader enqueues on exit.
        sentinel_seen = False
        while True:
            item = await asyncio.wait_for(q.get(), 2.0)
            if item is None:
                sentinel_seen = True
                break
        await asyncio.wait_for(task, 2.0)

        self.assertEqual(m1["t"], 1.0)  # 1000 ms * 1e-3
        self.assertEqual(m1["value"], 1.5)
        self.assertEqual(m1["message_id"], 1)
        self.assertEqual(m2["t"], 2.0)
        self.assertEqual(m2["value"], 2.5)
        self.assertEqual(m2["message_id"], 2)
        self.assertTrue(sentinel_seen)

    async def test_stop_with_no_data_terminates(self):
        parser = _make_parser()
        src = _FakeSource([])  # always idle
        q: asyncio.Queue = asyncio.Queue()
        stop = threading.Event()

        task = asyncio.create_task(source_reader_to_queue(src, parser, q, stop_event=stop))
        await asyncio.sleep(0.05)
        stop.set()

        self.assertIsNone(await asyncio.wait_for(q.get(), 2.0))
        await asyncio.wait_for(task, 2.0)


if __name__ == "__main__":
    unittest.main()
