"""End-to-end tests for stream-parser's --csv output (no sockets, no hardware).

Runs the real CLI in a subprocess so argument parsing is covered too, and
asserts --csv matches the older `stream-parser | json-to-csv` pipeline byte for
byte. The two must stay interchangeable: --csv exists only to skip the JSON
round trip, not to change the result.
"""

import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DELIM = b"\xde\xad\xbe\xef"  # 0xDEADBEEF

# One record: uint32 timestamp (ms), float value, int16 temp, float gyro[3].
_FMT = "<Ifh3f"
_HEADER_SRC = """
typedef struct
{
    uint32_t timestamp;
    float value;
    int16_t temp;
    float gyro[3];
} MyStruct;
"""
# Column order the parser emits with --ts-field timestamp: derived t first, the
# remaining fields in declaration order, then message_id from the batch header.
_EXPECTED_COLUMNS = "t,value,temp,gyro[0],gyro[1],gyro[2],message_id"


def _make_batch(msg_id, records):
    """Frame a counted batch: [DELIM][COUNT:1][msg_id:2 LE][record]*COUNT."""
    payload = b"".join(struct.pack(_FMT, *rec) for rec in records)
    return DELIM + bytes([len(records)]) + struct.pack("<H", msg_id) + payload


def _make_capture():
    """A few batches, including a negative value and a negative temperature."""
    return b"".join(
        [
            _make_batch(0x1234, [(1000, 1.5, -7, 0.1, 0.2, 0.3), (1005, -2.5, 21, 0.0, -1.0, 2.0)]),
            _make_batch(0x1234, [(1010, 0.0, 0, 1.0, 1.0, 1.0)]),
            _make_batch(0x5678, [(1015, 9.75, -40, -0.5, 0.5, 0.0)]),
        ]
    )


class CsvOutputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        cls.header = cls.dir / "telemetry.h"
        cls.header.write_text(_HEADER_SRC)
        cls.capture = cls.dir / "capture.bin"
        cls.capture.write_bytes(_make_capture())
        # The subprocesses import pj_bridge; make src/ importable whether or not
        # the package is installed in the interpreter running the tests.
        cls.env = dict(os.environ)
        src = Path(__file__).resolve().parents[1] / "src"
        cls.env["PYTHONPATH"] = os.pathsep.join([str(src), cls.env.get("PYTHONPATH", "")]).rstrip(
            os.pathsep
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _parser_argv(self, *extra):
        return [
            sys.executable,
            "-m",
            "pj_bridge.stream_parser",
            "--file",
            str(self.capture),
            "--struct-header",
            str(self.header),
            "--struct-name",
            "MyStruct",
            "--ts-field",
            "timestamp",
            *extra,
        ]

    def _run(self, argv, stdin_bytes=None):
        proc = subprocess.run(
            argv,
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"{argv[2:]} failed:\n{proc.stderr.decode()}")
        return proc.stdout

    def _csv_direct(self, *extra):
        return self._run(self._parser_argv("--csv", *extra))

    def _csv_via_json_to_csv(self):
        ndjson = self._run(self._parser_argv())
        self.assertTrue(ndjson.startswith(b'{"t":'), "expected NDJSON on the plain path")
        return self._run([sys.executable, "-m", "pj_bridge.json_to_csv"], stdin_bytes=ndjson)

    def test_csv_matches_json_to_csv_pipeline(self):
        self.assertEqual(self._csv_direct(), self._csv_via_json_to_csv())

    def test_csv_output_is_not_vacuously_empty(self):
        """Guard the comparison above: two empty outputs would also be equal."""
        lines = self._csv_direct().decode().splitlines()
        self.assertEqual(lines[0], _EXPECTED_COLUMNS)
        self.assertEqual(len(lines), 1 + 4)  # header + one row per record

    def test_csv_preserves_signed_values(self):
        """Negative floats and int16s must survive as negatives, not wrap."""
        rows = self._csv_direct().decode().splitlines()[1:]
        self.assertEqual(rows[1].split(",")[1:5], ["-2.5", "21", "0.0", "-1.0"])
        self.assertEqual(rows[3].split(",")[1:], ["9.75", "-40", "-0.5", "0.5", "0.0", "22136"])

    def test_csv_delimiter_and_no_header(self):
        out = self._csv_direct("--csv-delimiter", ";", "--no-header").decode().splitlines()
        self.assertEqual(len(out), 4)  # no header row
        self.assertNotIn(",", out[0])
        self.assertEqual(len(out[0].split(";")), len(_EXPECTED_COLUMNS.split(",")))

    def test_no_header_matches_pipeline_no_header(self):
        direct = self._csv_direct("--no-header")
        ndjson = self._run(self._parser_argv())
        piped = self._run(
            [sys.executable, "-m", "pj_bridge.json_to_csv", "--no-header"], stdin_bytes=ndjson
        )
        self.assertEqual(direct, piped)


if __name__ == "__main__":
    unittest.main()
