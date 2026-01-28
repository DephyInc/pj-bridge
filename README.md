# pj-bridge

Bridge a delimiter-framed TCP binary stream into JSON over WebSocket for [PlotJuggler](https://github.com/facontidavide/PlotJuggler) or stdout (if file).

**Mode:** PlotJuggler runs the **WebSocket Server**. The bridge connects as a **WebSocket client** and pushes JSON messages.

## What’s in this repo

- `derive_struct.py` — Parse a C header (`typedef struct { ... } Name;`) and derive the Python `struct` format and expanded field labels.
- `stream_parser.py` — Connect to the device, parse **[DE AD BE EF][COUNT][MSG_ID][PAYLOAD] × COUNT** batches into NDJSON (one JSON per line).
- `socket_client.py` — Read NDJSON (stdin or file) and forward to PlotJuggler’s WebSocket Server.
- `bridge.py` — One-process solution: connect to device, parse, and forward to PlotJuggler (no shell pipes needed) or stdout (if file).

## Requirements

- Python 3.12+
- Device emits batches framed like:

      [ 0xDE 0xAD 0xBE 0xEF ][ COUNT:1 byte ][MSG_ID:2 bytes][ PAYLOAD ] * COUNT

- The payload is a *packed* C struct defined in a header file.
- PlotJuggler with the WebSocket Server plugin enabled (Protocol: JSON).

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Start PlotJuggler’s WebSocket Server

- In PlotJuggler: **Streaming → WebSocket Server**
- Protocol: **JSON**
- Port: for example **9871**
- Click **Start**

## Start Bridge

Connect to device, parse batches, forward to PJ.
Default TCP port is **5000**; default WS URL is **ws://127.0.0.1:9871**.
Timestamps are in **milliseconds** by default (`--ts-scale 1e-3`).

```bash
python3 bridge.py \
  --host 192.168.1.91 \
  --struct-header /path/to/telemetry.h \
  --struct-name MyStruct \
  --controller-out-size MySize \
  --name-prefix "device_a."
```

Notes:
- Add `--controller-out-size` if using a struct with `HiddenHighLevelControllerOutputData_s` to specify size (ex: 109)
  (this is `CONTROLLER_OUTPUT_DATA_SIZE` value in `high_level_controller_common.h`)
- Add `--ignore-errors` if you think the stream might have corrupted frames but you want to recover instead of stopping
- Add `--ws-url ws://<pj_host>:9871` if PlotJuggler runs elsewhere.
- If needed, guard against corrupted batches with `--max-frames-per-batch N`.
- To fall back to single `[DELIM][PAYLOAD]` (no COUNT), pass `--no-counted-batch`.

## Two-process pipeline (for debugging)

0) Derive the struct (optional sanity check). Prints JSON describing the derived `struct_fmt`, `fields`, and `record_size`.

  ```bash
  python3 derive_struct.py \
    --header /path/to/telemetry.h \
    --struct-name MyStruct \
    --controller-out-size MySize \
  ```

1) Parse from device to NDJSON:

  ```bash
  python3 stream_parser.py \
   --host 192.168.1.91 \
   --struct-header /path/to/telemetry.h \
   --struct-name MyStruct \
   --controller-out-size MySize \
   --name-prefix "device_a."
  ```

2) Forward NDJSON to PlotJuggler:

  ```bash
  python3 stream_parser.py --host 192.168.1.91 --struct-header /path/to/telemetry.h --struct-name MyStruct --controller-out-size MySize | python3 socket_client.py --ws-url ws://127.0.0.1:9871
  ```

## Field naming

- All non-timestamp fields are emitted with the optional prefix:

  ```bash
  --name-prefix "device_a."
  ```

  Example JSON:

  ```json
  {"t": 1727370023.415, "device_a.ax": 0.02, "device_a.ay": -0.01, "device_a.az": 9.81}
  ```

- Arrays like `float gyro[3];` become `device_a.gyro[0]`, `device_a.gyro[1]`, `device_a.gyro[2]`.

## Timestamp (`t`)

- If `--ts-field ts_ms` is provided, `t = ts_ms * --ts-scale` (default `1e-3`, ms → seconds).
- If no `--ts-field` is set, arrival time is used (`time.time()` in seconds).
- If your device time is relative (since boot) and you want wall-clock, you can add an epoch offset in code; ask if you want a ready-made flag for that.

## Parsing log files

The project provides two standalone tools for working with telemetry logs:

- **`json-to-csv`** — converts NDJSON into CSV

You can generate JSON logs in one of two ways:

1. Live over TCP, using **`stream-parser`**
2. Offline from stored binary log files, using **`stream-parser`** with --file option

Both paths produce NDJSON (one JSON object per line), which can then be piped into **`json-to-csv`** for analysis in Excel, Pandas, or visualization tools.

### 1. Converting NDJSON to CSV

`json-to-csv` converts streamed JSON objects into a well-formed CSV file.
All JSON lines must contain the same fields (the parsers ensure this).

Example from a live TCP stream:

```bash
stream-parser --host ... | json-to-csv > live.csv
```

Example from offline logs:

```bash
stream-parser --file ... | json-to-csv > logs.csv
```

## Uninstall

- Deactivate the venv and remove the project directory, or run `pip uninstall pj-bridge` inside the venv (if installed as a package).

## License

[MIT](https://dephy-inc.mit-license.org/)
