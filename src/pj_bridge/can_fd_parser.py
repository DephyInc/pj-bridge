#!/usr/bin/env python3
"""
can_fd_fullstate.py

CAN FD → NDJSON for 47-byte MSGFullState messages.
Now supports `--motor` argument to select which motor (0 or 1) to decode.
Includes helper functions for scaling.
"""

import argparse
import json
import select
import socket
import struct
import sys
import time
from typing import Any, Dict, Optional

AF_CAN = socket.PF_CAN
CAN_RAW = 1
SOL_CAN_RAW = getattr(socket, "SOL_CAN_RAW", 101)
CAN_RAW_FD_FRAMES = 5
CANFD_FRAME_FMT = "=IBBBB64s"
CANFD_FRAME_SIZE = struct.calcsize(CANFD_FRAME_FMT)
FULLSTATE_LEN = 47  # bytes


# === Scaling helpers ===
def rpm(x: int) -> float:
    """Convert velocity-scaled value to RPM."""
    return x * 2.0


def amps(x: int) -> float:
    """Convert current-scaled value to amps."""
    return x / 1024.0


def duty(x: int) -> float:
    """Convert Q15 duty-cycle value to PU (0–1)."""
    return x / 32768.0


def volts(x: int) -> float:
    """Convert scaled voltage to volts."""
    return x / 16.0


def batt_amps(raw_adc: int) -> float:
    """Convert battery ADC reading to amps."""
    ib_offset = (4096.0 / 3.0) * 1.65
    return (raw_adc - ib_offset) / 4096.0 * 3.0 / 0.044


# === CAN setup ===
def make_socket(ifname: str, timeout: Optional[float]) -> socket.socket:
    s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, CAN_RAW)
    try:
        s.setsockopt(SOL_CAN_RAW, CAN_RAW_FD_FRAMES, 1)
    except OSError:
        pass
    s.bind((ifname,))
    if timeout is not None:
        s.settimeout(timeout)
    return s


def recv_can_fd(s: socket.socket) -> Optional[bytes]:
    try:
        pkt = s.recv(CANFD_FRAME_SIZE, socket.MSG_TRUNC)
    except socket.timeout:
        return None
    if not pkt or len(pkt) < CANFD_FRAME_SIZE:
        return None
    can_id, length, flags, _r0, _r1, data = struct.unpack(
        CANFD_FRAME_FMT, pkt[:CANFD_FRAME_SIZE]
    )
    return data[:length]


# === Message decoding ===
def _parse_state_flags(byte_val: int) -> Dict[str, int]:
    return {
        "run_mode": byte_val & 0x0F,
        "bad_hall": int(bool(byte_val & (1 << 5))),
        "using_halls": int(bool(byte_val & (1 << 6))),
        "calibrated": int(bool(byte_val & (1 << 7))),
    }


def _decode_motor_part_le(
    payload: bytes, base: int, prefix: str, idx: int
) -> Dict[str, Any]:
    flags = payload[base + 0]
    traj = payload[base + 1]
    pos = struct.unpack_from("<i", payload, base + 2)[0]
    exp = struct.unpack_from("<i", payload, base + 6)[0]
    vel_s = struct.unpack_from("<h", payload, base + 10)[0]
    cmdv_s = struct.unpack_from("<h", payload, base + 12)[0]
    cmdi_s = struct.unpack_from("<h", payload, base + 14)[0]
    snsi_s = struct.unpack_from("<h", payload, base + 16)[0]
    cmdq15 = struct.unpack_from("<h", payload, base + 18)[0]

    bits = _parse_state_flags(flags)
    p = f"{prefix}m_"
    return {
        f"{p}state": bits["run_mode"],
        f"{p}trajectory": traj,
        f"{p}calibrated": bits["calibrated"],
        # f"{p}using_halls": bits["using_halls"],
        # f"{p}bad_hall": bits["bad_hall"],
        f"{p}pos": pos,
        f"{p}expected_pos": exp,
        f"{p}vel_rpm": rpm(vel_s),
        f"{p}cmd_vel_rpm": rpm(cmdv_s),
        f"{p}cmd_cur_a": amps(cmdi_s),
        f"{p}sns_cur_a": amps(snsi_s),
        f"{p}cmd_duty": duty(cmdq15),
    }


def decode_fullstate(payload: bytes, prefix: str, motor_index: int) -> Dict[str, Any]:
    if len(payload) < FULLSTATE_LEN:
        raise ValueError(f"payload too short for MSGFullState (got {len(payload)})")

    seq = payload[0]
    sys_state = payload[1]
    ib_raw = struct.unpack_from("<H", payload, 2)[0]
    v_scaled = struct.unpack_from("<H", payload, 4)[0]
    last_cmd = payload[6]

    m_bases = {0: 7, 1: 27}
    base = m_bases.get(motor_index, 7)
    m = _decode_motor_part_le(payload, base=base, prefix=prefix, idx=motor_index)

    out = {
        "t": time.time(),
        f"{prefix}seq": seq,
        f"{prefix}system_state": sys_state,
        f"{prefix}last_cmd": last_cmd,
        f"{prefix}batt_curr_a": batt_amps(ib_raw),
        f"{prefix}voltage_v": volts(v_scaled),
    }
    out.update(m)
    return out


# === CLI + Main ===
def parse_args() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="CAN FD → NDJSON for MSGFullState (select motor)."
    )
    ap.add_argument(
        "--if",
        dest="ifname",
        default="can0",
        help="SocketCAN interface (default: can0)",
    )
    ap.add_argument(
        "--motor",
        type=int,
        choices=[0, 1],
        default=0,
        help="Motor index to decode (0 or 1)",
    )
    ap.add_argument("--name-prefix", default="", help="Prefix for output fields")
    ap.add_argument(
        "--no-flush", action="store_true", help="Do not flush stdout each line"
    )
    ap.add_argument(
        "--poll-timeout", type=float, default=1.0, help="Poll timeout seconds"
    )
    return ap


def main() -> None:
    args = parse_args().parse_args()
    flush = not args.no_flush
    prefix = args.name_prefix or ""

    try:
        s = make_socket(args.ifname, timeout=args.poll_timeout)
    except Exception as e:
        print(f"[CAN] open {args.ifname} failed: {e}", file=sys.stderr)
        sys.exit(2)

    print(
        f"[CAN] listening on {args.ifname}, decoding motor {args.motor}",
        file=sys.stderr,
    )
    poller = select.poll()
    poller.register(s, select.POLLIN)

    try:
        while True:
            events = poller.poll(int((args.poll_timeout or 1.0) * 1000))
            if not events:
                continue

            data = recv_can_fd(s)
            if not data or len(data) < FULLSTATE_LEN:
                continue

            try:
                obj = decode_fullstate(data[:FULLSTATE_LEN], prefix, args.motor)
                print(
                    json.dumps(obj, separators=(",", ":"), ensure_ascii=False),
                    flush=flush,
                )
            except Exception as e:
                print(f"[CAN] decode error: {e}", file=sys.stderr)
                continue

    except KeyboardInterrupt:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
