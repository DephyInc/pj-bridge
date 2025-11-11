#!/usr/bin/env python3
"""
can_fd_fullstate.py

Minimal CAN FD → JSON parser for the packed 45-byte MSGFullState:

struct MSGFullState {
    uint8_t  m_num;            // 0
    uint8_t  m_systemState;    // 1
    uint16_t m_voltageScaled;  // 2..3
    uint8_t  last_cmd_seq;     // 4
    MSGMotorPart m_motor0State;// 5..24
    MSGMotorPart m_motor1State;// 25..44
} __attribute__((packed));

struct MSGMotorPart {
    uint8_t  m_state;                 // +0
    uint8_t  m_trajectoryState;       // +1
    int32_t  m_position;              // +2..5
    int32_t  m_expectedPosition;      // +6..9
    int16_t  m_velocityScaled;        // +10..11   (RPM * 0.5)
    int16_t  m_commandedVelocityScaled;//+12..13   (RPM * 0.5)
    int16_t  m_commandedCurrentScaled;// +14..15   (/1024 A)
    int16_t  m_sensedCurrentScaled;   // +16..17   (/1024 A)
    int16_t  m_commandedDutyPu;       // +18..19   (/32768 PU)
} __attribute__((packed));

Assumptions:
- Little-endian
- CAN FD (payload length >= 45)
- No CAN ID filtering; any FD frame with >=45 bytes is attempted

Output:
- NDJSON (one JSON object per line), with fields:
  t (seconds) and name-prefixed metrics (default prefix "device_a.")
"""

import argparse
import json
import select
import socket
import struct
import sys
import time
from typing import Any, Dict, Optional

# Linux SocketCAN constants
AF_CAN = socket.PF_CAN
CAN_RAW = 1

# Frame formats
CAN_FRAME_FMT = "=IB3x8s"  # classic can_frame
CANFD_FRAME_FMT = "=IBBBB64s"  # canfd_frame
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)
CANFD_FRAME_SIZE = struct.calcsize(CANFD_FRAME_FMT)

SOL_CAN_RAW = getattr(socket, "SOL_CAN_RAW", 101)
CAN_RAW_FD_FRAMES = 5  # enable RX of CAN FD frames

FULLSTATE_LEN = 45  # bytes


def make_socket(ifname: str, timeout: Optional[float]) -> socket.socket:
    s = socket.socket(AF_CAN, socket.SOCK_RAW, CAN_RAW)
    try:
        s.setsockopt(SOL_CAN_RAW, CAN_RAW_FD_FRAMES, 1)
    except OSError:
        pass
    s.bind((ifname,))
    if timeout is not None:
        s.settimeout(timeout)
    return s


def recv_can_any(s: socket.socket) -> Optional[Dict[str, Any]]:
    """Receive classic or FD frame; return dict with {'data': bytes, 'is_fd': bool} or None on timeout."""
    try:
        pkt = s.recv(80, socket.MSG_TRUNC)
    except socket.timeout:
        return None
    if not pkt:
        return None

    if len(pkt) >= CANFD_FRAME_SIZE:
        can_id, length, flags, _, _, data = struct.unpack(
            CANFD_FRAME_FMT, pkt[:CANFD_FRAME_SIZE]
        )
        return {"data": data[:length], "is_fd": True}
    elif len(pkt) >= CAN_FRAME_SIZE:
        can_id, dlc, data = struct.unpack(CAN_FRAME_FMT, pkt[:CAN_FRAME_SIZE])
        return {"data": data[:dlc], "is_fd": False}
    else:
        return None


def _decode_motor_part_le(
    payload: bytes, base: int, prefix: str, idx: int
) -> Dict[str, Any]:
    """
    Decode one MSGMotorPart at payload[base:base+20] (little-endian).
    """
    off = base
    state = payload[off + 0]
    traj = payload[off + 1]
    pos = struct.unpack_from("<i", payload, off + 2)[0]
    exp = struct.unpack_from("<i", payload, off + 6)[0]
    vel = struct.unpack_from("<h", payload, off + 10)[0]
    cmd_v = struct.unpack_from("<h", payload, off + 12)[0]
    cmd_i = struct.unpack_from("<h", payload, off + 14)[0]
    sns_i = struct.unpack_from("<h", payload, off + 16)[0]
    cmd_d = struct.unpack_from("<h", payload, off + 18)[0]

    def rpm(x: int) -> float:
        return x * 2

    def amps(x: int) -> float:
        return x / 1024.0

    def duty(x: int) -> float:
        return x / 32768.0

    p = f"{prefix}m{idx}_"
    return {
        f"{p}state": state,
        f"{p}trajectory": traj,
        f"{p}pos": pos,
        f"{p}expected_pos": exp,
        f"{p}vel_rpm": rpm(vel),
        f"{p}cmd_vel_rpm": rpm(cmd_v),
        f"{p}cmd_cur_a": amps(cmd_i),
        f"{p}sns_cur_a": amps(sns_i),
        f"{p}cmd_duty": duty(cmd_d),
    }


def decode_fullstate_le_45(payload: bytes, prefix: str) -> Dict[str, Any]:
    """
    Decode the 45-byte MSGFullState (little-endian).
    """
    if len(payload) < FULLSTATE_LEN:
        raise ValueError("payload too short for MSGFullState (need 45 bytes)")

    num = payload[0]
    sys_state = payload[1]
    ib_raw = struct.unpack_from("<H", payload, 2)[0]
    v_scaled = struct.unpack_from("<H", payload, 4)[0]
    last_cmd = payload[4]

    ib_offset = 4096.0 / 3.0 * 1.65
    i_batt = (ib_raw - ib_offset) / 4096.0 * 3.0 / 0.044

    # Motors
    m0 = _decode_motor_part_le(payload, base=5, prefix=prefix, idx=0)
    m1 = _decode_motor_part_le(payload, base=25, prefix=prefix, idx=1)

    out = {
        "t": time.time(),
        f"{prefix}seq": num,
        f"{prefix}system_state": sys_state,
        f"{prefix}last_cmd": last_cmd,
        f"{prefix}batt_curr": i_batt,
        f"{prefix}voltage": v_scaled / 16,
    }
    out.update(m0)
    out.update(m1)
    return out


def parse_args() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Read CAN FD frames from SocketCAN and emit NDJSON for 45-byte MSGFullState."
    )
    ap.add_argument(
        "--if",
        dest="ifname",
        default="can0",
        help="SocketCAN interface (default: can0)",
    )
    ap.add_argument(
        "--name-prefix",
        default="device_a.",
        help="Prefix for output fields (default: device_a.)",
    )
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
        f"[CAN] listening on {args.ifname} (FD frames, expecting >= {FULLSTATE_LEN} bytes)",
        file=sys.stderr,
    )

    poller = select.poll()
    poller.register(s, select.POLLIN)

    try:
        while True:
            events = poller.poll(int((args.poll_timeout or 1.0) * 1000))
            if not events:
                continue

            frame = recv_can_any(s)
            if not frame:
                continue

            data = frame["data"]
            if len(data) < FULLSTATE_LEN:
                continue  # not our message

            try:
                obj = decode_fullstate_le_45(data[:FULLSTATE_LEN], prefix)
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
