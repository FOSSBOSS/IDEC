#!/usr/bin/env python3
"""
Goal: Verify the CPU type of an IDEC PLC connected over IP (TCP:2101)

This information is needed later if you want to Read or write programs to the PLC.

h@x$ ./cpu_id.py 10.1.0.175 # flags are optional
h@x$./cpu_id.py 10.1.0.175 --port 2101 --device FF --debug
TX (hex): 05464630525333340d
RX (hex): 063030303130336e43453544303232333031303030303030304246354230303030303030303030303030303036430d
Reply kind: ACK/OK
Reply device: 00  command: 0
BCC recv=6C calc=6C ok=True
PLC status: Stop
User program protection: Read+write protect
Operating-status payload length: 40
Operating-status payload (ascii): 103nCE5D0223010000000BF5B000000000000000
Operating-status payload (hex): 3130336e434535443032323330313030303030303042463542303030303030303030303030303030
CPU type code (best guess): 0 (payload index 8)
CPU type: 10-I/O

Key points learned from captures:
- PLC expects request BCC includes ENQ (0x05).
- PLC reply BCC includes the leading control byte (0x06 ACK or 0x15 NAK).
- Sending device "FF" (1:1 addressing) is fine, but PLC replies with its own
  device number "00".."1F" (you observed "00").

This script:
1) Sends "Read PLC Operating Status" (Request Message 1: ENQ dev 0 R S ...).
2) Validates BCC using the behavior proven on the PLC.
3) Prints:
   - PLC run/stop status
   - user program protection state
   - full payload fingerprint (ASCII and hex)
   - CPU type code (if we can confidently locate it)
   - mapped CPU type name if code is known (0/1/2/3/4/6), else unknown.

If the CPU type field layout differs on newer PLCs, you still get a stable
fingerprint you can use for future branching logic.
"""

import argparse
import socket
from binascii import hexlify

DEFAULT_PORT = 2101
DEFAULT_DEVICE = "FF"

# CPU module type code mapping from documentation (legacy set)
CPU_TYPE_MAP = {
    "0": "10-I/O",
    "1": "16-I/O",
    "2": "20-I/O transistor output",
    "3": "24-I/O",
    "4": "40-I/O",
    "6": "20-I/O relay output",
}


def xor_bcc(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x


def frame_request_including_enq(enq_plus_fields: bytes) -> bytes:
    """
    Your PLC behavior: Request BCC = XOR(ENQ + all request fields).
    Returns: enq_plus_fields + BCC(2 ASCII hex) + CR
    """
    bcc = xor_bcc(enq_plus_fields)
    return enq_plus_fields + f"{bcc:02X}".encode("ascii") + b"\r"


def build_read_operating_status_req(device_hex2: str) -> bytes:
    """
    Request Message 1: Read PLC Operating Status
      ENQ + dev(2) + cont('0') + cmd('R') + dtype('S') + BCC + CR

    For your PLC:
      BCC = XOR(ENQ + dev + cont + cmd + dtype)
    """
    if len(device_hex2) != 2:
        raise ValueError("device must be 2 ASCII hex chars (e.g. FF, 00)")
    dev = device_hex2.upper().encode("ascii")
    enq_fields = b"\x05" + dev + b"0" + b"R" + b"S"
    return frame_request_including_enq(enq_fields)


def recv_until_cr(sock: socket.socket, limit: int = 8192) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        chunk = sock.recv(256)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\r" in chunk:
            break
    if b"\r" in buf:
        buf = buf.split(b"\r", 1)[0] + b"\r"
    return bytes(buf)


def parse_reply(raw: bytes) -> dict:
    """
    Reply formats:
      ACK: 06 + dev2 + cmd1 + data... + bcc2 + CR
      NAK: 15 + dev2 + '0'  + err2     + bcc2 + CR

    Your PLC behavior:
      Reply BCC = XOR(CTRL + dev2 + cmd1 + data/err2...)
    i.e. include the leading control byte in the BCC range.
    """
    if not raw:
        return {"kind": "EMPTY", "raw": raw}

    if raw[-1:] != b"\r" or len(raw) < 9:
        return {"kind": "MALFORMED", "raw": raw}

    ctrl = raw[0:1]
    dev = raw[1:3]
    cmd = raw[3:4]
    data = raw[4:-3]
    bcc_ascii = raw[-3:-1]

    try:
        bcc_recv = int(bcc_ascii.decode("ascii"), 16)
    except Exception:
        return {"kind": "MALFORMED", "raw": raw}

    # Include CTRL in BCC calc; exclude trailing BCC+CR
    bcc_calc = xor_bcc(raw[0:-3])
    bcc_ok = (bcc_calc == bcc_recv)

    out = {
        "raw": raw,
        "ctrl": ctrl,
        "device": dev.decode("ascii", errors="replace"),
        "command": cmd.decode("ascii", errors="replace"),
        "data": data,
        "bcc_recv": bcc_recv,
        "bcc_calc": bcc_calc,
        "bcc_ok": bcc_ok,
    }

    if ctrl == b"\x15":
        out["kind"] = "NAK"
        out["nak_error_code"] = data[:2].decode("ascii", errors="replace") if len(data) >= 2 else ""
        return out

    if ctrl == b"\x06":
        if cmd == b"2":
            out["kind"] = "ACK/NG"
            out["ng_code"] = data[:2].decode("ascii", errors="replace") if len(data) >= 2 else ""
            return out
        out["kind"] = "ACK/OK"
        return out

    out["kind"] = "UNKNOWN"
    return out


def status_text(status_ch: str) -> str:
    return {"0": "Run", "1": "Stop"}.get(status_ch, f"unknown({status_ch})")


def preset_text(preset_ch: str) -> str:
    return {"0": "Not changed", "1": "Changed"}.get(preset_ch, f"unknown({preset_ch})")


def protection_text(prot_ch: str) -> str:
    return {
        "0": "Not protected",
        "1": "Write protect",
        "2": "Read protect",
        "3": "Read+write protect",
    }.get(prot_ch, f"unknown({prot_ch})")


def find_cpu_code_from_payload(text: str) -> tuple[str, int]:
    """
    Newer PLCs/firmware may change the operating-status payload layout.
    We do a conservative extraction:

    1) If classic index 3 is one of the known CPU codes, use it.
    2) Otherwise, look in the first ~12 chars after the first 3 fields,
       selecting the first valid CPU code that isn't obviously filler.
    3) Fallback: scan entire payload after index 2.

    Returns (cpu_code, index). cpu_code is '?' if not found.
    """
    valid = set("012346")

    # Classic spot: 4th byte
    if len(text) >= 4 and text[3] in valid:
        return text[3], 3

    # Search near the front, after the first 3 fields
    for i in range(3, min(len(text), 12)):
        ch = text[i]
        if ch in valid:
            # Avoid obvious filler zeros (runs of zeros)
            if ch == "0":
                left = text[max(0, i-3):i]
                right = text[i+1:i+4]
                if (left + right).count("0") >= 5:
                    continue
            return ch, i

    # Fallback scan
    for i, ch in enumerate(text):
        if i > 2 and ch in valid:
            return ch, i

    return "?", -1


def decode_operating_status(payload: bytes) -> dict:
    """
    Always decode the first three characters (status/preset/protection),
    because in your successful capture they match meaningfully.

    Then attempt to locate CPU type code robustly.
    """
    text = payload.decode("ascii", errors="replace")

    status_ch = text[0:1] if len(text) >= 1 else ""
    preset_ch = text[1:2] if len(text) >= 2 else ""
    prot_ch = text[2:3] if len(text) >= 3 else ""

    cpu_code, cpu_idx = find_cpu_code_from_payload(text)
    cpu_desc = CPU_TYPE_MAP.get(cpu_code, f"unknown({cpu_code})")

    return {
        "payload_ascii": text,
        "payload_hex": payload.hex(),
        "payload_len": len(payload),
        "plc_status": status_text(status_ch),
        "preset_change": preset_text(preset_ch),
        "user_program_protection": protection_text(prot_ch),
        "cpu_type_code": cpu_code,
        "cpu_type_index": cpu_idx,
        "cpu_type": cpu_desc,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify IDEC PLC CPU type over maintenance protocol (TCP).")
    ap.add_argument("ip", help="PLC IP address")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"PLC TCP port (default {DEFAULT_PORT})")
    ap.add_argument("--device", default=DEFAULT_DEVICE, help="Device number (FF for 1:1, default FF)")
    ap.add_argument("--timeout", type=float, default=3.0, help="Socket timeout seconds")
    ap.add_argument("--debug", action="store_true", help="Print TX/RX and BCC details")
    args = ap.parse_args()

    try:
        tx = build_read_operating_status_req(args.device)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    if args.debug:
        print(f"TX (hex): {hexlify(tx).decode()}")

    try:
        with socket.create_connection((args.ip, args.port), timeout=args.timeout) as s:
            s.settimeout(args.timeout)
            s.sendall(tx)
            raw = recv_until_cr(s)
    except Exception as e:
        print(f"ERROR: connection/IO failed: {e}")
        return 2

    parsed = parse_reply(raw)

    if args.debug:
        print(f"RX (hex): {hexlify(raw).decode()}")
        print(f"Reply kind: {parsed.get('kind')}")
        print(f"Reply device: {parsed.get('device')}  command: {parsed.get('command')}")
        if "bcc_recv" in parsed:
            print(f"BCC recv={parsed['bcc_recv']:02X} calc={parsed['bcc_calc']:02X} ok={parsed['bcc_ok']}")

    if not parsed.get("bcc_ok", False):
        print(f"ERROR: BCC mismatch. Raw RX={hexlify(raw).decode()}")
        return 3

    kind = parsed.get("kind")
    if kind == "NAK":
        print(f"PLC replied NAK error code {parsed.get('nak_error_code','??')}")
        return 4

    if kind == "ACK/NG":
        print(f"PLC replied NG code {parsed.get('ng_code','??')}")
        return 4

    if kind != "ACK/OK":
        print(f"Unexpected reply kind={kind}. Raw RX={hexlify(raw).decode()}")
        return 5

    info = decode_operating_status(parsed["data"])

    print(f"PLC status: {info['plc_status']}")
    print(f"User program protection: {info['user_program_protection']}")
    print(f"Operating-status payload length: {info['payload_len']}")
    print(f"Operating-status payload (ascii): {info['payload_ascii']}")
    print(f"Operating-status payload (hex): {info['payload_hex']}")
    print(f"CPU type code (best guess): {info['cpu_type_code']} (payload index {info['cpu_type_index']})")
    print(f"CPU type: {info['cpu_type']}")

    if info["cpu_type_code"] == "?":
        print("NOTE: Could not confidently locate a legacy CPU type code (0/1/2/3/4/6) in the payload.")
        print("      This may indicate a newer CPU encoding or a different payload layout.")
        print("      Use the payload fingerprint above to branch future logic safely.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
