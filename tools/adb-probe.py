#!/usr/bin/env python3
"""Catch the transient port and speak raw ADB CNXN to identify it definitively.

ADB handshake: we send a CNXN packet; a real adbd replies with either CNXN
(connected/device) or AUTH (wants RSA auth -> the 'Allow debugging' prompt).
Anything else = not adb. Logs the raw response either way.
"""
import socket, struct, time, datetime
HOST = "10.13.0.161"; PORT = 8156
LOG = "/home/blake/Projects/June-Fix/adb-probe.log"

def log(*a):
    line = datetime.datetime.now().strftime("%H:%M:%S ") + " ".join(map(str, a))
    print(line, flush=True)
    open(LOG, "a").write(line + "\n")

def adb_msg(cmd, a0, a1, data=b""):
    magic = cmd ^ 0xffffffff
    crc = sum(data) & 0xffffffff
    return struct.pack("<6I", cmd, a0, a1, len(data), crc, magic) + data

CNXN = 0x4e584e43; AUTH = 0x48545541; OKAY = 0x59414b4f
def name(c):
    return {CNXN: "CNXN", AUTH: "AUTH", OKAY: "OKAY",
            0x45534c43: "CLSE", 0x45545257: "WRTE"}.get(c, hex(c))

log(f"=== raw ADB CNXN prober watching {HOST}:{PORT} ===")
banner = b"host::features=cmd,shell_v2\x00"
while True:
    try:
        s = socket.create_connection((HOST, PORT), 1); s.settimeout(4)
    except Exception:
        time.sleep(0.25); continue
    log("PORT OPEN -- sending CNXN")
    try:
        s.sendall(adb_msg(CNXN, 0x01000001, 0x00100000, banner))
        hdr = b""
        while len(hdr) < 24:
            chunk = s.recv(24 - len(hdr))
            if not chunk: break
            hdr += chunk
        if len(hdr) == 24:
            cmd, a0, a1, dlen, dcrc, magic = struct.unpack("<6I", hdr)
            payload = b""
            while len(payload) < dlen and dlen < 4096:
                c = s.recv(dlen - len(payload))
                if not c: break
                payload += c
            log(f"REPLY cmd={name(cmd)} a0={hex(a0)} a1={hex(a1)} dlen={dlen} payload={payload[:200]!r}")
            if cmd == AUTH:
                log(">>> IT IS ADB, wants RSA AUTH -- an Allow-debugging prompt should appear on the oven.")
            elif cmd == CNXN:
                log(">>> IT IS ADB, ALREADY AUTHORIZED. banner above.")
            else:
                log(">>> responded but not an ADB handshake -- different protocol.")
            open("/home/blake/Projects/June-Fix/adb-probe.done", "w").write(name(cmd))
            s.close(); break
        else:
            log(f"short/no reply ({len(hdr)}B) -- port closed mid-handshake")
    except Exception as e:
        log(f"probe error: {type(e).__name__}: {e}")
    finally:
        try: s.close()
        except Exception: pass
    time.sleep(0.2)
