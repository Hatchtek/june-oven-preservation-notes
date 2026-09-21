#!/usr/bin/env python3
"""Minimal syslog receiver (UDP+TCP 514). Logs everything, and tags any line
that mentions the oven (10.13.0.161 / its MAC c4:57:1f:0f:61:6c / 'june') so we
can watch its behavior in the firewall/DNS/system logs streamed from the UDM.
"""
import socket, threading, datetime

LOG = "/out/syslog.log"
OVEN_IP = "10.13.0.161"; OVEN_MAC = "c4:57:1f:0f:61:6c"
HImark = ("june", OVEN_IP, OVEN_MAC, "61:6c")

def w(line):
    ts = datetime.datetime.now().strftime("%H:%M:%S ")
    tag = "  <<OVEN>> " if any(m in line.lower() for m in HImark) else " "
    out = ts + tag + line.rstrip()
    print(out, flush=True)
    try: open(LOG, "a").write(out + "\n")
    except Exception: pass

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 514))
    w("=== syslog UDP :514 up ===")
    while True:
        try:
            data, addr = s.recvfrom(65535)
            for ln in data.decode("utf-8", "replace").splitlines():
                w(f"[{addr[0]}] {ln}")
        except Exception as e:
            w(f"(udp err {type(e).__name__})")

def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 514)); s.listen(8)
    w("=== syslog TCP :514 up ===")
    while True:
        try:
            c, addr = s.accept()
            threading.Thread(target=_tcpconn, args=(c, addr), daemon=True).start()
        except Exception:
            pass

def _tcpconn(c, addr):
    buf = b""
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            buf += d
            while b"\n" in buf:
                ln, buf = buf.split(b"\n", 1)
                w(f"[{addr[0]}] {ln.decode('utf-8','replace')}")
    except Exception:
        pass

threading.Thread(target=udp, daemon=True).start()
tcp()
