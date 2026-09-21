#!/usr/bin/env python3
"""Catch the oven's LOCAL service (port 54890, _june-oven._tcp) the instant it
opens, and fingerprint what protocol it speaks. Tries, in order on each catch:
  1) read any server-first banner
  2) a TLS ClientHello (is it TLS like the cloud channel?)
  3) a raw newline / JSON poke
Logs everything. This is the local channel that would survive the cloud shutdown.
"""
import socket, ssl, struct, time, datetime, json

HOST = "10.13.0.161"; PORT = 54890
LOG = "/home/blake/Projects/June-Fix/local-probe.log"

def log(*a):
    line = datetime.datetime.now().strftime("%H:%M:%S ") + " ".join(map(str, a))
    print(line, flush=True)
    try: open(LOG, "a").write(line + "\n")
    except Exception: pass

def try_open():
    try:
        s = socket.create_connection((HOST, PORT), 1)
        return s
    except Exception:
        return None

log(f"=== local-service prober watching {HOST}:{PORT} ===")
done = False
while not done:
    s = try_open()
    if not s:
        time.sleep(0.2); continue
    log("PORT 54890 OPEN — fingerprinting")
    # 1) server-first banner
    try:
        s.settimeout(2)
        b = s.recv(256)
        log(f"  banner: {b[:120]!r}" if b else "  no server-first banner")
    except Exception as e:
        log(f"  no banner ({type(e).__name__})")
    try: s.close()
    except Exception: pass
    # 2) TLS?
    s = try_open()
    if s:
        try:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            t = ctx.wrap_socket(s, server_hostname="june-oven")
            log(f"  TLS: HANDSHAKE OK, peer cert present={bool(t.getpeercert(True))} cipher={t.cipher()}")
            done = True
        except ssl.SSLError as e:
            log(f"  TLS: rejected/none ({e.__class__.__name__}: {e})")
        except Exception as e:
            log(f"  TLS: err {type(e).__name__}: {e}")
        try: s.close()
        except Exception: pass
    # 3) raw pokes
    for name, payload in [("newline", b"\n"),
                          ("http", b"GET / HTTP/1.0\r\n\r\n"),
                          ("json", json.dumps({"message_code": 11011}).encode() + b"\n")]:
        s = try_open()
        if not s: break
        try:
            s.settimeout(2); s.sendall(payload)
            r = s.recv(256)
            log(f"  poke[{name}] -> {r[:120]!r}")
            if r: done = True
        except Exception as e:
            log(f"  poke[{name}] -> silent/{type(e).__name__}")
        try: s.close()
        except Exception: pass
    if done:
        open("/home/blake/Projects/June-Fix/local-probe.done", "w").write("caught")
        log("=== fingerprint captured — see log ===")
    time.sleep(0.2)
