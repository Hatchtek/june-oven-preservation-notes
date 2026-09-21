#!/usr/bin/env python3
"""Generic TLS capture server - answers the cert-pinning question.

Listens on :443, presents whatever cert.pem/key.pem you provide, and logs for
every connection: the client IP, the SNI it asked for, and whether the TLS
handshake COMPLETED or was ABORTED. If a client (the oven) completes the
handshake, it does NOT pin that cert. If it always aborts, it pins.

Then it reads and hex-logs whatever the client sends (the oven's first frames),
which is data no public artifact currently has.
"""
import socket, ssl, threading, datetime, sys

import os
LOG = os.environ.get("CAP_LOG", "/out/capture.log")
def log(*a):
    line = datetime.datetime.now().strftime("%H:%M:%S ") + " ".join(str(x) for x in a)
    print(line, flush=True)
    try:
        open(LOG, "a").write(line + "\n")
    except Exception:
        pass

def handle(raw, addr):
    holder = {"sni": None}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("cert.pem", "key.pem")
    ctx.sni_callback = lambda sslsock, servername, c: holder.__setitem__("sni", servername)
    try:
        tls = ctx.wrap_socket(raw, server_side=True)
    except ssl.SSLError as e:
        log(f"[{addr[0]}] SNI={holder['sni']} TLS ABORTED -> {e.__class__.__name__}: {e}  (=> client validates/pins this cert)")
        raw.close(); return
    except Exception as e:
        log(f"[{addr[0]}] SNI={holder['sni']} TLS error {e.__class__.__name__}: {e}"); raw.close(); return
    log(f"[{addr[0]}] SNI={holder['sni']} TLS COMPLETED  (=> client does NOT validate the cert) cipher={tls.cipher()[0]}")
    tls.settimeout(20)
    try:
        while True:
            data = tls.recv(4096)
            if not data: break
            log(f"[{addr[0]}] <<< {len(data)}B: {data[:200]!r}")
    except Exception as e:
        log(f"[{addr[0]}] recv end: {e.__class__.__name__}")
    finally:
        tls.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16)
    log(f"=== capture server listening on :{port} ===")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()

if __name__ == "__main__":
    main()
