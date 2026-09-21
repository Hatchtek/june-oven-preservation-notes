#!/usr/bin/env python3
"""Passively listen to mDNS (multicast 224.0.0.251:5353) and log every packet
that involves the oven (10.13.0.161) - both what it ADVERTISES and, crucially,
what service types it QUERIES/BROWSES for. That reveals whether the oven waits
to be connected to, or hunts for a local companion to connect out to.
No root needed (just joins the multicast group).
"""
import socket, struct, datetime

OVEN = "10.13.0.161"
GROUP = "224.0.0.251"; PORT = 5353
LOG = "/home/blake/Projects/June-Fix/mdns-sniff.log"

def log(*a):
    line = datetime.datetime.now().strftime("%H:%M:%S ") + " ".join(map(str, a))
    print(line, flush=True)
    try: open(LOG, "a").write(line + "\n")
    except Exception: pass

def parse_name(data, off):
    labels = []; jumped = False; start = off
    while True:
        if off >= len(data): break
        l = data[off]
        if l & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", data[off:off+2])[0] & 0x3FFF
            if not jumped: start = off + 2
            off = ptr; jumped = True; continue
        if l == 0:
            off += 1
            if not jumped: start = off
            break
        labels.append(data[off+1:off+1+l].decode("utf-8", "replace")); off += 1 + l
    return ".".join(labels), start

QTYPE = {1:"A",12:"PTR",16:"TXT",28:"AAAA",33:"SRV",255:"ANY",47:"NSEC"}

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", PORT))
mreq = struct.pack("4sl", socket.inet_aton(GROUP), socket.INADDR_ANY)
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
log(f"=== mDNS sniffer up; filtering for oven {OVEN} ===")

while True:
    try:
        data, addr = s.recvfrom(9000)
    except Exception:
        continue
    frm = addr[0]
    involves_oven = (frm == OVEN)
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
        off = 12
        qnames = []
        for _ in range(qd):
            nm, off = parse_name(data, off)
            if off+4 > len(data): break
            qt, qc = struct.unpack("!HH", data[off:off+4]); off += 4
            qnames.append(f"{QTYPE.get(qt,qt)} {nm}")
        # also scan answers/additionals for the oven's name/ip
        body = data
        mentions = (b"june" in body.lower())
        if involves_oven or (frm == OVEN):
            tag = "QUERY" if qd and an == 0 else "ANNOUNCE"
            log(f"from {frm} [{tag}] q={qnames}")
        elif mentions and frm != OVEN:
            log(f"from {frm} mentions 'june': q={qnames}")
    except Exception as e:
        if involves_oven:
            log(f"from {frm} (parse err {type(e).__name__})")
