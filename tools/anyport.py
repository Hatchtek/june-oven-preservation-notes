import socket, subprocess, datetime, time
HOST="10.13.0.161"
LOG="/home/blake/Projects/June-Fix/anyport.log"
def log(*a):
    line=datetime.datetime.now().strftime("%H:%M:%S ")+" ".join(map(str,a))
    print(line,flush=True); open(LOG,"a").write(line+"\n")
log(f"=== any-port scanner on {HOST} ===")
seen=set()
while True:
    try:
        out=subprocess.run(["nmap","-Pn","-T4","-p-","--open","--host-timeout","20s",HOST],
                           capture_output=True,text=True,timeout=30).stdout
        ports=[l.split("/")[0] for l in out.splitlines() if "/tcp" in l and "open" in l]
        cur=set(ports)
        if cur!=seen:
            log(f"OPEN PORTS: {sorted(cur, key=int) if cur else 'none'}")
            for p in cur-seen:
                try:
                    s=socket.create_connection((HOST,int(p)),2);s.settimeout(2)
                    try: b=s.recv(128); log(f"  :{p} banner {b[:80]!r}")
                    except Exception: log(f"  :{p} (no banner)")
                    s.close()
                except Exception as e: log(f"  :{p} grab-fail {type(e).__name__}")
            seen=cur
    except Exception as e:
        log("scan err",type(e).__name__)
    time.sleep(2)
