# June Oven - Post-Shutdown Preservation Notes

Independent research notes and diagnostic tools from investigating how to keep a
**June Oven (3rd-gen)** useful after Weber's connected-services shutdown
(2026-09-22). This repo is **documentation and generic diagnostic tooling only**.

> **Disclaimer:** Unofficial. Not affiliated with, endorsed by, or connected to
> June Life, Inc. or Weber Inc. "June" is used only to identify the hardware this
> concerns. Everything here is for interoperability with hardware you own and for
> educational purposes. No warranty. Commands can act on a real appliance - test
> carefully. Nothing here contains June/Weber copyrighted content or any
> credentials.

## TL;DR of what was learned

- **Pairing is broken on Weber's servers**, not on the oven. The oven completes
  the PIN/SRP handshake (you hear the tone) but the cloud never finalizes the
  association. The official app fails identically.
- **The oven's own AI cooking survives** the shutdown: food recognition and cook
  programs run on the device, not in the app or (at cook time) the cloud. The
  phone app ships no ML model.
- **What dies:** phone remote control, live camera-to-phone, time-lapses, in-app
  recipe browsing, OTA updates - all cloud-routed.
- **A LAN replacement server is blocked by TLS certificate pinning.** The oven
  connects to your DNS-redirected server but rejects any cert it can't verify
  against June's pinned key (`certificate_unknown` alert). Confirmed from the
  oven side via packet capture - new data not previously public.
- **Cutting the cloud does not expose a local control port.** Even fully offline,
  the oven opens no local listener; it just retries the cloud.

See [FINDINGS.md](FINDINGS.md) for the full protocol write-up, the pinning test
results, and message codes.

## tools/

Generic diagnostic scripts written during this research. Edit the hardcoded
IP addresses at the top of each before use.

| script | purpose |
|---|---|
| `mdns-sniff.py` | Passively log a device's mDNS advertisements and queries |
| `capture_server.py` | TLS server that logs SNI + whether a client validates/pins the cert |
| `anyport.py` | Watch a host and log any TCP port it opens, with a banner grab |
| `local-probe.py` | Catch a transient port and fingerprint its protocol (TLS/raw) |
| `adb-probe.py` | Send a raw ADB CNXN to a port to identify if it speaks ADB |
| `syslog-server.py` | Minimal UDP/TCP syslog receiver for gateway log streaming |

## Prior art / credit

This builds on and cross-checks the existing community projects, which are the
place to start if you want working (cloud-era) control:

- `keithah/homebridge-june-oven` - the reverse-engineered protocol + pairing spec
- `jclima/ha-june-oven` - Home Assistant integration
- `deftdawg/june` - catalog preservation crawler

The genuinely new contribution here is the **oven-side** behavior under a
redirected/blocked cloud (cert pinning confirmed, no local fallback), gathered by
packet capture rather than app instrumentation.
