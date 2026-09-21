# June Oven (Gen 3) — post-shutdown findings

Written 2026-09-20, from static analysis of the official June Android app
`com.junelife.companion` v1.24.1.11 (signed by June, cert SHA-256
`E6:54:88:76:...:91:82`) plus live probing of one oven on the LAN.
Weber's connected-services shutdown: **2026-09-22**.

## Bottom line

- **Pairing is already broken on Weber's servers.** The official June app cannot
  complete pairing either (observed 2026-09-20). Our clean-room implementation is
  byte-for-byte correct (verified against the app, see below), so the failure is
  server-side, not client-side. No client fix exists.
- **The oven's own AI cooking survives the shutdown.** Food recognition and cook
  programs run on the oven, not in the app or (at cook time) the cloud.
- **What dies:** phone remote-control, the live camera-to-phone view, time-lapse
  videos, in-app recipe browsing, and OTA firmware updates. All transit June's cloud.

## What runs where (verified)

| Capability | Where it runs | Survives 9/22? |
|---|---|---|
| Food recognition / Food ID | On the oven (camera + on-device bundles). The app ships **no** ML model (`grep` for `.tflite/.pb/.onnx` in the APK = none). | Yes, on the oven's screen |
| Cook programs / guided cooks | On-oven local DB (`CookProgramBrowserDatabase`) + `.jcpb` bundles on the oven | Yes, on the oven's screen |
| Manual bake/roast/broil/air-fry/toast | Oven firmware | Yes |
| Phone remote control (preheat/temp/cancel) | Cloud WebSocket relay `messaging.junelife.com` | No |
| Live camera view on phone | Cloud WS video frames (msg `10011`, `VideoFrame`, `signed_url`) | No |
| In-app recipe/collection browsing | Cloud REST `recipes.junelife.com`, `/1/recipes`, `/1/collections`, `/1/presets/catalog` | No |
| Pairing a new companion | Cloud (`api.junelife.com`) — already broken | No |
| Firmware / OTA | Cloud | No |

## Protocol facts (verified against the app, correcting the public spec)

The public reverse-engineering (keithah/homebridge-june-oven `JUNE_INTEGRATION_SPEC.md`)
is **correct**. Confirmed from June's own code:

- **Architecture:** oven opens an outbound WSS to `messaging.junelife.com` and
  verifies each command's **Ed25519 signature itself** against the key trusted at
  pairing. The cloud **never signs** — it only relays. (Implication: a LAN
  replacement server needs to relay transport, not impersonate June's authority.)
- **Pairing SRP-6a:** RFC-5054 **8192-bit** group, generator **g=19**, hash
  **SHA-1**, identity `"user"`, 16-byte salt. (`rb/i.java`, `qj/b.java` group `f22293g`.)
  Live-confirmed: the oven's SRP public value is exactly 1024 bytes / 8192 bits.
- **PIN:** server returns a **5-digit** `code` (used in the URL path). The 8-digit
  code shown to the user = `code` + 2 random digits + 1 **Damm** check digit; the
  **full 8 digits** are the SRP password. (`le/e.java`, `rb/i.java::c`.)
- **Sealed companion payload** (`bd/d.java`, snake_case, confirmed): keys
  `companion_id, companion_name, public_signing_key, public_encryption_key,
  timezone, platform, platform_version, model_number, serial_number`. Sealed as
  `base64( nonce(24) || secretbox_xsalsa20poly1305(json, nonce, K) )`,
  `K = BLAKE2b-256(S)` (unkeyed). (`rb/g.java::i`, `::k`.)
- **POST body** `/2/devices/pairing/{code}/companion` = `{key_info:{B, salt,
  companion_info}}` (three fields; `pin` is the URL path param, not a body field). (`yf/a.java`.)
- **Command signature** (`rb/g.java::a`): `base64( BLAKE2b(pubkey,8) || ed25519_sign(canonical_json) )`.

## Certificate pinning

- The **app** pins `*.junelife.com` to 3 SHA-256 SPKI pins (`o8/c.java`,
  `JuneCompanionApp` line ~371):
  - `sha256/63ehOyGTbdiutHEq3obqv/8QpKqbgJc23iS3lsXf2nQ=`
  - `sha256/8Rw90Ej3Ttt8RRkrg+WYDS9n7IS03bk5bjP/UXPtaY8=`
  - `sha256/Ko8tivDrEjiY90yGasP6ZpBU4jwXvHqVvQI0GS3GNdA=`
- **Unknown / untested:** whether the **oven firmware** pins when it connects to
  `messaging.junelife.com`. This single fact decides whether a DNS-redirect LAN
  server is viable (no pinning) or requires firmware/root access (pinning). No
  public artifact has tested this from the oven side. `lan-server/` is the test rig.

## Cloud endpoints (from the APK)

Hosts: `api.junelife.com`, `messaging.junelife.com`, `recipes.junelife.com`
(+ `dev-` variants). Paths: `/2/devices/register`, `/2/devices/pairing`,
`/2/devices/pairing/{pin}/companion`, `/2/devices/{id}`,
`/2/devices/{id}/associated`, `/2/devices/{id}/activation`,
`/2/devices/{id}/features`, `/2/devices/{id}/info`, `/2/auth/oauth/token`,
`/2/purchase/features`, `/2/purchase/products`, `/2/purchase/receipt`,
`/1/recipes`, `/1/recipes/{id}`, `/1/collections`, `/1/presets/catalog`,
`/1/analytics/log`.

## Message codes (WebSocket)

Commands (companion→oven): `11002` preheat, `11005` set-temp, `11004` cancel,
`11006` timer, `11011` keepalive.
Pushes (oven→companion): `10013` telemetry, `10018` device-state, `10020` ack,
`10014/10015/10016/10017` cook-plan, `10011` camera frame, `10026` pairing key,
`10027` pairing-session-invalidated, `10022` unpaired.

## LAN cert-pinning test — RESULT (2026-09-20, novel; nobody had tested oven-side)

Setup: UniFi DHCP DNS pointed at a box running dnsmasq (redirects
`*.junelife.com` → the box) + a TLS capture server on :443 with a self-signed
cert bearing the correct SANs. Oven rebooted.

Observed, oven `10.13.0.161`:
- **The oven uses the network's DNS.** On boot it queried our dnsmasq for
  `messaging.junelife.com` and `api.junelife.com` (also Android's
  `connectivitycheck.gstatic.com`, `www.google.com`, `time.android.com`).
  => No hardcoded IPs, no DoH. **DNS is a valid control point.**
- **The oven connected to us on :443** for both `api.junelife.com` and
  `messaging.junelife.com` (SNI present in ClientHello).
- **The oven REJECTED the self-signed cert:** it sent TLS alert
  `certificate_unknown` (alert 46) and aborted both handshakes. => The oven
  **validates the server certificate** (CA-validation and/or pinning; alert 46
  leans toward a pin/trust check rather than a plain `unknown_ca`).

**Conclusion:** a plain DNS-redirect + self-signed cert does **not** work — the
oven will not talk to a server it can't verify. Standing up a LAN replacement
server therefore requires either a cert the oven already trusts (we don't have
the private key; can't get a public CA cert for a domain we don't own) or
**root on the oven** to alter its trust store / disable validation. Root would
need a debug/exploit path; the transient port 8156 does not complete an ADB
handshake (opens <1s at boot, closes before responding to CNXN).

Net: **the oven's cloud link cannot be locally intercepted without oven root.**
On-device cooking is unaffected and continues to work from the oven's screen.
