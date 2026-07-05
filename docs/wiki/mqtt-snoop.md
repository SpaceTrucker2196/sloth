---
name: MQTT observability — MQTT_BROKER_BRUTE alert
description: Detecting IoT-broker credential brute-force on TCP/1883 via CONNECT and CONNACK-failure counting
type: feature
---

# MQTT observability

MQTT is the dominant IoT pub/sub protocol. Brokers default to
TCP/1883 cleartext; the TLS variant TCP/8883 is opaque past the
handshake. v3.1.1 is the most-deployed version; v3.1 lingers on
older firmware; v5 (2019) adds properties and richer reason codes.

The 1883 attack surface is huge: every botnet that has SSH
credentials in its loadout also has MQTT credentials. Mirai
descendants routinely sweep 1883 with the same `admin/admin`
wordlists. And many IoT brokers ship `allow_anonymous true` —
once an attacker is in, they can subscribe to every topic and
publish poisoned messages to every device.

Sloth's MQTT pass parses the cleartext Control Packet fixed
header on TCP/1883, recognises CONNECT / CONNACK / SUBSCRIBE /
PUBLISH, walks the CONNECT payload to pull the username when
present, and reads the CONNACK reason code to count auth
failures. Fires `MQTT_BROKER_BRUTE` on either path:
`connect_count ≥ 10` OR `connack_fail_count ≥ 5` per (client,
broker).

## What we detect

MQTT Control Packet fixed header:

```
0                   1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type | Flags |  Remaining Len  |  (1-4 bytes, varint)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type is the high nibble of byte 0. The Remaining Length is a
1-to-4-byte varint per OASIS §2.2.3 — each byte's bit 7 is the
continuation flag, bits 0-6 the value.

| Type | Name        | What we infer                          |
|------|-------------|----------------------------------------|
| 0x10 | CONNECT     | client opening a session — brute shape |
| 0x20 | CONNACK     | broker replying — reason code on byte 1|
| 0x30 | PUBLISH     | data flow — volume signal              |
| 0x80 | SUBSCRIBE   | topic-pattern enrollment               |

CONNECT variable header + payload, in order (v3.1.1 §3.1):
- Protocol Name UTF-8 string — `"MQTT"` (v4/v5) or `"MQIsdp"` (v3.1)
- Protocol Level byte — 3, 4, or 5
- Connect Flags byte — bit 7 = Username Flag (the bit we care about)
- Keep Alive (2 bytes)
- v5 only: Properties block (varint length + bytes)
- ClientID UTF-8 string
- If Will Flag set: Will Properties (v5) + Will Topic + Will Payload
- If Username Flag set: Username UTF-8 string ← extracted
- If Password Flag set: Password (binary) — not extracted

CONNACK reason codes:
- v3.1.1 §3.2.2.3: 0 = accepted; 1-5 = various failures (1 = unsupported version, 4 = bad credentials, 5 = not authorised).
- v5 §3.2.2.2: 0 = success; ≥ 0x80 = failure (0x86 = bad credentials, 0x87 = not authorised).

Per-(client_ip, broker_ip) aggregation: 32 flows tracked,
oldest-by-last-seen evicted.

## Alert: `MQTT_BROKER_BRUTE`

```
MQTT_BROKER_BRUTE: 203.0.113.7->10.0.0.10: 47 CONNECTs / 12 fails
(user=admin)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `connect_count ≥ 10` OR `connack_fail_count ≥ 5` |
| Dedup key | `mqtt-brute:<client>-><broker>` |
| `match_ip` | `src_ip` (the attacking client) |
| `match_port` | 1883 |

Two thresholds because there are two distinct attack shapes:

- **Connect-count path** mirrors the SSH/RDP brute-force model
  (10 connections from one client to one server). Catches
  attackers who don't wait for the server's response and just
  hammer.
- **CONNACK-fail path** is the broker telling us "wrong" five
  times. Lower threshold because it's stronger evidence — the
  broker has explicitly rejected. Catches paced attackers who
  stay under the connection-count radar.

## What's normal

- `connect_count` = 1 per session per client. Most MQTT clients
  open one connection at boot and reconnect on disconnect with
  modest backoff. Reconnect storms from a misbehaving client
  can hit 5-10 per minute but stabilise.
- `connack_fail_count` = 0 in steady state. A new device might
  generate one or two during initial provisioning.
- `proto_level` = 4 (v3.1.1) on most devices, 5 on newer
  deployments, 3 on legacy. A *mix* of levels from one client
  is suspicious.
- `publish_count` and `subscribe_count` track per-topic activity
  — useful for capacity inventory, not directly for security.

## What's suspicious

- `connect_count ≥ 10` — fires the alert.
- `connack_fail_count ≥ 5` — fires the alert independently.
  A scanner getting 5 explicit rejections is unambiguous.
- `connect_count` very high with `publish_count == 0` and
  `subscribe_count == 0` — client never moves past auth.
  The shape says "didn't get in".
- `last_username` rotating through obvious watchlist values
  (admin, root, mqtt, test, user) — not currently a dedicated
  alert; SIEM-side rules using the `mqtt_flow` record stream
  catch it.

## Deliberately out of scope (for now)

- **Topic-content inspection.** PUBLISH payloads are arbitrary
  bytes and could leak sensitive sensor data. We deliberately
  don't inspect them — payload sniffing crosses from
  observability into a different class of activity.
- **MQTT over WebSockets** (RFC 6455 over TCP/80 or TCP/443).
  Cleartext WS over 80 is observable but is parsed by the
  general HTTP path; v5 brokers exposing 80 are rare. TLS
  variant inherits the existing TLS handshake observability.
- **MQTT-SN** (UDP/1884 broker-side, mostly Zigbee/6LoWPAN).
  Different on-wire format and a much smaller attack surface.
- **MQTT v5 USER PROPERTIES.** Could leak per-vendor metadata;
  parsing the v5 Properties block beyond skipping it is a
  Tier 2 follow-up.
- **Rate-shape correlation across brokers.** A botnet spraying
  one (admin, password) pair across many brokers stays under
  every per-flow threshold here. SIEM-side aggregation by
  `last_username` catches it; per-broker rules can't.

## References

- [OASIS MQTT v3.1.1 spec](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).
- [OASIS MQTT v5.0 spec](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html).
- MITRE ATT&CK T1110.001 — Brute Force: Password Guessing
  (MQTT variant).
- [Mosquitto broker default config](https://github.com/eclipse/mosquitto)
  — `allow_anonymous false` is the v2.0+ default; pre-2.0
  deployments commonly had it `true`.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `mqtt_flow` wire format.
- [[ssh-snoop]] / [[rdp-snoop]] / [[snmp-snoop]] — sibling
  brute-force observables; MQTT joins SSH/RDP on the
  connection-count shape and SNMP on the username/cred-rotation
  shape, blended via the dual-threshold rule.
