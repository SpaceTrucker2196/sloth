# sloth v1.4 — protocol breadth + operator controls

The breadth release. v1.3 added a data socket and SIEM integrations;
v1.4 pushes hard on protocol coverage (eleven new alert rules across
IPv6 NDP, SMB, Kerberos, LDAP, BGP, SSH, RDP, SNMP, MQTT, plus
host-posture), gives the operator per-interface control of the
capture pipeline, and lands three reporter-filed bug fixes that
tightened the key-routing and TLS-labelling correctness stories.

## New passive observers + alert rules

| Rule | Sev | Signal | Commit |
|---|---|---|---|
| `ROGUE_RA` | CRIT | unexpected IPv6 Router Advertisement (rogue gateway) | 60a7842 |
| `SMB1_USE` | CRIT | SMBv1 dialect observed (deprecated by Microsoft, 2017) | b58e148 |
| `KERB_PREAUTH_BURST` | WARN | Kerberos AS-REQ pre-auth failure spray (password spray) | f52181b |
| `LDAP_SEARCH_FLOOD` | WARN | LDAP search-request flood (AD enumeration) | a924177 |
| `BGP_NOTIFICATION_BURST` | WARN | burst of BGP NOTIFICATION frames on a session | af85588 |
| `SSH_BRUTE_FORCE` | WARN | SSH connect-then-drop pattern from a single source | dfcdbec |
| `RDP_BRUTE_FORCE` | WARN | RDP X.224 CR bursts (Cobalt Strike / mstsc.exe patterns) | ae6ea3a |
| `SNMP_COMMUNITY_BRUTE` | WARN | SNMPv1/v2c GetRequest fan-out with rotating community strings | cbb7d9e |
| `MQTT_BROKER_BRUTE` | CRIT | MQTT CONNECT/CONNACK-fail burst (Mirai-class broker sweeps) | 56f2703 |
| `NO_MONITOR_MODE` | WARN | ≥1 iface seen but no radio in monitor mode | d6ea32a |
| `WEAK_TLS` (fixed) | WARN | now correctly attributes TLS 1.3 handshakes (GREASE-filtered) | 8a633a9 |

**27 total alert rules** (was 16 in v1.3).

## Interface controls

Two independent per-interface elections now live in the `[1]`
interfaces view, both purely logical (nothing writes to the wire or
touches kernel state):

- **`t` — visibility.** Hide/unhide an iface from the interfaces
  view and the dashboard band. Traffic still flows into the pipeline.
- **`y` — data-stream selection** (issue #17). Drop a deselected
  iface's packets in the pcap callback *before* any decode / log /
  alert runs. Connections, Packets, DNS, TLS, HTTP, QUIC, ICMP, NTP,
  the JSONL log, and the alert engine all lose that iface's frames
  until it's toggled back.

  The filter requires `DLT_LINUX_SLL2` (cooked capture v2, which
  carries `sll2_if_index` at offset 4 of the header). sloth now opens
  `any` with `pcap_create` + `pcap_activate` and requests the SLL2
  datalink; older libpcap or a rejecting kernel degrades to SLL v1 /
  EN10MB, in which case the toggle becomes a UI-only marker.

Each iface row now also carries a **Mode** column (ETH / WIFI / MON /
`?`) and a **Vendor** column derived from the iface's MAC via the
embedded OUI table — the operator can see at a glance which radio is
monitor-capable and who made the NIC.

## Bug fixes (reporter-filed)

- **#13** — active view now gets first refusal on shadowed keys via
  a centralized `view_claims_key` table in `src/view_route.c`.
  Previously, iface `t`/`m`, conns `s`, packets `p`/`x`/`w`, stats
  `r`, and dashboard Tab were silently swallowed by the global
  view-switch (efbf07a).
- **#14** — TLS `supported_versions` extension now GREASE-filtered
  per RFC 8701; Chrome/Firefox TLS 1.3 handshakes no longer mislabel
  as `"TLS"` (8a633a9).
- **#15** — dashboard interfaces band honours the iface hide
  election, matching the interfaces view (f0434e3).

## New view

| Key | View | What it shows |
|---|---|---|
| `l` | OSI / TCP-IP stack | Layer-by-layer synthesis of the observed session |

**31 total views** (was 30 in v1.3). Note: OSI landed late in the v1.3
cycle and is counted here.

## Native output formats

Beyond the default JSONL, sloth now emits alerts and observations in
two additional wire formats without the SIEM forwarder — pipe
directly into legacy stacks:

- `--out-format cef` — ArcSight CEF (colon-separated key/values).
- `--out-format syslog` — RFC 5424 syslog with structured data.

Sink fan-out in `examples/forwarder/` also gained a comma-separated
`--sink` flag (`--sink loki,datadog`), Datadog Logs, and a generic
webhook sink for anything JSON-over-HTTPS.

## Test hardening + docs

- **2746 test assertions** (was 2122 in v1.3, +624).
- Mutation-testing round 11 covered the WiFi-SIGINT engines
  (probe_pnl, eapol_log, seqnum_track, assoc_track).
- New `docs-drift` GitHub Action runs LLM-as-judge against the
  docs on every push.
- New ring-buffer wiki page pins the invariants the mutation-testing
  rounds surfaced.

## Dashboard

- **4× faster default refresh** (250 ms, was 1000 ms) with
  event-driven wakes on alert fire via a self-pipe — new alerts hit
  the screen in milliseconds, not up to a full poll interval
  (38c4012).
- New `--refresh-ms N` CLI flag with a 50 ms floor.

## Stats

- 60 commits since v1.3.0
- 27 alert rules (+11)
- 31 views (+1)
- 2746 test assertions (+624)

## Upgrade

```
git pull
make
sudo ./sloth --data-socket unix:/tmp/sloth.sock \
             --eapol-dir /tmp/sloth-eapol \
             -o /tmp/sloth.jsonl
```

Nothing removed; the JSONL schema is additive. Existing consumers
keep working.
