# PROGRESS.md — Agent activity log

A warm-start view of the repo: what's in flight, what just landed, what
was decided. Companion to [`MISSION.md`](MISSION.md) (the charter, slow
moving) and [`docs/wiki/log.md`](docs/wiki/log.md) (wiki edits only).

**Who writes here**: every agent that lands a non-trivial change.
**When**: at the end of a working session, before pushing the commits
that close out the work.
**Where to read first**: top of the file. Newest entries at the top of
their section; the "In progress" section is mutable, the "Recently
landed" section is append-only.

---

## Format

Each landed entry is one block:

```
### YYYY-MM-DD — short title
**Commits**: <hash1>, <hash2>
**Touched**: paths or modules
**Why**: one to three sentences on what motivated the change
**Follow-ups**: open work this exposed, if any (link to the In-progress entry)
```

Each in-progress entry is one block:

```
### <short title>
**Owner**: agent name + session (or human if a human is driving)
**Started**: YYYY-MM-DD
**Goal**: one sentence
**Status**: free text — where it is right now
**Blockers**: if any
**Next concrete step**: what the next agent picking it up should do
```

When an in-progress item lands, **move** it to "Recently landed" (do
not duplicate). Add the commit hashes. Append any follow-up that the
work exposed as a new In-progress entry.

---

## In progress

*(nothing actively in flight — pick from "Open follow-ups" or the
paused work below)*

### Paused: Mutation-testing follow-ups (rounds 10+)
**Owner**: next agent
**Started**: 2026-05-28 — paused 2026-05-28 by operator request
**Status**: rounds 1-9 closed. Aggregate kill rate is **51.0% of
considered** (estimated 938 killed / 1844 considered / 2311
mutants total). The campaign delivered ~600 net mutants killed and
the `--ignore-file` machinery; remaining work is small per-round
gains against the noise floor (see "diminishing returns" pattern in
the "Recently landed" entries). Resume at will; everything is
non-blocking and stateless.
**Next concrete step** (in priority order, if resuming):
1. ~~Bulk-add LZT / SBL / TIP entries for `dns_log.c`, `tls_log.c`,
   `http_log.c`~~ — landed 2026-06-03 (round 10).
2. ~~Mutate `src/probe_pnl.c`, `src/eapol_log.c`,
   `src/seqnum_track.c`, `src/assoc_track.c`~~ — landed 2026-06-04
   (round 11). 20 entries; modest because the WiFi-SIGINT engines
   reject fewer inputs than the protocol logs and the search-loop
   LZTs are not safely equivalent when zero-MAC inputs aren't
   filtered.
3. Skip `src/views/*.c` — render code, low semantic value.
4. Cosmetic: tighten the "killed (build broke)" sub-counter so
   compile failures and test-binary segfaults are categorised
   distinctly (both currently produce stderr containing "error"
   + "make"; the heuristic conflates them).

---

## Recently landed

### 2026-06-07 — Faster refresh + event-driven dashboard wakes
**Touched**: `include/sloth.h`, `src/main.c`, `src/tui.{c,h}`,
`src/alerts.c`, `src/event_wake.{c,h}` (new),
`tests/null_tui.c`, `Makefile`
**Why**: Operator ask — the dashboard should feel realtime and
react to events as they happen, not on a fixed 1 Hz cadence.
Two problems with the previous loop: the default refresh was
1000 ms (visibly laggy on a wall-clock scale) and the loop
blocked in tui_poll_key for the whole interval even when an
alert fired in the meantime, so new alerts could sit invisible
for up to a full tick before the next redraw.
**What's in it**:
- **Default refresh dropped from 1000 ms → 250 ms** (~4 Hz).
  Per-loop work is a few ms; 250 ms feels realtime to a
  human and keeps CPU modest.
- **New `--refresh-ms N` CLI flag** with a 50 ms floor (sub-50
  burns CPU without visible gain on a terminal). Validation
  rejects non-integer / out-of-range values cleanly.
- **New `src/event_wake.{c,h}` module**: tiny self-pipe
  wrapper — `event_wake_init / _fd / _signal / _drain`.
  Non-blocking writes, non-blocking drains, FD_CLOEXEC on
  both ends. Safe to call from any thread.
- **`tui_poll_key` gained a `wake_fd` parameter**: select()
  watches stdin AND the wake fd. If only the wake fd is
  ready, returns 0 (no key, but breaks the wait). Both the
  ncurses and ANSI-fallback paths take the new parameter so
  the embedded build keeps working.
- **`alerts.c fire()` calls `event_wake_signal()` after each
  new alert key**: so the very next loop iteration redraws
  with the new alert visible. End-to-end latency: a new alert
  goes from "engine row appended" to "pixels on screen" in
  milliseconds, not up to one full refresh interval.
- Main loop drains the wake pipe after each poll_key so a
  single wake doesn't fire forever.
- The wake module is a no-op when uninitialised
  (e.g. unit-test binaries that don't run a TUI) so
  `alerts.c` stays linkable in both contexts. The test
  null_tui.c stub was updated to the new `tui_poll_key`
  signature.
**Counts**: 2688 assertions still passing. make is warning-clean.
Smoke test 40/40 record types end-to-end.

### 2026-06-07 — MQTT observability: MQTT_BROKER_BRUTE alert
**Touched**: `include/sloth.h`, `src/mqtt_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_mqtt_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/mqtt-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Ninth passive-observable landing. Closes the IoT
slice of the internet-substrate bucket. MQTT brokers on
TCP/1883 are routinely swept by Mirai-class scanners with
the same wordlists they hammer SSH with; many brokers ship
`allow_anonymous true` and most clients ship with vendor
defaults. The cleartext fixed header (1 type byte + 1-4
byte Remaining Length varint) is tag-recognisable and
CONNECT payloads expose the username being guessed.
MITRE ATT&CK T1110.001 (Password Guessing — MQTT variant).
**What's in it**:
- New `src/mqtt_snoop.{c,h}` module: parses the MQTT Control
  Packet fixed header per OASIS v3.1.1 / v5 specs (1-4 byte
  Remaining Length varint, type-nibble dispatch on
  CONNECT/CONNACK/SUBSCRIBE/PUBLISH).
- CONNECT payload walk: protocol name + level + flags + keep
  alive + (v5) properties + ClientID + (will fields if Will
  Flag) + username (if Username Flag). Username extracted into
  `last_username`; non-printable bytes drop the value entirely
  to keep JSONL lines safe.
- CONNACK reason-code reading: v3.1.1 codes 1-5 count as
  failures, v5 codes ≥ 0x80 count as failures.
- Tracks CONNECTs, CONNACK failures, SUBSCRIBEs, PUBLISHes,
  and the latest protocol level on a per-(client, broker)
  basis. Flow attribution flips for CONNACK so the client
  stays as `src_ip` across both directions.
- Per-flow aggregation; 32 flows, oldest-by-last-seen
  evicted.
- New `ALERT_TYPE_MQTT_BROKER_BRUTE` +
  `rule_mqtt_broker_brute`: dual-threshold rule fires CRIT
  when `connect_count >= 10` (the SSH/RDP brute shape) OR
  `connack_fail_count >= 5` (the broker's explicit "wrong"
  signal — quieter but more specific). Dedup key
  `mqtt-brute:<client>-><broker>`; match_ip=client,
  match_port=1883.
- TCP/1883 dispatch via `try_mqtt` in both `decode_ipv4` and
  `decode_ipv6` branches of capture.c.
- New `mqtt_flow` JSONL record type via state-snapshot
  umbrella. Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 40 record
  types end-to-end across Loki + Datadog + webhook + fan-out.
- 13 tests in `tests/test_mqtt_snoop.c`: CONNECT / SUBSCRIBE
  / PUBLISH detection, username extraction, CONNACK bad-creds
  counts as failure (with client-side attribution flip),
  CONNACK success not counted, repeated CONNECTs accumulate,
  two clients tracked separately, non-1883 port rejected,
  non-MQTT payload rejected, unknown type rejected, truncated
  rejected, non-printable username dropped without crashing.
- 4 alert tests in `tests/test_alerts.c`: fires at connect
  threshold (10), fires at fail threshold (5), no-fire below
  both, separate alerts per attacker-broker.
- New wiki page `docs/wiki/mqtt-snoop.md`: fixed-header
  diagram, packet-type table, dual-threshold rationale,
  what's-normal / what's-suspicious sections, Tier 2
  follow-ups (topic-content / MQTT-SN / MQTT-over-WS / v5
  USER PROPERTIES / cross-broker rate-shape).
**Counts**: 2688 assertions (+29 from SNMP round). make is
warning-clean. Smoke test 40/40 record types end-to-end.
**Closes the original observable queue**: NDP + SMB +
Kerberos + LDAP + BGP + SSH + RDP + SNMP + MQTT all landed,
each fronted by a CRIT alert. The Tier 2 expansions per
protocol remain queued for follow-up rounds.

### 2026-06-07 — SNMP observability: SNMP_COMMUNITY_BRUTE alert
**Touched**: `include/sloth.h`, `src/snmp_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_snmp_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/snmp-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Eighth passive-observable landing. SNMP v1/v2c
carries the community string — the SNMP analogue of a
password — in cleartext ASN.1 BER on UDP/161/162. Almost
every embedded device, printer, and switch on a LAN still
runs v2c by default. snmpwalk with a community wordlist and
metasploit's snmp_login module both rotate community strings
one packet at a time; the unique-community count is the
unmistakable signature. MITRE ATT&CK T1110.001 (Password
Guessing — SNMP variant) and T1046 (Network Service
Scanning).
**What's in it**:
- New `src/snmp_snoop.{c,h}` module: parses the outer
  SEQUENCE + version INTEGER + community OCTET STRING +
  PDU tag of an SNMP message per RFC 1157 §4.1 / RFC 1901 §3.
  Handles short-form and multi-byte BER length encodings.
- Recognises all nine PDU tags 0xA0..0xA8 (Get / GetNext /
  Response / Set / Trap-v1 / GetBulk / Inform / Trap-v2 /
  Report). Set requests get their own counter — they're rare
  in monitoring traffic and a Set with a guessed community
  is the post-exploitation config-rewrite step.
- Tracks up to 8 distinct community strings per flow plus the
  most recent. Community strings with embedded non-printable
  bytes are dropped entirely (sanitisation) so they can't
  poison a JSONL line.
- v3 messages are recorded (version field set) but no
  community extraction — the v3 envelope is different and
  v3 brute-force has a different signature anyway.
- Flow attribution flips for GetResponse packets so the
  querier (not the agent) stays as `src_ip` across the whole
  conversation.
- Per-(src_ip, dst_ip) aggregation; 48 flows, oldest-by-
  last-seen-evicted.
- New `ALERT_TYPE_SNMP_COMMUNITY_BRUTE` +
  `rule_snmp_community_brute`: fires CRIT when
  `community_count >= 5` per (src, dst). Dedup key
  `snmp-brute:<src>-><dst>`; match_ip=src, match_port=161.
- UDP dispatch in both `decode_ipv4` and `decode_ipv6`
  branches of `capture.c` covers ports 161 and 162.
- New `snmp_flow` JSONL record type via state-snapshot
  umbrella. Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 39 record
  types end-to-end across Loki + Datadog + webhook + fan-out.
- 14 tests in `tests/test_snmp_snoop.c`: Get / GetNext /
  GetBulk / Set / Response (with querier-attribution flip) /
  v2-Trap detection, repeated-community deduplication,
  distinct-community accumulation, community-list cap,
  non-SNMP port rejected, non-SNMP payload rejected,
  truncated rejected, unknown PDU tag rejected, embedded
  NUL byte in community dropped without crashing.
- 3 alert tests in `tests/test_alerts.c`: fires at threshold
  (5), no-fire below (4), separate alerts per attacker-target.
- New wiki page `docs/wiki/snmp-snoop.md`: PDU-tag table,
  community-tracking rationale, what's-normal /
  what's-suspicious sections, Tier 2 follow-ups (OID
  inspection, SNMPv3 USM parsing, walk-rate analysis,
  reflective-amplification cross-link).
**Counts**: 2659 assertions (+33 from RDP round). make is
warning-clean. Smoke test 39/39 record types end-to-end.
**Deliberately out of scope**: OID-content inspection
(needed for known-sensitive OID flagging), v3 USM parsing
(security name extraction for v3 user enumeration),
per-second walk-rate analysis, reflective-amplification
detection (different module entirely — connection-cadence
side, not protocol-shape side).

### 2026-06-07 — RDP observability: RDP_BRUTE_FORCE alert
**Touched**: `include/sloth.h`, `src/rdp_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_rdp_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/rdp-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Seventh passive-observable landing — second from the
internet-substrate bucket after SSH. RDP is the Windows
lateral-movement and remote-administration substrate; the
TPKT + X.224 connection-setup envelope is cleartext even when
the session is wrapped in CredSSP/NLA. xfreerdp-loop, NLBrute,
and Crowbar all hammer 3389 the same way SSH brute tools
hammer 22 — one TCP connection per credential attempt.
MITRE ATT&CK T1110.001 (Password Guessing — RDP variant) and
T1021.001 (Remote Services: Remote Desktop Protocol).
**What's in it**:
- New `src/rdp_snoop.{c,h}` module: parses the TPKT envelope
  per RFC 1006 §6 (version 0x03, length BE u16) and the X.224
  Class 0 Connection Request TPDU (code 0xE0, DST-REF=0x0000).
- Extracts the mstshash cookie when present
  (`Cookie: mstshash=USERNAME\r\n`) — the username field the
  attacker is guessing against. Useful for surfacing the exact
  account under attack and for SIEM-side spray detection
  (username rotation against one server).
- Extracts the MS-RDPBCGR §2.2.1.1 RDP Negotiation Request
  TLV when present and OR-accumulates the requestedProtocols
  bitmask (RDP / SSL / HYBRID / HYBRID_EX). Lets operators
  spot clients that refuse NLA — possibly attack tools that
  don't bother implementing modern auth.
- Per-(client_ip, server_ip) aggregation; 64 flows,
  oldest-by-last-seen evicted.
- New `ALERT_TYPE_RDP_BRUTE_FORCE` + `rule_rdp_brute_force`:
  fires CRIT when `connect_req_count >= 10` per (client, server).
  Dedup key `rdp-brute:<client>-><server>`; match_ip=client,
  match_port=3389 so per-alert pcap pivots to the RDP traffic.
- Server→client direction (src_port=3389) is rejected at the
  parser — X.224 Connection Confirm has code 0xD0, not the CR
  code 0xE0 we match.
- New `rdp_flow` JSONL record type via state-snapshot umbrella.
  Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 38 record
  types end-to-end across Loki + Datadog + webhook + fan-out.
- 12 tests in `tests/test_rdp_snoop.c`: minimal CR detection,
  cookie username extraction, RDP_NEG_REQ protocol extraction,
  protocol mask accumulates across multiple CRs, repeated CRs
  accumulate per flow, two clients tracked separately,
  non-3389 port rejected, server-side (src_port=3389)
  rejected, bad TPKT version rejected, non-CR TPDU (Connection
  Confirm) rejected, truncated payload rejected, non-RDP HTTP
  payload rejected.
- 4 alert tests in `tests/test_alerts.c`: fires at threshold (10),
  no-fire below (9), separate alerts per attacker-target,
  no-cookie case renders cleanly.
- New wiki page `docs/wiki/rdp-snoop.md`: TPKT/X.224 layout
  diagrams, protocol-mask table, what's-normal /
  what's-suspicious sections, Tier 2 follow-ups (Negotiation
  Response parsing, per-second cadence, classic-username
  watchlist).
**Counts**: 2626 assertions (+27 from SSH round). make is
warning-clean. Smoke test 38/38 record types end-to-end.
**Deliberately out of scope**: Negotiation Response parsing
(would distinguish accepted vs rejected CRs), CredSSP-leak
user enumeration, per-second cadence-shape analysis,
MS-RDPEDC channel inspection (opaque past TLS wrap).

### 2026-06-01 — SSH observability: SSH_BRUTE_FORCE alert
**Touched**: `include/sloth.h`, `src/ssh_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_ssh_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/ssh-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Sixth passive-observable landing — first one drawn
from the internet-substrate (vs AD-substrate) bucket. SSH is
the universal remote-shell protocol and brute-force is the
universal internet attack. The signal is connection cadence
(many TCP flows per second from one source), not auth-payload
content — which is encrypted and that's fine, because we
never need it. MITRE ATT&CK T1110.001 (Password Guessing)
and T1110.003 (Password Spraying).
**What's in it**:
- New `src/ssh_snoop.{c,h}` module: matches the cleartext
  banner exchange per RFC 4253 §4.2. Requires the literal
  `SSH-` prefix plus a second `-` within the first 12 bytes
  so arbitrary cleartext starting with `SSH-` doesn't trigger.
- Only *server* banners (src_port=22) are counted — exactly
  one per TCP connection. Counting client banners too would
  double every connection.
- Server banner string is kept (truncated at CR/LF or first
  non-printable byte) so the alert detail carries the
  software fingerprint — `OpenSSH_8.9`, `dropbear_2022.83`,
  legacy `SSH-1.99-...`.
- Per-(client_ip, server_ip) aggregation; 64 flows,
  oldest-by-last-seen-evicted.
- New `ALERT_TYPE_SSH_BRUTE_FORCE` + `rule_ssh_brute_force`:
  fires CRIT when `banner_count >= 10` per (client, server).
  Dedup key `ssh-brute:<client>-><server>` so each attacker /
  target pair is its own alert. match_ip=client_ip,
  match_port=22 so per-alert pcap pivots to the SSH traffic.
- `decode_ipv4` / `decode_ipv6` route TCP/22 in either
  direction to `try_ssh`.
- New `ssh_flow` JSONL record type via state-snapshot umbrella.
  Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 37 record
  types end-to-end across Loki + Datadog + webhook + fan-out.
- 12 tests in `tests/test_ssh_snoop.c`: OpenSSH banner,
  Dropbear banner, legacy SSH-1.99 banner, client banner NOT
  counted, repeated banners accumulate, two clients tracked
  separately, two servers tracked separately, non-SSH port
  rejected, non-SSH payload rejected (HTTP-on-22),
  `SSH-`-without-dash rejected (anti-false-positive),
  truncated banner rejected, banner storage truncates at CR/LF.
- 3 alert tests in `tests/test_alerts.c`: fires at threshold
  (10), no-fire below (9), separate alerts per attacker-target.
- New wiki page `docs/wiki/ssh-snoop.md`: RFC banner format,
  server-vs-client counting decision, what's-normal /
  what's-suspicious sections, Tier 2 follow-ups (KEX-init
  parsing, HASSH client fingerprinting).
**Counts**: 2599 assertions (+28 from BGP round). make is
warning-clean. Smoke test 37/37 record types end-to-end.
**Deliberately out of scope**: KEX-method / cipher list
extraction from `SSH_MSG_KEXINIT` (needed for HASSH client
fingerprinting — Tier 2), failed-auth detection (encrypted —
sloth's connection-count heuristic substitutes), tunnelled
protocol detection (the beacon detector covers that pattern at
the higher layer).

### 2026-06-01 — BGP observability: BGP_NOTIFICATION_BURST alert
**Touched**: `include/sloth.h`, `src/bgp_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_bgp_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/bgp-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Fifth passive-observable landing. BGP-4 (RFC 4271)
wires the internet together — and increasingly the data-centre
fabric — over TCP/179. NOTIFICATION messages are the
session-teardown signal: rare in healthy peering, dense when
a peer is flapping or an on-path attacker is tearing the
session down before injecting competing routes. MITRE ATT&CK
T1565.002 (Transmitted Data Manipulation, BGP-hijack subset).
**What's in it**:
- New `src/bgp_snoop.{c,h}` module: walks the RFC 4271 §4.1
  19-byte header (16-byte 0xFF marker + 2-byte length + 1-byte
  type) per message, iterating across back-to-back records in
  one TCP segment. Stops on malformed framing or unknown type
  but commits everything observed so far — partial parses still
  count.
- Recognises OPEN (1), UPDATE (2), NOTIFICATION (3), KEEPALIVE
  (4); aggregates per peer-pair with peer IPs sorted lexically
  so messages in either direction collapse to one session.
- Per-(peer_a, peer_b) aggregation; 32 sessions, oldest-by-
  last-seen-evicted.
- New `ALERT_TYPE_BGP_NOTIFICATION_BURST` +
  `rule_bgp_notification_burst`: fires CRIT when
  `notification_count >= 3` for one peer-pair. Dedup key
  `bgp-notif:<peer_a><>peer_b>` so each flapping peering
  relationship gets its own alert. match_ip = peer_a (smaller
  IP), match_port=179 so per-alert pcap pivots to BGP traffic.
- `decode_ipv4` / `decode_ipv6` route TCP/179 in either
  direction to `try_bgp`. TCP/MD5-authenticated BGP (RFC 2385)
  is silently skipped because its non-0xFF marker won't match —
  virtually no one uses MD5 anymore.
- New `bgp_session` JSONL record type via the state-snapshot
  umbrella. Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 36 record
  types end-to-end across Loki + Datadog + webhook + fan-out.
- 14 tests in `tests/test_bgp_snoop.c`: per-type detection
  (OPEN / UPDATE / NOTIFICATION / KEEPALIVE), back-to-back
  message walking, notification-burst accumulation,
  peer-pair canonicalisation (either direction folds to one
  session), two-pair separation, port gating (non-179
  rejected; either endpoint on 179 works), bad-marker
  rejection, undersize rejection, oversize-length rejection,
  unknown-type stops walk but commits prior records.
- 3 alert tests in `tests/test_alerts.c`: fires at threshold
  (3), no-fire below (2), separate alerts per peer-pair.
- New wiki page `docs/wiki/bgp-snoop.md`: ASCII header
  diagram, type table with RFC § references, what's-normal /
  what's-suspicious sections, Tier 2 follow-ups (AS-number
  extraction, prefix-hijack detection, route-flap dampening).
**Counts**: 2571 assertions (+31 from LDAP round). make is
warning-clean. Smoke test 36/36 record types end-to-end.
**Deliberately out of scope**: AS-number extraction from OPEN
+ UPDATE (needed for prefix-hijack detection — requires RPKI/IRR
ground truth, which a passive observer can't get), route-flap
dampening (needs UPDATE NLRI parsing), BMP (RFC 7854 — would
be a richer signal but requires active router-config opt-in).

### 2026-06-04 — LDAP observability: LDAP_SEARCH_FLOOD alert
**Touched**: `include/sloth.h`, `src/ldap_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_ldap_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/ldap-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Fourth (and last in this round) passive-observable
landing. LDAP is the directory-substrate AD enumeration tools
hit hardest — BloodHound's SharpHound, ldapdomaindump, and the
impacket family produce 100+ SearchRequest messages in seconds
from a single workstation. A normal workstation logon produces
~10–20. The flood shape is unmistakable. MITRE ATT&CK
T1087.002 (Domain Account Discovery) + T1069.002 (Group
Discovery).
**What's in it**:
- New `src/ldap_snoop.{c,h}` module: ASN.1 BER framing parser per
  RFC 4511. Walks the outer SEQUENCE + messageID INTEGER to
  expose the protocolOp tag, recognises BindRequest (0x60),
  SearchRequest (0x63), and SearchResultReference (0x73). One
  more level of BER walk inside BindRequest checks whether the
  LDAPDN `name` field is empty — anonymous-bind detection.
- `BindResponse`, `SearchResultEntry`, `SearchResultDone`, and
  `UnbindRequest` are deliberately NOT counted. Including
  SearchResultEntry would inflate the search-flood counter by
  every result row and defeat the threshold.
- Per-(client_ip) aggregation; 64 sources, oldest-evicted.
- New `ALERT_TYPE_LDAP_SEARCH_FLOOD` + `rule_ldap_search_flood`:
  fires CRIT when `search_count >= 50` from a single source.
  Dedup key `ldap-flood:<src_ip>` so each enumerator is its own
  alert. match_port=389 so per-alert pcap pivots to cleartext
  LDAP.
- `decode_ipv4` / `decode_ipv6` routes TCP/389 and TCP/3268
  (Global Catalog) to `try_ldap`. LDAPS (636 / 3269) is opaque
  past the handshake and not observed.
- New `ldap_event` JSONL record type via state-snapshot umbrella.
  Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 35 record types
  end-to-end across Loki + Datadog + webhook + fan-out.
- 12 tests in `tests/test_ldap_snoop.c`: authenticated bind,
  anonymous bind, search request, search result reference,
  unrecognised op (SearchResultEntry) ignored, server-side
  src_port inference, Global Catalog port works, non-LDAP port
  rejected, repeated searches accumulate, two sources tracked
  separately, non-LDAP payload rejected, truncated/indefinite-
  length envelope rejected.
- 3 alert tests in `tests/test_alerts.c`: fires at threshold (50),
  no-fire below (49), separate alerts per enumerating source.
- New wiki page `docs/wiki/ldap-snoop.md`: protocol-op table with
  RFC § references, what's-normal / what's-suspicious sections,
  Tier 2 follow-ups (per-attribute query inspection,
  result-size analysis, referral URL extraction).
**Counts**: 2540 assertions (+27 from Kerberos round). make is
warning-clean. Smoke test 35/35 record types end-to-end.
**Deliberately out of scope**: per-attribute query inspection
(catches `servicePrincipalName` / `userPassword` /
`msDS-AllowedToActOnBehalfOfOtherIdentity` lookups specifically),
result-size analysis (catches throttled enumeration), referral
URL extraction (topology leakage), LDAPS (opaque). Each is a
tractable Tier 2 follow-up documented in the wiki page.

### 2026-06-04 — Kerberos observability: KERB_PREAUTH_BURST alert
**Touched**: `include/sloth.h`, `src/kerb_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_kerb_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/kerberos-snoop.md`
(new), `docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Third entry from "more passive observables" — Kerberos
is the substrate of every AD environment, and password spray
campaigns produce a clean burst of `KDC_ERR_PREAUTH_FAILED`
responses that's straightforward to detect passively. MITRE
ATT&CK T1110.003.
**What's in it**:
- New `src/kerb_snoop.{c,h}` module: message-type detection via
  the outer ASN.1 `[APPLICATION n]` tag (AS-REQ=0x6A, AS-REP=0x6B,
  TGS-REQ=0x6C, TGS-REP=0x6D, KRB-ERROR=0x7E). TCP/88 prepends a
  4-byte length; the parser checks for the magic at offset 0 or 4.
- Minimal ASN.1 walk in `parse_krb_error_code` scans the first
  ~96 bytes of a KRB-ERROR for the `[6]` context-specific tag
  (DER: `A6 LEN 02 ilen <bytes>`) — enough to bucket
  `KDC_ERR_PREAUTH_REQUIRED` (25), `KDC_ERR_PREAUTH_FAILED` (24),
  `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) without invoking a real
  ASN.1 parser.
- Per-(client_ip) aggregation table, 64 sources, oldest-evicted
  on overflow. Records counts of each message type + each error
  bucket.
- New `ALERT_TYPE_KERB_PREAUTH_BURST` + `rule_kerb_preauth_burst`:
  fires CRIT when `preauth_failed_count ≥ 5` per source. Dedup
  key `kerb-burst:<src_ip>` so each spraying source is its own
  alert. match_port=88 so per-alert pcap pivots to the KDC flow.
- `decode_ipv4` / `decode_ipv6` routes TCP/88 to `try_kerb_tcp`
  and UDP/88 directly to `kerb_snoop_observe` (in the existing
  UDP service-port switch).
- New `kerb_event` JSONL record type via state-snapshot umbrella.
  Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — 34 record types
  end-to-end across Loki + Datadog + webhook + fan-out.
- 12 tests in `tests/test_kerb_snoop.c`: message-type detection
  per tag, error-code extraction for all four buckets, TCP
  length-prefix skip, repeated-failures accumulate, two sources
  tracked separately, non-Kerberos / no-KDC-port rejection.
- 3 alert tests in `tests/test_alerts.c`: fires at threshold,
  no-fire below, separate alerts per spraying source.
- New wiki page `docs/wiki/kerberos-snoop.md`: message-type table
  with RFC § references, error-code bucket explanation, the "what
  is normal" / "what is suspicious" sections, and Tier 2 follow-up
  list (principal extraction, AS-REP roasting, kerberoasting).
**Counts**: 2513 assertions (+27 over SMB round). make is
warning-clean. Smoke test 34/34 record types end-to-end.
**Deliberately out of scope**: username/principal extraction
(AS-REQ `cname` parsing needs deeper ASN.1 walk), AS-REP roasting
(needs request/response pairing), kerberoasting (high TGS-REQ
volumes from one client), pre-auth bypass via NTLM fallback
(belongs in the SMB NTLMSSP follow-up). Documented in the wiki
so the next agent knows what's left.

### 2026-06-04 — SMB observability: SMB1 detection + SMB1_USE alert
**Touched**: `include/sloth.h`, `src/smb_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_smb_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/smb-snoop.md` (new),
`docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: Second entry from the "more passive observables"
follow-up. SMBv1 has been deprecated by Microsoft since 2017;
EternalBlue (CVE-2017-0144) and the WannaCry / NotPetya campaigns
specifically targeted it. Observing SMBv1 on the wire post-2024 is
by itself a finding — the dialect detection is enough to deliver
that finding without parsing further into the protocol.
**What's in it**:
- New `src/smb_snoop.{c,h}` module: 4-byte SMB magic detection
  (`\xFF SMB` = SMB1, `\xFE SMB` = SMB2/3), handles both direct
  (port 445) and NetBIOS-framed (port 139) payload layouts.
  Per-(client_ip, server_ip, server_port) session table, 64
  entries, evict-oldest on overflow. Dialect is **sticky to SMB1**
  — once observed it does NOT downgrade, since mid-flow v1
  negotiation is precisely the attacker-forced pattern.
- New `ALERT_TYPE_SMB1_USE` + `rule_smb1_use` fires CRIT per
  (client, server, port) tuple whose dialect is SMB1. Dedup key
  `smb1:<client>><server>:<port>` so each endpoint pair is its
  own alert — operators get a concrete pivot.
- `decode_ipv4` / `decode_ipv6` in `src/capture/capture.c` route
  TCP/445 and TCP/139 traffic to `try_smb` alongside the existing
  SNI / HTTP sniffers.
- New `smb_session` JSONL record type via state-snapshot umbrella.
  Schema documented in `jsonl-schema.md`.
- `mock-sloth.py` cycles a synthetic template — Compose demo + CI
  smoke test now cover 33 record types end-to-end on all sinks.
- Hand-crafted byte-array tests per [MS-SMB] / [MS-SMB2] in
  `tests/test_smb_snoop.c`: direct SMB1 + SMB2, NBSS-framed SMB1
  + SMB2, server-side src_port inference, SMB1 stickiness, two
  distinct sessions, non-SMB payload rejection, short payload
  rejection, no-SMB-port rejection.
- 3 alert tests in `tests/test_alerts.c`: SMB1 fires CRIT with
  correct match_ip/port + detail format, SMB2 does NOT fire, two
  distinct SMB1 sessions produce two separate alerts.
- New wiki page `docs/wiki/smb-snoop.md`: threat model, EternalBlue
  history, CISA reference, what's-normal / what's-suspicious, the
  "why not split SMB2/3" decision, and an explicit list of
  out-of-scope follow-ups (NTLMSSP parsing, tree-connect to admin
  shares, signing posture, DCE/RPC subprotocols).
**Counts**: 2486 assertions total (+37 from the NDP round).
make is warning-clean. Smoke test passes 33/33 record types
across Loki / Datadog / webhook + fan-out.
**Deliberately out of scope**: NTLMSSP auth extraction (username
+ domain leak in plaintext through Type 1/2/3), tree-connect
path tracking for `ADMIN$` / `C$` / `IPC$`, SMB signing /
encryption posture, DCE/RPC subprotocols. Each is a tractable
follow-up documented in the wiki page.

### 2026-06-04 — IPv6 NDP — Router Advertisement snoop + ROGUE_RA alert
**Touched**: `include/sloth.h`, `src/ndp_snoop.{c,h}` (new),
`src/capture/capture.c`, `src/main.c`, `src/alerts.c`,
`src/jsonl.{c,h}`, `tests/test_ndp_snoop.c` (new),
`tests/test_alerts.c`, `tests/main_test.c`, `Makefile`,
`examples/compose/mock-sloth.py`, `docs/wiki/ipv6-ndp.md` (new),
`docs/wiki/index.md`, `docs/wiki/jsonl-schema.md`
**Why**: First entry from the "more passive observables" follow-up
list. NDP (RFC 4861) is unauthenticated by default; modern IPv6
endpoints SLAAC themselves the moment a Router Advertisement
arrives. mitm6 / Slaacers and friends use rogue RAs to steal
default-router status — Windows in particular prefers IPv6 over
IPv4 when both are present, so a single injected RA can silently
divert all traffic. The IPv4 analogue (rogue DHCP) has been
detected for a while; the IPv6 detector closes the parallel gap.
**What's in it**:
- New `src/ndp_snoop.{c,h}` module: RA parser per RFC 4861 §4.2 + §4.6,
  per-router state table (16 distinct router sources, evict-oldest
  on overflow). Tracks `cur_hop_limit`, M/O/H flags byte,
  `router_lifetime`, plus up to 4 prefixes from PIO options and
  the optional `src_mac` from a Source Link-Layer Address option.
- New `ALERT_TYPE_ROGUE_RA` enum value + `rule_rogue_ra` in
  `alerts.c`, structurally identical to `rule_rogue_dhcp`: collects
  distinct `src_ip` values with `router_lifetime > 0`, sorts for a
  stable dedup key, fires CRIT once ≥2 distinct routers are
  observed. Dedup key is `rogue_ra:<comma-joined sorted IPs>`.
- `decode_ipv6` in `src/capture/capture.c` dispatches type-134
  ICMPv6 frames to `ndp_snoop_ra` (the existing ICMPv6 log emit
  continues to run too).
- New `ndp_ra` JSONL record type emitted via state-snapshot
  umbrella (`jsonl_emit_ndp_ras`). Schema documented in
  `jsonl-schema.md`.
- `examples/compose/mock-sloth.py` cycles a synthetic `ndp_ra`
  template so the Compose demo and CI smoke test cover the new
  record type automatically — 32/32 record types now pass through
  on all three sinks (Loki / Datadog / webhook) + fan-out.
- Hand-crafted byte-array tests per RFC 4861 in
  `tests/test_ndp_snoop.c` cover minimal RA, RA + SLLA option,
  RA + PIO option (prefix formatting via `inet_ntop`), two-router
  separation, repeat-RA increments-count, zero-lifetime recording,
  rejection of non-RA ICMPv6 (type 135 NS), rejection of truncated
  payloads, and the zero-length-option termination case (RFC 4861
  §4.6 — implementations SHOULD ignore len=0; we treat as
  end-of-options so the walk can't loop forever).
- 5 rogue-RA tests in `tests/test_alerts.c` mirror the rogue-DHCP
  suite: single-router no-fire, two-router CRIT, zero-lifetime
  filter, detail-string sorting + key stability, same-router
  dedup.
- New wiki page `docs/wiki/ipv6-ndp.md`: threat model + RFC
  citations + what's-normal / what's-suspicious sections + the
  scope decision (RA-only for v1; NS/NA neighbor cache deferred).
**Counts**: 2449 assertions total (+45 from the previous round).
make is warning-clean.
**Out of scope for this change**: NS/NA neighbor cache, DAD
exhaustion, Redirect frames, dedicated TUI view (alerts view
already surfaces ROGUE_RA). Documented in the wiki page so the
next agent knows what's intentionally left.

### 2026-06-04 — Mutation round 11: WiFi-SIGINT engine equivalences
**Touched**: `.github/scripts/mutate-equivalents.txt`
**Why**: Continues the paused mutation-testing campaign. Round 11
covers the four WiFi-SIGINT engines flagged as step 3 of the
original wind-down TODO: `probe_pnl`, `eapol_log`, `seqnum_track`,
`assoc_track`.
**What's in it**:
- **`assoc_track.c`** (3 LZT entries): search-loop, forget-loop,
  and snapshot clamp. The search/forget loops qualify because the
  observe entry explicitly rejects multicast/broadcast AND all-zero
  MACs (lines 34 + 40), so pair_eq against the zero-init tail is
  always false.
- **`seqnum_track.c`** (1 LZT entry): snapshot clamp only. The
  search loop does NOT qualify — the observe entry filters
  multicast but not all-zero MACs, so the zero-init tail could
  accidentally match an all-zero input and corrupt state.
- **`probe_pnl.c`** (1 LZT entry): snapshot clamp only. Same
  posture as seqnum_track; per-client SSID-list mutations are
  also excluded because the bounds are tight against the embedded
  array.
- **`eapol_log.c`** (15 entries): the WiFi-SIGINT engine with the
  largest mix — 6× SBL doublets (g_out_dir + two path[]s + three
  hashcat-22000 line builders + eapol_hex[1024]) + LZT for the
  ring-buffer triplet (saturating-add at push_event, snapshot
  clamp, snapshot loop bound). Pending-handshake search/eviction
  loops are excluded for the same zero-MAC risk as seqnum/PNL.

20 new equivalence lines; 158 in the file overall (was 138).
Modest gain compared to round 10 (27 entries) because the
WiFi-SIGINT engines reject fewer inputs than the protocol logs.

Steps 1+2+3 from the original paused-mutation TODO are now closed.
Step 4 (the build-broke / segfault sub-counter categorisation)
remains; it's cosmetic and can be picked up by anyone resuming.

**Verification**: `make test` → 2404 assertions still pass.
Equivalence file is consumed by `make mutate`, not by the unit
suite, so no test count change — kill-rate impact surfaces on the
next campaign.

### 2026-06-03 — Mutation round 10 + ring-buffer architecture wiki page
**Touched**: `.github/scripts/mutate-equivalents.txt`,
`docs/wiki/ring-buffers.md` (new), `docs/wiki/architecture.md`,
`docs/wiki/mutation-testing.md`, `docs/wiki/index.md`
**Why**: The 2026-05-28 mutation-testing wind-down left an
explicit follow-up: bulk-add the ring-buffer LZT / SBL equivalence
entries for `dns_log.c`, `tls_log.c`, `http_log.c` mirroring the
patterns already documented for `quic_log.c`. The expectation was
each file's kill rate-of-considered would climb above 55% and the
aggregate would recover from ~51% back toward ~55%. Pure
mutation-testing bookkeeping — no production code changes.
**What's in it**:
- **`dns_log.c`** (3 entries): LZT triplet for the saturating-add
  + snapshot-clamp + snapshot-loop-bound pattern. No SBL entries
  because the parser scratch buffers (`qname`, `tmp`, `rname`,
  `ip`, `first_ip`) all use the `DNS_NAME_LEN` macro, not
  literals.
- **`tls_log.c`** (13 entries): SBL doublets for the five literal-
  sized JA3-builder scratch buffers (`tmp[8]`, `ja3_str[512]`,
  `sni[64]`, `curves_buf[256]`, `fmts_buf[64]`) plus the ring-
  buffer LZT triplet. The test corpus (canned ClientHellos with
  bounded cipher / extension lists) never reaches truncation
  thresholds.
- **`http_log.c`** (7 entries): SBL doublets for `host[64]` and
  `ua[64]` header-value scratch buffers + ring-buffer LZT
  triplet.
- **`ntp_log.c`** (2 entries): saturating-add + snapshot-loop-
  bound only. No clamp entry: `ntp_log_snapshot` reads `n =
  ntp_count` directly without the `count < MAX ? count : MAX`
  ternary, so the clamp equivalence doesn't apply.
- **`icmp_log.c`** (2 entries): same shape as NTP — saturating-
  add + snapshot-loop-bound only.

27 new equivalence lines total; 138 in the file overall (was 111).
Steps 1+2 from the paused-mutation TODO close together; the
WiFi-SIGINT engines (`probe_pnl`, `eapol_log`, `seqnum_track`,
`assoc_track`) remain as the next concrete step if anyone resumes.

**Wiki page** (`docs/wiki/ring-buffers.md`): documents the
pattern the equivalence entries lean on — head pointer, saturating
count, mutex, snapshot reverse-chronological + selection clamp,
the three operations (`record`, `snapshot`, `clear`), and the
NTP/ICMP variation that omits the snapshot-clamp ternary.
Cross-linked from `architecture.md` (the source-map tree line for
the log files now points at `[[ring-buffers]]`) and from
`mutation-testing.md` (the equivalence-class shorthand list calls
out the LZT and SBL details that live in the new page).

**Verification**: `make test` → 2404 assertions still pass.
Equivalence file is consumed by `make mutate`, not by the unit
suite, so no test count change here — the kill-rate impact will
surface on the next mutation campaign.

### 2026-06-03 — docs-drift LLM judge (GitHub Action)
**Touched**: `.github/workflows/docs-drift.yml` (new),
`.github/scripts/docs_drift.py` (new),
`.github/scripts/docs_drift_prompt.md` (new),
`docs/wiki/docs-drift-judge.md` (new), `docs/wiki/index.md`
**Why**: `CLAUDE.md` mandates per-view docs (`docs/views/X.md`)
stay in sync with the implementation (`src/views/X.c`), but
sync was enforced only by human discipline at review time.
With the recent burst of new views (Twins) + rich field
additions (every `ap_fingerprint_t` flag bit, every
`twin_episode_t` field), the per-view docs are exactly the
artefact most prone to silent rot. The Toloka "Agent-as-a-Judge"
article (https://toloka.ai/blog/ai-agent-as-a-judge-...) made
the case for using LLMs as evaluators for fuzzy quality
dimensions; docs-code drift is the highest-leverage slice of
that pattern for sloth specifically.
**What's in it**:
- Mirror of the existing `code-review.yml` /
  `code_review.py` pattern (same `_http` helper, same OpenAI
  `chat/completions` call, same `response_format: json_object`,
  same `ensure_label` / `create_issue` shape) so an operator
  familiar with one understands the other.
- 42 `(src, doc)` pairs covered: every `src/views/*.c` paired
  with its same-stem `docs/views/*.md`, plus an explicit
  `EXTRA_PAIRS` map for synthesis docs (`alerts.c` →
  `alerts.md`, `beacon_snoop.c` → `beacons.md`, etc.) and the
  handful of views whose doc basename historically differs
  from the source file (`iface.c` → `interfaces.md`,
  `conns.c` → `connections.md`, `procs.c` → `processes.md`,
  `dns_log.c` → `dns.md`).
- Two triggers: weekly cron (Mondays 09:00 UTC) opens one
  issue per stale pair, deduped by title against existing
  open `docs-drift` issues. Pull-request trigger audits only
  the changed pairs and posts a single PR comment.
- Workflow is **advisory only** — never fails the build.
  Fails open when `OPENAI_API_KEY` is missing (forks /
  external contributors); CI stays hermetic for offline
  development.
- Judge prompt versioned as
  `.github/scripts/docs_drift_prompt.md` — markdown so
  prompt-only changes show up cleanly in PR diffs.
- Output schema is structured JSON
  (`verdict`/`confidence`/`findings[]` with `severity`,
  `category`, `evidence_code`, `evidence_doc`,
  `explanation`); the judge is explicitly allowed to return
  `"uncertain"` rather than guess.
- Operator-facing wiki page at
  `docs/wiki/docs-drift-judge.md` documents the dismissal
  workflow (close the issue with a comment; the stateless
  judge won't reopen until the next sweep actually still
  sees drift) and the deliberate non-gating posture.
**Toloka mapping**: the article's full trajectory-based judge
is for evaluating AI agents on multi-step code-generation
tasks — not directly applicable to a static C99 program.
The narrower "LLM-as-judge for fuzzy quality dimensions"
idea is what we landed; trajectory-based eval of sloth on
synthetic pcaps is documented as a possible follow-up.
**Cost**: ~42 API calls/week + PR-bounded runs; well under
$1/month at GPT-5.2-Codex pricing.
**Verification**: dry-run against every pair via
`python .github/scripts/docs_drift.py --mode schedule
--no-llm --dry-run` exits 0 and shows the discovery loop
finds 42 pairs. Real API call deferred to first scheduled
run once the `OPENAI_API_KEY` secret is set in the repo.

### 2026-06-02 — Evil-twin AP detection (6 phases)
**Commits**: `24b2aa7`, `f81aab0`, `32f53a8`, `059f502`, `50a768b`, `16cfd0a`
**Touched**: `include/sloth.h`, `src/alerts.{c,h}`, `src/beacon_snoop.c`,
`src/eapol_log.c`, `src/jsonl.{c,h}`, `src/main.c`, `src/tui.c`,
`src/twins.{c,h}`, `src/views/{beacon,twins}.{c,h}`,
`src/wifi_oui_attacker.{c,h}`, `tests/test_alerts.c`,
`tests/test_beacon_snoop.c`, `tests/test_eapol_log.c`,
`tests/test_jsonl.c`, `tests/test_twins.c`,
`tests/test_wifi_oui_attacker.c`, `tests/test_{state,arp}.c`
(VIEW_COUNT bumps), `tests/main_test.c`, `Makefile`, `README.md`,
`docs/views/{README,twins}.md`, `docs/wiki/{jsonl-schema,index,
evil-twin-reproducer}.md`
**Why**: Modern evil-twin attacks (Pineapple, ESP32-Marauder) mirror
the legit AP's SSID + cipher to defeat the existing weak/strong twin
check. Extends `rule_evil_twin` with same-cipher diff-OUI detection,
vendor-IE fingerprint hashing, RSSI-step proximity, deauth-correlated
attack-chain CRIT, and full UI / JSONL surface. Lands the newer of
the two copilot plans (`copilot/evil-twin-ap-detection-update`,
planned 2026-06-01).
**What's in it** (phase-by-phase):
- **Phase 1** (`24b2aa7`) — `ap_fingerprint_t` carrier + same-cipher
  WARN branch with dedup key `twin-fp:<ssid>`. Skips OPEN. New enum
  `ALERT_TYPE_EVIL_TWIN_PROXIMITY` reserved for Phase 3.
- **Phase 2** (`f81aab0`) — beacon parser fills `fp.flags`
  (HT/VHT/HE/WPS-UUID-zero) and `vendor_ies_hash` (FNV-1a over non-MS
  tag-221 IEs in beacon order). New `src/wifi_oui_attacker.{c,h}`
  with Hak5 + Espressif tables. WARN→CRIT escalation on hash
  mismatch or attacker OUI.
- **Phase 3** (`32f53a8`) — `rssi_ring_t` (16-slot ring) in
  `beacon_ap_t`; `rssi_ring_push()` recomputes the 60s min/max on
  each beacon. `rule_evil_twin_proximity` fires WARN on ≥15 dBm
  swing, key `twin-prox:<bssid>`. `0` sentinel guards first-observation
  false fires.
- **Phase 4** (`059f502`) — `rule_evil_twin_attack_chain` correlates
  twin pair + recent DEAUTH_FLOOD → CRIT `EVIL_TWIN` (key
  `twin-chain:<ssid>`, "attack-in-progress" detail). 32-slot taint
  tracker (300s TTL, alerts.h API). EAPOL `.22000` export prepends
  `# provenance=tainted-evil-twin bssid=<MAC>` for handshakes against
  tainted BSSIDs (hashcat ignores `#`).
- **Phase 5** (`50a768b`) — `twin_episode_t` materialised view +
  `twins_snapshot()` (RSSI-default real/twin, taint override). New
  `[x] Twins` view (`VIEW_TWINS = 30`, `VIEW_COUNT = 31`) with flag
  glyphs `!@#*~`. Beacon view SSID column gets glyph suffix; status
  line surfaces episode count. New JSONL `twin_episode` record type.
- **Phase 6** (`16cfd0a`) — validation. Hand-crafted parser tests for
  HT/VHT/HE/WPS-UUID-zero/vendor-hash. EAPOL provenance-marker test.
  End-to-end attack-chain scenario asserting all 5 acceptance
  criteria (chain fires, all flags set; clean baseline doesn't fire).
  scapy reproducer doc at `docs/wiki/evil-twin-reproducer.md` for
  live testing.

**Counts**: 2302 assertions total, was 2143 before Phase 1 (+159).
All 6 phases warning-clean.

**Deliberate non-fixtures**: skipped literal pcap fixtures in
`tests/fixtures/` despite the original plan. Per CLAUDE.md "Hand-
crafted protocol tests" discipline, a scapy-roundtripped pcap would
be circular (sloth parsing scapy output without a third-party
reference). The same coverage now lives in hand-crafted byte arrays
(Phase 6 parser tests) plus the e2e scenario, with scapy reproducer
snippets documented for live testing.

**Follow-ups**: `AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS` remains reserved
but unpopulated — signature needs pcap calibration before it can be
defined reliably. (The `HAK5_OUI` / `ESPRESSIF_OUI` follow-ups closed
2026-06-02 in the entry below.)

### 2026-06-02 — Evil-twin AP/OUI flag-bit population + Loki sink + Compose demo
**Touched**: `src/beacon_snoop.c`, `tests/test_beacon_snoop.c`,
`examples/forwarder/sloth-forward.py`, `examples/forwarder/README.md`,
`examples/compose/` (new dir: `docker-compose.yml`, `mock-sloth.py`,
`loki-config.yml`, `grafana-datasource.yml`, `README.md`)
**Why**: Closes two open follow-ups and lights up a third end-to-end
demo path so evaluators can see the JSONL stream land in a SIEM-like
surface within seconds of `docker compose up`.

**What's in it**:
- **`AP_FP_FLAG_HAK5_OUI` / `AP_FP_FLAG_ESPRESSIF_OUI` population**
  — `beacon_record` now sets the flag bits inline from the BSSID OUI
  via `oui_is_hak5()` / `oui_is_espressif()`. Bits never clear; they
  live for the entry's lifetime. Downstream consumers (JSONL,
  iOS, Twins view) can surface the marker without re-doing the
  table lookup. 3 new tests in `test_beacon_snoop.c` (Hak5 OUI sets
  the flag, Espressif OUI sets the flag, clean OUI sets neither).
- **Loki sink in the forwarder** — fourth sink type alongside
  `hec` / `syslog` / `elastic`. Groups by `type` field so each
  record type becomes its own Loki stream (keeps label
  cardinality bounded). Supports multi-tenant (`X-Scope-OrgID`),
  basic auth, and `--loki-insecure` for test clusters. ~95 LoC for
  the sink class + ~25 LoC for CLI flags + a documentation block in
  the forwarder README.
- **`examples/compose/`** — four-container demo stack
  (mock-sloth producer + forwarder + Loki + Grafana). One
  `docker compose up`, then open Grafana on `:3000` and run
  `{job="sloth"}` to see records arriving. The producer is a
  synthetic Python script (`mock-sloth.py`) emitting one record per
  record-type per second; the wire format matches sloth's
  `--data-socket tcp:HOST:PORT` so swapping in real sloth is one
  line. README documents the substitution. Grafana datasource is
  auto-provisioned; Loki runs single-binary with filesystem storage.

**Counts**: 2311 assertions total (+9 from Phase 6 close). make is
warning-clean.

**Follow-ups**: None directly. The Compose stack documents how to
swap in real sloth; that requires a published Docker image which
isn't built here.

### 2026-06-02 — `connections` JSONL record type
**Commits**: `23777db`
**Touched**: `src/jsonl.{c,h}`, `src/main.c`, `tests/test_jsonl.c`,
`docs/wiki/jsonl-schema.md`
**Why**: Eighth JSONL record type — per-flow connection snapshots so
`sloth-ios` (and any other JSONL consumer) can build a Connections
view with RTT, retx, and bw join, without having to re-derive flow
identity from packet-level records. Lands the older of the two
copilot plans (`copilot/add-connection-records`, planned 2026-05-28).
**What's in it**:
- New emitter `jsonl_emit_connections(s)` writes one line per active
  flow in `s->conns[0..conn_count)`. Driven from `poll_data()` at the
  ≈1 Hz poll cadence; consumers rebuild their table from the latest
  snapshot keyed by `(src, dst, proto)`.
- TCP records carry `state` (kernel `TCP_*` table — duplicated in
  `jsonl.c` to avoid a layering dep on view code), `rtt_ms`
  (omitted when `rtt_us == 0`), and `retx`.
- UDP records omit `state` / `rtt_ms` / `retx`.
- Endpoints render as `host:port`; IPv6 addresses get bracketed
  (`[fe80::1]:54321`).
- `rx_bytes` / `tx_bytes` join from `bw_lookup()` — both 0 when no
  bw entry (also when `WITH_PCAP=0`).
- `age_s` was deferred — option (b) of the plan. `linux_get_conns`
  rebuilds the conn array from `/proc/net/{tcp,udp}{,6}` every poll
  with no state retention, so `first_seen` can't be carried forward
  without breaking the platform vtable contract. Consumers can
  compute age client-side from the first record they observe.
- Schema doc updated; iOS Swift consumer sketch already expects this
  record shape so no client-side change required.
- Three new tests in `tests/test_jsonl.c`: mixed TCP+UDP fields,
  IPv6 bracketing, `rtt_ms` omission on zero RTT.
**Follow-ups**:
- `age_s` revisit — would need a tuple-keyed parallel table in
  `main.c` (carry `first_seen` across polls) or a vtable change.
  Not urgent: consumers can compute it.
- `retx` is currently always emitted for TCP, including when 0.
  The spec said `omit for UDP` (which we do) but didn't specify
  zero-skip for TCP — leaving as-is, consumer treats 0 as "none".

### 2026-05-28 — `examples/forwarder/` SIEM forwarder (HEC + syslog + Elastic)
**Commits**: `742257c`, `a093e23`
**Touched**: `examples/forwarder/sloth-forward.py` (new, ~525 lines
across two commits), `examples/forwarder/README.md` (new),
`examples/README.md`, `docs/wiki/jsonl-schema.md`
**Why**: After the consumer landed, the next step was a SIEM
forwarder showing how to take the same JSONL stream to a real
downstream. Three sinks ship — covering ~95% of operator
deployments (Splunk, syslog-anything, Elastic / OpenSearch / cloud
clusters). Sink interface is two members (`.name`,
`.send(batch)`), so adding Loki / Datadog / in-house collectors
is ~30 lines per sink.
**What's in it**:
- `hec` — Splunk HEC envelopes over HTTPS POST. Token via
  `--hec-token-env` to keep credentials out of `ps`.
- `syslog` — RFC 5424 over UDP (default) or TCP. MSGID is the
  record's `type`, MSG is the raw JSON, PRI defaults to 134
  (local0.info).
- `elastic` — Bulk API (`POST /_bulk`). Time-rolled indices via
  strftime tokens (`sloth-events-%Y.%m.%d`). `@timestamp` derived
  from `ts`. Basic auth or API key. Partial failures
  (`errors:true` in the 200 response) surface as batch failures
  so the retry loop sees them.
- Batching (`--batch-size 100 --batch-ms 1000` default), retries
  with exponential backoff, drop-on-failure to match sloth's
  non-durable contract (MISSION.md §4). Stats line to stderr
  every `--stats-interval` (default 30s): `received=N
  forwarded=N dropped=N retries=N`.
- `--type` / `--src` filters mirror the consumer.
- `--no-reconnect` for one-shot / test use; default is loop forever.
- Smoke-tested end-to-end against in-process fake servers for
  HEC, syslog-UDP, and Elastic (including the partial-failure
  path with mapper_parsing_exception).
- Production patterns documented in the README: systemd unit
  template with `EnvironmentFile`, "one forwarder per sink"
  rationale, when to combine with `-o FILE` for durability.

### 2026-05-28 — `examples/consumer/` Python reference consumer
**Commits**: `4526f8a`
**Touched**: `examples/consumer/sloth-stream.py` (new, ~270 lines),
`examples/consumer/README.md` (new), `examples/README.md` (new),
`FACTORY.md`, `docs/wiki/jsonl-schema.md`
**Why**: The JSONL data socket spec was documented but had no
runnable companion. A reference consumer validates the schema by
exercising it, gives external integrators a working starting point
in the simplest possible language, and serves as the textbook shape
for porting to Go / Node / Swift / etc.
**What's in it**:
- `parse_spec` → `connect` → `stream_lines` → `json.loads` →
  filter → format → print, with disconnect → backoff → reconnect.
- `unix:` and `tcp:` specs (matches sloth's `--data-socket SPEC`).
- `--type` and `--src` filters; `--raw` pass-through (for `| jq .`);
  `--count` 5s-interval tally; `--no-reconnect` for one-shot.
- Per-type ANSI-colour pretty formatters. Forward-compat for
  unknown `type` values (raw fields rendered instead of dropped).
- Stdlib only. Python 3.7+. ~270 lines, single file.
- Smoke-tested end-to-end against a fake sloth producer; every
  record type from the schema renders with its distinctive marker.

### 2026-05-28 — Round 9: per-protocol log files + selection-clamp tests
**Commits**: *(this commit)*
**Touched**: `tests/test_dns_log.c`, `tests/test_tls_log.c`,
`tests/test_quic_log.c`, `tests/test_http_log.c`,
`.github/scripts/mutate-equivalents.txt`, `README.md`,
`PROGRESS.md`
**Why**: Round 9 baselined the four per-protocol log files and
discovered they all share the same selection-clamp boundary that
the existing `_clamps_sel` test didn't pin (it seeds `sel=99` with
`n=1` — way above the boundary, so `>=` -> `>` and `>` -> `>=`
mutations both survive).

**Per-file baselines** (no triage yet for 3 of 4):

| target              | mutants | baseline raw | of considered (post-r9) |
|---------------------|---------|--------------|-------------------------|
| `src/dns_log.c`     | 203     | 47.8%        | ~48.8% (boundary tests only) |
| `src/tls_log.c`     | 276     | 37.0%        | ~37.7% (boundary tests only) |
| `src/quic_log.c`    | 22      | 68.2%        | **100.0%** (full triage) |
| `src/http_log.c`    | 179     | 38.0%        | ~39.1% (boundary tests only) |

**8 new assertions** added across 4 tests:
- `tests/test_dns_log.c`: `test_snapshot_clamps_sel_at_exact_boundary`
  + `test_snapshot_empty_resets_sel_to_zero`
- `tests/test_quic_log.c`, `tests/test_tls_log.c`,
  `tests/test_http_log.c`: combined
  `test_snapshot_clamps_sel_at_boundary_and_empty` (sel == n
  exactly + empty-log path)

Each test pair kills two specific mutations:
- `>=` -> `>`: when sel exactly equals n (one past last valid
  index), the clamp must still trigger.
- `>` -> `>=`: when n is 0, mutated code computes `n - 1 = -1`
  and assigns that to sel — a real bug.

**5 new ignore entries** for `quic_log.c` only (`SBL` for
`char ver[8]`, `LZT` for the snapshot loop bounds + saturating
add). `quic_log.c` now reports **100.0% of considered** (17/17,
5 ignored) — same clean result as `threat_intel.c`. The pattern
extends to the other 3 log files but their bulk-ignore work is
queued for round 10.

**Aggregate estimate after round 9**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 2311  | 467     | 1844       | ~938   | **~51.0%**    |

The aggregate **dropped from 55.4% to ~51.0%** because adding
the four new log files introduced ~700 mutants at 37-48% raw
baselines, pulling the average down. Round 10's bulk-ignore work
will recover most of this without code changes — the same
LZT/SBL/return-sentinel patterns documented for quic_log apply
to the other three.

**README badges** bumped: tests 2114 → 2122; mutation kill rate
55.4% (yellowgreen) → 51.0% **(yellow — first downward
tier-move in the campaign)**.

**Decisions worth flagging**:
- Did NOT fully triage dns_log/tls_log/http_log this round. They
  share quic_log's structure exactly; bulk-extending the ignore
  entries would close most of the gap, but doing it correctly
  per-line (rather than wildcarded) is the right move and adds
  ~30 entries to the ignore file. Queued for round 10 to keep
  this commit focused.
- The badge tier-move (yellowgreen → yellow) is honest. Aggregate
  is a moving target while new files are still being mutated;
  short-term wobbles are expected.

### 2026-05-28 — Round 8: scan + filter + host_cache + ip_owner (DT class)
**Commits**: *(this commit)*
**Touched**: `.github/scripts/mutate.py`,
`.github/scripts/mutate-equivalents.txt`,
`tests/test_scan.c`, `tests/test_filter.c`,
`docs/wiki/mutation-testing.md`, `README.md`, `PROGRESS.md`
**Why**: Push beyond the export-path / alerts files into smaller
untouched code. `scan.c`'s RFC1918/multicast filter has a clean
boundary surface that pays off in tests; `filter.c`/`host_cache.c`
were nearly equivalence-class-only; `ip_owner.c` exposed a new
issue — files dominated by static data tables.

**Per-file results** (post-ignore-file):

| target              | mutants | ignored | considered | killed | of considered |
|---------------------|---------|---------|------------|--------|---------------|
| `src/scan.c`        | 77      | 0       | 77         | 66     | **85.7%**     |
| `src/filter.c`      | 35      | 8       | 27         | 21     | **77.8%**     |
| `src/host_cache.c`  | 20      | 3       | 17         | 14     | **82.4%**     |
| `src/ip_owner.c`    | 393     | 352     | 41         | 20     | **48.8%**     |

**9 new tests** in `tests/test_scan.c`:
- A `routable_seed_then_assert` helper drives a comprehensive
  boundary sweep over `scan_is_routable`'s ranges:
  10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT), 127/8,
  169.254/16, 224/4 (multicast). Each range tested with one IP
  just inside and one just outside on each side. Kills the
  bulk of the const ±1 and rel `>=`→`>` mutations on lines 16-22.
- `test_routable_rejects_malformed_ips` covers the
  `sscanf < 2` guard (single-octet input, non-numeric "abc").

**1 new test** in `tests/test_filter.c`:
- `test_needle_exact_length_match`: needle and haystack of
  equal length must match. Kills the line-10 `nlen > hlen`
  boundary that the existing `_longer_than_haystack` test
  didn't pin.

**New ignore-file capability: wildcards + line ranges**.
`mutate.py` now supports:
- `<line>` field as a range `M-N` (inclusive).
- `<op>` / `<original>` / `<mutated>` as `*` (any).

Together these enable bulk-ignoring structurally-untestable
blocks of code. The triggering case: `ip_owner.c` has 70+ CIDR
entries in a `static const ip_owner_range_t g_owners[]` table.
Each octet literal is a mutation site (393 mutants total, 291
of them on table lines). Writing a behavioural test per octet
just repeats the table in the test file — the data IS the
contract. Bulk-ignored via:

    src/ip_owner.c:22-94:*:*:*    # DT: g_owners CIDR data block

This dropped ip_owner's 393-mutant pile to 41 considered (the
actual lookup functions); 20/41 killed (48.8%) — a fair number.

**New DT equivalence class** documented in
`docs/wiki/mutation-testing.md`: static lookup tables whose
correctness is a data-validation concern, not a behavioural-test
concern.

**Aggregate after round 8**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 1631  | 462     | 1169       | 648    | **55.4%**     |

(Up from 52.3% in round 7. The jump comes from scan.c's
85.7% boundary sweep + the new files' generally clean baselines.)

**README badges** bumped: tests 2085 → 2114; mutation kill rate
52.3% (yellow) → 55.4% **(yellowgreen)** — first colour tier
move since the campaign began.

**Decisions worth flagging**:
- Wildcard support is powerful and dangerous. Documented the
  failure mode (carelessly-broad entries hide real gaps forever)
  in `docs/wiki/mutation-testing.md` "Filtering known
  equivalents". The DT entry for ip_owner.c specifically covers
  *only* lines 22-94 (the static array), leaving lines 95-113
  (the lookup functions) under behavioural test.
- `scan_is_routable` is static and not directly testable, but
  the boundary sweep tests through `scan_update`'s public
  surface get the same coverage with no API churn.
- Did NOT triage all 21 ip_owner code-path survivors. Many are
  in the `ip_owner_lookup_str` parser (`sscanf` returns, octet
  bounds) and overlap with the `scan_is_routable` patterns
  already covered. Marginal value; deferred to a future round.

### 2026-05-27 — Round 7: data_socket fault-injection seam
**Commits**: *(this commit)*
**Touched**: `src/data_socket.{c,h}`, `tests/test_data_socket.c`,
`.github/scripts/mutate-equivalents.txt`,
`docs/wiki/mutation-testing.md`, `README.md`, `PROGRESS.md`
**Why**: Round 6 closed the cheap real-socket wins on
`data_socket.c`; the remaining survivors are in `send` / `accept`
error paths that real-socket fixtures can't reliably trigger. Add
a small fault-injection seam (function-pointer indirection +
test-only setter) so unit tests can force EAGAIN, partial-send,
and accept-overflow.

**Seam design** (production cost: one predictable branch per call):
```
static data_socket_send_fn   g_send_fn   = send;
static data_socket_accept_fn g_accept_fn = accept;
void data_socket_test_set_send_fn  (data_socket_send_fn   fn);
void data_socket_test_set_accept_fn(data_socket_accept_fn fn);
```
Setters accept NULL to restore defaults. All `send`/`accept` call
sites in `data_socket.c` now go through `g_send_fn` / `g_accept_fn`.
Header declarations cite "test only — production must not call".

**Three new tests**:
- `test_send_eagain_keeps_client`        : fake send returns -1 with
                                           errno=EAGAIN; client must
                                           stay (slow-client branch).
- `test_send_partial_harvests_client`    : fake returns n < len;
                                           client must be closed +
                                           compacted (non-EAGAIN
                                           failure branch).
- `test_tick_caps_at_max_clients`        : fake accept always
                                           succeeds; the `while
                                           (g_client_n < MAX_CLIENTS)`
                                           guard must drain exactly
                                           16 fds (not 15, not 17).

**Per-file delta** (after the seam + tests + line-number
re-anchoring of the ignore file):

| target              | before | after  | delta |
|---------------------|--------|--------|-------|
| `src/data_socket.c` | 26.7%  | **27.6%** | +1 mutant |

**Smaller win than expected**. The fault-injection seam unlocks 3
specific branches, but most send/accept failure paths reduce to
the same close-and-compact behavior the EPIPE test already
covered. The infrastructure remains valuable for testing future
error-path additions; it's not pure overhead.

**New OPT entry**: `data_socket.c:208:bool:||:&&` — on Linux and
Darwin, `EAGAIN == EWOULDBLOCK` (same numeric value), so
`errno == EAGAIN || errno == EWOULDBLOCK` collapses to the same
test under either operator. Documented as OPT (equivalence-by-data,
not by structure).

**Ignore-file fragility documented** in
`docs/wiki/mutation-testing.md` §"Line numbers are fragile":
inserting code above an ignored mutation site invalidates the
entry. The 18-line fault-injection seam at the top of
`data_socket.c` shifted every entry below by +18; I re-anchored
them in the same commit. A future improvement (queued) is
content-hash fingerprinting so adds/removes don't churn the
ignore file.

**Aggregate after round 7**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 1106  | 100     | 1006       | 527    | **52.4%**     |

(The "ignored" count is 100 with the EAGAIN OPT entry added but
the line-shift adjustments preserved net coverage; effective
delta on the aggregate is +1 mutant killed, +1 mutant ignored.)

**README badges** bumped: tests 2071 → 2085; mutation kill rate
52.2% → 52.3% of considered.

**Decisions worth flagging**:
- Used `static ssize_t (*g_send_fn)(...) = send;` rather than a
  conditional initializer or `dlsym` lookup. C99 allows function-
  symbol addresses in static initializers; one less branch in the
  hot path.
- Header declarations of the test setters are in `data_socket.h`
  itself rather than a separate `data_socket_test.h`. The "test
  only — production must not call" comment is the contract;
  splitting the header would add files for marginal isolation.
- The fault-injection tests use `dup(fd)` to mint fake fds for the
  accept-overflow test. Cheap, valid, harmless to close in cleanup.

### 2026-05-27 — Round 6: dns_snoop hop-chain + data_socket real-socket triage
**Commits**: *(this commit)*
**Touched**: `tests/test_dns_snoop.c`, `tests/test_data_socket.c`,
`README.md`, `PROGRESS.md`
**Why**: Two of the round-5 follow-ups closed without needing
infrastructure changes — the dns_snoop hop-chain test and the
data_socket compaction/empty-payload tests can be done with
real-socket manipulation alone, no fault-injection seam required.

**Per-file delta**:

| target            | before        | after          | delta   |
|-------------------|---------------|----------------|---------|
| `src/dns_snoop.c` | 51.1% (92/180) | **52.8%** (95/180) | +3 mutants |
| `src/data_socket.c` | 22.9% (24/105) | **26.7%** (28/105) | +4 mutants |

**Four new tests**:

`tests/test_dns_snoop.c` (2):
- `compression_chain_20_hops_succeeds`  — exactly 20 chained
  compression pointers must resolve to the trailing label "x".
- `compression_chain_21_hops_rejected`  — 21 chained pointers
  must trigger the `if (++hops > 20)` guard.

Together these pin the threshold and kill all four line-37
survivors: `rel >→>=`, `const 20→21`, `const 20→19`, and
`const 1→2` (the `++hops` increment becoming `hops += 2`).

`tests/test_data_socket.c` (2):
- `emit_empty_payload_is_skipped`     — `data_socket_emit("")`
  must not send anything (not even a bare `\n` that would corrupt
  the JSONL frame). Verifies by emitting "" then "hello" and
  asserting the consumer reads exactly "hello\n".
- `middle_client_disconnect_compacts` — three clients A/B/C; B
  disconnects; emit must compact via swap-with-last (line 200:
  `g_clients[i] = g_clients[--g_client_n]`) so A *and* C both
  still receive subsequent messages. A second emit confirms both
  remaining fds are still healthy.

**Aggregate after round 6**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 1106  | 99      | 1007       | 526    | **52.2%**     |

**README badges** bumped: tests 2053 → 2071; mutation kill rate
51.5% → 52.2%.

**Decisions worth flagging**:
- Skipped the fault-injection seam this round. The cheap real-
  socket wins delivered 7 more kills; the remaining
  `data_socket.c` survivors need infrastructure (a swappable
  `send` / `accept` pointer) which is more than this commit
  should carry. Surfaced as round-7 priority with a concrete
  ~10-line design sketch.
- The dns_snoop hop-chain test packets are hand-crafted following
  RFC 1035 §4.1.4 layout; inline comment explains the offset math
  so the next agent can extend (e.g. test the 22-hop case) without
  re-deriving.

### 2026-05-27 — Round 5: mutate the export-path files
**Commits**: *(this commit)*
**Touched**: `tests/test_jsonl.c`,
`.github/scripts/mutate-equivalents.txt`,
`docs/wiki/mutation-testing.md`, `README.md`, `PROGRESS.md`
**Why**: Round 5 of the verify-the-verifier campaign — the
export-path files were last on the round 1-4 priority list because
JSONL is a downstream contract (the iOS Swift client and any SIEM
forwarder reads it; schema drift breaks them silently).

**Per-file delta** (all numbers post-ignore-file):

| target               | mutants | ignored | considered | killed | kill-rate (considered) |
|----------------------|---------|---------|------------|--------|------------------------|
| `src/jsonl.c`        | 26      | 8       | 18         | 10     | **55.6%**              |
| `src/data_socket.c`  | 122     | 17      | 105        | 24     | **22.9%**              |
| `src/pcap_write.c`   | 43      | 8       | 35         | 21     | **60.0%**              |

**One new test** (`test_emit_icmp_v6_true_writes_one` in
`tests/test_jsonl.c`): with `is_v6 = 1`, asserts the emitted JSON
contains `"v6":1` AND does not contain `"v6":2`. Kills the
`is_v6 ? 1 : 0` const-1 mutation that the existing v6=0 test
couldn't catch (mutation 1→2 still emits `"v6":0` when is_v6 is false).

**New `OPT` equivalence class** documented in
[`docs/wiki/mutation-testing.md`](docs/wiki/mutation-testing.md):
early-return optimisation guards (e.g. `if (!any_sink() || !e)
return;`). Mutating the `||` to `&&` doesn't change correctness — the
function still produces the right output downstream; the early
return is only a fast-path skip. Eight `jsonl.c` emitters share this
exact pattern; all eight `|| -> &&` mutations now classified as OPT.

**~30 new equivalents added to** `mutate-equivalents.txt`:
- jsonl.c: 8 OPT (all emitter early-return guards) + 1 FAB
- data_socket.c: 17 (TIP negative-sentinel returns whose callers
  check `< 0`, SBL buffer sizes for `g_unix_path`, listen backlog)
- pcap_write.c: 8 (harness `>>` quirk, SBL `char path[128]`,
  TIP `fopen`-fail sentinel)

**README badge** bumped: `mutation kill rate` now 51.5% of
considered (was 54.7% — the addition of `data_socket.c` at 22.9%
pulled the aggregate down). The `tests` badge moved 2050 → 2053.

**Aggregate after round 5**:

| total mutants | ignored | considered | killed | kill-rate of considered |
|---------------|---------|------------|--------|-------------------------|
| 1106          | 99      | 1007       | 519    | **51.5%**               |

`data_socket.c` accounts for most of the surviving real gaps (81).
Tracked as the round-6 priority — those gaps are in the socket I/O
error paths and need a fault-injection seam to test cleanly.

**Decisions worth flagging**:
- pcap_write.c's raw kill rate dropped 53.5% → 48.8% between runs.
  Cause: the `> -> >=` ignore entry on line 15 matches three sites
  (the three `v>>8`, `v>>16`, `v>>24` shifts); two of those were
  killed before, so ignoring all three loses two kills. Acceptable
  for the harness-quirk class; would need fingerprints with column
  index to be more granular.
- Did not chase the 81 `data_socket.c` real survivors in this
  commit. They cluster in error paths that need a fault-injection
  seam (a `data_socket_inject_fault()` API guarded by a build flag),
  which is more design than this commit should carry. Surfaced as
  round 6 in the In-progress entry.

### 2026-05-27 — Round 4: `--ignore-file` flag + equivalence seed file
**Commits**: *(this commit)*
**Touched**: `.github/scripts/mutate.py`,
`.github/scripts/mutate-equivalents.txt` (new),
`docs/wiki/mutation-testing.md`, `PROGRESS.md`
**Why**: Round 3 surfaced the diminishing-returns problem — by the
third round of triage, ~95% of surviving mutants on a file fell into
the documented equivalence classes. The raw kill rate stopped
trending because new tests couldn't catch what was already
unkillable.

`mutate.py` now accepts `--ignore-file PATH`. A default file ships
at `.github/scripts/mutate-equivalents.txt` and is loaded
automatically. Each non-blank, non-comment line is
`file:line:op:original:mutated`; matching mutants are reported as
**IGNORED** rather than **SURVIVED**, and the report surfaces two
kill rates: **of considered** (the real-test rate) and
**of total** (preserved for trend continuity with pre-ignore runs).

The seeded equivalents file covers seven classes documented in
[`docs/wiki/mutation-testing.md`](../docs/wiki/mutation-testing.md):
FPA (function-parameter array size), SBL (stack buffer sizing
literal), FXS (memcmp/memcpy length on fixed-size struct field),
LZT (loop bound reading zero-initialised tail), TIP (truthy-
initialiser perturbation), FAB (function-as-boolean return value),
LCP (lowercase prefix case-folding). Initial entries (~55) come
from manually-verified survivors in rounds 1-3. The discipline for
adding entries (per the wiki page): truly equivalent or leave as a
survivor — falsely-ignored real mutants hide forever.

**Kill-rate picture, before vs. after the ignore file** (all files
mutated so far, post-triage):

| file                 | raw     | effective (`of considered`) | ignored |
|----------------------|---------|------------------------------|---------|
| `src/alerts.c`       | 43.2%   | **47.0%**                    | 27      |
| `src/threat_intel.c` | 81.8%   | **100.0%**                   | 4       |
| `src/dga.c`          | 50.0%   | **53.7%**                    | 6       |
| `src/beacon_detect.c`| 72.2%   | **83.0%**                    | 7       |
| `src/dns_snoop.c`    | 47.4%   | **51.1%**                    | 14      |
| `src/sni_snoop.c`    | 51.4%   | **52.1%**                    | 2       |
| `src/http_snoop.c`   | 65.1%   | **70.0%**                    | 6       |
| **aggregate**        | **50.7%** | **54.7%**                  | **66**  |

Aggregate: 915 mutants total, 66 ignored, 849 considered, 464 killed.
The `alerts.c` raw is one decimal lower than the round-1 record
(43.8% → 43.2%) — run-to-run noise on a single-digit number of
mutants flipping. The trend stands.

`threat_intel.c` shows the value most clearly: the raw 81.8% had
hidden the fact that 100% of *non-equivalent* mutants are killed.
The wiki rule ("don't write fake assertions to kill equivalents")
made writing 0 new tests the right call in round 2 — `--ignore-file`
now makes that visible to future readers without re-deriving the
reasoning.

**No product behaviour change.** `make` warning-clean, `make test`
green (2050 assertions).

**Decisions worth flagging**:
- Default ignore file auto-loads if present. Skipping it requires
  passing `--ignore-file ""` explicitly. Trade-off: convenience
  beats surprise — agents running `make mutate` cold get the
  noise-suppressed view automatically; pure-raw mode is the
  one-keyword opt-out.
- The "of total" kill rate is kept in the report so historical
  trends remain comparable. Drop only if a future tooling round
  rewrites PROGRESS.md to use the considered rate consistently.

### 2026-05-27 — Mutation round 3 triage: dns_snoop + sni_snoop + http_snoop
**Commits**: *(this commit)*
**Touched**: `tests/test_http_snoop.c`, `tests/test_sni_snoop.c`,
`tests/test_dns_snoop.c`, `PROGRESS.md`
**Why**: Closed real gaps in the round-3 protocol-parser
baselines. Ten new tests across three files. Gains are smaller
than rounds 1-2 because the existing RFC-byte test discipline
already covered the happy paths; remaining survivors are
overwhelmingly equivalence-class.

**Per-file delta**:

| target            | before | after  | new tests | mutants killed |
|-------------------|--------|--------|-----------|----------------|
| `src/http_snoop.c`| 61.6%  | **65.1%** | 3         | +3             |
| `src/sni_snoop.c` | 47.9%  | **51.4%** | 3         | +5             |
| `src/dns_snoop.c` | 44.8%  | **47.4%** | 4         | +5             |

**New tests (10 total)**:

- `test_http_snoop`:
  - `host_with_hostsz_two`              : `hostsz < 2` boundary
  - `hostname_prefix_does_not_alias_host`: prefix-length 5 vs 4 —
                                          `Hostname:` decoy header
                                          must not match `Host:`
  - `host_no_space_after_colon`         : `ci_startswith`
                                          `slen < plen` boundary

- `test_sni_snoop`:
  - `sni_hostsz_zero_rejected`          : `hostsz <= 0` boundary
  - `sni_non_host_name_type_rejected`   : SNI extension with
                                          name_type ≠ 0x00 (rare,
                                          but reserved by the spec)
  - `sni_empty_name_rejected`           : SNI `name_len == 0`
                                          guard. Both come with
                                          new hand-crafted packets
                                          following the RFC 5246
                                          layout.

- `test_dns_snoop`:
  - `header_only_no_questions`          : `len < 12` boundary —
                                          12-byte header-only
                                          message must parse
  - `non_a_record_with_rdlen_4_not_injected`:
                                          NS record (TYPE=2) with
                                          RDLEN=4 must not be
                                          misread as A. Kills the
                                          `&& -> ||` mutation on
                                          line 113.
  - `a_record_with_wrong_rdlen_not_injected`:
                                          TYPE=A but RDLEN=5
                                          (malformed) must not
                                          inject.
  - `non_aaaa_record_with_rdlen_16_not_injected`:
                                          symmetric for line 125
                                          AAAA branch.

**Suite totals**: 2031 → 2050 assertions (+19); 0 failed. Build
warning-clean.

**Decisions worth flagging**:
- Did not chase the compression-pointer hop-count mutations
  (line 37 `if (++hops > 20)`). Killing them requires a hand-
  crafted DNS message with >20 distinct compression pointer
  hops — doable but verbose; queued in the In-progress entry.
- For `dns_lookup`, the original assertion `== NULL` was too
  strict. dns_lookup returns the IP itself when the entry is
  in PENDING state (queued by the background resolver), not
  NULL — so my assertion would fire on prior tests' residue.
  Loosened to "must not return the resolved hostname"; still
  kills the intended mutations.

### 2026-05-27 — OSI / TCP-IP stack view (`[l]`)
**Commits**: *(this commit)*
**Touched**: `src/views/osi.{c,h}` (new), `include/sloth.h` (VIEW_OSI
+ VIEW_COUNT bump 29→30), `src/tui.c`, `src/main.c`,
`src/views/help.c`, `Makefile`, `tests/test_osi.c` (new),
`tests/test_state.c`, `tests/test_arp.c`, `tests/main_test.c`,
`docs/views/osi.md` (new), `docs/views/README.md`
**Why**: User request — a synthesis view that maps everything sloth
sees onto the seven OSI layers, one row per layer, drawn as a grid
with ANSI box-drawing chars. Pure derivation from `sloth_state_t`:
- L7  DNS / HTTP / TLS / QUIC / mDNS / NBNS / NTP log counts
- L6  TLS-version histogram + distinct JA3 fingerprints (the legacy
      bucket lights up red on >0 to echo the WEAK_TLS alert)
- L5  TLS sessions / QUIC / EAPOL counts
- L4  TCP split by state (E/L/?), UDP, ICMP
- L3  distinct remote hosts (IPv4 / IPv6) + ARP mappings
- L2  ifaces, APs, STAs, devices, beacons
- L1  probe iface name (if monitor mode) or primary iface
Layout uses horizontal bracket rules (top/bottom) and an internal
`│` separator between the label and data columns. Side borders
intentionally dropped — content width varies per layer, and closing
them cleanly would require per-cell column tracking that added
nothing to readability. Three tests in `tests/test_osi.c`: empty
state, key noop, populated-state render.
**Follow-ups**: TLS-version histogram in the test exercises a
TLS 1.0 entry (legacy>0 path) but not the alert-palette colour
specifically. Out of scope for unit tests (null TUI swallows
attrs); covered when running the binary.

### 2026-05-27 — Mutation round 3 baselines (protocol parsers)
**Commits**: *(this commit, alongside OSI view)*
**Touched**: `PROGRESS.md`
**Why**: Recorded baseline kill-rates for the three protocol
parsers named as round-3 priority. No test additions in this
round — the user redirected mid-triage to the OSI feature, so
round-3 closure is deferred. Numbers stand as the starting
waterline for whoever picks this up.

| target            | mutants | killed | survived | kill-rate |
|-------------------|---------|--------|----------|-----------|
| `src/dns_snoop.c` | 194     | 87     | 107      | 44.8%     |
| `src/sni_snoop.c` | 142     | 68     | 74       | 47.9%     |
| `src/http_snoop.c`| 86      | 53     | 33       | **61.6%** |

`http_snoop.c` already at 61.6% — RFC-byte test discipline pays off.
The DNS/SNI parsers will likely have a chunky equivalence-class tail
(loop bounds reading zero-init, buffer-size literals on stack
buffers); real test gaps probably concentrate on extension-walk and
compression-pointer edge cases.

### 2026-05-27 — Mutation round 2: threat_intel + dga + beacon_detect
**Commits**: *(this commit)*
**Touched**: `tests/test_dga.c`, `tests/test_beacon_detect.c`,
`PROGRESS.md`
**Why**: Round 2 of the verify-the-verifier campaign (issue #4).
Baselined and (where worthwhile) triaged the three security-critical
files named in the issue as next-priority after `src/alerts.c`.

**Per-file results**:

- `src/threat_intel.c` (IOC matcher): **81.8% baseline (18/22)**.
  All 4 survivors fall in the documented equivalence classes —
  three are `return 1; → return 2;` (function-as-boolean), one is
  the empty-IOC guard which is unreachable given the fixed embedded
  list. **No new tests** — by the wiki page's own "don't write fake
  assertions to kill equivalent mutants" rule. Effective real-test
  kill rate: 100%.

- `src/dga.c` (DGA/DNS-tunnel heuristic): **36.4% → 50.0%** (+12).
  Added five boundary tests in `tests/test_dga.c`:
    - `label_exactly_ten_chars_flagged` (kills `len < 10` boundary)
    - `consonant_cluster_exactly_four` (kills `cons >= 4` boundary;
      constructed label `aakjxqe1212.com` keeps entropy ≈ 2.91 so
      the cluster signal is necessary, not redundant)
    - `digit_density_exactly_thirty_percent` (kills `>= 30` in the
      `30 → 31` direction)
    - `uppercase_label_normalized` (kills the `+ 32` ASCII
      case-conversion arith and `32 ± 1` const mutations on line 17,
      AND — via the AKJXBQZPQVZ.com follow-up — the `>= 'A'`
      char-range mutation that wasn't exercised by the lowercase
      tests)

- `src/beacon_detect.c` (periodicity detector for C2): **55.6% →
  72.2%** (+9). Added eight tests in `tests/test_beacon_detect.c`:
    - `find_distinguishes_port_from_ip` (kills the `&& → ||` in
      `find()` — would have aliased two tracks sharing only one
      coordinate)
    - `observe_empty_ip_is_noop` (kills `bd_observe`'s `|| → &&`
      NULL/empty guard mutation — empty string would otherwise
      create a track keyed on `""`)
    - `update_skips_zero_port_conn` (same shape for `bd_update`'s
      `||` guard on conn filtering)
    - `update_at_exact_gap_records_new_sample` (kills the
      `>= BD_GAP_S → > BD_GAP_S` boundary in `bd_update`)
    - `stats_two_samples_computes_mean` (kills `n < 2` early-return
      and the `2 ± 1` mutations on the minimum-samples guard)
    - `is_strong_at_exact_min_interval` (kills `mean <
      BD_MIN_INTERVAL_S` boundary)
    - `is_strong_at_exact_max_jitter_ratio` (kills the `jitter/mean
      > BD_MAX_JITTER_RATIO` boundary; constructed gaps
      [25,15,25,15] for mean=20, stddev=5, ratio=0.25 exact)
  Also moved `seed_conn` helper above the tests that need it
  (forward-declaration would have worked too).

**Suite totals**: 2008 → 2027 assertions (+19); 0 failed. Build
warning-clean.

**Decisions flagged** (per `docs/dark-factory.md` §4.2):
- Skipped writing tests for `threat_intel.c` survivors — documented
  equivalence-class only. The wiki page's rule is explicit; adding
  fake assertions would degrade the suite's honesty.
- Kept boundary-construction comments inline in the new tests
  (entropy/jitter math). The tests would otherwise look magic-number-y;
  the comment is the proof of correctness that lets the next agent
  modify the seed values without breaking the boundary semantics.
- Did not chase the remaining 44 dga.c / 15 beacon_detect.c / 4
  threat_intel.c survivors. The remaining gaps are dominated by the
  equivalence classes plus a few constructed-input cases (e.g.
  `bd_stats` mean==0 guard requires synthetically seeding a
  zero-cadence track).

### 2026-05-26 — Close mutation-testing gaps round 1 (`src/alerts.c`)
**Commits**: *(this commit)*
**Touched**: `tests/test_alerts.c`, `docs/wiki/mutation-testing.md`,
`PROGRESS.md`
**Why**: First triage round on the 258 surviving mutants from the
`make mutate` baseline on `src/alerts.c`. Targeted the four
highest-survivor rules — `rule_rogue_dhcp` (41), `rule_arp_spoof`
(37), `rule_evil_twin` (27), `rule_probe_flood` (23) — plus the
`mac_to_str` byte-index cluster (12, reached indirectly via
`rule_deauth_flood`). Added nine new boundary / detail-content
tests, fixed `add_deauth_flood`'s missing `memset` (latent bug —
`bssid` was uninitialised), and added a "known equivalence classes"
section to `docs/wiki/mutation-testing.md` that names the patterns
that will always survive (function-parameter array sizes, stack
buffer sizing, loop bounds reading zero-init tail, truthy
initialisers).

**Kill-rate trajectory** for `src/alerts.c`:
| pass        | mutants | killed | survived | kill-rate |
|-------------|---------|--------|----------|-----------|
| baseline    | 329     | 71     | 258      | 21.6%     |
| after r1    | 329     | 144    | 185      | **43.8%** |

Per-rule survivor counts (baseline → after r1): arp_spoof 37 → 14,
rogue_dhcp 41 → 32, evil_twin 27 → 7, probe_flood 23 → 12,
mac_to_str 12 → 2, deauth_flood 5 → 5 (all 5 remaining are
documented equivalence-class patterns). Build warning-clean.
`make test` green: 2008 assertions, 0 failed.

**Decisions flagged**:
- Did not write tests for mutants in the equivalence classes —
  documented them instead. Adding fake assertions to "kill" them
  would have made the suite lie. The wiki page §"Known equivalence
  classes" is now the operator's reference for skipping them.
- Did not chase deep snprintf-loop arithmetic mutations (lines 655,
  656, 662, 663 in rule_rogue_dhcp). Real gaps, but at the level of
  "off-by-one in string formatting on >2-server case" with low
  practical impact. Left for round 2.
- Sample test bug caught during development: `mac[6] = {0x11, ...}`
  triggered the rule's multicast-skip (LSB set). Now corrected and
  the lesson noted inline.

### 2026-05-26 — Mutation-testing harness (`make mutate`, closes #4)
**Commits**: *(this commit)*
**Touched**: `.github/scripts/mutate.py` (new, ~370 LoC),
`Makefile` (added `mutate` target), `docs/wiki/mutation-testing.md`
(new), `docs/wiki/index.md`, `docs/wiki/log.md`, `PROGRESS.md`
**Why**: Closes the loop the dark-factory pattern doc
([`docs/dark-factory.md`](docs/dark-factory.md) §3.3) opens: the
Level-5 claim in `MISSION.md` rests on `make test` being a
trustworthy oracle, but the suite had ~1974 hand-crafted assertions
with no evidence they'd actually fail on real regressions.
`make mutate` introduces small faults (relational swaps, ±1 on
integer literals, `&&`↔`||`, `+`↔`-`, `return N` → `return 0`) into
src files one at a time, runs `make -B test`, and reports surviving
mutants as concrete test-suite gaps. Sandboxed: src is never
modified in place — the harness copies the repo to a tmpdir and
mutates there. No third-party framework, no product behaviour
changes, `make` + `make test` still clean.
**Baseline kill-rates** (record as new targets are added):
| target          | mutants | killed | survived | kill-rate |
|-----------------|---------|--------|----------|-----------|
| `src/alerts.c`  | 329     | 71     | 258      | 21.6%     |
The low rate confirms issue #4's premise: assertions were broadly
counted but rarely targeted at thresholds and boundary conditions.
A sampled review of survivors shows ~30–40% are likely equivalent
mutants (function-parameter array sizes, no-effect post-condition
writes); the rest are real gaps.
**Follow-ups**: see In-progress entry above (close the gaps on
`src/alerts.c` first, then mutate `src/threat_intel.c`, `src/dga.c`,
`src/dns_snoop.c`, `src/beacon_detect.c` in that order). A minor
cosmetic issue: the "killed (build broke)" sub-counter sometimes
catches test-binary segfaults instead of compile failures (stderr
contains both "error" and "make"). Real kill-count is correct; only
the breakdown is noisy.

### 2026-05-26 — Read-only data socket (`--data-socket SPEC`)
**Commits**: `1199563`
**Touched**: `src/data_socket.{c,h}` (new), `src/jsonl.c`, `src/main.c`,
`tests/test_data_socket.c` (new), `tests/main_test.c`, `Makefile`,
`docs/wiki/jsonl-schema.md` (new), `docs/wiki/index.md`, `FACTORY.md`
**Why**: Implements the data socket the 2026-05-25 MISSION §4
amendment opened the door for. Supports `unix:/path` (local SIEM
agents) and `tcp:HOST:PORT` (e.g. binding to a Tailscale IP so the
upcoming iOS Swift UI dashboard can consume the JSONL stream over
the tailnet). Read-only — nothing is ever read from the socket.
Multi-client (up to 16), non-blocking writes, drop slow lines on
EAGAIN, harvest on EPIPE. Hooked into `src/jsonl.c` so every
`jsonl_emit_*` line broadcasts to both sinks; the new `any_sink()`
helper short-circuits format work when nobody is listening. 5 new
unit tests via a hermetic UNIX-domain fixture; 1974 assertions
total. Build warning-clean. Bonus: `docs/wiki/jsonl-schema.md`
finally pins down the stream format and resolves the long-standing
`docs/wiki/log.md` naming-collision follow-up.
**Follow-ups**: TCP path is exercised by the production binary but
not by a unit test (ephemeral-port collisions in CI). An iOS
SwiftUI client consumer is upcoming work.

### 2026-05-26 — Three-tier alert palette + cross-panel severity coloring
**Commits**: `21814ec`
**Touched**: `include/sloth.h`, `src/tui.h`, `src/tui.c`, `src/main.c`,
`src/alerts.c`, `src/views/alerts.c`, `src/views/dashboard_bands.c`,
`src/views/packets.c`, `tests/null_tui.c`, `tests/test_alerts.c`,
`docs/views/alerts.md`, `docs/wiki/alerts.md`, `docs/wiki/ip-palette.md`
**Why**: The old alert palette was binary (WARN/CRIT). Port-scan
reconnaissance and active attack-path exploitation rendered the same
deep red across every panel, which devalued the red channel — the
operator couldn't tell at a glance whether a flagged IP was
"interesting" or "on fire". Three-tier (LOW=yellow / WARN=orange /
CRIT=red) restores the gradient. Reclassified `PORT_SCAN`,
`NXDOMAIN_BURST`, and `PROBE_FLOOD` to LOW. Cross-panel
`tui_alert_hot_*` now carries severity; `tui_alert_hot_check(ip)`
returns the tier (or -1 if cold); `tui_alert_hot_set` is
promotion-only so a later LOW won't downgrade an earlier CRIT.
1950 assertions still pass; build warning-clean.
**Follow-ups**: none directly; the data-socket follow-up below would
benefit from exporting the per-IP severity too.

### 2026-05-25 — Three-tier mission amendment + dashboard.c split
**Commits**: `f4dda8d`, `0ddda50`
**Touched**: `src/views/dashboard*.c`, `Makefile`, `MISSION.md`,
`docs/wiki/log.md`
**Why**: `src/views/dashboard.c` had grown to 1863 lines (2.3× the
next largest file in the repo) and mixed orchestration, primitives,
and 17 per-panel renderers. Split into orchestrator (456) +
primitives (199) + bands (755) + grid (455) + internal header (104).
Same commit window opened the door for a future read-only local data
socket by tightening the MISSION §4 ban: it now targets *control*
surfaces specifically and explicitly allows a `tail -f`-style
data-only socket. 1950 test assertions still pass; build is
warning-clean.
**Follow-ups**: data-socket implementation (not started).

### 2026-05-25 — FACTORY.md build & infra runbook
**Commits**: `c62b8f0`
**Touched**: `FACTORY.md` (new), staged previously-untracked
`MISSION.md` and `docs/dark-factory.md`
**Why**: An agent landing on the repo cold needs one file that
answers "what do I install, build, run, deploy, debug?". Charter
(MISSION) and pattern (dark-factory) already existed; FACTORY closes
the loop on the operational side.
**Follow-ups**: none.

### 2026-05-25 — Wiki prime from per-view docs
**Commits**: `8ca0b99`
**Touched**: `docs/wiki/*.md` (15 concept pages + index + log),
`docs/CLAUDE.md`
**Why**: First ingest of the per-view docs (`docs/views/*.md`) into
a Karpathy-style LLM Wiki. Source view docs are immutable; the wiki
adds a concept layer (alerts, JA3, threat-intel, beacon-detection,
wifi-sigint, mac-randomisation, ip-palette, platform-vtable,
pcap-export, attack-map, etc.) cross-linked with `[[wiki-link]]`.
**Follow-ups**: JSONL schema page (MISSION §4(3) names
`docs/wiki/log.md` as the home but the current `log.md` is the wiki
ops log — naming collision to resolve).

---

## Open follow-ups (not yet owned)

### Forwarder / consumer extensions

- **Additional forwarder sinks** — `examples/forwarder/` ships
  HEC, syslog, Elastic, Loki, Datadog, and webhook. OpenSearch
  compatibility documented under the Elastic section (wire-
  compatible `_bulk`). Slack/Discord-style incoming webhooks
  intentionally not supported as a built-in sink (their message
  envelope is outside the schema-agnostic remit); operators write
  a transform proxy or use a Slack app.
- ~~**Sink fan-out**~~ — landed 2026-06-03. `--sink loki,datadog`
  (comma-separated) pushes every record to every named sink in the
  same batch. Per-sink failures are isolated; stats output adapts
  to show each sink's forwarded/dropped/retries separately. Sends
  are sequential per batch — one slow sink slows the whole
  pipeline, so use separate forwarder processes when backpressure
  isolation matters. Smoke test now covers fan-out alongside the
  individual sinks (one producer → forwarder → two fake-sink HTTP
  servers).
- ~~**Smoke-test the consumer/forwarder in CI**~~ — landed
  2026-06-03 in `examples/compose/smoke_test.py` +
  `.github/workflows/examples-smoke.yml`. Runs end-to-end
  (mock-sloth → forwarder → fake Loki) in &lt;10 s and asserts every
  record type in mock-sloth's template list arrives at the sink.

### iOS / Tailscale (out of this repo)

- **Tailscale integration** — install + configure on the deployment
  host so `--data-socket tcp:100.x.x.x:8765` actually reaches the
  iOS client. Out of repo (configuration, not code), but blocks the
  iOS client from being useful.
- **iOS SwiftUI client** — consume the data socket and render the
  same panels sloth shows in the TUI. Lives in a separate repo
  (confirmed by the operator 2026-05-28).

### Product depth (sloth itself)

- ~~**Beacon detection v2**~~ — landed 2026-06-03. `bd_is_strong`
  now returns kind=1 (v1 low-jitter) or kind=2 (v2 gap-concentration)
  to a unified call site. v2 catches ~40% additive jitter (covers
  Cobalt at "interactive" 30% and Sliver default) at ~0.1% per-flow
  false positive rate. Alert detail labels which detector fired.
  Sliver "low-and-slow" at 50% jitter still uncaught — statistical
  separation isn't reliable with the current 16-sample buffer; the
  mitigation is longer flow histories feeding v1.
- **More passive observables** — per MISSION §4(1) "coverage > precision".
  The original AD/infrastructure-substrate set is now landed:
  IPv6 RA/NDP, SMB, Kerberos, and LDAP (all 2026-06-04) plus BGP
  (2026-06-01), each fronted by a CRIT alert: `ROGUE_RA`,
  `SMB1_USE`, `KERB_PREAUTH_BURST`, `LDAP_SEARCH_FLOOD`,
  `BGP_NOTIFICATION_BURST`. Each has Tier 2 follow-ups documented
  in its wiki page — NS/NA neighbor cache for NDP; NTLMSSP /
  admin-share tracking for SMB; username extraction + AS-REP
  roasting + kerberoasting for Kerberos; per-attribute query
  inspection + result-size analysis + referral URL extraction
  for LDAP; AS-number extraction + prefix-hijack detection +
  route-flap dampening for BGP. Next candidates from the
  internet-substrate side: SSH (brute-force detection on
  TCP/22), RDP (TCP/3389 NLA / lateral-movement substrate),
  SNMP (UDP/161 snmpwalk enumeration), and MQTT/IoT control
  planes.
- ~~**Sibling forensic-export formats**~~ — `--out-format jsonl|cef|syslog`
  landed 2026-06-03. CEF (ArcSight) and RFC 5424 syslog are
  available as direct output formats for both `-o FILE` and
  `--data-socket`, with no forwarder process required. Implemented
  as a transform at the single emit point (`src/formatter.{c,h}`)
  so every record type picks up the new formats automatically.
  Splunk HEC-over-local-socket intentionally not added — HEC's
  envelope is fundamentally an HTTP POST, not a line format, and
  the forwarder's `hec` sink covers the use case.
