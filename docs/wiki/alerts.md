---
name: alerts
description: Alert engine internals — dedup-by-key ring, the rule set (one rule per ALERT_TYPE_*), severity levels, per-alert pcap hook
type: reference
---

# Alerts

**Summary**: A small dedup-by-key ring runs every poll. Each rule scans current state, builds a stable key, and either bumps an existing alert or appends a fresh one. New keys get a JSONL `alert` line and (when `--pcap-dir` is set) a per-alert pcap dump. Everything that happens to an alert *after* creation — escalation, changed evidence, expiry — rides the `alert.*` incident-lifecycle records added in #98.

**Sources**: `docs/views/alerts.md`, `docs/views/dns.md`, `docs/views/connections.md`, `docs/views/deauth.md`.

**Last updated**: 2026-10-23 (#148: `BEACONING` capped at `bd.max_findings` per-destination findings plus one `beacon-overflow` finding).
**Last updated**: 2026-10-21 (#144 slice 4: `BLE_ADV_FLOOD`, `BLE_HID_UNEXPECTED`, `BLE_WATCHLIST`; #144 slice 2: `BT_OWN_TRANSMIT`, the Bluetooth host's own transmissions).
**Last updated**: 2026-10-20 (#101 slice A: `COUNTRY_ABSENT`, `DFS_MASKING`; #82: the two Pixie-Dust rules).
**Last updated**: 2026-10-20 (#106 slice B: `CAM_RTSP_UNAUTH`, anonymous RTSP DESCRIBE).

---

## Engine

- Files: `src/alerts/` (#118). `engine.c` is the engine — the
  incident ring, `fire()` and its variants, eviction, the side table,
  the tainted-BSSID tracker, snapshot, per-alert pcap export and
  `alerts_update()`. The rules live by domain:

  | File | Rules |
  |---|---|
  | `rules_wired.c` | IP side: scans, the DNS family, threat intel, ARP and rogue DHCP/RA, protocol brute force, cleartext credentials, weak TLS, HTTP attack signatures, ICMP tunnelling, beaconing, camera WS-Discovery and cloud SNI |
  | `rules_wifi_mgmt.c` | 802.11 management/control plane and the sensor's radio: the floods, BTM, CSA, RRM, RTS, SA Query, MFP, Block Ack, malformed management frames, probe floods, recon, transit, unknown devices, RF degradation, no monitor radio, PM forgery, queue release, TPC |
  | `rules_twin.c` | impersonation: the evil-twin family, SSID confusion, KARMA, open/camera setup SSIDs, captive portal, WPA downgrade, SAE, FragAttacks — and the pair scoring the Twins view shares |
  | `rules_enterprise.c` | rogue RADIUS, PEAP without a server certificate, the three WPS verdicts |
  | `rules_mle.c` | the 802.11be Multi-Link Element rules: five keyed by MLD MAC, two by BSSID (#104) |

  `src/alerts.h` is the public API and did not change.
- **Rule order is a table (#118).** `alerts_update()` derives the
  Wi-Fi posture (`wifi_downgrade_update()`), then runs
  `g_alert_rules[]` from `src/alerts/rules_table.c` in order. The
  order is the one the hand-written call sequence had, copied verbatim,
  and it is load-bearing: JSONL events within one tick reach the stream
  in this order; `rule_evil_twin_attack_chain` taints the rogue half of
  a pair and `rule_evil_twin`, earlier in the table, reads that taint
  on the next tick; `rule_deauth_flood` runs before the chain rule
  whose finding cites the flood. `tests/test_alert_rules.c` pins those
  pairs by name and fails if a rule defined under `src/alerts/` is
  missing from the table or listed twice.
- **Frame citations (#92).** The no-IP wireless rules whose triggering
  frames are monitor frames hand the alert the evidence-ring IDs of
  those frames (`fire_ev()`, or `fire_inv()` when the rule also reports
  a confidence), and the JSONL records carry them as `evidence_id_N`.
  Which rules, and what each cites, is [[pcap-export]] § Which alerts
  cite frames. The beacon-sourced ones (`BEACON_FLOOD`, `EVIL_TWIN`,
  `KARMA_AP`) read small rings on the AP record itself
  (`beacon_ap_t.ev_ids`, `ssid_history_ev`), filled by
  `beacon_record_ev()`.
- Dedup key examples: `scan:<ip>`, `threat-d:<domain>`, `threat-ip:<ip>:<port>`.
- New-key path: JSONL `alert` line + `alert.create` + (optional) pcap
  dump of the matching packets via `src/alert_pcap.c`. See
  [[pcap-export]].
- `c` clears all alerts and resets dedup state; future hits re-arm.
  Every open incident is resolved with `reason: "cleared"` first.
- **Key lookup is hash-first (#112).** Each slot's key has a 64-bit
  FNV-1a beside it, so a non-matching slot costs one integer compare;
  `strcmp` still decides, so a hash collision cannot merge two
  findings. A key is looked up exactly as it is stored (truncated to
  `ALERT_KEY_LEN - 1`), so an over-long key dedupes instead of opening
  a new incident every tick.
- **Incident side state (#112).** A new incident memsets its slot,
  which is right for the incident's own counters and id and wrong for
  what belongs to the key. A bounded LRU side table (512 keys, 4x
  `MAX_ALERTS`) keeps, per key: the last real pcap export time and path
  (the cooldown, formerly `pcap_cool[]`), `pcap_write_failures`,
  `reopen_count`, and the last incident's `first_seen`. `first_seen` is
  restored **only** when the previous incident was closed by eviction —
  the engine ran out of room, the finding did not end — so the `--db`
  row keyed on `(key, first_seen)` stays one row across evict→refire
  churn. After an `expired` resolve the re-fire is a new episode with
  its own `first_seen`. The side table bounds memory, not cardinality:
  per-type fair eviction (below) still decides which findings hold
  slots. Dropping a row that held an export is tallied as
  `evict_pcap_cooldown` on the `sensor_health` record, as before.

## Dedup key shapes (#112)

A dedup key decides what is one finding. Rules that put a
remote-chosen string into their key — an SSID, a hostname, a queried
name, a username — used to bound it with a `printf` precision
(`ssidconf:%.30s:%s`), and a precision **merges**: two SSIDs sharing a
30-byte prefix became one incident and whichever fired last wrote the
detail. Those rules now build keys with the typed builder in
`src/alert_key.h`:

| Component | Renders as |
|-----------|-----------|
| MAC | `aa:bb:cc:dd:ee:ff` |
| IP | `192.0.2.7`, or `[2001:db8::1]` (bracketed so its colons are not separators). Anything not address-shaped is keyed as a remote string kept to 24 bytes |
| number | decimal |
| token | one of sloth's own literals (`FTP`, `HTTP-Basic`) |
| hex | lowercase hex of raw bytes (a WPS UUID-E, all 16 bytes) |
| remote string | up to *keep* bytes with `:` `,` `[` `]` and non-printables mapped to `_`, then `:` and the 16-hex FNV-1a of the **full** string |
| set | `<count>:<16-hex FNV-1a>` of the sorted members, so the order they were seen in does not matter |

Components are joined with `:`. The readable prefix is for a human
grepping the stream; identity is the hash. A key that would not fit
`ALERT_KEY_LEN` is a programming error — every migrated rule's worst
case is pinned by a test — and yields `""`, which the engine refuses,
so the failure mode is a missed alert, never a merged one.

**Scope.** The builder bounds key **length** and removes truncation
merges. It does not bound **cardinality**: a remote side choosing a
thousand SSIDs still makes a thousand keys, and that stays with
per-type fair eviction (below), measured by `evict_alert`.

**Contract change.** Key strings changed for the rules below. A
consumer matching `key` text (the `alert` record and every `alert.*`
event) sees the new shape from #112 on; `incident_id` remains the join
key between records and is unaffected. The `--db` `alerts` table is
unchanged — keys are stored as text, so a database spanning the upgrade
holds both shapes for one finding.

| Rule | Before | After |
|------|--------|-------|
| `DGA_DOMAIN` | `dga:<qname>` | `dga:<qname, 40 kept>:<hash>` |
| `CLEARTEXT_CRED` | `cred:<src>-><dst>:<port>:<proto>:<user>` | `cred:<src>:<dst>:<port>:<proto>:<user, 32 kept>:<hash>` (IPv6 bracketed) |
| `CAPTIVE_PORTAL` | `portal:<host, 30 cut>:<kind>` | `portal:<host, 40 kept>:<hash>:<kind>` |
| `SAE_PSK_SPLIT` | `saesplit:<ssid>` | `saesplit:<ssid, 32 kept>:<hash>` |
| `SSID_CONFUSION` | `ssidconf:<ssid, 30 cut>:<weak bssid>` | `ssidconf:<ssid, 32 kept>:<hash>:<weak bssid>` |
| `EVIL_TWIN` (attack chain) | `twin-chain:<ssid>` | `twin-chain:<ssid, 32 kept>:<hash>` |
| `ROGUE_DHCP` | `rogue_dhcp:<ip>,<ip>,...` (cut at 191 bytes) | `rogue_dhcp:<server count>:<hash of the sorted set>` |
| `WPS_PIN_BRUTE` (rotating MAC) | `wpsbrute-uuid:<bssid>:<first 8 UUID-E bytes>` | `wpsbrute-uuid:<bssid>:<all 16 UUID-E bytes, hex>` |
| `BEACONING` | `beacon:<ip, 39 cut>:<port>` | `beacon:<ip>:<port>` (IPv6 bracketed, never cut). Unchanged by #148, which adds the one fixed key `beacon-overflow` and keys an IPv4-mapped peer (`::ffff:a.b.c.d`) as its IPv4 address |

## BEACONING cap (#148)

Owner ruling 2026-10-23. `BEACONING` is one finding per strong
(destination, port) track — each C2 candidate its own incident, its
`match_ip`/`match_port` the destination so [[pcap-export]] captures that
flow — but at most `bd.max_findings` (default 16, `--tune`, 1..64) are
open. The rest are **one** finding of the same type keyed
`beacon-overflow`, whose detail counts them (K) and names the next four
strongest; it has no `match_ip`, opens while K > 0 and resolves with
`reason` `drained` when K returns to 0. Seats go to the strongest
tracks (v1 before v2, then jitter/mean or concentration, then samples)
and change hands only when a challenger wins by a margin — 0.05
jitter/mean, 0.10 concentration — so two near-equal tracks never flap;
the displaced finding resolves with `reason` `displaced` and the track,
while it is still strong, joins K. A holder that stopped being strong yields to any strong
challenger.

Why: 128 detector tracks against 128 engine slots meant one busy
segment could want the whole engine, and fair eviction only moved the
damage onto `BEACONING`'s own churn. Coalescing per source host was
tried and rejected — tracks come only from the sensor's own socket
table, so "per source" was one row aimed at the sensor itself. Full
reasoning, the choice of 16 and of a margin over a delay:
`docs/views/alerts.md` § BEACONING cap (#148). See also
[[beacon-detection]].

## Incident lifecycle (#98)

One continuous run of a dedup key is an **incident**: it opens with
`alert.create`, carries one `incident_id` through every
`alert.escalate` / `alert.update`, and closes with exactly one
`alert.resolve`. Before #98 only the create was visible downstream — a
WARN→CRIT escalation updated the ring in place and emitted nothing.

- **Material change only.** Any severity move emits (never throttled);
  a changed `detail` emits at most once per `ALERT_UPDATE_MIN_S` (60 s).
  An evaluation that re-renders identical evidence emits nothing, so a
  retained condition held across 100 polls is one create and silence.
- **Resolve** after `ALERT_RESOLVE_AFTER_S` (300 s) in which no rule
  re-asserted the key — the last *evaluation*, not the last
  observation. Reasons: `expired`, `evicted`, `cleared`. A key that
  fires again afterwards opens a new incident with a new id.
- **Counters.** `count` / `evaluations` are rule ticks;
  `observations` only moves when the evidence does. Timestamps split
  the same way (`first_detected` / `last_evaluated` vs
  `first_observed` / `last_observed`).
- Durations run on `CLOCK_MONOTONIC` via the clock seam
  (`src/sloth_clock.c`, #109; the only libc clock reader in `src/`);
  exported timestamps stay wall clock. The evil-twin taint TTL
  (`EVIL_TWIN_TAINT_TTL_SECS`) is stamped and aged by that same wall
  clock — before #109 the check read libc directly, so an injected
  clock never matched and an NTP step mis-aged it.
- **Eviction is fair between rules (#96).** The ring holds `MAX_ALERTS`
  (128) entries for every rule together. Resolved incidents go first;
  among live ones the victim is the oldest entry of the type holding the
  **most** slots, not the oldest entry overall. Globally-oldest let one
  unbounded rule fill the ring and then discard every other rule's
  findings — the same bug three times (#105, #107, #96) — so the rule is
  now in the engine rather than in each detector. It is not a quota: a
  rule may use all 128 slots unopposed and yields one as soon as another
  rule fires. Detail: `docs/views/alerts.md`.

Wire format and the full field table: [[jsonl-schema]].

## Severity vs confidence (#89)

Severity answers *how bad is this if it is real*. **Confidence** answers
*how likely is it to be real*. They are separate fields on the alert and
they move independently: a CRIT at 20 % and a WARN at 25 % are both
meaningful findings and neither one dominates the other.

Most rules omit confidence. They assert a condition they observed
directly — a flood counted, a cleartext credential seen — and have
nothing to qualify. Rules that *infer* from circumstantial RF report
both numbers: `EVIL_TWIN` is the first, reported as **suspected
impersonation** with a percentage rather than as an established fact;
`KARMA_AP` is the second (#90) — a bare SSID-count candidate is WARN,
uncorroborated, and escalates to CRIT only when a PNL match on **one**
station, a shared-victim deauth-then-lure chain, or a verified tool
signature match ties the pattern to that specific BSSID rather than
coincidence. The PNL escalator wants at least `KARMA_PNL_CORROB_MIN`
= 2 of the advertised SSIDs in a *single* station's list: PineAP
Beacon Response answers one station's probes for its whole remembered
list, whereas the union over every nearby client is a description of
the neighbourhood. The union is still reported and still feeds the
`[y]` view's Jaccard column; it stopped being the gate because one
common SSID in one passer-by's list made a benign multi-VAP AP page
as an active lure.

Collapsing the two axes is what let an uncorroborated same-SSID
coincidence page at the same volume as an observed attack, and it pushed
the detector toward suppressing weak candidates outright to keep the
noise down. Splitting them means a weak candidate can be *shown as
weak* instead of being hidden.

### Nothing observed over the air is a trust anchor

`EVIL_TWIN`'s same-security branch used to drop a pair outright on two
grounds, and #89 removed both:

- **A matching vendor OUI.** Three bytes of a frame the attacker writes.
  Every rogue-AP tool can set them to the target's prefix.
- **An 802.11k neighbour report from either side.** An unauthenticated
  management frame. An attacker advertises the AP it is impersonating
  and the finding disappeared — the suppression handed the adversary an
  off switch.

Both are now weighted context that lowers confidence, and a neighbour
claim may demote a severity resting only on soft signals — never one
backed by a hard signal (attacker-tool OUI, a BTM steer at the pair), or
naming your target becomes a severity lever.

What replaces them is a requirement for **positive evidence**: with none,
the rule is silent. A legitimate single-vendor multi-BSSID deployment
stays quiet because there is nothing to report, not because an observed
value was read as proof of ownership. The same reasoning removed RSSI as
the tie-breaker for *which* half of a pair is the impostor — see
[`docs/views/twins.md`](../views/twins.md).

### ...except the one the operator wrote down

Slice 2 of #89 added the anchor that leaves: the **approved inventory**
(`--inventory`, full page at [[inventory]]). It is the only trust input
in this family that does not arrive over the air, so it is the only one
allowed to settle a pair either way:

- a BSSID that is **not** approved for an SSID the file declares is
  `+50` positive evidence and **hard** — which is what keeps a spoofed
  neighbour claim from erasing it, and what makes the same-OUI clone in
  this issue's regression list visible at all;
- a pair whose **both** halves are approved is not a candidate, whatever
  the radios look like to each other. That is the mixed-vendor
  deployment case, where a differing OUI and contradicting vendor-IE
  hashes are the strongest observed signals here and both are simply
  wrong.

That second one is a sole suppressor, deliberately. It is not the
pre-#89 behaviour renamed: what #89 removed were suppressors sourced
from *frames the attacker writes*. The test is not "does anything
suppress" but "can the adversary reach the input". With no inventory
configured nothing above applies and the heuristics are exactly as
slice 1 left them — an operator who never writes a file must not
silently lose detection.

### Corroboration before intent (#94)

The same doctrine reaches the rules whose *finding is about a person's
behaviour* rather than a protocol state. `MY_NET_RECON` is the case an
external CISO/GRC review raised: it fires when a client's PNL names a
designated SSID and no association to that network was observed, and
that precondition is satisfied by at least four innocent situations —
a returning employee, a device roaming the operator's own APs, a capture
that never saw the association, and a handset probing with a rotating
address while associated under its per-network one.

Calling that *reconnaissance* names an intent the evidence does not
carry. Since #94:

- **Uncorroborated it is LOW at 25 % confidence**, and the detail
  reports the observation (`probed for designated network …
  uncorroborated, benign explanations include a returning device or an
  unobserved association`). The word *reconnaissance* does not appear.
- **WARN and the reconnaissance framing require positive
  corroboration** — sustained probing (≥ 600 s span and ≥ 20 probes) or
  a PNL naming two or more designated networks. The detail names which
  corroborator fired, so the operator weighs the evidence rather than
  the label.
- Two things deliberately **do not** corroborate. A randomised MAC is
  default behaviour on every current handset, so it describes the phone
  population. And the *absence* of an observed association is not
  evidence of anything — an incomplete capture is precisely the benign
  case this rule has to respect. Absence of evidence never corroborates.
- Three exonerations: association to a designated BSSID/SSID, the
  operator's `--known-mac` roster, and association by a
  **seqnum-correlated sibling address**. The last one closes the
  randomised-probe / real-association case, where matching on the exact
  MAC accused a device that had been sitting on the network all along.
  For an *exoneration* any reported correlation counts — the safe error
  is to stay quiet, so it does not wait for the strong score a positive
  claim would need.

#### When the observable itself is ambiguous (#107 shape B)

`MY_NET_RECON` reports something unusual and the doubt is about what it
*means*. `QUEUE_EVICT` is a step further: the thing it observes — a
burst of unicast downlink frames to one station just after that
station's session changed — is **exactly what an ordinary roam looks
like**. An AP that has just admitted a station has traffic for it. The
attack (Framing Frames, CVE-2022-47522: the AP releasing a transmit
queue it filled under the station's previous security context) and the
benign case are the same bytes on the air.

So corroboration decides the whole severity ladder here, not just the
wording:

- **Uncorroborated it is LOW at 25 %**, and the detail carries the word
  `uncorroborated` plus the benign readings (`an ordinary roam or a
  buffered-traffic flush`). The words *attack* and *attacker* do not
  appear.
- **WARN at 70 % needs `PM_FORGE` for the same station within 10 s** of
  the release. That pairing is the attack's own sequence — the forged
  PM bit is what makes the AP start buffering, the session change is
  what makes it hand the buffer over — and it is the correlation rule
  #107 itself proposed.
- **CRIT needs that corroboration *and* `--my-bssid` ownership.**
  Ownership alone does **not** escalate, which is where this departs
  from `PM_FORGE`. A PM-bit contradiction is something one honest
  half-duplex radio cannot produce, so it earns a CRIT the moment it is
  on your own network. A roam is the single most common event on your
  own network, and promoting that to CRIT would bury the type precisely
  where the operator is paying attention — the same "don't teach the
  operator to ignore a type" reasoning `OPEN_SETUP_AP` applied to its
  pattern table, applied here to severity.

The window the burst is measured in (100 ms) is a **chosen** bound and
says so in the header: 802.11 fixes no deadline for flushing a buffered
frame, so unlike `PM_FORGE`'s beacon-interval window there is nothing
to derive from the air.

Both `PM_FORGE` and `QUEUE_EVICT` cite the frames they fired on (#92
slice 4): the contradicting PM=1/PM=0 pair, and the session-change
frame plus the released burst. Neither has a flow to export on, so the
evidence-ring IDs in `evidence_id_N` are the only route back to the
bytes — see [[pcap-export]] § Which alerts cite frames.

### Records are not conclusions about people

Two families here produce records that can be read as identifying an
individual, and both are bounded in writing rather than left to the
reader: `MY_NET_RECON` above, and the seqnum correlation that feeds it
([[mac-randomisation]]).

For both: a MAC address can qualify as **personal data** (UK ICO
guidance on Wi-Fi location analytics), and **hashing a MAC does not make
longitudinal tracking anonymous**. **These records alone must not be
used for personnel action, physical identification of an individual, or
automated containment.** Sloth is the eyes, not the hands — MISSION §2.5
puts the consequences on the operator, which only works if sloth is
honest about what it actually saw.

### Canonical pair keys

A finding about a *pair* keys on the pair, not on the SSID:
`<rule_id>:<bssid_lo>:<bssid_hi>:<site>:<security_profile>`, BSSIDs in
byte order so `(A,B)` and `(B,A)` are one incident. `twin:<ssid>` and
`twin-fp:<ssid>` collapsed every pair under one name into a single
engine record, and later evaluations overwrote the earlier pair's
detail — two rogues on one SSID read as one.

`site` is the operator's label for where the sensor is. Since #89
slice 2 it comes from `--site` or the inventory file's `site` field and
from **nothing else** — never from the uplink association, an observed
SSID, or any captured frame. Two reasons: unauthenticated RF must not
become a trust input, and a site derived from the uplink would re-key on
every roam, fragmenting one physical impersonator into several incidents
and opening a fresh `alert.create` for each instead of escalating the
one already open. Unset stays the empty string and the key shape does
not change. See [[inventory]].

## Severity tiers

Three tiers, yellow → orange → red, with cross-panel coloring (see
[[ip-palette]]):

| Tier | Hue    | Meaning                                          |
|------|--------|--------------------------------------------------|
| LOW  | yellow | Recon / suspicious-but-passive (port scan, etc.) |
| WARN | orange | Clearly malicious, not yet active exploitation   |
| CRIT | red    | Active attack or IOC hit                         |

## Rules (current)

The full table lives in [`docs/views/alerts.md`](../views/alerts.md);
the headline rules per tier:

- **LOW**: `PORT_SCAN`, `NXDOMAIN_BURST`, `PROBE_FLOOD`, `SURV_DNS`,
  `COUNTRY_ABSENT`, `DFS_MASKING` (both WARN on corroboration)
- **WARN**: `DEAUTH_FLOOD`, `BEACONING`, `DGA_DOMAIN`, `WEAK_TLS`,
  `SURV_CLOUD_SNI`
- **CRIT**: `THREAT_DOMAIN`, `THREAT_IP`, `ARP_SPOOF`, `ROGUE_DHCP`,
  `EVIL_TWIN`, `KARMA_AP`, `DNS_TUNNEL`, `ATTACK_TOOL_UA`,
  `ATTACK_PATH`, `WPS_PIN_BRUTE`, `WPS_PBC_RACE`,
  `WPS_PIXIE_LIKELY_SUCCESS`

### Own operational state

These rules report on sloth's own sensor rather than on the network, and
each carries an empty ATT&CK technique for that reason (the first form of
the exemption in `agents/AGENTS.md`, *Detectors cite their sources*):

| Kind | Sev | Fires on |
|---|---|---|
| `NO_MONITOR_MODE` | WARN | interfaces seen, none in monitor mode — the 802.11 views will be empty |
| `BT_OWN_TRANSMIT` | WARN | the Bluetooth host controller sloth listens through (`--bt-monitor`, or a DLT 254 replay) was told by the host stack to transmit and is still on, or was told within 120 s: an LE scan configured or enabled **active** (it sends SCAN_REQ), Inquiry or Periodic Inquiry, legacy / extended / periodic advertising enabled, LE or BR/EDR Create Connection, Remote Name Request, or Write Scan Enable with inquiry or page scan on (#144 slice 2) |

`BT_OWN_TRANSMIT` is **bucketed, not latched**, on two clocks. The
persistent kinds — advertising (legacy, extended, periodic), inquiry or
page scan, periodic inquiry, and an LE scan enabled under active
parameters — stay on the air from their enable to their disable, so
each controller holds them **on/off**: they are re-asserted for as long
as they are on, however old the enable, and end at the matching disable
(Advertising Enable = 0, Write Scan Enable with both scans off, Exit
Periodic Inquiry Mode, Scan Enable = 0), at Reset, or at DEL_INDEX. The
one-shot kinds (Inquiry, the connects, Remote Name Request) are
re-asserted while their command arrived within `BT_TX_RECENT_SECS`
(120 s). A kind fires while either holds and resolves through the normal
quiet period once neither does. **One incident per transmission kind**
(`bttx:<kind>`), each on its own clock, so two kinds inside the window
are two incidents. sloth sends no HCI or MGMT command itself; what fires
here is the operator's own stack, and MISSION §2's Bluetooth paragraph
is what makes it a finding. The finding's view of the host is limited to
what crosses the monitor channel since sloth opened it: a controller
already transmitting before then is not seen until the host next
commands it or resets it (`ble_own_tx_baseline` = `1` once a Reset of
every controller has been seen), a command the controller then rejects
still counts, and a transmission a controller makes on its own without
a host command is not seen. `sensor_health` carries the same state as
`ble_own_tx_on` (on now), `ble_own_tx_asserted` (what the rule fires
on), `ble_own_tx` / `ble_own_tx_kind` (the newest command), and the scan
configuration
as `ble_scan_mode` / `ble_scan_filter`. → [[ble]]

### Bluetooth Low Energy advertisements (#144 slice 4)

Three lanes over advertisements other devices broadcast, read from the
same BLE device table every BLE sensor fills (`--bt-monitor`,
`--bt-capture`). sloth never scans actively, connects, pairs or reads
GATT for any of them. All three are **WARN**: the issue's CRIT for a
"stalk-grade" category "from a non-resident source" is deferred,
because "non-resident" has no definition yet.

| Kind | Sev | Fires on |
|---|---|---|
| `BLE_ADV_FLOOD` | WARN | many addresses, at high rate, on one documented BLE-spam payload key, in one window — all three gates together (below) |
| `BLE_HID_UNEXPECTED` | WARN | a keyboard-class advertiser on attacker-helper silicon (public address, Hak5 / Espressif OUI), or HID appearances arriving on rotating random addresses |
| `BLE_WATCHLIST` | WARN | an advertiser of a watched category in range — row-driven, **shipped empty** |

**`BLE_ADV_FLOOD`'s gates.** Per sensor, per (HCI Event_Type, payload
family, id, subtype) key, tumbling windows of `ble.flood_window_s` on
the monotonic clock. The family is the Manufacturer Specific Data when a
report has it (id = company ID, subtype = the first octet after it),
else Service Data - 16-bit UUID. A window passes when it holds at least
`ble.flood_distinct_addrs` **fresh** addresses — heard on the key in
neither of the two windows before it, counted only when the window
before held advertisements on the key — **and** at least
`ble.flood_rate` advertisements per second over the whole window length
**and** the key is on the spam list. The list is what the public BLE
Spam tool's own source emits (Apple Proximity Pair 0x07 and Nearby
Action 0x0F, Microsoft Swift Pair beacon 0x03, Samsung EasySetup 0x42
and 0x01, Google Fast Pair 0xFE2C); the tool also gives each payload a
fresh random address (`randomize_mac()` before every payload, held for
one 20–500 ms delay), which is what makes *fresh* addresses and rate the
observables: a crowd of genuine advertisers is many addresses but keeps
them from window to window. The costs, stated: a key's first window,
and the first after a silent one, cannot fire, so a flood is reported
one window late; and the tool's three dedicated Apple attacks set
`random_mac = false` (one address for the whole run), so only its mixed
"Kitchen Sink" mode floods Apple keys from many addresses — a
single-address flood is not this rule's shape. Every key on the list is also
what genuine AirPods, Surface peripherals, Galaxy Buds and Fast Pair
headsets send, and **no source measures how many of them a crowded room
holds** — so neither number has a cited basis, the defaults are a
judgement stated as one, and no gate can be switched off. A window in
progress is judged on what it holds so far, never extrapolated; a burst
straddling a window boundary is split, which can only under-count.
Ubertooth rows are a one-channel sample and say so.

**`BLE_HID_UNEXPECTED` is a precursor, not an exploit.**
CVE-2023-45866 is a HID host (BlueZ, Android, macOS, iOS) accepting an
unauthenticated HID peripheral and its keyboard reports. sloth sees no
pairing and no connection, and the public proof of concept presents as
a BR/EDR keyboard (class of device 0x002540), not over LE — so what this
rule sees is the advertising shape of an injected keyboard, nothing
more. Form (a) keys on the two attacker-helper OUI tables that exist;
form (b)'s threshold has no cited basis, and cannot fire in a sensor's
first window of observation, when every address is new to it (per
sensor: an Ubertooth capture started later has its own).

**`BLE_WATCHLIST` is a category, never an identity** (the #94
posture). Finder tags use random addresses that rotate, so the finding
says "an advertiser of this kind is in range" and counts addresses, not
devices. The shipped table is empty for #68's reason — an invented row
passes every test and matches nothing — and each row lands with the
primary source that documents its payload shape. Candidates and what
each still needs: `research/bluetooth/ble-watchlist-categories.md`. The
kind carries an empty technique on the cited-basis list: a tag riding in
its owner's own bag is not T1430. → [[ble]]

### Multi-Link rules keyed by BSSID (#104)

| Kind | Sev | Fires on |
|---|---|---|
| `MLE_RECONFIG_NO_MLO` | WARN | a Reconfiguration Multi-Link element in a Beacon or Probe Response from a BSSID that has never sent a Basic Multi-Link element, the frame itself included |
| `MLE_PR_BEACON_DIFF` | WARN | a Probe Response whose own Basic MLE names a different MLD MAC or own Link ID than the same BSSID's newest Beacon within 30 s. Not compared, so not caught: a Probe Response whose every Basic MLE carries an AP MLD ID, and the Link ID when either frame omits Link ID Info |

The five earlier MLE rules key on the MLD MAC an element asserts
(`sloth_mld_t`); these two need the BSSID that sent the frame, so they
read a separate 64-row table, `sloth_mle_bss_t`, filled by
`src/mle.c :: mle_bss_observe_frame()` from Beacons and Probe
Responses. A row is created only for a BSSID that sent some Multi-Link
element.

Both are shaped by what a **conformant** AP MLD sends, read from
hostapd's builders: it puts a Reconfiguration MLE in the same Beacon as
its Basic MLE, so the first rule counts the frame's own Basic MLE; and
its multi-link Probe Response carries Per-STA Profiles, an extra Basic
MLE with an AP MLD ID for another MLD, and a moving BSS Parameters
Change Count, none of which a Beacon has, so the second compares only
the MLD MAC and the own Link ID. Both cite their frames from the
evidence ring and say *corroborates*, not *confirms*. Not caught: a
Reconfiguration MLE forged from the cloned BSSID of a real AP MLD. See
`research/ieee/802.11be-2024-9.4.2.322-bss-mle-consistency.md` and the
rows in `docs/views/alerts.md`.

### Surveillance-vendor endpoints (#105)

`SURV_CLOUD_SNI` fires when a host on the monitored segment opens TLS
whose SNI names a body-cam or ALPR platform's cloud — Axon's evidence
platform (`evidence.com`, `axon.com`), Flock Safety
(`flocksafety.com`) or Verkada's camera control plane
(`control.verkada.com`). The hostname was already in state from a
ClientHello sloth overheard, so the rule is a lookup over the embedded
table in `src/vendor_watchlist.c` and adds no capture surface.

Three things about it are deliberate and worth reading before trusting
a hit:

- **It cannot tell a device from a browser.** A docked body camera
  uploading and an analyst with the vendor's portal open in a tab are
  the same observation. The alert text says so.
- **A Flock hit is not a Flock camera.** Flock's field cameras uplink
  over cellular and never cross a monitored LAN, so `flocksafety.com`
  on the wire means someone on *this* network is using the platform.
  #105's headline question — "is there a Flock on my street" — is not
  what this answers, and the other signal families that would try are
  still gated on owner decisions recorded in that issue.
- **The table is short because every row needs a primary vendor
  source.** #105 lists roughly two dozen more vendors with candidate
  domains, all at the issue's own "confidence: low". A row ships only
  for a vendor that publishes its own network-requirements or firewall
  allow-list document naming the domain (#145 ruling 2), one row per
  document. Verkada passed that bar (its *Camera Network Settings*
  page); Ring failed it (its ports page names no domains); the rest
  had no such document this pass could locate. A domain nobody
  publishes is a guess with a vendor's name attached, which is the
  overstatement #90 is open about.

`SURV_DNS` reads the same table from the other end of the exchange: a
DNS **query** from a host on the segment naming a watchlist domain,
keyed on vendor plus that local host like the SNI rule. It covers the
cases where no parseable ClientHello follows the lookup (QUIC, ECH, a
TLS path the capture misses), and Verkada documents that its devices
do not use DNS over HTTPS, so their lookups are plaintext. It is LOW,
one tier under `SURV_CLOUD_SNI`, because a lookup is weaker than a
session — prefetching browsers and link previews resolve names nobody
connects to. Both firing for one host and vendor corroborate each
other; neither confirms a device. Responses are skipped: their source
is the resolver, which would fold every client behind it into one
alert.

Three edges, found in review:

- **A forwarding resolver is still an asker.** Skipping responses does
  not keep a resolver out of the key. Where sloth sees a Pi-hole or a
  router's dnsmasq forward a lookup upstream, that query's source is
  the resolver, so it gets its own alert merging every client behind
  it. The client's own query, where seen, still gives the per-client
  alert beside it.
- **A cut name is not matched.** `dns_log` and `tls_log` keep 63 bytes
  of a name, and the prefix of a longer one can end on a listed suffix
  (`<43 x a>.control.verkada.com.evil.example` stores as a Verkada
  host). The parsers flag a stored name shorter than the wire name
  (`qname_trunc`, `host_trunc`), and both rules skip it.
  `THREAT_DOMAIN` skips `qname_trunc` rows the same way since #152
  (see [[threat-intel]]).
- **One name per incident.** The detail carries the smallest name the
  host used for the vendor across the ring, not each row's, so two
  names under one key do not turn the incident into an `alert.update`
  every 60 s for unchanged evidence.

Embedded, not a file: same choice as the IOC list (MISSION.md §3), so
behaviour stays reproducible from the commit. #105 asked for a
SIGHUP-reloaded CSV; the owner ruled for the embedded table (#145
ruling 8).

Full row, including the false-positive cases, in
[`docs/views/alerts.md`](../views/alerts.md); basis in
`research/papers/surveillance-vendor-endpoints.md`.
### Exposure rules — no ATT&CK technique, on purpose

`OPEN_SETUP_AP` (#80), `CAM_WS_DISCOVERY` (#106 slice 1),
`CAM_SETUP_SSID` (#106 slice 2) and the three camera-identity rules
below (#106 slice A) return `""` from `alert_technique()`
while still carrying a cited basis. What they report is a third
party's device exposing itself — an unconfigured SoftAP, a camera
announcing itself over unauthenticated multicast, a camera still in
setup mode. **Nobody has to be present for any of them to fire**, so
assigning T1046, T1669 or T1557 would claim an adversary step sloth did
not observe. They are not the whole set of cited-but-techniqueless
kinds: `SURV_CLOUD_SNI` and `SURV_DNS` (#105, above), `TPC_ABSENT_HIGH_BAND` (#101,
[[wifi-sigint]]) and `COUNTRY_ABSENT` / `DFS_MASKING` (#101 slice A,
below) are on the same list for a posture or a heuristic shape rather
than an exposure, and that list in the test named below is the authority — this
page said "three" while it held five.

This is not the `NO_MONITOR_MODE` (or `BT_OWN_TRANSMIT`) case, which has no source to cite at
all. These have sources, they are just not ATT&CK IDs, and
`tests/test_research_corpus.c ::
test_uncitable_kinds_with_a_real_basis_are_still_cited` names each kind
explicitly and fails if its citing document disappears.

`CAM_SETUP_SSID` is also the one rule in the engine that deliberately
does **not** gate on an open network. Hikvision's `HAP_` setup AP and
EZVIZ's AP-mode network are WPA-protected with a key printed on the
device label, so an OPEN gate would make the most common camera case
undetectable; the rule reports the provisioning state and records the
encryption in the detail instead. See the full row in
[`docs/views/alerts.md`](../views/alerts.md).

### Regulatory heuristics (#101 slice A)

Two kinds in `src/alerts/rules_regulatory.c`, both labelled
**heuristic** in their detail text because no advisory backs either
(the issue says so for both):

| Kind | Sev | Fires on |
|---|---|---|
| `COUNTRY_ABSENT` | LOW / WARN | a 5 GHz AP (band from `ap_band_label()`) whose beacons have never carried a Country element — IEEE 802.11d, now 802.11-2020 §9.4.2.8. Ungated: a missing domain claim is worth seeing on any AP. WARN when the BSSID is designated, or the SSID is designated from a BSSID that is not. Needs 60 s and 3 beacons of observation, and states those floors rather than live counters so the change signature stays still; suppressed for `phy == "legacy"` and 6 GHz. A malformed element is named as such, not as absent. |
| `DFS_MASKING` | LOW / WARN | a BSSID not in the session's RF baseline whose `first_seen_channel` is a DFS channel per [[regulatory-table]], with no CSA naming that channel from the same BSSID, or from an SSID peer that was then itself heard on that channel (a forged peer CSA — the #63 lure — does not excuse the newcomer while the real AP stays put). Only CSAs with addr2 == addr3 count. A rebooted legitimate AP looks the same, so LOW; WARN only when the AP carries a designated SSID from an undesignated BSSID, or is the twin half of an evil-twin episode (the real half stays LOW). Inert before the baseline. |

Sources: `research/ieee/802.11d-country-element.md`,
`research/regulatory/dfs-15.407-en301893.md`. Full rows in
[`docs/views/alerts.md`](../views/alerts.md).
### Camera identity: mDNS, SSDP, OUI (#106 slice A)

Three more on the same exposure list, each reading a table sloth
already keeps against `src/camera_vendor.c` (embedded, #145 ruling 8):

- **`CAM_MDNS_SERVICE`** — a DNS-SD service type IANA registers for
  camera video (`axis-video`, `cctv`), or `rtsp`, which the detail
  reports as a protocol rather than a camera. Vendor-specific types
  nobody registered or documented are not matched.
- **`CAM_SSDP_DEVICE`** — a NOTIFY for UPnP `DigitalSecurityCamera:1`,
  or `Basic:1` only when the SERVER product token names a camera
  vendor. M-SEARCH is the asker's want and is skipped.
- **`CAM_SETUP_OUI`** — a beaconing BSSID in a camera vendor's IEEE
  MA-L block, compared with the U/L bit masked; a match on a locally
  administered address carries `randomized-local` in the detail. A
  mixed-vendor block (Ubiquiti, TP-Link, Wyze; #155) fires only beside a
  camera setup SSID on the same BSSID, says `mixed vendor` in the
  detail, and never matches a locally administered address.

All three WARN on first sighting with one alert per identity and a
rising count: per advertised DNS-SD service instance (a camera that
advertises both `_axis-video._tcp` and `_rtsp._tcp` is two alerts), per
SSDP device UUID with one detail however many rows it announces, and
per BSSID. They corroborate and never confirm: an OUI names who the IEEE
assigned the block to and a SERVER string is the firmware's own claim,
so each detail says what was and was not observed. Sources, and what was
considered and left out (unregistered mDNS types among them), in
`research/papers/camera-vendor-identity.md`. Ubiquiti, TP-Link and Wyze
are in the table since the owner's 2026-10-21 ruling on #106, as
mixed-vendor rows: a prior for the device classifier, not a finding on
their own ([[camera-detection]], `research/papers/camera-router-role.md`).
#106's Case B (`B6:FB:E4`, a locally administered address) still does
not fire: a mixed row never matches one.
The camera rules' evidence is also folded onto the device record
and shown as a `CAMERA` row on `[g]` Devices; how, and on which keys,
is [[camera-detection]].
### Anonymous RTSP — `CAM_RTSP_UNAUTH` (#106 slice B)

`src/rtsp_snoop.c` reads RTSP on TCP 554 and 8554 (RFC 2326, RFC 7826
§10.2) and pairs each `DESCRIBE` with its response by CSeq, per
connection (RFC 7826 §18.20). A `200` to a `DESCRIBE` that carried no
`Authorization` header, on a connection with no earlier `401`, is
recorded as anonymous for that (server, port, path); the rule raises one
WARN per server IP with the distinct-path count in the detail. It
corroborates anonymous stream access and does not confirm it: SETUP or
PLAY may still be authenticated, the server may filter by address, and
the device need not be a camera.

Segments are not reassembled: only the first RTSP message in each TCP
segment is read, so a DESCRIBE pipelined behind another in one segment
is missed. A DESCRIBE whose header block does not end (empty line) in
its segment is dropped rather than counted anonymous, because its
`Authorization` header may be in the next one. The detail's example path
is the smallest of the server's anonymous paths, so only a new path or a
stream-table eviction moves the incident.

What it never does: read an `Authorization` value, keep URL userinfo or
a credential-shaped parameter — `user=`, `password=`, `loginuse=` /
`loginpas=`, `account=`, `token=`, `auth=` and other names on those
stems (such a request is not tracked), or
compare anything against a default-credential list — the issue's
`camera_default_creds.csv` was dropped by the #145 ruling and the
`src/cleartext_creds.h` guardrail stands. Same exposure position as
`CAM_WS_DISCOVERY`: no ATT&CK technique, a cited basis
(`research/rfc/2326-7826-rtsp.md`), named on the list in
`test_uncitable_kinds_with_a_real_basis_are_still_cited`. Full row in
[`docs/views/alerts.md`](../views/alerts.md).

### Tunable thresholds (#82)

Almost every threshold in the engine is a `#define` and nothing else —
`KARMA_SSID_THRESH`, `ASSOC_FLOOD_THRESH`, the flood windows. The three
WPS rules are the exception: the owner's decision of 2026-09-30 was to
ship the issue's proposed numbers *each behind a config knob*, so each
has a `#define` default in `src/alerts.h` **and** a CLI override, in the
shape `seqnum_corr_set_retain_secs()` / `db_set_retain_days()` already
use. There is no configuration-file format in sloth and this did not add
one.

| Rule | Default | Flag |
|---|---|---|
| `WPS_PIN_BRUTE` | 5 cycles / 60 s | `--wps-pin-brute-cycles N` |
| `WPS_LOCKOUT_CYCLING` | 2 cycles / 1 h | `--wps-lockout-cycles N` |
| `WPS_PBC_RACE` | fires above 2 / 120 s | `--wps-pbc-concurrent N` |
| `WPS_PIXIE_PROBE` | 60 s of silence after M3 with no M4 | `--tune wps.pixie_silence_s=N` |
| `WPS_PIXIE_LIKELY_SUCCESS` | 24 h look-back from a completed run | `--tune wps.pixie_success_window_s=N` |

`WPS_LOCKOUT_CYCLING`'s evidence is readable: the **WPS ACTIVITY**
block on the Beacons detail screen (`b`, then Enter on the AP) shows
the lifetime cycle count, the windowed count against the current
threshold, and the retained locked→unlocked timeline with a relative
age per transition. The screen and the rule call the same counter, so
the figure in the WARN and the figure on screen are one number. See
[beacons.md](../views/beacons.md).

For those three only the **counts** are tunable. The windows are not
operator policy: 60 s is the rate the brute-force threshold is defined
over, one hour is the period the lockout sawtooth is stated in, and
120 s is the PBC walk time the WSC protocol fixes. A knob that moved the
walk time would be measuring something the protocol does not do.

The two Pixie-Dust rules are the other way round, by owner ruling
(2026-10-19): they have no count, and their *windows* are the knobs —
how long a run must stay quiet after M3 before it is called abandoned,
and how far back a completed registration looks for one.

### Pixie Dust (#82)

Source: Bongard, *Offline bruteforce attack on WiFi Protected Setup*
(Hack.lu 2014), `research/papers/bongard-pixie-dust-2014.md`. The
attack has two on-air steps and everything between them is offline;
sloth reads the two steps.

- **`WPS_PIXIE_PROBE`** (WARN) — an attempt that reached M1 and M3 and
  never M4, M5..M8 or Done, then went silent. M4 is the registrar's
  next message and carries R-Hash1, the online guess; a registrar that
  took M3 (E-Hash1/E-Hash2) and sent no M4 wanted only what an offline
  crack needs. In practice it catches **failed, timed-out or deferred**
  offline attempts.
- **`WPS_PIXIE_LIKELY_SUCCESS`** (CRIT, title `WPS_PIXIE_SUCCESS` —
  the kind name does not fit `ALERT_TITLE_LEN`) — a registration at
  the same AP that reached M7/M8/Done, from any station, after such a
  run. Not gated on the silence, because the run with the PIN can
  start at once. If the probing station also sent refused M4 guesses,
  the detail says it may be an online PIN brute force that got past a
  missed M4 rather than Pixie-Dust; the CRIT stands either way.

**What these rules do not see.** A successful `reaver -K` finishes in
one exchange: reaver (t6x fork, read at `f9b5e15`) runs `pixiewps`
while it handles M3 and, on success, swaps the cracked PIN in and sends
M4..M8 on the same run. On the air that is an ordinary M1..M8
enrolment with no M3 abandon, so neither rule fires. The probe shape is
what reaver leaves when `pixiewps` fails (NACK, exit) or outlasts the
receive timeout (silent NACK, exit, *"Send pin with -p"*); the success
rule reads that run followed by a later one with the PIN. `bully` and
OneShot were not checked. A possible follow-up is the timing reaver
does leave: an M3→M4 gap of the `pixiewps` runtime, seconds, against
an online round trip's fraction of one.

`src/wps_track.c` keeps the per-attempt view this needs: the Mn bits of
the current attempt (M1 to the next M1), when its M3 arrived, the newest
closed attempt that was abandoned after M3 and the silence that followed
it, and when an attempt first reached the credentials. Both rules
**corroborate, never confirm** (#145 ruling 2): a passive sensor cannot
see whether the AP's nonce generator is weak, and a receiver gap after
M3 of a legitimate enrolment produces the same shape.

**No weak-RNG chipset watchlist ships.** #82 proposed one, conditional
on the pixiewps/Bongard list counting as a primary source. The slides
name chipset vendors only in passing and map no observable identifier
(OUI, WPS Manufacturer/Model, firmware) to any flawed generator — and
say outright that brands reskin chipset reference code and mix
chipsets — so no row has a primary source and the watchlist is struck
under #145 ruling 2. The research document records the reasoning.

The session behind both rules is readable on the Beacons detail screen:
the **WPS SESSIONS** block lists each station's state, the M1..M8 strip,
whether the newest run is in the abandoned-after-M3 shape and how long
it has been quiet against the threshold, when the credentials were
reached, and the last eight EAP-WSC frames. See
[beacons.md](../views/beacons.md).

Every threshold is a **floor** — the rule fires at or above the count —
so raising one can only quiet sloth and can never invent a finding. A
value of zero or less is **rejected** rather than read as "disabled": a
floor of zero fires on every observation, which is the opposite of what
the operator typed. See [[cli-reference]].

## Cross-panel coloring

Any alert with a concrete `match_ip` adds that IP to the TUI
alert-hot list at the rule's severity for `ALERT_HOT_TTL_S` (1h).
Every panel that renders the IP (connections, top-hosts, packets,
hostname rows) paints it in the matching tier colour. Promotion only
— a later LOW does not demote an earlier CRIT on the same IP within
the TTL window.

## How rules find each other

- DNS rules read `s->dns_log[]` (see [`dns.md`](../views/dns.md)).
- Connection rules read `s->conns[]` (see [`connections.md`](../views/connections.md)).
- Deauth rule reads the `(BSSID, victim)` aggregates `s->deauth_victims[]`, not the per-stream rows `s->deauth_events[]` (#88; see [`deauth.md`](../views/deauth.md)).
- Threat-intel matching uses the embedded lists in `src/threat_intel.c`.
  Those lists are **synthetic demo data, not a threat feed**, so
  `THREAT_DOMAIN` / `THREAT_IP` fire on nothing real until an operator
  replaces them — see [[threat-intel]].
- Beaconing math lives in `src/beacon_detect.c` — see [[beacon-detection]].

## Adding a rule

Per `agents/AGENTS.md` "How to add an alert rule" (updated for #118):

1. Append `X(<NAME>, "T1xxx")` to `include/sloth_alerts.def` — at the
   end, since enum values are carried by JSONL and the SQLite store. That
   one row is the enum value, `alert_type_name()` and `alert_technique()`
   (#117). A `""` technique needs a comment on the row saying which
   exemption it is, and a citing document either way.
2. Write `void rule_<name>(const sloth_state_t *s, time_t now)` in the
   `src/alerts/rules_<domain>.c` it belongs to, calling `fire(...)`
   (prototypes for the engine's entry points are in
   `src/alerts/engine_internal.h`), and declare it in
   `src/alerts/rules.h`.
3. Add `R(rule_<name>)` to `src/alerts/rules_table.c` — at the end
   unless it depends on another rule's output in the same tick.
   `test_rule_table_is_complete` goes red until it is there.
4. If the alert has a known target IP, pass `match_ip` + `match_port`
   to `fire()` so per-alert pcap works.
5. Add a row to the rule table in `docs/views/alerts.md`.
6. Test: seed state that should trigger, run `alerts_update`, assert
   `find_alert(type) >= 0`.
7. `make docs-counts` to move the rule count in the docs.

## Footer enrichment

The selected alert's footer shows RIR region (from the `/8` table) and
embedded hosting-org lookup (`src/ip_owner.c`). Useful for triage when
the rule fires on an unfamiliar IP.

## Related pages

- [[threat-intel]] — IOC list format, suffix matching, swap-in.
- [[beacon-detection]] — periodicity math.
- [[pcap-export]] — `--pcap-dir` mechanics.
- [[attack-map]] — protocol → threat table.
