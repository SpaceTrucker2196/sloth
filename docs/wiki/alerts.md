---
name: alerts
description: Alert engine internals — dedup-by-key ring, the six rules, severity levels, per-alert pcap hook
type: reference
---

# Alerts

**Summary**: A small dedup-by-key ring runs every poll. Each rule scans current state, builds a stable key, and either bumps an existing alert or appends a fresh one. New keys get a JSONL `alert` line and (when `--pcap-dir` is set) a per-alert pcap dump. Everything that happens to an alert *after* creation — escalation, changed evidence, expiry — rides the `alert.*` incident-lifecycle records added in #98.

**Sources**: `docs/views/alerts.md`, `docs/views/dns.md`, `docs/views/connections.md`, `docs/views/deauth.md`.

**Last updated**: 2026-10-19.

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
  | `rules_mle.c` | the five 802.11be Multi-Link Element rules |

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
| `BEACONING` | `beacon:<ip, 39 cut>:<port>` | `beacon:<ip>:<port>` (IPv6 bracketed, never cut) |

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

- **LOW**: `PORT_SCAN`, `NXDOMAIN_BURST`, `PROBE_FLOOD`
- **WARN**: `DEAUTH_FLOOD`, `BEACONING`, `DGA_DOMAIN`, `WEAK_TLS`,
  `SURV_CLOUD_SNI`
- **CRIT**: `THREAT_DOMAIN`, `THREAT_IP`, `ARP_SPOOF`, `ROGUE_DHCP`,
  `EVIL_TWIN`, `KARMA_AP`, `DNS_TUNNEL`, `ATTACK_TOOL_UA`,
  `ATTACK_PATH`, `WPS_PIN_BRUTE`, `WPS_PBC_RACE`

### Surveillance-vendor endpoints (#105)

`SURV_CLOUD_SNI` fires when a host on the monitored segment opens TLS
whose SNI names a body-cam or ALPR platform's cloud — Axon's evidence
platform (`evidence.com`, `axon.com`) or Flock Safety
(`flocksafety.com`). The hostname was already in state from a
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
  domains, all at the issue's own "confidence: low"; none is included.
  A domain nobody publishes is a guess with a vendor's name attached,
  which is the overstatement #90 is open about.

Embedded, not a file: same choice as the IOC list (MISSION.md §3), so
behaviour stays reproducible from the commit. #105 asks for a
SIGHUP-reloaded CSV; that is an architecture-contract question the
owner has not answered and this leaves it open.

Full row, including the false-positive cases, in
[`docs/views/alerts.md`](../views/alerts.md); basis in
`research/papers/surveillance-vendor-endpoints.md`.
### Exposure rules — no ATT&CK technique, on purpose

Three rules return `""` from `alert_technique()` while still carrying a
cited basis: `OPEN_SETUP_AP` (#80), `CAM_WS_DISCOVERY` (#106 slice 1)
and `CAM_SETUP_SSID` (#106 slice 2). What they report is a third
party's device exposing itself — an unconfigured SoftAP, a camera
announcing itself over unauthenticated multicast, a camera still in
setup mode. **Nobody has to be present for any of them to fire**, so
assigning T1046, T1669 or T1557 would claim an adversary step sloth did
not observe.

This is not the `NO_MONITOR_MODE` case, which has no source to cite at
all. These three have sources, they are just not ATT&CK IDs, and
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

`WPS_LOCKOUT_CYCLING`'s evidence is readable: the **WPS ACTIVITY**
block on the Beacons detail screen (`b`, then Enter on the AP) shows
the lifetime cycle count, the windowed count against the current
threshold, and the retained locked→unlocked timeline with a relative
age per transition. The screen and the rule call the same counter, so
the figure in the WARN and the figure on screen are one number. See
[beacons.md](../views/beacons.md).

Only the **counts** are tunable. The windows are not operator policy:
60 s is the rate the brute-force threshold is defined over, one hour is
the period the lockout sawtooth is stated in, and 120 s is the PBC walk
time the WSC protocol fixes. A knob that moved the walk time would be
measuring something the protocol does not do.

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
