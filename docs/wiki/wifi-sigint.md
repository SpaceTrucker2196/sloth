---
name: wifi-sigint
description: The v1.1 WiFi SIGINT feature set — PNL, EAPOL/PMKID, seqnum correlation, assoc inventory
type: project
---

# WiFi SIGINT (v1.1)

**Summary**: Four views added in v1.1 turn sloth from "what's on the wire" into "who is in the room and what do they remember". Built around passive 802.11 monitor-mode capture.

**Sources**: `docs/views/pnl.md`, `docs/views/eapol.md`, `docs/views/seqnum.md`, `docs/views/assoc.md`, `docs/views/probe.md`, `docs/views/beacons.md`.

**Last updated**: 2026-10-20 (#101 slice A: `COUNTRY_ABSENT`, `DFS_MASKING`, [[regulatory-table]]).
**Last updated**: 2026-10-20.

---

## The four views

| Key | View | Primitive |
|-----|------|-----------|
| `k` | PNL    | Per-MAC Preferred-Network-List aggregation + OS fingerprint via vendor IE |
| `e` | EAPOL  | PMKID + 4-way handshake capture; hashcat 22000 + replayable per-handshake pcap |
| `j` | Seqnum | MAC-randomisation deanonymisation via 802.11 sequence-control correlation |
| `w` | Assoc  | Confirmed STA ↔ AP associations (EAPOL > Reassoc ≥ Assoc evidence) |

## What each enables

- **PNL (k)** — fingerprints a device by the SSIDs it remembers.
  Survives MAC rotation because the OS vendor IE in probe requests is
  the same across rotations.
- **EAPOL (e)** — exports `eapol.22000` in hashcat mixed format plus
  per-handshake pcaps replayable in aircrack-ng / Wireshark. PMKID
  rows are offline-crackable with no client interaction.
- **Seqnum (j)** — reports address pairs whose frames fall on the same
  forward-running 12-bit sequence counter, with a calibrated score and
  the evidence window. A hypothesis about a radio, never an
  identification of a person, and not on its own grounds for personnel
  action or physical identification (#94). `--no-correlate` switches the
  linkage off. See [[mac-randomisation]] for the full explanation and the
  limits on use.
- **Assoc (w)** — answers "who is on which AP, right now" with
  graded evidence (EAPOL is definitive, AssocResp / ReassocResp are
  strong).

## Cross-view correlation chains

The four views compose:

```
Probe (raw) ──► PNL (k)     ──► fingerprint by SSID list
                Seqnum (j)  ──► fingerprint by chipset counter
                                    │
                                    ▼
                              same physical device across MACs
                                    │
                                    ▼
                              Assoc (w) tells you which AP it landed on
                                    │
                                    ▼
                              EAPOL (e) lets you crack the PSK against it
```

## Hardware requirements

Monitor mode on a card / driver that supports
`ARPHRD_IEEE80211_RADIOTAP`. The project README cites rtl88XXau as a
tested chipset. Set the probe-capture interface from `[1] Interfaces`
(`m` key).

## Storage caps

- `MAX_PNL_CLIENTS = 128` × 16 SSIDs per client, LRU evicted by `last_seen`.
- `MAX_ASSOC_ENTRIES = 128`, LRU evicted by `last_seen`.

## Multiple monitor-mode radios (issue #21)

A single monitor adapter hears one channel at a time. Channel hopping
covers the band over time, but a short management frame — a lone
deauth, a probe response — slips past while the radio is tuned
elsewhere. A second adapter parked on another channel closes that gap.

sloth merges observations from every monitor radio into one coherent
world model. Each adapter is a `SENSOR_WIFI` sensor with its own id
(see the [[non-ip-sensors]] registry); every 802.11 observation is
tagged with the radio that heard it and folded into an entity-keyed
merge table (AP BSSID / STA MAC). The existing Wi-Fi views still
aggregate **by observed entity, not by adapter** — you see one row per
AP no matter how many radios saw it — but the merge layer retains
enough observer metadata to answer *which radio saw this, on what
channel, at what signal, and when*:

- `seen_by` — how many distinct radios heard the entity.
- `sensor_mask` — which radios (bit *i* = sensor id *i*).
- `best_rssi` / `best_sensor` — strongest signal and the radio closest
  to the entity (useful for coarse direction-finding across a spread of
  adapters).

This metadata is emitted on the additive `wifi_merged` JSONL record
(see [[jsonl-schema]]) so downstream consumers can reason about
coverage and per-radio provenance. With a single adapter the merge is
an identity map — one row per AP, `seen_by == 1` — so nothing changes
for the common case.

### Setup expectations

sloth is **passive**. It does **not** put any adapter into monitor
mode and does **not** change channel assignments except the operator's
own `--hop` scheduler on sloth's own monitor interface (see
[[wifi-sigint]] channel hopping). Prepare each radio externally before
launch, exactly as for a single adapter:

```
airmon-ng start wlan0        # → wlan0mon
airmon-ng start wlan1        # → wlan1mon, park on another channel with iw
```

Each prepared monitor interface registers as its own Wi-Fi sensor and
contributes to the merged view. sloth never transmits, associates, or
reconfigures an adapter it did not create.

> **Hardware note.** Concurrent capture across two physical radios is
> validated only on Linux with two monitor-capable adapters and
> `CAP_NET_ADMIN`. The merge, dedup, and JSONL layers are exercised in
> CI against seeded multi-sensor state (`tests/test_wifi_merge.c`); the
> live N-thread capture path is hardware-gated like the nl80211
> channel-set path.

## Regulatory elements (issue #101, slices 1-3)

`src/reg_ie.c` parses the three elements that carry the regulatory
envelope an AP *claims* to operate in. Until #101 sloth read none of
them, so the cheapest non-compliance signal there is — a 5 GHz AP that
names no country at all, the hostapd / OpenWrt stripped-build default —
was invisible.

| Element | Tag | Clause | Fields taken |
|---|---|---|---|
| Country          | 7  | IEEE 802.11-2020 §9.4.2.8 (802.11d-2016) | ISO 3166-1 alpha-2 code, environment octet, triplets |
| Power Constraint | 32 | §9.4.2.13 | Local Power Constraint, unsigned dB |
| TPC Report       | 35 | §9.4.2.16 (802.11h) | Transmit Power, signed dBm; Link Margin, signed dB |

Two details in the Country element are where a naive parser goes wrong.

**The third octet of the Country String is not always an environment.**
§9.4.2.8 gives it five forms: ASCII `' '` (all environments), `'I'`
(indoor only), `'O'` (outdoor only), `'X'` (non-country entity, with the
code itself `"XX"`), or the *binary* Annex E Operating Class table
number — which is what hostapd emits as `0x04` when it advertises global
operating classes. Anything outside those five is recorded as
`REG_ENV_UNKNOWN` rather than folded into "any": an AP that emits an
undefined octet has made no environment claim, and inventing one would
put a regulatory assertion in the record that never went over the air.

**The triplets are two different structures sharing one shape.** Each is
three octets, and which three fields they are is decided by the first
octet, per triplet, not per element: at 201 or above it is an Operating
Extension Identifier and the triplet is (ext id, operating class,
coverage class); below it, (first channel, number of channels, maximum
transmit power). Read the wrong way, an operating triplet for global
class 81 reports "channel 201, 81 channels, 3 dBm" — plausible enough to
pass unnoticed. Maximum transmit power is **signed** dBm; sub-1 mW caps
are real, and an unsigned read turns −2 dBm into 254 dBm.

Both TPC Report fields are signed too. Link Margin is reserved (0) in a
beacon or probe response and only carries a value in a TPC Report action
frame; it is parsed regardless, since the element layout is the same.

The parser reaches frames through `beacon_parse_ies()` — the one seam
both the monitor path and the nl80211 managed path use, so the two
cannot diverge on regulatory depth the way they once did on RSN depth.
Its `reg_out` parameter is optional and NULL-safe; the same parse is
also published into `rsn_out->reg`, which is the copy that reaches
storage.

### Where the parse is kept (slice 2)

Slice 1 shipped inert: every caller passed NULL, so the parser ran
under tests only and no value was retained. Slice 2 gives it a home.
`beacon_ap_t` carries one `reg_ie_t` per BSSID, folded in by
`beacon_record()` through `reg_ie_merge()`.

It lives on the AP entry rather than in a BSSID-keyed table of its own
because every other per-AP observation does — `neighbors[]`,
`ssid_history[]`, the WPS strings, the RSSI ring — and a second table
would age on its own schedule, so an AP this one had already evicted
could still have a regulatory claim on file. That is the divergence the
shared IE walk exists to prevent. The price is `sizeof(reg_ie_t)` on
every one of the 256 entries, paid whether or not the AP ever sends a
regulatory element.

The merge is **per element, not per struct**. A beacon that omits the
Country element leaves the stored country alone; only an element that
actually parsed replaces the stored one. Assigning the whole struct
each frame would turn every bare beacon into a stored envelope of
"country unknown, 0 dB constraint, 0 dBm transmit power" — three
regulatory claims the AP never made, and ones a later legality check
would read as real. The `*_present` flags are the only thing that can
separate "never claimed" from "claimed zero", so every reader checks
the flag before the value.

The corollary is that a retained envelope is **sticky**: an AP that
stops advertising a Country element keeps the last one it sent. On a
hopping radio a missing element nearly always means the beacon
carrying it was not heard, not that the AP retracted it. Seeing a real
retraction needs per-element recency, which is a later slice's field.
The three malformed counters accumulate across the BSSID's frames,
saturating rather than wrapping — the same relation `beacon_ap_t`'s
`fuzz_*` counters have to `beacon_rsn_t`'s.

`reg_ie.h` sits in `include/` rather than `src/` because `beacon_ap_t`
embeds the type, so every translation unit that sees `sloth.h` must
see it too — including the ones built without `-Isrc`.

**Still mostly inert past storage.** No regulatory table, no
channel-legality decision, no SQLite column. Slice B below adds the
operator surfaces — a `REG` column, a detail block and a JSONL record —
none of which judges anything.
Reading a claim is not the same as judging it, and the judging half
needs a versioned regulatory table that these halves must not pre-empt.
Slice 3 below is the one exception, and it is deliberately the cheapest
one: the single finding that needs no table at all. The nl80211
managed-mode path still passes no envelope onward: `wifi_ap_t` has no
field for it, the same way it has no `neighbors[]`.

Malformed elements are counted (`malformed_country`,
`malformed_power_constraint`, `malformed_tpc`) in the same spirit as
`beacon_rsn_t`'s `ie_overruns`: a truncated or crafted regulatory
element is itself a signal, so it is recorded rather than silently
skipped.

Tests are hand-built byte arrays, per `agents/AGENTS.md` — the issue's
pcap-fixture test plan is deferred to the `needs-pcap-fixture`
follow-up layer it belongs to. `tests/test_reg_ie.c` covers the parse
clause by clause; `tests/test_beacon_snoop.c` covers retention
(update-not-duplicate, per-BSSID isolation, absent and unparseable
elements storing nothing, no stale triplet tail, no envelope surviving
slot reuse) by driving whole frames through
`beacon_parse` → `beacon_record` → `beacon_snapshot`.

### The first finding drawn from it (slice 3)

`ALERT_TYPE_TPC_ABSENT_HIGH_BAND` is the one rule of the five #101
specifies that needs neither the regulatory table nor a path-loss model
nor a new field on `beacon_ap_t`. It reads two flags the retained
envelope already holds and nothing else.

It fires WARN when a BSS the operator **designated** (`--my-bssid` /
`--my-ssid`) and which is operating in **5 GHz** has, across every
beacon ever heard from it, advertised neither a Power Constraint element
(tag 32) nor a TPC Report element (tag 35). IEEE 802.11-2020 §11.8 makes
those two the mechanism by which an AP publishes a local transmit-power
ceiling, so an AP sending neither has published no ceiling at all — the
shape a build with the feature switched off leaves behind (hostapd
`ieee80211d=0` / `ieee80211h=0`, stripped OpenWrt images), which keeps
its default 20 dBm wherever the device is carried.

Four things it deliberately is not:

- **Not an accusation.** It reports non-compliance, so
  `alert_technique()` returns `""` — the third rule in that family after
  `OPEN_SETUP_AP` (#80) and `CAM_WS_DISCOVERY` (#106). T1557.004, the
  technique #101 proposed, would assert impersonation from a
  configuration gap. The basis is still cited and still enforced:
  `research/ieee/802.11-2020-11.8-spectrum-management.md`, held by
  `tests/test_research_corpus.c`.
- **Not about anyone else's AP.** Ungated it would fire on every
  third-party 5 GHz AP in RF range, where sloth has no standing to call
  a posture wrong and the operator has nothing to fix. The issue scopes
  it to a designated network and so does the rule.
- **Not a 6 GHz rule.** In 6 GHz the power limit rides the Transmit
  Power Envelope element (tag 195), so the absence of 32 and 35 there
  is the wrong element missing. Slice B below parses tag 195; this rule
  still does not read it. The band
  comes from `ap_band_label()` and `channel_source` (#66, #91), never
  from the channel number — 5 and 6 GHz numbers overlap outright.
- **Not a judgement about legality.** Whether the power actually in use
  is legal where the AP stands, and whether the country it names is the
  right one, both still need the regulatory table.

The sticky envelope turns out to be exactly right for this rule rather
than something it has to work around: a `*_present` flag set by any
beacon at any point stays set, so "absent" means "no beacon from this
BSSID has ever carried one" and not "the last one did not". The
observation floor (`TPC_ABSENT_MIN_OBSERVED_S`, 60 s) is the other half
— longer than the 30 s posture debounce, because a missing element is
also what a radio that was listening elsewhere produces. `phy ==
"legacy"` is suppressed: 802.11a predates 802.11h-2003.

One corroborator that would strengthen this is unavailable today. The
Spectrum Management bit in Capability Information (§9.4.1.4) would turn
"no ceiling published" into "the AP said it does spectrum management and
then did not", but sloth retains no capability field, so the bit is not
readable from `beacon_ap_t`.

Full row: `docs/views/alerts.md`.

### Slice A: `COUNTRY_ABSENT`, `DFS_MASKING`, the channel table

Two more rules read the retained envelope (`src/alerts/rules_regulatory.c`).
`COUNTRY_ABSENT` reports a 5 GHz AP whose beacons have never carried a
Country element — the 802.11d domain claim the TPC rule's detail
already printed as "absent too" — on any AP in range at LOW, and at
WARN when it touches something designated. `DFS_MASKING` reports a
BSSID that arrives after the RF baseline on a DFS channel with no CSA
leading there; it reads a new per-BSSID field, `first_seen_channel`,
set once by `beacon_record` on insert, and takes its DFS set from the
compiled-in table described on [[regulatory-table]]. Both call
themselves heuristics in their detail text. Channel-in-country
validation, the 6 GHz regulatory envelope and the observed-vs-claimed
power observation are other slices.
### 6 GHz claims and the operator surfaces (slice B)

Two more places carry a regulatory claim, both 802.11ax-2021 and both
on the 6 GHz side, where the 5 GHz trio above is not the mechanism:

| Field | Where | Clause | What is retained |
|---|---|---|---|
| Regulatory Info | HE Operation (255/ext 36), 6 GHz Operation Information, Control B3-B5 | 802.11ax-2021 §9.4.2.249 | 0 Indoor AP, 1 Standard Power AP; 2-7 reserved in that text, kept raw |
| Transmit Power Envelope | tag 195 | §9.4.2.161 as 802.11ax-2021 amends it | Information octet (Count, Interpretation, Category) and the values, signed, 0.5 dB steps |

`src/reg_6g.c` parses both into a `reg_6g_t`, kept beside `reg_ie_t`
on `beacon_ap_t` and folded in by `reg_6g_merge()` on the same terms:
per element, sticky, present flags first. Two traps, both pinned by
`tests/test_reg_6g.c`:

- **The 6 GHz field moves.** VHT Operation Information (3 octets) and
  the Max Co-Hosted BSSID Indicator (1) sit in front of it when their
  Parameters bits are set. Miss either and Control is read from Primary
  Channel or CCFS0, which yields a plausible reserved value rather than
  an error.
- **EIRP and PSD count differently.** EIRP has Count + 1 values (20, 40,
  80, 160 MHz); PSD has one value at Count 0 and 1, 2, 4 or 8 at Count
  1-4. Count 2 is three EIRP values but two PSD values. A reserved
  Interpretation or Count is recorded with no values rather than read
  at a guessed length. Octets past the values (802.11be's 320 MHz
  extension) are counted, not decoded and not malformed.

TPE entries are kept per (Interpretation, Category) pair, at most 8,
the overflow flagged, so a beacon carrying only the regulatory-client
PSD envelope does not erase the local EIRP one.

What the operator sees, none of it a verdict:

- **`REG` column on `[b]`** — country and environment, then `MAL`,
  `6G:IN`/`6G:SP`, `TPCn`, `PCn`, `TPEn` while they fit; the column
  takes the width left after the fixed columns, and is not drawn below
  136 columns rather than wrap the row. See
  [`docs/views/beacons.md`](../views/beacons.md).
- **`REGULATORY` block on the `[b]` detail screen** — each claim in
  full, plus the observed-vs-claimed **power delta**: the received
  level against the TPC Report power (or, failing that, the local EIRP
  TPE ceiling), compared with free-space loss at 1 m. Positive excess
  means the AP was heard stronger than a transmitter at the claimed
  power could produce at a metre. It assumes free-space loss and 0 dBi
  antennas and the distance is unknown, so it is shown as an
  observation and never fires an alert — the owner's ruling on #101
  (plan #145). It is highlighted only past a 10 dB margin (the ±5 dB
  TPC Report tolerance of §9.4.2.16 plus typical receive gain and RSSI
  calibration); a smaller excess is printed as a plain number.
- **`wifi_regulatory` JSONL record** — change-only per BSSID, emitted
  only once a regulatory element has been parsed from it; see
  [[jsonl-schema]].

Still not here: the channel-legality table and the rules that read it
(the other half of #101), and SQLite persistence.

## Related pages

- [[regulatory-table]] — the cited, dated 5 GHz channel table `DFS_MASKING` reads.
- [[mac-randomisation]] — the seqnum deanonymisation primitive in
  depth.
- [[non-ip-sensors]] — the passive sensor registry each radio joins.
- [[attack-map]] — entries for evil-twin, PMKID harvest, PNL leakage,
  hidden-SSID disclosure all live here.
- [[views-catalog]] — full view index.
