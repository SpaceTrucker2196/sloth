# Beacons  `[b]`

Passive 802.11 beacon sniffer — the APs visible to a monitor-mode iface.

## Protocol

APs send beacon frames periodically (typically every 100 ms) to
advertise their SSID, BSSID, supported rates, security, and other
parameters. The frames are unencrypted (the SSID could be "hidden" /
"cloaked" but that's mostly cosmetic — any associated client reveals
it via probe responses).

## What sloth captures

Per AP: SSID, BSSID (6-byte MAC), signal (dBm), channel, encryption
(`OPEN` / `WEP` / `WPA` / `WPA2` / `WPA3`), beacon interval (ms),
last-seen, frame count.

When the AP advertises a **QBSS Load** element (802.11e, tag 11), sloth
also records its self-reported occupancy: associated **station count**
and **channel utilisation** (0–255, a fraction of 255 — e.g. 128 ≈ 50 %
busy). This is a free congestion signal — no airtime maths, just what
the AP itself is broadcasting — and appears as `qbss_stations` /
`qbss_chan_util` in the `beacon` JSONL record (omitted when the IE is
absent, so consumers can tell "no data" from a genuine zero).

## WPS vendor-string leakage (#77)

When the AP's WPS IE carries the optional Manufacturer / Model Name /
Model Number / Serial Number attributes (WFA WPS 2.0 §12, IDs
`0x1021`/`0x1023`/`0x1024`/`0x1042`), the detail screen shows a `WPS ID:`
line beneath the `WPS:` state, e.g. `WPS ID: Realtek / RTL8196E (v1.2)
SN:1234567890`. Many SOHO routers and default hostapd/OpenWrt builds
broadcast these in plaintext on every beacon.

This is a passive fingerprinting/TSCM signal, not an attack detector: it
names what the AP says about itself, the same way `Vendor:` does from
the OUI. It needs no attribution to a specific tool to be useful — an
operator doing a sweep can search a site for a serial number, or notice
that a "different" SSID shares a model/serial with an AP they already
know. No signature table, no verdict, nothing unverified: the values
come straight off the wire, letter for letter. Absent when the WPS IE
carries none of these attributes (the common case) or `WPS:` is `-`.

Additive JSONL fields on the `beacon` record: `wps_manufacturer`,
`wps_model_name`, `wps_model_number`, `wps_serial` (all `""` when
absent). Not persisted to `--db` — like `#60f`'s `phy_confirmed` column,
a new field on an existing SQLite table needs a schema version bump that
invalidates every prior database file, and that cost isn't worth paying
for a display/forensic nuance already visible in the JSONL log.

## IE-ordering fingerprint (#77)

Every beacon's element list is hashed by *identity and order*: the
Element ID of each element, plus the extension ID for tag 255 and the
OUI + OUI type for tag 221, FNV-1a in the order they appear. Element
bodies are not hashed, so renaming the SSID or moving channel leaves it
unchanged; `vendor_ies_hash` already covers vendor-IE bodies.

IEEE 802.11-2020 §9.3.3.2 (Table 9-34) fixes the beacon element order,
but which optional elements a stack emits — and how faithfully it
follows that order — is a property of the software building the frame
(hostapd, a vendor SDK, ESP-IDF, a beacon-spam loop). Element presence
and order as a device fingerprint is the technique of Vanhoef et al.,
*Why MAC Address Randomization is not Enough* (AsiaCCS 2016), applied
there to probe requests; this is the AP-side analogue.

- **Transient elements are skipped**: Channel Switch (37), Quiet (40),
  Extended Channel Switch (60), Channel Switch Wrapper (196) and Quiet
  Channel (198) announce an event for a few beacons on an unchanged AP.
  Hashing them would make every DFS move look like a new stack.
- **A frame that overruns contributes nothing**: a truncated element
  list is a prefix, and its hash would name a stack that does not exist.
  `0` means not decoded; a later `0` never overwrites a real value.
- **Latest non-zero wins** per BSSID, same as `vendor_ies_hash`.

This is an observable, not a verdict. There is no table of known stack
hashes behind it — those are empirical facts about firmware that need a
capture to establish (see [`tool-fingerprints.md`](../wiki/tool-fingerprints.md)).
What it supports today is comparison: two BSSIDs claiming different
vendors but emitting the same element order, or a known AP whose order
changes mid-session.

Additive JSONL fields on the `beacon` record: `ie_order_hash`,
`ie_order_count` (elements that entered the hash). Monitor-mode only,
not shown in the TUI and not persisted to `--db` — the same placement
as `vendor_ies_hash`.

## Beacon TBTT jitter (#77)

How tightly an AP holds its own beacon schedule, measured on the AP's
clock rather than on ours.

Per IEEE 802.11-2020 §11.1.3 an AP schedules beacons at TBTTs that are
exact multiples of its Beacon Interval (in TU, §9.4.1.3; 1 TU = 1024
µs), and sets the beacon body's Timestamp field to its own TSF timer
value at transmission (frame body order 1, §9.3.3.2; field §9.4.1.10).
So for two beacons from one BSSID, the residual between the observed
TSF delta and the nearest whole multiple of the beacon interval is the
AP's medium-access deferral — how long it had to wait for a clear
medium past its scheduled TBTT.

Measuring from the transmitter's timestamp rather than from our
receive time is the whole point: the figure survives a receiver with no
radiotap TSFT, a hopping radio that hears the BSSID in bursts, and
dropped frames. A receive-clock jitter measure survives none of those.

- **First beacon from a BSSID** establishes the baseline and is not a
  sample; a residual needs two timestamps.
- **A delta that is an exact multiple** of the interval is a real
  sample with residual 0, not a frame to skip. A well-behaved AP on an
  idle channel genuinely does read 0.
- **Two frames landing on the same TBTT** (a retransmission, the same
  beacon captured twice) mean no interval elapsed — no sample, and the
  baseline is not moved by the duplicate.
- **No beacon interval** (absent or 0) means nothing to normalise
  against, so no sample.
- **The baseline is discarded** when the TSF runs backwards, when the
  AP changes its Beacon Interval, or when the delta implies an absence
  longer than `BEACON_AGE_SECS` (300 s). All three say the timer
  changed rather than the schedule — an AP reboot, or another radio
  adopting the BSSID — and samples taken against the old timer describe
  a different clock. `tbtt_jitter_resets` counts these; it is itself a
  signal, since a BSSID whose TSF keeps restarting is not one AP.
- **The accumulator decays** rather than saturating: at 1024 samples
  the count and both sums halve, which leaves the mean and mean-square
  intact while bounding the sums, so a long-lived AP reports a rolling
  figure instead of freezing on its first 1024 beacons.

The published quantity is the standard deviation. The mean residual is
offset by the unknown deferral of whichever beacon happened to
establish the baseline, so it is diagnostic only — the offset cancels
in the stddev, which is what makes the stddev meaningful at all.

**No threshold ships with this.** The issue quotes "real APs hold ±2
TU, Marauder-class firmware jitters 8-40 TU"; no source for those
numbers could be verified here, and `agents/AGENTS.md` requires a
detector to cite what it detects from. The measurement is
spec-grounded, the attribution is not, so only the measurement lands —
no alert rule, no TUI row, no signature table. What it supports today
is comparison: an AP whose jitter changes mid-session, or a BSSID whose
scheduling discipline does not match the gear it claims to be.

Additive JSONL fields on the `beacon` record: `tbtt_jitter_us`
(stddev in µs, 0 when fewer than 2 samples), `tbtt_jitter_samples`,
`tbtt_jitter_resets`. The sample count is what keeps a `0` stddev from
reading as "perfectly scheduled" when it really means "not enough
beacons yet". Monitor-mode only — the managed-mode nl80211 path is
handed an IE blob with no frame and so has no timestamp — not shown in
the TUI, and not persisted to `--db` for the same reason as the WPS
strings above: a new column bumps the schema and invalidates every
prior database file.

## View

```
 SSID                    BSSID               Sig   Ch  Enc    Pairwise   posture   AKM         WPS  Vendor     PHY       Last
 home_5g                 c8:0a:a9:1b:2c:3d   -42   36  WPA3   CCMP       REQ       SAE         -    Apple      Wi-Fi 6   2s
 corp-wifi               00:11:22:33:44:55   -55    6  WPA3   CCMP       WPA2+3    SAE,PSK     -    Cisco      Wi-Fi 6   1s
 legacy-net              de:ad:be:ef:00:01   -60   11  WPA2   CCMP       WPA1+RSN  PSK         ON   ?          Wi-Fi 4   4s
 (hidden)                d8:5d:4c:5e:6f:70   -71    6  WPA2   CCMP       cap       PSK         -    ?          Wi-Fi 5   9s
```

SSID names are coloured via the same hash-palette as Probe — same SSID
gets the same colour wherever it appears.

### The `posture` column

This column used to show MFP alone (`REQ` / `cap` / `-`). It still does
when the AP's posture is clean — but when the AP advertises a **weaker
lane beside its primary one** the column names that instead, heat-
coloured, because that is the finding (#62):

| Shown | Meaning |
|---|---|
| `WPA1+RSN` | a legacy WPA1 IE beside the RSN IE — TKIP still on offer |
| `WPA2+3` | PSK and SAE both in the AKM list — WPA3 transition mode |
| `OWE-tr` | an OWE BSS with a paired open companion BSS |
| `MFP-opt` | SAE with MFP capable-but-not-required — the Dragonblood primitive |
| `REQ` / `cap` / `-` | no downgrade lane; the MFP state as before |

Worst-first when several apply — the column has room for one, and an AP
still offering TKIP is a bigger problem than one whose MFP is merely
optional. The `[v]` Alerts view carries one `WPA_DOWNGRADE` alert per
lane, so nothing is lost by the column showing only the worst.

**None of these is an attack.** Each is a configuration the AP is
broadcasting about itself, and each is the prerequisite an attacker
needs: CVE-2023-52424 (SSID Confusion) and the Dragonblood family both
depend on the AP having offered the weak lane in the first place.

## What's normal

- Stable neighbour APs with consistent signal +/- a few dB.
- Beacon interval of 100 ms (= 102.4 ms, the standard).
- WPA2 / WPA3 encryption.

## Channel width (#66)

The `Ch` column shows the primary channel and the **operating width**:
`36/80` is a very different amount of spectrum from `36`. `80+`
means 80+80 MHz non-contiguous.

Until the operation IEs were decoded sloth treated every AP as 20 MHz,
which makes any airtime or occupancy answer wrong by up to a factor of
sixteen. Width comes from HT Operation (tag 61), VHT Operation (tag
192), HE Operation (255 ext 36) and EHT Operation (255 ext 106) — the
*operation* IEs, which say what the BSS is doing, as opposed to the
*capability* IEs, which say what the radio could do.

Two distinctions the parser is careful about, because both are easy to
get wrong in the direction that overstates:

- **40 MHz needs both** the HT width bit *and* a non-zero secondary
  channel offset. The width bit alone means "may use more than 20".
- **160 MHz and 80+80 are different.** Two 80 MHz segments whose centres
  are 8 apart are one contiguous 160; further apart is genuinely
  non-contiguous. Reporting the second as the first overstates
  contiguous spectrum by a factor of two.

A blank width means no operation IE was decoded — which is not the same
as 20 MHz, and the JSONL `operating_width` is `0` rather than `20` for
exactly that reason.

### The durable 6 GHz channel fix

The beacon channel used to come from the DS Parameter Set (tag 3),
which **much 6 GHz and HE gear omits entirely**. HE Operation's 6 GHz
Operation Info carries the authoritative primary channel, and it now
wins when both are present. The JSONL record carries `channel_source`
so a wrong channel is attributable rather than mysterious.

## Pending channel switches (#63)

When an AP is announcing a **Channel Switch**, the `PHY` cell is
replaced by `CSA>N` — the channel it is moving to — heat-coloured while
the switch is in flight. It is transient and the more urgent fact; the
PHY tier will still be there after the AP has moved.

A legitimate switch is DFS doing its job: the AP heard radar, it has to
leave, and it tells its clients where it is going. The abuse cases are
in `ALERT_TYPE_CSA_ABUSE` — a forged transmitter, several distinct
targets in a minute, or a destination channel that happens to host a
known rogue. Clients honour CSA, which is what makes it a quieter
alternative to a deauth flood, and it works on firmware that ignores
deauth entirely.

## RRM surveys (#61)

A footer line appears when 802.11k **Beacon Requests** have been seen:

```
 RRM surveys: 7 targeted requests in the last 300s, 3 reported back
```

A Beacon Request asks a client to scan and report what it can hear —
BSSIDs, channels, RSSIs. The client obliges, because that is what
802.11k is for. It is also how an AP enumerates the airspace *through
someone else's radio*, from a position its own antenna cannot reach,
and the report that comes back is precisely the input needed to build a
convincing evil twin.

The distinction the footer draws is between **targeted** requests (which
name a specific SSID in a subelement) and broadcast ones (which do not).
Only the first is a signal. `ALERT_TYPE_RRM_SURVEY_ABUSE` fires when the
asker has been heard beaconing *something* but has never advertised the
SSID it is asking about — a legitimate AP asks about its own networks.

The "has been heard beaconing something" half is the `--hop` guard: on a
channel-hopping sensor the AP inventory is a sample, so a BSSID we have
never heard tells us nothing about what it does or does not advertise.

## What's suspicious

- **A heat-coloured `posture` cell.** See the table above. A migration
  window is a legitimate reason to run WPA3 transition mode; a posture
  that has been there for weeks is a compliance finding. sloth reports
  the live state — "this AP is *currently* offering a downgrade path" —
  and leaves the duration judgement to the operator, since the AP table
  does not persist across runs unless `--db` is on.

- **Twin SSID** with different BSSID and stronger signal than the real
  AP — classic [evil-twin
  attack](https://en.wikipedia.org/wiki/Evil_twin_(wireless_networks)).
  An attacker is impersonating a network the target trusts so they
  associate to it instead.
- **OPEN encryption on a network that should be secured** — see also
  [karma attack](https://en.wikipedia.org/wiki/MAC_filtering#KARMA).
- **WEP** still in use. WEP has been broken since 2001.
- **Excessive beacon interval drift** — usually noise but could
  indicate a rogue AP with cheap/buggy firmware.
- **Hundreds of APs appearing at once** — see
  [mdk3 beacon flood](https://github.com/aircrack-ng/mdk4). Used to
  hide a real attack in noise.
- **Sudden signal jump** (an existing SSID's signal goes from -80 to
  -40) — someone planted a copy of your network closer to the target.

## See also

- Parser: [`src/beacon_snoop.c`](../../src/beacon_snoop.c).
- Probe-side counterpart: [`probe.md`](probe.md).
- Deauth-flood prelude: [`deauth.md`](deauth.md) (attackers often
  knock clients off the real AP to force them onto the evil twin).
