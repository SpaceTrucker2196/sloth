---
source_url: https://www.bluetooth.com/specifications/specs/core-specification-5-4/
retrieved: 2026-10-22
topics: [bluetooth, ble, privacy, address-rotation, rpa, nrpa, continuity, handoff, ms-cdp, fast-pair, tracking, correlation]
citation: Bluetooth Core Specification v5.4, Vol 3 Part C §10.7, §10.8, Appendix A; Vol 6 Part B §1.3.2, §4.4.2.2.1, §6.1; Vol 4 Part E §7.7.65.2, §7.7.65.13, §7.8.11, §7.8.45, §7.8.65, §7.8.122; Becker, Li, Starobinski, "Tracking Anonymized Bluetooth Devices", PoPETs 2019(3):50-65, doi:10.2478/popets-2019-0036; Celosia, Cunche, "Saving Private Addresses: An Analysis of Privacy Issues in the Bluetooth-Low-Energy Advertising Mechanism", MobiQuitous 2019, doi:10.1145/3360774.3360777; Celosia, Cunche, "Discontinued Privacy: Personal Data Leaks in Apple Bluetooth-Low-Energy Continuity Protocols", PoPETs 2020(1):26-46, doi:10.2478/popets-2020-0003; Martin, Alpuche, Bodeman, Brown, Fenske, Foppe, Mayberry, Rye, Sipes, Teplov, "Handoff All Your Privacy - A Review of Apple's Bluetooth Low Energy Continuity Protocol", PoPETs 2019(4), arXiv:1904.10600; Jouans, Carneiro Viana, Achir, Fladenmuller, "Associating the Randomized Bluetooth MAC Addresses of a Device", IEEE CCNC 2021, doi:10.1109/CCNC49032.2021.9369628; Alghamdi, Verna, Mellia, "Learning to Link: Automatic Re-identification of BLE Devices Under MAC Address Randomisation", WTMC 2026, arXiv:2609.26079; Microsoft [MS-CDP] 2.2.2.2.3 "Bluetooth: Advertising Beacon" (updated 2023-09-11); Google Fast Pair "Provider Advertising signal" (updated 2026-09-30); Apple Platform Security (August 2026)
---
# BLE address rotation — what can link two private addresses, and how far it goes

The basis for `--ble-rotation-hints` (#156 item 2, `src/ble_rotation.c`).
Every source below was read first-hand on 2026-10-22. Sources the
research found only cited through another paper (Akiyama et al. ICCE-Asia
2021/2023; Boussad et al. "McMatcher" ICCE 2024; Despres et al.
"DeTagTive" 2023) were **not** read and back nothing here.

**Verdict.** The sources support a *hint* — a possible link between two
private addresses — and not an alert kind, and not an identity claim.
The feature is internal use only and off by default (owner ruling
2026-10-23).

## The spec: payload continuity is the anomaly

Core v5.4 Vol 3 Part C (GAP):

- §10.7.1.1: "If the advertising data or the scan response data change
  regularly then those changes should be synchronized with any changes
  in private addresses (both local and remote)."
- §10.7.1 and §10.7.3: the device "should not send the device name or
  unique data in the advertising data" that can be used to recognize it.
- §10.7.4: an Observer's T_GAP(private_addr_int) "shall not be greater
  than 1 hour".
- Appendix A: T_GAP(private_addr_int) **15 min**, "Maximum time interval
  between private address change", a *recommended* value.

Vol 4 Part E (HCI) §7.8.45: RPA_Timeout 1 s to 1 hour, default 0x0384
(900 s). §7.8.122 (LE Set Data Related Address Changes) exists so the
controller can change the address when the data changes. Vol 6 Part B
(LL) §6.1: "It is recommended to set the timer to 15 minutes." §1.3.2:
the random sub-type is Address[47:46] — 00 non-resolvable private, 01
resolvable private, 11 static.

**Correction to the issue text.** #156 said "RPAs rotate every 5–15 min".
No source read gives that. The spec gives **a recommended maximum of
15 minutes** (and an Observer ceiling of 1 hour); observation gives
**seconds to days**: Windows 10 about 960 s (Becker) or 16 min (Celosia
2019), Apple 15 min (Martin 2019) but "seconds up to around two hours
... average of around 20 minutes" (Becker), RPAs carrying Nearby Info
held more than 4 days in power-saving mode (Celosia 2020), Android 15–45
min (Becker). Martin 2019 calls 15 min a "minimum" and Jouans says
devices "keep ... at least 15 minutes"; the spec says it is the
recommended maximum, so the spec is cited for the interval, not the
papers.

## Grade A: a documented token carried across the change

A token must be at least 40 bits (Becker's collision bound,
n ≥ log2(mk²/p): 39 bits for m = 1000, p = 1e-3) at a field position a
spec or a first-hand paper defines. Vendor constants are excluded:
the bound holds for random values, not shared prefixes, so fixed octets
inside a token's span are left out of what sloth digests (MS-CDP's four
leading octets, Handoff's first body octet, Fast Pair's 0x21 header).

| Token | Layout source | Carry-over source | Status |
|---|---|---|---|
| MS-CDP Salt (4) + Device_Hash (19), company 0x0006, Scenario_Type 1 | [MS-CDP] 2.2.2.2.3 | Becker ("last 23 bytes", static about 1 h while the address changes about every 960 s); Celosia 2019 (Device_Hash lives about 60 min against an address of about 16 min) | documented; current behaviour unverified |
| Apple Handoff body (14 octets) under 0x004C, Continuity type 0x0C, first octet excluded | Martin 2019 Fig. 2; Celosia 2020 Fig. 9 (no vendor spec) | Becker; Celosia 2019/2020 (IV not reset at the change); Martin 2019 (sequence number and data preserved across the private_addr_int expiry, iOS 9 to 12.3) | **unverified**: Jouans 2021 ran carry-over on iOS 12.4/13.x and "Apple appears to have patched the vulnerability" |
| Fast Pair Account Key Filter + Salt, Service Data 0xFE2C, non-discoverable form, filter of at least 5 octets | Fast Pair "Provider Advertising signal" | none: a match is the vendor ignoring the spec's "should" | matches only when the salt did not change; a 4-octet filter is under the bound (below) |

[MS-CDP] layout, read: Length 0x1E, 0xFF, Microsoft ID 0006, then
Scenario_Type (1, "Set to (1) Bluetooth scenario"), Version_and_Device_Type
(1), Version_and_Flags (1), Flags_and_Device_Status (1), Salt (4, "Four
random bytes"), Device_Hash (19, "SHA256 Hash of Salt plus Device
Thumbprint"). **Error in the source, flagged:** the page labels the
section "Beacon Data (24 bytes)", but its own fields sum to 27 and its
Length of 30 (type + ID + 27) agrees with 27; sloth requires 27. The
four leading octets are the fixed ones Becker excludes. The page says
nothing about when Salt and Device_Hash rotate.

Fast Pair, read: discoverable, "the BLE address shall not be rotated"
and the service data is the 24-bit Model ID (per model, not per
device), or the LE Audio Sharing form whose first field is type 0b0111.
Not discoverable: version 0x00, then 0bLLLLTTTT (T 0b0000 show UI or
0b0010 hide UI), the Account Key Filter of (1.2 n + 3) octets for
n ≥ 1 keys (so at least 4), then 0b00100001 and a 2-octet Salt. "This
salt should be regenerated every time the RPA is updated for the
Provider to avoid tracking across address rotation."

**Entropy of the Fast Pair token, worked.** Each account key sets at
most 8 bits of the filter. One key gives a 4-octet (32-bit) filter with
at most 8 bits set: at most log2(Σ C(32, j), j = 1..8) ≈ 23.8 bits, and
≈ 39.8 with the 16-bit salt — **under the 40-bit bound**, so sloth takes
no token from a 4-octet filter. Two keys give 5 octets with at most 16
bits set in 40: ≈ 37.1, ≈ 53.1 with the salt. These are ceilings, not
measured entropy: the set bits come from hashes of the keys, and in the
very case the row exists for (a vendor not regenerating the salt) the
salt may be a constant, leaving the filter alone.

Apple Platform Security (August 2026), read: Handoff advertisements are
encrypted and authenticated "using AES-256 in GCM mode, with replay
protection measures"; Find My's offline key is replaced "approximately
every 15 minutes". **It says nothing about payload/address
synchronisation and carries no fix note for the 2019 findings**, and no
Microsoft fix note was found either. Each token row is therefore
"documented, current behaviour unverified" until a capture on a current
OS shows it.

Not tokens: the Apple Nearby Info 3-octet Auth Tag (under the bound;
Celosia and Cunche 2020 §4.1 saw its change "not completely
synchronized" with the address change), and the 4-octet data field of
iOS 11 and 12 Nearby messages, which Martin 2019 §5 saw "remains
constant for one to two frames" across it — corroborators at most; the
Fast Pair Model ID (per model); any 16-bit UUID, company ID or
appearance (categories); iBeacon and Eddystone frames (fleets share
them by design).

## Grade B: exclusivity and a seam

Jouans et al. 2021: timing-only association links a disappear/appear
seam inside d_swap = 10 × T_int, solved by linear assignment, captured
with hcitool and btmon on a Raspberry Pi 4 — the same class of source as
sloth's HCI monitor. Measured mismatches are a lower bound (only brand
or advertising-type contradictions are detectable): 5/1087 pairs by
brand, 24/1088 by advertising type. Martin 2019 §6 makes the same
point: with every payload flaw fixed, a fixed 15-minute rotation is
still linkable from the stop/start seam alone. Timing-only linking is a
corroborator, never a finding.

sloth's frame clock reaches the device table at one-second resolution,
so T_int (20 ms to about 10,486 s per LL §4.4.2.2.1, in 10 ms bins per
Jouans) is not measured, and d_swap is fixed at 10 s — a judgement.

## Grade C: shape agreement (corroborators only)

Same Event_Type, payload family (company ID and first octet, or Service
Data UUID), and AD structure list with lengths. Alghamdi et al. 2026, on
14 current devices: advertising-data byte 3-grams carry 91.7% of a
classifier's importance, RSSI 3.2%, TX power 1.1%, SID 0.02% — but the
method is **supervised and target-specific**, no evidence for an
unlabeled passive any-device linker, and generic AD shared across
devices causes false associations. So shape corroborates and never
decides.

## Guards the sources call for

- **Replay and spam.** Celosia 2020 §5.1 replays Handoff messages; BLE
  spam tools put genuine Continuity payloads on fresh addresses
  (`research/bluetooth/ble-spam-flood.md`). A token heard on two
  interleaving addresses is poisoned, and no link forms while
  `BLE_ADV_FLOOD`'s fresh-address gate is active on the key. A replay
  sprayed on fresh addresses one after another never interleaves, so
  sloth also poisons a token first heard on three addresses inside one
  d_swap (no single advertiser rotates that fast), and judges the gate
  at commit as well as at each report. The poison window is the token's
  documented life, not the address interval: the MS-CDP last 23 octets
  "static about 1 h" (Becker), the Device_Hash about 60 min against an
  address of about 16 min (Celosia 2019) — 3600 s, where the 15-minute
  T_GAP(private_addr_int) would re-arm a token still live.
- **Concurrent addresses.** Martin 2019: macOS 10.13/10.14 sends Nearby
  on the public address while Handoff is active; Celosia 2019 saw names
  and 128-bit UUIDs that embed the public address. Static and public
  addresses never rotate and are never candidates; a resolved identity
  address (Address_Type 0x02/0x03, the operator's controller holding an
  IRK) is not rotating either.
- **Scanning.** Celosia 2019 **sent scan requests**; sloth does not
  (MISSION §2), so scan-response-only fields from that paper are
  unavailable. Duplicate filtering (HCI §7.8.11 Filter_Duplicates) and
  controller report coalescing hide timing: a filtering controller
  reports an address once, so an older address heard again after the
  newer one — what exclusivity and poisoning rest on — is never seen.
  sloth reads Filter_Duplicates from the host's own LE Set (Extended)
  Scan Enable and proposes no link on an HCI adapter where it is on or
  unknown. Coalescing below that is not visible and is not handled.
- **Freshness.** An entry is fresh for d_swap after its last report.
  sloth wipes an entry's digests and shape at 2 × d_swap of silence
  (d_swap, plus the d_swap a pending link waits), but keeps the address
  and its chain fields for 2 h: **a deviation**, because the
  exclusivity guard has to recognise the older address if it speaks
  again after its successor, and the chain caps read the chain's start.
- **Privacy.** The capability is itself longitudinal device correlation.
  Default off, keyed per run, never exported, bounded.

## How sloth words it

- Payload: "possible address rotation — corroborates one advertiser
  rotating its address; does not confirm it, and identifies no device or
  person."
- Timing only: "possible address rotation (timing only) ... Weak: another
  advertiser leaving and arriving reads the same." Timing-only links
  reach the `[*]` estimate (with this caveat) and never an alert: they
  do not reduce `BLE_HID_UNEXPECTED`'s count.
- Every surface: "These records alone are not grounds for personnel
  action or physical identification."
- Never "same device", "tracked", "identified" or "linked to" a person.

## Related

- `src/ble_rotation.h` — the implementation's contract.
- `docs/wiki/ble.md` — the operator-facing section.
- `research/bluetooth/ble-spam-flood.md` — the flood gate's basis.
