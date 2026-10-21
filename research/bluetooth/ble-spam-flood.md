---
source_url: https://www.bleepingcomputer.com/news/security/flipper-zero-can-now-spam-android-windows-users-with-bluetooth-alerts/
retrieved: 2026-10-21
topics: [bluetooth, ble, advertising, flood, flipper-zero, swift-pair, fast-pair, continuity, denial-of-service]
alert_kinds: [ALERT_TYPE_BLE_ADV_FLOOD]
citation: BleepingComputer (Bill Toulas, 2023-10-25), "Flipper Zero can now spam Android, Windows users with Bluetooth alerts"; Bitdefender HOTforSecurity (2023-10-27), "Evolving Threat: Flipper Zero 'Spam Attacks' Now Target Android and Windows Devices"; the BLE Spam application source, Next-Flip/Momentum-Apps ble_spam/ (ble_spam.c, protocols/continuity.h, continuity.c, swiftpair.c, fastpair.c, easysetup.c); Apple, "About the security content of iOS 17.2 and iPadOS 17.2" (HT214035, 2023-12-11)
---
# BLE advertising spam — what the tool sends, and what that does not tell us

The source `BLE_ADV_FLOOD` (#144 slice 4) is built on. Read and quoted
on 2026-10-21. The coverage establishes that the attack exists and what
it targets; the tool's own source is the only document found that says
what goes on the air, and it is therefore what the spam list in
`src/ble_flood.c` rests on.

## The coverage

BleepingComputer, 2023-10-25 (Bill Toulas): the BLE Spam app offers
"eight flood attack options, including: Every method combined, iOS 17
Lockup Crash, Apple Action Modal, Apple Device popup, Android device
pair, Windows Device Found." The attack uses the Flipper Zero's
"wireless communication capabilities to spoof advertising packets and
transmit them to devices in range of pairing and connection requests",
and the article reports the Xtreme firmware's claim of "a denial of
service (DoS) attack on a Samsung Galaxy device, where a constant feed
of connection notifications renders the device unusable."

Bitdefender, 2023-10-27: the attacks were "initially targeted at Apple
devices using Bluetooth Low Energy (BLE) technology" and now "extend to
Android and Windows devices"; "The latest iteration of these spam
attacks, dubbed 'BLE Spam,' consists of six different flood attacks,
each tailored to a specific platform, including iOS, Android and
Windows." Mitigations named: disable "Show notification" in Nearby
Share on Android 14, and "Show notifications to connect using Swift
Pair" on Windows.

Neither article gives a company ID, a payload layout, an advertising
rate or anything about addresses. Neither can be a source for a
detector threshold.

## The tool's source (primary for the payload keys)

Next-Flip/Momentum-Apps, `ble_spam/`, read 2026-10-21:

- `protocols/continuity.h`: `ContinuityTypeProximityPair = 0x07`,
  `ContinuityTypeNearbyAction = 0x0F` (with AirDrop 0x05, AirplayTarget
  0x09, Handoff 0x0C, TetheringSource 0x0E, NearbyInfo 0x10).
  `continuity.c` writes `0xFF; // AD Type (Manufacturer Specific)`,
  `0x4C; // Company ID (Apple, Inc.)`, then the type byte. Its custom
  crash packet writes `ContinuityTypeNearbyAction` and carries the
  comment "CRASH FIXED IN IOS 17.2".
- `protocols/swiftpair.c`: `0xFF; // AD Type (Manufacturer Specific)`,
  `0x06; // Company ID (Microsoft)`, `0x03; // Microsoft Beacon ID`,
  `0x00; // Microsoft Beacon Sub Scenario`, `0x80; // Reserved RSSI
  Byte`, then the device name.
- `protocols/fastpair.c`: `0x03; // AD Type (Service UUID List)` with
  `0x2C, 0xFE` "(Google LLC, FastPair)", then `0x16; // AD Type (Service
  Data)` with the same UUID and a 24-bit device model.
- `protocols/easysetup.c`: `0x75; // Company ID (Samsung Electronics
  Co. Ltd.)`, followed by `0x42` (the buds packet) or `0x01` (the watch
  packet).
- `ble_spam.c`: `randomize_mac()` is
  `furi_hal_random_fill_buf(state->config.address, sizeof(state->config.address));`.
  `start_extra_beacon()` sets `config->min_adv_interval_ms = delay;`,
  `config->max_adv_interval_ms = delay * 1.5;`, then
  `if(payload->random_mac) randomize_mac(state);` before building and
  starting each payload, with `delay` from
  `static uint16_t delays[] = {20, 50, 100, 200, 500};`. `adv_thread()`
  loops `start_extra_beacon(state);`,
  `furi_thread_flags_wait(true, FuriFlagWaitAny, delays[state->delay]);`,
  `furi_hal_bt_extra_beacon_stop()` — so with `random_mac` set, every
  payload goes out on a new address and is held for one delay. Before
  the loop, `if(!payload->random_mac) randomize_mac(state);`: one
  address for the whole run otherwise. Re-read 2026-10-21 at the
  `dev` branch, last commit to the file `cfea009e` (2024-09-02).
- `ble_spam.c` `attacks[]`: `.random_mac = true` for "The Kitchen
  Sink" (`.protocol = NULL`: a random protocol per payload), "BT
  Settings Flood", "Android Device Connect" (Fast Pair), "Samsung Buds
  Popup", "Samsung Watch Pair", "Windows Device Found" (Swift Pair) and
  the two LoveSpouse entries; `.random_mac = false` for "iOS 17 Lockup
  Crash", "Apple Action Modal" and "Apple Device Popup".

So the keys `src/ble_flood.c` lists — (0x004C, 0x07), (0x004C, 0x0F),
(0x0006, 0x03), (0x0075, 0x42), (0x0075, 0x01), Service Data 0xFE2C —
are each documented by the tool that sends them. The per-payload
address, held for one 20–500 ms delay, is why **fresh** addresses (new
to the key since the windows before) and rate are the observables: the
tool's addresses do not outlive a window, and a crowd of genuine
devices on the same key keeps its addresses from window to window. That
is the distinction `BLE_ADV_FLOOD` gate 1 draws; counting addresses
*present* instead fired on 25 stable Fast Pair advertisers at a 250 ms
interval (the slice 4 review's probe).

The Apple attacks are the exception the source itself shows: their
`random_mac = false` means one address per run, so the tool floods
Apple keys from many addresses only in Kitchen Sink mode, mixed with
every other protocol. A single-address Apple flood is a different shape
(one advertiser at a high rate), and no source gives a rate at which a
genuine device stops; sloth does not detect it.

## Apple HT214035

"About the security content of iOS 17.2 and iPadOS 17.2", released
December 11, 2023, lists two Bluetooth entries: CVE-2023-45866 ("An
attacker in a privileged network position may be able to inject
keystrokes by spoofing a keyboard", Marc Newlin of SkySafe) and
CVE-2023-42941 ("An attacker in a privileged network position may be
able to perform a denial-of-service attack using crafted Bluetooth
packets", Christopher Reynolds). The page does not name the Flipper or
BLE Spam. The tool's own comment says its crash was fixed in 17.2; sloth
does not claim that CVE-2023-42941 is that crash, and the rule depends
on neither.

## Why sloth cites this

`ALERT_TYPE_BLE_ADV_FLOOD` fires when one window on one documented key
holds many addresses at a high rate. T1499 (Endpoint Denial of Service):
the cost is the receiving device's pairing UI.

## What it does not say

- **No threshold.** Nothing above measures how many genuine AirPods,
  Surface mice or Fast Pair headsets advertise in a crowded room. Every
  listed key is also what a genuine device sends. That is why the rule
  requires all three gates, why none can be switched off, and why the
  defaults (`ble.flood_distinct_addrs` 20 fresh addresses,
  `ble.flood_rate` 10/s over a 10 s window) are described as a
  judgement, not a cited value. The source backs gate 1's *form*
  (fresh, not present), not its number.
- **No attribution to a Flipper.** The same payloads come from an
  nRF52 board, an ESP32 or a laptop running the same code. The finding
  names a payload family at flood volume, not a device.
- **No rate at the receiver.** The 20–500 ms interval is the
  transmitter's. A host controller with duplicate filtering on reports
  each address once; an Ubertooth hears one channel of three. Both make
  the observed rate a lower bound.
- The tool's other Continuity types (AirDrop, Handoff, ...) are not on
  the list: the coverage names Device popup and Action Modal as the
  Apple floods, and those are the two types the tool sends for them.
