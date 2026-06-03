# Twins  `[x]`

Materialised view of detected evil-twin episodes. One row per
same-SSID + same-cipher + diff-OUI pair, with the Phase 2/3/4 signal
sources merged in.

## Protocol / data source

Built passively from `s->beacon_aps[]` plus state held in the alert
engine (`evil_twin_bssid_is_tainted()`). No new radio traffic — every
input is already captured by the beacon snooper, the deauth tracker,
or the EAPOL log.

## What sloth captures

Per episode: SSID, real BSSID, twin BSSID, shared encryption, last
observed RSSI on each side, the twin's RSSI swing in the last 60 s,
and three flags:

- **attack_in_progress** — the chain rule has tainted the twin BSSID
  (a recent `DEAUTH_FLOOD` targeted the real half within 5 s).
- **attacker_oui** — the twin's OUI matches the Hak5 (Pineapple /
  Alfa) or Espressif (ESP32 / ESP8266) tables in
  `src/wifi_oui_attacker.c`.
- **hash_mismatch** — the two APs' vendor-IE fingerprint hashes (FNV-1a
  over non-Microsoft tag-221 IEs) disagree.

"Real" / "twin" assignment defaults to the lower-RSSI side being real
(a distant legit AP overshadowed by a close rogue). When the chain
rule has tainted a BSSID, that override pins the assignment.

## View

```
 ── Twins ────────────────────────────────────────────────────────
 Evil-twin episodes: 1 / max 64  attack-in-progress: 1
 SSID                Real BSSID         Twin BSSID         Cipher  Swing  Flags   Last
 ------------------  -----------------  -----------------  ------  -----  ------  ----
 Cafe-Net            aa:bb:cc:01:02:03  11:22:33:44:55:66  WPA2    18dB   !@#     3s
 flags: ! attack-in-progress  * attacker OUI  # vendor-IE hash mismatch
```

The twin column is bright (the suspected rogue gets the operator's
attention); the real column dim.

## What's normal

- Zero rows. Most networks do not host a same-SSID pair with
  different vendor OUIs.
- A single row with all flags off, low RSSI swing, no taint: usually
  a multi-vendor mesh deployment. Worth a glance; not an attack.

## What's suspicious

- **`attack_in_progress` set** — `rule_evil_twin_attack_chain` has
  observed a `DEAUTH_FLOOD` against the real BSSID within 5 s of the
  twin appearing. This is the textbook
  [evil-twin handshake-capture pattern](https://attack.mitre.org/techniques/T1557/004/):
  jam the real AP, force clients to re-associate, capture the EAPOL
  4-way against the rogue. Any subsequent EAPOL captures against the
  twin BSSID are tagged `# provenance=tainted-evil-twin` in the
  `eapol.22000` export.
- **`attacker_oui` set** — the rogue's BSSID prefix is on the Hak5 or
  Espressif lists. Combined with twin-pair geometry, this is a strong
  signal: legit APs from those vendors rarely overlap a competitor's
  SSID on the same cipher.
- **`hash_mismatch` set** — the two APs claim to be the same network
  but their beacon vendor-IE bodies don't match. Stock firmware emits
  IEs in a stable order; a rogue mimicking only the SSID and cipher
  produces a different hash. CERT/CC VU#871675 (hostapd/wpa_supplicant
  WPA3/SAE) and CVE-2022-23303 / -23304 describe related
  vendor-IE-driven attack surfaces.
- **High RSSI swing on the twin** — a rogue being switched on / moved
  closer mid-capture (Pineapple in a backpack, ESP32 booting). Phase 3
  fires `EVIL_TWIN_PROXIMITY` independently when the swing crosses
  15 dBm.

## See also

- [beacons.md](beacons.md) — source of every twin episode; SSID rows
  carry the same flag glyphs (`!@#~*`).
- [deauth.md](deauth.md) — the `DEAUTH_FLOOD` that triggers the chain.
- [eapol.md](eapol.md) — where the `tainted-evil-twin` provenance
  marker lands in the `.22000` export.
- [alerts.md](alerts.md) — the underlying rules (`rule_evil_twin`,
  `rule_evil_twin_proximity`, `rule_evil_twin_attack_chain`).
- JSONL `twin_episode` record — see
  [jsonl-schema](../wiki/jsonl-schema.md#twin_episode).
