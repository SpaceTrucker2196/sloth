# Twins  `[x]`

Materialised view of evil-twin **candidate** pairs. One row per
same-SSID + same-cipher pair that carries positive impersonation
evidence, with the Phase 2/3/4 signal sources merged in.

Reads the same `twin_evidence_score()` the `EVIL_TWIN` rule does, so the
view and the alert cannot disagree about a pair.

## Protocol / data source

Built passively from `s->beacon_aps[]` plus state held in the alert
engine (`evil_twin_bssid_is_tainted()`). No new radio traffic — every
input is already captured by the beacon snooper, the deauth tracker,
or the EAPOL log.

## What sloth captures

Per episode: SSID, the two BSSIDs, shared encryption, a confidence
percentage, last observed RSSI on each side, the RSSI swing in the last
60 s, the pair's class and wired-attachment state (#89 slice 3, below),
and four flags:

- **attack_in_progress** — the chain rule has tainted the twin BSSID
  (a `DEAUTH_FLOOD` against the real half met its threshold within the
  last 5 s).
- **attacker_oui** — the twin's OUI matches the Hak5 (Pineapple /
  Alfa) or Espressif (ESP32 / ESP8266) tables in
  `src/wifi_oui_attacker.c`.
- **hash_mismatch** — the two APs' vendor-IE fingerprint hashes (FNV-1a
  over non-Microsoft tag-221 IEs) disagree.
- **unattributed** (`?`) — nothing has established which half is the
  impostor. The two BSSID columns are the pair in canonical byte order,
  not an accusation.

`confidence` is how likely the pair is an impersonation. It is a
**separate number from the alert's severity**, which is how bad it would
be if true (#89). A row at 5 % is still a row: the operator gets to see
the weak candidate and decide, rather than having the detector decide
silently on their behalf.

## Which half is the impostor

Ranked by what the signal actually establishes:

1. An **operator-designated BSSID** (`--my-bssid`, #52) is never the
   impostor, and neither is one the **approved inventory** declares for
   this SSID (`--inventory`, #89 slice 2 — see
   [`docs/wiki/inventory.md`](../wiki/inventory.md)). Both are a human
   asserting ownership out-of-band, so they outrank everything inferred
   from the air, and the two are read together rather than ranked
   against each other: `inventory_verdict()` already unions
   `--my-bssid` into the approved set.
2. A BSSID the **deauth chain tainted** is the impostor — behaviour
   observed against that BSSID.
3. An **attacker-tool OUI** (Hak5 / Espressif) is the impostor — an
   observed device identity.
4. Otherwise **unattributed**: canonical BSSID order, `?` flag, no
   verdict.

Rule 4 replaced "the stronger signal is the impostor" in #89. **RSSI is
not ownership.** It is a fact about distance and antennas, and in the
commonest case it gets the answer backwards, because the operator's own
AP is usually the closest radio in the room — which the old rule read as
the rogue. Canonical ordering also stabilises the `twin_episodes`
primary key `(ssid, real_bssid, twin_bssid)`, which used to swap, and so
insert a duplicate row, whenever two RSSIs crossed.

A pair whose **both** halves are inventory-approved produces no episode
at all — the view and the alert share one scorer, so they cannot
disagree about whether a declared mixed-vendor deployment is a
candidate.

## What kind of AP, and is it on the wire (#89 slice 3)

The issue's last fix bullet asked this view to separate three things an
operator does very different work about:

| Category | Column value | What establishes it |
|---|---|---|
| Over-the-air impersonator | `impostor` | The inventory declares this SSID and a half is not an approved BSSID for it — **or** a hard RF signal (attacker-tool OUI, a BTM steer aimed at the pair) |
| Neighbouring AP | `neighbor` | An inventory is loaded, it declares an estate, and this SSID is not in it |
| Operator's own infrastructure | `declared` | Both halves are in the approved inventory |
| Nothing established | `?` | No inventory loaded and no hard signal — the day-one default |
| **Unauthorized AP on the wired network** | **not a class** | **Not decidable from RF. See below.** |

**The third category is deliberately not a class value.** It lives on a
separate `Wired` column that reads `?` on every row unless a correlator
that can actually see the wire has been registered — and nothing in-tree
registers one today, so in practice it reads `?` everywhere.

That is not an omission, it is the finding. Everything the twin family
reads — SSID, BSSID, cipher, vendor IEs, RSSI, 802.11k neighbour
reports — is carried in beacons a radio transmits, and none of it says
what that radio is plugged into. A Pineapple in a backpack on an LTE
uplink and a rogue bridged onto the access VLAN emit indistinguishable
beacons. The distinction lives on the wire: a switch CAM entry, a
controller's rogue-on-wire classification, a DHCP lease against the
AP's Ethernet MAC.

Inferring it anyway would be the same mistake slice 1 removed — RSSI,
a matching OUI and an unauthenticated neighbour report were each an
inference dressed as a fact — except on the claim with the heaviest
consequence, since "there is a rogue on your LAN" gets a switch port
shut. So the column says `?` and the status bar says
`wired correlation: none`, which distinguishes *nobody is looking* from
*nothing was found*.

The hook is `src/wired_attach.h`: an in-process registration seam a
future switch/controller/DHCP correlator fills. It is not a plugin
loader, not a control surface, and registering a correlator does not
authorise it to transmit — MISSION §2 applies to a correlator exactly
as it does to everything else here.

**Classification is a label, never a gate.** No class suppresses an
episode, changes a severity or moves a confidence. A classifier that
could silence a finding would be a new sole suppressor, which is the
bug this whole issue opened on — so `neighbor`, the value most tempting
to treat as "safe, drop it", still shows the row with its confidence
intact.

## View

```
 ── Twins ────────────────────────────────────────────────────────
 Evil-twin episodes: 2 / max 64  attack-in-progress: 1  wired correlation: none
 SSID                BSSID A            BSSID B            Cipher  Conf  Class     Wired  Swing  Flags   Last
 ------------------  -----------------  -----------------  ------  ----  --------  -----  -----  ------  ----
 CorpWiFi            aa:bb:cc:01:02:03  11:22:33:44:55:66  WPA2    60%   impostor  ?      18dB   !*#     3s
 Cafe-Net            11:22:33:44:55:66  99:88:77:66:55:44  WPA2    5%    neighbor  ?      -      ?       9s
 flags: ! attack-in-progress  * attacker OUI  # vendor-IE hash mismatch
        ? sides unattributed - candidate pair, neither half accused
 class: impostor over-the-air impersonation  neighbor outside the declared
        estate  declared both halves in the approved inventory  ? no inventory
 wired: ? not established - RF cannot show what a radio is plugged into;
        needs controller/switch/DHCP correlation (none registered)
```

The `Class` column is bright only on `impostor`. A `neighbor` or
`declared` row is the detector saying "not your problem" and should not
compete for attention. The `Wired` column is never bright on `?` —
highlighting a column sloth has no answer for would advertise the
absence as a finding.

`Wired` is asked only of the half something has actually accused. On an
unattributed (`?`) pair the two BSSID columns are canonical order, so
asking about `BSSID B` would pin a wired-attachment claim on whichever
BSSID sorted higher — the same shape of mistake as letting RSSI name
the impostor.

On an **attributed** row the B column is bright — that really is the
suspected rogue, and it gets the operator's attention. On a `?` row both
columns are dim: colouring one of them would accuse whichever BSSID
sorted higher.

The columns are headed "BSSID A / B" rather than "Real / Twin" for the
same reason. The old headings stated a verdict on every row, including
the rows where sloth had none.

## What's normal

- Zero rows. Most networks do not host a same-SSID pair carrying any
  positive impersonation evidence. A single-vendor multi-BSSID
  deployment with nothing else going on produces none — because there
  is no evidence to report, not because a matching OUI vouched for it.
- A `?` row at low confidence, flags otherwise off, low RSSI swing, no
  taint: usually a multi-vendor mesh or a range extender. Worth a
  glance; not an attack. This is the row that used to be suppressed
  entirely when either AP advertised the other as an 802.11k neighbour —
  which also meant an attacker could suppress it by advertising its
  target.

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
