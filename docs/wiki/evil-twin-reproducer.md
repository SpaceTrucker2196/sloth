# Evil-twin reproducer

scapy snippets for replaying each detection layer against a running
sloth instance. **Live testing only** — none of this is wired into the
unit test suite (sloth's parser tests are hand-crafted byte arrays per
project discipline; see `CLAUDE.md` § "Hand-crafted protocol tests").

These snippets assume:

- sloth running on a wireless adapter in monitor mode, with `-i wlan0mon`
  and (for Phase 4) `--collect-handshakes --eapol-dir /tmp/eapol-out`
  (the opt-in is required; `--eapol-dir` alone exits 2).
- A second adapter able to inject — `wlan1mon` in the examples below.
- Python 3 with `scapy` installed (`pip install scapy`).
- Root / `CAP_NET_RAW` privileges on the injecting adapter.

The five reproducers map 1:1 to the Phase 1-4 detection layers + a
clean baseline.

## Phase 1 — Same-cipher diff-OUI twin (WARN)

```python
from scapy.all import (RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp)

def beacon(bssid, ssid, channel=6):
    return (RadioTap() /
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=bssid, addr3=bssid) /
            Dot11Beacon(cap=0x1104) /        # ESS + Privacy + ShortSlot
            Dot11Elt(ID="SSID", info=ssid) /
            Dot11Elt(ID="DSset", info=bytes([channel])) /
            # RSN IE: WPA2-PSK + CCMP, MFP off
            Dot11Elt(ID=48, info=bytes.fromhex(
                "0100"               # version
                "000fac04"           # group: CCMP
                "0100" "000fac04"   # pairwise: CCMP
                "0100" "000fac02"   # AKM: PSK
                "0000")))            # RSN caps

real  = "a8:bb:cc:01:02:03"        # globally administered (see below)
twin  = "11:22:33:44:55:66"        # different OUI
sendp([beacon(real, "Cafe-Net"),
       beacon(twin, "Cafe-Net")], iface="wlan1mon", inter=0.1, count=20)
```

Expected: `EVIL_TWIN` WARN alert with key `twin-fp:Cafe-Net`; row
appears in `[x] Twins`.

Both addresses must be globally administered (bit `0x02` of the first
octet clear). Since #188 a locally administered BSSID has no OUI to
compare, so the `aa:bb:cc:..` address this page used before earns no
"vendor OUI differs" credit and Phase 1 raises nothing with it.

## Phase 2 — Vendor-IE delta (escalates to CRIT)

Build two beacons whose tag-221 vendor IEs differ (and aren't the
Microsoft 00:50:F2 WPS IE):

```python
def beacon_with_vendor_ie(bssid, ssid, vendor_payload):
    b = beacon(bssid, ssid)
    return b / Dot11Elt(ID=221, info=vendor_payload)

# Same prefix, distinct vendor body
real_v = bytes.fromhex("0017f205") + b"\x01\x02\x03\x04"   # Apple OUI
twin_v = bytes.fromhex("004096") + b"\x05" + b"\x99\xaa\xbb\xcc"
sendp([beacon_with_vendor_ie(real, "Cafe-Net", real_v),
       beacon_with_vendor_ie(twin, "Cafe-Net", twin_v)],
      iface="wlan1mon", inter=0.1, count=20)
```

Expected: the `twin-fp:Cafe-Net` alert is now CRIT with detail
"vendor-IE fingerprint differs".

Since #188 this needs both beacons on one band (the helper's
`channel=6` default does that; vendor IEs are not compared across
bands) and the different globally administered OUIs of Phase 1: the
mismatch alone is 35 % and a soft-signal CRIT needs 50 %. With a
same-OUI twin the row stays WARN.

**Late arrival** (ruling 3b on #188): a twin on a locally administered
address (say `02:9a:3c:71:5e:08`) has no OUI to differ, so sent together
with the real AP as above it is WARN at 35 %. Keep the real beacon on
the air, start the twin's beacon at least 120 s later
(`twin.late_arrival_s`), and the row is CRIT at 55 % with
`+late-arrival` in the detail and `>` in the `[x]` Twins flags. The
sensor must be at rest: a gpsd fix at 1 m/s or more restarts the wait.
The twin's BSSID must be new to the session under that SSID: if sloth
heard it beacon `Cafe-Net` earlier and dropped it (300 s of silence),
its return is not an arrival. Use a fresh BSSID, or clear the beacon
table, between runs.
The same delay on the Phase 1 pair with no vendor-IE mismatch changes
nothing: a late arrival corroborates other evidence and never raises a
row on its own.

**Attacker OUI bonus**: swap the twin BSSID to `00:13:37:..` (Hak5) or
`24:0a:c4:..` (Espressif) and the same WARN→CRIT escalation fires even
without distinct vendor-IE bodies. Detail will read "attacker-tool OUI
present".

## Phase 3 — RSSI step (proximity)

scapy can't fake an adapter-level RSSI step directly — the RadioTap
`dbm_antsignal` field is set by the receiving radio, not the sender.
Since #189 the swing is reported only for a BSSID that is half of an
`EVIL_TWIN` pair, so keep the Phase 1 pair on the air; the weakest
reading in the window must be above -92 dBm, and a sensor that gpsd
reports moving at 1 m/s or more stays silent. Reproduce by either:

- **Physical**: walk the twin radio toward sloth's antenna while
  re-broadcasting. A 15 dBm swing inside 60 s fires
  `EVIL_TWIN_PROXIMITY` with key `twin-prox:<bssid>`.
- **Two-rig**: keep one beacon source far (low TX power), bring up a
  second on the same BSSID at high power. Same effect; sloth observes
  the BSSID's RSSI jump.

## Phase 4 — Attack-chain (CRIT + EAPOL taint)

Send the twin pair as in Phase 1, then deauth-flood the real BSSID:

```python
from scapy.all import Dot11Deauth

deauth = (RadioTap() /
          Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff",
                addr2=real, addr3=real) /
          Dot11Deauth(reason=7))
sendp([deauth] * 20, iface="wlan1mon", inter=0.02)
```

Since #188 (ruling 4a) the chain needs a pair the scorer accepts, which
the Phase 1 pair is (two globally administered OUIs). A twin on a
locally administered address is named only with evidence of its own:
use the Phase 2 vendor IEs on one band. Two addresses at most 2 bytes
apart on different bands, first sent within 10 s of each other, are one
device and are not named.

Expected within 5 s of the last deauth:

- `EVIL_TWIN` CRIT alert with key `twin-chain:Cafe-Net:<16-hex hash>` (#112), detail
  `attack-in-progress: real=<real> twin=<twin>`.
- `evil_twin_bssid_is_tainted(twin)` returns 1 — visible via the
  `[x] Twins` view's `!` glyph.
- Any subsequent EAPOL handshake against the twin BSSID writes
  `eapol.22000` with a `# provenance=tainted-evil-twin bssid=<twin>`
  comment line above the `WPA*01*…` or `WPA*02*…` line. Hashcat skips
  `#` lines so the hash itself is still crackable; the comment is
  metadata for forensic review.

To exercise the EAPOL path, replay a captured 4-way against the twin
BSSID (any aircrack-ng / hcxdumptool capture works).

## Phase 5 — Clean baseline (no false fires)

```python
sendp(beacon(real, "Home-Wifi"), iface="wlan1mon", inter=1.0, count=10)
```

Expected: no `EVIL_TWIN*` alerts, no rows in `[x] Twins`. If anything
fires here, that's a regression in one of the rules.

## See also

- [twins](../views/twins.md) — the materialised episode view.
- [beacons](../views/beacons.md) — flag glyphs (`!@#*~`) on twin-cluster
  membership.
- [jsonl-schema](jsonl-schema.md#twin_episode) — the streaming record.
- [alerts](../views/alerts.md) — the underlying rule set.
