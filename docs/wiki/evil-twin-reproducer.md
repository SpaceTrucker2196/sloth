# Evil-twin reproducer

scapy snippets for replaying each detection layer against a running
sloth instance. **Live testing only** — none of this is wired into the
unit test suite (sloth's parser tests are hand-crafted byte arrays per
project discipline; see `CLAUDE.md` § "Hand-crafted protocol tests").

These snippets assume:

- sloth running on a wireless adapter in monitor mode, with `-i wlan0mon`
  and (for Phase 4) `--eapol-dir /tmp/eapol-out`.
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

real  = "aa:bb:cc:01:02:03"
twin  = "11:22:33:44:55:66"        # different OUI
sendp([beacon(real, "Cafe-Net"),
       beacon(twin, "Cafe-Net")], iface="wlan1mon", inter=0.1, count=20)
```

Expected: `EVIL_TWIN` WARN alert with key `twin-fp:Cafe-Net`; row
appears in `[x] Twins`.

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

**Attacker OUI bonus**: swap the twin BSSID to `00:13:37:..` (Hak5) or
`24:0a:c4:..` (Espressif) and the same WARN→CRIT escalation fires even
without distinct vendor-IE bodies. Detail will read "attacker-tool OUI
present".

## Phase 3 — RSSI step (proximity)

scapy can't fake an adapter-level RSSI step directly — the RadioTap
`dbm_antsignal` field is set by the receiving radio, not the sender.
Reproduce by either:

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

Expected within 5 s of the last deauth:

- `EVIL_TWIN` CRIT alert with key `twin-chain:Cafe-Net`, detail
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
