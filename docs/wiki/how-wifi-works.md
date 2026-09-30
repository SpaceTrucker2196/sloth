---
name: how-wifi-works
description: 802.11 reference — bands, channels, frame classes, the join sequence, security generations, roaming, MAC randomisation — the ground truth each sloth WiFi view reads
type: reference
---

# How Wi-Fi works

**Summary**: A protocol reference for 802.11, in the order a client
experiences it: PHY and channels, the three frame classes, the
discover → authenticate → associate → key sequence, the security
generations, roaming, and MAC randomisation. Every section ends with
**where sloth sees it**, because this page is the ground truth the WiFi
views and detectors read from.

**Sources**: `src/capture/capture.c`, `src/platform/linux_wifi.c`,
`docs/views/{beacons,probe,wifi,channel,eapol,assoc,seqnum,deauth}.md`,
IEEE 802.11-2020.

**Last updated**: 2026-09-30.

---

## 1. The radio and the channels

Wi-Fi is radio. A station and an access point (AP) agree on a **channel**
— a centre frequency and a width — and share the air on it. Only one
radio can transmit on a channel at a time, so 802.11 is *listen before
talk*: a device waits for the channel to go quiet, then sends.

- **2.4 GHz** — channels 1–14, 20/40 MHz wide. Long range, crowded,
  only three non-overlapping channels (1, 6, 11).
- **5 GHz** — many more channels, 20/40/80/160 MHz wide. Shorter range,
  far more capacity. Some channels require DFS (radar avoidance).
- **6 GHz** — added by Wi-Fi 6E, huge clean spectrum, 802.11ax/be only.

A monitor-mode radio hears **one channel at a time**. To see the whole
band it must retune — *channel hopping*. That is the one-at-a-time
trade every passive sniffer lives with.

**Where sloth sees it**: the Channel view `[m]` is a per-channel
activity histogram. `--hop` retunes sloth's own monitor interface across
a band list, dwelling longer where activity is seen (`src/platform/linux_wifi.c`).

## 2. The three frame classes

Every 802.11 frame is one of three types. Sloth reads all three off the
monitor interface; a normal (managed-mode) NIC only ever hands up the
data frames addressed to it.

| Class | Purpose | Examples | Sloth view |
|-------|---------|----------|------------|
| **Management** | Build and tear down the link | Beacon, Probe Req/Resp, Auth, (Re)Assoc, Deauth, Disassoc, Action | Beacons `[b]`, Probe `[7]`, Assoc `[w]`, Deauth `[a]` |
| **Control** | Coordinate access to the air | RTS/CTS, ACK, Block-Ack | Deauth-view flood counters, [[fragattacks]] |
| **Data** | Carry the actual payload | The IP traffic, once associated | Packets `[4]` and every L3+ view |

Management frames are the SIGINT-rich class: most of them are sent
**unencrypted** even on a protected network, so a passive listener reads
them without any key. That is why so much of sloth's Wi-Fi work lives in
the management-frame views.

## 3. The join sequence

A client goes from "nothing" to "passing traffic" in four steps. Each
step is observable.

1. **Discover.** The client learns which APs exist, two ways at once:
   - *Passive* — it listens for **Beacons**, which every AP broadcasts
     ~10×/second carrying the SSID, supported rates, channel, and the
     security parameters (the RSN information element).
   - *Active* — it broadcasts **Probe Requests**. A directed probe names
     an SSID it remembers; APs with that name answer with a Probe
     Response. The list of names a device probes for is its **Preferred
     Network List (PNL)** and it leaks verbatim.
   - **Sloth**: Beacons `[b]`, Probe `[7]`, PNL `[k]`.

2. **Authenticate.** In modern networks this is *Open System* auth — a
   two-frame formality that predates real security; the actual
   authentication happens later in the key exchange. (Legacy WEP shared-
   key auth is the exception, and is itself a weakness.)

3. **Associate.** The client sends an **Association Request**; the AP
   replies with an **Association Response** and an association ID. The
   client is now "on" the AP but cannot yet pass protected traffic.
   - **Sloth**: Assoc `[w]` records confirmed STA↔AP pairings, graded by
     evidence (EAPOL is definitive; (Re)Assoc responses are strong).

4. **Key.** On WPA2/WPA3 the AP and client run a **4-way handshake**
   (EAPOL) that proves both sides know the passphrase and derives fresh
   session keys. After this, data frames are encrypted.
   - **Sloth**: EAPOL `[e]` captures the handshake and the PMKID; see
     [[wifi-sigint]] and §4 below.

## 4. Security generations

| Gen | Auth / key exchange | Confidentiality | Notes |
|-----|--------------------|-----------------|-------|
| **Open** | none | none | Everything is readable in the clear. Sloth flags open onboarding APs (`OPEN_SETUP_AP`). |
| **WEP** | shared-key / RC4 | broken | Trivially recoverable. Treated as insecure everywhere. |
| **WPA/WPA2-PSK** | 4-way handshake, PSK | CCMP (AES) | The handshake is passively capturable; the PSK is offline-guessable from it. |
| **WPA2-Enterprise** | 802.1X / EAP + RADIUS | CCMP | Per-user auth; the EAP identity and method are visible. See [[enterprise-rogue]]. |
| **WPA3-SAE** | Dragonfly (SAE) | CCMP/GCMP | No offline handshake crack; PMF (management-frame protection) is mandatory. |
| **WPA3-Enterprise** | 802.1X + PMF | GCMP-256 optional | Highest assurance tier. |

Two facts drive most of sloth's WiFi detectors:

- **The WPA2 4-way handshake and the PMKID are visible to a passive
  listener.** They do not reveal the passphrase directly, but they let
  an offline guess *verify itself* — so a weak passphrase falls. Sloth
  exports what it captures in hashcat 22000 format precisely so an
  operator can test their **own** network's passphrase strength. See
  [[wifi-sigint]] and [[monitor-mode]].
- **Management-frame protection (PMF/802.11w)** signs management frames.
  Without it, forged Deauth/Disassoc frames are accepted by clients —
  the classic disconnect. WPA3 makes PMF mandatory; that is the biggest
  practical security jump between WPA2 and WPA3.

## 5. Roaming

A client moving between APs on the same network (same SSID, different
BSSID) *roams*. The 802.11 amendments that smooth this — **802.11k**
(neighbour reports), **802.11v** (BSS Transition Management steering),
**802.11r** (fast transition) — are all management-frame machinery, and
all observable. They are useful, and they are also a lever: a BTM steer
can move a client toward a chosen BSSID with no Deauth frame at all
([[btm-abuse]], [[action-frames]]).

## 6. MAC randomisation

Modern OSes (iOS, Android 8+, macOS, Windows 10+) use a **random MAC
address** when probing for networks while unassociated, so a device
cannot be trailed by a fixed hardware address. The locally-administered
bit is set on the first octet (`02:`, `06:`, `0a:`, `0e:` …).

Randomisation hides the *address*, not the *device*. Two signals survive
it, and sloth reads both:

- The **PNL** — the SSID list a device remembers is stable across
  rotations (PNL view `[k]`).
- The **sequence number** — the 12-bit counter in every 802.11 header
  runs forward per-radio and does not reset on a MAC change, so frames
  from one physical radio fall on one counter trail ([[mac-randomisation]],
  Seqnum view `[j]`). This is a *hypothesis about a radio*, never an
  identification of a person; `--no-correlate` turns it off.

## Related pages

- [[what-sloth-does]] — the tool built on top of all this.
- [[monitor-mode]] — how sloth gets to hear frame classes at all.
- [[wifi-sigint]] — the SIGINT primitives (PNL, EAPOL, seqnum, assoc).
- [[wifi-sigint-techniques]] — the passive techniques an analyst applies.
- [[where-exploits-happen]] — which step in §3 each attack targets.
- [[mac-randomisation]] — the seqnum deanonymisation primitive in full.
- [[wifi-state-of-the-art]] — where 802.11 is heading (Wi-Fi 7 / 8).
