---
name: monitor-mode
description: What monitor mode is, how it differs from managed/promiscuous, what it lets sloth gather that a normal NIC cannot, how to enable it, and its limits
type: reference
---

# Monitor mode

**Summary**: Monitor mode is the radio mode that lets a Wi-Fi interface
hand *every* 802.11 frame it hears up to userspace — management and
control frames included, from every device in range, not just the ones
addressed to you. It is the single capability that turns sloth from an
IP monitor into a Wi-Fi SIGINT tool. sloth **reads** a monitor interface;
it never puts one into monitor mode itself.

**Sources**: `src/platform/linux_wifi.c`, `src/capture/capture.c`,
`src/privdrop.c`, `docs/views/{wifi,probe,beacons}.md`, `README.md`
"WiFi SIGINT usage", IEEE 802.11-2020.

**Last updated**: 2026-10-15.

---

## The four NIC modes, and why the mode matters

A Wi-Fi radio can hear far more than it normally reports. The driver
mode decides how much reaches software:

| Mode | Hears | Reports to userspace | Can associate |
|------|-------|----------------------|---------------|
| **Managed** (normal) | its own AP | data frames addressed to this station | yes |
| **Promiscuous** | its own BSS | all data frames on the joined network | yes |
| **Monitor** | the whole channel | **every** frame — mgmt, control, data — from every device | no |
| **AP / mesh** | (transmit roles — out of scope, sloth never uses them) | | |

Promiscuous mode is the wired-Ethernet idea ported to Wi-Fi and it is
**not** enough for SIGINT: it still only sees frames on the network you
joined, and only data frames. Monitor mode is different in kind — the
radio stops being a member of any network and becomes a **listener on a
channel**. That is what exposes the management-frame class
([[how-wifi-works]] §2), which is where nearly all the passively-readable
intelligence lives.

## What monitor mode lets sloth gather

Because management frames are broadcast in the clear even on protected
networks, a monitor interface yields all of this **without any key**:

- **Every AP in range** — SSID (including hidden ones, revealed when a
  client probes or associates), BSSID, channel, supported rates, and the
  full security posture (RSN IE: ciphers, AKM suites, PMF state). Beacons `[b]`.
- **Every client in range** — even ones not associated to anything —
  from their Probe Requests, and the **PNL** (the SSIDs each remembers).
  Probe `[7]`, PNL `[k]`.
- **Who is on which AP** — from Association/Reassociation frames and the
  EAPOL handshake. Assoc `[w]`.
- **The WPA2 4-way handshake and PMKID** — capturable passively, which
  is what makes offline passphrase-strength testing of your **own**
  network possible. EAPOL `[e]`, [[wifi-sigint]].
- **The sequence-number trail** that survives MAC randomisation.
  Seqnum `[j]`, [[mac-randomisation]].
- **Attack frames on the air** — deauth/disassoc floods, forged action
  frames, fragmentation attacks, evil-twin beacons, KARMA responses.
  Deauth `[a]`, Twins `[x]`, KARMA `[y]`, FragAttacks `[c]`.
- **A signal reading (dBm)** per frame → rough proximity.

A managed-mode NIC sees **none** of the above. This is why the
`NO_MONITOR_MODE` alert exists: if sloth sees interfaces but none in
monitor mode, it says so, because every WiFi SIGINT view will be empty.

## Enabling it (external — sloth never does this)

sloth deliberately does not touch link state. You set the mode with a
standard tool *before* starting sloth:

```sh
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
# then:
sudo ./sloth --collect-handshakes --eapol-dir /tmp/sloth-eapol \
             -o /tmp/sloth.jsonl
```

`airmon-ng start wlan1` does the same and also kills interfering
processes. sloth auto-discovers the monitor interface at startup;
`--monitor-only` restricts the whole capture to it and fails closed if
none is found ([[cli-reference]]).

Requirements: a chipset+driver that supports monitor mode (not all do),
and `CAP_NET_ADMIN` / root. `--hop` additionally needs the driver to
accept channel retunes.

## Privileges while monitoring — why `CAP_NET_ADMIN` stays with `--hop`

sloth gives up privilege once the capture handles are open (#140,
default on for root runs; [[cli-reference]] "Privilege"). Two
capabilities matter here, and they are needed for different lengths of
time:

- **`CAP_NET_RAW`** — only to *open* the monitor radio's pcap handle
  (`pcap_open_live()` creates the `AF_PACKET` socket). Reading frames
  from an open handle needs nothing, so it is dropped straight after
  `probe_open()`.
- **`CAP_NET_ADMIN`** — for every `NL80211_CMD_SET_CHANNEL`. sloth does
  not hold an nl80211 socket open between retunes:
  `linux_wifi_set_channel()` opens a fresh one each time, and the kernel
  checks the capability per command. So a `--hop` run keeps
  `CAP_NET_ADMIN` effective for its whole life (`CapEff:
  0000000000001000`), and a run without `--hop` or `--allow-active`
  keeps nothing. Reading the scan cache, station dumps and INET_DIAG
  needs no capability.

One interactive consequence: the `[m]` retarget opens a **new** pcap
handle on another radio, which needs the `CAP_NET_RAW` a dropped run
no longer has. The new handle is opened before the old one is stopped,
so the refusal reports the pcap error in the radio status and the
current radio keeps capturing; restart sloth on the interface you want,
or run with
`--no-privdrop` on a dev box. A radio that re-enumerates under the
shipped unit is handled by `BindsTo=` and a restart, not a reopen
([[deployment]]).

## Limits — what monitor mode does *not* give you

- **One channel at a time.** The radio hears only its current channel;
  the rest of the band is silent to it until it retunes (`--hop`). A busy
  attacker on channel 36 is invisible while you dwell on channel 6.
- **No decryption.** Data-frame payloads on a protected network stay
  encrypted. Monitor mode exposes *metadata and management frames*, not
  the plaintext inside WPA2/WPA3 data frames.
- **No transmit.** Monitor mode is receive-only in sloth's use. sloth
  never injects — see [[what-sloth-does]] "What it never does".
- **Range is physics.** You hear what your antenna hears; a weak signal
  is a weak signal.
- **The driver's framing is applied before parsing, not trusted
  blindly** (#122, #123). Radiotap's FLAGS octet says whether the frame
  ends in a 4-octet FCS (`0x10`) and whether the driver padded the MAC
  header to a 4-octet boundary (`0x20`, DATAPAD). sloth strips the FCS
  and removes the pad before any parser sees the frame, so an
  FCS-including driver no longer reads as a stream of malformed beacons
  and a padded QoS EAPOL frame is not missed. A radiotap header that
  does not parse is refused at one gate shared by both monitor entry
  points and counted (`mon rt-reject` on the interfaces health strip).
  The evidence ring keeps the frame exactly as delivered, FCS and pad
  included. **Deferred:** a frame whose FCS the driver marked failed
  (`0x40`) still feeds RF quality, the evidence ring *and* the per-type
  parsers — whether its contents should be parsed at all is an open
  decision, not a settled one.
- **"Monitor mode" is not a transmit interlock.** The mode itself does
  not stop a radio transmitting — that is a property of sloth's code, not
  the mode. This is why sloth is explicit that `--hop` and `--allow-active`
  are the only kernel-state writes and both are opt-in.

## Related pages

- [[how-wifi-works]] — the frame classes monitor mode exposes.
- [[what-sloth-does]] — the tool this capability sits under.
- [[wifi-sigint]] — the SIGINT primitives built on captured frames.
- [[wifi-sigint-techniques]] — how an analyst uses the capture.
- [[where-exploits-happen]] — the attacks that ride the exposed frames.
