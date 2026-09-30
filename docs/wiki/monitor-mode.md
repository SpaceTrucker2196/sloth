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
`docs/views/{wifi,probe,beacons}.md`, `README.md` "WiFi SIGINT usage",
IEEE 802.11-2020.

**Last updated**: 2026-09-30.

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
sudo ./sloth --eapol-dir /tmp/sloth-eapol -o /tmp/sloth.jsonl
```

`airmon-ng start wlan1` does the same and also kills interfering
processes. sloth auto-discovers the monitor interface at startup;
`--monitor-only` restricts the whole capture to it and fails closed if
none is found ([[cli-reference]]).

Requirements: a chipset+driver that supports monitor mode (not all do),
and `CAP_NET_ADMIN` / root. `--hop` additionally needs the driver to
accept channel retunes.

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
