# View docs

One file per sloth view. Each covers:

1. **Protocol / data source** — what's actually on the wire (or what
   kernel surface we read).
2. **What sloth captures** — the fields the view exposes.
3. **View** — a text mockup showing realistic output.
4. **What's normal** — baseline expectations.
5. **What's suspicious** — anomalies and attacks to watch for, with
   links to references.

## Observation (data straight from the wire / kernel)

| Key | View | Doc |
|-----|------|-----|
| `1` | Interfaces  | [interfaces.md](interfaces.md) |
| `2` | Connections | [connections.md](connections.md) |
| `3` | WiFi        | [wifi.md](wifi.md) |
| `4` | Packets     | [packets.md](packets.md) |
| `5` | Processes   | [processes.md](processes.md) |
| `6` | Stats       | [stats.md](stats.md) |
| `7` | Probe       | [probe.md](probe.md) |
| `8` | ARP         | [arp.md](arp.md) |
| `9` | mDNS        | [mdns.md](mdns.md) |
| `0` | NBNS        | [nbns.md](nbns.md) |
| `d` | DHCP        | [dhcp.md](dhcp.md) |
| `s` | SSDP        | [ssdp.md](ssdp.md) |
| `b` | Beacons     | [beacons.md](beacons.md) |
| `a` | Deauth      | [deauth.md](deauth.md) |
| `h` | HTTP        | [http.md](http.md) |
| `t` | TLS         | [tls.md](tls.md) |
| `u` | QUIC        | [quic.md](quic.md) |
| `r` | DNS         | [dns.md](dns.md) |
| `p` | NTP         | [ntp.md](ntp.md) |
| `i` | ICMP        | [icmp.md](icmp.md) |

## Synthesis (derived from observation)

| Key | View | Doc |
|-----|------|-----|
| `v` | Alerts    | [alerts.md](alerts.md) |
| `g` | Devices   | [devices.md](devices.md) |
| `o` | Dashboard | [dashboard.md](dashboard.md) |

## Quick map of protocols to attacks

Useful entry points if you're hunting for a specific threat class:

| Threat                          | Start here |
|---------------------------------|------------|
| DGA / DNS tunnelling            | [dns.md](dns.md) |
| TLS downgrade / weak crypto     | [tls.md](tls.md) |
| Implant / C2 fingerprint        | [tls.md](tls.md), [alerts.md](alerts.md) (BEACONING) |
| ARP spoofing / MITM             | [arp.md](arp.md) |
| Rogue DHCP                      | [dhcp.md](dhcp.md) |
| Evil-twin / WPA capture         | [beacons.md](beacons.md), [deauth.md](deauth.md) |
| Probe-request PNL leakage       | [probe.md](probe.md) |
| Responder / LLMNR poisoning     | [nbns.md](nbns.md) |
| UPnP-IGD abuse / CallStranger   | [ssdp.md](ssdp.md) |
| NTP amplification               | [ntp.md](ntp.md) |
| ICMP tunnel / RA flood          | [icmp.md](icmp.md) |
| Port scan                       | [alerts.md](alerts.md) (PORT_SCAN) |
| Credential stuffing on HTTP     | [http.md](http.md) |
