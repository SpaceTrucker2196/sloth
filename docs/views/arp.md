# ARP  `[8]`

The Layer 2 neighbour table — who has which MAC on which interface,
plus OUI vendor lookup.

## Protocol

ARP ([RFC 826](https://www.rfc-editor.org/rfc/rfc826)) maps IPv4
addresses to Ethernet MACs on a local segment. It's chatty,
unauthenticated, and completely trusts whoever answers — making it
the foundation of one of the oldest attacks in the book.

Sloth doesn't capture ARP packets directly; instead it reads the
kernel's resolved ARP table (`/proc/net/arp`), so what you see here
is what your host *currently believes* about its neighbours.

## What sloth captures

Per entry: IP, MAC (6 bytes), interface, vendor (from the embedded
OUI table in [`src/oui.c`](../../src/oui.c)).

## View

```
 ── ARP table ──────────────────────────────────────────────────
 ip              mac
 192.168.1.1     dc:a6:32:00:00:01    ← Raspberry Pi (OUI)
 192.168.1.100   b8:27:eb:11:22:33    ← Raspberry Pi
 192.168.1.150   aa:bb:cc:dd:ee:ff    ← (unknown vendor)
 192.168.1.255   ff:ff:ff:ff:ff:ff    ← broadcast
```

## What's normal

- The router's MAC is stable (matches the gateway's vendor).
- Devices come and go over hours / days.
- Each IP has exactly one MAC.

## What's suspicious

- **Same MAC, multiple IPs** in quick succession — could be a router
  doing proxy ARP, or could be **ARP spoofing**: an attacker claiming
  your gateway's IP to MITM your traffic. See
  [arpspoof(8)](https://github.com/ossec/dsniff) /
  [ettercap](https://www.ettercap-project.org/).
- **Same IP, different MAC** suddenly — the gateway's MAC changing
  mid-session is almost certainly an attack.
- **Locally-administered bit set** (the second-least-significant bit
  of the first MAC byte) on a "device" pretending to be a real
  manufacturer's hardware — randomised / spoofed MAC.
- **Multicast bit set** on a source MAC — these are never legitimate
  (the MAC space's all-multicast addresses are for destinations only).
- **Unknown vendor on critical infra**: a "?" vendor for your alleged
  gateway is worth investigating.

## See also

- OUI table: [`src/oui.c`](../../src/oui.c) — extend it with your own
  hardware as needed.
- See [`docs/views/devices.md`](devices.md) for the synthesised
  device record that joins ARP, DHCP, beacons, and probes.
