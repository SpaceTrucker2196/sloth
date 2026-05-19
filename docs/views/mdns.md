# mDNS  `[9]`

Multicast DNS / Bonjour / Zeroconf service table built from passive
UDP/5353 observation.

## Protocol

mDNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)) and DNS-SD
([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)) let devices on a
local link discover each other without a central DNS server. Apple's
Bonjour, Avahi on Linux, and most IoT gadgets all speak it.

Queries and responses go to `224.0.0.251:5353` (IPv4) or
`ff02::fb:5353` (IPv6). Service instances follow the form
`Name._service._proto.local` — for example
`Office Printer._ipp._tcp.local`.

## What sloth captures

Per service: instance name (`Name._service._proto.local`), service
type (`_ipp._tcp`), SRV target hostname, resolved IP (if seen),
port, last-seen.

## View

```
 ── mDNS services ──────────────────────────────────────────────
 instance                                           port
 My Office Printer._ipp._tcp.local                  631
 Apple TV._airplay._tcp.local                       7000
 iPhone._companion-link._tcp.local                  49500
 NAS._smb._tcp.local                                445
 _googlecast._tcp.local                             8009
```

(Instance column auto-stretches to the panel width — long names like
`Living Room Lights._hap._tcp.local` render in full.)

## What's normal

- A handful of devices per network — printer, TV, smart speakers,
  phones.
- Service types that match what's actually plugged in.

## What's suspicious

- **Hostname leak** of a device that shouldn't be on this network —
  `john-laptop._smb._tcp.local` showing up on a guest network reveals
  John's machine and possibly his SMB shares.
- **Unexpected service** advertisements — a host advertising
  `_ssh._tcp.local` it has no business running. Common malware/RAT
  pattern: drop a backdoor that advertises itself.
- **Probe spoofing**: a device claiming a hostname that doesn't match
  its OUI vendor. Tools like
  [mdns_recon](https://github.com/chenjj/CORScanner) /
  [pholcus](https://github.com/henrypp/pholcus) inject responses to
  poison the local cache.
- **mDNS query for `_workstation._tcp.local`**: a recon technique —
  the response lists every Windows/Samba host on the LAN by hostname.

## See also

- Parser: [`src/mdns_snoop.c`](../../src/mdns_snoop.c).
- DNS-SD service-type registry:
  [dns-sd.org/ServiceTypes.html](http://www.dns-sd.org/ServiceTypes.html).
- NetBIOS sibling: [`nbns.md`](nbns.md) (the Windows-flavoured
  equivalent for hostname discovery).
