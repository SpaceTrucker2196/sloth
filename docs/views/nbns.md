# NBNS  `[0]`

NetBIOS Name Service — Windows/Samba hostname discovery on UDP/137.

## Protocol

NBNS ([RFC 1002](https://www.rfc-editor.org/rfc/rfc1002)) is how
pre-modern Windows networks resolve hostnames. SMB shares, network
neighbourhood, and Active Directory all leaned on it for years.
Modern AD prefers DNS, but NBNS is still alive — and very chatty — on
most Windows LANs.

Each Windows host announces itself periodically and answers broadcast
"who has this name?" queries. The names are also a 16th-character
"suffix" code identifying what service this is:

- `<00>` workstation
- `<03>` messenger / user
- `<20>` file server
- `<1c>` domain controller
- `<1e>` browser election

## What sloth captures

Per name: NetBIOS name (16 chars), suffix code, source IP, last-seen.

## View

```
 ── NBNS names ─────────────────────────────────────────────────
 name                suffix  ip
 WORKGROUP           <00>    192.168.1.255
 LAPTOP-DEV01        <00>    192.168.1.50
 ACCOUNTING-PC       <20>    192.168.1.51
 DC1                 <1c>    192.168.1.10
```

## What's normal

- A workgroup or domain name (`WORKGROUP`, `EXAMPLE.CORP`).
- Hostnames matching your Windows fleet.
- Periodic announcements every few minutes per host.

## What's suspicious

- **Hostname leak** to a network the host shouldn't be on — guests
  picking up your AD hostnames mean your VLAN segmentation is broken.
- **WPAD/PROXY queries**: NBNS lookups for `WPAD` or `ISATAP` are
  the lead-in for
  [Responder](https://github.com/lgandx/Responder)-style
  credential-relay attacks. An attacker on the segment answers the
  query, the victim hands over an NTLM hash, attacker cracks it
  offline. *Disable LLMNR + NBT-NS on hosts you control to mitigate.*
- **Same name claimed by multiple IPs** — name collision, either
  benign (DHCP churn) or a deliberate impersonation.
- **`<1e> browser election` storms** can indicate Responder is active
  trying to win an election to become the local Master Browser.

## See also

- Parser: [`src/nbns_snoop.c`](../../src/nbns_snoop.c).
- Responder reference:
  [lgandx/Responder](https://github.com/lgandx/Responder).
- Hardening:
  [Microsoft NBT-NS / LLMNR poisoning mitigation](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2011/2229593).
