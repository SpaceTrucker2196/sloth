# DHCP  `[d]`

Live log of DHCP DISCOVER / OFFER / REQUEST / ACK events on UDP/67–68
plus the system's current lease table.

## Protocol

DHCP ([RFC 2131](https://www.rfc-editor.org/rfc/rfc2131)) is how
clients get IPv4 addresses. The full handshake (DORA) is:

1. **DISCOVER** — client broadcasts "anyone out there?"
2. **OFFER** — server proposes an IP
3. **REQUEST** — client claims the offered IP
4. **ACK** — server confirms

Plus **NAK**, **DECLINE**, **RELEASE**, **INFORM** for edge cases.
DHCP messages carry vendor-class strings (option 60), hostnames
(option 12), and a vendor-specific fingerprint that often identifies
the device's OS.

## What sloth captures

Two data sources — the live snoop and the static lease table:

- **Live events**: MAC, IP (when known), hostname, message type, timestamp.
- **Leases**: from system files (`/var/lib/dhcp/dhclient.leases`,
  `/run/systemd/netif/leases/*`) — IP, hostname, expiry.

## View

```
 ── DHCP events ────────────────────────────────────────────────
 msg        ip               host
 ACK        192.168.1.100    raspberrypi
 REQUEST    192.168.1.100    raspberrypi
 OFFER      192.168.1.100    -
 DISCOVER   -                raspberrypi
 ACK        192.168.1.101    iphone
 NAK        -                -                ← something went wrong
```

Newest first; private IPs in default colour.

## What's normal

- DORA handshakes complete in <1 s.
- Each device reappears every `lease_time / 2` to renew (typically
  every 12 h for a 24 h lease).
- One DHCP server's IP shows up consistently as the offer source.

## What's suspicious

- **Two servers replying** — an unauthorised DHCP server is on the
  network. Could be a misconfigured router, a "[rogue
  DHCP](https://en.wikipedia.org/wiki/Rogue_DHCP)" attack, or a
  Wireshark/Yersinia user testing.
- **Floods of DISCOVERs** from one MAC — DHCP starvation attack
  (typically as a precursor to standing up a rogue server).
- **Lease times of seconds** — also a starvation signal.
- **Hostname leak**: clients often include their hostname in option 12.
  Watch for sensitive names (e.g. `accounting-pc`, `ceo-laptop`)
  showing up on guest networks.
- **Unexpected NAKs**: usually benign (stale REQUEST after a server
  restart), but a sustained rate hints at MAC spoofing collisions.

## See also

- Parser: [`src/dhcp_snoop.c`](../../src/dhcp_snoop.c).
- Lease readers: [`src/platform/linux_dhcp.c`](../../src/platform/linux_dhcp.c).
- DHCP fingerprint database:
  [fingerbank.org](https://fingerbank.org/) — sloth doesn't ship one
  but you can correlate vendor-class strings manually.
