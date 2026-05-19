# SSDP  `[s]`

UPnP device table from passive UDP/1900 NOTIFY / M-SEARCH traffic.

## Protocol

SSDP (Simple Service Discovery Protocol — part of
[UPnP](https://openconnectivity.org/foundation/faq/uplnp-device-architecture-faq/))
discovers devices on a local network. NOTIFY announcements advertise
"I exist", M-SEARCH queries hunt for specific service types. Both go
to `239.255.255.250:1900`.

It is famously insecure: UPnP services on the open internet have been
abused for [reflection
DDoS](https://www.cloudflare.com/learning/ddos/ssdp-ddos-attack/),
and locally any host can claim to be a router and announce port
forwards via UPnP-IGD.

## What sloth captures

Per device: source IP, NT/ST (notify or search target), USN (unique
service name), LOCATION URL, NTS (`alive` / `byebye` / `search`),
last-seen.

## View

```
 ── SSDP / UPnP ────────────────────────────────────────────────
 ip               type
 192.168.1.1      urn:schemas-upnp-org:device:InternetGatewayDevice:2
 192.168.1.100    urn:dial-multiscreen-org:service:dial:1
 192.168.1.150    upnp:rootdevice
```

## What's normal

- Your router advertising `InternetGatewayDevice`.
- TVs / Chromecasts / printers advertising AV / DIAL / printer
  services.
- Periodic M-SEARCH from new clients joining the network.

## What's suspicious

- **Two `InternetGatewayDevice` announcers** — UPnP impersonation. An
  attacker that wins the race can have the victim open holes in
  *their* firewall via UPnP-IGD requests.
- **Devices reachable from outside via UPnP** — these were the
  primary amplifiers for the 2014–2018 SSDP DDoS wave. Your home
  network's UPnP should NEVER be reachable from WAN. Test with
  [shodan.io](https://shodan.io/) for your public IP.
- **M-SEARCH floods** from one source — could be legitimate
  discovery on join, or scanning recon.
- **LOCATION URL pointing to a non-local IP** — unsigned XML fetched
  from a remote attacker = full
  [CallStranger](https://kb.cert.org/vuls/id/339275)-class exfil
  channel.

## See also

- Parser: [`src/ssdp_snoop.c`](../../src/ssdp_snoop.c).
- UPnP IGD risks:
  [US-CERT TA13-088A](https://www.cisa.gov/news-events/alerts/2013/01/29/upnp-vulnerabilities).
- DDoS amplification factor:
  [Cloudflare on SSDP](https://www.cloudflare.com/learning/ddos/ssdp-ddos-attack/).
