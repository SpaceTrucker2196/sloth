---
source_url: https://www.axon.com/resources/axon-cloud-customer-faq
retrieved: 2026-10-13
topics: [surveillance, body-worn-camera, alpr, sni, tls, dns, cloud-endpoint, vendor]
alert_kinds: [ALERT_TYPE_SURV_CLOUD_SNI, ALERT_TYPE_SURV_DNS]
citation: Axon Enterprise, "Axon Cloud Customer FAQ" (evidence.com to axon.com transition) and "Axon VR — network allowed lists", axon.com/help; Flock Safety, "Transparency Portal", flocksafety.com/articles/transparency-portal; Verkada, "Camera Network Settings", help.verkada.com
---
# Surveillance-vendor cloud endpoints — what a TLS SNI can and cannot say

What `ALERT_TYPE_SURV_CLOUD_SNI` (#105, signal family B) detects from,
and the much narrower claim it is allowed to make.

## The signal

Body-worn cameras and ALPR platforms are cloud products. The camera (or
its dock, or an analyst's workstation) speaks TLS to a vendor-operated
evidence platform, and the ClientHello carries the server name in
cleartext. sloth already parses SNI from ClientHellos it overhears
(`tls_log_parse()` in `src/tls_log.c`, landing in
`tls_log_entry_t.host`), so the detector
is a watchlist lookup, not new capture.

The watchlist rows are not inferred from product names. Each is a
domain the vendor's own operational documentation tells customers to
permit through a firewall or DNS filter, which is the only kind of
source that makes a row checkable by someone who does not own the
device.

### Axon — `evidence.com`, `axon.com`

Axon's cloud evidence platform has historically been reached at
`evidence.com`. Axon's **Axon Cloud Customer FAQ** states the platform
is moving: *"Access to Axon Evidence services will begin transitioning
from evidence.com to a new address under axon.com."* The same document
instructs agencies that operate allowlists, DNS filtering, proxies or
SSL inspection to permit `axon.com` addresses before the migration
reaches them, and points at `status.evidence.com/status/network` as a
self-service connectivity test. Both domains are therefore live service
addresses for the same platform, which is why both are on the list.

Axon's **VR training network-allowlist page** (axon.com/help) is a
second primary confirmation that `evidence.com` is an operational
service domain rather than a marketing one: it tells agencies to
allowlist `vr.evidence.com/nlu` and `vr.evidence.com/g2p`, alongside
`my.axon.com`.

Retrieved 2026-10-13.

### Flock Safety — `flocksafety.com`

Flock Safety publishes its agency-facing **Transparency Portal** under
`transparency.flocksafety.com`, one path per agency; Flock's own
article on the portal and a large number of municipal pages linking
agency portals both show that hostname pattern. `flocksafety.com` is
therefore Flock's service domain, not only a brochure site.

Retrieved 2026-10-13.

### Verkada — `control.verkada.com`

Verkada sells cloud-managed fixed cameras, including models with
licence-plate analytics, which is why #105's scope extension lists it
as a Flock-like surveillance vendor. Its help centre page **Camera
Network Settings** (https://help.verkada.com/verkada-cameras/configuration/camera-network-settings)
is a firewall allowlist in the sense this table requires: under
*Firewall settings* it says *"Verkada cameras require access to many
endpoints to ensure they can communicate with Command and all features
will be accessible"*, then gives a coarse rule set (`*.verkada.com`,
`time.cloudflare.com`, `*.amazonaws.com`) and, *"if you prefer a more
granular allowlist"*, per-region FQDN tables for the US, Europe and
Australia.

Every Verkada-operated FQDN in those tables is under
`control.verkada.com` — `api.control.verkada.com`,
`relay.prod-us-ohio.control.verkada.com`,
`index.prod.ap.syd.control.verkada.com`,
`firmware.control.verkada.com`, `update.control.verkada.com`,
`*.vstream.vnetcap.control.verkada.com` and the rest — except the
`vconductor.*.command.verkada.com` hosts. The row is therefore
`control.verkada.com`, one row for one document:

- **Not `verkada.com`.** The page's coarse rule covers it, but it also
  covers Verkada's marketing site, which would repeat the `axon.com`
  false-positive source below on purpose. The narrow row loses nothing
  the camera list names except the vconductor hosts.
- **Not `command.verkada.com` as a second row.** That is also the
  operator web application, so it adds portal traffic rather than
  device traffic, and the ruling is one row per document.
- **Not the `*.amazonaws.com` entries** (Kinesis Video, S3). They are
  shared AWS infrastructure: a row there would name Verkada on traffic
  that is overwhelmingly someone else's.

The same page, and Verkada's general **Required Network Settings**
page (https://help.verkada.com/command/need-help/required-network-settings),
state that *"DNS over HTTPS (DoH) is currently not supported"* and that
devices resolve over UDP port 53, and that Verkada devices are
incompatible with LANs that require proxies or TLS inspection. Both
facts matter to a passive sensor: the device's lookups are plaintext
DNS and its ClientHellos reach the wire unmodified.

Retrieved 2026-10-20.

## The second signal: DNS (`ALERT_TYPE_SURV_DNS`)

The same table is read a second way. Before a device opens TLS to a
watchlist domain it resolves the name, and sloth already logs DNS
queries it overhears (`s->dns_log`). `ALERT_TYPE_SURV_DNS` fires when a
**query** (not a response — a response's source is the resolver)
names a watchlist domain, keyed on vendor plus the asking local host,
exactly as the SNI rule is.

What it adds over the SNI rule is coverage, not certainty. The name
crosses the wire in DNS in cases where no parseable ClientHello
follows: an upload over QUIC, a ClientHello using Encrypted Client
Hello, a TLS path the capture does not see. For Verkada the vendor
says so directly — its devices *"do not support"* DNS over HTTPS and
resolve over UDP port 53 (Required Network Settings, above) — so a
Verkada device's lookups are plaintext by the vendor's own design.

What it costs is strength. A lookup is weaker evidence than a TLS
session: link previews, prefetching browsers and filtering resolvers
all resolve names that nothing then connects to. So it fires at LOW,
one tier under the SNI rule's WARN, and when both fire for one host
and vendor they corroborate each other. Neither confirms a device; the
limits below apply to both rules unchanged.

Two edges of the DNS signal, found in review and stated here because
both are about what the alert can be trusted to mean:

- **A forwarding resolver on the segment is its own asking host.**
  Skipping responses keeps the resolver out of the key only for
  responses. The capture path logs any UDP packet with port 53 at
  either end, so where sloth can see a Pi-hole or a router's dnsmasq
  forward a client's lookup upstream, that forwarded query has the
  resolver as its source and produces a second alert keyed on the
  resolver — one that merges every client behind it. The client's own
  query to the forwarder, where sloth sees it, still produces the
  per-client alert beside it. Not suppressed: sloth has no list of
  which local hosts are resolvers, and guessing would hide a real
  asker.
- **A name sloth stored only part of is not matched.** `dns_log` keeps
  63 bytes of a query name and `tls_log` 63 of an SNI. The stored text
  of a longer name is a prefix, and a prefix can end on a listed
  suffix: the first 63 bytes of
  `<43 x a>.control.verkada.com.evil.example` read as a Verkada host,
  and any web page can make a browser resolve a name like that. The
  parsers now flag a stored name that is shorter than the wire name
  (cut at 63, or stopped at a NUL octet inside a label), and both
  rules skip flagged rows rather than report a lookup nobody made. A
  genuine vendor name longer than 63 bytes is missed in exchange.

## What the detector does not establish

Three limits, all of which the alert text states rather than leaving to
a doc nobody reads at 02:00:

1. **It cannot tell a device from a browser.** A docked body camera
   uploading and an analyst with the vendor's portal open in a tab
   produce the same observation: TLS from a host on this segment to
   that domain. There is no field in a ClientHello that separates them.
2. **For Flock specifically, the camera is almost never the source.**
   Flock's field cameras are solar-powered and **cellular**-uplinked —
   public vendor and municipal descriptions are consistent that there
   is no inbound path to the camera and its data goes out over
   cellular. A Flock ALPR camera's own traffic therefore never crosses
   a monitored LAN. A hit on `flocksafety.com` means a host *on this
   network* is using the platform. It is not an answer to #105's
   "is there a Flock on my street".
3. **`axon.com` is broad and that is a known false-positive source.**
   It is Axon's marketing site as well as the migration destination for
   the evidence platform, so reading a product page fires the rule. The
   alternative — guessing at the upload subdomains Axon has not
   published — would be worse: it would match nothing real while
   still attaching a vendor name to whatever it did hit.

## Rows deliberately absent

#105's scope-extension comment lists roughly two dozen further body-cam
and ALPR vendors (Motorola/WatchGuard, Digital Ally, Utility, Reveal,
Getac, Panasonic i-PRO, Safe Fleet/COBAN, Zepcam, Rekor, Verkada, Ring,
SoundThinking and others) with candidate SNI globs. The comment states
plainly that every row starts at `confidence: low` and that *"no vendor
on this list publishes its on-air fingerprint"*. None is in the table,
because a domain nobody publishes is a guess carrying a vendor's name.
They are additions pending a source, not an omission.

The bar, as the owner set it on 2026-10-19 (#145 ruling 2, applied to
#105): a row ships only for a vendor that publishes a primary
network-requirements or firewall allow-list document naming the
domain, one row per document, cited here with URL and retrieval date.
The close-out pass on 2026-10-20 checked the scope-extension vendors
against that bar:

- **Verkada** — passes; row added above.
- **Ring** — fails. Ring's support article on the protocols and ports
  its devices use (https://ring.com/us/en/support/articles/xws8s/Protocols-and-Ports-Used-by-Ring-Devices,
  titled *Understanding router security settings*; the old
  support.ring.com "Network Requirements" URL redirects there) lists
  ports 443, 80, 53 and 123 and **no domains**. The issue's
  `*.ring.com` glob is therefore the issue's, not Ring's, and
  `ring.com` stays absent. Retrieved 2026-10-20.
- **Flock Safety** — already present on the transparency-portal basis
  above; Flock's help centre index shows no network-requirements or
  allowlist page, so no second Flock row.
- **Rekor** — the issue's `*.rekor.ai` / `*.rekorsystems.com` globs have
  no Rekor network-requirements document behind them that this pass
  could locate. Absent.
- **Motorola Solutions / WatchGuard / Vigilant / Avigilon, Digital Ally,
  Utility, Reveal, Getac, Panasonic i-PRO, Safe Fleet / COBAN, Zepcam,
  Genetec, PlateSmart, Leonardo ELSAG, Perceptics, SoundThinking,
  Wolfcom, PatrolEyes, Hytera, Pinnacle Response** — no publicly
  reachable network-requirements or allowlist document was located for
  any of them in this pass. That is "not found", not "does not exist":
  several of these vendors keep deployment guides behind customer
  logins. Each stays absent until someone can cite the document.
- **Axon Outpost / Fusus** — the scope extension already notes these
  ride the existing `evidence.com` / `axon.com` rows, so no new row.

`tests/test_vendor_watchlist.c :: test_unsourced_domains_are_absent`
pins the checked-and-failed cases (`ring.com`, the Rekor globs) so a
later pass has to read this section before adding them.

`axondocs.com` appears in #105's design and is **not** in the table:
searching for it surfaces no Axon-operated service by that name (the
near-miss hits are Axxon Soft, an unrelated company). It would have
been an unverifiable row.

## Why there is no ATT&CK technique

`alert_technique()` returns `""`, the third detector to do so after
`ALERT_TYPE_OPEN_SETUP_AP` (#80) and `ALERT_TYPE_CAM_WS_DISCOVERY`
(#106), and it is on the named list in
`tests/test_research_corpus.c :: test_uncitable_kinds_with_a_real_basis_are_still_cited`.

Nothing observed here is an adversary's behaviour. The two nearest
candidates both point the wrong way: T1041 (Exfiltration Over C2
Channel) and T1567.002 (Exfiltration to Cloud Storage) describe an
attacker moving data out of a network, and a police body camera
uploading to its own vendor's evidence platform is the system working
exactly as designed. Tagging it as exfiltration would be the
evidence-overstatement defect #90 is open about. The basis is cited —
it is just not an ATT&CK ID.

`ALERT_TYPE_SURV_DNS` returns `""` for the same reason and sits on the
same named list. Its nearest candidate, T1071.004 (Application Layer
Protocol: DNS), describes command-and-control carried inside DNS — a
claim about the payload of the lookup that a vendor-name match cannot
make.

## Sources

- Axon Enterprise, *Axon Cloud Customer FAQ*,
  https://www.axon.com/resources/axon-cloud-customer-faq — retrieved
  2026-10-13.
- Axon Enterprise, *Axon VR — network allowed lists*,
  https://www.axon.com/help/axon-vr/vr-training/device-support/network-allowed-lists.htm
  — retrieved 2026-10-13.
- Flock Safety, *Transparency Portal*,
  https://flocksafety.com/articles/transparency-portal — retrieved
  2026-10-13; agency portal hostnames corroborated by municipal pages
  (e.g. Clear Creek County CO, Kent County MI).
- Verkada, *Camera Network Settings*,
  https://help.verkada.com/verkada-cameras/configuration/camera-network-settings
  — retrieved 2026-10-20.
- Verkada, *Required Network Settings*,
  https://help.verkada.com/command/need-help/required-network-settings
  — retrieved 2026-10-20 (DoH unsupported; no proxy / TLS inspection).
- Ring, *Understanding router security settings* (protocols and ports
  used by Ring devices),
  https://ring.com/us/en/support/articles/xws8s/Protocols-and-Ports-Used-by-Ring-Devices
  — retrieved 2026-10-20; cited for the absence of a Ring row.
- EFF Street Level Surveillance vendor lists, cited by #105's own
  scope-extension comment as the origin of the wider vendor roster that
  this table does not yet include.
