---
source_url: https://www.axon.com/resources/axon-cloud-customer-faq
retrieved: 2026-10-13
topics: [surveillance, body-worn-camera, alpr, sni, tls, cloud-endpoint, vendor]
alert_kinds: [ALERT_TYPE_SURV_CLOUD_SNI]
citation: Axon Enterprise, "Axon Cloud Customer FAQ" (evidence.com to axon.com transition) and "Axon VR — network allowed lists", axon.com/help; Flock Safety, "Transparency Portal", flocksafety.com/articles/transparency-portal
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
- EFF Street Level Surveillance vendor lists, cited by #105's own
  scope-extension comment as the origin of the wider vendor roster that
  this table does not yet include.
