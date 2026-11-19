# surveillance-endpoints: surveillance-vendor cloud domains

`surveillance_endpoints.csv` is sloth's `kEndpoints` (sloth
[`src/vendor_watchlist.c`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/src/vendor_watchlist.c)
at `fa366881`), read by `vendor_watchlist_match_domain()` for
`ALERT_TYPE_SURV_CLOUD_SNI` and `ALERT_TYPE_SURV_DNS`. Columns `domain`
(matches itself and any subdomain, at a label boundary), `vendor`,
`family`. Moved unchanged, and held byte for byte to the source by
sloth-comint's parity check. The full citations, URL and retrieval date
per row, are sloth's
[`research/papers/surveillance-vendor-endpoints.md`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/research/papers/surveillance-vendor-endpoints.md)
(retrieved 2026-10-13).

"The bar for a new row (sloth #145 ruling 2): the vendor publishes its
own network-requirements or firewall allow-list document naming the
domain; one row per document."

| Row | Source, as the comment above it gives it |
|---|---|
| `evidence.com` | Axon's VR network-allowlist page instructs agencies to allowlist "vr.evidence.com/nlu" and "vr.evidence.com/g2p", and the Axon Cloud customer FAQ points at "status.evidence.com/status/network" as its own connectivity test (<https://www.axon.com/resources/axon-cloud-customer-faq>) |
| `axon.com` | the Axon Cloud customer FAQ: "Access to Axon Evidence services will begin transitioning from evidence.com to a new address under axon.com". Broad on purpose: this is also Axon's marketing site, and the alert says it cannot tell the two apart |
| `flocksafety.com` | Flock Safety's service domain: agency transparency portals at transparency.flocksafety.com, published by Flock. A Flock camera uplinks over cellular, so a hit is a host using the platform, not a camera on the network |
| `control.verkada.com` | Verkada's "Camera Network Settings" page: every Verkada-operated FQDN in its per-region allowlists sits under control.verkada.com except the vconductor hosts under command.verkada.com; not the bare verkada.com, which also covers the marketing site |

**Licence.** Domains named in the vendors' own public documents; the
selection was written in sloth (SLOTH SOURCE-AVAILABLE LICENSE 1.0) by
the owner of both repositories. sloth carries it under its own licence;
sloth-comint publishes it under PolyForm Noncommercial 1.0.0.