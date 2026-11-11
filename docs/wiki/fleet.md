---
name: fleet
description: The owner's own sensors sharing over the tailnet (#192) - slothweb's /api/fleet/export, the --peer pull, slothweb.db v8's peer_sites and peer_sightings, what never travels, and the inferences the later slices build on it
type: reference
---

# Fleet: the owner's sensors, pulled over the tailnet

**Summary**: one operator running several sloth sensors (in 2026-11
W9FJC with GPS and Wi-Fi, beta-site with ADS-B) can let their
slothwebs share what each has seen, under [ADR 0008](adr/0008-own-fleet.md):
full fidelity (SSIDs and client MACs travel), opt-in, peer-authenticated
by the tailnet and pull-only. Each slothweb serves
`/api/fleet/export?since=` to the addresses its `--web-allow` list
already admits, and pulls the same from each `--peer NAME=URL` every
`--peer-interval-secs` into its own `slothweb.db` (v8: `peer_sites`,
`peer_sightings`). The sensor and `sloth.db` are not touched, and
slothweb still never writes `sloth.db` (ADR 0005). Credentials,
usernames, alert keys and details, EAPOL rows and RADIUS identities
never travel: the export reads `sloth.db` only through the M4 reader's
column allow-list, every member name is held to `web_secret.h`, and a
test seeds each one and holds it out. Slice F1 of #192 is the plumbing;
the Fleet tab (F2) and the inferences across sites (F3, F4) come next.

**Sources**: `web/src/web_fleet.h`, `web/src/web_fleet.c` (the export,
the member allow-list, the HTTP/1.1 client, the ingest and its checks,
the pull thread, `/api/fleet/peers`), `web/src/web_store.c` (`STEP_V8_SQL`),
`web/src/web_config.c` (`--peer`, `--peer-interval-secs`,
`--peer-allow-outside-tailnet`, the tailnet refusal and its warning),
`web/src/web_routes.c` (`/api/fleet/export`, `/api/fleet/peers`, the
health member), `web/src/web_frrs.c` (`web_frrs_verdicts()`),
`web/src/web_gnss.c` (`web_gnss_site()`), `web/src/web_secret.h`,
`web/tests/test_fleet.c`, `web/tests/test_store.c`
(`test_v7_file_is_migrated`), `web/README.md` ("Fleet"),
[ADR 0008](adr/0008-own-fleet.md), [ADR 0006](adr/0006-sharing-is-opt-in.md),
issue #192; RFC 9112 (HTTP/1.1 message syntax), RFC 6598 (the
100.64.0.0/10 shared address space Tailscale numbers its nodes from).

**Last updated**: 2026-11-10 (#192 F1 review: the export sends only lines the importer takes; a transfer coding or a second Content-Length refused; the read deadline is the whole answer's); 2026-11-10 (#192 F1: the export, the pull, slothweb.db v8, `/api/health`'s `fleet`, `/api/fleet/peers`).

## What travels, and what never does

ADR 0008 amends ADR 0006 for one case: between sensors the same
operator runs, the fields ADR 0006 removes are the ones the inferences
need (a client MAC heard at both sites, a probe list at one naming the
other's SSID, one site's own BSSID broadcast at the other). So the
export carries, each kind newest first and bounded:

| Kind | From | Members | Cap |
|---|---|---|---|
| site (header) | sloth.db's newest session label; `sensor_health`'s `loc_*` | label, the sensor's lat / lon / alt, its source (`gps`, `fixed`) and age, slothweb's build | - |
| `gnss` | `sensor_health`'s `gnss_*` | receiver state, satellites in view and used, mean C/N0, clock offset, jamming indicator | 1 |
| `wifi` | sloth.db `devices`, `assocs` | MAC, vendor, last SSID, RSSI, newest associated BSSID, first / last seen | 2,000 |
| `ap` | `beacon_aps` | BSSID, SSID, channel, encryption, vendor, RSSI, times | 1,000 |
| `probe` | `pnl_ssids` of the exported clients | client MAC, SSID, times | 32 a client, 4,000 |
| `ble` | slothweb's BLE table | address and its type, local name, device class, RSSI, times | 1,024 |
| `alert` | sloth.db `alerts` | type, title, a fingerprint of type and title, match IP, severity, count, times | 1,000 |
| `verdict` | slothweb.db `triage` | the finding's descriptor (type, address, port, first seen) and its current state | 1,000 |

The export holds every line it writes to the importer's own checks
(below) before sending it, because one line the importer refuses
refuses the whole answer, at every pull, for as long as that row is in
the window. A row a sensor stored outside those ranges (a signal of
+60 dBm, a first seen after its last seen) is therefore left out and
its kind's `truncated_<kind>` is true; a receiver summary out of range
is left out; a position out of range goes as none.

Never: a credential or username (`cleartext_creds`, `alerts.key`,
`alerts.detail`, `mqtt_flows.last_username`, `rdp_flows.last_cookie`,
`rogue_radius.last_identity`), any EAPOL or handshake row, any column
`web_secret.h` withholds, a triage note, who wrote it or from where.
Three guards hold that, any one of which suffices for the `sloth.db`
columns: no export statement names them; the M4 reader's authorizer
refuses to prepare a statement that does (`web/src/web_slothdb.h`);
and the member list, `web_fleet_members[]`, is the only place a member
name comes from on either side, each name held to `web_sdb_is_secret()`
by `test_members_are_not_secret`. `test_export_withholds_secrets` seeds
every item above and asserts each is absent from the body.

An alert travels as type and title and a fingerprint of the two, not by
its key, because the key is the one column that can carry a remote
string (a cleartext credential's username) and the reader cannot read
it. The fingerprint is therefore coarser than the key: two findings of
one type with the same title (most of sloth's titles are the type's
name) share it. Matching the same tool across sites by IE-order or
vendor-IE hash (#192 I4) needs those hashes exported as their own
members, which F3 will add.

## The transport

The link is the operator's WireGuard tailnet (Tailscale): a `100.x`
address is bound to a node key, so the source address of a request is
authenticated, and each side admits only its listed peers. sloth adds
no cryptography and no TLS library (the #100 ruling). In practice:

- On each sensor, `--web-allow-remote --web-allow 100.A.B.C/32` for each
  other sensor (one address each, never the tailnet's /10, ADR 0008),
  with `--web-bind` on the sensor's own tailnet address.
- On each sensor, `--peer NAME=http://100.A.B.C:8770` for each other
  sensor. A URL outside `100.64.0.0/10` is refused at start (exit 2)
  unless `--peer-allow-outside-tailnet` is given, which is announced as
  a warning: the pull would then be plain HTTP over whatever path
  reaches that address.

Nothing is pulled and nothing is announced as pulled until a `--peer`
is given (`MISSION.md` §2: opt-in and announced). The export itself is
a read on the existing listener, so it answers exactly what the allow
list admits; on a loopback-only slothweb, nothing off the host.
`--strict` refuses `--peer`.

## The pull

A thread of its own wakes every `--peer-interval-secs` (default 60,
10..3600) and sends each peer one `GET /api/fleet/export?since=N`
over HTTP/1.1, `Connection: close`: 5 s to connect, 30 s for the whole
answer, held to 10 MB (refused whole past it, never cut to fit), a
`Content-Length` that does not match the body refused as cut short, and
a second `Content-Length` or any `Transfer-Encoding` refused (the export
sends neither). The 30 s is the whole answer's, not each read's, so a
peer that trickles bytes is cut off at 30 s.
`since` is the peer's own `generated` time at its last good pull less
120 s, so the two sites' clocks need not agree; the first pull asks
from 0 and gets the newest rows of each kind at their caps.

The answer is JSON Lines, read by the stream's own strict decoder
(`web/src/web_jsonl.h`) one line at a time and checked whole before a
row is written: a `fleet_export` header of version 1 first, a
`fleet_end` line last saying `complete` with each kind's count equal to
the rows sent, every member of every line on the list, every value in
range (MACs canonical, times before 2100, RSSI -150..30 dBm, strings at
most 255 bytes, altitude -1,000..100,000 m as slothweb's own position
takes it, verdict states triage's own words). Anything else is
refused with a reason in slothweb's words, kept on the peer, in
`/api/health` and in `peer_sites.last_error`, and no sighting is
written.

## The store: slothweb.db v8

`peer_sites` is one row per peer name: its URL, the last attempt and
the last good pull, the last refusal, the site's label, position and
source as the peer reported them, its build, its clock at the last good
answer and the rows that answer held. `peer_sightings` is one row per
`(peer, kind, key)`: a device, AP, BLE advertiser, probed SSID, alert,
verdict or the receiver; its label, vendor and RSSI as last reported,
its first and last seen widened by every pull, and the rest of the row
as JSON slothweb writes from validated members. The v7 -> v8 step is
additive and one `BEGIN IMMEDIATE` transaction; a v7 file is migrated
with every row kept, and a step that fails leaves it at v7 (both
tested). Retention, per peer at every pull: nothing older than 90 days
by the peer's clock, and at most 20,000 sightings, the least recently
seen first.

## What it makes possible

The issue's table, I1-I9, is what a second location lets slothweb infer:
a device heard at two of the operator's sites (I1), a client at one
probing for the other's network (I2), one site's own SSID or BSSID at
the other (I3), the same attack tool at both (I4), an emitter both hear
(I5), a GNSS event regional or local (I6), an ADS-B cross-check (I7),
verdicts shared (I8) and peer health (I9). F1 stores what they need;
each inference is a slothweb fleet finding, not a sloth alert, and is
held to the cited-basis rule when it lands.

## Related pages

- [ADR 0008 — own fleet](adr/0008-own-fleet.md)
- [ADR 0006 — sharing is opt-in and sanitised](adr/0006-sharing-is-opt-in.md)
- [[slothweb]] — the dashboard this runs in.
- [[location]] — the sensor positions the site block carries.
- [[gnss]] — the receiver summary.
- [[data-socket-exposure]] — the other network surface and its rules.
- [[threat-model]]
