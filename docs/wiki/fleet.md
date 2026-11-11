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
F2 is the Fleet tab (the sites on a map, each peer's health, what was
seen at more than one site) and the backfill of a kind an answer cut at
its cap; the inferences across sites (F3, F4) come next.

**Sources**: `web/src/web_fleet.h`, `web/src/web_fleet.c` (the export,
the member allow-list, the HTTP/1.1 client, the ingest and its checks,
the pull thread, `/api/fleet/peers`), `web/src/web_store.c` (`STEP_V8_SQL`),
`web/src/web_config.c` (`--peer`, `--peer-interval-secs`,
`--peer-allow-outside-tailnet`, the tailnet refusal and its warning),
`web/src/web_routes.c` (`/api/fleet/export`, `/api/fleet/peers`, the
health member), `web/src/web_frrs.c` (`web_frrs_verdicts()`),
`web/src/web_gnss.c` (`web_gnss_site()`), `web/src/web_secret.h`,
`web/src/web_slothdb.c` (`web_sdb_devices_after()`, `web_sdb_aps_after()`,
`web_sdb_seen()`), `web/ui/fleet.js`, `web/ui/fleet.css`,
`web/tests/test_fleet.c`, `web/tests/test_store.c`
(`test_v7_file_is_migrated`), `web/README.md` ("Fleet"),
[ADR 0008](adr/0008-own-fleet.md), [ADR 0006](adr/0006-sharing-is-opt-in.md),
issue #192; RFC 9112 (HTTP/1.1 message syntax), RFC 6598 (the
100.64.0.0/10 shared address space Tailscale numbers its nodes from).

**Last updated**: 2026-11-11 (#192 F2: the Fleet tab, `/api/fleet/overview`, `/api/fleet/shared`, the backfill); 2026-11-10 (#192 F1 review: the export sends only lines the importer takes; a transfer coding or a second Content-Length refused; the read deadline is the whole answer's); 2026-11-10 (#192 F1: the export, the pull, slothweb.db v8, `/api/health`'s `fleet`, `/api/fleet/peers`).

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

## The backfill

`since` advances at every good pull, so the rows a kind's cap cut from
an answer (the first pull of a busy sensor: 2,000 devices, 1,000 APs)
would never be asked for again. From F2 the pull asks with `next=1`, and
the export's end line then carries `next_wifi`, `next_ap`, `next_alert`
and `next_verdict`: `null`, or for a kind that was cut a cursor,
`<last_seen>~<key>`, naming the last row sent in the reader's own order
(a device's MAC or an AP's BSSID as `sloth.db` holds it, an alert's
rowid, a triage row's id). The puller keeps, per peer and kind, the cut
answer's `since` (the floor) and the cursor, and after each good pull
asks for up to 4 pages of each:
`GET /api/fleet/export?since=FLOOR&kind=wifi&after=CURSOR`, which answers
that kind only, the next cap's worth after the cursor, and its own
`next_wifi`. A page that is not cut ends the backfill.

The page is a keyset on (last_seen, key), not an offset: a row updated
meanwhile moves above the cursor, out of the page's range and into the
next incremental pull, and the rows below the cursor do not shift, so
none is skipped; rows that share a `last_seen` across the cut are
ordered by their key (`web/tests/test_fleet.c` seeds 4,500 devices in
four `last_seen` values to hold that). A client's probe list rides its
wifi row (a device goes with all of its probes, or the page ends before
it), so `probe` needs no cursor; the BLE table never holds more
advertisers than the BLE cap, so `ble` is never cut. A row the export
leaves out because the importer would refuse it marks its kind
truncated but gives no cursor: asking again would not change it.

The state is kept in slothweb.db's `meta` table, one row a peer and
kind (`fleet.backfill.NAME.KIND`, the floor and the cursor), written in
the same transaction as the rows it follows and read back at start, so
a restart resumes a backfill rather than lose its rows; there is no new
column and no schema step. A whole export cut again while a backfill
runs restarts that kind's backfill from the new cut, with the older of
the two floors, which fetches some rows twice and loses none. Only
`next=1` brings the cursors: an F1 puller, which refuses a member it
does not know, is answered as before. An F2 puller needs an F2 peer
(an F1 export refuses `next=1` as an unknown parameter), so upgrade
both.

## The Fleet tab

After TACDB (`web/ui/fleet.js`, `web/ui/fleet.css`, one module with its
own `fleet-*` ids, one `SlothFleet.init` and one `show` hook in
`app.js`). Three panels, refreshed every minute while shown:

- **Sites**: an SVG map, equirectangular (x = longitude x cos of the
  mean latitude, y = -latitude), fitted to the sites with a margin,
  north up; this site in the accent colour, each peer in the data
  colour, a dashed line between each pair with a position and its
  great-circle distance. No tiles and nothing fetched but this server.
  A site with no position is named under the map; one site alone is
  centred.
- **Peers**: a card each, from `peer_sites` and the pull's live state:
  last good pull and last attempt (this slothweb's clock), the last
  refusal, the clock skew, the distance from this site, the rows held
  by kind, and the backfill (running for which kinds, pages fetched and
  refused, or complete). A peer no longer given with `--peer` is shown
  as such.
- **Seen at more than one site**: for Wi-Fi devices, BLE advertisers,
  APs or probed SSIDs (the one `kind` select, kept per browser), each
  key a peer sent that this site holds too, newest activity first: its
  label, this site's triage verdict of a finding at that address (else
  the newest a peer sent, named with its site), and one bar per site
  from first to last seen, every row on the same time axis. The key
  opens the device drawer (the BLE drawer for an advertiser; a probed
  SSID opens its client).

No `--peer` gives an empty state that says how to configure one; a peer
with nothing in common says that instead. A random MAC that rotates is
a new key at each site and is never matched; correlating rotations is
F3's.

## The tab's routes

**`GET /api/fleet/overview`**: `local` (`name` `self`, the label from
`sloth.db`'s newest session, `sloth_db`, and the position the export
sends: `lat`, `lon`, `alt_m`, `pos_source`, `pos_age_s`), `interval_s`,
`store`, `configured`, and `peers`, each `peer_sites` row and each
configured peer not yet pulled: `name`, `configured`, `url`, `label`,
the position as the peer last reported it (`pos_age_s` by the peer's own
clock), `last_ok_age_s`, `last_attempt_age_s`, `last_error`, `skew_s`
(the peer's clock at its last good answer less this one's then:
positive, the peer runs ahead; within one pull's duration of the
truth), `remote_version`, `rows_last`, `counts` by kind, `backfill`
(each running kind's `floor` and `cursor`), `pages`, `page_failures`
and `distance_m` from this site. `distances` lists every pair of sites
with a position (`a`, `b`, `m`), this site named `self`: the haversine
on the IUGG mean radius, 6,371,008.8 m.

**`GET /api/fleet/shared?kind=wifi|ble|ap|probe&limit=N`** (`limit`
50 by default, 1..200; GET only): the newest 5,000 `peer_sightings` rows
of the kind are grouped by key, and each key is looked up at this site,
most recently seen at a peer first: a device in `sloth.db`'s `devices`,
an AP in `beacon_aps`, a probed SSID in `pnl_ssids`, through the M4
reader (read-only, its column allow-list, the 1.5 s overview budget); a
BLE address in slothweb's own BLE table. `rows`, newest activity at any
site first: `key`, `addr` (what the drawer opens), `label`, `vendor`,
`last`, `sites` (`self` first, then each peer: `first_seen`,
`last_seen`, `rssi`) and `verdict` (`state` and `site`, or null).
`partial` is true when the scan stopped at 5,000 rows or the budget ran
out; `scanned`, `keys` and `looked_up` say how far it got, and `local`
whether `sloth.db` was read (`open`, `none`, `unavailable`, `ble`).

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
- [[slothweb]] — the dashboard this runs in, the Fleet tab among its tabs.
- [[location]] — the sensor positions the site block carries.
- [[gnss]] — the receiver summary.
- [[data-socket-exposure]] — the other network surface and its rules.
- [[threat-model]]
