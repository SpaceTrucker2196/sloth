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
its cap. I5 locates an emitter two or more sites hear, from each site's
signal strength (`/api/fleet/locate`, the map's located emitters), with
each receiver calibrated by another site's own radio when it hears one;
I6 compares the sites' GNSS receivers (`/api/fleet/gnss`): each GNSS
event classified regional, local or undetermined, the baseline between
two static sites against its bound, and a clock step named to its site;
I7 compares the sites' ADS-B receivers (`/api/fleet/aircraft`): each
aircraft confirmed, unconfirmed (a second receiver that demonstrably
hears that sector did not hear it), out of that receiver's coverage, or
undetermined, which is every aircraft while the fleet has one receiver;
the identity inferences across sites (F3) come next.

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
`web/src/web_locate.h`, `web/src/web_locate.c` (I5), `src/rf_model.h`,
`src/rf_model.c` (the path-loss model both sloth and slothweb link),
`web/src/web_fleetgnss.h`, `web/src/web_fleetgnss.c` (I6),
`web/src/web_slothdb.c` (`web_sdb_gnss_incidents()`), `web/src/web_gnss.c`
(`web_gnss_fleet()`), `web/src/web_fleetadsb.h`, `web/src/web_fleetadsb.c`
(I7), `web/src/web_slothdb.c` (`web_sdb_adsb_fleet()`,
`web_sdb_adsb_positions()`),
`web/tests/test_fleet.c`, `web/tests/test_locate.c`, `web/tests/test_fleetgnss.c`,
`web/tests/test_fleetadsb.c`,
`web/tests/test_store.c`
(`test_v7_file_is_migrated`), `web/README.md` ("Fleet"),
[ADR 0008](adr/0008-own-fleet.md), [ADR 0006](adr/0006-sharing-is-opt-in.md),
issue #192; RFC 9112 (HTTP/1.1 message syntax), RFC 6598 (the
100.64.0.0/10 shared address space Tailscale numbers its nodes from);
ITU-R P.1238-10 eq. (1), Tables 2 and 4, through
`research/papers/rssi-distance-estimation.md` (I5's model, exponent and
error); for I6 `research/gnss/jamming-detection.md`,
`research/gnss/spoofing-detection.md`,
`research/gnss/time-and-position-integrity.md` and
`docs/wiki/alert-assessments/GNSS_*.md`; for I7
`research/adsb/multi-receiver-verification.md` (Strohmeier, Lenders and
Martinovic's ADS-B security survey, section V-F; the 4/3-earth radio
horizon) and `research/adsb/emergency-squawks.md` (ADS-B carries no
authentication).

**Last updated**: 2026-11-11 (#192 I7: aircraft across the sites, the export's `adsb=1` (`adsb_rx`, `aircraft` lines), peer_sightings kinds `aircraft` and `adsb`, `/api/fleet/aircraft`, the overview's `aircraft`, the Fleet tab's aircraft panel with each receiver's coverage plot); 2026-11-11 (#192 I6 review: no quiet peer before a pull past the window's end; a span never bridged across a sample that was not observing; `rx` only with the drop test's history; the sample events kept for the week across a restart; a sample event never quiet on incidents alone; `gnss_complete`, so a pre-v11 `sloth.db`, a timeout or the cap is no coverage; an eph of 0 no bound; the UI's "local" worded as seen at one site while the others watched); 2026-11-11 (#192 I6: GNSS regional or local, the baseline and clock checks, `/api/fleet/gnss`, the export's `gnss=1`, `--peer-gnss-region-km`, the Fleet tab's GNSS panel); 2026-11-11 (#192 I5 review: the least-squares fix damped and refused when unsettled; `nearest` with its difference's sigma and `within_band`; the export's probe reading only within 120 s of its row and not on 5 or 6 GHz; a 5 GHz probe no calibration link and modelled at 5 GHz; an address two sites claim no link); 2026-11-11 (#192 I5: locating emitters from two or more sites' signal strength, `/api/fleet/locate`, the own-radio calibration and `own=1`, the overview's `calibration`, the map's located emitters and metre scale; a stored 0 dBm is no reading, and an ARP-only device takes its probe reading); 2026-11-11 (#192 F2 review: the alert backfill past the reader's 20,000-row scan, an F1 peer pulled without `next=1`, the shared list's verdicts in one pass); 2026-11-11 (#192 F2: the Fleet tab, `/api/fleet/overview`, `/api/fleet/shared`, the backfill); 2026-11-10 (#192 F1 review: the export sends only lines the importer takes; a transfer coding or a second Content-Length refused; the read deadline is the whole answer's); 2026-11-10 (#192 F1: the export, the pull, slothweb.db v8, `/api/health`'s `fleet`, `/api/fleet/peers`).

## What travels, and what never does

ADR 0008 amends ADR 0006 for one case: between sensors the same
operator runs, the fields ADR 0006 removes are the ones the inferences
need (a client MAC heard at both sites, a probe list at one naming the
other's SSID, one site's own BSSID broadcast at the other). So the
export carries, each kind newest first and bounded:

| Kind | From | Members | Cap |
|---|---|---|---|
| site (header) | sloth.db's newest session label; `sensor_health`'s `loc_*` | label, the sensor's lat / lon / alt, its source (`gps`, `fixed`) and age, slothweb's build | - |
| `gnss` | `sensor_health`'s `gnss_*`; with `gnss=1` the newest `gnss_fix` and the satellites | receiver state, satellites in view and used, mean C/N0, clock offset, jamming indicator; with `gnss=1` the fix (time, mode, position, eph, hdop) and the tracked median C/N0 | 1 |
| `gnss_event` | sloth.db `alert_incidents` of the four GNSS keys, `gnss=1` only | type, first and last seen, count, peak severity | 256, the last week |
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
the two floors, which fetches some rows twice and loses none. A page
that does not move its cursor (the peer's read ran out of its budget
first) is asked again at the next pull, not again in the same one.

Alerts need one more step. The reader takes its keys from the newest
20,000 rows of the range (`WEB_SDB_ALERT_SCAN`), and on a busy sensor
one finding's incidents fill that long before the cap: on W9FJC
(2026-11-11) the newest 20,000 of 364,191 incidents were 955 of 17,988
keys, so the first answer looked whole at 955. When the scan does not
reach the range's floor, the export now marks `alert` cut and its
cursor is the scan's oldest `last_seen` (`<ts>~`, every key at it
included); a page reads only the rows at or before its cursor
(`web_sdb_alerts_upto()`), so each page's scan starts where the last
one ended. A key newer than the cursor may come again with an older
`last_seen`; the importer's widening keeps its newest. More than 20,000
incidents in one second would stop the alert backfill at that second
(it is asked again each pull, and says so in its unchanged cursor).

Only `next=1` brings the cursors: an F1 puller, which refuses a member
it does not know, is answered as before. An F1 export refuses `next=1`
as an unknown parameter; an F2 puller that gets that 400 asks again
with `since=` alone, stores the answer, pulls that peer without `next=1`
for the next hour (then tries it again), and pages nothing from it;
the overview's `pages_refused` and the peer's card say so. A fleet can
therefore be upgraded one host at a time.

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
(each running kind's `floor` and `cursor`), `pages`, `page_failures`,
`pages_refused` (the peer's export refused `next=1`: an F1 build, pulled
without it) and `distance_m` from this site. `distances` lists every pair of sites
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
`last_seen`, `rssi`) and `verdict` (`state` and `site`, or null):
this site's triage at the address, else the newest a peer sent, each
found in one pass over its table for all the listed rows, not a scan a
row. `partial` is true when the scan stopped at 5,000 rows or the budget
ran out (checked between the lookups, which are each too short for the
reader's own progress check); `scanned`, `keys` and `looked_up` say how far it got, and `local`
whether `sloth.db` was read (`open`, `none`, `unavailable`, `ble`).

## Locating emitters (I5)

Each site that hears an emitter has a range to it from its signal
strength, by sloth's own model (`src/rf_model.h`, linked by sloth and
slothweb alike so the two cannot disagree; [[rf-distance]]):

    d = 10 ^ ((P_tx - RSSI - (20 log10 f - 28) - offset) / N)

ITU-R P.1238-10 eq. (1) on one floor, `N` from its Table 2 (2.8 at
2.4 GHz and for BLE, 3.0 at 5 and 6 GHz), the shadow-fading sigma from
its Table 4 (8 dB at 2.4 GHz, 12 dB above). The sources, read first-hand,
are in `research/papers/rssi-distance-estimation.md`, whose section
"Two or more sensors" covers this use. `P_tx` is assumed (a Wi-Fi client
15 dBm, an AP 20, BLE 0, sloth's defaults): slothweb sees no TPC Report
or TX Power element. A client's frequency is 2437 MHz unless its row
names a channel (sloth's choice; across 2.4 GHz the term moves 0.2 dB).

**The band.** One sigma, in quadrature: shadow fading, 6 dB for the
assumed power, and 6 dB more for a receiver that is not calibrated (its
antenna and receive chain unknown: W9FJC's 9 dBi panel is such a
term). At 2.4 GHz that is 11.7 dB uncalibrated, a factor of 2.6 in
distance each way, and 10 dB calibrated, 2.3. A "17 m" range is 7-38 m.

**Calibration.** Each slothweb reads its host's own radios (the
physical interfaces under `/sys/class/net`, at start) and names them to
a peer that asks with `own=1` (the header's `own_macs`). A receiver
that hears another site's own radio has one link of known length: the
haversine between the two sites. Its offset is the measured path loss
less the model's at that length, `rf_ref_offset_db()` as the sensor's
`--my-bssid` calibration computes it, bounded by +/-20 dB; the median of
a receiver's accepted links is its offset. One length fixes the offset,
not the exponent: `N` stays P.1238's. The offset is a 2.4 GHz Wi-Fi
receiver's, applied to 2.4 GHz Wi-Fi rows only, never to 5/6 GHz or
BLE (`rf_distance.h` keeps its calibration per radio for the same
reason). An offset past the bound is reported as `refused` with its
value: a wall or a receiver far from the model, not a gain to correct.
A link at most a day old counts, and only from a reading on 2.4 GHz or
an unknown channel (a probe heard on 5 GHz is no link for a 2.4 GHz
offset).

**Pairing in time.** A peer's value is its last RSSI as of its
`last_seen`. Every site used for a key has `last_seen` within 120 s
of the newest (two default pull intervals), on this site's clock (a
peer's less its measured skew), and the newest is within 15 minutes of
now; `unpaired` and `stale` count the keys left out. A Wi-Fi device's
time is its row's `last_seen`, which an ARP or DHCP sighting also moves,
so the pairing is no tighter than that.

**Geometry**, on a plane tangent at the sites' centroid (east and north
metres, equirectangular on the IUGG mean radius: well under a metre of
error at a few kilometres):

- two sites: the two range circles' crossings, 0, 1 (tangent) or 2
  candidates, each with a radius of the two bands' half-widths combined
  over the sine of the crossing angle (never below 0.25, so a tangent
  crossing is spread along the line);
- three or more: a weighted least-squares fix (Levenberg-Marquardt,
  each range weighted by its band), its rms residual and the fix's
  one-sigma from the normal equations; collinear sites give no fix, nor
  does an iteration that has not settled within 500 steps (an undamped
  Gauss-Newton step overshoots when the ranges disagree, and the first
  build reported wherever its 50th step landed);
- always `nearest`: the site with the least path loss after each
  receiver's offset, by how many dB, and that difference's one-sigma
  (`sigma_db`: each link's shadow fading and each uncalibrated
  receiver's 6 dB, in quadrature; the assumed power is the same
  emitter's at both and cancels), with `within_band` when the
  difference is inside it. At 2.4 GHz that sigma is 11.3 dB with both
  receivers calibrated and 14.1 dB with neither, so a few dB is no
  side at all. When the circles do not cross, this is the whole answer.

A site with no other within 2 km shares no emitter and is not paired
(`too_far`). Metres are quantised as sloth quantises a third party's
proximity (0.5 m below 10 m, 1 m below 100 m, 10 m above).

**What it is worth.** At W9FJC and beta-site, 16.8 m apart, a band of
+/-15 to 30 m is wider than the baseline, and the row says `coarse`:
the candidates are not a position, only a side. What two sensors that
close can say honestly is which one an emitter is nearer, when the
difference in path loss exceeds its own 11-14 dB sigma, and roughly how
far; a point needs more sites, a longer
baseline, or both. Three sites give a least-squares fix whose residual
shows how far the ranges disagree.

The live link (measured 2026-11-11): W9FJC's monitor hears beta-site's
managed card at -52 dBm on probe requests, an offset of -7 dB (about its
9 dBi antenna); beta-site hears W9FJC's card at -84 to -92 dBm, about
+29 dB, past the bound, so beta-site stays uncalibrated. Path loss is
reciprocal, so a 36 dB asymmetry between the two directions is the two
cards' powers and the two receivers' gains, not the path; beta-site
reads APs both sites hear about 20 dB weaker than W9FJC does.

**`GET /api/fleet/locate?kind=wifi|ap|ble&limit=N`** (50, 1..200; GET
only): the newest 5,000 peer rows of the kind with a reading, grouped by
key, each looked up at this site within the overview's budget as
`/api/fleet/shared` does. `sites`: each site with a position, its plane
coordinates, `too_far`, and its receiver's `calibration` (`state`
`calibrated`, `refused` or `none`, `offset_db`, `exponent_x10`, and each
`link`: `from`, `mac`, `rssi`, `dist_m`, `offset_db`, `accepted`,
`age_s`). `rows`, newest first: `key`, `label`, `age_s`, `freq_mhz`,
`ptx_dbm`, `ptx` (`assumed`), `exponent_x10`, `sites` (each `site`,
`rssi`, `seen`, `range_m`, `lo_m`, `hi_m`, `sigma_db`, `calibrated`),
`nearest` (`site`, `by_db`, `than`, `sigma_db`, `within_band`), `candidates` (`lat`, `lon`, `e`,
`n`, `radius_m`), `method` (`two_circles`, `least_squares`),
`residual_m`, `baseline_m`, `band_m` and `coarse`. Then `scanned`,
`keys`, `looked_up`, `unpaired`, `stale`, `partial`. The overview gains
`calibration`: each site, its count of own radios, and its receiver's
state as above.

**A stored 0 is no reading.** sloth stores 0 in a Wi-Fi row's signal
for "never heard on the air" (an ARP- or DHCP-only device). F1 and F2
sent and showed it as 0 dBm; from I5 the export sends none, the shared
list shows none (a peer still on F2 included), and a device row without
a reading takes `probe_clients`' reading of the same MAC, where sloth
keeps the monitor's signal of a station heard probing. That is how a
sensor's own managed card, whose `devices` row comes from ARP, has a
signal at the other site. In the export the probe's reading travels
only when it is within 120 s of the row's `last_seen` and not on 5 or
6 GHz: the importer takes a row's `rssi` as of its `last_seen` and,
with no channel, at 2.4 GHz. On W9FJC (2026-11-11) every one of the 24
client rows this applied to had an ARP-moved `last_seen` newer than its
probe by more than 120 s (7 by a day), and 10 of the probes were on
5 GHz. Locally the probe's own time and channel are used: a reading on
5 or 6 GHz is modelled there, and is no calibration link.

On the map: each located emitter's candidates as translucent circles of
their radius, the key on hover or tap, the two-site range circles as
dashed arcs for the row picked in the table, and a metre scale bar; the
map fits the sites and the candidates, so at a 17 m baseline it is
drawn in metres. A table under the map lists each located emitter: key,
the sites with their ranges, the nearer site by dB with that
difference's sigma ("neither" when the difference is inside it), the
method, and
"coarse" when the band exceeds the baseline.

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
I5 and I6 are built (above and below);
each inference is a slothweb fleet finding, not a sloth alert, and is
held to the cited-basis rule when it lands.

## GNSS: regional or local (I6)

Two receivers a few metres apart see the same sky. A GNSS event at one
of the owner's sites and not at a peer within reach points to a source
near that site; the same event at both within a short window points to
something wider: one source reaching both, an exercise, the ionosphere.
And two static sensors carry a known baseline between them, which a
spoofed position moves. slothweb does this over what the export
carries; these are fleet findings, not sloth alerts, and nothing is
written to `sloth.db` (`web/src/web_fleetgnss.h`).

**What travels.** With `gnss=1` (asked for only, like `own=1`) the
`gnss` line gains the newest fix (`fix_ts`, `mode`, `fix_lat`,
`fix_lon`, `eph`, `hdop`) and the median C/N0 of the satellites tracked
(`cn0_med` over `tracked`: a C/N0 above 0, reported within 660 s, the
jamming rule's own observable, "Tracked only and a median"), and the
export sends `gnss_event` lines: `sloth.db`'s `alert_incidents` of the
four GNSS rules' keys (`gnssjam`, `gnssspoof`, `gnsstime`, `gnsspos`;
the keys are sloth's constants, compared in the WHERE and never read),
the last week's changed since `since`, at most 256, with the end line's
`gnss_event` count and `gnss_complete`: true only when the read ran to
its end. A `sloth.db` before v11 (no incident rows), a read error or
timeout, or the cap is not "nothing happened", and the importer takes no
`ev` coverage from that answer. An I5 export refuses `gnss=1`; the puller asks again
with `next=1&own=1` and not with `gnss=1` for the hour, as for `own=1`.
The importer keys an incident `TYPE|first_seen` in `peer_sightings`.

**The samples.** After each good pull of a peer, and once a round for
this site, the pull thread takes one sample of each receiver: fresh when
its summary is at most 660 s old (two of sloth's 300 s heartbeats and a
margin), the state, satellites, mean and tracked-median C/N0, jamming
indicator, clock offset, the fix, and a peer's skew (its `generated`
less this site's clock). From them, per site:

- *coverage*: the spans of this site's clock over which the site was
  seen observing, `rx` (its receiver fresh, a sky listed, its tracked
  median sent and the hour's history the CN0_DROP test needs, so a drop
  there would have shown) and `ev` (its `sloth.db` open and the whole of
  its incidents offered). Samples more than the gap apart (two pull
  intervals and 30 s, 150 s by default) start a new span, and so does
  any sample that said it was not observing: a span is never bridged
  across one. Nothing stands for the time after the newest sample.
- *sample events* (below): flagged as each sample is added and kept as
  runs for the week, at most 256, so a restart or the ring's eight hours
  never leave a site covered with its event gone.
- a *reference position*: one fix a 600 s (fresh, mode 2 or 3, with an
  eph above 0), the last 1,008 (a week); the coordinate-wise median of them,
  from 6 on (an hour). A move held for more than half the week becomes
  the new reference, and is then no longer flagged: the route gives the
  reference's `n`, not the time it last moved, so a slow drag-off or a
  real re-siting both settle in silently after 3.5 days.

Coverage, the sample events and the reference are kept in
`slothweb.db`'s `meta` table (`fleet.gnss.<site>`, written at most every
600 s), so a restart keeps them; no schema step. Nothing loaded is
extended: the first samples after a restart open new spans. The sample
ring (8 hours) is memory only: the C/N0 and clock medians rebuild within
the hour, and until the drop test has its ten samples no sample is `rx`
coverage.

**The events**, each in this site's clock (a peer's less its skew from
`peer_sites`): this site's GNSS incidents from `sloth.db`, each peer's
from its `gnss_event` rows, and two the samples show: `JAM_IND`, the
jamming indicator at 128 or more, and `CN0_DROP`, the tracked median at
least 10 dB under the site's own median of the hour before (at least ten
samples; the dropped samples kept out of that median, as the rule holds
its onset baseline, so a standing drop is not absorbed into its own
reference; a sample tracking nothing while satellites are listed is
0 dB-Hz, the rule's reading). Each has a class: *interference*
(GNSS_JAMMING, JAM_IND, CN0_DROP), *spoof*, *time* or *position*.

**The classification.** For an event [a, b] at site S, over the sites
within `--peer-gnss-region-km` (default 50) of S:

| Verdict | When |
|---|---|
| regional | a site there has an event of the same class whose span comes within 120 s of [a, b] |
| local | none has, and at least one of them was covered over [a - 120 s, b + 120 s] |
| undetermined | none of them was covered: stale, unreachable, pulled only since, an older export with no incidents, no `sloth.db` here, an event still running or not yet pulled past its window, or no site within the region |

Covered means one span holds the interval, its last sample at or after
b + 120 s: a peer's incident in the window reaches this site only with
the next answer, so an event still running reads undetermined until it
has ended, the window has passed and each peer has been pulled again
(at the default 60 s, within about three minutes of its end). "Local"
says the event was seen at one site only while the others were
watching; it does not say where a source is. An incident needs `ev`
coverage (the peer's incidents were offered all along), or for
interference `rx` coverage when it lasted at least the gap, so a peer
sample fell inside it. A sample event (`JAM_IND`, `CN0_DROP`) takes only
the latter: a peer's sloth not firing its rule says nothing of a drop
under the rule's test. Each event lists the sites `with` the same
class, `quiet` (covered, nothing), `stale` (not covered) and `far`
(outside the region, or with no position). A site's position for the
region is its reference, else its newest fix, else what it last stated.
Events from before a site was first sampled read undetermined: there is
no record that the peer was observing then.

**The window, 120 s, is a choice with no source.** The jamming research
says so plainly: "No read source puts a number on 'simultaneous'"
(`research/gnss/jamming-detection.md`). It is two default pull
intervals, past the jamming rule's 30 s indicator hold and 10 s collapse
window, so one onset seen by two receivers a pull apart still pairs.
**The region, 50 km, is a choice too**: how far a ground-level source
reaches is not in the corpus.

**The basis of each class**, as the corpus holds it:

- *Interference*: "C/N0 collapsing on every satellite at once while the
  sky is unchanged", with the receiver's CW indicator as corroboration;
  interference and jamming are "the same effect", and "One receiver
  cannot bearing a jammer" (`research/gnss/jamming-detection.md`). A
  jammer aimed at one receiver affecting another nearby is the FCC's
  Bojczak case, quoted there. Two receivers seeing it at once are one
  source reaching both, or a wide one; one alone is a source near it.
  The 10 dB drop and the indicator's 128 are the GNSS_JAMMING rule's
  defaults, themselves judgements (`alert-assessments/GNSS_JAMMING.md`):
  the research gives no threshold for either. `JAM_IND` and `CN0_DROP`
  are slothweb's own tests on samples a pull apart, not the rule: they
  cannot see the simultaneity the rule looks for, so a `CN0_DROP` is
  interference or attenuation alike, the C/N0 half "that cannot tell
  interference from attenuation".
- *Spoof*: "a suspicion built from several weak observables, not a
  detection" (`research/gnss/spoofing-detection.md`). At both sites at
  once it is wide; at one, that receiver.
- *Time*: a step of the receiver's clock, 1000 ms: "anything below
  roughly a second is noise", over the gpsd HOWTO's 200 ms floor
  (`research/gnss/time-and-position-integrity.md`,
  `alert-assessments/GNSS_TIME_JUMP.md`).
- *Position*: for a fixed sensor "the bound collapses to the two error
  estimates" (`research/gnss/time-and-position-integrity.md`), and k = 3
  is the GNSS_POSITION_JUMP rule's own default, a judgement because
  gpsd's eph is "guessed to be 95% confidence, may also be 50%, one
  sigma, or two sigma" (`alert-assessments/GNSS_POSITION_JUMP.md`).

**The baseline.** Each site's displacement from its reference against
3 x its own eph, and for each pair the distance between the fixes now
against the distance between the references, bounded by
3 x (eph_a + eph_b). No eph, no bound, no claim, as the rule; an eph of
0 is no eph (it would make a 0 m bound and any metre of noise "moved"). A site past
its own bound is named (`moved`); one site alone gives the position
verdict `one_site` and that site, which moved or is being spoofed (the
two look alike here, as for the rule: "a spoofed position, multipath or
a receiver fault look alike"). The pair and the site checks differ on
purpose: a site moving along the line away from the other changes the
distance by less than it moved, so the distance can stay within the
pair's bound while the site is past its own; a common-mode spoof that
moves both sites alike keeps the distance and moves both references.

**The clock.** Each site's receiver offset (`time_offset_ms`: the
receiver's clock against its host's) now against its median of the hour
before; a step of 1000 ms or more at one site and not at the other
names that site (`time` verdict `one_site`). A peer's skew (its clock
against this one's at the pull, whole seconds) is shown beside it,
against its own median: a step in the offset with the skew still is
the receiver; a skew that moved is a host clock, but the skew is a
difference and does not say whose: this site's or the peer's. Where a
host is disciplined from its own receiver (W9FJC), that receiver's time
stepping moves the host after it, so its offset may step only until
the host has followed, and the step stays as every peer's skew moving;
the `time` verdict may then name no site, and the skews are the
evidence. Sub-second steps are
not seen: in-band GNSS time over USB without PPS is good to "not much
better than 1 second" (the HOWTO), and `generated` is whole seconds. A
patient pull of a GNSS-disciplined clock (W9FJC's is, through ntpsec)
moves the skew slowly and the offset not at all; the skew's median is
an hour, so a drag slower than that is not caught here either, as the
time research says of any jump test.

**`GET /api/fleet/gnss?limit=N`** (50, 1..200; GET only): `local`
(`sloth.db`: `open`, `none`, `unavailable`, `no_incidents` for a file
before v11; any but `open` leaves this site never quiet for an incident), `store`, the constants
(`window_s`, `gap_s`, `region_m`, `fresh_s`, `k`, `time_step_ms`,
`cn0_drop_db`, `jam_ind`, `ref_min`), `sites` (each receiver as its last
sample said, its `reference` and `time`, `covered_since`,
`observed_since`), `baseline` (each pair: `ref_m`, `now_m`, `delta_m`,
`bound_m`, `verdict` `within`/`outside`/`undetermined` with `why`,
`moved`), `position` and `time` (`consistent`, `one_site` with `site`,
`several`, or `undetermined` with fewer than two sites evaluated),
`counts` by verdict over the week, `events` newest first (`site`,
`type`, `class`, `source` `incident` or `sample`, `first_seen`,
`last_seen`, `count`, `sev`, `verdict`, `with`, `quiet`, `stale`, `far`),
`events_total`, `events_cut`, and `basis` (each class's sources, and the
window's and the region's "a choice, no source"). Every number is
finite or null. `/api/fleet/overview` gains `gnss`: `position`, `time`
and `events_24h` by verdict.

**The Fleet tab** gains "GNSS across the sites" after the map: a card
per receiver (state and satellites, C/N0, fix, distance from its
reference against its bound, clock offset and step, the jamming
indicator, whether its incidents are offered), a gauge per pair of sites
(the band is the bound around the reference distance, the mark the
distance now, drawn in the warning colour outside it) and the events
with their verdicts and the other sites, each row's basis on hover.

**At W9FJC and beta-site** (measured 2026-11-11, before this build ran
there): both u-blox 7 through gpsd, static, the fixes 13.9 m apart at
eph 6.1 and 5.4 m (a bound of 34 m), the headers' positions 14.8 m. In
the week W9FJC's `sloth.db` holds one GNSS_JAMMING incident (07:58 to
08:05 MST on 11-11) and one GNSS_TIME_JUMP (11-05); beta-site's alert
page shows eight GNSS_JAMMING incidents from 11-07 to 23:03 MST on
11-10. None of beta's comes within 120 s of W9FJC's, so on the raw times
each is single-site; with no coverage recorded before the build, the
route reads them undetermined until the samples cover a new one.
W9FJC's clock is disciplined from its receiver (ntpsec, SHM preferred);
beta-site's is ntpsec over the network pool only (its selected source a
stratum-1 PPS server, no refclock), so the two clocks are independent
and the skew compares a GNSS-steered clock with a network one.

## Aircraft across the sites (I7)

One ADS-B receiver cannot tell a real aircraft from one a transmitter
injected: ADS-B carries no authentication
(`research/adsb/emergency-squawks.md`). Two can check each other in the
coarsest way the literature lists, presence: an aircraft one receiver
places well inside the area a second receiver demonstrably hears, which
the second, hearing other aircraft at the time, never heard, is a
plausibility red flag (Strohmeier, Lenders and Martinovic, section V-F:
"Investigating airplanes which suddenly appear well within the maximum
communication range of a receiver", and a per-station map of where it
hears aircraft; `research/adsb/multi-receiver-verification.md`). Never a
detection: terrain, buildings and the antenna shadow a receiver, and a
weak transponder is heard shorter than the strongest one that set a
sector's reach.

**What travels.** With `adsb=1` (asked for only, like `gnss=1`; an I6
export refuses it, and the puller asks again with `gnss=1` and not with
`adsb=1` for the hour) the whole export adds:

- one `adsb_rx` line, this site's receiver: the decoder's source kind
  (`file`, never its path) and state, aircraft and message counts and
  messages/s between two summaries, and its **demonstrated coverage**:
  every airborne position `sloth.db` holds from the last 24 h, measured
  from the site's own position (the header's), as the farthest in each
  30-degree sector (`r000` .. `r330`, metres) with the positions counted
  (`n000` .. `n330`), and overall. A position beyond the horizon of an
  aircraft at 50,000 ft (521 km from a 10 m antenna) is no line-of-sight
  decode and is not counted, so a ghost far out cannot inflate it;
- one `aircraft` line per `adsb_aircraft` row changed since `since`
  within the last 6 h, newest first, at most 1,000: the ICAO address,
  callsign, squawk, category, emergency word, the newest altitude, ground
  speed, track, RSSI and messages, the newest position of the current
  visit with its time and altitude, and first seen, the visit's start
  and last seen. Each held to the importer's own checks first (an address
  of six lower-case hex digits, `~` first for a non-ICAO one; a squawk of
  four octal digits; a category A0..D7; one of sloth's eight emergency
  words; every number in range and finite);
- on the end line, `aircraft` (the lines sent) and `truncated_aircraft`.

No cursor and no backfill: the comparison needs the last two hours,
which at beta-site's measured rate (1,047 aircraft in 24 h) is far below
the cap; a cut answer instead makes its site undetermined over the time
it covered.

**The store.** `peer_sightings` kind `aircraft` (key the address, label
the callsign, vendor the category, `extra` the rest) and kind `adsb` (key
`receiver`), upserted like every kind (earliest first seen, newest last
seen); kept two days and at most 3,000 aircraft rows a peer by the
peer's clock, so a busy sky never crowds the other kinds out. `meta`
`fleet.adsb.<peer>` holds the peer's clock at its newest answer that
carried aircraft and at its newest cut one. No schema step.

**The comparison** (`web_fa_classify()`), per address over the last two
hours, every time in this site's clock (a peer's less its skew):

- `confirmed`: two receivers heard it at overlapping times, each
  receiver's [visit start, last seen + 300 s] within 120 s of the
  other's. 300 s is sloth's ADS-B write heartbeat (`src/db.c`): a
  receiver still hearing an aircraft writes it at least that often.
- `unconfirmed`: the reporting receiver's newest position (at time t)
  lies within 0.8 of a second receiver B's farthest decoded position in
  that bearing sector, the sector holding at least 10 positions, and
  within 0.8 of the radio horizon between B's antenna and the aircraft,
  d = 4.12 (sqrt h_rx + sqrt h_ac) km (the 4/3-earth line-of-sight
  distance; h_rx taken as 10 m, h_ac as the altitude less B's); and B
  was answering (its data complete past t + 120 s, its writer's 30 s lag
  allowed), not cut, hearing at least two other aircraft within
  [t - 120, t + 120], and had not heard the address since before
  t - 120 - 300 s.
- `out_of_peer_coverage`: the same, but the position lies beyond that
  for every such B, or in a sector B never showed 10 positions in.
- `undetermined`, with the reason: `single_receiver` (fewer than two
  receivers: every aircraft, today), `no_position`, `no_altitude` (or on
  the ground), and for B `pending` (no data past the window yet),
  `answer_cut`, `not_receiving`, `heard_later` (B's newest visit started
  after the window, so its earlier hearing cannot be ruled out).

Never a false `unconfirmed` by construction: every reason B might have
heard the aircraft without the data showing it reads `undetermined`;
the tests build each one and watch the guard's removal turn it
`unconfirmed`.

Separately, two receivers' positions for one address at most 600 s
apart that are further apart than the aircraft could fly between them
(its reported ground speed x 1.25 + 30 m/s, else 340 m/s, times the gap,
plus 2 km) are flagged `inconsistent`: the survey's "mobility grade
threshold" across receivers.

**The thresholds are choices with no source**: the survey does not
quantify "well within". 0.8 keeps the test off the edge of what B was
seen to reach; 10 positions a sector over 24 h keeps one lucky decode
from defining a sector; two other aircraft is the least evidence B was
receiving; 30-degree sectors are coarse enough to fill in a day at
beta-site's rate; 10 m for the antenna because sloth knows no antenna
height. The route's `basis` says so.

**`GET /api/fleet/aircraft?limit=N`** (100, 1..500; GET only): `local`
(this site's `sloth.db`: `open`, `none`, `unavailable`, `partial`),
`store`, `receivers`, `single_receiver`, the constants (`window_s`,
`heartbeat_s`, `list_s`, `cov_window_s`, `k`, `rx_agl_m`, `sector_min`,
`health_min`); `sites` (each: `receiver`, the decoder's `source`,
`state`, `summary_age_s`, `fresh`, `aircraft_now`, `messages`,
`msg_rate`, the position, `skew_s`, `through_age_s`, `cut_age_s`,
`held`, `positions`, `cov_complete`, `range_max_m` and `sectors`, twelve
`{from, max_m, n}`); `counts` by verdict and `inconsistent`; `aircraft`,
unconfirmed first, then inconsistent, then the most recently heard (each:
`hex`, `flight`, `squawk`, `category`, `emergency`, `alt`, `gs`, `track`,
`lat`, `lon`, `pos_ts`, `last_seen`, `verdict`, `why`, `ref` (the site
whose position was tested), `inconsistent` with `separation_m` and
`allowed_m`, `seen` per site (`first_seen`, `visit_first`, `last_seen`,
`rssi`, `messages`, `pos`, `range_m`), `peers` per other receiver
(`state`: `heard`, `should_have_heard`, `outside_coverage`,
`no_coverage`, `pending`, `answer_cut`, `not_receiving`, `heard_later`,
`no_position`, `no_altitude`; `dist_m`, `sector_max_m`, `horizon_m`));
`total`, `partial`, and `basis`. Every number is finite or null.
`/api/fleet/overview` gains `aircraft`: `receivers`, `single_receiver`,
the aircraft compared and the `counts`.

**The Fleet tab** gains "aircraft across the sites" after the GNSS
panel: a card per receiver (decoder state, aircraft and messages/s now,
coverage positions and the farthest, how old its data is) with a polar
plot of its coverage, north up, each sector drawn out to its farthest
decode scaled to the farthest of all; and a row per aircraft with what
was reported and by whom, the sites that heard it, the verdict (its
basis on hover) and each other receiver's state. With one receiver the
note says every aircraft is undetermined until a second site decodes
ADS-B.

**At W9FJC and beta-site** (measured 2026-11-11 from beta-site's own
`/api/adsb/seen` and `/api/adsb/aircraft`, before this build ran there):
beta-site's readsb heard 1,047 aircraft in 24 h, 867 of them with a
position, 8,327 positions in all; the farthest 80.6 km (bearing
240-270), the sectors from north clockwise 37.2, 43.1, 45.5, 68.5, 78.4,
58.2, 49.7, 64.5, 80.6, 60.3, 32.2 and 22.2 km, every sector above 190
positions. W9FJC has no ADS-B receiver (owner ruling: GPS, Wi-Fi and BLE
only), so the fleet has one receiver and every aircraft reads
`undetermined` (`single_receiver`): the cross-check is built and tested
on synthetic two-receiver data and is honestly inert until a second
site runs `--adsb`.

## Related pages

- [ADR 0008 — own fleet](adr/0008-own-fleet.md)
- [ADR 0006 — sharing is opt-in and sanitised](adr/0006-sharing-is-opt-in.md)
- [[slothweb]] — the dashboard this runs in, the Fleet tab among its tabs.
- [[location]] — the sensor positions the site block carries.
- [[rf-distance]] — the single-sensor RSSI distance whose model I5 uses.
- [[gnss]] — the receiver summary.
- [[adsb]] — the receiver the aircraft cross-check (I7) compares.
- [[data-socket-exposure]] — the other network surface and its rules.
- [[threat-model]]
