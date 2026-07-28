---
name: sqlite-schema
description: The --db SQLite sink — why it exists, the 38-table schema v1, retention tiers, MISSION §2 guardrails, and query recipes
type: reference
---

# SQLite sink (`--db`)

**Summary**: `-o FILE` is the **wire format** — a stream other tools
consume. `--db FILE` is the **retained artifact** — durable entity state
and findings, upserted per entity rather than appended per tick, so a
month of operation costs megabytes instead of a terabyte.

**Sources**: `src/db.h`, `src/db.c`, `src/db_schema.c`,
`tests/test_db.c`, issue #42.

**Last updated**: 2026-07-28.

---

## Why it exists

A production sensor writing `-o` produced **12.6 GB in 8 hours**
(~38 GB/day), and after 12 hours the operator could not `jq` the file
interactively — a full-log query timed out. Roughly half that volume was
unchanged snapshot rows: the same entity re-serialised every poll
because it was still there.

Change-only emission (#44) cut the re-serialisation on the wire. The
sink attacks the other half of the problem: **sloth's persisted
cardinality is bounded by construction**. Every entity table in
`include/sloth.h` is a fixed array — `MAX_DEVICES` 256,
`MAX_BEACON_APS` 256, `MAX_PNL_CLIENTS` 128, `MAX_WIFI_MERGED` 512.
Upserting per entity with `first_seen` / `last_seen` instead of
appending per tick turns 38 GB/day into an estimated 15–30 MB (home),
~140 MB (busy office), ~350 MB (conference).

That pair of columns is also what makes the file *queryable*: **"who was
here between 2 and 4 AM" is a range scan, not a log grep.**

`-o` and `--data-socket` are unchanged and are not deprecated. What
changed is positioning, in docs only: JSONL is the wire format and SIEM
contract; the SQLite file is the retained artifact.

## What it is not

- **Not a query surface.** The database is never served over the data
  socket and gets no RPC. MISSION §4 rules out remote-control surfaces;
  a local file is a sink, and that distinction only holds if there is no
  way to reach it remotely. Operators query with the `sqlite3` CLI.
- **Not a replacement for pcap.** Per-alert pcap export
  ([[pcap-export]]) is still where packet-level evidence lives.
- **Not on by default.** No `--db`, no database, no dependency cost at
  runtime.

## Building

`WITH_SQLITE ?= 1` links the system `libsqlite3`, cloned from the
`WITH_PCAP` block. `make WITH_SQLITE=0` builds without it; `make
embedded` already excludes it, so the zero-dependency embedded target is
unchanged. CI builds both.

## Write path

```
poll_data()
  ├─ every snapshot refreshes sloth_state_t
  └─ db_tick(state, now)          ← last, so it sees fully-refreshed state
       ├─ BEGIN IMMEDIATE
       ├─ ~29 prepared upserts
       └─ COMMIT       … then hourly: db_maintain()
```

**It reads `sloth_state_t` directly and cannot hang off the jsonl
emitters.** Every `jsonl_emit_*` opens with `any_sink()`, which is false
when neither `-o` nor `--data-socket` is active — so a `--db`-only run
would silently write an empty database. Routing through
`jsonl_changed()` would also make durable `last_seen` lag by up to the
300-second heartbeat, coupling durable state to a wire-format
optimisation.

- **WAL** so a reader (your `sqlite3` session) never blocks the writer.
- **`synchronous=NORMAL`** — fsync at checkpoint, not per commit. At
  1 Hz on an SD card the difference is the card's lifetime; the exposure
  is the last few seconds of telemetry on a power cut, which a passive
  sensor can afford.
- **`BEGIN IMMEDIATE`** takes the write lock up front, so a competing
  writer fails fast instead of surfacing at COMMIT with a batch staged.
- **Fail-open, always.** Any error disables further writes and reports
  once. A database problem costs the operator persistence, never
  visibility.

## Upsert semantics

These are what make the file trustworthy rather than merely present.

| Rule | Where | Why |
|---|---|---|
| `first_seen` = MIN, `last_seen` = MAX | every table | A re-observation never moves the start of an entity's history; an out-of-order tick cannot rewind its end. |
| `assocs.source` prefers the smaller **non-zero** value | `assocs` | `ASSOC_SRC_*` is ordered **strongest-first** (EAPOL=1, ASSOC=2, REASSOC=3). A naive MAX preserves the *weakest* evidence and silently downgrades confirmed handshakes. 0 is UNKNOWN — absence of evidence — and must never win despite sorting below everything. |
| Flow counters = MAX | protocol flows | The in-memory rings reset counts on eviction; the durable row means "what has this pair done", not "since the last eviction". |
| `sensor_mask`, `proto_mask`, `eap_types_seen` = OR | merge / RDP / RADIUS | Coverage and offered-capability bits accumulate. A radio that heard an entity once still heard it. |
| SMB `dialect` sticky to `SMB1` | `smb_sessions` | Once a flow has spoken SMB1 that *is* the finding; a later SMB2 negotiation must not erase it. |
| Evidence flags latch | deauth, twins, karma | A burst that crossed the flood threshold *was* a flood; a twin caught mid-attack was caught mid-attack. |
| `sev` / `detail` track latest | `alerts` | Matches how `fire()` overwrites them in the live engine. |

## Schema v1 — 38 tables

`meta` holds `schema_version`. `db_open()` refuses a file whose version
differs from the running build, in either direction: with one version
defined, a mismatch can only mean a hand-edited or corrupt file, and
writing into it would produce rows a reader misinterprets.

### Entities — "who was here"

Keyed by natural identity, bounded by the fixed arrays in `sloth.h`.

| Table | Key | Notes |
|---|---|---|
| `devices` | `mac` | synthesised profile + risk signals |
| `pnl_clients` / `pnl_ssids` | `mac` / `(mac, ssid)` | split so *"which devices remember network X"* is a join, not a scan of repeated JSON arrays — the deanonymisation question |
| `probe_clients` | `mac` | unassociated 802.11 devices |
| `beacon_aps` / `beacon_ap_ssids` | `bssid` / `(bssid, ssid)` | passive monitor inventory; the SSID child table is the KARMA signal and the multi-VAP topology record |
| `wifi_aps` | `bssid` | nl80211 scan list — kept **separate** from `beacon_aps` because they are different observations with different trust: what we heard on the air versus what the kernel reports |
| `wifi_stas` | `mac` | |
| `assocs` | `(bssid, sta_mac)` | graded evidence; see the upsert rule above |
| `wifi_merged` | `entity` | multi-radio coverage (#21) |
| `arp` | `(ip, mac)` | |
| `dhcp_leases` | `ip` | |
| `top_hosts` | `ip` | byte counters keep the high-water mark, since state resets them on ring eviction |
| `mdns_services` / `nbns_names` / `ssdp_devices` | `instance` / `(name, suffix)` / `usn` | |
| `ndp_ras` / `ndp_ra_prefixes` | `src_ip` / `(src_ip, prefix)` | |
| `sensors` | `(kind, iface)` | passive sensor registry (#28) |

### Protocol flows — "what was happening"

Aggregates per endpoint pair, not per packet.

`bgp_sessions`, `ssh_flows`, `rdp_flows`, `snmp_flows`, `mqtt_flows`,
`ldap_events`, `kerb_events`, `smb_sessions`.

### Events — "what fired"

Keyed by **episode**, not by tick: an alert that persists for an hour is
one row whose `count` and `last_seen` advance, not 3600 rows. A second
episode under the same key *is* a new row, because `first_seen` is part
of the identity and merging would erase the gap between them — which is
the interesting part for an investigator.

`alerts`, `cleartext_creds`, `eapol_events`, `deauth_events`,
`seqnum_correlations`, `twin_episodes`, `scan_entries` /
`scan_entry_ports`.

`scan_entries` is **flagged-only** (#41): an unflagged entry is one host
touching a couple of ports — ordinary traffic — and persisting it would
put the CDN false positives #41 removed back into the durable record.

### Detector evidence — "why we concluded that"

`karma_candidates` (#30) and `rogue_radius` (#31). These closed a real
hole: neither struct had a `jsonl_emit_*` at all, so the alert survived
while the reasoning behind it — SSID/PNL overlap, Jaccard, IE
uniformity, deauth chain, offered EAP methods, identity leaks — was
TUI-only and gone on exit. 96 rows maximum.

## Retention

`--db-retain-days N` (default 30) sets the window for **observation**
rows. Entities keep **3×**, findings keep **12×**.

| Tier | Window | Contents |
|---|---|---|
| observation | 1× | protocol flows, deauths, twins, EAPOL, scans, seqnum correlations |
| entity | 3× | devices, PNL, beacons, assocs, ARP, leases, discovery, sensors |
| finding | 12× | `alerts`, `cleartext_creds`, `karma_candidates`, `rogue_radius` |

The ordering is what an investigator reaches for months later: *what
fired* outlives *who was here*, which outlives *the individual
observations that established it*. A single uniform window would drop
all three together and lose the alert that made the file worth keeping.

Detector evidence sits in the **finding** tier deliberately. At 3× it
would expire while the CRIT it justifies was still retained at 12× —
recreating the #30/#31 hole through retention rather than through a
missing emitter.

Everything does eventually age out. Findings keep twelve times longer,
not forever.

`--db-max-mb N` (default 512, 0 = unlimited) is a hard ceiling. On
breach the **oldest observation rows go first** — entity, alert,
credential and detector-evidence rows are never dropped by this guard. A
sensor that fills its disk should lose telemetry, not the findings the
disk was being kept for. If pruning every eligible row still leaves the
file over the ceiling, that is reported once and the file is allowed to
exceed it: discarding evidence to satisfy a number is the worse failure.

Maintenance runs hourly, after the write, so a pruning stall never
delays the observation that triggered it.

> **`auto_vacuum` caveat.** `PRAGMA auto_vacuum=INCREMENTAL` is
> requested at open, but SQLite only honours it on a **newly created**
> file — it cannot be changed on an existing database without a full
> `VACUUM`. A database created before that pragma landed reuses freed
> pages instead of returning them: the file stops growing, but will not
> shrink. `sqlite3 sloth.db VACUUM;` once, offline, if you need the
> space back.

## MISSION §2 guardrails

Enforced by `tests/test_db.c`, not by convention — a future column that
violates one turns the suite red.

1. **No column can hold secret material.** No column named for a secret
   may be TEXT or BLOB. Checked against the *live* schema via
   `pragma_table_info`, so it covers tables added later.
2. **No column is named for a secret**, whatever its type — no
   `password`, `passwd`, `pmkid`, `anonce`, `snonce`, `mic`.
3. **The bytes are not there.** A test seeds an EAPOL event carrying
   recognisable material in `pmkid` / `anonce` / `snonce` / `mic`, ticks,
   then **scans the raw database file** and asserts none of it appears —
   with a string we *do* persist as a positive control, so a pass means
   "absent" rather than "the scan is broken". A schema assertion cannot
   catch a leak through a future column, an index, or a stray bind.

The distinction the schema draws is **identifier versus secret**:

- **Kept** — usernames and identifiers that crossed the wire in the
  clear: `cleartext_creds.username`, RDP mstshash cookies, MQTT
  usernames, leaked EAP identities, SSH server banners. That is the
  exposure *fact*, which is the finding.
- **Kept as flags** — `pw_observed`, `has_pmkid`. 0/1, named to match
  the JSONL fields exactly. They record that an exposure was observed.
- **Never kept** — the secrets themselves. PMKID / ANonce / SNonce / MIC
  stay in the `--eapol-dir` hashcat file the operator explicitly asked
  for. **SNMP community strings are not persisted either**, in any form:
  a v1/v2c community string is a shared secret, so it gets the same
  treatment as a PMKID. The distinct community *count* is kept, which is
  what `SNMP_COMMUNITY_BRUTE` keys on.

> Note the SNMP case deviates from the wire format on purpose: `jsonl.c`
> *does* emit `last_community`. A stream the operator chose to write is
> not the same artifact as a database accumulating for months — the same
> distinction #42 drew for `--eapol-dir`.

## Query recipes

```sh
# Which devices remember a given network? (the deanonymisation question)
sqlite3 sloth.db "SELECT mac, first_seen, last_seen FROM pnl_ssids
                  WHERE ssid='CorpWiFi' ORDER BY last_seen DESC;"

# Who was here between 02:00 and 04:00?
sqlite3 sloth.db "SELECT mac, vendor, hostname FROM devices
                  WHERE last_seen  >= strftime('%s','2026-07-28 02:00:00')
                    AND first_seen <= strftime('%s','2026-07-28 04:00:00');"

# Findings by severity, most recent first
sqlite3 sloth.db "SELECT datetime(last_seen,'unixepoch'), title, sev, detail
                  FROM alerts ORDER BY sev DESC, last_seen DESC LIMIT 20;"

# Every AP that ever advertised more than one SSID (KARMA / multi-VAP)
sqlite3 sloth.db "SELECT bssid, COUNT(*) n FROM beacon_ap_ssids
                  GROUP BY bssid HAVING n > 1 ORDER BY n DESC;"

# A Pineapple candidate with the evidence behind it
sqlite3 sloth.db "SELECT bssid, score, ssid_count, pnl_overlap,
                         pnl_jaccard_ppm, ie_uniform, deauth_chain
                  FROM karma_candidates ORDER BY score DESC;"

# Cleartext credential exposures (usernames only, by design)
sqlite3 sloth.db "SELECT datetime(ts,'unixepoch'), src, dst, protocol,
                         username, pw_observed FROM cleartext_creds;"

# What is actually taking the space?
sqlite3 sloth.db "SELECT name, SUM(pgsize) b FROM dbstat
                  GROUP BY name ORDER BY b DESC LIMIT 10;"
```

## Related pages

- [[jsonl-schema]] — the wire format, and the change-only emission this
  complements.
- [[log]] — doc-change record.
- [[alerts]] — what populates the `alerts` table.
- [[pcap-export]] — where packet-level evidence lives instead.
