---
name: sqlite-schema
description: The --db SQLite sink — why it exists, the schema and its v1 → v8 migration chain, survey sessions, retention tiers, MISSION §2 guardrails, and query recipes
type: reference
---

# SQLite sink (`--db`)

**Summary**: `-o FILE` is the **wire format** — a stream other tools
consume. `--db FILE` is the **retained artifact** — durable entity state
and findings, upserted per entity rather than appended per tick, so a
month of operation costs megabytes instead of a terabyte.

**Sources**: `src/db.h`, `src/db.c`, `src/db_schema.c`,
`tests/test_db.c`, issues #42, #56, #154 and #170.

**Last updated**: 2026-10-26 (#170: schema v8, one `alerts` row per finding rather than per incident — the incident semantics below, the v7 → v8 step, and the opt-in `--db-compact-alerts` copy for the duplicates older builds wrote). 2026-10-23 (#163: the query recipes are slothweb's SQL box's, extracted at its build; three are refused there, the space recipe because `dbstat` gives away a withheld column's length). 2026-10-21 (#154: the v1 → v4 migration steps, so the chain now runs the full v1 → v7 and nothing below v5 is refused any more; also fixed a latent `check_version()` bug — reopening a file already at the current version could wrongly re-enter the migration chain once the floor reached v1, because "a schema_version row exists" and "the version to migrate from" shared one variable). 2026-10-21 (#155: schema v7, the devices classifier and DHCP option columns, the v6 → v7 step and the migration chain). 2026-10-20 (#106 round 2: schema v6, devices camera columns, the add-column-only v5 → v6 migration). Earlier: 2026-10-15 (#113: write path names `poll_tick()`; #134: sqlite3 >= 3.31.0 compile-time pin, SQLITE_OPEN_NOFOLLOW unconditional; #137).

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
  socket and gets no RPC. MISSION §4 forbids remote-control surfaces;
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

**sqlite3 >= 3.31.0 is a compile-time requirement** (#134). `src/db.c`
and `research/query.c` carry
`#if SQLITE_VERSION_NUMBER < 3031000 #error …`. The reason is
`SQLITE_OPEN_NOFOLLOW`: the `-wal` / `-shm` / `-journal` checks in
`db_prepare_private()` are advisory — a symlink can appear between the
`lstat` and SQLite's own open — and are acceptable only because SQLite
itself refuses to follow one. The flag used to sit behind an `#ifdef`
that compiled silently without it on older headers, which made the
side-file checks look stronger than they were on exactly the systems
where they were weakest. `rq_open()` (the read-only research corpus)
passes it too. 3.31.0 is from January 2020; every supported Debian,
Ubuntu, Fedora and Alpine ships newer.

**`SQLITE_DBCONFIG_DEFENSIVE` is on** (#137). `db_open()` sets it before
the first PRAGMA and reads it back; a library that does not honour it
fails the open (`DEFENSIVE refused`) rather than proceeding. The file
`--db` names may predate this run or have been written by something
else, and DEFENSIVE closes the schema-corruption paths
(`writable_schema`, direct shadow-table writes) that sloth never uses.
Only DEFENSIVE: `TRUSTED_SCHEMA=0` is for the research corpus, whose
schema somebody else wrote — see [[research-corpus]].

## Write path

```
poll_tick()                       (src/poll.c, #113)
  ├─ every snapshot refreshes sloth_state_t
  └─ db_tick(state, now)          ← DURABLE, the last phase: fully-refreshed state
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

- **Private files (#87).** SQLite would create the database `0644 &
  ~umask` and gives `-wal` / `-shm` the main file's mode, so sloth
  creates the database file itself at **0600** first (by descriptor,
  `O_NOFOLLOW`) and opens it with `SQLITE_OPEN_NOFOLLOW`; the WAL and
  shared-memory files inherit 0600. An existing database, `-wal`, `-shm`
  or `-journal` that is a symlink, belongs to another user, has more
  than one link or carries any group/other bit is **refused** — `db_open`
  fails and startup stops. sloth never `chmod`s it. A database written
  by an older build is typically `0644`; before upgrading, `chmod 600
  FILE FILE-wal FILE-shm` (as the owning user) once.
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
| One row per finding; `count` sums incidents, `reopens` counts them | `alerts` | A write continues the key's newest row, so evict-and-refire, a quiet-period reopen and a restart all advance one row (#170). See *Findings and incidents* below. |

## Schema — 41 tables, v1 → v8

`meta` holds `schema_version`, currently **8**. `db_open()` checks it
*before* applying the rest of the schema, so a mismatch produces the
clear version message rather than whatever SQL error the schema happens
to hit first. Since #154 the chain covers the full **v1 → v8**: any
file this build has ever written opens and migrates forward. Only a
file from a *newer* build (`schema_version` above 8) is refused.

**v5** (#90): `karma_candidates.pnl_best`. **v6** (#106 round 2):
`devices` gains `device_class`, `camera_vendor`, `camera_model`,
`setup_mode`, `cam_signals` — see [[camera-detection]]. **v7** (#155):
`devices` gains `cam_score`, `cam_evidence` (`CAM_EV_*` mask),
`cam_vetoes` (`CAM_VETO_*` mask), `cam_conflict`, `dhcp_prl` and
`dhcp_vci` (the client's DHCP options 55 / 60, display-only), and
`device_class` may now hold 3, `not-camera`. **v8** (#170): `alerts`
gains `reopens`, `incident_id` and `incident_count`, and its rows become
one per finding — *Findings and incidents* below.

**The v7 → v8 migration.** Three `ALTER TABLE alerts ADD COLUMN`
statements with defaults (`db_schema_migrate_v7_sql()`) and the stamp,
in one `BEGIN IMMEDIATE` transaction. No v7 value changes — including
the duplicate rows an older build wrote, which stay exactly as they
were; folding them is `--db-compact-alerts`, on a copy, never the
migration. A v7 row reads `reopens` 0, `incident_id` NULL,
`incident_count` 0, and the first v8 write for its key continues the
key's newest row as a reopen. Tested on a v7 file holding three rows for
one key (`test_v7_file_migrates_additively`) and on one whose last ALTER
fails, which stays v7 with none of the step's columns
(`test_v7_migration_failure_leaves_file_unchanged`).

**The v6 → v7 migration.** Six `ALTER TABLE devices ADD COLUMN`
statements with defaults (`db_schema_migrate_v6_sql()`) and the stamp,
in one `BEGIN IMMEDIATE` transaction; no v6 value changes (a v6 row's
`device_class` was 0..2 and stays so). Tested on a v6 file holding a
camera row (`test_v6_file_migrates_additively`) and on one whose last
ALTER fails, which stays v6 with none of the step's columns
(`test_v6_migration_failure_leaves_file_unchanged`).

**The chain.** `src/db.c`'s `g_steps[]` lists one entry per step (`from`
1 through 7) and runs every one from the file's version up, each in its
own transaction with its own stamp, so a v1 file opened by this build
goes v1 → v2 → v3 → v4 → v5 → v6 → v7 → v8 in one `db_open()` call. A step
that fails leaves the file at the last version it fully reached — a v3
file whose next step fails is a v4 file, never half of v5
(`test_v3_chain_stops_at_last_whole_step`) — and `db_open()` refuses the
open (though the partial progress already committed stays on disk).
Each step also names the table(s) its `ALTER`s touch (`tables[]`); if
one of them was never created (a file that stopped very early), the
step skips its `ALTER` and only stamps, since the unconditional schema
below creates that table whole regardless of the stamped version. A
static check fails the build unless the steps run from
`DB_MIGRATES_FROM` to `DB_SCHEMA_VERSION` without a gap, so a bump
without its step does not compile.

**#154 also fixed a latent bug in `check_version()`.** It used one
variable both as "a `schema_version` row exists" and as "the version to
migrate from" (reusing the boolean `1` as a fake low version number when
no migration was needed). That was harmless while `DB_MIGRATES_FROM` was
5, because `1 < 5` ; once it dropped to 1, a file already sitting at the
current version satisfied `found >= DB_MIGRATES_FROM` on the strength of
the stale flag and got silently re-run through the whole chain,
failing on the first `ALTER` since every column already existed —
`db_open()` on an up-to-date file started returning 0. Fixed by tracking
the real migrate-from version (`-1` when none applies) separately from
whether a row was found at all.

**Upsert and `not-camera`.** `not-camera` is a verdict against, not a
higher "for", so the `devices` upsert never lets it override the class
a row's MAC-keyed beacon bits imply (setup SSID 2, OUI 16): that history
keeps its class and the row is written `cam_conflict` 1, as the live
classifier would. For 0..2 the rule is the `MAX` it was. The other v7
columns are the latest tick's.

**The v5 → v6 migration.** The first migration `db_open()` performs, and
deliberately the only kind it will: five `ALTER TABLE devices ADD
COLUMN` statements with defaults (`db_schema_migrate_v5_sql()`), plus the
version stamp, in one `BEGIN IMMEDIATE` transaction. No existing value
is rewritten, so a v5 forensic record reads the same afterwards; a
statement that fails rolls the whole step back and the file stays v5
(`tests/test_db.c :: test_v5_migration_failure_leaves_file_unchanged`).
Only a file newer than v8 is refused.

**Migration path, by design** (owner ruling 2026-10-21, replacing the
earlier "no migration path by design"). Every schema bump ships its
migration from the previous version in the same change, and the steps
chain, so `db_open()` brings a file of any supported age forward one
version at a time. A migration preserves forensic values: it adds
columns or tables with defaults, and where a change would alter what
stored data means it keeps the old column or table and adds the new one
beside it, never rewriting a recorded value in place. Each step is one
`BEGIN IMMEDIATE` transaction, tested on a file built at the previous
version, including the failure that leaves the file unchanged. Only a
file from a newer build is refused. `src/db.c` carries
a static check that the step list ends at `DB_SCHEMA_VERSION`, so the
next bump does not build until its step is written.

**When to bump.** Adding a whole new table is safe without a bump —
`CREATE TABLE IF NOT EXISTS` runs on every open, so an older file simply
gains it. Adding a **column to an existing table** is not: that
statement is a no-op on a table that already exists, and the column
never appears. **v2** exists because `probe_clients.presence` (#53) was
added without a bump, so a v1 file failed at schema application with a
confusing SQL error instead of the clear version message — the v1 → v2
step (#154) adds the column. **v3** is the one exception that proves the
rule above: `assoc_reqs` (#60 slice 5a) is a *new table*, so by this
same rule it needed no bump at all — `METRICS.md` row `60e` records that
the bump was taken anyway, and the no-bump call was independently
confirmed three weeks later when `#59`'s `btm_requests` (also new) rode
the then-current version with no bump of its own. The v2 → v3 step
(#154) therefore has no `ALTER` statement; it only advances the stamp,
and `assoc_reqs` gets created by the unconditional schema below exactly
as it would on any other version.

**v4 is a deliberately batched bump.** Four columns across three issues
each wanted one, and each on its own was a poor trade — making every
existing database refuse to open, for one field:

| Issue | Column | Table |
|---|---|---|
| `#60` | `phy_confirmed` | `pnl_clients` |
| `#62` | `downgrade_flags`, `akm_bits` | `beacon_aps` |
| `#65` | `nocert_sessions`, `nocert_no_hello`, `last_nocert_sta`, `last_nocert_ts` | `rogue_radius` |

Taken together it is one break instead of three, and it is the right
moment to take the next one too: if you are adding a column, look at
what else has been deferred first. The v3 → v4 step (#154) applies all
seven `ALTER`s across the three tables in one transaction: a v3 file on
which the last one fails keeps v3, none of the seven, including the two
that would have applied cleanly on their own
(`test_v3_migration_failure_leaves_file_unchanged`).

The consequence worth remembering when reading a slice note: `#59`'s
`btm_requests` and anything else that adds only a *table* rides the
current version. There is also no automated guard here — a fresh file
gets every table regardless of version, so a missing bump only surfaces
when an existing older database is opened, which `tests/test_db.c`'s
v1 → v4 migration tests now do.

**v5** (#90, above) is the v4 → v5 step (#154): one `ALTER TABLE
karma_candidates ADD COLUMN pnl_best` and the stamp. A v4 file on which
it fails (`pnl_best` already there) keeps v4 and its row unchanged
(`test_v4_migration_failure_leaves_file_unchanged`).

### Entities — "who was here"

Keyed by natural identity, bounded by the fixed arrays in `sloth.h`.

| Table | Key | Notes |
|---|---|---|
| `devices` | `mac` | synthesised profile + risk signals; camera identity since v6 (`device_class`, `camera_vendor`, `camera_model`, `setup_mode`, `cam_signals` — sticky only for the MAC-keyed beacon bits 2 and 16: those OR, the class they imply and `setup_mode` only rise, and the vendor stays while they stand; the IP-joined bits, the class they alone gave and `camera_model` are the latest tick's, so a reused lease does not write a camera onto another host's MAC for good — see [[camera-detection]]). An IP-only camera record (no MAC) is not written. Since v7 also `cam_score`, `cam_evidence`, `cam_vetoes`, `cam_conflict`, `dhcp_prl`, `dhcp_vci` (#155), the latest tick's; `device_class` 3 (`not-camera`) never overrides a MAC-keyed camera class |
| `pnl_clients` / `pnl_ssids` | `mac` / `(mac, ssid)` | split so *"which devices remember network X"* is a join, not a scan of repeated JSON arrays — the deanonymisation question |
| `probe_clients` | `mac` | unassociated 802.11 devices |
| `beacon_aps` / `beacon_ap_ssids` | `bssid` / `(bssid, ssid)` | passive monitor inventory; the SSID child table is the KARMA signal and the multi-VAP topology record |
| `wifi_aps` | `bssid` | nl80211 scan list — kept **separate** from `beacon_aps` because they are different observations with different trust: what we heard on the air versus what the kernel reports |
| `wifi_stas` | `mac` | |
| `assocs` | `(bssid, sta_mac)` | graded evidence; see the upsert rule above |
| `assoc_reqs` | `(bssid, sta_mac)` | what the client *asked* for (#60) — the ask beside the grant. `downgrade_flags` OR-accumulates: a client recovering to strong parameters does not erase having been moved onto weak ones |
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
one row whose `count` and `last_seen` advance, not 3600 rows. For
`alerts` the episode is the *finding*, below.

#### Findings and incidents (`alerts`, #170)

Two units, deliberately different:

- An **incident** (#98) is one continuous run of a dedup key in the
  engine: it opens with `alert.create`, carries one `incident_id`, and
  closes with exactly one `alert.resolve` — after
  `ALERT_RESOLVE_AFTER_S` (300 s) with no rule re-asserting it, when the
  engine evicts it for room, or when its rule clears it. A key that
  fires again opens a **new** incident with a new id. Incidents are the
  JSONL lifecycle stream's unit ([[jsonl-schema]]), and that stream is
  where the gaps between them are recorded.
- A **finding** is every incident of one key, for as long as its row is
  retained. It is the `alerts` row's unit: a re-fire of the key — after
  an eviction, after a quiet period, or in a later process — advances
  the key's newest row rather than starting one.

So one row per key in steady state, and:

| Column | Meaning |
|---|---|
| `first_seen` | the finding's first sighting; never moved by a write |
| `last_seen` | MAX, as everywhere |
| `count` | evaluations, **summed across incidents**: a write of the incident already on the row adds what its count moved since the last write; a write of a different incident adds its whole count |
| `reopens` | incidents after the first that this row absorbed |
| `incident_id` | the latest of them — the join into the JSONL stream |
| `incident_count` | that incident's own count as last written, so `count` never double-counts the one still open |
| `sev`, `detail` | the latest write's, as before |
| `type`, `title`, `technique`, `match_ip`, `match_port` | the first write's |

How it holds: the engine keeps a key's `first_seen` across every reopen
in its side table (`alert_side_t`, #112 — before #170 only across an
eviction), and the writer looks up the key's newest row
(`ST_ALERT_ROW`, a seek on the primary key's prefix) and writes to that
`first_seen` whatever the engine says. The second is the guarantee: the
side table is 512 rows LRU and dies with the process, and the owner's
sensor had 7,598 keys. `tests/test_db.c ::
test_alert_evict_refire_churn_is_one_row` evicts and re-fires one key
100 times under enough key pressure that the side table forgets it each
time, and gets one row with `reopens` 100;
`test_alert_finding_outlives_a_restart` does it across a close and
reopen.

Why not one row per (key, incident): the owner's v6 file held
**867,748 rows for 7,598 keys**. Its rate fell from about 130,000 rows a
day to about 2,500 on 2026-10-21, the eviction churn #112 addressed; of
the 12,317 rows written from 2026-10-22 to 10-26, 9,704 were a known key
back after a gap longer than the 300 s resolve period (most of them
five minutes to an hour) — the reopens a per-incident row would keep
producing forever. The gap the old per-episode row
showed is not lost: it is in the JSONL stream, and `reopens` says how
many there were. Retention still applies: a key whose row ages out of
the finding tier (12× `--db-retain-days`) and fires again starts a new
row.

#### Compacting an older file (`--db-compact-alerts`)

The migration never rewrites a recorded value, so the duplicates a
pre-#170 build wrote stay in the file. Folding them is an explicit,
offline copy the operator runs and then decides what to do with:

```bash
sloth --db-compact-alerts data/sloth.db data/sloth-compact.db
```

- SRC is opened **read-only** and never written; the test holds it
  byte-identical. A file in WAL mode should be from a stopped sensor
  (or a snapshot), so the copy includes what its `-wal` holds.
- DST must not exist — nor `DST-wal`, `-shm` or `-journal`, which SQLite
  would replay into the copy. It is created `0600`, filled with `VACUUM
  INTO`, migrated to this build's schema, compacted in one transaction
  and `VACUUM`ed. A failure removes it.
- One row per key: MIN `first_seen`, MAX `last_seen`, summed `count`,
  **peak** `sev`, `reopens` = rows − 1 (plus any `reopens` a v8 row
  carried), and the most recent row's `detail`, `title`, `type`,
  `technique`, `match_*` and incident join. Peak rather than latest
  severity because a folded row stands for many incidents and the worst
  of them is what an investigator asks for first.
- Prints the counts and the time, and exits. Every other table is
  copied as it was.

On a copy of the owner's 254 MB snapshot (2026-10-26): 867,748 rows for
7,598 keys → 7,598 rows, file 245 MB → 13.7 MB, 17 s, source checksum
unchanged. A generated 900,000-row v7 table compacts in 3.5–7 s on the same host
(`test_compact_alerts_900k_rows` prints its timing). Swapping the
compacted file in — stop the sensor, move it over `--db`'s path, start
— is the owner's call, and the original is the backup.

`alerts`, `cleartext_creds`, `eapol_events`, `deauth_events`,
`seqnum_correlations`, `twin_episodes`, `scan_entries` /
`scan_entry_ports`.

`scan_entries` is **flagged-only** (#41): an unflagged entry is one host
touching a couple of ports — ordinary traffic — and persisting it would
put the CDN false positives #41 removed back into the durable record.

### Detector evidence — "why we concluded that"

`karma_candidates` (#30), `rogue_radius` (#31) and `btm_requests` (#59).

The first two closed a real hole: neither struct had a `jsonl_emit_*` at
all, so the alert survived while the reasoning behind it — SSID/PNL
overlap, Jaccard, IE uniformity, deauth chain, offered EAP methods,
identity leaks — was TUI-only and gone on exit. 96 rows maximum.

`btm_requests` records **every** 802.11v steer, forcing or not, keyed by
`(bssid, sta_mac)`. Storing only the alerting subset would leave no
baseline: ordinary load balancing and a forced roam are the same frame,
separated by one bit and a rate. Counters upsert with `MAX` rather than
`excluded`, because the in-memory table is LRU-evicted and a pair that
ages out and returns restarts at 1 — taking the fresh value would erase
the steering that justified an alert still sitting in `alerts`.

## Survey sessions

`sessions` records one row per run — `started`, `ended`, and the
`--site-label` if given. It exists so a returning surveyor can ask *what
is new since last time*.

The data for that was already present: `first_seen` is MIN-ed across
every upsert, so an entity seen on a previous visit keeps its original
timestamp and only genuinely new ones fall inside the current window.
The session boundary is the only thing that was missing.

`--report` grows a **New since last survey** section listing new APs,
devices and probe clients. A session that never recorded an end (crash,
`kill -9`) falls back to its own start rather than reading as "no
previous visit", which would flood the next report with the whole site.

```sh
# what arrived between the last two visits, by hand
sqlite3 sloth.db "
  SELECT mac, vendor, datetime(first_seen,'unixepoch') FROM devices
  WHERE first_seen >= (SELECT COALESCE(ended,started) FROM sessions
                       ORDER BY started DESC LIMIT 1 OFFSET 1)
  ORDER BY first_seen DESC;"
```

## Retention

`--db-retain-days N` (default 30) sets the window for **observation**
rows. Entities keep **3×**, findings keep **12×**.

| Tier | Window | Contents |
|---|---|---|
| observation | 1× | protocol flows, deauths, twins, EAPOL, scans, seqnum correlations |
| entity | 3× | devices, PNL, beacons, assocs, ARP, leases, discovery, sensors |
| finding | 12× | `alerts`, `cleartext_creds`, `karma_candidates`, `rogue_radius`, `btm_requests` |

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

`--db-max-mb N` (default 512, 0 = unlimited) is a **pruning trigger, not
a cap**. On breach the **oldest observation rows go first** — entity,
alert, credential and detector-evidence rows are never dropped by this
guard. A sensor that fills its disk should lose telemetry, not the
findings the disk was being kept for. If pruning every eligible row
still leaves the file over target, that is reported once and the file is
allowed to exceed it: discarding evidence to satisfy a number is the
worse failure. The guard is also bounded at 64 pruning rounds per pass
and measures only the main database file, not `-wal`/`-shm`.

Maintenance runs hourly, after the write, so a pruning stall never
delays the observation that triggered it — which also means it runs
only while sloth is running, and the first pass is an hour after the
first write. Age-out is `last_seen < cutoff`, so a row that keeps being
refreshed never expires.

> Retention is an **investigative tradeoff, not a deletion guarantee**,
> it covers nothing outside this file, and row deletion is not secure
> erasure. [[retention]] states exactly what is and is not covered —
> read that before citing sloth in a data-handling document.

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

These are also slothweb's SQL box recipes ([[slothweb]], M5): its build
extracts every quoted statement below as written, and stops on a
`sqlite3` line written any other way. The box withholds
credential-bearing columns from the browser, so it refuses the two
recipes that read one (`alerts.detail`, `cleartext_creds.username`),
and `dbstat` too (a table's payload less its readable columns is the
withheld one's length), so the space recipe is refused as well; run
those three here.

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
