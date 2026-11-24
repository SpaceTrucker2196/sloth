---
name: retention
description: What sloth actually deletes, when, and what it never touches — tiered --db retention, the size guard's real behaviour, and the artifact classes outside both
type: reference
---

# Retention — what is actually deleted

**Summary**: `--db` ages rows out on three tiered windows and prunes
observation rows when the database file exceeds `--db-max-mb`. That is
an **investigative tradeoff**, not a deletion guarantee: it is not a
"30-day deletion" promise, it is not a hard disk cap, and row deletion is
not secure erasure. Separately, the one artifact class that is
offline-crackable — EAPOL / PMKID exports — is opt-in behind
`--collect-handshakes` and swept on a 7-day default window (§2c), and
per-alert pcaps in `--pcap-dir` are swept on a 14-day default window
(§2d, #166). JSONL and report artifacts still have no retention at all.

**Sources**: `src/db.c` (`db_maintain`, `prune_tier`, `db_purge_random_step`, `rd_apply`,
`prune_oldest_observations`, `db_size_bytes`), `src/db.h`
(`DB_DEFAULT_RETAIN_DAYS`, `DB_DEFAULT_MAX_MB`, `DB_RANDOM_PURGE_AGE_S`, `DB_RANDOM_REPEAT_DEFAULT_S`, `DB_RANDOM_PURGE_SCAN`), `src/db_schema.c`, `src/tune.c` (`retention.random_repeat_s`),
`tests/test_db.c`, issue #96; `src/secure_file.c` for §4.1 (#87);
`src/eapol_log.c` (`eapol_sweep`, `eapol_maintain`), `include/eapol_log.h`
(`EAPOL_DEFAULT_RETENTION_DAYS`), `tests/test_eapol_log.c` for §2c (#87);
`src/alert_pcap.c` (`alert_pcap_sweep_step`, `alert_pcap_maintain`,
`alert_pcap_is_name`, `alert_pcap_shares_eapol_dir`), `src/alert_pcap.h`
(`ALERT_PCAP_DEFAULT_RETAIN_DAYS`), `tests/test_alert_pcap.c` for §2d
(#166).

**Last updated**: 2026-11-23 (#242 item 2 review — the tier table lists the tables `src/db.c` walks, 22 observation and 24 entity, and the ceiling's bound is 64 × 512 × 22). 2026-11-23 (#242 item 2 — `coverage_intervals` on the observation tier, the size ceiling may take it). 2026-11-20 (#239 review — a pass continues across maintenance; observation-tier groupings expire with their tier). 2026-11-20 (#239, owner ruling of that day — §2b, the random-address purge: a random address heard once is a count in `random_devices_daily` after 7 days, not a row; `retention.random_repeat_s`; §2.3 `random_devices_daily` is never pruned). 2026-11-03 (#175 — `alert_incidents` on the finding tier, and its per-key bound of `DB_INCIDENTS_PER_KEY` incidents). 2026-10-26 (#166 — the `--pcap-dir` age sweep, §2d; owner ruling: two weeks; review: one directory for both sinks refused, the stale-clock guard, the sweep's own stderr line). Previously 2026-10-19 (#96 — dashboard `!persist` badge closes the §6 gap).

---

## 1. The short version

If you need one paragraph for a risk register:

> Sloth's database sink deletes rows whose `last_seen` timestamp falls
> outside a per-tier window, and prunes the oldest telemetry rows when
> the database file grows past a configured size. Both run only while
> sloth is running, at most once an hour. Neither is a guaranteed
> deletion deadline, a guaranteed size ceiling, or a secure wipe.
> A randomised device address heard once and tied to no network leaves
> the device table after a week and survives only as a daily count.
> Handshake exports — the only offline-crackable artifact class — are not
> written at all unless `--collect-handshakes` is given, and are deleted
> on a 7-day default window swept at startup and daily. Per-alert
> pcaps in `--pcap-dir` are deleted on a 14-day default window swept at
> startup and hourly. Every other artifact sloth can write — JSONL,
> reports, manual exports — has no retention mechanism whatsoever and
> grows without bound until the operator removes it.

## 2. What `--db` retention does

Retention exists only when `--db FILE` is given. Without it sloth holds
state in bounded in-memory ring buffers and writes nothing durable, so
there is nothing to retain.

`--db-retain-days N` (default **30**, `DB_DEFAULT_RETAIN_DAYS` in
`src/db.h`) sets the **base** window. Three tiers are derived from it:

| Tier | Window | Tables | What it holds |
|------|--------|-------:|---------------|
| observation | **1×** (30 d) | 22 | `bgp_sessions`, `ssh_flows`, `rdp_flows`, `snmp_flows`, `mqtt_flows`, `ldap_events`, `kerb_events`, `smb_sessions`, `deauth_events`, `seqnum_correlations`, `twin_episodes`, `eapol_events`, `scan_entries`, `scan_entry_ports`, `device_positions`, `sensor_positions`, `gnss_fixes`, `gnss_sightings`, `adsb_sightings`, `aprs_packets`, `victron_readings`, `coverage_intervals` |
| entity | **3×** (90 d) | 24 | `devices`, `pnl_clients`, `pnl_ssids`, `probe_clients`, `beacon_aps`, `beacon_ap_ssids`, `ssid_akm_history`, `wifi_aps`, `wifi_stas`, `assocs`, `assoc_reqs`, `wifi_merged`, `arp`, `dhcp_leases`, `top_hosts`, `mdns_services`, `nbns_names`, `ssdp_devices`, `ndp_ras`, `ndp_ra_prefixes`, `sensors`, `adsb_aircraft`, `aprs_stations`, `victron_devices` |
| finding | **12×** (360 d) | 6 | `alerts`, `alert_incidents`, `cleartext_creds`, `karma_candidates`, `rogue_radius`, `btm_requests` |

The ordering is the point: *what fired* outlives *who was here*, which
outlives *the individual observations that established it*.

`coverage_intervals` (schema v18, #242 item 2) is on the observation
tier: one row a minute of what the monitor radios did (time per channel
and band, frames by class, drops, sources; [[coverage-assessment]] § 6),
about 43,000 rows in a 30-day window. A row qualifies the observations
of its minute and is worth no more than they are, so it expires with
them, and the size ceiling may take it like any other observation row.

`alert_incidents` (schema v11, #175) has one more bound besides its
tier: a key keeps its newest `DB_INCIDENTS_PER_KEY` (256) incidents,
the oldest trimmed as the writer records a new one, because a key
evicted under pressure re-fires as a new incident every tick. That trim
removes per-incident detail only: the key's `alerts` row, which holds
the finding across every incident, is not touched by it
([[sqlite-schema]], *Per-incident rows*).

`--db-retain-days 0` does **not** disable retention. Since #120 it is
refused at startup (exit 2): the flag is an alias for the
`db.retain_days` knob in the `--tune` registry, whose range is
`1..36500`. Before that the flag was read with `atoi()` and a zero —
or a typo such as `abc` — was silently replaced by the 30-day default.
There is no "keep everything" setting for the age-out pass. The same
change makes `--db-interval-secs`, `--db-max-mb`,
`--handshake-retention` and `--correlate-retain` registry aliases: each
is validated like `--tune`, and a moved value shows in
`sensor_health.tuned`, so a sensor retaining less than the default says
so in its own export.

### 2.1 Age is measured from `last_seen`, not from first record

The pass is literally `DELETE FROM <table> WHERE last_seen < cutoff`.
So a device, AP or credential exposure that keeps being observed is
**never** aged out, however long ago it first appeared. "30-day
retention" describes the window after a thing stops being seen, not a
cap on how long a record can exist. A permanently-installed AP on a
sensor that runs for a year will still be in `beacon_aps` after that
year.

### 2.2 When it runs

`db_maintain()` is called from `db_tick()` only, after a successful
write commit, and at most once per `DB_MAINT_INTERVAL_S` = **3600 s**.
`g_last_maint` is seeded on the first tick, so the first maintenance
pass happens no sooner than **one hour after the first successful
write**.

Consequences, stated plainly:

- Retention does not run while sloth is stopped. A database left on
  disk for six months with sloth off is exactly as it was left.
- A run shorter than an hour never prunes anything.
- If a database write fails, the sink is disabled for the rest of the
  process (`db_fail()` — one line on stderr, capture continues). Once
  that has happened, retention has also stopped, and there is no
  further warning.

### 2.3 Three tables are never pruned

`sessions` (one row per run, with `--site-label`), `meta` (schema
version) and, since #239, `random_devices_daily` are in no tier and are
**never** deleted by retention or by the size guard. `sessions`
therefore grows by one row per sloth run, forever, and
`random_devices_daily` by at most one row per UTC day and `sources`
mask (§2b).

## 2b. Random addresses that did not repeat (#239)

**Owner ruling, 2026-11-20:** "yes unless the random repeats purge it
after 7 days unless other means is used to group it with ssids. then
after 7 days keep a random category that totals the random devices
historically."

Measured that day on copies of both reference sensors' files, about
95% of `devices` rows were randomised addresses heard in one tick
(W9FJC: 83,000 of 87,224; beta-site: 61,373 of 64,157). Such a row
says only that some phone probed once. After a week it is kept as a
count, not a row.

**What is purged.** A `devices` row, when all of these hold:

- its MAC is locally administered (the `0x02` bit of the first octet);
- `last_seen` is more than 7 days ago (`DB_RANDOM_PURGE_AGE_S`);
- it did not repeat: `last_seen - first_seen` is at most
  `retention.random_repeat_s` seconds (`--tune`, default **600**,
  range `0..86400`; 0 purges only rows heard in one tick);
- nothing groups it with an SSID. The ruling's list: a non-empty SSID
  for it in `pnl_ssids` (the PNL's SSID set; `pnl_clients` has no SSID
  column) or `probe_clients`, any `assocs` row, any
  `seqnum_correlations` row on either side. Added by the build, each a
  tie to a network the ruling's list did not name: its own
  `last_ssid`; `is_ap`, or any `sources` bit other than probe (a
  beacon BSSID is an SSID's; ARP, DHCP, mDNS, station and camera rows
  are the joined network's); any `assoc_reqs`, `btm_requests` or
  `eapol_events` row; a `wifi_stas` or `arp` row. #229's grouping
  across MAC rotation joins the list when it lands.

The test is one statement, `RD_SELECT_SQL` in `src/db.c`.

**What goes with it.** The rows that exist only for that address:
`probe_clients`, `pnl_clients`, `pnl_ssids` (none with an SSID, or it
would have been kept), `device_positions` and `wifi_merged`. Every
other table naming a station MAC either groups it (and so kept it),
belongs to another entity (`beacon_aps`, `wifi_aps`, `ndp_ras`), or is
a finding or event with its own copy of the address and its own tier
(`alerts`, `alert_incidents`, `deauth_events`). An alert about a purged
address keeps its key and detail.

**What is kept instead.** Before a row is deleted it is counted, in the
same transaction, into `random_devices_daily`: one row per UTC day of
the row's `first_seen` and `sources` mask, with `count`, the earliest
`first_seen` and the latest `last_seen`. That table is additive and in
no tier, so the total over a sensor's life survives its rows
([[sqlite-schema]]). A random address that the **entity tier** drops
first (a `db.retain_days` of 2 or less makes that tier shorter than the
week) is counted the same way on its way out, so the total does not
depend on the window. A repeating or grouped random address is not in
the category and ages out with its tier, uncounted.

**When, and how much at a time.** Each hourly `db_maintain()` starts a
pass at the first rowid. A batch reads the next
`DB_RANDOM_PURGE_SCAN` (1024) `devices` rows by rowid, counts and
deletes the qualifying ones, and commits; maintenance takes one batch
and each tick after it one more, until the pass has walked the table.
A tick therefore never waits on more than one batch, however large the
first purge. On a copy of the W9FJC file (2026-11-20, NVMe) the first
pass took 87 batches: 28 ms on average, the worst 246 ms, 2.5 s in
all. A pass still walking when the next maintenance comes (fewer
ticks in an hour than batches in the table, as with a long
`db.interval_secs`) continues from where it stopped rather than
restarting, so the tail of the table is always reached. A row whose
grouping has aged out since the last pass is read again by the next
one. Two of the groupings are observation-tier rows
(`seqnum_correlations`, `eapol_events`, kept `db.retain_days`, default
30): a random address held only by one of those is purged once that
row ages out, when nothing in the file groups it any longer. On the
W9FJC copy that was 2 rows.

**Measured on that copy**, the first pass:

| | before | after |
|---|---:|---:|
| `devices` | 87,224 | 42,229 |
| `probe_clients` | 84,144 | 39,149 |
| `device_positions` | 472,704 | 464,794 |
| `pnl_clients`, `pnl_ssids`, `wifi_merged`, `alerts` | unchanged | unchanged |
| `random_devices_daily` | — | 29 rows, 44,995 counted |

44,995 rows purged; of the 71,653 random one-tick rows past the week,
23,367 were kept by a PNL SSID (most of the rest of the gap) and 889 as
beacon BSSIDs. The file stays 486 MiB: freed pages are reused, and
returned to the filesystem only by the size guard's incremental vacuum
(§3) or an offline `VACUUM`.

**What this costs.** A random address that comes back after its row
was purged is a new row with a new `first_seen`: "new since last
survey" ([[posture-report]]) counts it as new, and a reader can no
longer say it was heard before. The rules do not read the purged rows:
`RECURRING_TRANSIT` (`transit_device_t`) and `UNKNOWN_DEVICE`
(`s->assocs`, and only on a designated network) are computed from
in-memory state, and `MY_NETWORK_RECON`'s persisted exoneration reads
`assocs`, which keeps a row it names.

## 2c. Handshake exports: the opt-in and its sweep

Owner decision, 2026-09-30 (#87). Handshake material is the one artifact
class where the file itself is the attack: a PMKID or a paired M1+M2
supports offline password guessing by anyone who gets a copy. It is
therefore the one class with both an opt-in and a default retention
window, and both are independent of `--db`.

| Setting | Default | Effect |
|---------|---------|--------|
| `--collect-handshakes` | **off** | Required before anything crackable is written. Without it `--eapol-dir` exits `2` and no export directory is created. |
| `--handshake-retention DAYS` | `7` | Delete exported artifacts last written before the window. `0` = keep forever. Rejected outside `0..36500` rather than coerced. |

**What is swept.** Only the names sloth itself writes, inside the
directory `--eapol-dir` pinned at startup: `eapol.22000`, the
per-handshake `<bssid>_<sta>.pcap` files, and `.<name>.tmp` partials left
by a crash mid-write. A file you put in that directory yourself is not
touched — the sweep deletes sloth's artifacts, not the directory's
contents.

**When it runs.** Once at startup, then once per
`EAPOL_SWEEP_INTERVAL_S` (24 h) from the poll loop. Startup as well as
daily because a sensor restarted more often than once a day would
otherwise never age anything out.

**Granularity is the whole artifact, by mtime.** That is exact for the
per-handshake pcaps — one file per handshake. It is *not* exact for
`eapol.22000`: that is a single run-spanning file hashcat reads whole, its
mtime is its last append, and the 22000 format carries no per-line
timestamp, so there is nothing to expire a line against. Consequence,
stated plainly: **a collection that is still appending keeps lines older
than the window**, and the file goes only once nothing has been added for
the entire window. If per-line expiry matters for your policy, roll the
file outside sloth (a dated directory per `--eapol-dir`, rotated by a
systemd timer).

**Nothing is followed, and nothing is silent.** Entries are
`fstatat(..., AT_SYMLINK_NOFOLLOW)`-ed and only regular files are
unlinked, so a symlink planted at an artifact name cannot redirect a
deletion out of the export directory. Such an entry is left exactly as it
is; it, and any `unlinkat` that fails, is counted and surfaced through the
same path as an export failure — one stderr line, the running count and
latest reason in the `[e]` view header, and
`storage_eapol_failures` in the `sensor_health` record. A sweep that
cannot honour the window says so.

**What the gate does not do.** It does not blind the detector. With
`--collect-handshakes` absent, the EAPOL-Key parser, the M1..M4 state
machine, the replay-counter pairing verdict, the PTK-generation counter
the FragAttacks rule reads, association evidence from M3, the `[e]` view
and the JSONL / `--db` `eapol_events` records all behave exactly as with
the gate open. Only the `.22000` lines and the per-handshake pcaps are
withheld — the material that is dangerous because it is *on disk*.

**Known limit: retention needs a live collection.** The sweep runs
against the directory `--eapol-dir` validated at startup. A run without
`--collect-handshakes` has no such directory, so material left by an
earlier opted-in run is **not** swept — sloth no longer knows where it
is. Turning collection off stops new material; it does not clean up old
material. Delete it yourself, or restart with the flags and let the
startup sweep do it.

## 2d. Per-alert pcaps: the age sweep (#166)

Owner ruling 2026-10-26: **keep alert pcaps for two weeks.** The
four questions #166 put were answered as: yes, there is a default; 14
days; by age; and the sweep deletes. It runs **beside** the storage
floors (§6, `storage.min_free_*`), which are unchanged — a floor refuses
a write inside a burst, the sweep ages files out over weeks, and neither
replaces the other.

| Setting | Default | Effect |
|---------|---------|--------|
| `--tune pcap.retain_days=N` | `14` | Delete alert pcaps whose mtime is more than `N` days old. Range `0..3650`; `0` = keep forever (the pre-#166 behaviour). A value outside the range exits `2`. |

`0` disables rather than being refused because it is the meaning `0`
already has on `handshake.retention_days`, the one other age sweep, and
because "keep everything" is an operator decision this registry has
always allowed for evidence (`pcap.min_severity=0`,
`pcap.key_cooldown_secs=0`). A disabled sweep is reported: startup
prints `retention disabled`, and `sensor_health` carries
`pcap_retain_days: 0`.

**What is swept.** Only names `alert_pcap_dump()` writes, inside the
directory `--pcap-dir` pinned at startup: `alert_YYYYMMDD_HHMMSS_<slug>.pcap`
and its `_N` same-second variants (the slug is `[A-Za-z0-9_]`), plus the
`sloth-manifest-*.jsonl` hashed manifest (#92 slice 3), whose mtime is
its newest line so it goes only once every file it lists could have.
Anything else — a `capture.pcap` you dropped in, a `.pcapng`, a dotted
file — is the operator's and is not touched. The matcher is
`alert_pcap_is_name()`, pinned by `test_sweep_name_shape`.

**Nothing is followed.** Each entry is `fstatat(..., AT_SYMLINK_NOFOLLOW)`-ed
relative to the pinned directory descriptor and removed with
`unlinkat()` relative to it, so a rename or symlink swap of the path
cannot redirect a deletion. Only regular files are removed. A symlink,
directory or FIFO at an artifact name is left exactly as it is and
counted as a sweep error — in a 0700 directory only sloth writes, it is
either operator error or someone steering the sweep.

**When it runs, and how much at once.** A pass starts at startup and
then at most once per `ALERT_PCAP_SWEEP_INTERVAL_S` (1 h). Each poll
tick examines at most `ALERT_PCAP_SWEEP_BUDGET` (1024) directory
entries and the next tick resumes where it stopped, so a directory of
millions of files — the measured failure was ~16M — cannot stall the
poll loop; at the default 250 ms refresh that is ~4,000 entries a second,
so 16M entries clear in about an hour, against a measured worst
production rate of ~14 files/s. A
pass applies one cutoff, fixed when it started. The next interval is
counted from a pass's start, so a pass longer than an hour is followed
by the next one immediately.

**Counted, never silent.** `sensor_health` carries `pcap_retain_days`,
`pcap_swept` (files removed) and `pcap_sweep_errors` (unreadable
directory, failed stat, non-regular file at an artifact name, failed
unlink) whenever `--pcap-dir` is set; the change-only signature takes
their decade bands, not the counts, so a sweep clearing a backlog writes
a handful of lines, not one per tick ([[jsonl-schema]]). The first
error is also one stderr line, `sloth: --pcap-dir retention sweep: …`
— deliberately not the `… export failed` wording the write path uses,
so a grep for lost evidence does not match it. A sweep error is **not** a write
failure: it does not move `storage_pcap_failures` or the `!persist`
badge, because no evidence was lost.

**Evidence pcaps in `--eapol-dir` are covered — by the other sweep.**
The #92 per-alert *evidence* pcaps (`<incident_id>-<event_id>-<RULE>.pcap`,
raw 802.11 frames) are written into `--eapol-dir`, not `--pcap-dir`,
and `eapol_sweep()` already expires every `*.pcap`, the manifest and
`.<name>.tmp` partials there (§2c). They are therefore aged on
**`handshake.retention_days` (7 days)**, not on `pcap.retain_days`: the
frames carry EAPOL/PMKID material, and the owner ruling of 2026-10-08
put them under the crackable-material policy on purpose.

**One directory for both is refused.** Because `eapol_sweep()` takes
every `*.pcap` and manifest in its directory, `--pcap-dir` and
`--eapol-dir` naming the same directory would put the alert pcaps on
the 7-day handshake window whatever `pcap.retain_days` says — `0`
included, while startup printed "kept until you delete them". sloth
pins both, compares the pinned descriptors by dev/ino (so `DIR` and
`DIR/.` are the same) and exits `2` before either sweep runs
(`alert_pcap_shares_eapol_dir()`, `test_sweep_detects_a_shared_eapol_dir`).
Refusal rather than teaching `eapol_sweep()` to skip alert names,
because the two sinks also write manifests of the same shape and one
directory cannot keep them apart.

**Age is the wall clock, with one guard.** A file's age is its mtime
against `sloth_wall()`. A sensor with no RTC that starts on a stale
clock stamps its alert pcaps in the past, and once NTP steps the clock
forward they would read as older than the window and go on the next
pass. So until the process has been up one whole window by the
monotonic clock, a file whose mtime is at or after the wall time sloth
started at is not deleted. On a clock that was right all along those
files are younger than the uptime and would be kept anyway, so the
guard changes nothing there (`test_sweep_spares_files_written_before_a_clock_step`).
What it cannot cover: files written on a stale clock by an *earlier*
run are judged by their stamps alone at the next start, and a start on
a stale clock spares the previous run's files until the window of
uptime has passed. The handshake sweep (§2c) has no such guard on
purpose — for crackable material, expiring early is the safer failure.

**Same known limit as §2c.** Retention is process-local: a run without
`--pcap-dir` does not know where an earlier run's files are and sweeps
nothing.

## 3. What the size guard actually does

`--db-max-mb N` (default **512**, `DB_DEFAULT_MAX_MB`; `0` = unlimited)
is best read as a **pruning trigger, not a cap**. What it does:

1. Measures `PRAGMA page_count × PRAGMA page_size` — the **main
   database file only**. The `-wal` and `-shm` sidecars are not
   counted, so sloth's actual on-disk footprint can exceed `--db-max-mb`
   while the guard considers the file to be under it.
2. If over, deletes the **512 oldest rows** (by `last_seen`) from each
   of the 22 observation tables (`TIER_OBSERVATION` in `src/db.c`),
   then runs `PRAGMA incremental_vacuum`.
3. Repeats, at most **64 rounds per maintenance pass** — an upper bound
   of 64 × 512 × 22 = 720 896 rows. If the file is still over target
   after 64 rounds, the pass simply ends, **with no message**, and the
   next hourly pass continues where it left off.
4. If a round deletes nothing — no prunable telemetry left — it logs
   once and stops:

   ```
   sloth: db over --db-max-mb (N MiB > M MiB) with no prunable telemetry left; findings are never dropped
   ```

   The file is then allowed to stay over target indefinitely.

Entity, finding and detector-evidence rows are **never** dropped by this
guard. That is deliberate: a sensor that fills its disk should lose
telemetry, not the findings the disk was being kept for. The direct
consequence is that `--db-max-mb` cannot be relied on as a disk-capacity
control — a database that is mostly alerts and credential exposures will
sail past it and say so once.

`PRAGMA incremental_vacuum` only returns pages to the filesystem on a
database **created** with `auto_vacuum=INCREMENTAL`. Sloth requests that
pragma at open, but SQLite honours it only for a new file; on a database
created by an older build the pages are reused rather than returned, so
the file stops growing but never shrinks. One offline `VACUUM;` fixes
that.

## 3b. In-memory retention: device correlation (#94)

One in-memory table has retention of its own, and it is here because it
is the one whose contents can be personal data rather than telemetry.

`src/seqnum_track.c` holds a per-MAC sequence-counter trail and links
addresses across MAC rotations. Two horizons apply, both while sloth is
running and independent of `--db`:

| Knob | Default | What it bounds |
|------|---------|----------------|
| `--correlate-retain SECS` | **300** | Evidence window for a correlation. A pair is reported only while **both** addresses have been heard inside it, counted from now. |
| `SEQNUM_CLIENT_RETAIN_S` | **3600** | Per-MAC trails, dropped on snapshot once this stale. Effective value is `max(3600, --correlate-retain)`. |

`--no-correlate` switches the linkage off entirely: trails still render,
no pair is linked, exported, or written to `seqnum_correlations`.

Before #94 neither horizon existed — the only way out of the table was
eviction once it hit 256 entries, so a quiet sensor retained every
address it had ever heard for the life of the process, and stale trails
kept producing *current* correlations. Two things follow that are worth
stating for a risk register:

- **Stated purpose.** Correlation exists so device counts, alert dedup
  and transit passes are not inflated by MAC rotation. The five-minute
  evidence default is set for that purpose, not for building a movement
  history.
- **Not a deletion guarantee, same caveat as §1.** Expiry runs on
  snapshot while sloth is running. Anything already exported to JSONL,
  the data socket, or `--db seqnum_correlations` is governed by those
  sinks' retention (the observation tier, 1×, for the DB) and not by
  these horizons.

## 4. What retention does *not* cover

Apart from the handshake exports in §2c and the alert pcaps in §2d,
nothing outside the SQLite file is managed. These grow until the
operator deletes them:

| Artifact | Flag | Retention |
|----------|------|-----------|
| JSONL forensic log | `-o FILE` | **none** — append-only, no rotation, no size cap. A `-o` run writes on the order of tens of GB/day |
| Per-alert pcaps | `--pcap-dir DIR` | **14 days** by default (`pcap.retain_days`, `0` = forever) — see §2d |
| EAPOL / PMKID export | `--eapol-dir DIR` + `--collect-handshakes` | **7 days** by default — see §2c. The one managed artifact outside the database, because it is the one that is offline-crackable |
| Per-handshake pcaps | `--eapol-dir DIR` + `--collect-handshakes` | **7 days** by default (§2c) |
| Posture reports | `--report`, `--report-json` | **none** — overwritten per run at the path you name, never aged |
| Live, per-session and unclean reports (#190) | `--report-interval`, `--report-history` | **none** — `report.live.*` is replaced in place; `report.<UTC>.*` and `report.<UTC>.unclean.*` accumulate, one small file per session per format, never pruned |
| Packets-view manual export | `w` key | **none** |
| Wi-Fi AP snapshot | `--snapshot-out FILE` | **none** — overwritten per run at the path you name |
| SQLite WAL / SHM | `--db` | not measured by the size guard; checkpointed by SQLite, not by sloth |
| Filesystem copies, backups, snapshots | — | outside sloth entirely |

If your data-handling policy needs those bounded, bound them outside
sloth — logrotate, a tmpfiles.d rule, a systemd timer. Apart from the
crackable material in §2c and the alert pcaps in §2d (an owner ruling,
not an engineering default), sloth deliberately ships no deletion logic
for artifacts the operator asked for by name.

### 4.1 File permissions on those artifacts (current behaviour)

Retention does not bound these files; their permissions at creation are
enforced. This subsection describes what the code does as of 1.8.4
(`src/secure_file.c`, #87). It records behaviour, not a policy.

- **Created private, independent of the umask.** Files are opened with
  `openat(…, O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600)`. A directory sloth
  creates (`--eapol-dir`, `--pcap-dir`) is made with `mkdir(…, 0700)` and
  then opened `O_DIRECTORY | O_NOFOLLOW`. A umask can only clear bits
  from those modes.
- **What is checked, and how.** For files and directories sloth opens
  itself, every check below is an `fstat` of the opened descriptor, not
  a second lookup of the path. The SQLite side files (`-wal`, `-shm`,
  `-journal`) are the exception: sloth does not open them, so an
  existing one is checked by `lstat` of the path before SQLite opens it
  by path. That check is not pinned to a descriptor, and a swap between
  the check and SQLite's open is not detected.
- **An existing path is refused, not repaired — for append and truncate
  targets and for directories.** That covers `--eapol-dir` and
  `--pcap-dir`, `DIR/eapol.22000`, `-o FILE`, `--db FILE` and its side
  files, `--report`, `--report-json` and `--snapshot-out`. sloth refuses such a path, with
  a reason on stderr, when it is the wrong type, is owned by a uid other
  than sloth's effective uid, has any group or other permission bit
  (`mode & 077`), is a file with more than one hard link, or is a
  symlink as the final component. It never `chmod`s or `chown`s the
  path. The owning gid is not checked. Parent directories of an
  operator-named file are neither created nor checked.
- **Exclusive-create artifacts never open an existing name.** Per-alert
  pcaps and the packets-view `w` export are created `O_EXCL`; an
  existing file at the name is left untouched and sloth moves to the
  next suffix (`_2` … `_99`).
- **The per-handshake pcap is replaced, not inspected.** It is written
  to an exclusive temp file `DIR/.<name>.tmp` and `rename`d over
  `DIR/<bssid>_<sta>.pcap`. Whatever sits at that name — any owner,
  mode or type, a symlink included — is replaced without being checked
  or written through. A stale temp file of that name is unlinked first,
  on the basis that only sloth writes the private directory.
- **No group mode exists for the artifacts in the table below.** No
  flag or setting makes sloth create one of them group-readable or
  accept a group-accessible existing one. Whether a group mode should
  exist is an open question on #87; nothing here answers it.

| Artifact | Created as | Write | If refused |
|----------|------------|-------|------------|
| `--eapol-dir DIR`, `--pcap-dir DIR` | directory 0700 | — | startup stops. `--eapol-dir` additionally needs `--collect-handshakes` (§2c), checked before the directory is created |
| `DIR/eapol.22000` | 0600 | append; a failed write is truncated back to the previous length | counted, shown in the EAPOL view header; later exports still attempted |
| `DIR/<bssid>_<sta>.pcap` | 0600 | exclusive temp file in `DIR`, renamed over the old name | a temp-file create, write or rename failure is counted and shown in the EAPOL view header; the previous capture stays |
| Per-alert pcaps in `--pcap-dir` | 0600 | exclusive create, `_2` … `_99` on a same-second name clash | counted, retried next tick |
| Packets-view `w` export | 0600 | exclusive create in the working directory, same suffixing | export fails |
| `-o FILE` JSONL | 0600 | append | startup stops |
| `--db FILE` | 0600, created before SQLite opens it (`SQLITE_OPEN_NOFOLLOW` where available) | SQLite | startup stops |
| `FILE-wal`, `FILE-shm`, `FILE-journal` | by SQLite, mode copied from the main file | SQLite | an existing one failing the checks stops startup |
| `--report`, `--report-json` | 0600 | validated, then truncated and rewritten | report skipped; the old file is left as it was |
| `--snapshot-out FILE` | 0600 | validated, then truncated and rewritten | snapshot skipped; the old file is left as it was |

Detail for the EAPOL export, including the refusal message, is in
[`docs/views/eapol.md`](../views/eapol.md#export-handling-87).

## 5. Deletion is logical, not secure erasure

`DELETE FROM …` marks pages free inside the database file. It does not
overwrite the bytes. Sloth never sets `PRAGMA secure_delete`, so a stock
SQLite build leaves the old content in place until those pages are
reused. Specifically, after retention has "deleted" a row:

- the bytes may remain in free pages of the main file;
- the pre-delete page images may remain in the `-wal` file;
- any backup, filesystem snapshot or copied file taken earlier is
  untouched;
- `incremental_vacuum` returns free pages to the filesystem but does not
  zero them, and the filesystem does not zero them either.

Treat an aged-out database as *not queryable through sloth's schema*,
not as *erased*. If an artifact must be unrecoverable, destroy the
media or the file with a tool built for that; sloth does not claim to.

## 6. Known gaps

Recorded here rather than implied away:

- **A failing sink is visible on every view, dashboard included.**
  `persist_health_poll()` (`src/persist_health.c`, polled once per tick
  in `src/poll.c`'s `health_capture` stage) snapshots the three sinks' lifetime write-failure
  counts, and `persist_badge()` renders `!persist jsonl:N pcap:N
  eapol:N` — failing sinks only — on the tab bar at full alert heat in
  both front ends (`draw_tabbar` in `src/tui.c`, ncurses and ANSI).
  This bullet used to record a hole: under ncurses `tui_draw()` returns
  early for `VIEW_DASH`, the startup view, and draws no tab bar, so the
  badge was seen only after a switch to a detail view. Closed on
  2026-10-19 (#96): the dashboard draws the same badge itself, on the
  Interfaces title rule, and under its "terminal too small" notice when
  the terminal cannot hold the tile (`draw_persist_badge` in
  `src/views/dashboard_bands.c`). It overprints the rule rather than
  taking a row, so the band layout is unchanged;
  `tests/test_views_render.c` pins presence, absence when healthy, the
  unchanged rows, both small-terminal cases, a wrapped notice, and
  truncation by whole `sink:N` tokens (never mid-count). Format and caveats:
  [[cli-reference]] § Status badges.
- **`--pcap-dir` keeps what is worth keeping, and can be opened all
  the way up.** Two `--tune` knobs decide what reaches disk:
  `pcap.min_severity` (default `2`, CRIT only) and
  `pcap.key_cooldown_secs` (default `3600`). Set both to `0` for an
  unfiltered full capture.

  The defaults exist because of what unfiltered actually produced on a
  live sensor: **16,131,622 files and 78 GB** in `--pcap-dir`, **17.9
  per second**, of which **98.6%** were one *WARN*-severity rule
  (`BEACONING`) re-exported after every alert-engine eviction. Measured
  across the whole corpus, those 16.1M files held about **191 distinct
  (destination, port) pairs** — a couple of hundred real findings,
  written millions of times. One address, the monitored host's own IPv6,
  appeared in 81% of sampled files.

  Two separate defects produced that, and both are fixed rather than
  merely configurable. The severity gate never existed: `--help` has
  always said "when a critical alert fires" and `dump_new_alert_pcaps()`
  tested only `match_ip`. And `fire_inv()` memsets a reused engine slot,
  which clears `pcap_dumped`, so an evicted-then-refired alert looked
  brand new and exported again. `incident_id` cannot be the dedupe key
  either — `incident_id_make()` runs on the new-entry path, so the
  re-fire has a fresh id even though the finding does not. The cooldown
  therefore keys on the alert key.

  A third change removed the *source* of that churn rather than its
  output: alert-engine eviction now takes the oldest entry of whichever
  type holds the most slots, so 128 beaconing tracks recycle their own
  slots instead of the whole ring. See [[alerts]] and `docs/views/alerts.md`.

  The cooldown records only a **successful** export. A write that fails
  leaves `pcap_dumped` at 0 so the next tick retries (#92), and starting
  a cooldown from a failed attempt would block that retry and lose the
  evidence the retry exists to save.

- **Capacity control covers one sink, and no sink ever gives up.**
  `--pcap-dir` is checked before each write, and nothing else is.
  `src/fs_capacity.c` reads the headroom of the filesystem holding that
  directory and `src/alert_pcap.c` refuses the dump when it is below a
  floor. **The guard is ON by default** (owner instruction 2026-10-13):
  `storage.min_free_pct` is 5, so a write is refused once free inodes or
  free bytes fall under 5% of the filesystem. `storage.min_free_mb` and
  `storage.min_free_inodes` are absolute overrides and remain 0 (none).

  The default is a percentage rather than a count because an absolute
  floor cannot be right for two filesystems of different size: the floor
  that protects a 30M-inode host is ~1.5M free inodes, which would
  refuse every write on a small one. An upgrade therefore DOES change
  behaviour on a filesystem already under 5% free — that is the point of
  the change, not a side effect. `storage.min_free_pct=0` with both
  absolutes at 0 restores the previous behaviour. Free bytes *and* free inodes are
  reported unconditionally in `sensor_health`
  (`pcap_dir_free_mb`, `pcap_dir_free_inodes`), because the operator
  failure mode here is false reassurance rather than surprise: measured
  on a live monitor host, `--pcap-dir` held 15.9M files and ~93% of the
  filesystem's inodes while `df -h` read 39% used.

  What is still open: the JSONL log, the SQLite database and its WAL,
  `--report` output and the EAPOL exports have **no** capacity check at
  all, and nothing anywhere is ENOSPC-specific. Nor does any sink enter
  a disabled state. A write on a full volume fails, `sfile_fail()`
  (`src/secure_file.c`) increments that sink's counter and prints one
  stderr line behind a `reported` latch, and the next write is
  attempted anyway: the JSONL sink `clearerr()`s the stream on purpose
  ("keep trying: a full disk may drain", `src/jsonl_core.c`), while
  per-alert pcap and EAPOL exports open a fresh file per export
  (`src/alert_pcap.c`, `src/eapol_log.c`). Counters rise, the badge
  grows, and the sink keeps trying at full rate — nothing throttles,
  degrades or stops.

  Alert pcaps are now aged out: owner ruling 2026-10-26 on #166 set a
  two-week window, swept hourly (§2d). The sweep bounds the directory
  over weeks; within a burst the floors above are still the only guard.
- **The size guard measures the wrong number for a disk budget** — the
  main database file only, excluding `-wal`/`-shm` — and gives up for
  the hour after 64 pruning rounds (§3).
- **Retention is process-local.** It runs only while sloth runs. For the
  handshake sweep that also means it needs a live opted-in collection:
  material from an earlier run is not swept by a run that omits
  `--collect-handshakes` (§2c).
- **`eapol.22000` expires whole-file, not per line.** The format carries
  no per-line timestamp, so a file still being appended to keeps lines
  older than the window (§2c).

## Related pages

- [[sqlite-schema]] — the tables themselves, and the MISSION §2
  guardrails the schema enforces.
- [[pcap-export]] — per-alert pcap files and their permissions.
- [[log]] — the JSONL stream.
- [[posture-report]] — `--report` output.
- [[collection-cycle]] — when each sweep and maintenance step runs, beside the other cycles.
