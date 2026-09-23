---
name: retention
description: What sloth actually deletes, when, and what it never touches — tiered --db retention, the size guard's real behaviour, and the artifact classes outside both
type: reference
---

# Retention — what is actually deleted

**Summary**: `--db` ages rows out on three tiered windows and prunes
observation rows when the database file exceeds `--db-max-mb`. That is
an **investigative tradeoff**, not a deletion guarantee: it is not a
"30-day deletion" promise, it is not a hard disk cap, it does not touch
JSONL / pcap / EAPOL / report artifacts, and row deletion is not secure
erasure.

**Sources**: `src/db.c` (`db_maintain`, `prune_tier`,
`prune_oldest_observations`, `db_size_bytes`), `src/db.h`
(`DB_DEFAULT_RETAIN_DAYS`, `DB_DEFAULT_MAX_MB`), `src/db_schema.c`,
`tests/test_db.c`, issue #96.

**Last updated**: 2026-09-23 (sloth 1.8.1).

---

## 1. The short version

If you need one paragraph for a risk register:

> Sloth's database sink deletes rows whose `last_seen` timestamp falls
> outside a per-tier window, and prunes the oldest telemetry rows when
> the database file grows past a configured size. Both run only while
> sloth is running, at most once an hour. Neither is a guaranteed
> deletion deadline, a guaranteed size ceiling, or a secure wipe. Every
> other artifact sloth can write — JSONL, pcap, EAPOL exports, reports
> — has no retention mechanism whatsoever and grows without bound until
> the operator removes it.

## 2. What `--db` retention does

Retention exists only when `--db FILE` is given. Without it sloth holds
state in bounded in-memory ring buffers and writes nothing durable, so
there is nothing to retain.

`--db-retain-days N` (default **30**, `DB_DEFAULT_RETAIN_DAYS` in
`src/db.h`) sets the **base** window. Three tiers are derived from it:

| Tier | Window | Tables | What it holds |
|------|--------|-------:|---------------|
| observation | **1×** (30 d) | 14 | `bgp_sessions`, `ssh_flows`, `rdp_flows`, `snmp_flows`, `mqtt_flows`, `ldap_events`, `kerb_events`, `smb_sessions`, `deauth_events`, `seqnum_correlations`, `twin_episodes`, `eapol_events`, `scan_entries`, `scan_entry_ports` |
| entity | **3×** (90 d) | 21 | `devices`, `pnl_clients`, `pnl_ssids`, `probe_clients`, `beacon_aps`, `beacon_ap_ssids`, `ssid_akm_history`, `wifi_aps`, `wifi_stas`, `assocs`, `assoc_reqs`, `wifi_merged`, `arp`, `dhcp_leases`, `top_hosts`, `mdns_services`, `nbns_names`, `ssdp_devices`, `ndp_ras`, `ndp_ra_prefixes`, `sensors` |
| finding | **12×** (360 d) | 5 | `alerts`, `cleartext_creds`, `karma_candidates`, `rogue_radius`, `btm_requests` |

The ordering is the point: *what fired* outlives *who was here*, which
outlives *the individual observations that established it*.

`--db-retain-days 0` does **not** disable retention — a value of zero or
less is replaced by the 30-day default (`db_set_retain_days`). There is
no "keep everything" setting for the age-out pass.

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

### 2.3 Two tables are never pruned

The schema has 42 tables; the three tiers cover 40. `sessions` (one row
per run, with `--site-label`) and `meta` (schema version) are in no
tier and are **never** deleted by retention or by the size guard.
`sessions` therefore grows by one row per sloth run, forever.

## 3. What the size guard actually does

`--db-max-mb N` (default **512**, `DB_DEFAULT_MAX_MB`; `0` = unlimited)
is best read as a **pruning trigger, not a cap**. What it does:

1. Measures `PRAGMA page_count × PRAGMA page_size` — the **main
   database file only**. The `-wal` and `-shm` sidecars are not
   counted, so sloth's actual on-disk footprint can exceed `--db-max-mb`
   while the guard considers the file to be under it.
2. If over, deletes the **512 oldest rows** (by `last_seen`) from each
   of the 14 observation tables, then runs `PRAGMA incremental_vacuum`.
3. Repeats, at most **64 rounds per maintenance pass** — an upper bound
   of 64 × 512 × 14 = 458 752 rows. If the file is still over target
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

## 4. What retention does *not* cover

Nothing outside the SQLite file is managed. These grow until the
operator deletes them:

| Artifact | Flag | Retention |
|----------|------|-----------|
| JSONL forensic log | `-o FILE` | **none** — append-only, no rotation, no size cap. A `-o` run writes on the order of tens of GB/day |
| Per-alert pcaps | `--pcap-dir DIR` | **none** — one file per alert flow, kept forever |
| EAPOL / PMKID export | `--eapol-dir DIR` | **none** — and this is offline-crackable material |
| Per-handshake pcaps | `--eapol-dir DIR` | **none** |
| Posture reports | `--report`, `--report-json` | **none** — overwritten per run at the path you name, never aged |
| Packets-view manual export | `w` key | **none** |
| SQLite WAL / SHM | `--db` | not measured by the size guard; checkpointed by SQLite, not by sloth |
| Filesystem copies, backups, snapshots | — | outside sloth entirely |

If your data-handling policy needs those bounded, bound them outside
sloth — logrotate, a tmpfiles.d rule, a systemd timer. Sloth
deliberately ships no deletion logic for artifacts the operator asked
for by name.

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

- **No filesystem capacity control.** Sloth does not check free space
  before writing, and there is no "cannot persist" error surfaced to the
  operator when the volume fills — the write simply fails and the sink
  disables itself with one stderr line. Tracked as remaining work on
  issue #96; not implemented as of 1.8.1.
- **The size guard measures the wrong number for a disk budget** — the
  main database file only, excluding `-wal`/`-shm` — and gives up for
  the hour after 64 pruning rounds (§3).
- **Retention is process-local.** It runs only while sloth runs.

## Related pages

- [[sqlite-schema]] — the tables themselves, and the MISSION §2
  guardrails the schema enforces.
- [[pcap-export]] — per-alert pcap files and their permissions.
- [[log]] — the JSONL stream.
- [[posture-report]] — `--report` output.
