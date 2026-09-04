/* Embedded SQLite sink — issue #42.
 *
 * The JSONL log is the *wire format* (a contract other tools consume);
 * this is the *retained artifact*. A run with `-o` writes ~38 GB/day
 * because snapshot rows re-serialise every poll; the same information
 * as durable state is 15-350 MB, because sloth's cardinality is bounded
 * by construction — every entity table in sloth.h is a fixed array.
 *
 * Design constraints, all load-bearing:
 *
 *  - **Reads sloth_state_t directly, never the jsonl emitters.** Every
 *    jsonl_emit_* opens with any_sink(), which is false when neither -o
 *    nor --data-socket is active, so a --db-only run would silently
 *    write an empty database. Routing through jsonl_changed() would
 *    also make last_seen lag by up to the 300 s heartbeat and couple
 *    durable state to a wire-format optimisation.
 *
 *  - **Fail-open, always.** Any SQLite error disables further writes
 *    and reports once. A database problem must never kill a capture —
 *    the operator loses persistence, not visibility.
 *
 *  - **No query surface.** MISSION §4 rules out remote control. This is
 *    a local file sink; it is never exposed over the data socket and
 *    gets no RPC. Operators query with the sqlite3 CLI.
 *
 *  - **Schema-level MISSION §2 guardrails.** No password column on
 *    credential exposures; no PMKID / nonce / MIC columns on EAPOL.
 *    Crackable material stays in the --eapol-dir file the operator
 *    explicitly asked for rather than accumulating in a long-lived
 *    general-purpose DB. Enforced by tests, not just convention. */

#ifndef SLOTH_DB_H
#define SLOTH_DB_H

#include "sloth.h"

/* Schema version stamped into the meta table. db_open() refuses a file
 * whose version differs from this build.
 *
 * Bump this whenever an EXISTING table changes shape. Adding a whole
 * new table is safe without a bump — the schema runs
 * CREATE TABLE IF NOT EXISTS on every open, so an older file simply
 * gains it. Adding a *column* to an existing table is NOT safe that
 * way, because CREATE TABLE IF NOT EXISTS is a no-op on a table that
 * already exists and the new column never appears.
 *
 * v2: probe_clients.presence (#53) was added without a bump, so a v1
 * file fails at schema application with a confusing SQL error instead
 * of the clear version message. Bumped retroactively; v1 files are
 * refused with an explanation. */
#define DB_SCHEMA_VERSION 4

/* ── AKM regression (#74 Detector B, temporal half) ──────────────────
 *
 * An SSID that was SAE-only on one BSSID for a sustained window and is
 * PSK-only on that same BSSID now. The concurrent form — two BSSIDs
 * disagreeing at the same moment — is ALERT_TYPE_SAE_PSK_SPLIT and
 * needs no history; this is the other one, and it cannot be answered
 * without a persisted file.
 *
 * Note the sustain requirement is what makes it a regression rather
 * than a sample. A single beacon caught mid-`--hop` says nothing about
 * what the AP was configured as, so the SAE window has to have been
 * observed across at least DB_AKM_SUSTAIN_S. That in turn means a fresh
 * database is silent here for its first day, which is correct: sloth
 * has no basis for the claim yet.
 *
 * Computed at db_tick, not on demand. A new row can only appear at a
 * tick, so querying more often than that costs SQL for an answer that
 * cannot have changed — and the alert rule runs every poll. */
#define DB_AKM_SUSTAIN_S   (24 * 3600)
#define DB_MAX_AKM_REGRESSIONS 16

typedef struct {
    char     ssid[33];
    char     bssid[18];
    uint32_t was_akm;      /* the SAE-family set it advertised before */
    uint32_t now_akm;      /* the PSK-family set it advertises now    */
    time_t   was_first_seen;
    time_t   was_last_seen;
    time_t   now_first_seen;
} db_akm_regression_t;

/* Retention defaults. See db_set_retain_days / db_set_max_mb. */
#define DB_DEFAULT_RETAIN_DAYS 30
#define DB_DEFAULT_MAX_MB     512

#ifdef WITH_SQLITE

/* Open (creating if needed) the database at `path` and apply the
 * schema. Returns 1 on success, 0 on failure (message on stderr).
 * A failure here is fatal to --db only; the caller decides. */
int  db_open(const char *path);

/* Flush and close. Safe when never opened. */
void db_close(void);

/* True iff a database is open and writes have not been disabled by a
 * prior error. */
int  db_is_open(void);

/* Persist one tick of entity state. Called from the poll loop after
 * poll_data() has refreshed `s`. Wraps every upsert in a single
 * transaction; on any error the transaction is rolled back, the sink
 * is disabled, and the caller is never told (fail-open).
 *
 * `now` is passed rather than read so tests are deterministic. */
void db_tick(const sloth_state_t *s, time_t now);

/* Seconds between write ticks (--db-interval-secs). 0 restores the
 * default. db_tick() itself is unconditional; the poll loop uses this
 * to decide when to call it. */
void db_set_interval(int secs);
int  db_interval(void);

/* Retention (--db-retain-days). 0 restores the default.
 *
 * Tiered, because not all rows are worth the same on a disk that is
 * filling up. The configured window applies to observation and event
 * rows; entities keep 3x that, and alerts and credential exposures
 * keep 12x. The reasoning is what an investigator reaches for months
 * later: "which devices were here" outlives "which BGP keepalives were
 * counted", and "what fired, and when" outlives both. */
void db_set_retain_days(int days);
int  db_retain_days(void);

/* Hard size ceiling in megabytes (--db-max-mb). 0 = unlimited.
 *
 * On breach the oldest observation rows go first, in batches, until
 * the file is back under. Entity, alert and credential rows are NEVER
 * dropped by this guard — a sensor that fills its disk should lose
 * telemetry, not the findings the operator is keeping the disk for. If
 * pruning every eligible row still leaves the file over the ceiling,
 * that is reported once and the file is allowed to exceed it, because
 * the alternative is discarding evidence to satisfy a number. */
void db_set_max_mb(int mb);
int  db_max_mb(void);

/* Run the retention + ceiling pass. db_tick() calls this at most once
 * an hour; exposed so tests can drive it directly. No-op when closed. */
void db_maintain(time_t now);

/* Database size in bytes (page_count * page_size), or -1 if closed. */
long long db_size_bytes(void);

/* ── survey sessions (#56) ────────────────────────────────
 *
 * A surveyor returning to a site asks "what is new since last time".
 * The data for that already exists — first_seen is MIN-ed across every
 * upsert, so an entity seen on a previous visit keeps its original
 * timestamp and only genuinely new ones fall inside this run. What was
 * missing is the boundary: a record of when the visits were. */

/* Record the start of a survey session. `site_label` may be NULL. */
void db_session_begin(const char *site_label, time_t now);

/* Stamp the current session's end. Safe if none was begun. */
void db_session_end(time_t now);

/* Start of the previous completed session at this site, or 0 if this is
 * the first visit. This is the timestamp "new since last survey"
 * compares against. */
time_t db_previous_session_end(void);

typedef enum {
    DB_NEW_DEVICE = 0,
    DB_NEW_PROBE_CLIENT,
    DB_NEW_BEACON_AP,
} db_new_kind_t;

typedef struct {
    char   ident[24];    /* MAC / BSSID as text */
    char   label[72];    /* vendor, SSID or hostname — whatever names it */
    time_t first_seen;
} db_new_entity_t;

/* Entities of `kind` first seen at or after `since`, newest first.
 * Returns the number written to `out`. */
int db_new_since(db_new_kind_t kind, time_t since,
                 db_new_entity_t *out, int max);

/* Count only — for a report that wants "14 new devices" without
 * listing them all. */
int db_count_new_since(db_new_kind_t kind, time_t since);

/* Regressions found at the most recent tick, newest transition first.
 * Returns the number written. */
int db_akm_regressions(db_akm_regression_t *out, int max);

/* True when `now` is far enough past the last write for another tick.
 * Kept here rather than in main.c so the cadence is testable. */
int  db_due(time_t now);

#else

static inline int  db_open(const char *path) { (void)path; return 0; }
static inline void db_close(void)            {}
static inline int  db_is_open(void)          { return 0; }
static inline void db_tick(const sloth_state_t *s, time_t now)
                                             { (void)s; (void)now; }
static inline void db_set_interval(int secs) { (void)secs; }
static inline int  db_interval(void)         { return 0; }
static inline void db_set_retain_days(int d) { (void)d; }
static inline int  db_retain_days(void)      { return 0; }
static inline void db_set_max_mb(int mb)     { (void)mb; }
static inline int  db_max_mb(void)           { return 0; }
static inline void db_maintain(time_t now)   { (void)now; }
static inline long long db_size_bytes(void)  { return -1; }
static inline int db_akm_regressions(db_akm_regression_t *o, int m)
       { (void)o; (void)m; return 0; }

typedef enum {
    DB_NEW_DEVICE = 0,
    DB_NEW_PROBE_CLIENT,
    DB_NEW_BEACON_AP,
} db_new_kind_t;

typedef struct {
    char   ident[24];
    char   label[72];
    time_t first_seen;
} db_new_entity_t;

static inline void db_session_begin(const char *l, time_t n) { (void)l; (void)n; }
static inline void db_session_end(time_t n)                  { (void)n; }
static inline time_t db_previous_session_end(void)           { return 0; }
static inline int db_new_since(db_new_kind_t k, time_t s,
                               db_new_entity_t *o, int m)
                               { (void)k; (void)s; (void)o; (void)m; return 0; }
static inline int db_count_new_since(db_new_kind_t k, time_t s)
                               { (void)k; (void)s; return 0; }
static inline int  db_due(time_t now)        { (void)now; return 0; }

#endif /* WITH_SQLITE */

/* The schema text, exposed unconditionally so the guardrail tests can
 * assert on it without linking SQLite: no password column, no key
 * material. Returns a NUL-terminated string of CREATE statements. */
const char *db_schema_sql(void);

/* Just the meta table. Applied before the version check so a
 * mismatched file gets the clear "use a separate file" message rather
 * than whatever SQL error the rest of the schema happens to hit
 * first. */
const char *db_schema_meta_sql(void);

#endif /* SLOTH_DB_H */
