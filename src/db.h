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

/* Schema version stamped into the meta table. Bumped whenever the
 * shape changes; db_open() refuses a file written by a newer sloth. */
#define DB_SCHEMA_VERSION 1

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
static inline int  db_due(time_t now)        { (void)now; return 0; }

#endif /* WITH_SQLITE */

/* The schema text, exposed unconditionally so the guardrail tests can
 * assert on it without linking SQLite: no password column, no key
 * material. Returns a NUL-terminated string of CREATE statements. */
const char *db_schema_sql(void);

#endif /* SLOTH_DB_H */
