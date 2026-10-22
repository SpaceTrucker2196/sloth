/* slothweb baseline engine (#161, M3): hour-of-week cells per
 * (metric, key), docs/web-ui-spec.md §5.3.
 *
 * Each entry holds WEB_BL_CELLS cells, one per hour of the week. The
 * index is (t / 3600) % WEB_BL_CELLS, UTC, unix-epoch aligned: which
 * weekday lands on index 0 is whatever 1970-01-01 (a Thursday) put
 * there. The index space only needs to be consistent with itself, not
 * labelled, so nothing here reads a calendar or a timezone.
 *
 * A cell is fed once an hour, when that hour's bucket closes for the
 * key (the tick thread calls web_baseline_feed with the closed
 * bucket's value): an EWMA mean and variance with a four-sample
 * half-life, matching §5.3's formula exactly (a cell sees at most one
 * sample a week, so four samples is about four weeks). A cell with
 * fewer than WEB_BL_WARM_N samples is "warming" and is not yet a claim
 * to score against.
 *
 * Deferred, flagged: §5.3 also specifies a MAD ratio over a 28-sample
 * ring per cell. At default cardinality (see web_baseline_cap_for)
 * that ring alone would cost tens of megabytes for a score neither of
 * this slice's rules (A1, A3) uses. Left for whichever rule needs it,
 * with a cheaper streaming estimator rather than a dense per-cell
 * ring.
 *
 * Entries are keyed by (metric, canonical key) rather than the
 * rollup's series id, so a baseline survives the key's own churn there
 * (a reconnect gives a key a new series id; its baseline must not
 * reset). The table is flat-capped and LRU-evicted by last_seen: no
 * per-class bounding, because unlike the rollup a baseline's cost is
 * the same shape for every key class, and the cap passed in already
 * accounts for every class's worst case (web_baseline_cap_for).
 *
 * One mutex guards everything; the tick thread feeds it, anomaly
 * scoring only reads it. */
#ifndef SLOTHWEB_BASELINE_H
#define SLOTHWEB_BASELINE_H

#include <pthread.h>

#include "web_rollup.h"

#define WEB_BL_CELLS      168
#define WEB_BL_WARM_N     3
#define WEB_BL_HALFLIFE_N 4     /* samples (weeks) for the EWMA half-life */
#define WEB_BL_VAR_EPS    1e-9

typedef struct {
    double mean, var;
    int    n;
} web_bl_cell_t;

typedef struct {
    char          key[WEB_KEY_MAX + 1];
    int           metric;
    int           used;
    int           next;           /* hash chain, -1 ends it */
    long long     last_seen;
    web_bl_cell_t cell[WEB_BL_CELLS];
} web_bl_entry_t;

typedef struct {
    pthread_mutex_t mu;
    web_bl_entry_t *e;
    int             cap, n;
    int            *head;
    int             nhead;
    unsigned long   evictions;
} web_baseline_t;

typedef struct {
    double mean, sd, z;
    int    n;          /* samples this cell has seen */
    int    warming;    /* n < WEB_BL_WARM_N */
} web_bl_score_t;

/* The entries worth capacity for, from --web-max-keys: every metric's
 * keyed class at its own cap, once. Overflow-safe for any max_keys up
 * to WEB_MAX_KEYS_MAX. */
int web_baseline_cap_for(int max_keys);

/* cap bounds the number of (metric, key) entries kept, LRU-evicted by
 * last_seen when full. 0, or -1 (memory). */
int  web_baseline_init(web_baseline_t *b, int cap);
void web_baseline_destroy(web_baseline_t *b);

/* The hour-of-week index of unix second t, 0..WEB_BL_CELLS-1. */
int  web_bl_cell_index(long long t);

/* Feed one closed hour's value for (metric, key) at hour-start t into
 * its cell. Creates the entry (evicting the LRU one if the table is
 * full) on first sight of this (metric, key) pair. A NaN or infinite
 * value is ignored. */
void web_baseline_feed(web_baseline_t *b, int metric, const char *key,
                       long long t, double value);

/* Score value against the cell for now_s's hour-of-week, for an
 * (metric, key) that has been fed at least once. 0 with *out filled,
 * or -1 when the pair has never been fed (no claim exists yet). A
 * warming cell (out->warming) scores z as 0: there is a mean but not
 * yet a basis to call anything out of band. */
int  web_baseline_score(web_baseline_t *b, int metric, const char *key,
                        long long now_s, double value, web_bl_score_t *out);

unsigned long web_baseline_evictions(web_baseline_t *b);
int           web_baseline_count(web_baseline_t *b);

#endif
