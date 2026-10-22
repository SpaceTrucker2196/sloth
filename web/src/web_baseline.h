/* slothweb baseline engine (#161, M3): hour-of-week cells per
 * (metric, key), docs/web-ui-spec.md §5.3.
 *
 * The question §5.3 asks is "is this normal for a Tuesday at 14:00", a
 * question about the operator's own week, so a cell is a LOCAL hour of
 * the week: web_bl_cell_index() is ((tm_wday + 6) % 7) * 24 + tm_hour
 * from localtime_r(), Monday 00:00 local time being cell 0. Indexing by
 * UTC epoch hours instead would move a device's routine by one cell at
 * every daylight-saving change, and every edge hour of its day would
 * read as out of band for the week after. A closed hour bucket starts
 * on a UTC hour (web_rollup.h); it is filed under the local hour its
 * start falls in. In a zone with a half-hour offset that hour spans two
 * local hours and is filed under the first. Across a DST change one
 * cell gets no sample that week (spring) or two (autumn): both are one
 * sample of four in the half-life, not a shifted routine.
 *
 * A cell is fed once an hour, when the hour closes, with the bucket's
 * value on one scale per metric (web_bl_value()): a gauge's mean, a
 * presence metric's max (0 or 1), and a counter's sum PER MINUTE, so
 * that a minute bucket and an hour bucket of the same counter can be
 * compared directly. Each cell is an EWMA mean and variance with a
 * four-sample half-life, §5.3's formula (alpha = 1 - 2^(-1/4); a cell
 * sees one sample a week, so about four weeks). A cell with fewer than
 * WEB_BL_WARM_N samples is warming and makes no claim.
 *
 * What an hour without a row means depends on the metric's kind:
 * a counter that counted nothing and a device that was not present
 * both had a real value of 0, and web_baseline_zero_missing() feeds it
 * to every counter and presence entry the hour did not feed. A gauge
 * with no row was not measured (sloth did not report the host, the
 * channel, the interface), which is not a zero, so it is not fed. Only
 * an entry that exists is zero-fed: a key gets an entry from its first
 * real hour row and never before.
 *
 * The spread used to score is floored (web_bl_sd_floor()): sd is at
 * least WEB_BL_SD_REL of |mean| and at least one unit of the metric
 * (one count a minute, one connection, one AP; 1 KiB/s for a byte
 * rate). A cell whose samples were all equal has var 0, and without a
 * floor one extra AP on a channel was z = 31,623.
 *
 * Entries are keyed by (metric, canonical key), not by the rollup's
 * series id, so a key's churn there does not reset its baseline. The
 * table is capped: entries come from fixed chunks allocated as they are
 * needed (memory follows the entries there are, not the cap), a free
 * list and a doubly linked LRU list ordered by last_active (the last
 * hour with a real row) make insert, touch and evict O(1), and an entry
 * whose last_active is older than the hour tier keeps (400 days) is
 * aged out. Evictions are counted on /api/health. A cell is 12 bytes
 * (float mean, float var, 16-bit n), an entry about 2.1 KB.
 *
 * Persistence (slothweb.db v3, web_store.h): every entry carries the id
 * of its row there and a bitmap of cells changed since it was last
 * written. The store thread takes the dirty cells after each hourly
 * feed and writes them; an evicted or aged-out entry's id is queued for
 * deletion. Restored entries are loaded before any thread starts.
 *
 * One mutex guards everything. Only the store thread writes (feeds,
 * evicts, takes dirty cells); the HTTP thread reads cells for
 * /api/baseline. */
#ifndef SLOTHWEB_BASELINE_H
#define SLOTHWEB_BASELINE_H

#include <pthread.h>
#include <stdint.h>

#include "web_rollup.h"

#define WEB_BL_CELLS      168
#define WEB_BL_WARM_N     3
#define WEB_BL_HALFLIFE_N 4     /* samples (weeks) for the EWMA half-life */
#define WEB_BL_SD_REL     0.10  /* sd floor, as a share of |mean| */
#define WEB_BL_CHUNK      256   /* entries per allocation */
#define WEB_BL_N_MAX      65535
/* Ids of evicted entries waiting to be deleted from the store. Past
 * this the oldest are forgotten (counted): their rows are then deleted
 * when the store next finds more rows than entries, at restore. */
#define WEB_BL_DEL_MAX    4096

typedef struct {
    float    mean, var;
    uint16_t n;
} web_bl_cell_t;

typedef struct {
    char          key[WEB_KEY_MAX + 1];
    int           metric;
    int           used;
    int           hnext;          /* hash chain, or the free list */
    int           lprev, lnext;   /* LRU list, most recently active first */
    long long     last_active;    /* hour start of the last real row */
    long long     last_fed;       /* hour start of the last feed, real or zero */
    long long     db_id;          /* its row in slothweb.db, -1 none yet */
    int           dirty_meta;
    uint8_t       dirty[(WEB_BL_CELLS + 7) / 8];
    web_bl_cell_t cell[WEB_BL_CELLS];
} web_bl_entry_t;

typedef struct {
    pthread_mutex_t  mu;
    web_bl_entry_t **chunk;
    int              nchunk, cap, n, alloc;
    int              free_head;
    int              lru_head, lru_tail;
    int             *head;
    int              nhead;
    unsigned long    evictions, aged_out, zero_fed, fed, skipped_dup;
    long long        del[WEB_BL_DEL_MAX];
    int              ndel;
    unsigned long    del_lost;
} web_baseline_t;

typedef struct {
    double mean, sd, z;
    int    n;          /* samples this cell has seen */
    int    warming;    /* n < WEB_BL_WARM_N */
} web_bl_score_t;

/* One dirty cell of an entry, for the store thread to write. */
typedef struct {
    long long db_id;              /* -1: the entry has no row yet */
    int       metric;
    char      key[WEB_KEY_MAX + 1];
    long long last_active, last_fed;
    int       cell;               /* -1: the entry's row only */
    double    mean, var;
    int       n;
} web_bl_rec_t;

/* The entries worth capacity for, from --web-max-keys: every metric's
 * class at its own cap, once. The table never allocates more than it
 * holds, so this is a ceiling, not a cost. */
int web_baseline_cap_for(int max_keys);

int  web_baseline_init(web_baseline_t *b, int cap);
void web_baseline_destroy(web_baseline_t *b);

/* The local hour-of-week cell of unix second t: Monday 00:00 is 0. */
int  web_bl_cell_index(long long t);

/* The value a bucket of step seconds stands for on the baseline's
 * scale: a gauge's mean, a presence metric's max, a counter's sum per
 * minute. */
double web_bl_value(int metric, const web_point_t *p, int step);

/* The least sd a score divides by, for metric at mean. */
double web_bl_sd_floor(int metric, double mean);

/* Feed one closed hour (start t) of (metric, key). real: the hour had a
 * row, so the entry is created if it is new and its last_active moves;
 * not real (a zero feed): only an existing entry is fed. An hour
 * already fed for the entry, a NaN or an infinity is ignored. 0 fed,
 * -1 not. */
int  web_baseline_feed(web_baseline_t *b, int metric, const char *key,
                       long long t, double value, int real);

/* Feed 0 at hour t to every counter and presence entry whose last feed
 * is older than t. Returns how many. */
int  web_baseline_zero_missing(web_baseline_t *b, long long t);

/* Drop every entry whose last_active is older than before. Returns how
 * many. */
int  web_baseline_age_out(web_baseline_t *b, long long before);

/* Score value against the cell of t's hour of the week. 0 with *out
 * filled, or -1 when the pair has never been fed. A warming cell scores
 * z as 0. */
int  web_baseline_score(web_baseline_t *b, int metric, const char *key,
                        long long t, double value, web_bl_score_t *out);

/* The 168 cells of (metric, key) into out. 0, or -1 when never fed. */
int  web_baseline_cells(web_baseline_t *b, int metric, const char *key,
                        web_bl_cell_t out[WEB_BL_CELLS]);

/* Every counter entry: fn(ctx, metric, key) under the lock, for A1's
 * "a counter with no row this minute counted zero". fn must not call
 * back into the baseline. */
void web_baseline_each_counter(web_baseline_t *b,
                               void (*fn)(void *ctx, int metric,
                                          const char *key),
                               void *ctx);

/* Up to max dirty cells (and entry rows) into out, clearing them.
 * Returns how many. */
int  web_baseline_take_dirty(web_baseline_t *b, web_bl_rec_t *out, int max);
/* The store gave (metric, key) row id. */
void web_baseline_set_dbid(web_baseline_t *b, int metric, const char *key,
                           long long id);
/* Up to max ids of entries evicted since the last call. */
int  web_baseline_take_deleted(web_baseline_t *b, long long *out, int max);

/* Restore: an entry with its row id, then its cells. 0, or -1 when the
 * table is full or the pair is not valid. */
int  web_baseline_load(web_baseline_t *b, int metric, const char *key,
                       long long db_id, long long last_active,
                       long long last_fed);
int  web_baseline_load_cell(web_baseline_t *b, int metric, const char *key,
                            int cell, double mean, double var, long n);

typedef struct {
    int           entries, cap, chunks;
    unsigned long evictions, aged_out, zero_fed, fed, skipped_dup, del_lost;
} web_bl_stats_t;

void web_baseline_stats(web_baseline_t *b, web_bl_stats_t *out);
unsigned long web_baseline_evictions(web_baseline_t *b);
int           web_baseline_count(web_baseline_t *b);

#endif
