/* slothweb /api/series/all (2026-11-11, the Activity page's "keys: all").
 *
 *   /api/series/all?metric=M&tier=T&from=F&to=E&cols=C&after=K
 *       every key of one metric over one window, each key's buckets
 *       merged into at most C cells so one answer can carry many keys:
 *       {"metric":..,"cell":S,"cells":N,"total":M,
 *        "keys":[{"key":K,"p":[i,v,i,v,...]},...],"more":B,"next":K,
 *        "source":W}
 *       A cell is S seconds, a whole number of the tier's buckets, the
 *       least that puts the window in C cells; cell i starts at
 *       from + i * S. "p" is sparse and flat: the index of each cell
 *       that holds a bucket and its value, oldest first. A cell's value
 *       is its buckets' merge read as /api/series reads one bucket: a
 *       gauge's mean, a counter's sum (so per S seconds, not per
 *       bucket), presence's max.
 *
 * The keys are every key of the metric, not /api/keys' 256 most
 * recently seen (owner ruling 2026-11-11, "lift the cap"): the union of
 * the keys the rollup holds a series of now (at most --web-max-keys)
 * and the keys the store holds a bucket of in the window, so a key the
 * rollup has since evicted is still answered. Those the scope holds, in
 * byte order of the key, WEB_ALLKEYS_PAGE at most to an answer and
 * fewer when the answer is full or has taken WEB_ALLKEYS_ANSWER_MS:
 * "more":true and "next" (the last key answered) say to ask again with
 * after=next. The first answer (no after) carries "total", how many
 * keys there are, and "total_min":true when the store holds more than
 * the WEB_ALLKEYS_COUNT it counts; the others carry "total":null. The
 * lists are read afresh for each answer, so a key that appeared or was
 * evicted between two pages is the one inconsistency a paged read can
 * show; none is answered twice.
 *
 * Parameters as /api/series' (web_series.h), with these of its own:
 *   - cols is decimal, WEB_ALLKEYS_COLS_MIN..WEB_ALLKEYS_COLS_MAX
 *     ("bad_cols"); WEB_ALLKEYS_COLS_DEF when absent;
 *   - after is a key of the metric, canonicalised as key= is
 *     ("bad_after");
 *   - the window holds at most WEB_ALLKEYS_BUCKETS of the tier's
 *     buckets ("range_too_long"): what bounds the rows one key costs.
 * The cost is rows, not cells: each key is one read of at most
 * WEB_ALLKEYS_BUCKETS + 1 buckets (the store's and the ring's, merged
 * as /api/series merges them) and one pass over the fine ring. An
 * answer stops taking keys once it has run WEB_ALLKEYS_ANSWER_MS (it
 * always answers one), which is what keeps it inside the request's
 * 250 ms whatever the keys hold; the key lists cost one seek a series
 * (web_store_keys_after()). test_allkeys.c times the worst page it can
 * build and a walk of 8,192 keys. */
#ifndef SLOTHWEB_ALLKEYS_H
#define SLOTHWEB_ALLKEYS_H

#include <stddef.h>

#include "web_rollup.h"
#include "web_scope.h"
#include "web_tsdb.h"

#define WEB_ALLKEYS_COLS_MIN 8
#define WEB_ALLKEYS_COLS_MAX 480
#define WEB_ALLKEYS_COLS_DEF 240
/* 7 d of minutes; 24 h of 10 s buckets is 8,640 and 400 d of hours
 * 9,600, so each tier reaches the longest window the page offers it. */
#define WEB_ALLKEYS_BUCKETS  10080
#define WEB_ALLKEYS_PAGE     128
/* The time an answer takes keys for; under half the request's 250 ms,
 * because the key it is reading when the time passes still finishes. */
#define WEB_ALLKEYS_ANSWER_MS 100
/* The store's keys the first answer counts for "total". */
#define WEB_ALLKEYS_COUNT    65536

typedef struct {
    int       metric, tier, cols;
    long long from, to;
    int       has_after;
    char      after[WEB_KEY_MAX + 1];
    /* The capture scope, NULL Hybrid; the parser leaves it NULL. */
    const web_scope_ctx_t *sc;
} web_allkeys_q_t;

/* 0, or -1 with the reason word in err. */
int    web_allkeys_parse(const char *query, long long now_s, int store_on,
                         web_allkeys_q_t *q, char *err, size_t errsz);

/* The cell a window is read in: *cell_s seconds, *ncell of them. */
void   web_allkeys_cells(int tier, long long from, long long to, int cols,
                         long long *cell_s, int *ncell);

/* WEB_ALLKEYS_ANSWER_MS, as a variable: a test sets it to 0 to see an
 * answer stop after its first key. */
extern int web_allkeys_budget_ms;

/* The answer's JSON into out. 0 if not even one key fit (or memory). */
size_t web_allkeys_json(web_tsdb_t *t, const web_allkeys_q_t *q, char *out,
                        size_t cap);

#endif
