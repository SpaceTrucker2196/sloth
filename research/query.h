#ifndef RESEARCH_QUERY_H
#define RESEARCH_QUERY_H

#include <time.h>

/* Research-corpus queries — issue #73, slice 2.
 *
 * The four operations the issue specifies, over the FTS5 index slice 1
 * builds. Deliberately a *library* rather than only an MCP server:
 *
 *   - sloth links it directly for `--with-research`. It is sloth's own
 *     data file; spawning a subprocess and speaking JSON-RPC to ask
 *     about it would be ceremony, not architecture. The issue proposes
 *     that path; this is a §4.2 departure.
 *   - sloth-research-mcp is a thin transport wrapper over the same
 *     functions, for the external consumers MCP is actually for —
 *     Claude sessions and scheduled tasks querying a corpus they did
 *     not build.
 *
 * One implementation, two front doors. Everything worth testing is in
 * here, where the tests can reach it without a protocol in the way.
 *
 * ── Degradation ──
 *
 * Every function is safe against a NULL handle and returns zero
 * results. That is the contract `--with-research` depends on: a
 * missing, unreadable or schema-mismatched corpus must leave sloth
 * running with no research context, never fail to start. The research
 * surface is additive; nothing in the capture path may depend on it. */

#define RQ_MAX_HITS      16
#define RQ_STR          128
#define RQ_SNIPPET      256

typedef struct rq_handle rq_handle_t;

typedef struct {
    char   title[RQ_STR];
    char   snippet[RQ_SNIPPET];
    char   source_url[RQ_STR];
    char   retrieved[16];
    char   topics[RQ_STR];
    char   path[RQ_STR];
    double score;          /* BM25; lower is a better match */
} rq_hit_t;

#ifdef WITH_SQLITE

/* Open the corpus read-only. Returns NULL when the file is missing,
 * unreadable, or does not carry the expected schema — the caller logs
 * and continues without research context. */
rq_handle_t *rq_open(const char *path);
void         rq_close(rq_handle_t *h);

/* Why the last rq_open() returned NULL; "" when it succeeded. Exists so
 * the startup banner can say *which* of the three it was, rather than
 * "research unavailable". */
const char *rq_open_error(void);

/* Full-text search, BM25-ranked. `filter` may be NULL, or a topic or
 * alert-kind to restrict to. Returns the number of hits written. */
int rq_search(rq_handle_t *h, const char *query, const char *filter,
              rq_hit_t *out, int max);

/* Every document whose frontmatter names `alert_kind`. This is the
 * query --report makes per alert.
 *
 * Ordering is by retrieved date descending, then path — stable across
 * runs on the same database, so a regenerated report is byte-identical
 * rather than merely equivalent. */
int rq_for_alert(rq_handle_t *h, const char *alert_kind,
                 rq_hit_t *out, int max);

/* Canonical citation strings for a topic, deduplicated and stably
 * sorted. Writes NUL-terminated strings into `out`. */
int rq_cite(rq_handle_t *h, const char *topic,
            char out[][RQ_STR], int max);

/* Documents retrieved within `days` of `now`. Feeds the weekly brief.
 * `now` is passed rather than read so the query is testable against a
 * fixed clock. */
int rq_recent(rq_handle_t *h, int days, time_t now, rq_hit_t *out, int max);

#else  /* !WITH_SQLITE */

/* The corpus is an FTS5 index, so without SQLite there is nothing to
 * query. Stubbed rather than conditionally called at every site: the
 * additive contract already requires every caller to handle a NULL
 * handle and a zero result, so the no-SQLite build takes the same path
 * as a missing corpus file. */
static inline rq_handle_t *rq_open(const char *p) { (void)p; return 0; }
static inline void rq_close(rq_handle_t *h)       { (void)h; }
static inline const char *rq_open_error(void)
                                 { return "built without SQLite"; }
static inline int rq_search(rq_handle_t *h, const char *q, const char *f,
                            rq_hit_t *o, int m)
       { (void)h; (void)q; (void)f; (void)o; (void)m; return 0; }
static inline int rq_for_alert(rq_handle_t *h, const char *k,
                               rq_hit_t *o, int m)
       { (void)h; (void)k; (void)o; (void)m; return 0; }
static inline int rq_cite(rq_handle_t *h, const char *t,
                          char o[][RQ_STR], int m)
       { (void)h; (void)t; (void)o; (void)m; return 0; }
static inline int rq_recent(rq_handle_t *h, int d, time_t n,
                            rq_hit_t *o, int m)
       { (void)h; (void)d; (void)n; (void)o; (void)m; return 0; }

#endif /* WITH_SQLITE */

#endif /* RESEARCH_QUERY_H */
