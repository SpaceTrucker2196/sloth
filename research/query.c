#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "query.h"

struct rq_handle { sqlite3 *db; };

static char g_open_err[128];

const char *rq_open_error(void) { return g_open_err; }

rq_handle_t *rq_open(const char *path) {
    g_open_err[0] = '\0';
    if (!path || !path[0]) {
        snprintf(g_open_err, sizeof(g_open_err), "no path given");
        return NULL;
    }
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        snprintf(g_open_err, sizeof(g_open_err), "cannot open %.80s", path);
        if (db) sqlite3_close(db);
        return NULL;
    }
    /* Schema check, not just an open. A file that exists and is a valid
     * SQLite database but carries some other schema would otherwise
     * fail later, one query at a time, with errors that say nothing
     * useful. */
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_prepare_v2(db, "SELECT title, body, source_url, retrieved,"
                                    " topics, alert_kinds, path FROM research"
                                    " LIMIT 0", -1, &st, NULL) == SQLITE_OK;
    if (st) sqlite3_finalize(st);
    if (!ok) {
        snprintf(g_open_err, sizeof(g_open_err),
                 "%.60s is not a research corpus", path);
        sqlite3_close(db);
        return NULL;
    }
    rq_handle_t *h = calloc(1, sizeof(*h));
    if (!h) { sqlite3_close(db); return NULL; }
    h->db = db;
    return h;
}

void rq_close(rq_handle_t *h) {
    if (!h) return;
    if (h->db) sqlite3_close(h->db);
    free(h);
}

static void col_str(sqlite3_stmt *st, int i, char *dst, size_t cap) {
    const unsigned char *v = sqlite3_column_text(st, i);
    snprintf(dst, cap, "%s", v ? (const char *)v : "");
}

static void fill_hit(sqlite3_stmt *st, rq_hit_t *hit, int has_score) {
    memset(hit, 0, sizeof(*hit));
    col_str(st, 0, hit->title,      sizeof(hit->title));
    col_str(st, 1, hit->snippet,    sizeof(hit->snippet));
    col_str(st, 2, hit->source_url, sizeof(hit->source_url));
    col_str(st, 3, hit->retrieved,  sizeof(hit->retrieved));
    col_str(st, 4, hit->topics,     sizeof(hit->topics));
    col_str(st, 5, hit->path,       sizeof(hit->path));
    hit->score = has_score ? sqlite3_column_double(st, 6) : 0.0;
}

int rq_search(rq_handle_t *h, const char *query, const char *filter,
              rq_hit_t *out, int max) {
    if (!h || !h->db || !query || !query[0] || !out || max <= 0) return 0;
    if (max > RQ_MAX_HITS) max = RQ_MAX_HITS;

    /* snippet() gives the matching passage rather than the head of the
     * section — a hit that shows the first 256 bytes of a document is
     * a citation, not an answer. */
    /* Free-text query goes through MATCH — fuzzy is the point of a
     * search. The *filter* does not: see the note on rq_for_alert about
     * why an alert kind must never be matched by the tokenizer. */
    const char *sql =
        "SELECT title,"
        "       snippet(research, 1, '', '', '…', 24),"
        "       source_url, retrieved, topics, path, bm25(research)"
        "  FROM research"
        " WHERE research MATCH ?1"
        "   AND (?3 = ''"
        "        OR (' ' || topics      || ' ') LIKE ('% ' || ?3 || ' %')"
        "        OR (' ' || alert_kinds || ' ') LIKE ('% ' || ?3 || ' %'))"
        " ORDER BY bm25(research), path"
        " LIMIT ?2";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, max);
    sqlite3_bind_text(st, 3, (filter && filter[0]) ? filter : "",
                      -1, SQLITE_TRANSIENT);

    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        fill_hit(st, &out[n++], 1);
    sqlite3_finalize(st);
    return n;
}

int rq_for_alert(rq_handle_t *h, const char *alert_kind,
                 rq_hit_t *out, int max) {
    if (!h || !h->db || !alert_kind || !alert_kind[0] || !out || max <= 0)
        return 0;
    if (max > RQ_MAX_HITS) max = RQ_MAX_HITS;

    /* **Not MATCH.** The unicode61 tokenizer splits on underscores, so
     * `alert_kinds MATCH 'ALERT_TYPE_EVIL_TWIN'` requires only the
     * tokens alert/type/evil/twin to be present — and a document naming
     * *only* ALERT_TYPE_EVIL_TWIN_PROXIMITY contains all four. The
     * References block for one alert would silently cite a document
     * about a different one.
     *
     * Delimiter-wrapped LIKE against the stored list is exact: the
     * needle must appear as a whole space-separated token. Same
     * whole-token requirement the corpus guard has, enforced here in
     * SQL rather than in C.
     *
     * Ordered by retrieved desc then path, not by relevance: a
     * References block regenerated tomorrow must be byte-identical to
     * today's, and BM25 scores shift as the corpus grows. */
    /* One row per *document*, not per section. The index stores a row
     * per heading, so a document with four sections naming this alert
     * would otherwise put the same source in a References block four
     * times — which reads as four citations.
     *
     * MIN(rowid) picks the document's first section, which ingest
     * writes as the preamble carrying the H1 — the document title, and
     * the right thing to show in a citation. */
    const char *sql =
        "SELECT title, substr(body,1,200), source_url, retrieved, topics, path"
        "  FROM research"
        " WHERE rowid IN ("
        "     SELECT MIN(rowid) FROM research"
        "      WHERE (' ' || alert_kinds || ' ') LIKE ('% ' || ?1 || ' %')"
        "      GROUP BY path)"
        " ORDER BY retrieved DESC, path"
        " LIMIT ?2";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, alert_kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, max);

    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        fill_hit(st, &out[n++], 0);
    sqlite3_finalize(st);
    return n;
}

int rq_cite(rq_handle_t *h, const char *topic, char out[][RQ_STR], int max) {
    if (!h || !h->db || !topic || !topic[0] || !out || max <= 0) return 0;

    /* Exact on both columns, for the same reason as rq_for_alert: a
     * citation set that quietly includes a neighbouring alert kind is
     * worse than an empty one, because it looks right.
     *
     * DISTINCT source_url: one citation per source, however many
     * sections of it matched. Ordered by url so the set is stable. */
    const char *sql =
        "SELECT DISTINCT source_url FROM research"
        " WHERE (' ' || topics      || ' ') LIKE ('% ' || ?1 || ' %')"
        "    OR (' ' || alert_kinds || ' ') LIKE ('% ' || ?1 || ' %')"
        " ORDER BY source_url"
        " LIMIT ?2";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, topic, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, max);

    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        snprintf(out[n], RQ_STR, "%s", v ? (const char *)v : "");
        if (out[n][0]) n++;
    }
    sqlite3_finalize(st);
    return n;
}

int rq_recent(rq_handle_t *h, int days, time_t now, rq_hit_t *out, int max) {
    if (!h || !h->db || !out || max <= 0) return 0;
    if (days <= 0) days = 7;
    if (max > RQ_MAX_HITS) max = RQ_MAX_HITS;

    /* retrieved is stored as YYYY-MM-DD text, so the cutoff is computed
     * as text and compared lexically — which is correct for that format
     * and needs no date parsing on either side. */
    time_t cutoff_t = now - (time_t)days * 86400;
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&cutoff_t, &tm_buf);
    if (!tm) return 0;
    /* Bounded rather than trusted. GCC cannot prove a struct tm's
     * fields are in range and warns about the truncation that would
     * follow — and it is right to: a garbage tm should produce a cutoff
     * that finds nothing, not one that silently matches everything.
     * Same treatment as #58, which was the last -Wformat-truncation
     * here: bound the input, do not silence the warning. */
    int yy = tm->tm_year + 1900, mm = tm->tm_mon + 1, dd = tm->tm_mday;
    if (yy < 0)    yy = 0;
    if (yy > 9999) yy = 9999;
    if (mm < 1)    mm = 1;
    if (mm > 12)   mm = 12;
    if (dd < 1)    dd = 1;
    if (dd > 31)   dd = 31;
    char cutoff[16];
    snprintf(cutoff, sizeof(cutoff), "%04d-%02d-%02d", yy, mm, dd);

    const char *sql =
        "SELECT title, substr(body,1,200), source_url, retrieved, topics, path"
        "  FROM research"
        " WHERE retrieved >= ?1"
        " ORDER BY retrieved DESC, path"
        " LIMIT ?2";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h->db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, cutoff, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, max);

    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        fill_hit(st, &out[n++], 0);
    sqlite3_finalize(st);
    return n;
}
