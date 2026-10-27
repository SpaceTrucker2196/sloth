#include "web_alertdb.h"

#include <stdio.h>
#include <string.h>

#include "web_json.h"
#include "web_scope.h"

#ifndef WITH_SQLITE

int web_adb_groups(web_sdb_conn_t *c, const web_adb_filter_t *f,
                   long long limit, long long offset, web_adb_group_fn fn,
                   void *ctx, web_adb_stats_t *st) {
    (void)c; (void)f; (void)limit; (void)offset; (void)fn; (void)ctx;
    if (st) memset(st, 0, sizeof(*st));
    return -1;
}
int web_adb_key_totals(web_sdb_conn_t *c, long long rid, const char *key,
                       web_adb_totals_t *t) {
    (void)c; (void)rid; (void)key; (void)t;
    return -1;
}
int web_adb_row(web_sdb_conn_t *c, long long rid, web_adb_row_t *out) {
    (void)c; (void)rid; (void)out;
    return -1;
}
int web_adb_incidents(web_sdb_conn_t *c, long long rid, const char *key,
                      int max, web_adb_row_fn fn, void *ctx) {
    (void)c; (void)rid; (void)key; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_adb_device(web_sdb_conn_t *c, long long rid, const char *key,
                   const char *ip, char mac[18]) {
    (void)c; (void)rid; (void)key; (void)ip; (void)mac;
    return -1;
}

#else

#include <sqlite3.h>

/* ── a statement with its binds, assembled from constant fragments ── */

#define SQL_MAX   (12 * 1024)
#define BINDS_MAX (WEB_ADB_EXCLUDE + 3 * WEB_ADB_TYPES + 48)

typedef struct {
    char        sql[SQL_MAX];
    size_t      o;
    int         over;
    int         nb;
    int         kind[BINDS_MAX];       /* 0 integer, 1 text */
    long long   i[BINDS_MAX];
    const char *s[BINDS_MAX];
} sqlb_t;

static void add(sqlb_t *b, const char *frag) {
    size_t n = strlen(frag);
    if (b->o + n + 1 > sizeof(b->sql)) { b->over = 1; return; }
    memcpy(b->sql + b->o, frag, n + 1);
    b->o += n;
}

static void bind_i(sqlb_t *b, long long v) {
    if (b->nb >= BINDS_MAX) { b->over = 1; return; }
    b->kind[b->nb] = 0;
    b->i[b->nb++] = v;
    add(b, "?");
}

static void bind_s(sqlb_t *b, const char *v) {
    if (b->nb >= BINDS_MAX) { b->over = 1; return; }
    b->kind[b->nb] = 1;
    b->s[b->nb++] = v;
    add(b, "?");
}

static sqlite3_stmt *prepare(web_sdb_conn_t *c, const sqlb_t *b) {
    if (b->over) return NULL;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, b->sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return NULL;
    }
    for (int k = 0; k < b->nb; k++) {
        if (b->kind[k]) sqlite3_bind_text(st, k + 1, b->s[k], -1, SQLITE_TRANSIENT);
        else            sqlite3_bind_int64(st, k + 1, b->i[k]);
    }
    return st;
}

static void text_col(sqlite3_stmt *st, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(st, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

/* Has the file an alerts table with the columns read here? The probe's
 * WEB_QF_ALERTS covers every allow-listed column of it. */
static int have_alerts(const web_sdb_conn_t *c) {
    return (c->feats & WEB_QF_ALERTS) != 0;
}

static long long cap_of(const web_adb_filter_t *f) {
    return f->scan_cap > 0 ? f->scan_cap : WEB_ADB_SCAN_CAP;
}

/* The rows a list reads: the window's rows that f's predicates match,
 * newest last_seen first through idx_alerts_last_seen, at most scan_cap
 * of them. The predicates sit inside the bounded read, so the cap
 * counts matching rows: an old row of a rare type is reached by asking
 * for its type, where a cap taken before the filter would have stopped
 * at the newest rows of every type. A filter that matches little walks
 * the window for it, under the request's budget (WEB_SDB_HTTP_MS).
 * type_filter 0 leaves the type filter out (the facets). */
static void window_rows(sqlb_t *b, const web_adb_filter_t *f, int type_filter,
                        char like[WEB_ADB_Q_MAX * 2 + 3]) {
    add(b, "SELECT rowid AS rid, key, type, sev, title, match_ip, match_port,"
           " technique, count, first_seen, last_seen FROM alerts"
           " WHERE last_seen >= ");
    bind_i(b, f->since);
    add(b, " AND last_seen <= ");
    bind_i(b, f->until);
    if (f->sev_mask) {
        add(b, " AND sev IN (-1");
        for (int s = 0; s < 3; s++)
            if (f->sev_mask & (1u << s)) { add(b, ","); bind_i(b, s); }
        add(b, ")");
    }
    if (type_filter && f->ntypes) {
        add(b, " AND type IN (-1");
        for (int i = 0; i < f->ntypes; i++) { add(b, ","); bind_i(b, f->types[i]); }
        add(b, ")");
    }
    if (f->scope) {
        /* The scope's types, the facets' read as well: a scope's
         * dropdown lists its own types only. sloth.db rows carry no
         * link type, so radio 0 (web_scope.h). */
        int ty[WEB_ADB_TYPES + 32];
        int n = web_scope_alert_types(f->scope, 0, ty, WEB_ADB_TYPES + 32);
        add(b, " AND type IN (-1");
        for (int i = 0; i < n; i++) { add(b, ","); bind_i(b, ty[i]); }
        add(b, ")");
    }
    if (f->q[0]) {
        /* A substring, LIKE-escaped: \, % and _ stand for themselves. */
        size_t o = 0;
        like[o++] = '%';
        for (const char *p = f->q; *p; p++) {
            if (*p == '\\' || *p == '%' || *p == '_') like[o++] = '\\';
            like[o++] = *p;
        }
        like[o++] = '%';
        like[o] = '\0';
        add(b, " AND (title LIKE ");
        bind_s(b, like);
        add(b, " ESCAPE '\\' OR match_ip LIKE ");
        bind_s(b, like);
        add(b, " ESCAPE '\\'");
        if (f->nqtypes) {
            add(b, " OR type IN (-1");
            for (int i = 0; i < f->nqtypes; i++) { add(b, ","); bind_i(b, f->qtypes[i]); }
            add(b, ")");
        }
        add(b, ")");
    }
    if (f->nexclude) {
        add(b, " AND key NOT IN (''");
        for (int i = 0; i < f->nexclude; i++) { add(b, ","); bind_s(b, f->exclude[i]); }
        add(b, ")");
    }
    add(b, " ORDER BY last_seen DESC LIMIT ");
    bind_i(b, cap_of(f));
}

/* One facet row into st, the type filter weighed for st->groups. */
static void facet(web_adb_stats_t *st, const web_adb_filter_t *f, int ty, long long keys) {
    int in = !f->ntypes;
    for (int i = 0; i < f->ntypes && !in; i++) in = f->types[i] == ty;
    if (in) st->groups += keys;
    if (st->ntypes < WEB_ADB_TYPES) {
        st->facet_type[st->ntypes] = ty;
        st->facet_n[st->ntypes] = keys;
        st->ntypes++;
    }
}

int web_adb_groups(web_sdb_conn_t *c, const web_adb_filter_t *f,
                   long long limit, long long offset, web_adb_group_fn fn,
                   void *ctx, web_adb_stats_t *st) {
    if (st) memset(st, 0, sizeof(*st));
    if (!have_alerts(c)) return 0;
    sqlb_t b;                        /* 22 KB of text and its binds */
    char like[WEB_ADB_Q_MAX * 2 + 3];
    int rc = 0, n = 0, saw_scan = 0;
    /* One walk of the bounded read, materialised once, answers the page
     * (GROUP BY key, the key deciding the group and no result column
     * reading it), how many matching rows were read and the oldest of
     * them, and, with no type filter, the facets: a filter that matches
     * little walks the window once, not three times. */
    int facets_here = st && !f->ntypes;
    memset(&b, 0, sizeof(b));
    add(&b, "WITH w AS MATERIALIZED (");
    window_rows(&b, f, 1, like);
    add(&b, "), t AS (SELECT count(*) AS n, min(last_seen) AS o FROM w)"
            " SELECT * FROM (SELECT 0, max(rid), type, max(sev), COALESCE(title,''),"
            " COALESCE(match_ip,''), COALESCE(match_port,-1), COALESCE(technique,''),"
            " sum(count), min(first_seen), max(last_seen), count(*),"
            " (SELECT n FROM t), (SELECT o FROM t)"
            " FROM w GROUP BY key ORDER BY max(last_seen) DESC, max(rid) DESC LIMIT ");
    bind_i(&b, limit);
    add(&b, " OFFSET ");
    bind_i(&b, offset);
    add(&b, ") UNION ALL SELECT 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,"
            " NULL, NULL, n, o FROM t");
    if (facets_here)
        add(&b, " UNION ALL SELECT * FROM (SELECT 2, NULL, type, NULL, NULL, NULL, NULL, NULL,"
                " NULL, NULL, NULL, count(DISTINCT key), NULL, NULL FROM w GROUP BY type"
                " ORDER BY 12 DESC, 3)");
    c->pred_ok = 1;
    sqlite3_stmt *s = prepare(c, &b);
    if (!s) { c->pred_ok = 0; return -1; }
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        int kind = sqlite3_column_int(s, 0);
        if (kind == 1) {
            if (st) {
                st->scanned = sqlite3_column_int64(s, 12);
                st->oldest = sqlite3_column_int64(s, 13);
            }
            saw_scan = 1;
            continue;
        }
        if (kind == 2) {
            facet(st, f, sqlite3_column_int(s, 2), sqlite3_column_int64(s, 11));
            continue;
        }
        if (!fn) continue;
        web_adb_group_t g;
        memset(&g, 0, sizeof(g));
        g.rid = sqlite3_column_int64(s, 1);
        g.type = sqlite3_column_int(s, 2);
        g.sev = sqlite3_column_int(s, 3);
        text_col(s, 4, g.title, sizeof(g.title));
        text_col(s, 5, g.ip, sizeof(g.ip));
        g.port = sqlite3_column_int(s, 6);
        text_col(s, 7, g.technique, sizeof(g.technique));
        g.count = sqlite3_column_int64(s, 8);
        g.first_seen = sqlite3_column_int64(s, 9);
        g.last_seen = sqlite3_column_int64(s, 10);
        g.rows = sqlite3_column_int64(s, 11);
        n++;
        if (fn(ctx, &g)) fn = NULL;  /* full: the scan and facet rows still to read */
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE || !saw_scan) { c->pred_ok = 0; return -1; }
    if (st && !facets_here) {
        /* With a type filter the facets leave it out, so the dropdown
         * shows every type: a second walk, of the other predicates. */
        memset(&b, 0, sizeof(b));
        add(&b, "WITH w AS (");
        window_rows(&b, f, 0, like);
        add(&b, ") SELECT type, count(DISTINCT key) FROM w GROUP BY type ORDER BY 2 DESC, 1");
        s = prepare(c, &b);
        if (!s) { c->pred_ok = 0; return -1; }
        while ((rc = sqlite3_step(s)) == SQLITE_ROW)
            facet(st, f, sqlite3_column_int(s, 0), sqlite3_column_int64(s, 1));
        sqlite3_finalize(s);
        if (rc != SQLITE_DONE) { c->pred_ok = 0; return -1; }
    }
    if (st) st->capped = st->scanned >= cap_of(f);
    c->pred_ok = 0;
    return n;
}

/* "key = ?" by the key itself, or by "the key of rowid ?". */
static void key_is(sqlb_t *b, long long rid, const char *key) {
    if (key) { add(b, "key = "); bind_s(b, key); return; }
    add(b, "key = (SELECT key FROM alerts WHERE rowid = ");
    bind_i(b, rid);
    add(b, ")");
}

int web_adb_key_totals(web_sdb_conn_t *c, long long rid, const char *key,
                       web_adb_totals_t *t) {
    memset(t, 0, sizeof(*t));
    if (!have_alerts(c)) return 0;
    sqlb_t b;
    memset(&b, 0, sizeof(b));
    /* The primary key's index: (key, first_seen) and the rowid in it.
     * A v8 row holds 1 + reopens incidents (#170), a v7 row one. */
    add(&b, (c->opt & WEB_SDB_OPT_INC)
        ? "SELECT count(*), min(first_seen), max(rowid), sum(count),"
          " sum(1 + reopens) FROM alerts WHERE "
        : "SELECT count(*), min(first_seen), max(rowid), sum(count),"
          " count(*) FROM alerts WHERE ");
    key_is(&b, rid, key);
    c->pred_ok = 1;
    sqlite3_stmt *s = prepare(c, &b);
    if (!s) { c->pred_ok = 0; c->detail_ok = 0; return -1; }
    int rc = sqlite3_step(s), found = 0;
    if (rc == SQLITE_ROW && sqlite3_column_int64(s, 0) > 0) {
        t->rows = sqlite3_column_int64(s, 0);
        t->first_seen = sqlite3_column_int64(s, 1);
        t->newest_rid = sqlite3_column_int64(s, 2);
        t->count = sqlite3_column_int64(s, 3);
        t->incidents = sqlite3_column_int64(s, 4);
        found = 1;
    }
    sqlite3_finalize(s);
    c->pred_ok = 0;
    c->detail_ok = 0;
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

static void row_of(sqlite3_stmt *s, web_adb_row_t *r) {
    memset(r, 0, sizeof(*r));
    r->rid = sqlite3_column_int64(s, 0);
    r->type = sqlite3_column_int(s, 1);
    r->sev = sqlite3_column_int(s, 2);
    text_col(s, 3, r->title, sizeof(r->title));
    text_col(s, 4, r->ip, sizeof(r->ip));
    r->port = sqlite3_column_int(s, 5);
    text_col(s, 6, r->technique, sizeof(r->technique));
    r->count = sqlite3_column_int64(s, 7);
    r->first_seen = sqlite3_column_int64(s, 8);
    r->last_seen = sqlite3_column_int64(s, 9);
    r->has_detail = sqlite3_column_type(s, 10) != SQLITE_NULL;
    text_col(s, 10, r->detail, sizeof(r->detail));
}

/* The one place alerts.detail is read: through web_detail_ok(type). */
static const char ROW_COLS[] =
    "SELECT rowid, type, sev, COALESCE(title,''), COALESCE(match_ip,''),"
    " COALESCE(match_port,-1), COALESCE(technique,''), count, first_seen,"
    " last_seen, CASE WHEN web_detail_ok(type) THEN COALESCE(detail,'') END"
    " FROM alerts WHERE ";

int web_adb_row(web_sdb_conn_t *c, long long rid, web_adb_row_t *out) {
    if (!have_alerts(c)) return 0;
    sqlb_t b;
    memset(&b, 0, sizeof(b));
    add(&b, ROW_COLS);
    add(&b, "rowid = ");
    bind_i(&b, rid);
    c->detail_ok = 1;
    sqlite3_stmt *s = prepare(c, &b);
    if (!s) { c->pred_ok = 0; c->detail_ok = 0; return -1; }
    int rc = sqlite3_step(s), found = 0;
    if (rc == SQLITE_ROW) { row_of(s, out); found = 1; }
    sqlite3_finalize(s);
    c->pred_ok = 0;
    c->detail_ok = 0;
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? found : -1;
}

int web_adb_incidents(web_sdb_conn_t *c, long long rid, const char *key,
                      int max, web_adb_row_fn fn, void *ctx) {
    if (!have_alerts(c)) return 0;
    if (max < 1 || max > WEB_ADB_INCIDENTS) max = WEB_ADB_INCIDENTS;
    sqlb_t b;
    memset(&b, 0, sizeof(b));
    add(&b, ROW_COLS);
    key_is(&b, rid, key);
    add(&b, " ORDER BY first_seen DESC LIMIT ");
    bind_i(&b, max);
    c->pred_ok = 1;
    c->detail_ok = 1;
    sqlite3_stmt *s = prepare(c, &b);
    if (!s) { c->pred_ok = 0; c->detail_ok = 0; return -1; }
    int rc, n = 0;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        web_adb_row_t r;
        row_of(s, &r);
        n++;
        if (fn(ctx, &r)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(s);
    c->pred_ok = 0;
    c->detail_ok = 0;
    return rc == SQLITE_DONE ? n : -1;
}

int web_adb_device(web_sdb_conn_t *c, long long rid, const char *key,
                   const char *ip, char mac[18]) {
    sqlb_t b;
    int found = 0, rc = SQLITE_DONE;
    if (have_alerts(c) || key) {
        /* A MAC in the key, matched as a predicate: only devices.mac is
         * read out. */
        memset(&b, 0, sizeof(b));
        add(&b, "SELECT mac FROM devices WHERE instr(");
        if (key) bind_s(&b, key);
        else {
            add(&b, "(SELECT key FROM alerts WHERE rowid = ");
            bind_i(&b, rid);
            add(&b, ")");
        }
        add(&b, ", mac) > 0 ORDER BY last_seen DESC LIMIT 1");
        c->pred_ok = 1;
        sqlite3_stmt *s = prepare(c, &b);
        if (!s) { c->pred_ok = 0; c->detail_ok = 0; return -1; }
        rc = sqlite3_step(s);
        if (rc == SQLITE_ROW) { text_col(s, 0, mac, 18); found = mac[0] != '\0'; }
        sqlite3_finalize(s);
        c->pred_ok = 0;
        c->detail_ok = 0;
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) return -1;
    }
    if (!found && ip && ip[0]) {
        memset(&b, 0, sizeof(b));
        add(&b, "SELECT mac FROM devices WHERE ip = ");
        bind_s(&b, ip);
        add(&b, " ORDER BY last_seen DESC LIMIT 1");
        sqlite3_stmt *s = prepare(c, &b);
        if (!s) { c->pred_ok = 0; c->detail_ok = 0; return -1; }
        rc = sqlite3_step(s);
        if (rc == SQLITE_ROW) { text_col(s, 0, mac, 18); found = mac[0] != '\0'; }
        sqlite3_finalize(s);
        c->pred_ok = 0;
        c->detail_ok = 0;
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) return -1;
    }
    return found;
}

#endif /* WITH_SQLITE */
