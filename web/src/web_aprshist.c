#include "web_aprshist.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_aprs.h"
#include "web_json.h"
#include "web_series.h"
#include "web_slothdb.h"

#define DAY_S 86400LL

static int answer_error(int status, const char *reason, const char *detail,
                        char *body, size_t cap, size_t *len, int *st) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, reason);
    if (detail) {
        web_jw_raw(&w, ",\"detail\":");
        web_jw_strn(&w, detail, strnlen(detail, 240));
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *st = status;
    return 0;
}

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    if (!s || !*s || strlen(s) > 12) return -1;
    long long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

static void jw_num(web_jw_t *w, int has, double v, int dp) {
    char t[40];
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static void jw_int_or_null(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

static int open_sdb(const web_m4_t *m, web_sdb_conn_t *conn, long long now_s,
                    char *body, size_t cap, size_t *len, int *status) {
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, conn, WEB_SDB_HTTP_MS, now_s, oerr, sizeof(oerr)) != 0) {
        web_slothdb_close(conn);
        web_sdb_stats_t st;
        web_slothdb_stats(m->sdb, &st);
        char r[48];
        snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
        answer_error(503, r, oerr, body, cap, len, status);
        return -1;
    }
    return 0;
}

static int no_db(const web_m4_t *m, char *body, size_t cap, size_t *len, int *status) {
    if (m && m->sdb && m->sdb->configured && web_slothdb_available()) return 0;
    answer_error(503, "no_sloth_db",
                 "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                 body, cap, len, status);
    return 1;
}

/* ── /api/aprs/seen ─────────────────────────────────────────────────── */

static void stn_json(web_jw_t *w, const web_sdb_aprs_stn_t *a, size_t cm_max) {
    web_jw_raw(w, "{\"call\":"); web_jw_str(w, a->call);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, a->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, a->last_seen);
    web_jw_raw(w, ",\"visits\":"); web_jw_int(w, a->visits);
    web_jw_raw(w, ",\"packets\":"); web_jw_int(w, a->packets);
    web_jw_raw(w, ",\"via\":"); web_jw_str(w, a->via);
    web_jw_raw(w, ",\"heard_direct\":"); web_jw_int(w, a->heard_direct != 0);
    web_jw_raw(w, ",\"best_level\":"); jw_int_or_null(w, a->has_level, a->best_level);
    web_jw_raw(w, ",\"dti\":"); web_jw_str(w, a->dti);
    web_jw_raw(w, ",\"symbol\":"); web_jw_str(w, a->symbol);
    web_jw_raw(w, ",\"lat\":"); jw_num(w, a->has_pos, a->lat, 5);
    web_jw_raw(w, ",\"lon\":"); jw_num(w, a->has_pos, a->lon, 5);
    web_jw_raw(w, ",\"pos_ts\":"); jw_int_or_null(w, a->has_pos && a->pos_ts, a->pos_ts);
    web_jw_raw(w, ",\"comment\":"); web_jw_strn(w, a->comment, strnlen(a->comment, cm_max));
    if (cm_max >= sizeof(a->comment)) {
        web_jw_raw(w, ",\"status\":"); web_jw_str(w, a->status);
        web_jw_raw(w, ",\"system\":"); web_jw_str(w, a->system);
    }
    web_jw_raw(w, "}");
}

typedef struct { web_jw_t *w; size_t cap; int n, limit, more; } stn_ctx_t;

static int emit_stn(void *ctx, const web_sdb_aprs_stn_t *a) {
    stn_ctx_t *k = ctx;
    /* Row limit reached, or the buffer could not take a worst-case row:
     * stop, and the page continues from offset + n. */
    if (k->n >= k->limit ||
        k->w->len + WEB_APRSHIST_ROW_WORST + WEB_APRSHIST_TAIL > k->cap) {
        k->more = 1;
        return 1;
    }
    if (k->n++) web_jw_raw(k->w, ",");
    stn_json(k->w, a, WEB_APRSHIST_SEEN_CM);
    return 0;
}

/* q: a callsign prefix, upper-cased; [0-9A-Za-z-] only, never a LIKE
 * wildcard, refused rather than stripped. */
static int q_take(const char *q, char *out, size_t outsz) {
    size_t l = strlen(q);
    if (l > WEB_APRSHIST_Q_MAX || l >= outsz) return -1;
    for (size_t i = 0; i < l; i++) {
        char ch = q[i];
        if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 'a' + 'A');
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || ch == '-'))
            return -1;
        out[i] = ch;
    }
    out[l] = '\0';
    return 0;
}

int web_aprs_seen_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[4] = { { "days", "", 0 }, { "limit", "", 0 }, { "q", "", 0 },
                          { "offset", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days = 7, limit = WEB_APRSHIST_SEEN_MAX, offset = 0;
    if (ps[3].seen && decimal(ps[3].val, 0, WEB_APRSHIST_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_APRSHIST_DAYS_MAX, &days) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_APRSHIST_SEEN_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    char q[WEB_APRSHIST_Q_MAX + 1];
    if (q_take(ps[2].seen ? ps[2].val : "", q, sizeof(q)) != 0)
        return answer_error(400, "bad_q", NULL, body, cap, len, status);
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) return 0;
    long long from = now_s - days * DAY_S;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    web_jw_raw(&w, ",\"from\":"); web_jw_int(&w, from);
    web_jw_raw(&w, ",\"offset\":"); web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"q\":"); web_jw_str(&w, q);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 13 ? "true" : "false");
    web_jw_raw(&w, ",\"stations\":[");
    stn_ctx_t k = { &w, cap, 0, (int)limit, 0 };
    int n = web_sdb_aprs_seen(&conn, from, limit + 1, offset, q, emit_stn, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n);
    web_jw_raw(&w, ",\"more\":"); web_jw_raw(&w, k.more ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/aprs/station ──────────────────────────────────────────────── */

/* A compact row, its names in the answer's "cols". */
static void pkt_json(web_jw_t *w, const web_sdb_aprs_pkt_t *p) {
    web_jw_raw(w, "["); web_jw_int(w, p->ts);
    web_jw_raw(w, ","); web_jw_str(w, p->heard);
    web_jw_raw(w, ","); web_jw_str(w, p->dti);
    web_jw_raw(w, ","); web_jw_str(w, p->name);
    web_jw_raw(w, ","); web_jw_str(w, p->symbol);
    web_jw_raw(w, ","); jw_num(w, p->has_pos, p->lat, 5);
    web_jw_raw(w, ","); jw_num(w, p->has_pos, p->lon, 5);
    web_jw_raw(w, ","); jw_num(w, p->has_speed, p->speed_kt, 1);
    web_jw_raw(w, ","); jw_num(w, p->has_course, p->course, 0);
    web_jw_raw(w, ","); jw_num(w, p->has_alt, p->alt_m, 0);
    web_jw_raw(w, ","); jw_int_or_null(w, p->has_level, p->level);
    web_jw_raw(w, ","); web_jw_str(w, p->status);
    web_jw_raw(w, ","); web_jw_str(w, p->comment);
    web_jw_raw(w, "]");
}

typedef struct { web_sdb_aprs_pkt_t *p; int n, max; } pkt_ctx_t;

static int keep_pkt(void *ctx, const web_sdb_aprs_pkt_t *p) {
    pkt_ctx_t *k = ctx;
    if (k->n >= k->max) return 1;
    k->p[k->n++] = *p;
    return 0;
}

/* The bytes one row costs, measured by writing it. */
static size_t pkt_size(const web_sdb_aprs_pkt_t *p) {
    char tmp[2048];
    web_jw_t w;
    web_jw_init(&w, tmp, sizeof(tmp));
    pkt_json(&w, p);
    return w.overflow ? sizeof(tmp) : w.len + 1;
}

int web_aprs_station_route(const web_m4_t *m, const char *query, long long now_s,
                           char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[2] = { { "call", "", 0 }, { "days", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long days = 7;
    if (!ps[0].seen || !web_aprs_call_ok(ps[0].val))
        return answer_error(400, "bad_call", NULL, body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_APRSHIST_DAYS_MAX, &days) != 0)
        return answer_error(400, "bad_days", NULL, body, cap, len, status);
    if (no_db(m, body, cap, len, status)) return 0;
    WEB_M4_CHECKED(m, len, status);
    web_sdb_aprs_pkt_t *pk = malloc(WEB_APRSHIST_PKTS_MAX * sizeof(*pk));
    if (!pk) return -1;
    web_sdb_conn_t conn;
    if (open_sdb(m, &conn, now_s, body, cap, len, status) != 0) { free(pk); return 0; }
    long long from = now_s - days * DAY_S;
    web_sdb_aprs_stn_t a;
    int found = web_sdb_aprs_one(&conn, ps[0].val, &a);
    pkt_ctx_t k = { pk, 0, WEB_APRSHIST_PKTS_MAX };
    int n = found < 0 ? -1
          : web_sdb_aprs_packets(&conn, ps[0].val, from, WEB_APRSHIST_PKTS_MAX, keep_pkt, &k);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (n < 0) {
        free(pk);
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"days\":"); web_jw_int(&w, days);
    web_jw_raw(&w, ",\"call\":"); web_jw_str(&w, ps[0].val);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, conn.schema >= 13 ? "true" : "false");
    web_jw_raw(&w, ",\"station\":");
    if (found > 0) stn_json(&w, &a, sizeof(a.comment)); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"cols\":[\"ts\",\"heard\",\"dti\",\"name\",\"symbol\",\"lat\","
                   "\"lon\",\"speed_kt\",\"course\",\"alt_m\",\"level\",\"status\","
                   "\"comment\"],\"packets\":[");
    /* The newest that fit, measured from the end back; the oldest of
     * the window are what a budget leaves out. */
    size_t room = cap > w.len + WEB_APRSHIST_TAIL ? cap - w.len - WEB_APRSHIST_TAIL : 0;
    int start = k.n;
    size_t used = 0;
    while (start > 0) {
        size_t sz = pkt_size(&pk[start - 1]);
        if (used + sz > room) break;
        used += sz;
        start--;
    }
    for (int i = start; i < k.n; i++) {
        if (i > start) web_jw_raw(&w, ",");
        pkt_json(&w, &pk[i]);
    }
    free(pk);
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, k.n - start);
    web_jw_raw(&w, ",\"cut\":"); web_jw_raw(&w, start > 0 ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
