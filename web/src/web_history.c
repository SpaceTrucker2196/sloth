#include "web_history.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_series.h"

int web_hist_test_expire = 0;

/* The overview cache holds a whole answer. */
typedef char web_hist_ovc_fits[(WEB_HIST_COLS_MAX <= WEB_SDB_OVC_CELLS &&
                                WEB_HIST_SESSIONS <= WEB_SDB_OVC_SESSIONS)
                               ? 1 : -1];

int web_hist_error(int status, const char *reason, const char *detail,
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

static void jw_text_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 11) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

int web_hist_range(const char *from_s, const char *to_s, long long now_s,
                   long long *from, long long *to, const char **why) {
    *to = now_s;
    if (to_s && web_param_secs(to_s, to) != 0) { *why = "bad_to"; return -1; }
    *from = *to > WEB_HIST_DEFAULT_S ? *to - WEB_HIST_DEFAULT_S : 0;
    if (from_s && web_param_secs(from_s, from) != 0) { *why = "bad_from"; return -1; }
    if (*to > now_s + 86400) { *why = "to_in_future"; return -1; }
    if (*from >= *to) { *why = "empty_range"; return -1; }
    if (*to - *from > WEB_HIST_SPAN_MAX) { *why = "range_too_long"; return -1; }
    return 0;
}

int web_hist_no_db(char *body, size_t cap, size_t *len, int *status) {
    return web_hist_error(503, "no_sloth_db",
                        "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                        body, cap, len, status);
}

int web_hist_configured(const web_m4_t *m) {
    return m && m->sdb && m->sdb->configured && web_slothdb_available();
}

/* Open sloth.db with budget_ms, or answer why not: 0 open, 1 answered,
 * -1. */
static int hist_open_budget(const web_m4_t *m, web_sdb_conn_t *c, int budget_ms,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status) {
    char err[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, c, budget_ms, now_s, err, sizeof(err)) == 0)
        return 0;
    web_slothdb_close(c);
    web_sdb_stats_t st;
    web_slothdb_stats(m->sdb, &st);
    char r[48];
    snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
    return web_hist_error(503, r, err, body, cap, len, status) == 0 ? 1 : -1;
}

int web_hist_open(const web_m4_t *m, web_sdb_conn_t *c, long long now_s,
                  char *body, size_t cap, size_t *len, int *status) {
    return hist_open_budget(m, c, WEB_SDB_HTTP_MS, now_s, body, cap, len, status);
}

int web_hist_read_failed(web_sdb_conn_t *c, char *body, size_t cap, size_t *len,
                       int *status) {
    int to = c->timed_out;
    web_slothdb_close(c);
    return web_hist_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                        body, cap, len, status);
}

static void session_json(web_jw_t *w, const web_sdb_session_t *s) {
    web_jw_raw(w, "{\"id\":");       web_jw_int(w, s->id);
    web_jw_raw(w, ",\"started\":");  web_jw_int(w, s->started);
    web_jw_raw(w, ",\"ended\":");
    if (s->ended >= 0) web_jw_int(w, s->ended); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"label\":");    jw_text_or_null(w, s->label);
    web_jw_raw(w, "}");
}
#define SESSION_JSON_MAX (64 + WEB_SDB_TEXT_MAX * WEB_JW_EXPAND + 80)

/* ── /api/history/overview ───────────────────────────────────────────── */

/* The overview's 503 says which read failed and how far it got, so
 * "too slow" names the table and the rows it had counted when the
 * budget ran out: {"error", "detail", "query", "rows_read" (null when
 * not counting rows), "budget_ms"}. Closes c. */
static int overview_failed(web_sdb_conn_t *c, char *body, size_t cap,
                           size_t *len, int *status) {
    int to = c->timed_out;
    const char *what = c->what ? c->what : "open";
    long long rows = c->rows_read;
    web_slothdb_close(c);
    char detail[160];
    if (rows >= 0)
        snprintf(detail, sizeof(detail), "%s %s after %lld rows", what,
                 to ? "ran past the budget" : "failed", rows);
    else
        snprintf(detail, sizeof(detail), "%s %s", what,
                 to ? "ran past the budget" : "failed");
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, to ? "sloth_db_timeout" : "sloth_db_error");
    web_jw_raw(&w, ",\"detail\":");     web_jw_str(&w, detail);
    web_jw_raw(&w, ",\"query\":");      web_jw_str(&w, what);
    web_jw_raw(&w, ",\"rows_read\":");
    if (rows >= 0) web_jw_int(&w, rows); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"budget_ms\":");  web_jw_int(&w, WEB_SDB_OVERVIEW_MS);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 503;
    return 0;
}

int web_history_overview_route(const web_m4_t *m, const char *query,
                               long long now_s, char *body, size_t cap,
                               size_t *len, int *status) {
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);
    web_param_t ps[3] = { { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    long long from, to, cols = WEB_HIST_COLS;
    const char *why;
    if (web_hist_range(ps[0].seen ? ps[0].val : NULL, ps[1].seen ? ps[1].val : NULL,
                       now_s, &from, &to, &why) != 0)
        return web_hist_error(400, why, NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_HIST_COLS_MAX, &cols) != 0)
        return web_hist_error(400, "bad_cols", NULL, body, cap, len, status);
    long long span = to - from;
    long long cell = (span + cols - 1) / cols;
    if (cell < 60) cell = 60;
    int ncell = (int)((span + cell - 1) / cell);
    web_sdb_ovw_t *v = calloc(1, sizeof(*v));
    if (!v || ncell > WEB_SDB_OVC_CELLS) { free(v); return -1; }
    web_sdb_ident_t id;
    int cacheable = web_sdb_ovc_ident(m->sdb, &id) == 0;
    if (!cacheable || !web_sdb_ovc_get(m->sdb, &id, from, (int)cell, ncell, v)) {
        web_sdb_conn_t c;
        int o = hist_open_budget(m, &c, WEB_SDB_OVERVIEW_MS, now_s, body, cap,
                                 len, status);
        if (o) { free(v); return o > 0 ? 0 : -1; }
        if (web_hist_test_expire) c.deadline_ms = 0;
        int ns = -1;
        int ok = web_sdb_overview(&c, from, (int)cell, ncell, v->devs,
                                  v->alerts) == 0;
        if (ok) {
            c.what = "sessions";
            c.rows_read = -1;
            ok = (ns = web_sdb_sessions(&c, v->ss, WEB_HIST_SESSIONS)) >= 0;
        }
        if (!ok) {
            free(v);
            return overview_failed(&c, body, cap, len, status);
        }
        web_slothdb_close(&c);
        v->from = from;
        v->to = to;
        v->cell_s = (int)cell;
        v->ncell = ncell;
        v->ns = ns;
        if (cacheable) web_sdb_ovc_put(m->sdb, &id, v);
    }
    /* A cached answer is the one counted for a from in the same cell,
     * at most a minute ago: from and to say which. */
    from = v->from;
    to = v->to;
    long long *devs = v->devs, *al = v->alerts;
    web_sdb_session_t *ss = v->ss;
    int ns = v->ns;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"from\":");    web_jw_int(&w, from);
    web_jw_raw(&w, ",\"to\":");      web_jw_int(&w, to);
    web_jw_raw(&w, ",\"cols\":");    web_jw_int(&w, ncell);
    web_jw_raw(&w, ",\"cell_s\":");  web_jw_int(&w, cell);
    web_jw_raw(&w, ",\"devices\":[");
    for (int i = 0; i < ncell; i++) {
        if (i) web_jw_raw(&w, ",");
        web_jw_int(&w, devs[i]);
    }
    web_jw_raw(&w, "],\"alerts\":[");
    for (int i = 0; i < ncell; i++) {
        if (i) web_jw_raw(&w, ",");
        web_jw_int(&w, al[i]);
    }
    web_jw_raw(&w, "],\"sessions\":[");
    int shown = 0, overlapping = 0;
    for (int i = 0; i < ns; i++) {
        long long end = ss[i].ended >= 0 ? ss[i].ended : now_s;
        if (end < from || ss[i].started > to) continue;
        overlapping++;
        if (w.len + SESSION_JSON_MAX + 64 > cap) continue;
        if (shown++) web_jw_raw(&w, ",");
        session_json(&w, &ss[i]);
    }
    web_jw_raw(&w, "],\"sessions_more\":");
    web_jw_raw(&w, shown < overlapping || ns == WEB_HIST_SESSIONS ? "true" : "false");
    web_jw_raw(&w, "}\n");
    free(v);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/history/alerts and /api/history/flows ─────────────────────── */

typedef struct {
    web_jw_t *w;
    size_t    cap;
    int       n, max, kind, cut;
} hl_t;

#define ITEM_JSON_MAX (2 * WEB_SDB_TEXT_MAX * WEB_JW_EXPAND + 200)

static int emit_alert(void *ctx, const web_sdb_item_t *it) {
    hl_t *h = ctx;
    if (h->n >= h->max) { h->cut = 1; return 1; }
    if (h->w->len + ITEM_JSON_MAX + 96 > h->cap) { h->cut = 1; return 1; }
    web_jw_t *w = h->w;
    web_jw_raw(w, h->n++ ? ",{\"title\":" : "{\"title\":");
    jw_text_or_null(w, it->a);
    web_jw_raw(w, ",\"ip\":");     jw_text_or_null(w, it->b);
    web_jw_raw(w, ",\"type\":");   web_jw_int(w, it->n1 & 0xffff);
    web_jw_raw(w, ",\"sev\":");    web_jw_int(w, it->n2 < 0 ? 0 : it->n2 > 2 ? 2 : it->n2);
    web_jw_raw(w, ",\"count\":");  web_jw_int(w, it->has_n3 && it->n3 > 0 ? it->n3 : 0);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, it->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, it->last_seen);
    web_jw_raw(w, "}");
    return 0;
}

static int emit_flow(void *ctx, const web_sdb_item_t *it) {
    static const char *const P[WEB_FLOW_KINDS] = { "ssh", "rdp", "smb", "snmp" };
    hl_t *h = ctx;
    if (h->n >= h->max) { h->cut = 1; return 1; }
    if (h->w->len + ITEM_JSON_MAX + 96 > h->cap) { h->cut = 1; return 1; }
    web_jw_t *w = h->w;
    int k = it->n1 >= 0 && it->n1 < WEB_FLOW_KINDS ? (int)it->n1 : 0;
    web_jw_raw(w, h->n++ ? ",{\"proto\":" : "{\"proto\":");
    web_jw_str(w, P[k]);
    web_jw_raw(w, ",\"src\":");    jw_text_or_null(w, it->a);
    web_jw_raw(w, ",\"dst\":");    jw_text_or_null(w, it->b);
    web_jw_raw(w, ",\"count\":");  web_jw_int(w, it->n2 > 0 ? it->n2 : 0);
    web_jw_raw(w, k == WEB_FLOW_SNMP ? ",\"version\":" : ",\"port\":");
    if (it->has_n3) web_jw_int(w, it->n3 & 0xffff); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, it->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, it->last_seen);
    web_jw_raw(w, "}");
    return 0;
}

static int list_route(const web_m4_t *m, const char *query, long long now_s,
                      int flows, char *body, size_t cap, size_t *len,
                      int *status) {
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);
    web_param_t ps[3] = { { "from", "", 0 }, { "to", "", 0 }, { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    long long from, to, limit = WEB_HIST_LIMIT;
    const char *why;
    if (web_hist_range(ps[0].seen ? ps[0].val : NULL, ps[1].seen ? ps[1].val : NULL,
                       now_s, &from, &to, &why) != 0)
        return web_hist_error(400, why, NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_HIST_LIMIT_MAX, &limit) != 0)
        return web_hist_error(400, "bad_limit", NULL, body, cap, len, status);
    web_sdb_conn_t c;
    int o = web_hist_open(m, &c, now_s, body, cap, len, status);
    if (o) return o > 0 ? 0 : -1;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"from\":");   web_jw_int(&w, from);
    web_jw_raw(&w, ",\"to\":");     web_jw_int(&w, to);
    web_jw_raw(&w, ",\"limit\":");  web_jw_int(&w, limit);
    web_jw_raw(&w, flows ? ",\"flows\":[" : ",\"alerts\":[");
    hl_t h = { &w, cap, 0, (int)limit, 0, 0 };
    int got = flows
        ? web_sdb_flows_between(&c, from, to, (int)limit + 1, emit_flow, &h)
        : web_sdb_alerts_between(&c, from, to, (int)limit + 1, emit_alert, &h);
    if (got < 0) return web_hist_read_failed(&c, body, cap, len, status);
    web_slothdb_close(&c);
    web_jw_raw(&w, "],\"count\":");  web_jw_int(&w, h.n);
    web_jw_raw(&w, ",\"more\":");    web_jw_raw(&w, h.cut ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

int web_history_alerts_route(const web_m4_t *m, const char *query,
                             long long now_s, char *body, size_t cap,
                             size_t *len, int *status) {
    return list_route(m, query, now_s, 0, body, cap, len, status);
}

int web_history_flows_route(const web_m4_t *m, const char *query,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status) {
    return list_route(m, query, now_s, 1, body, cap, len, status);
}

/* ── /api/sessions and /api/sessions/new ────────────────────────────── */

int web_sessions_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status) {
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);
    if (query && query[0])
        return web_hist_error(400, "unknown_parameter", NULL, body, cap, len, status);
    web_sdb_session_t *ss = calloc(WEB_HIST_SESSIONS + 1, sizeof(*ss));
    if (!ss) return -1;
    web_sdb_conn_t c;
    int o = web_hist_open(m, &c, now_s, body, cap, len, status);
    if (o) { free(ss); return o > 0 ? 0 : -1; }
    int ns = web_sdb_sessions(&c, ss, WEB_HIST_SESSIONS + 1);
    if (ns < 0) { free(ss); return web_hist_read_failed(&c, body, cap, len, status); }
    web_slothdb_close(&c);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");  web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"sessions\":[");
    int shown = 0;
    for (int i = 0; i < ns && i < WEB_HIST_SESSIONS; i++) {
        if (w.len + SESSION_JSON_MAX + 64 > cap) break;
        if (shown++) web_jw_raw(&w, ",");
        session_json(&w, &ss[i]);
    }
    web_jw_raw(&w, "],\"count\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");   web_jw_raw(&w, shown < ns ? "true" : "false");
    web_jw_raw(&w, "}\n");
    free(ss);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

typedef struct {
    web_jw_t *w;
    size_t    cap;
    int       n, max, cut;
} nl_t;

static int emit_new(void *ctx, const web_sdb_item_t *it) {
    nl_t *l = ctx;
    if (l->n >= l->max) return 1;
    if (l->w->len + ITEM_JSON_MAX + 400 > l->cap) { l->cut = 1; return 1; }
    web_jw_t *w = l->w;
    web_jw_raw(w, l->n++ ? ",{\"ident\":" : "{\"ident\":");
    web_jw_str(w, it->a);
    web_jw_raw(w, ",\"label\":");  jw_text_or_null(w, it->b);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, it->first_seen);
    web_jw_raw(w, "}");
    return 0;
}

int web_sessions_new_route(const web_m4_t *m, const char *query,
                           long long now_s, char *body, size_t cap,
                           size_t *len, int *status) {
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);
    web_param_t ps[1] = { { "id", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    long long id;
    if (!ps[0].seen) return web_hist_error(400, "missing_id", NULL, body, cap, len, status);
    if (decimal(ps[0].val, 1, 99999999999LL, &id) != 0)
        return web_hist_error(400, "bad_id", NULL, body, cap, len, status);
    web_sdb_conn_t c;
    int o = web_hist_open(m, &c, now_s, body, cap, len, status);
    if (o) return o > 0 ? 0 : -1;
    web_sdb_session_t s, prev;
    int has_prev = 0;
    long long next_started = -1;
    int f = web_sdb_session_pair(&c, id, &s, &prev, &has_prev, &next_started);
    if (f < 0) return web_hist_read_failed(&c, body, cap, len, status);
    if (f == 0) {
        web_slothdb_close(&c);
        return web_hist_error(404, "no_such_session", NULL, body, cap, len, status);
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"session\":");
    session_json(&w, &s);
    web_jw_raw(&w, ",\"previous\":");
    if (has_prev) session_json(&w, &prev); else web_jw_raw(&w, "null");
    /* db_session_begin(): the previous visit's end, or its start when
     * it never recorded one. */
    long long since = has_prev ? (prev.ended >= 0 ? prev.ended : prev.started) : -1;
    /* The visit's own end: what --report said when it closed. */
    long long until = s.ended >= 0 ? s.ended : next_started;
    web_jw_raw(&w, ",\"since\":");
    if (has_prev) web_jw_int(&w, since); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"until\":");
    if (has_prev && until >= 0) web_jw_int(&w, until); else web_jw_raw(&w, "null");
    /* --report's own order and headings. */
    static const struct { int kind; const char *name; } K[] = {
        { WEB_NEW_AP, "aps" }, { WEB_NEW_DEVICE, "devices" },
        { WEB_NEW_PROBE, "probe_clients" },
    };
    for (size_t k = 0; k < sizeof(K) / sizeof(K[0]); k++) {
        web_jw_raw(&w, ",");
        web_jw_key(&w, K[k].name);
        if (!has_prev) { web_jw_raw(&w, "null"); continue; }
        web_jw_raw(&w, "{\"rows\":[");
        nl_t l = { &w, cap, 0, WEB_HIST_NEW, 0 };
        long long total = 0;
        int got = web_sdb_new_since(&c, K[k].kind, since, until, WEB_HIST_NEW,
                                    emit_new, &l, &total);
        if (got < 0) return web_hist_read_failed(&c, body, cap, len, status);
        web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, total);
        web_jw_raw(&w, ",\"listed\":"); web_jw_int(&w, l.n);
        web_jw_raw(&w, "}");
    }
    web_slothdb_close(&c);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
