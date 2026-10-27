#include "web_alerts.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertdb.h"
#include "web_alertfmt.h"
#include "web_alertkb.h"
#include "web_history.h"
#include "web_json.h"
#include "web_series.h"
#include "web_ssid.h"

#define INC_MAX (WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED)
/* The most one list row renders to: every text member at its cut
 * length, each byte escaped six-fold, and the fixed members. */
#define ROW_JSON_MAX (2 * WEB_SDB_TEXT_MAX * WEB_JW_EXPAND + 64 * WEB_JW_EXPAND + 400)

static const char *const SEV_WORD[] = { "low", "warn", "crit" };

static int sev_clamp(int s) { return s < 0 ? 0 : s > 2 ? 2 : s; }

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 19) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        if (v > (hi - (s[i] - '0')) / 10) return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* ASCII case-insensitive substring. */
static int has_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    if (!n) return 1;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] &&
               tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == n) return 1;
    }
    return 0;
}

static void jw_str_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

/* The technique a record carries, else the one sloth_alerts.def gives
 * its type (sloth.db rows from before the column was filled have none). */
static const char *tech_of(const char *t, int type) {
    const web_akb_t *k = web_akb_get(type);
    return t && t[0] ? t : k ? k->technique : NULL;
}

static void jw_type(web_jw_t *w, int type) {
    const web_akb_t *k = web_akb_get(type);
    web_jw_raw(w, ",\"type\":");
    if (type >= 0) web_jw_int(w, type); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"type_name\":");
    jw_str_or_null(w, k ? k->name : NULL);
}

/* ── /api/alerts ─────────────────────────────────────────────────────── */

enum { ST_ALL = 0, ST_OPEN, ST_CLOSED };

typedef struct {
    int       state;
    unsigned  sev_mask;
    int       type;                  /* -1 any */
    char      q[WEB_PARAM_MAX + 1];
    long long window, limit, offset;
} aq_t;

static int parse_list(const char *query, aq_t *a, char *err, size_t errsz) {
    web_param_t ps[7] = {
        { "state", "", 0 }, { "sev", "", 0 }, { "type", "", 0 }, { "q", "", 0 },
        { "window", "", 0 }, { "limit", "", 0 }, { "offset", "", 0 },
    };
    if (web_params_parse(query, ps, 7, err, errsz) != 0) return -1;
    memset(a, 0, sizeof(*a));
    a->type = -1;
    a->window = WEB_ALERTS_WINDOW_S;
    a->limit = WEB_ALERTS_LIMIT;
    if (ps[0].seen) {
        if (!strcmp(ps[0].val, "open")) a->state = ST_OPEN;
        else if (!strcmp(ps[0].val, "closed")) a->state = ST_CLOSED;
        else if (!strcmp(ps[0].val, "all")) a->state = ST_ALL;
        else { snprintf(err, errsz, "bad_state"); return -1; }
    }
    if (ps[1].seen) {
        /* A comma list of words or digits, each at most once. */
        char *p = ps[1].val;
        while (*p) {
            char *e = strchr(p, ',');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            int s = -1;
            for (int k = 0; k < 3; k++)
                if (n == strlen(SEV_WORD[k]) && !strncmp(p, SEV_WORD[k], n)) s = k;
            if (n == 1 && p[0] >= '0' && p[0] <= '2') s = p[0] - '0';
            if (s < 0 || (a->sev_mask & (1u << s))) { snprintf(err, errsz, "bad_sev"); return -1; }
            a->sev_mask |= 1u << s;
            if (!e) break;
            p = e + 1;
            if (!*p) { snprintf(err, errsz, "bad_sev"); return -1; }
        }
        if (!a->sev_mask) { snprintf(err, errsz, "bad_sev"); return -1; }
    }
    if (ps[2].seen) {
        long long t;
        if (decimal(ps[2].val, 0, web_akb_n - 1, &t) == 0) a->type = (int)t;
        else if ((a->type = web_akb_find(ps[2].val)) < 0) {
            snprintf(err, errsz, "bad_type");
            return -1;
        }
    }
    if (ps[3].seen) {
        for (const char *p = ps[3].val; *p; p++)
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e) {
                snprintf(err, errsz, "bad_q");
                return -1;
            }
        snprintf(a->q, sizeof(a->q), "%s", ps[3].val);
    }
    if (ps[4].seen && decimal(ps[4].val, 60, WEB_ALERTS_WINDOW_MAX, &a->window) != 0) {
        snprintf(err, errsz, "bad_window");
        return -1;
    }
    if (ps[5].seen && decimal(ps[5].val, 1, WEB_ALERTS_LIMIT_MAX, &a->limit) != 0) {
        snprintf(err, errsz, "bad_limit");
        return -1;
    }
    if (ps[6].seen && decimal(ps[6].val, 0, WEB_ALERTS_OFFSET_MAX, &a->offset) != 0) {
        snprintf(err, errsz, "bad_offset");
        return -1;
    }
    return 0;
}

/* Does a stream incident pass the filters? */
static int inc_match(const aq_t *a, const web_live_inc_t *e, long long since) {
    if (a->sev_mask && !(a->sev_mask & (1u << sev_clamp(e->sev)))) return 0;
    if (a->type >= 0 && e->type != a->type) return 0;
    if (e->closed_ts >= 0 && e->last_ts < since) return 0;
    if (a->q[0]) {
        const web_akb_t *k = web_akb_get(e->type);
        if (!has_ci(e->title, a->q) && !has_ci(e->match_ip, a->q) &&
            !(k && has_ci(k->name, a->q)))
            return 0;
    }
    return 1;
}

/* One list row, from either source. A stream row is one alert key:
 * inc the incident shown (the key's open one, else its newest closed),
 * and sn, s_count and s_first over every incident of the key the stream
 * holds. */
typedef struct {
    int       stream;                /* 1: inc, 0: group */
    const web_live_inc_t *inc;
    int       sn;
    long long s_count, s_first;
    web_adb_group_t g;
    web_adb_totals_t t;              /* sloth.db's totals of the key */
    int       have_t;
    long long last;
} row_t;

static int by_open(const void *x, const void *y) {
    const row_t *a = x, *b = y;
    if (a->inc->sev != b->inc->sev) return b->inc->sev - a->inc->sev;
    return a->inc->seq < b->inc->seq ? 1 : a->inc->seq > b->inc->seq ? -1 : 0;
}

static int by_last(const void *x, const void *y) {
    const row_t *a = x, *b = y;
    return a->last < b->last ? 1 : a->last > b->last ? -1 : 0;
}

typedef struct {
    row_t    *rows;
    int       n, cap;
} gl_t;

static int take_group(void *ctx, const web_adb_group_t *g) {
    gl_t *l = ctx;
    if (l->n >= l->cap) return 1;
    row_t *r = &l->rows[l->n++];
    memset(r, 0, sizeof(*r));
    r->g = *g;
    r->last = g->last_seen;
    return 0;
}

/* What a key amounts to, the same on the list and on the alert's page:
 * sloth.db's totals over every row of the key when it has any, else the
 * stream's. Each source can lag the other (sloth writes the file on its
 * own schedule; the stream holds only what this connection heard), so
 * the larger of the two stands for the incidents and the count. */
typedef struct {
    long long incidents, count, first_seen;
} sum_t;

static sum_t key_sum(const web_adb_totals_t *t, int have_t, int sn, long long s_count,
                     long long s_first, long long reopen) {
    sum_t o;
    o.incidents = sn > 0 ? sn : 1;
    if (sn > 0 && 1 + reopen > o.incidents) o.incidents = 1 + reopen;
    o.count = s_count;
    o.first_seen = s_first;
    if (have_t) {
        if (t->incidents > o.incidents) o.incidents = t->incidents;
        if (t->count > o.count) o.count = t->count;
        if (t->first_seen > 0 && (o.first_seen <= 0 || t->first_seen < o.first_seen))
            o.first_seen = t->first_seen;
    }
    return o;
}

static void row_json(web_jw_t *w, const row_t *r, int first) {
    web_jw_raw(w, first ? "{\"id\":" : ",{\"id\":");
    char id[48];
    sum_t k;
    if (r->stream) {
        const web_live_inc_t *e = r->inc;
        k = key_sum(&r->t, r->have_t, r->sn, r->s_count, r->s_first, e->reopen);
        snprintf(id, sizeof(id), "s%s", e->hid);
        web_jw_str(w, id);
        web_jw_raw(w, ",\"state\":");
        web_jw_str(w, e->closed_ts < 0 ? "open" : "closed");
        web_jw_raw(w, ",\"source\":");
        web_jw_str(w, r->have_t ? "both" : "stream");
        jw_type(w, e->type);
        web_jw_raw(w, ",\"title\":");      web_jw_str(w, e->title);
        web_jw_raw(w, ",\"sev\":");        web_jw_int(w, sev_clamp(e->sev));
        web_jw_raw(w, ",\"technique\":");  jw_str_or_null(w, tech_of(e->technique, e->type));
        web_jw_raw(w, ",\"ip\":");         jw_str_or_null(w, e->match_ip);
        web_jw_raw(w, ",\"port\":");
        if (e->match_ip[0]) web_jw_int(w, e->match_port); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, k.first_seen);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, e->last_ts);
    } else {
        const web_adb_group_t *g = &r->g;
        web_adb_totals_t t0;
        memset(&t0, 0, sizeof(t0));
        t0.incidents = g->rows;
        t0.count = g->count;
        t0.first_seen = g->first_seen;
        k = key_sum(r->have_t ? &r->t : &t0, 1, 0, 0, 0, 0);
        snprintf(id, sizeof(id), "d%lld", g->rid);
        web_jw_str(w, id);
        web_jw_raw(w, ",\"state\":\"recorded\",\"source\":\"sloth.db\"");
        jw_type(w, g->type);
        /* sloth.db's title as sloth wrote it, an SSID in it as it came:
         * the display form (web_ssid.h). The stream's is kept in it. */
        web_jw_raw(w, ",\"title\":");      web_jw_text(w, g->title);
        web_jw_raw(w, ",\"sev\":");        web_jw_int(w, sev_clamp(g->sev));
        web_jw_raw(w, ",\"technique\":");  jw_str_or_null(w, tech_of(g->technique, g->type));
        web_jw_raw(w, ",\"ip\":");         jw_str_or_null(w, g->ip);
        web_jw_raw(w, ",\"port\":");
        if (g->ip[0] && g->port >= 0) web_jw_int(w, g->port); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, k.first_seen);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, g->last_seen);
    }
    /* The key's, all time: the alert's page shows the same two. */
    web_jw_raw(w, ",\"count\":");      web_jw_int(w, k.count);
    web_jw_raw(w, ",\"incidents\":");  web_jw_int(w, k.incidents);
    web_jw_raw(w, ",\"reason\":");
    jw_str_or_null(w, r->stream ? r->inc->reason : NULL);
    web_jw_raw(w, "}");
}

/* Does the stream state filter keep e? */
static int state_ok(const aq_t *a, const web_live_inc_t *e) {
    int is_open = e->closed_ts < 0;
    return !((a->state == ST_OPEN && !is_open) || (a->state == ST_CLOSED && is_open));
}

/* The row of the stream already standing for e's key, or -1. A keyless
 * incident stands alone. */
static int row_of_key(const row_t *rows, int n, const web_live_inc_t *e) {
    if (!e->key[0]) return -1;
    for (int i = 0; i < n; i++)
        if (rows[i].stream && !strcmp(rows[i].inc->key, e->key)) return i;
    return -1;
}

int web_alerts_route(const web_m4_t *m, web_live_t *live, const char *query,
                     long long now_s, char *body, size_t cap, size_t *len,
                     int *status) {
    aq_t a;
    char err[48];
    if (parse_list(query, &a, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    long long since = now_s - a.window;
    web_live_inc_t *inc = calloc(INC_MAX, sizeof(*inc));
    row_t *rows = calloc(INC_MAX + WEB_ALERTS_OFFSET_MAX + WEB_ALERTS_LIMIT_MAX + 1,
                         sizeof(*rows));
    if (!inc || !rows) { free(inc); free(rows); return -1; }
    int nopen = 0, ninc = live ? web_live_incidents(live, inc, INC_MAX, &nopen) : 0;

    /* The stream's, filtered, one row per key: inc[] holds the open
     * ones first, then the closed, each newest change first, so the
     * first incident of a key to pass is the one its row shows (its open
     * one if it has one). sloth holds one open incident per key; the
     * rest of the key's incidents are its row's history. */
    int nr = 0, open_rows = 0, stream_closed = 0;
    for (int i = 0; i < ninc; i++) {
        if (!inc_match(&a, &inc[i], since) || !state_ok(&a, &inc[i])) continue;
        if (row_of_key(rows, nr, &inc[i]) >= 0) continue;
        row_t *r = &rows[nr++];
        r->stream = 1;
        r->inc = &inc[i];
        r->last = inc[i].last_ts;
        if (inc[i].closed_ts < 0) open_rows++; else stream_closed++;
    }
    /* Each stream row over every incident of its key in the stream. */
    for (int i = 0; i < ninc; i++) {
        int k = row_of_key(rows, nr, &inc[i]);
        for (int j = 0; j < nr && k < 0; j++)      /* keyless: its own row */
            if (rows[j].inc == &inc[i]) k = j;
        if (k < 0) continue;
        row_t *r = &rows[k];
        r->sn++;
        r->s_count += inc[i].count;
        if (inc[i].first_ts > 0 && (r->s_first <= 0 || inc[i].first_ts < r->s_first))
            r->s_first = inc[i].first_ts;
    }
    /* Rows were taken open first, so the open rows lead; sort them. */
    qsort(rows, (size_t)open_rows, sizeof(*rows), by_open);

    /* sloth.db's, unless only the open ones were asked for. */
    const char *db = "none";
    web_adb_stats_t st;
    memset(&st, 0, sizeof(st));
    long long want = a.offset + a.limit + 1;
    int ngroups = 0, db_more = 0;
    web_sdb_conn_t c;
    int have_c = 0;
    if (web_hist_configured(m)) {
        /* sloth.db missing or refused: the stream's incidents stand
         * alone, and "db" says why sloth.db's are not there. */
        int o = web_hist_open(m, &c, now_s, body, cap, len, status);
        have_c = o == 0;
        db = o == 0 ? "open" : "unreadable";
        if (have_c && a.state != ST_OPEN) {
            web_adb_filter_t f;
            memset(&f, 0, sizeof(f));
            f.since = since;
            f.until = now_s + 86400;
            f.sev_mask = a.sev_mask;
            if (a.type >= 0) { f.types[0] = a.type; f.ntypes = 1; }
            snprintf(f.q, sizeof(f.q), "%s", a.q);
            for (int t = 0; a.q[0] && t < web_akb_n && f.nqtypes < WEB_ADB_TYPES; t++)
                if (has_ci(web_akb[t].name, a.q)) f.qtypes[f.nqtypes++] = t;
            /* Every stream key is the stream's row, never a second one. */
            for (int i = 0; i < ninc && f.nexclude < WEB_ADB_EXCLUDE; i++) {
                int dup = 0;
                for (int j = 0; j < f.nexclude && !dup; j++) dup = !strcmp(f.exclude[j], inc[i].key);
                if (inc[i].key[0] && !dup) f.exclude[f.nexclude++] = inc[i].key;
            }
            f.scan_cap = WEB_ADB_SCAN_CAP;
            gl_t gl = { rows + nr, 0, (int)want };
            ngroups = web_adb_groups(&c, &f, want, 0, take_group, &gl, &st);
            if (ngroups < 0) {
                free(inc); free(rows);
                return web_hist_read_failed(&c, body, cap, len, status);
            }
            db_more = ngroups >= want;
            if (db_more) ngroups = (int)want - 1;
        }
    } else if (m && m->sdb && m->sdb->configured) {
        db = "unbuilt";
    }
    /* The closed: the stream's and sloth.db's, newest first. */
    int nclosed = stream_closed + ngroups;
    qsort(rows + open_rows, (size_t)nclosed, sizeof(*rows), by_last);
    int total = open_rows + nclosed;
    int lo = (int)a.offset, hi = (int)(a.offset + a.limit);
    if (hi > total) hi = total;

    /* The page's rows only: each key's totals, by key or rowid. */
    for (int i = lo; have_c && i < hi; i++) {
        row_t *r = &rows[i];
        int got = r->stream
            ? (r->inc->key[0] ? web_adb_key_totals(&c, 0, r->inc->key, &r->t) : 0)
            : web_adb_key_totals(&c, r->g.rid, NULL, &r->t);
        if (got < 0) {
            free(inc); free(rows);
            return web_hist_read_failed(&c, body, cap, len, status);
        }
        r->have_t = got > 0;
    }
    if (have_c) web_slothdb_close(&c);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");      web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"since\":");    web_jw_int(&w, since);
    web_jw_raw(&w, ",\"db\":");       web_jw_str(&w, db);
    web_jw_raw(&w, ",\"stream\":");
    if (live) {
        web_live_sum_t s;
        web_live_summary(live, &s, 0);
        web_jw_str(&w, web_live_sock_word(s.sock_state));
    } else {
        web_jw_raw(&w, "\"none\"");
    }
    web_jw_raw(&w, ",\"open\":");     web_jw_int(&w, open_rows);
    web_jw_raw(&w, ",\"open_all\":"); web_jw_int(&w, nopen);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int i = lo; i < hi; i++) {
        if (w.len + ROW_JSON_MAX + 2048 > cap) break;
        row_json(&w, &rows[i], shown == 0);
        shown++;
    }
    long long next = a.offset + shown;
    int more = next < total || db_more;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"total\":");    web_jw_int(&w, total);
    web_jw_raw(&w, ",\"total_more\":"); web_jw_raw(&w, db_more || st.capped ? "true" : "false");
    web_jw_raw(&w, ",\"more\":");     web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_offset\":");
    if (more && next <= WEB_ALERTS_OFFSET_MAX) web_jw_int(&w, next); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"scan\":{\"rows\":"); web_jw_int(&w, st.scanned);
    web_jw_raw(&w, ",\"cap\":");      web_jw_int(&w, WEB_ADB_SCAN_CAP);
    web_jw_raw(&w, ",\"capped\":");   web_jw_raw(&w, st.capped ? "true" : "false");
    /* When capped, sloth.db's rows reach back to here and no further. */
    web_jw_raw(&w, ",\"oldest\":");
    if (st.capped) web_jw_int(&w, st.oldest); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"groups\":");   web_jw_int(&w, st.groups);
    web_jw_raw(&w, "},\"types\":[");
    /* The facets: sloth.db's groups per type (the type filter left out)
     * with the stream's keys of each added, a key once. */
    long long fn[WEB_ADB_TYPES + 1];
    int ft[WEB_ADB_TYPES + 1], nf = 0;
    for (int i = 0; i < st.ntypes; i++) { ft[nf] = st.facet_type[i]; fn[nf] = st.facet_n[i]; nf++; }
    aq_t b = a;
    b.type = -1;
    for (int i = 0; i < ninc; i++) {
        if (!inc_match(&b, &inc[i], since) || !state_ok(&a, &inc[i])) continue;
        int seen = 0;
        for (int j = 0; j < i && !seen && inc[i].key[0]; j++)
            seen = !strcmp(inc[j].key, inc[i].key) && inc_match(&b, &inc[j], since) &&
                   state_ok(&a, &inc[j]);
        if (seen) continue;
        int k = 0;
        while (k < nf && ft[k] != inc[i].type) k++;
        if (k == nf) {
            if (nf > WEB_ADB_TYPES) continue;
            ft[nf] = inc[i].type;
            fn[nf++] = 0;
        }
        fn[k]++;
    }
    for (int i = 0; i < nf; i++) {
        const web_akb_t *k = web_akb_get(ft[i]);
        web_jw_raw(&w, i ? ",{\"type\":" : "{\"type\":");
        web_jw_int(&w, ft[i]);
        web_jw_raw(&w, ",\"name\":");   jw_str_or_null(&w, k ? k->name : NULL);
        web_jw_raw(&w, ",\"n\":");      web_jw_int(&w, fn[i]);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "]}\n");
    free(inc);
    free(rows);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/alert ──────────────────────────────────────────────────────── */

typedef struct {
    web_adb_row_t *r;
    int            n, cap;
} il_t;

static int take_row(void *ctx, const web_adb_row_t *r) {
    il_t *l = ctx;
    if (l->n >= l->cap) return 1;
    l->r[l->n++] = *r;
    return 0;
}

static const char *ev_word(char ev) {
    return ev == 'c' ? "create" : ev == 'e' ? "escalate" : ev == 'r' ? "resolve" : "update";
}

static void kb_json(web_jw_t *w, const web_akb_t *k) {
    web_jw_raw(w, ",\"kb\":");
    if (!k) { web_jw_raw(w, "null"); return; }
    web_jw_raw(w, "{\"name\":");        web_jw_str(w, k->name);
    web_jw_raw(w, ",\"technique\":");   jw_str_or_null(w, k->technique);
    web_jw_raw(w, ",\"sev\":");         web_jw_str(w, k->sev);
    web_jw_raw(w, ",\"summary\":");     web_jw_str(w, k->summary);
    web_jw_raw(w, ",\"what\":");        web_jw_str(w, k->what);
    web_jw_raw(w, ",\"match\":");       web_jw_str(w, k->match);
    web_jw_raw(w, ",\"context\":");     web_jw_str(w, k->context);
    web_jw_raw(w, ",\"sources\":[");
    for (int i = 0; i < k->nsrc; i++) {
        const web_akb_src_t *s = &k->src[i];
        web_jw_raw(w, i ? ",{\"path\":" : "{\"path\":");
        web_jw_str(w, s->path);
        web_jw_raw(w, ",\"citation\":"); web_jw_str(w, s->citation);
        web_jw_raw(w, ",\"url\":");      web_jw_str(w, s->url);
        web_jw_raw(w, ",\"lead\":");     web_jw_str(w, s->lead);
        web_jw_raw(w, ",\"excerpt\":");  web_jw_str(w, s->excerpt);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"investigate\":[");
    for (int i = 0; i < k->ninvestigate; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, k->investigate[i]);
    }
    web_jw_raw(w, "],\"fix\":[");
    for (int i = 0; i < k->nfix; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, k->fix[i]);
    }
    web_jw_raw(w, "],\"vendor_fix\":"); web_jw_str(w, k->vendor_fix);
    web_jw_raw(w, ",\"fix_sources\":[");
    for (int i = 0; i < k->nfix_src; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, k->fix_src[i]);
    }
    web_jw_raw(w, "],\"generated_from\":"); web_jw_str(w, web_akb_inputs);
    web_jw_raw(w, "}");
}

/* Every incident of the key as runs, newest run first: incidents less
 * than WEB_ALERT_RUN_GAP_S apart (one's first_seen after the previous
 * one's last_seen) are one run, which is what sloth's churn on one key
 * looks like. r is newest first. */
static void runs_json(web_jw_t *w, const web_adb_row_t *r, int n, size_t cap,
                      int *runs_out) {
    int runs = 0, at = 0, cut = 0;
    while (at < n) {
        int end = at;                 /* r[at..end], newest to oldest */
        while (end + 1 < n && r[end].first_seen - r[end + 1].last_seen <= WEB_ALERT_RUN_GAP_S)
            end++;
        if (runs >= WEB_ALERT_RUNS || w->len + 512 > cap) { cut = 1; break; }
        int sev = 0;
        long long count = 0;
        for (int i = at; i <= end; i++) {
            if (r[i].sev > sev) sev = r[i].sev;
            count += r[i].count;
        }
        char id[32];
        snprintf(id, sizeof(id), "d%lld", r[at].rid);
        web_jw_raw(w, runs ? ",{\"from\":" : "{\"from\":");
        web_jw_int(w, r[end].first_seen);
        web_jw_raw(w, ",\"to\":");        web_jw_int(w, r[at].last_seen);
        web_jw_raw(w, ",\"incidents\":"); web_jw_int(w, end - at + 1);
        web_jw_raw(w, ",\"sev\":");       web_jw_int(w, sev_clamp(sev));
        web_jw_raw(w, ",\"count\":");     web_jw_int(w, count);
        web_jw_raw(w, ",\"id\":");        web_jw_str(w, id);
        web_jw_raw(w, "}");
        runs++;
        at = end + 1;
    }
    *runs_out = cut ? -runs - 1 : runs;
}

/* id: "s<handle>" (web_live_inc_t.hid) or "d<rowid>". */
static int parse_id(const char *query, int *kind, char *sid, long long *rid,
                    char *err, size_t errsz) {
    web_param_t ps[1] = { { "id", "", 0 } };
    if (web_params_parse(query, ps, 1, err, errsz) != 0) return -1;
    if (!ps[0].seen) { snprintf(err, errsz, "missing_id"); return -1; }
    const char *v = ps[0].val;
    if (v[0] == 'd' && decimal(v + 1, 1, 9223372036854775806LL, rid) == 0) {
        *kind = 'd';
        return 0;
    }
    size_t n = strlen(v + 1);
    if (v[0] == 's' && n >= 1 && n <= WEB_LIVE_HID_MAX) {
        for (size_t i = 1; v[i]; i++)
            if (!isalnum((unsigned char)v[i])) {
                snprintf(err, errsz, "bad_id");
                return -1;
            }
        *kind = 's';
        memcpy(sid, v + 1, n + 1);
        return 0;
    }
    snprintf(err, errsz, "bad_id");
    return -1;
}

int web_alert_route(const web_m4_t *m, web_live_t *live, const char *query,
                    long long now_s, char *body, size_t cap, size_t *len,
                    int *status) {
    int kind = 0;
    char sid[WEB_LIVE_HID_MAX + 1] = "";
    long long rid = 0;
    char err[48];
    if (parse_id(query, &kind, sid, &rid, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);

    web_live_inc_t *e = calloc(1, sizeof(*e));
    web_live_inc_t *all = calloc(INC_MAX, sizeof(*all));
    web_adb_row_t *hist = calloc(WEB_ADB_INCIDENTS, sizeof(*hist));
    web_adb_row_t row;
    memset(&row, 0, sizeof(row));
    if (!e || !hist || !all) { free(e); free(hist); free(all); return -1; }
    int na = live ? web_live_incidents(live, all, INC_MAX, NULL) : 0;
    int have_inc = kind == 's' && live && web_live_incident(live, sid, e);
    if (kind == 's' && !have_inc) {
        free(e); free(hist); free(all);
        return web_hist_error(404, "no_such_alert", NULL, body, cap, len, status);
    }
    if (kind == 'd' && !web_hist_configured(m)) {
        free(e); free(hist); free(all);
        return web_hist_no_db(body, cap, len, status);
    }
    const char *db = "none";
    int have_row = 0, nh = 0, have_t = 0;
    web_adb_totals_t tot;
    memset(&tot, 0, sizeof(tot));
    char mac[18] = "";
    if (web_hist_configured(m)) {
        web_sdb_conn_t c;
        int o = web_hist_open(m, &c, now_s, body, cap, len, status);
        if (o) {
            /* A stream incident stands without sloth.db. */
            if (kind == 'd') { free(e); free(hist); free(all); return o > 0 ? 0 : -1; }
            db = "unreadable";
        } else {
            db = "open";
            const char *key = have_inc && e->key[0] ? e->key : NULL;
            int got = 0;
            if (kind == 'd') {
                got = web_adb_row(&c, rid, &row);
                if (got == 0) {
                    web_slothdb_close(&c);
                    free(e); free(hist); free(all);
                    return web_hist_error(404, "no_such_alert", NULL, body, cap, len, status);
                }
                have_row = got > 0;
            }
            if (got >= 0 && (key || kind == 'd')) {
                got = web_adb_key_totals(&c, kind == 'd' ? rid : 0, kind == 'd' ? NULL : key,
                                         &tot);
                have_t = got > 0;
            }
            il_t il = { hist, 0, WEB_ADB_INCIDENTS };
            if (got >= 0 && (key || kind == 'd'))
                got = web_adb_incidents(&c, kind == 'd' ? rid : 0, kind == 'd' ? NULL : key,
                                        WEB_ADB_INCIDENTS, take_row, &il);
            nh = il.n;
            /* A sloth.db alert the stream has too: its live state, the
             * key's open incident first (all[] holds the open ones
             * first), matched by key as a predicate (the key itself
             * never read). */
            for (int i = 0; got >= 0 && kind == 'd' && i < na && !have_inc; i++) {
                web_adb_totals_t t2;
                if (!all[i].key[0]) continue;
                int g2 = web_adb_key_totals(&c, 0, all[i].key, &t2);
                if (g2 < 0) got = -1;
                else if (g2 > 0 && t2.newest_rid == tot.newest_rid) { *e = all[i]; have_inc = 1; }
            }
            if (got >= 0) {
                const char *ip = have_inc ? e->match_ip : row.ip;
                got = web_adb_device(&c, kind == 'd' ? rid : 0, kind == 'd' ? NULL : key,
                                     ip, mac);
            }
            if (got < 0) {
                free(e); free(hist); free(all);
                return web_hist_read_failed(&c, body, cap, len, status);
            }
            web_slothdb_close(&c);
        }
    }
    /* The stream's incidents of the key, as a list row counts them. */
    int sn = 0;
    long long s_count = 0, s_first = 0;
    for (int i = 0; have_inc && i < na; i++) {
        if (e->key[0] ? strcmp(all[i].key, e->key) != 0 : strcmp(all[i].hid, e->hid) != 0)
            continue;
        sn++;
        s_count += all[i].count;
        if (all[i].first_ts > 0 && (s_first <= 0 || all[i].first_ts < s_first))
            s_first = all[i].first_ts;
    }
    free(all);
    if (have_inc && sn == 0) { sn = 1; s_count = e->count; s_first = e->first_ts; }
    if (!have_inc && !have_t && have_row) {
        tot.incidents = 1;
        tot.count = row.count;
        tot.first_seen = row.first_seen;
        have_t = 1;
    }
    sum_t k = key_sum(&tot, have_t, have_inc ? sn : 0, s_count, s_first,
                      have_inc ? e->reopen : 0);

    /* The fields, the stream's first: it is the newer. */
    int type = have_inc ? e->type : row.type;
    int sev = sev_clamp(have_inc ? e->sev : row.sev);
    const char *title = have_inc ? e->title : row.title;
    const char *tech = tech_of(have_inc && e->technique[0] ? e->technique : row.technique, type);
    const char *ip = have_inc && e->match_ip[0] ? e->match_ip : row.ip;
    int port = have_inc && e->match_ip[0] ? e->match_port : row.port;
    long long first = k.first_seen;
    long long last = have_inc ? e->last_ts : row.last_seen;
    if (have_row && row.last_seen > last) last = row.last_seen;
    int shown_ok = web_alert_detail_ok(type);
    const char *detail = !shown_ok ? NULL
                       : have_inc && e->detail[0] ? e->detail
                       : have_row && row.has_detail ? row.detail : NULL;

    web_jw_t w;
    web_jw_init(&w, body, cap);
    char id[48];
    if (kind == 's') snprintf(id, sizeof(id), "s%s", sid);
    else snprintf(id, sizeof(id), "d%lld", rid);
    web_jw_raw(&w, "{\"id\":");       web_jw_str(&w, id);
    web_jw_raw(&w, ",\"db\":");       web_jw_str(&w, db);
    web_jw_raw(&w, ",\"state\":");
    web_jw_str(&w, have_inc ? (e->closed_ts < 0 ? "open" : "closed") : "recorded");
    web_jw_raw(&w, ",\"source\":");
    web_jw_str(&w, have_inc && tot.rows > 0 ? "both" : have_inc ? "stream" : "sloth.db");
    if (have_inc) {
        char sid2[48];
        snprintf(sid2, sizeof(sid2), "s%s", e->hid);
        web_jw_raw(&w, ",\"stream_id\":"); web_jw_str(&w, sid2);
    } else {
        web_jw_raw(&w, ",\"stream_id\":null");
    }
    web_jw_raw(&w, ",\"db_id\":");
    if (tot.newest_rid > 0) {
        char did[32];
        snprintf(did, sizeof(did), "d%lld", tot.newest_rid);
        web_jw_str(&w, did);
    } else {
        web_jw_raw(&w, "null");
    }
    jw_type(&w, type);
    /* The stream's text is kept in the display form (web_live.c);
     * sloth.db's is escaped here, so neither goes out raw or twice. */
    web_jw_raw(&w, ",\"title\":");
    if (have_inc) web_jw_str(&w, title); else web_jw_text(&w, title);
    web_jw_raw(&w, ",\"sev\":");        web_jw_int(&w, sev);
    web_jw_raw(&w, ",\"technique\":");  jw_str_or_null(&w, tech);
    web_jw_raw(&w, ",\"ip\":");         jw_str_or_null(&w, ip);
    web_jw_raw(&w, ",\"port\":");
    if (ip && ip[0] && port >= 0) web_jw_int(&w, port); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, first);
    web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, last);
    /* count and incidents are the key's, as its list row shows them;
     * latest_count is the one incident's this page opened on. */
    web_jw_raw(&w, ",\"count\":");      web_jw_int(&w, k.count);
    web_jw_raw(&w, ",\"latest_count\":");
    web_jw_int(&w, have_inc ? e->count : row.count);
    web_jw_raw(&w, ",\"observations\":");
    if (have_inc) web_jw_int(&w, e->observations); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"incidents\":");  web_jw_int(&w, k.incidents);
    web_jw_raw(&w, ",\"closed_at\":");
    if (have_inc && e->closed_ts >= 0) web_jw_int(&w, e->closed_ts); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"reason\":");     jw_str_or_null(&w, have_inc ? e->reason : NULL);
    /* Whether sloth wrote a pcap of it is in the stream's records only. */
    web_jw_raw(&w, ",\"pcap\":");
    web_jw_raw(&w, !have_inc ? "null" : e->pcap ? "true" : "false");
    web_jw_raw(&w, ",\"detail\":");
    if (!detail) web_jw_raw(&w, "null");
    else if (have_inc && detail == e->detail) web_jw_str(&w, detail);
    else web_jw_text(&w, detail);
    web_jw_raw(&w, ",\"detail_shown\":"); web_jw_raw(&w, shown_ok ? "true" : "false");
    web_jw_raw(&w, ",\"sev_history\":[");
    if (have_inc) {
        int nk = e->nsev < WEB_LIVE_SEVH ? e->nsev : WEB_LIVE_SEVH;
        for (int i = 0; i < nk; i++) {
            web_jw_raw(&w, i ? ",{\"ts\":" : "{\"ts\":");
            web_jw_int(&w, e->sevh[i].ts);
            web_jw_raw(&w, ",\"sev\":"); web_jw_int(&w, sev_clamp(e->sevh[i].sev));
            web_jw_raw(&w, ",\"ev\":");  web_jw_str(&w, ev_word(e->sevh[i].ev));
            web_jw_raw(&w, "}");
        }
    }
    web_jw_raw(&w, "],\"sev_changes\":");
    web_jw_int(&w, have_inc ? e->nsev : 0);
    web_jw_raw(&w, ",\"device\":{\"mac\":"); jw_str_or_null(&w, mac);
    web_jw_raw(&w, ",\"ip\":");             jw_str_or_null(&w, ip);
    web_jw_raw(&w, "}");
    kb_json(&w, web_akb_get(type));
    web_jw_raw(&w, ",\"history\":{\"gap_s\":"); web_jw_int(&w, WEB_ALERT_RUN_GAP_S);
    web_jw_raw(&w, ",\"incidents_read\":");   web_jw_int(&w, nh);
    web_jw_raw(&w, ",\"incidents_cap\":");    web_jw_int(&w, WEB_ADB_INCIDENTS);
    web_jw_raw(&w, ",\"runs\":[");
    int runs = 0;
    runs_json(&w, hist, nh, cap > 1024 ? cap - 1024 : 0, &runs);
    web_jw_raw(&w, "],\"more\":");
    web_jw_raw(&w, runs < 0 || nh >= WEB_ADB_INCIDENTS ? "true" : "false");
    web_jw_raw(&w, "}}\n");
    free(e);
    free(hist);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
