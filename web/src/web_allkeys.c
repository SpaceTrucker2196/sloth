#include "web_allkeys.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_metrics.h"
#include "web_series.h"

/* What the members after the keys can take: "],"more":true,"next":" a
 * key of WEB_KEY_MAX bytes, each at most six when escaped, the source
 * and the close. A key is only kept in the answer while this much is
 * left. */
#define AK_TAIL (128 + WEB_KEY_MAX * 6)

static int fail(char *err, size_t errsz, const char *why) {
    snprintf(err, errsz, "%s", why);
    return -1;
}

static const long long DEFAULT_SPAN[WEB_TIER_COUNT] = { 3600, 86400, 30 * 86400 };

int web_allkeys_parse(const char *query, long long now_s, int store_on,
                      web_allkeys_q_t *q, char *err, size_t errsz) {
    web_param_t ps[6] = {
        { "metric", "", 0 }, { "tier", "", 0 }, { "from", "", 0 },
        { "to", "", 0 }, { "cols", "", 0 }, { "after", "", 0 },
    };
    memset(q, 0, sizeof(*q));
    if (web_params_parse(query, ps, 6, err, errsz) != 0) return -1;
    if (!ps[0].seen) return fail(err, errsz, "missing_metric");
    q->metric = web_metric_find(ps[0].val);
    if (q->metric < 0) return fail(err, errsz, "unknown_metric");
    q->tier = ps[1].seen ? web_tier_find(ps[1].val) : WEB_TIER_FINE;
    if (q->tier < 0) return fail(err, errsz, "unknown_tier");
    if (q->tier != WEB_TIER_FINE && !store_on)
        return fail(err, errsz, "tier_unavailable");
    long long step = web_tier_step(q->tier);
    if (ps[3].seen) {
        if (web_param_secs(ps[3].val, &q->to) != 0) return fail(err, errsz, "bad_to");
    } else {
        q->to = now_s - now_s % step + step;
    }
    if (ps[2].seen) {
        if (web_param_secs(ps[2].val, &q->from) != 0) return fail(err, errsz, "bad_from");
    } else {
        q->from = q->to > DEFAULT_SPAN[q->tier] ? q->to - DEFAULT_SPAN[q->tier] : 0;
    }
    if (q->to > now_s + 86400) return fail(err, errsz, "to_in_future");
    if (q->from >= q->to) return fail(err, errsz, "empty_range");
    if (q->to - q->from > (long long)WEB_ALLKEYS_BUCKETS * step)
        return fail(err, errsz, "range_too_long");
    q->cols = WEB_ALLKEYS_COLS_DEF;
    if (ps[4].seen) {
        long long c;
        if (web_param_secs(ps[4].val, &c) != 0 || c < WEB_ALLKEYS_COLS_MIN ||
            c > WEB_ALLKEYS_COLS_MAX)
            return fail(err, errsz, "bad_cols");
        q->cols = (int)c;
    }
    if (ps[5].seen) {
        /* A global metric has the one key "", which nothing follows. */
        if (web_metric_defs[q->metric].keykind[0] == '\0' ||
            web_key_canon(q->metric, ps[5].val, q->after) != 0)
            return fail(err, errsz, "bad_after");
        q->has_after = 1;
    }
    return 0;
}

void web_allkeys_cells(int tier, long long from, long long to, int cols,
                       long long *cell_s, int *ncell) {
    long long step = web_tier_step(tier);
    long long nb = (to - from + step - 1) / step;
    long long per = (nb + cols - 1) / cols;
    if (per < 1) per = 1;
    *cell_s = per * step;
    *ncell = (int)((to - from + *cell_s - 1) / *cell_s);
}

/* web_series.c's key_in() and metric_in(): a key's and a metric's place
 * in a scope, as /api/keys lists them. */
static int key_in(int metric, const char *key, const web_scope_ctx_t *sc) {
    if (!sc || sc->scope == WEB_SCOPE_HYBRID) return 1;
    return web_scope_pass(sc->scope, web_scope_metric_key(metric, key, sc));
}
static int metric_in(int metric, const web_scope_ctx_t *sc) {
    if (!sc || sc->scope == WEB_SCOPE_HYBRID) return 1;
    int tag = web_scope_metric(metric);
    if (tag == WEB_SC_BYKEY) return 1;
    return web_scope_pass(sc->scope, web_scope_eff(tag, sc->radio));
}

static int cmp_key(const void *a, const void *b) {
    return strcmp(((const web_keyinfo_t *)a)->key, ((const web_keyinfo_t *)b)->key);
}

static const char *kind_word(int k) {
    return k == WEB_MK_COUNTER ? "counter" : k == WEB_MK_PRESENCE ? "presence"
                                                                  : "gauge";
}

/* A cell's value: six significant digits is more than a pixel reads,
 * and keeps a full key's cells well inside one answer. */
static void jw_val(web_jw_t *w, double v) {
    char b[40];
    if (!isfinite(v)) { web_jw_raw(w, "null"); return; }
    if (v == 0) v = 0;
    snprintf(b, sizeof(b), "%.6g", v);
    web_jw_raw(w, b);
}

size_t web_allkeys_json(web_tsdb_t *t, const web_allkeys_q_t *q, char *out,
                        size_t cap) {
    long long cell_s;
    int ncell;
    web_allkeys_cells(q->tier, q->from, q->to, q->cols, &cell_s, &ncell);
    const int maxb = WEB_ALLKEYS_BUCKETS + 1;
    web_keyinfo_t *k = malloc(WEB_KEYS_MAX * sizeof(*k));
    web_point_t *m = malloc((size_t)maxb * sizeof(*m));
    web_agg_t *cell = malloc((size_t)ncell * sizeof(*cell));
    if (!k || !m || !cell) { free(k); free(m); free(cell); return 0; }

    int total = 0;
    int n = web_rollup_keys(t->ru, q->metric, k, WEB_KEYS_MAX, &total);
    int in = metric_in(q->metric, q->sc);
    if (q->sc && q->sc->scope != WEB_SCOPE_HYBRID) {
        int o = 0;
        for (int i = 0; i < n; i++)
            if (key_in(q->metric, k[i].key, q->sc)) k[o++] = k[i];
        n = in ? o : 0;
        total = n;
    }
    qsort(k, (size_t)n, sizeof(*k), cmp_key);

    const web_metric_t *md = &web_metric_defs[q->metric];
    int use_store = t->store && t->store->rd;
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"metric\":");  web_jw_str(&w, md->name);
    web_jw_raw(&w, ",\"tier\":");    web_jw_str(&w, web_tier_name(q->tier));
    web_jw_raw(&w, ",\"step\":");    web_jw_int(&w, web_tier_step(q->tier));
    web_jw_raw(&w, ",\"cell\":");    web_jw_int(&w, cell_s);
    web_jw_raw(&w, ",\"cells\":");   web_jw_int(&w, ncell);
    web_jw_raw(&w, ",\"kind\":");    web_jw_str(&w, kind_word(md->kind));
    web_jw_raw(&w, ",\"unit\":");    web_jw_str(&w, md->unit);
    web_jw_raw(&w, ",\"keykind\":"); web_jw_str(&w, md->keykind);
    web_jw_raw(&w, ",\"from\":");    web_jw_int(&w, q->from);
    web_jw_raw(&w, ",\"to\":");      web_jw_int(&w, q->to);
    web_jw_raw(&w, ",\"total\":");   web_jw_int(&w, total);
    web_jw_raw(&w, ",\"listed\":");  web_jw_int(&w, n);
    if (!in) web_jw_raw(&w, ",\"out_of_scope\":true");
    web_jw_raw(&w, ",\"keys\":[");

    int done = 0, more = 0, store_err = 0, last = -1;
    for (int i = 0; i < n && !w.overflow; i++) {
        if (q->has_after && strcmp(k[i].key, q->after) <= 0) continue;
        if (done == WEB_ALLKEYS_PAGE) { more = 1; break; }
        int pm = 0, se = 0;
        int np = web_series_points(t, q->tier, q->metric, k[i].key, q->from,
                                   q->to, m, maxb, &pm, &se);
        if (np < 0) { free(k); free(m); free(cell); return 0; }
        if (se) store_err = 1;
        for (int c = 0; c < ncell; c++) { cell[c].t = -1; cell[c].n = 0; }
        for (int j = 0; j < np; j++) {
            long long ci = (m[j].t - q->from) / cell_s;
            if (m[j].t < q->from || ci >= ncell) continue;
            web_agg_t *a = &cell[ci];
            if (a->t < 0) { *a = m[j]; continue; }
            a->sum += m[j].sum;
            if (m[j].min < a->min) a->min = m[j].min;
            if (m[j].max > a->max) a->max = m[j].max;
            a->n += m[j].n;
        }
        size_t mark = w.len;
        web_jw_raw(&w, done ? ",{\"key\":" : "{\"key\":");
        web_jw_str(&w, k[i].key);
        web_jw_raw(&w, ",\"p\":[");
        int first = 1;
        for (int c = 0; c < ncell; c++) {
            if (cell[c].t < 0 || !cell[c].n) continue;
            if (!first) web_jw_raw(&w, ",");
            first = 0;
            web_jw_int(&w, c);
            web_jw_raw(&w, ",");
            jw_val(&w, web_point_value(q->metric, &cell[c]));
        }
        web_jw_raw(&w, "]}");
        if (w.overflow || w.len + AK_TAIL > cap) {
            /* It did not fit beside the others: it is the next answer's
             * first. With none before it, it fits no answer at all. */
            if (!done) { free(k); free(m); free(cell); return 0; }
            w.len = mark;
            w.overflow = 0;
            more = 1;
            break;
        }
        done++;
        last = i;
    }
    web_jw_raw(&w, "],\"more\":");
    web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next\":");
    if (more && last >= 0) web_jw_str(&w, k[last].key); else web_jw_raw(&w, "null");
    /* The same words /api/series uses; after the reads, because a
     * store error is only known then. */
    web_jw_raw(&w, ",\"source\":");
    web_jw_str(&w, use_store ? (store_err ? "memory (store error)"
                                          : q->tier == WEB_TIER_FINE
                                            ? "store+memory" : "store")
                             : "memory");
    web_jw_raw(&w, "}\n");
    size_t len = w.overflow ? 0 : w.len;
    free(k);
    free(m);
    free(cell);
    return len;
}
