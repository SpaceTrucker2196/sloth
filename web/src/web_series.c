#include "web_series.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_metrics.h"

/* ── the query string ────────────────────────────────────────────────── */

typedef struct {
    const char *name;
    char        val[WEB_PARAM_MAX + 1];
    int         seen;
} param_t;

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int fail(char *err, size_t errsz, const char *why) {
    snprintf(err, errsz, "%s", why);
    return -1;
}

/* Split query into the named params; anything else is refused. */
static int parse_params(const char *query, param_t *ps, int np, char *err,
                        size_t errsz) {
    if (!query || !query[0]) return 0;
    const char *p = query;
    for (;;) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg);
        if (!seg || !eq || eq == p) return fail(err, errsz, "bad_query");
        size_t nl = (size_t)(eq - p);
        for (size_t i = 0; i < nl; i++)
            if (p[i] < 'a' || p[i] > 'z') return fail(err, errsz, "unknown_parameter");
        int which = -1;
        for (int i = 0; i < np; i++)
            if (strlen(ps[i].name) == nl && !memcmp(ps[i].name, p, nl)) which = i;
        if (which < 0) return fail(err, errsz, "unknown_parameter");
        if (ps[which].seen) return fail(err, errsz, "repeated_parameter");
        ps[which].seen = 1;
        size_t o = 0;
        for (const char *v = eq + 1; v < p + seg; v++) {
            int c = (unsigned char)*v;
            if (c == '%') {
                if ((size_t)(p + seg - v) < 3) return fail(err, errsz, "bad_escape");
                int h = hexv((unsigned char)v[1]), l = hexv((unsigned char)v[2]);
                if (h < 0 || l < 0) return fail(err, errsz, "bad_escape");
                c = h * 16 + l;
                v += 2;
            }
            if (c < 0x21 || c > 0x7e) return fail(err, errsz, "bad_value");
            if (o >= WEB_PARAM_MAX) return fail(err, errsz, "value_too_long");
            ps[which].val[o++] = (char)c;
        }
        ps[which].val[o] = '\0';
        if (!o) return fail(err, errsz, "empty_value");
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int parse_secs(const char *s, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 11) return -1;
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return -1;
    *out = atoll(s);
    return 0;
}

static long long tier_keep(int tier, int retain_days) {
    switch (tier) {
    case WEB_TIER_FINE:   return WEB_FINE_KEEP_S;
    case WEB_TIER_MINUTE: return (long long)retain_days * 86400;
    default:              return WEB_HOUR_KEEP_S;
    }
}

static const long long DEFAULT_SPAN[WEB_TIER_COUNT] = { 3600, 86400, 30 * 86400 };

int web_series_parse(const char *query, long long now_s, int retain_days,
                     int store_on, web_series_q_t *q, char *err,
                     size_t errsz) {
    param_t ps[5] = {
        { "metric", "", 0 }, { "key", "", 0 }, { "tier", "", 0 },
        { "from", "", 0 }, { "to", "", 0 },
    };
    memset(q, 0, sizeof(*q));
    if (parse_params(query, ps, 5, err, errsz) != 0) return -1;
    if (!ps[0].seen) return fail(err, errsz, "missing_metric");
    q->metric = web_metric_find(ps[0].val);
    if (q->metric < 0) return fail(err, errsz, "unknown_metric");
    if (web_key_canon(q->metric, ps[1].seen ? ps[1].val : "", q->key) != 0)
        return fail(err, errsz, "bad_key");
    q->tier = ps[2].seen ? web_tier_find(ps[2].val) : WEB_TIER_FINE;
    if (q->tier < 0) return fail(err, errsz, "unknown_tier");
    if (q->tier != WEB_TIER_FINE && !store_on)
        return fail(err, errsz, "tier_unavailable");
    long long step = web_tier_step(q->tier);
    long long end_now = now_s - now_s % step + step;
    if (ps[4].seen) {
        if (parse_secs(ps[4].val, &q->to) != 0) return fail(err, errsz, "bad_to");
    } else {
        q->to = end_now;
    }
    if (ps[3].seen) {
        if (parse_secs(ps[3].val, &q->from) != 0) return fail(err, errsz, "bad_from");
    } else {
        q->from = q->to > DEFAULT_SPAN[q->tier] ? q->to - DEFAULT_SPAN[q->tier] : 0;
    }
    if (q->to > now_s + 86400) return fail(err, errsz, "to_in_future");
    if (q->from >= q->to) return fail(err, errsz, "empty_range");
    if (q->to - q->from > tier_keep(q->tier, retain_days) + step)
        return fail(err, errsz, "range_too_long");
    return 0;
}

/* ── answers ─────────────────────────────────────────────────────────── */

static void jw_num(web_jw_t *w, double v) {
    char b[40];
    /* Values are finite by construction (the rollup clamps them), so
     * %g never writes inf or nan here; -0 reads as 0. */
    if (v == 0) v = 0;
    snprintf(b, sizeof(b), "%.7g", v);
    web_jw_raw(w, b);
}

static const char *kind_word(int k) {
    return k == WEB_MK_COUNTER ? "counter" : k == WEB_MK_PRESENCE ? "presence"
                                                                  : "gauge";
}

size_t web_series_json(web_tsdb_t *t, const web_series_q_t *q, char *out,
                       size_t cap) {
    const int max = WEB_SERIES_MAX_POINTS;
    web_point_t *a = malloc((size_t)max * sizeof(*a));
    web_point_t *b = malloc((size_t)max * sizeof(*b));
    web_point_t *m = malloc((size_t)max * sizeof(*m));
    if (!a || !b || !m) { free(a); free(b); free(m); return 0; }
    int na = 0, nb = 0, more_a = 0, more_b = 0, store_err = 0;
    int use_store = t->store && t->store->rd;
    if (use_store) {
        na = web_store_query(t->store, q->tier, q->metric, q->key, q->from,
                             q->to, a, max, &more_a);
        if (na < 0) { na = 0; store_err = 1; }
    }
    if (q->tier == WEB_TIER_FINE)
        nb = web_rollup_fine(t->ru, q->metric, q->key, q->from, q->to, 1,
                             b, max, &more_b);

    /* Both newest first; one point per bucket, the fuller one when both
     * have it. In one process lifetime the store's row for a bucket is a
     * copy of the ring's, or the ring's merged with an older part, so
     * the fuller one is right. The one exception is the bucket a
     * restart split: until this process's part of it is flushed (at
     * most two flush intervals after start), the store holds only the
     * last run's part and the ring only this run's, and the answer
     * shows the fuller part, not their sum: a transient undercount of
     * that one bucket, accepted rather than tracked. */
    int i = 0, j = 0, n = 0, more = more_a || more_b;
    while ((i < na || j < nb) && n < max) {
        if (j >= nb || (i < na && a[i].t > b[j].t)) m[n++] = a[i++];
        else if (i >= na || b[j].t > a[i].t) m[n++] = b[j++];
        else { m[n++] = a[i].n >= b[j].n ? a[i] : b[j]; i++; j++; }
    }
    if (i < na || j < nb) more = 1;

    const web_metric_t *md = &web_metric_defs[q->metric];
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"metric\":");  web_jw_str(&w, md->name);
    web_jw_raw(&w, ",\"key\":");     web_jw_str(&w, q->key);
    web_jw_raw(&w, ",\"tier\":");    web_jw_str(&w, web_tier_name(q->tier));
    web_jw_raw(&w, ",\"step\":");    web_jw_int(&w, web_tier_step(q->tier));
    web_jw_raw(&w, ",\"kind\":");    web_jw_str(&w, kind_word(md->kind));
    web_jw_raw(&w, ",\"unit\":");    web_jw_str(&w, md->unit);
    web_jw_raw(&w, ",\"from\":");    web_jw_int(&w, q->from);
    web_jw_raw(&w, ",\"to\":");      web_jw_int(&w, q->to);
    web_jw_raw(&w, ",\"source\":");
    web_jw_str(&w, use_store ? (store_err ? "memory (store error)"
                                          : q->tier == WEB_TIER_FINE
                                            ? "store+memory" : "store")
                             : "memory");
    web_jw_raw(&w, ",\"more\":");    web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_to\":");
    if (more && n) web_jw_int(&w, m[n - 1].t); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"points\":[");
    for (int k = n - 1; k >= 0; k--) {
        web_jw_raw(&w, k == n - 1 ? "[" : ",[");
        web_jw_int(&w, m[k].t);
        web_jw_raw(&w, ",");
        jw_num(&w, web_point_value(q->metric, &m[k]));
        web_jw_raw(&w, ",");
        jw_num(&w, m[k].min);
        web_jw_raw(&w, ",");
        jw_num(&w, m[k].max);
        web_jw_raw(&w, ",");
        /* A count past 2^32 is not a real bucket; capping it keeps every
         * point inside the worst case the buffer is sized for. */
        web_jw_int(&w, m[k].n > 4294967295UL ? 4294967295LL : (long long)m[k].n);
        web_jw_raw(&w, "]");
    }
    web_jw_raw(&w, "]}\n");
    free(a); free(b); free(m);
    return w.overflow ? 0 : w.len;
}

int web_keys_parse(const char *query, int *metric, char *err, size_t errsz) {
    param_t ps[1] = { { "metric", "", 0 } };
    if (parse_params(query, ps, 1, err, errsz) != 0) return -1;
    if (!ps[0].seen) return fail(err, errsz, "missing_metric");
    *metric = web_metric_find(ps[0].val);
    if (*metric < 0) return fail(err, errsz, "unknown_metric");
    return 0;
}

size_t web_keys_json(web_tsdb_t *t, int metric, char *out, size_t cap) {
    web_keyinfo_t *k = malloc(WEB_KEYS_MAX * sizeof(*k));
    if (!k) return 0;
    int total = 0;
    int n = web_rollup_keys(t->ru, metric, k, WEB_KEYS_MAX, &total);
    const web_metric_t *md = &web_metric_defs[metric];
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"metric\":");  web_jw_str(&w, md->name);
    web_jw_raw(&w, ",\"keykind\":"); web_jw_str(&w, md->keykind);
    web_jw_raw(&w, ",\"total\":");   web_jw_int(&w, total);
    web_jw_raw(&w, ",\"keys\":[");
    for (int i = 0; i < n; i++) {
        web_jw_raw(&w, i ? ",{\"key\":" : "{\"key\":");
        web_jw_str(&w, k[i].key);
        web_jw_raw(&w, ",\"last_seen\":");
        web_jw_int(&w, k[i].last_seen);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "]}\n");
    free(k);
    return w.overflow ? 0 : w.len;
}

int web_metrics_parse(const char *query, char *err, size_t errsz) {
    if (query && query[0]) return fail(err, errsz, "unknown_parameter");
    return 0;
}

size_t web_metrics_json(web_tsdb_t *t, char *out, size_t cap) {
    int store_on = t->store && t->store->rd;
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"store\":");
    web_jw_raw(&w, store_on ? "true" : "false");
    web_jw_raw(&w, ",\"max_points\":");
    web_jw_int(&w, WEB_SERIES_MAX_POINTS);
    web_jw_raw(&w, ",\"tiers\":[");
    for (int i = 0; i < WEB_TIER_COUNT; i++) {
        web_jw_raw(&w, i ? ",{\"name\":" : "{\"name\":");
        web_jw_str(&w, web_tier_name(i));
        web_jw_raw(&w, ",\"step\":");
        web_jw_int(&w, web_tier_step(i));
        web_jw_raw(&w, ",\"keep_s\":");
        web_jw_int(&w, tier_keep(i, t->retain_days));
        web_jw_raw(&w, ",\"available\":");
        web_jw_raw(&w, i == WEB_TIER_FINE || store_on ? "true" : "false");
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"metrics\":[");
    for (int i = 0; i < WM_COUNT; i++) {
        const web_metric_t *md = &web_metric_defs[i];
        web_keyinfo_t one;
        int total = 0;
        web_rollup_keys(t->ru, i, &one, 1, &total);
        web_jw_raw(&w, i ? ",{\"name\":" : "{\"name\":");
        web_jw_str(&w, md->name);
        web_jw_raw(&w, ",\"kind\":");    web_jw_str(&w, kind_word(md->kind));
        web_jw_raw(&w, ",\"keykind\":"); web_jw_str(&w, md->keykind);
        web_jw_raw(&w, ",\"unit\":");    web_jw_str(&w, md->unit);
        web_jw_raw(&w, ",\"source\":");  web_jw_str(&w, md->source);
        web_jw_raw(&w, ",\"keys\":");    web_jw_int(&w, total);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "]}\n");
    return w.overflow ? 0 : w.len;
}

size_t web_series_error_json(const char *reason, char *out, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, reason);
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}
