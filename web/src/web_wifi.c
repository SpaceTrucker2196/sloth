#include "web_wifi.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_metrics.h"
#include "web_series.h"

/* ── names ───────────────────────────────────────────────────────────── */

/* src/rsn_ie.c rsn_akm_name(), the suite types IEEE 802.11-2020 Table
 * 9-151 names that sloth names; web/tests/test_wifi.c holds the two
 * equal for every type a bit can carry. */
const char *web_akm_name(int t) {
    switch (t) {
    case 1:  return "802.1X";
    case 2:  return "PSK";
    case 3:  return "FT-802.1X";
    case 4:  return "FT-PSK";
    case 5:  return "802.1X-SHA256";
    case 6:  return "PSK-SHA256";
    case 8:  return "SAE";
    case 9:  return "FT-SAE";
    case 11: return "Suite-B";
    case 12: return "Suite-B-192";
    case 18: return "OWE";
    case 19: return "FT-PSK-SHA384";
    case 24: return "SAE-EXT-KEY";
    case 25: return "FT-SAE-EXT-KEY";
    default: return "?";
    }
}

/* include/sloth.h sloth_downgrade_kind_t, bit by bit (test_wifi.c). */
const char *web_downgrade_name(int b) {
    static const char *const N[] = {
        "SAE/PSK transition", "OWE transition", "MFP optional",
        "WPA1 alongside RSN",
    };
    return b >= 0 && b < 4 ? N[b] : NULL;
}

/* sloth's own ranges (src/beacon_snoop.c ap_band_label()): 1-14 2.4 GHz,
 * 32-177 5 GHz, 6 GHz only when an HE 6 GHz element said so (the "6g"
 * key), and "?" for any other number, which a plain key outside both
 * ranges therefore is. */
const char *web_channel_band(const char *key, int *rank) {
    if (!strncmp(key, "6g", 2)) { *rank = 2; return "6"; }
    long ch = strtol(key, NULL, 10);
    if (ch >= 1 && ch <= 14) { *rank = 0; return "2.4"; }
    if (ch >= 32 && ch <= 177) { *rank = 1; return "5"; }
    *rank = 3;
    return "?";
}

/* ── answers ─────────────────────────────────────────────────────────── */

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

static void jw_text_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

/* A cell's value: whole numbers as such, the rest to four figures. At
 * most 17 bytes: the rollup clamps every value to 1e15. */
static void jw_cell(web_jw_t *w, double v) {
    char b[40];
    if (!isfinite(v)) { web_jw_raw(w, "null"); return; }
    if (v == 0) v = 0;
    if (v == floor(v) && fabs(v) < 1e15) snprintf(b, sizeof(b), "%.0f", v);
    else snprintf(b, sizeof(b), "%.4g", v);
    web_jw_raw(w, b);
}

/* ── the grid ────────────────────────────────────────────────────────── */

typedef struct {
    int       tier, ncol;
    long long step, from, to, col_s;
} grid_t;

#define GRID_KEYS 512
#define GRID_PTS  12000

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 6) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* from, to and cols (ps[0..2]) into g, the tier the range needs. 0, or
 * -1 with the reason in why. */
static int grid_of(const web_m4_t *m, const web_param_t *ps, long long now,
                   grid_t *g, const char **why) {
    memset(g, 0, sizeof(*g));
    g->to = now - now % 10 + 10;
    if (ps[1].seen && web_param_secs(ps[1].val, &g->to) != 0) {
        *why = "bad_to";
        return -1;
    }
    g->from = g->to - 3600;
    if (ps[0].seen && web_param_secs(ps[0].val, &g->from) != 0) {
        *why = "bad_from";
        return -1;
    }
    if (g->to > now + 86400) { *why = "to_in_future"; return -1; }
    if (g->from >= g->to) { *why = "empty_range"; return -1; }
    long long span = g->to - g->from;
    if (span > WEB_WIFI_SPAN_MAX) { *why = "range_too_long"; return -1; }
    long long cols = WEB_WIFI_COLS;
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_WIFI_COLS, &cols) != 0) {
        *why = "bad_cols";
        return -1;
    }
    int store_on = m->tsdb->store && m->tsdb->store->rd;
    int in_fine = g->from >= now - WEB_FINE_KEEP_S;
    if (span <= 6 * 3600 && in_fine) g->tier = WEB_TIER_FINE;
    else if (!store_on) {
        if (!in_fine) { *why = "tier_unavailable"; return -1; }
        g->tier = WEB_TIER_FINE;
    } else if (span <= 3 * 86400 &&
               g->from >= now - (long long)m->tsdb->retain_days * 86400)
        g->tier = WEB_TIER_MINUTE;
    else g->tier = WEB_TIER_HOUR;
    g->step = web_tier_step(g->tier);
    long long raw = (span + cols - 1) / cols;
    g->col_s = (raw + g->step - 1) / g->step * g->step;
    g->ncol = (int)((span + g->col_s - 1) / g->col_s);
    return 0;
}

/* The keys of metric: the rollup's and the store's for the grid's tier
 * and range, each once. */
static int grid_keys(const web_m4_t *m, int metric, const grid_t *g,
                     char (*keys)[WEB_KEY_MAX + 1]) {
    int n = 0;
    web_keyinfo_t *ki = malloc(WEB_KEYS_MAX * sizeof(*ki));
    if (ki) {
        int total = 0;
        int k = web_rollup_keys(m->tsdb->ru, metric, ki, WEB_KEYS_MAX, &total);
        for (int i = 0; i < k && n < GRID_KEYS; i++)
            snprintf(keys[n++], WEB_KEY_MAX + 1, "%s", ki[i].key);
        free(ki);
    }
    if (m->tsdb->store && m->tsdb->store->rd && n < GRID_KEYS) {
        char (*sk)[WEB_KEY_MAX + 1] = malloc(256 * sizeof(*sk));
        int ns = sk ? web_store_keys(m->tsdb->store, g->tier, metric, g->from,
                                     g->to, sk, 256) : 0;
        for (int i = 0; i < ns && n < GRID_KEYS; i++) {
            int dup = 0;
            for (int j = 0; j < n && !dup; j++) dup = !strcmp(keys[j], sk[i]);
            if (!dup) snprintf(keys[n++], WEB_KEY_MAX + 1, "%s", sk[i]);
        }
        free(sk);
    }
    return n;
}

/* One key's cells: the mean of its buckets per cell for a gauge, their
 * sum for a counter; cnt 0 is an empty cell. -1 on memory. */
static int grid_row(const web_m4_t *m, int metric, const grid_t *g,
                    const char *key, web_point_t *pts, double *sum, int *cnt,
                    double *total) {
    int more = 0, serr = 0;
    long long maxp = (g->to - g->from) / g->step + 2;
    if (maxp > GRID_PTS) maxp = GRID_PTS;
    int n = web_series_points(m->tsdb, g->tier, metric, key, g->from, g->to,
                              pts, (int)maxp, &more, &serr);
    if (n < 0) return -1;
    memset(sum, 0, (size_t)g->ncol * sizeof(*sum));
    memset(cnt, 0, (size_t)g->ncol * sizeof(*cnt));
    *total = 0;
    for (int i = 0; i < n; i++) {
        long long c = (pts[i].t - g->from) / g->col_s;
        if (c < 0 || c >= g->ncol) continue;
        double v = web_point_value(metric, &pts[i]);
        if (!isfinite(v)) continue;
        sum[c] += v;
        cnt[c]++;
        *total += v;
    }
    return 0;
}

static void grid_head(web_jw_t *w, int metric, const grid_t *g) {
    const web_metric_t *md = &web_metric_defs[metric];
    web_jw_raw(w, "{\"metric\":");   web_jw_str(w, md->name);
    web_jw_raw(w, ",\"kind\":");
    web_jw_str(w, md->kind == WEB_MK_COUNTER ? "counter" : "gauge");
    web_jw_raw(w, ",\"unit\":");     web_jw_str(w, md->unit);
    web_jw_raw(w, ",\"tier\":");     web_jw_str(w, web_tier_name(g->tier));
    web_jw_raw(w, ",\"step\":");     web_jw_int(w, g->step);
    web_jw_raw(w, ",\"from\":");     web_jw_int(w, g->from);
    web_jw_raw(w, ",\"to\":");       web_jw_int(w, g->to);
    web_jw_raw(w, ",\"cols\":");     web_jw_int(w, g->ncol);
    web_jw_raw(w, ",\"col_s\":");    web_jw_int(w, g->col_s);
}

static void cells_json(web_jw_t *w, int metric, const grid_t *g,
                       const double *sum, const int *cnt) {
    int gauge = web_metric_defs[metric].kind != WEB_MK_COUNTER;
    web_jw_raw(w, "[");
    for (int c = 0; c < g->ncol; c++) {
        if (c) web_jw_raw(w, ",");
        if (!cnt[c]) web_jw_raw(w, "null");
        else jw_cell(w, gauge ? sum[c] / cnt[c] : sum[c]);
    }
    web_jw_raw(w, "]");
}

typedef struct {
    char key[WEB_KEY_MAX + 1];
    int  rank;
    long num;
    double total;
} krow_t;

static int by_band(const void *a, const void *b) {
    const krow_t *x = a, *y = b;
    if (x->rank != y->rank) return x->rank - y->rank;
    if (x->num != y->num) return x->num < y->num ? -1 : 1;
    return strcmp(x->key, y->key);
}

static int by_total(const void *a, const void *b) {
    const krow_t *x = a, *y = b;
    if (x->total != y->total) return x->total > y->total ? -1 : 1;
    return strcmp(x->key, y->key);
}

typedef struct {
    char (*keys)[WEB_KEY_MAX + 1];
    krow_t      *rows;
    web_point_t *pts;
    double      *sum;
    int         *cnt;
} gbuf_t;

static int gbuf_alloc(gbuf_t *b) {
    b->keys = malloc(GRID_KEYS * sizeof(*b->keys));
    b->rows = malloc(GRID_KEYS * sizeof(*b->rows));
    b->pts = malloc(GRID_PTS * sizeof(*b->pts));
    b->sum = malloc(WEB_WIFI_COLS * sizeof(*b->sum));
    b->cnt = malloc(WEB_WIFI_COLS * sizeof(*b->cnt));
    return b->keys && b->rows && b->pts && b->sum && b->cnt ? 0 : -1;
}

static void gbuf_free(gbuf_t *b) {
    free(b->keys); free(b->rows); free(b->pts); free(b->sum); free(b->cnt);
}

/* A row's worst case: its key and band, and every cell at 17 bytes. */
static size_t row_max(const grid_t *g, size_t extra) {
    return 160 + (size_t)g->ncol * 18 + extra;
}

/* ── /api/wifi/channels ──────────────────────────────────────────────── */

int web_wifi_channels_route(const web_m4_t *m, const char *query,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status) {
    if (!m || !m->tsdb)
        return answer_error(503, "no_time_series", NULL, body, cap, len, status);
    web_param_t ps[4] = {
        { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 },
        { "metric", "", 0 },
    };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    int metric = WM_WIFI_AP_COUNT;
    if (ps[3].seen) {
        if (!strcmp(ps[3].val, "ap_count")) metric = WM_WIFI_AP_COUNT;
        else if (!strcmp(ps[3].val, "ctrl_total")) metric = WM_WIFI_CTRL_TOTAL;
        else return answer_error(400, "unknown_metric", NULL, body, cap, len,
                                 status);
    }
    grid_t g;
    const char *why;
    if (grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, NULL, body, cap, len, status);
    gbuf_t b;
    if (gbuf_alloc(&b) != 0) { gbuf_free(&b); return -1; }
    int nk = grid_keys(m, metric, &g, b.keys);
    for (int i = 0; i < nk; i++) {
        snprintf(b.rows[i].key, sizeof(b.rows[i].key), "%s", b.keys[i]);
        web_channel_band(b.keys[i], &b.rows[i].rank);
        b.rows[i].num = strtol(b.keys[i] + (b.rows[i].rank == 2 ? 2 : 0), NULL, 10);
        b.rows[i].total = 0;
    }
    qsort(b.rows, (size_t)nk, sizeof(*b.rows), by_band);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    grid_head(&w, metric, &g);
    web_jw_raw(&w, ",\"total_keys\":"); web_jw_int(&w, nk);
    web_jw_raw(&w, ",\"channels\":[");
    int shown = 0;
    for (int i = 0; i < nk && shown < WEB_WIFI_ROWS; i++) {
        if (w.len + row_max(&g, 0) + 64 > cap) break;
        double total;
        if (grid_row(m, metric, &g, b.rows[i].key, b.pts, b.sum, b.cnt,
                     &total) != 0) {
            gbuf_free(&b);
            return -1;
        }
        int rank;
        const char *band = web_channel_band(b.rows[i].key, &rank);
        if (shown++) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"key\":");  web_jw_str(&w, b.rows[i].key);
        web_jw_raw(&w, ",\"band\":"); web_jw_str(&w, band);
        web_jw_raw(&w, ",\"cells\":");
        cells_json(&w, metric, &g, b.sum, b.cnt);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"shown\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");    web_jw_raw(&w, shown < nk ? "true" : "false");
    web_jw_raw(&w, "}\n");
    gbuf_free(&b);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/wifi/deauth ────────────────────────────────────────────────── */

typedef struct {
    web_jw_t *w;
    int       n, max;
} flood_t;

static int emit_flood(void *ctx, const web_sdb_item_t *it) {
    flood_t *f = ctx;
    if (f->n >= f->max) return 1;
    web_jw_raw(f->w, f->n++ ? ",[" : "[");
    web_jw_int(f->w, it->first_seen);
    web_jw_raw(f->w, ",");
    web_jw_int(f->w, it->last_seen);
    web_jw_raw(f->w, ",");
    web_jw_int(f->w, it->n2 < 0 ? 0 : it->n2 > 2 ? 2 : it->n2);
    web_jw_raw(f->w, ",");
    web_jw_int(f->w, it->has_n3 && it->n3 > 0 ? it->n3 : 0);
    web_jw_raw(f->w, "]");
    return 0;
}

int web_wifi_deauth_route(const web_m4_t *m, const char *query,
                          long long now_s, char *body, size_t cap,
                          size_t *len, int *status) {
    if (!m || !m->tsdb)
        return answer_error(503, "no_time_series", NULL, body, cap, len, status);
    web_param_t ps[3] = { { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    grid_t g;
    const char *why;
    if (grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, NULL, body, cap, len, status);
    const int metric = WM_WIFI_DEAUTH;
    gbuf_t b;
    if (gbuf_alloc(&b) != 0) { gbuf_free(&b); return -1; }
    int nk = grid_keys(m, metric, &g, b.keys);
    for (int i = 0; i < nk; i++) {
        snprintf(b.rows[i].key, sizeof(b.rows[i].key), "%s", b.keys[i]);
        if (grid_row(m, metric, &g, b.keys[i], b.pts, b.sum, b.cnt,
                     &b.rows[i].total) != 0) {
            gbuf_free(&b);
            return -1;
        }
    }
    qsort(b.rows, (size_t)nk, sizeof(*b.rows), by_total);

    web_sdb_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    char oerr[WEB_SDB_ERR_MAX] = "";
    int have_db = m->sdb && m->sdb->configured &&
                  web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                                   sizeof(oerr)) == 0;
    web_sdb_stats_t sst;
    memset(&sst, 0, sizeof(sst));
    if (m->sdb) web_slothdb_stats(m->sdb, &sst);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    grid_head(&w, metric, &g);
    web_jw_raw(&w, ",\"db\":");
    web_jw_str(&w, have_db ? "open" : m->sdb && m->sdb->configured
                   ? web_slothdb_state_word(sst.state) : "none");
    web_jw_raw(&w, ",\"total_keys\":"); web_jw_int(&w, nk);
    web_jw_raw(&w, ",\"bssids\":[");
    int shown = 0;
    /* Each flood is at most 48 bytes. */
    size_t extra = (size_t)(WEB_WIFI_FLOODS + 1) * 48;
    for (int i = 0; i < nk && shown < WEB_WIFI_ROWS; i++) {
        if (w.len + row_max(&g, extra) + 64 > cap) break;
        double total;
        if (grid_row(m, metric, &g, b.rows[i].key, b.pts, b.sum, b.cnt,
                     &total) != 0)
            break;
        if (shown++) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"bssid\":"); web_jw_str(&w, b.rows[i].key);
        web_jw_raw(&w, ",\"total\":");  jw_cell(&w, total);
        web_jw_raw(&w, ",\"cells\":");
        cells_json(&w, metric, &g, b.sum, b.cnt);
        web_jw_raw(&w, ",\"floods\":[");
        flood_t f = { &w, 0, WEB_WIFI_FLOODS };
        int got = have_db ? web_sdb_deauth_floods(&conn, b.rows[i].key, g.from,
                                                  g.to, WEB_WIFI_FLOODS + 1,
                                                  emit_flood, &f) : 0;
        web_jw_raw(&w, "],\"floods_more\":");
        web_jw_raw(&w, got > WEB_WIFI_FLOODS ? "true" : "false");
        web_jw_raw(&w, "}");
    }
    web_slothdb_close(&conn);
    web_jw_raw(&w, "],\"shown\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");    web_jw_raw(&w, shown < nk ? "true" : "false");
    web_jw_raw(&w, "}\n");
    gbuf_free(&b);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/wifi/aps ───────────────────────────────────────────────────── */

typedef struct {
    web_sdb_ap_t *rows;
    int           n, cap;
} apcol_t;

static int collect_ap(void *ctx, const web_sdb_ap_t *a) {
    apcol_t *c = ctx;
    if (c->n >= c->cap) return 1;
    c->rows[c->n++] = *a;
    return 0;
}

typedef struct {
    web_jw_t *w;
    int       n, max;
} ssids_t;

static int emit_ssid(void *ctx, const web_sdb_item_t *it) {
    ssids_t *s = ctx;
    if (s->n >= s->max) return 1;
    web_jw_raw(s->w, s->n++ ? ",{\"ssid\":" : "{\"ssid\":");
    web_jw_str(s->w, it->a);
    web_jw_raw(s->w, ",\"first_seen\":"); web_jw_int(s->w, it->first_seen);
    web_jw_raw(s->w, ",\"last_seen\":");  web_jw_int(s->w, it->last_seen);
    web_jw_raw(s->w, "}");
    return 0;
}

static void ap_json(web_jw_t *w, web_sdb_conn_t *c, const web_sdb_ap_t *a) {
    web_jw_raw(w, "{\"bssid\":");    web_jw_str(w, a->bssid);
    web_jw_raw(w, ",\"ssid\":");     jw_text_or_null(w, a->ssid);
    web_jw_raw(w, ",\"signal\":");
    if (a->has_signal)
        web_jw_int(w, a->signal_dbm < -200 ? -200 : a->signal_dbm > 50 ? 50
                                                  : a->signal_dbm);
    else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"channel\":");  web_jw_int(w, a->channel & 0xffff);
    web_jw_raw(w, ",\"enc\":");      jw_text_or_null(w, a->enc);
    web_jw_raw(w, ",\"akm\":");      jw_text_or_null(w, a->akm);
    unsigned long long bits = (unsigned long long)a->akm_bits & 0xffffffffULL;
    web_jw_raw(w, ",\"akm_bits\":"); web_jw_int(w, (long long)bits);
    web_jw_raw(w, ",\"akm_names\":[");
    int k = 0;
    for (int t = 0; t < 32; t++) {
        if (!(bits & (1ULL << t))) continue;
        const char *nm = web_akm_name(t);
        char other[16];
        if (!strcmp(nm, "?")) { snprintf(other, sizeof(other), "AKM-%d", t); nm = other; }
        if (k++) web_jw_raw(w, ",");
        web_jw_str(w, nm);
    }
    web_jw_raw(w, "]");
    static const char *const MFP[] = { "off", "capable", "required" };
    long long mfp = a->mfp < 0 ? 0 : a->mfp > 2 ? 2 : a->mfp;
    web_jw_raw(w, ",\"mfp\":");      web_jw_int(w, mfp);
    web_jw_raw(w, ",\"mfp_word\":"); web_jw_str(w, MFP[mfp]);
    long long dg = a->downgrade & 0xff;
    web_jw_raw(w, ",\"downgrade\":"); web_jw_int(w, dg);
    web_jw_raw(w, ",\"downgrade_names\":[");
    k = 0;
    for (int bit = 0; bit < 8; bit++) {
        if (!(dg & (1 << bit))) continue;
        const char *nm = web_downgrade_name(bit);
        char other[16];
        if (!nm) { snprintf(other, sizeof(other), "flag-%d", bit); nm = other; }
        if (k++) web_jw_raw(w, ",");
        web_jw_str(w, nm);
    }
    web_jw_raw(w, "]");
    web_jw_raw(w, ",\"vendor\":");   jw_text_or_null(w, a->vendor);
    web_jw_raw(w, ",\"phy\":");      jw_text_or_null(w, a->phy);
    web_jw_raw(w, ",\"wps\":");      web_jw_raw(w, a->has_wps ? "true" : "false");
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, a->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, a->last_seen);
    long long sc = a->ssid_count < 0 ? 0 : a->ssid_count;
    web_jw_raw(w, ",\"ssid_count\":"); web_jw_int(w, sc);
    web_jw_raw(w, ",\"multi_ssid\":"); web_jw_raw(w, sc > 1 ? "true" : "false");
    web_jw_raw(w, ",\"ssids\":[");
    ssids_t s = { w, 0, WEB_WIFI_SSIDS };
    int got = web_sdb_ap_ssids(c, a->bssid, WEB_WIFI_SSIDS + 1, emit_ssid, &s);
    web_jw_raw(w, "],\"ssids_more\":");
    web_jw_raw(w, got > WEB_WIFI_SSIDS ? "true" : "false");
    web_jw_raw(w, ",\"karma\":");
    if (!a->has_karma) {
        web_jw_raw(w, "null");
    } else {
        web_jw_raw(w, "{\"score\":");        web_jw_int(w, a->k_score);
        web_jw_raw(w, ",\"ssid_count\":");   web_jw_int(w, a->k_ssids);
        web_jw_raw(w, ",\"pnl_overlap\":");  web_jw_int(w, a->k_overlap);
        web_jw_raw(w, ",\"ie_uniform\":");   web_jw_raw(w, a->k_ie_uniform ? "true" : "false");
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "}");
}

int web_wifi_aps_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status) {
    if (!m || !m->sdb || !m->sdb->configured || !web_slothdb_available())
        return answer_error(503, "no_sloth_db",
                            "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                            body, cap, len, status);
    web_param_t ps[3] = { { "sort", "", 0 }, { "limit", "", 0 },
                          { "offset", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    static const char *const SORT[WEB_AP_SORT_COUNT] = { "last", "ssids",
                                                         "karma", "bssid" };
    int sort = WEB_AP_SORT_LAST;
    if (ps[0].seen) {
        sort = -1;
        for (int i = 0; i < WEB_AP_SORT_COUNT; i++)
            if (!strcmp(ps[0].val, SORT[i])) sort = i;
        if (sort < 0) return answer_error(400, "bad_sort", NULL, body, cap, len, status);
    }
    long long limit = WEB_WIFI_AP_LIMIT, offset = 0;
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_WIFI_AP_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, 0, WEB_DEV_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);

    web_sdb_conn_t conn;
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                         sizeof(oerr)) != 0) {
        web_slothdb_close(&conn);
        web_sdb_stats_t st;
        web_slothdb_stats(m->sdb, &st);
        char r[48];
        snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
        return answer_error(503, r, oerr, body, cap, len, status);
    }
    apcol_t c = { calloc((size_t)limit + 1, sizeof(web_sdb_ap_t)), 0,
                  (int)limit + 1 };
    if (!c.rows) { web_slothdb_close(&conn); return -1; }
    int got = web_sdb_aps(&conn, sort, limit + 1, offset, collect_ap, &c);
    if (got < 0) {
        int to = conn.timed_out;
        web_slothdb_close(&conn);
        free(c.rows);
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error",
                            NULL, body, cap, len, status);
    }
    int show = c.n > limit ? (int)limit : c.n;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");     web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"sort\":");    web_jw_str(&w, SORT[sort]);
    web_jw_raw(&w, ",\"limit\":");   web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":");  web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int i = 0; i < show; i++) {
        if (w.len + WEB_WIFI_AP_ROW_MAX + 96 > cap) break;
        if (i) web_jw_raw(&w, ",");
        ap_json(&w, &conn, &c.rows[i]);
        shown++;
    }
    web_slothdb_close(&conn);
    int more = shown < c.n;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");     web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    web_jw_raw(&w, "}\n");
    free(c.rows);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
