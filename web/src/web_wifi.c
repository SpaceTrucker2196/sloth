#include "web_wifi.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_metrics.h"
#include "web_rf.h"
#include "web_series.h"
#include "web_ssid.h"
#include "web_chmix.h"
#include "web_chain.h"
#include "web_own.h"

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

typedef web_grid_t grid_t;

#define GRID_KEYS WEB_GRID_KEYS
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
int web_grid_of(const web_m4_t *m, const web_param_t *ps, long long now,
                web_grid_t *g, const char **why) {
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

/* The plain grid for another view (web_bledev.c): one key's cells. */
int web_grid_keys(const web_m4_t *m, int metric, const web_grid_t *g,
                  char (*keys)[WEB_KEY_MAX + 1]) {
    return grid_keys(m, metric, g, keys);
}

int web_grid_cells_json(const web_m4_t *m, int metric, const web_grid_t *g,
                        const char *key, web_jw_t *w, double *total) {
    web_point_t *pts = malloc(GRID_PTS * sizeof(*pts));
    double *sum = malloc(WEB_WIFI_COLS * sizeof(*sum));
    int *cnt = malloc(WEB_WIFI_COLS * sizeof(*cnt));
    int rc = -1;
    if (pts && sum && cnt && grid_row(m, metric, g, key, pts, sum, cnt, total) == 0) {
        cells_json(w, metric, g, sum, cnt);
        rc = 0;
    }
    free(pts); free(sum); free(cnt);
    return rc;
}

void web_grid_head(web_jw_t *w, int metric, const web_grid_t *g) {
    grid_head(w, metric, g);
}

/* ── /api/wifi/channels?mix=1 ────────────────────────────────────────── */

/* The aggregation behind one answer. Every channel and transmitter the
 * range holds is folded into the grid's cells: a cell tracks at most
 * MIX_CELL_TRACK transmitters (a fine cell holds a few closed buckets of
 * five each; a minute or hour cell a few more), and one past that goes
 * to "other" as web_chmix.c folds them. Cut to the top WEB_CHMIX_TOP on
 * the way out. */
#define MIX_CELL_TRACK 24
#define MIX_TXD        1024
#define MIX_TXH        2048          /* a power of two, twice MIX_TXD */
#define MIX_READ_MAX   250000        /* store rows read for one answer */
/* The answer's transmitter table: at most this many, in this many bytes
 * (an AP's entry is at most about 500 bytes: its vendor and its SSID
 * in their escaped forms). The rest of the answer is the rows. */
#define MIX_DICT_MAX   160
#define MIX_DICT_BYTES 20480

typedef struct {
    int16_t  tx;
    uint32_t f;
} mcell_e_t;

/* The client lane (owner 2026-11-17: "the spectrum should show where
 * the clients sit in the spectrum highlighting their channel"). The mix
 * names a bucket's five busiest transmitters and folds the rest into
 * "other", so a client is seen only in a bucket where it was one of the
 * five: a cell's client count is the distinct clients named in its
 * buckets, a floor (at most MIX_CELL_CL of them; "clients_cell_cut" past
 * that), and a client that never made a bucket's five is not in the
 * list. A client's frames are its probe requests (web_chmix.h). */
#define MIX_CELL_CL    32
#define MIX_CL_CH      8             /* channels kept per client */
#define MIX_CL_MAX     64            /* clients the answer lists */
#define MIX_CL_BYTES   16384

typedef struct {
    uint32_t  other;
    int       n;
    mcell_e_t e[MIX_CELL_TRACK];
    uint8_t   ncl, cl_cut;
    int16_t   cl[MIX_CELL_CL];
} mcell_t;

/* One client's window: its frames per channel (the busiest MIX_CL_CH
 * channels it was named on; ch_cut past that), the cells it was named
 * in on each, and the bounds of the buckets it was named in. */
#define MIX_CL_WORDS ((WEB_WIFI_COLS + 31) / 32)
typedef struct {
    unsigned long long frames;
    long long first, last;
    int       nch, ch_cut;
    int16_t   ch[MIX_CL_CH];
    unsigned long long chf[MIX_CL_CH];
    uint32_t  cols[MIX_CL_CH][MIX_CL_WORDS];
} mcl_t;

typedef struct {
    char      key[WEB_CHMIX_KEY_MAX + 1];
    int       idx;                     /* its place in magg_t's ch[] */
    int       rank;
    long      num;
    unsigned long long total;
} mchan_t;

typedef struct {
    uint8_t mac[6];
    uint8_t kind;
    int     out;                       /* index in the answer's tx, -1 */
} mtx_t;

typedef struct {
    const grid_t *g;
    const web_mix_ops_t *ops;
    mchan_t  ch[WEB_CHMIX_CHANNELS];
    int      nch, cut_ch;
    mcell_t *cells;                    /* WEB_CHMIX_CHANNELS x ncol */
    mtx_t    tx[MIX_TXD];
    int      ntx, cut_tx;
    int16_t  hash[MIX_TXH];
    mcl_t   *cl;                       /* MIX_TXD, when ops->clients */
    int      cell_cut;
} magg_t;

static uint32_t sat32(uint32_t a, unsigned long long b) {
    unsigned long long s = (unsigned long long)a + b;
    return s > 0xffffffffULL ? 0xffffffffu : (uint32_t)s;
}

static int mix_chan(magg_t *a, const char *key) {
    for (int i = 0; i < a->nch; i++)
        if (!strcmp(a->ch[i].key, key)) return i;
    if (a->nch >= WEB_CHMIX_CHANNELS) { a->cut_ch = 1; return -1; }
    int rank = 0;
    long num = 0;
    /* Read back from the store as if off the wire: a key slothweb did not
     * write is not shown. */
    if (a->ops->key(key, &rank, &num) != 0) return -1;
    mchan_t *c = &a->ch[a->nch];
    snprintf(c->key, sizeof(c->key), "%s", key);
    c->idx = a->nch;
    c->rank = rank;
    c->num = num;
    c->total = 0;
    return a->nch++;
}

/* The WiFi mix's keys: canonical channel keys, by band then number. */
static int wifi_mix_key(const char *key, int *rank, long *num) {
    char canon[WEB_KEY_MAX + 1];
    if (web_key_channel_text(key, canon) != 0 || strcmp(canon, key)) return -1;
    web_channel_band(key, rank);
    *num = strtol(key + (*rank == 2 ? 2 : 0), NULL, 10);
    return 0;
}

static int mix_tx(magg_t *a, const uint8_t mac[6], int kind) {
    unsigned h = 2166136261u;
    for (int i = 0; i < 6; i++) h = (h ^ mac[i]) * 16777619u;
    h = (h ^ (unsigned)kind) * 16777619u;
    for (unsigned k = 0; k < MIX_TXH; k++) {
        unsigned s = (h + k) & (MIX_TXH - 1);
        int i = a->hash[s];
        if (i < 0) {
            if (a->ntx >= MIX_TXD) { a->cut_tx = 1; return -1; }
            i = a->ntx++;
            memcpy(a->tx[i].mac, mac, 6);
            a->tx[i].kind = (uint8_t)kind;
            a->tx[i].out = -1;
            a->hash[s] = (int16_t)i;
            return i;
        }
        if (a->tx[i].kind == kind && !memcmp(a->tx[i].mac, mac, 6)) return i;
    }
    a->cut_tx = 1;
    return -1;
}

/* A client x named with f frames on channel c in cell at bucket t. */
static void mix_client(magg_t *a, mcell_t *cell, int c, int x, long long t,
                       long long col, unsigned long long f) {
    int seen = 0;
    for (int i = 0; i < cell->ncl; i++) if (cell->cl[i] == x) { seen = 1; break; }
    if (!seen) {
        if (cell->ncl < MIX_CELL_CL) cell->cl[cell->ncl++] = (int16_t)x;
        else { cell->cl_cut = 1; a->cell_cut = 1; }
    }
    mcl_t *k = &a->cl[x];
    long long end = t + a->g->step;
    if (!k->frames || t < k->first) k->first = t;
    if (!k->frames || end > k->last) k->last = end;
    k->frames += f;
    int s = -1;
    for (int i = 0; i < k->nch; i++) if (k->ch[i] == c) { s = i; break; }
    if (s < 0 && k->nch < MIX_CL_CH) {
        s = k->nch++;
        k->ch[s] = (int16_t)c;
        k->chf[s] = 0;
        memset(k->cols[s], 0, sizeof(k->cols[s]));
    } else if (s < 0) {
        /* Full: the quietest gives way to a busier one, as a cell's do. */
        int q = 0;
        for (int i = 1; i < k->nch; i++) if (k->chf[i] < k->chf[q]) q = i;
        k->ch_cut = 1;
        if (f <= k->chf[q]) return;
        s = q;
        k->ch[s] = (int16_t)c;
        k->chf[s] = 0;
        memset(k->cols[s], 0, sizeof(k->cols[s]));
    }
    k->chf[s] += f;
    if (col >= 0 && col < WEB_WIFI_COLS)
        k->cols[s][col / 32] |= 1u << (col % 32);
}

/* f frames on chan at t from the transmitter mac (NULL: the rest). */
static void mix_put(magg_t *a, const char *chan, long long t,
                    const uint8_t *mac, int kind, unsigned long long f) {
    const grid_t *g = a->g;
    if (f == 0 || t < g->from || t >= g->to) return;
    long long col = (t - g->from) / g->col_s;
    if (col < 0 || col >= g->ncol) return;
    int c = mix_chan(a, chan);
    if (c < 0) return;
    a->ch[c].total += f;
    mcell_t *cell = &a->cells[(size_t)c * (size_t)g->ncol + (size_t)col];
    int x = mac ? mix_tx(a, mac, kind) : -1;
    if (x < 0) { cell->other = sat32(cell->other, f); return; }
    if (a->cl && kind == WEB_TX_CLIENT) mix_client(a, cell, c, x, t, col, f);
    for (int i = 0; i < cell->n; i++)
        if (cell->e[i].tx == x) { cell->e[i].f = sat32(cell->e[i].f, f); return; }
    if (cell->n < MIX_CELL_TRACK) {
        cell->e[cell->n].tx = (int16_t)x;
        cell->e[cell->n].f = sat32(0, f);
        cell->n++;
        return;
    }
    int q = 0;
    for (int i = 1; i < cell->n; i++) if (cell->e[i].f < cell->e[q].f) q = i;
    if (f > cell->e[q].f) {
        cell->other = sat32(cell->other, cell->e[q].f);
        cell->e[q].tx = (int16_t)x;
        cell->e[q].f = sat32(0, f);
    } else {
        cell->other = sat32(cell->other, f);
    }
}

static int mix_from_ring(void *ctx, const web_mix_row_t *r) {
    magg_t *a = ctx;
    for (int i = 0; i < r->n && i < WEB_CHMIX_TOP; i++)
        mix_put(a, r->chan, r->t, r->tx[i].mac, r->tx[i].kind, r->tx[i].frames);
    mix_put(a, r->chan, r->t, NULL, 0, r->other);
    return 0;
}

static int mix_from_store(void *ctx, const char *chan, long long t,
                          const char *tx, int kind, long long frames) {
    magg_t *a = ctx;
    uint8_t mac[6];
    if (frames <= 0) return 0;
    if (!tx[0]) { mix_put(a, chan, t, NULL, 0, (unsigned long long)frames); return 0; }
    if (kind < 0 || kind > 7 || !(a->ops->kinds & (1u << kind)) ||
        web_mix_mac_bytes(tx, mac) != 0)
        return 0;
    mix_put(a, chan, t, mac, kind, (unsigned long long)frames);
    return 0;
}

static int by_cell_f(const void *x, const void *y) {
    const mcell_e_t *a = x, *b = y;
    if (a->f != b->f) return a->f > b->f ? -1 : 1;
    return a->tx - b->tx;
}

/* qsort() has no context: the frames by_tx_frames() sorts by, set
 * around the one call on the HTTP thread. */
static const unsigned long long *g_mix_txf;

static int by_tx_frames(const void *x, const void *y) {
    int a = *(const int *)x, b = *(const int *)y;
    if (g_mix_txf[a] != g_mix_txf[b]) return g_mix_txf[a] > g_mix_txf[b] ? -1 : 1;
    return a - b;
}

static int by_mix_band(const void *x, const void *y) {
    const mchan_t *a = x, *b = y;
    if (a->rank != b->rank) return a->rank - b->rank;
    if (a->num != b->num) return a->num < b->num ? -1 : 1;
    return strcmp(a->key, b->key);
}

/* An AP's SSID: sloth.db's octets first, they are the TUI's
 * (web_ssid.h), then the stream's. The source, or NULL with ssid "". */
#define AP_SSID_BUF ((WEB_SDB_TEXT_MAX > WEB_CHMIX_SSID_MAX ? WEB_SDB_TEXT_MAX \
                                                            : WEB_CHMIX_SSID_MAX) + 1)
static const char *ap_ssid_of(const web_m4_t *m, web_sdb_conn_t *conn,
                              const uint8_t bssid[6], char ssid[AP_SSID_BUF]) {
    char mac[18];
    web_mix_mac_text(bssid, mac);
    ssid[0] = '\0';
    if (conn && web_sdb_ap_ssid(conn, mac, ssid) == 1) return "sloth.db";
    if (m->tsdb && m->tsdb->mix && web_chmix_ssid(m->tsdb->mix, bssid, ssid))
        return "stream";
    ssid[0] = '\0';
    return NULL;
}

/* One transmitter of the WiFi answer's tx list. */
static void wifi_tx_json(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *conn,
                         const uint8_t txmac[6], int kind, void *ctx) {
    (void)ctx;
    char mac[18];
    web_mix_mac_text(txmac, mac);
    web_jw_raw(w, "{\"id\":");   web_jw_str(w, mac);
    web_jw_raw(w, ",\"kind\":"); web_jw_str(w, kind == WEB_TX_AP ? "ap" : "client");
    web_oui_hit_t hit;
    memset(&hit, 0, sizeof(hit));
    if (m->oui) web_oui_lookup(m->oui, txmac, &hit);
    web_jw_raw(w, ",\"vendor\":");
    if (hit.found) web_jw_str(w, hit.name); else web_jw_raw(w, "null");
    if (kind == WEB_TX_AP) {
        char ssid[AP_SSID_BUF];
        const char *src = ap_ssid_of(m, conn, txmac, ssid);
        web_jw_raw(w, ",\"ssid\":"); web_jw_ssid(w, ssid);
        web_jw_ssid_meta(w, "ssid", ssid);
        web_jw_raw(w, ",\"ssid_src\":");
        if (src && ssid[0]) web_jw_str(w, src); else web_jw_raw(w, "null");
    }
    web_jw_raw(w, "}");
}

/* ── the client lane ─────────────────────────────────────────────────── */

int web_wifi_test_expire;

/* sloth.db's newest association of a station: its BSSID. */
typedef struct { char bssid[WEB_SDB_TEXT_MAX + 1]; int got; } first_assoc_t;
static int take_first_assoc(void *ctx, const web_sdb_item_t *it) {
    first_assoc_t *f = ctx;
    snprintf(f->bssid, sizeof(f->bssid), "%s", it->a);
    f->got = 1;
    return 1;
}

static int by_cl_ch(const void *x, const void *y, const mcl_t *k) {
    int a = *(const int *)x, b = *(const int *)y;
    if (k->chf[a] != k->chf[b]) return k->chf[a] > k->chf[b] ? -1 : 1;
    return a - b;
}

/* One client of the answer's "clients": its MAC, vendor, whether the MAC
 * is locally administered (randomised), its frames and the bounds of
 * the buckets it was named in, its channels busiest first, its index in
 * "tx" (null when the table had no room), and its AP: sloth.db's newest
 * association, else the stream's newest assoc record, named as the AP's
 * own transmitter entry is (ap_ssid_of()), so its colour is the AP's.
 * *db_cut once sloth.db's budget is spent: the rest from the stream. */
static void client_json(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *conn,
                        const magg_t *a, int x, int *db_cut) {
    const mcl_t *k = &a->cl[x];
    const uint8_t *mac = a->tx[x].mac;
    char id[18];
    web_mix_mac_text(mac, id);
    web_jw_raw(w, "{\"id\":"); web_jw_str(w, id);
    web_oui_hit_t hit;
    memset(&hit, 0, sizeof(hit));
    if (m->oui) web_oui_lookup(m->oui, mac, &hit);
    web_jw_raw(w, ",\"vendor\":");
    if (hit.found) web_jw_str(w, hit.name); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"laa\":"); web_jw_raw(w, mac[0] & 0x02 ? "true" : "false");
    web_jw_raw(w, ",\"frames\":"); web_jw_int(w, (long long)(k->frames > 0x7fffffffffffULL
                                                           ? 0x7fffffffffffULL : k->frames));
    web_jw_raw(w, ",\"first\":"); web_jw_int(w, k->first);
    web_jw_raw(w, ",\"last\":");  web_jw_int(w, k->last);
    int ord[MIX_CL_CH];
    for (int i = 0; i < k->nch; i++) ord[i] = i;
    for (int i = 1; i < k->nch; i++)          /* at most eight: insertion */
        for (int j = i; j > 0 && by_cl_ch(&ord[j - 1], &ord[j], k) > 0; j--) {
            int t = ord[j]; ord[j] = ord[j - 1]; ord[j - 1] = t;
        }
    web_jw_raw(w, ",\"chans\":[");
    for (int i = 0; i < k->nch; i++) {
        web_jw_raw(w, i ? ",[" : "[");
        web_jw_str(w, a->ch[k->ch[ord[i]]].key);
        web_jw_raw(w, ",");
        web_jw_int(w, (long long)(k->chf[ord[i]] > 0x7fffffffffffULL ? 0x7fffffffffffULL
                                                                    : k->chf[ord[i]]));
        /* Its cells as hex, a digit four cells, the first the high bit. */
        char hex[WEB_WIFI_COLS / 4 + 2];
        int nd = (a->g->ncol + 3) / 4;
        if (nd > WEB_WIFI_COLS / 4) nd = WEB_WIFI_COLS / 4;
        for (int d = 0; d < nd; d++) {
            unsigned v = 0;
            for (int b = 0; b < 4; b++) {
                int col = d * 4 + b;
                if (col < a->g->ncol && (k->cols[ord[i]][col / 32] >> (col % 32) & 1u))
                    v |= 8u >> b;
            }
            hex[d] = "0123456789abcdef"[v];
        }
        hex[nd] = '\0';
        web_jw_raw(w, ",\"");
        web_jw_raw(w, hex);
        web_jw_raw(w, "\"]");
    }
    web_jw_raw(w, "],\"chans_more\":"); web_jw_raw(w, k->ch_cut ? "true" : "false");
    web_jw_raw(w, ",\"tx\":");
    if (a->tx[x].out >= 0) web_jw_int(w, a->tx[x].out); else web_jw_raw(w, "null");
    uint8_t bssid[6];
    const char *asrc = NULL;
    if (conn && !*db_cut) {
        if (web_sdb_spent(conn)) *db_cut = 1;
        else {
            first_assoc_t f;
            memset(&f, 0, sizeof(f));
            if (web_sdb_assocs(conn, id, 1, take_first_assoc, &f) > 0 && f.got &&
                web_mix_mac_bytes(f.bssid, bssid) == 0)
                asrc = "sloth.db";
            else if (conn->timed_out)
                *db_cut = 1;
        }
    }
    if (!asrc && m->tsdb && m->tsdb->mix && web_chmix_sta_bssid(m->tsdb->mix, mac, bssid))
        asrc = "stream";
    web_jw_raw(w, ",\"assoc\":");
    if (!asrc) { web_jw_raw(w, "null}"); return; }
    char bt[18], ssid[AP_SSID_BUF];
    web_mix_mac_text(bssid, bt);
    const char *ssrc = ap_ssid_of(m, *db_cut ? NULL : conn, bssid, ssid);
    web_jw_raw(w, "{\"bssid\":"); web_jw_str(w, bt);
    web_jw_raw(w, ",\"src\":"); web_jw_str(w, asrc);
    web_jw_raw(w, ",\"ssid\":"); web_jw_ssid(w, ssid);
    web_jw_ssid_meta(w, "ssid", ssid);
    web_jw_raw(w, ",\"ssid_src\":");
    if (ssrc && ssid[0]) web_jw_str(w, ssrc); else web_jw_raw(w, "null");
    web_jw_raw(w, "}}");
}

/* The answer's "clients" members into w: every client the window named,
 * busiest first, at most MIX_CL_MAX in w's bytes. */
static void clients_json(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *conn,
                         magg_t *a, unsigned long long *frames, int *byf) {
    int n = 0;
    for (int i = 0; i < a->ntx; i++)
        if (a->tx[i].kind == WEB_TX_CLIENT && a->cl[i].frames) {
            byf[n] = i;
            frames[i] = a->cl[i].frames;
            n++;
        }
    g_mix_txf = frames;
    qsort(byf, (size_t)n, sizeof(*byf), by_tx_frames);
    g_mix_txf = NULL;
    int shown = 0, more = 0, db_cut = 0;
    web_jw_raw(w, ",\"clients\":[");
    for (int i = 0; i < n; i++) {
        if (shown >= MIX_CL_MAX) { more = 1; break; }
        size_t mark = w->len;
        if (shown) web_jw_raw(w, ",");
        client_json(w, m, conn, a, byf[i], &db_cut);
        /* Room for the members after the list. */
        if (w->overflow || w->len + 128 > w->cap) {
            w->overflow = 0;
            w->len = mark;
            w->buf[mark] = '\0';
            more = 1;
            break;
        }
        shown++;
    }
    web_jw_raw(w, "],\"clients_total\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"clients_more\":"); web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, ",\"clients_cell_cut\":"); web_jw_raw(w, a->cell_cut ? "true" : "false");
    web_jw_raw(w, ",\"clients_db_cut\":"); web_jw_raw(w, db_cut ? "true" : "false");
}

static void wifi_row_extra(web_jw_t *w, const char *key, void *ctx) {
    (void)ctx;
    int rank;
    web_jw_raw(w, ",\"band\":");  web_jw_str(w, web_channel_band(key, &rank));
}

int web_mix_answer(const web_m4_t *m, const web_grid_t *g, const web_mix_ops_t *ops,
                   long long now_s, char *body, size_t cap, size_t *len, int *status) {
    web_chmix_t *mix = ops->mix;
    magg_t *a = calloc(1, sizeof(*a));
    mcell_t *cells = calloc((size_t)WEB_CHMIX_CHANNELS * (size_t)g->ncol,
                            sizeof(*cells));
    char *dict = malloc(cap), *rows = malloc(cap), *row = malloc(cap);
    if (!a || !cells || !dict || !rows || !row) {
        free(a); free(cells); free(dict); free(rows); free(row);
        return -1;
    }
    a->g = g;
    a->ops = ops;
    a->cells = cells;
    char *clb = NULL;
    if (ops->clients) {
        a->cl = calloc(MIX_TXD, sizeof(*a->cl));
        clb = malloc(MIX_CL_BYTES);
        if (!a->cl || !clb) {
            free(a->cl); free(clb);
            free(a); free(cells); free(dict); free(rows); free(row);
            return -1;
        }
    }
    for (int i = 0; i < MIX_TXH; i++) a->hash[i] = -1;
    int read_more = 0;
    long long nread = 0;
    const char *source = "memory";
    if (g->tier == WEB_TIER_FINE) {
        nread = web_chmix_each_fine(mix, g->from, g->to, mix_from_ring, a);
    } else if (m->tsdb->store && m->tsdb->store->rd) {
        source = "store";
        nread = web_store_mix_query_ns(m->tsdb->store, ops->ns, g->tier, g->from,
                                       g->to, MIX_READ_MAX, mix_from_store, a,
                                       &read_more);
        if (nread < 0) {
            free(a->cl); free(clb);
            free(a); free(cells); free(dict); free(rows); free(row);
            return answer_error(503, "store_error", NULL, body, cap, len, status);
        }
    }
    /* Band order: the rows move, so each keeps its cells' offset. */
    int order[WEB_CHMIX_CHANNELS];
    mchan_t sorted[WEB_CHMIX_CHANNELS];
    memset(sorted, 0, sizeof(sorted));
    memcpy(sorted, a->ch, (size_t)a->nch * sizeof(sorted[0]));
    qsort(sorted, (size_t)a->nch, sizeof(sorted[0]), by_mix_band);
    for (int i = 0; i < a->nch; i++) order[i] = sorted[i].idx;

    web_sdb_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    char oerr[WEB_SDB_ERR_MAX] = "";
    int have_db = ops->use_db && m->sdb && m->sdb->configured &&
                  web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                                   sizeof(oerr)) == 0;

    /* The transmitters the answer names: the busiest over the whole
     * range first, while the table stays within MIX_DICT_BYTES and
     * MIX_DICT_MAX entries. A cell's five are its busiest among those;
     * the frames of any other are in its "other" ("folded"). */
    unsigned long long *txf = calloc((size_t)(a->ntx ? a->ntx : 1), sizeof(*txf));
    int *byf = malloc((size_t)(a->ntx ? a->ntx : 1) * sizeof(*byf));
    if (!txf || !byf) {
        free(txf); free(byf);
        web_slothdb_close(&conn);
        free(a->cl); free(clb);
        free(a); free(cells); free(dict); free(rows); free(row);
        return -1;
    }
    for (size_t k = 0; k < (size_t)WEB_CHMIX_CHANNELS * (size_t)g->ncol; k++)
        for (int i = 0; i < cells[k].n; i++) txf[cells[k].e[i].tx] += cells[k].e[i].f;
    for (int i = 0; i < a->ntx; i++) byf[i] = i;
    g_mix_txf = txf;
    qsort(byf, (size_t)a->ntx, sizeof(*byf), by_tx_frames);
    g_mix_txf = NULL;
    web_jw_t dw, rw;
    web_jw_init(&dw, dict, cap < MIX_DICT_BYTES ? cap : MIX_DICT_BYTES);
    web_jw_init(&rw, rows, cap);
    int nout = 0, folded = a->cut_tx;
    for (int k = 0; k < a->ntx; k++) {
        if (nout >= MIX_DICT_MAX) { folded = 1; break; }
        size_t mark = dw.len;
        if (nout) web_jw_raw(&dw, ",");
        ops->tx_json(&dw, m, have_db ? &conn : NULL, a->tx[byf[k]].mac,
                     a->tx[byf[k]].kind, ops->ctx);
        if (dw.overflow) {
            dw.overflow = 0;
            dw.len = mark;
            dict[mark] = '\0';
            folded = 1;
            break;
        }
        a->tx[byf[k]].out = nout++;
    }
    /* The client list, after the table so it can point into it. */
    web_jw_t cw;
    web_jw_init(&cw, clb ? clb : row, clb ? MIX_CL_BYTES : 1);
    if (clb) {
        if (have_db && web_wifi_test_expire) conn.deadline_ms = 0;
        memset(txf, 0, (size_t)(a->ntx ? a->ntx : 1) * sizeof(*txf));
        clients_json(&cw, m, have_db ? &conn : NULL, a, txf, byf);
    }
    free(txf);
    free(byf);
    /* Rows a row at a time, and only while the whole answer still fits. */
    size_t head_max = 720, tail_max = 160 + ops->tail_max;
    int shown = 0, rows_cut = 0;
    for (int oi = 0; oi < a->nch && shown < WEB_WIFI_ROWS; oi++) {
        int ci = order[oi];
        const mchan_t *c = &a->ch[ci];
        web_jw_t r;
        web_jw_init(&r, row, cap);
        web_jw_raw(&r, shown ? ",{\"key\":" : "{\"key\":");
        web_jw_str(&r, c->key);
        ops->row_extra(&r, c->key, ops->ctx);
        web_jw_raw(&r, ",\"total\":");
        web_jw_int(&r, (long long)(c->total > 0x7fffffffffffULL ? 0x7fffffffffffULL
                                                                 : c->total));
        web_jw_raw(&r, ",\"cells\":[");
        for (int col = 0; col < g->ncol; col++) {
            mcell_t *cell = &cells[(size_t)ci * (size_t)g->ncol + (size_t)col];
            if (col) web_jw_raw(&r, ",");
            if (!cell->n && !cell->other) { web_jw_raw(&r, "null"); continue; }
            qsort(cell->e, (size_t)cell->n, sizeof(cell->e[0]), by_cell_f);
            unsigned long long other = cell->other;
            unsigned long long total = other;
            int keep = 0, pick[WEB_CHMIX_TOP];
            for (int i = 0; i < cell->n; i++) {
                total += cell->e[i].f;
                if (keep < WEB_CHMIX_TOP && a->tx[cell->e[i].tx].out >= 0)
                    pick[keep++] = i;
                else
                    other += cell->e[i].f;
            }
            web_jw_raw(&r, "[");
            web_jw_int(&r, (long long)total);
            web_jw_raw(&r, ",");
            web_jw_int(&r, (long long)other);
            for (int i = 0; i < keep; i++) {
                web_jw_raw(&r, ",");
                web_jw_int(&r, a->tx[cell->e[pick[i]].tx].out);
                web_jw_raw(&r, ",");
                web_jw_int(&r, (long long)cell->e[pick[i]].f);
            }
            web_jw_raw(&r, "]");
        }
        web_jw_raw(&r, "]");
        /* The client lane: each cell's distinct clients named (null
         * where the cell is). */
        if (a->cl) {
            web_jw_raw(&r, ",\"clients\":[");
            for (int col = 0; col < g->ncol; col++) {
                const mcell_t *cell = &cells[(size_t)ci * (size_t)g->ncol + (size_t)col];
                if (col) web_jw_raw(&r, ",");
                if (!cell->n && !cell->other) web_jw_raw(&r, "null");
                else web_jw_int(&r, cell->ncl);
            }
            web_jw_raw(&r, "]");
        }
        web_jw_raw(&r, "}");
        if (r.overflow ||
            head_max + dw.len + rw.len + r.len + tail_max + (clb ? cw.len : 0) > cap) {
            rows_cut = 1;
            break;
        }
        web_jw_raw(&rw, row);
        shown++;
    }
    web_slothdb_close(&conn);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"metric\":");  web_jw_str(&w, ops->metric);
    web_jw_raw(&w, ",\"kind\":\"counter\",\"unit\":");  web_jw_str(&w, ops->unit);
    web_jw_raw(&w, ",\"tier\":");    web_jw_str(&w, web_tier_name(g->tier));
    web_jw_raw(&w, ",\"step\":");    web_jw_int(&w, g->step);
    web_jw_raw(&w, ",\"from\":");    web_jw_int(&w, g->from);
    web_jw_raw(&w, ",\"to\":");      web_jw_int(&w, g->to);
    web_jw_raw(&w, ",\"cols\":");    web_jw_int(&w, g->ncol);
    web_jw_raw(&w, ",\"col_s\":");   web_jw_int(&w, g->col_s);
    web_jw_raw(&w, ",\"top\":");     web_jw_int(&w, WEB_CHMIX_TOP);
    web_jw_raw(&w, ",\"source\":");  web_jw_str(&w, source);
    web_chmix_stats_t ms;
    web_chmix_stats(mix, &ms);
    web_jw_raw(&w, ",\"ring_from\":");
    if (g->tier == WEB_TIER_FINE && ms.ring_oldest >= 0) web_jw_int(&w, ms.ring_oldest);
    else web_jw_raw(&w, "null");
    if (ops->use_db) {
        web_sdb_stats_t sst;
        memset(&sst, 0, sizeof(sst));
        if (m->sdb) web_slothdb_stats(m->sdb, &sst);
        web_jw_raw(&w, ",\"db\":");
        web_jw_str(&w, have_db ? "open" : m->sdb && m->sdb->configured
                       ? web_slothdb_state_word(sst.state) : "none");
    }
    web_jw_raw(&w, ",\"total_keys\":"); web_jw_int(&w, a->nch);
    web_jw_raw(&w, ",\"tx\":[");
    web_jw_raw(&w, dict);
    web_jw_raw(&w, "],\"");
    web_jw_raw(&w, ops->rows_word);
    web_jw_raw(&w, "\":[");
    web_jw_raw(&w, rows);
    web_jw_raw(&w, "],\"shown\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");
    web_jw_raw(&w, shown < a->nch || rows_cut || a->cut_ch ? "true" : "false");
    /* What the bounds folded: transmitters past the answer's table, rows
     * past the read cap. Their frames are in "other" or not read. */
    web_jw_raw(&w, ",\"folded\":"); web_jw_raw(&w, folded ? "true" : "false");
    web_jw_raw(&w, ",\"read_cut\":"); web_jw_raw(&w, read_more ? "true" : "false");
    if (clb) web_jw_raw(&w, clb);
    if (ops->tail) ops->tail(&w, ops->ctx);
    web_jw_raw(&w, "}\n");
    (void)nread;
    free(a->cl); free(clb);
    free(a); free(cells); free(dict); free(rows); free(row);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/wifi/channels ──────────────────────────────────────────────── */

/* ── G3's scales (docs/web-visual-spec.md F8, slice V3) ─────────────── */

/* The window a channel's absolute scale is read over: the last 30 days
 * at the hour tier when there is a store, the fine ring's day without
 * one; and the channels a grid lists however quiet its own range was. */
#define CHAN_SEEN_S (30LL * 86400)

/* A channel's own largest value over chan_scale_window(): a gauge's
 * largest sample (each bucket's max), a counter's busiest minute as a
 * count per minute (an hour bucket's sum over its 60 minutes, which is
 * that hour's mean rate; fine buckets summed by minute). Never the
 * busiest cell in view, which is what F8 found wrong: a colour that
 * means "busiest in the last hour" means nothing when the hour was
 * quiet. -1 on memory; 0 with *out 0 when the key has nothing there. */
static int chan_scale_max(const web_m4_t *m, int metric, const char *key,
                          long long now, web_point_t *pts, double *out) {
    int store_on = m->tsdb->store && m->tsdb->store->rd;
    int tier = store_on ? WEB_TIER_HOUR : WEB_TIER_FINE;
    long long span = store_on ? CHAN_SEEN_S : WEB_FINE_KEEP_S;
    long long maxp = span / web_tier_step(tier) + 2;
    if (maxp > GRID_PTS) maxp = GRID_PTS;
    int more = 0, serr = 0;
    int n = web_series_points(m->tsdb, tier, metric, key, now - span, now + 1,
                              pts, (int)maxp, &more, &serr);
    if (n < 0) return -1;
    int counter = web_metric_defs[metric].kind == WEB_MK_COUNTER;
    double best = 0, run = 0;
    long long minute = -1;
    for (int i = 0; i < n; i++) {
        double v;
        if (!counter) v = pts[i].max;
        else if (tier == WEB_TIER_HOUR) v = pts[i].sum / 60.0;
        else {
            /* Newest first: a minute's fine buckets are adjacent. */
            long long mi = pts[i].t / 60;
            if (mi != minute) { run = 0; minute = mi; }
            run += pts[i].sum;
            v = run;
        }
        if (isfinite(v) && v > best) best = v;
    }
    *out = best;
    return 0;
}

/* One row's scale member and, for a counter with a baseline, its cells
 * as z (F8: "ctrl_total against its hour-of-week baseline as a
 * z-score", so the strip is flat while the channel is normal). Each
 * cell's count per minute against the hour-of-week cell its UTC hour
 * bucket was filed under, as A1 scores (web_baseline.h): a minute's
 * spread for a cell shorter than an hour, the hour's for one an hour or
 * longer, as the page's band() reads sd_hour. A warming cell and an
 * empty one are null. A counter whose baseline was never fed, and every
 * gauge, take the absolute scale: 0 to the channel's own largest value
 * (chan_scale_max()), widened to every cell of the answer so the top of
 * the scale is never under a value the page draws. */
static int chan_scale_json(const web_m4_t *m, int metric, const grid_t *g,
                           const char *key, const double *sum, const int *cnt,
                           web_point_t *pts, web_bl_cell_t *bl, web_jw_t *w) {
    int counter = web_metric_defs[metric].kind == WEB_MK_COUNTER;
    web_baseline_t *b = m->anomaly ? m->anomaly->cfg.bl : NULL;
    if (counter && b && web_baseline_cells(b, metric, key, bl) == 0) {
        int warming = 0;
        web_jw_raw(w, ",\"scale\":{\"kind\":\"z\"");
        web_jw_raw(w, "},\"z\":[");
        for (int c = 0; c < g->ncol; c++) {
            if (c) web_jw_raw(w, ",");
            if (!cnt[c]) { web_jw_raw(w, "null"); continue; }
            long long t0 = g->from + (long long)c * g->col_s;
            const web_bl_cell_t *cl = &bl[web_bl_cell_index(t0 - t0 % 3600)];
            if (cl->n < WEB_BL_WARM_N) { web_jw_raw(w, "null"); warming++; continue; }
            double sh, sd = web_bl_cell_sd(metric, cl, &sh, NULL);
            double v = sum[c] * 60.0 / (double)g->col_s;
            double d = g->col_s >= 3600 ? sh : sd;
            double z = d > 0 ? (v - cl->mean) / d : 0;
            char t[32];
            snprintf(t, sizeof(t), "%.2f", isfinite(z) ? z : 0.0);
            if (!strcmp(t, "-0.00")) snprintf(t, sizeof(t), "0.00");
            web_jw_raw(w, t);
        }
        web_jw_raw(w, "],\"z_warming\":");
        web_jw_int(w, warming);
        return 0;
    }
    double mx = 0;
    if (chan_scale_max(m, metric, key, g->to, pts, &mx) != 0) return -1;
    for (int c = 0; c < g->ncol; c++) {
        if (!cnt[c]) continue;
        double v = counter ? sum[c] * 60.0 / (double)g->col_s : sum[c] / cnt[c];
        if (isfinite(v) && v > mx) mx = v;
    }
    web_jw_raw(w, ",\"scale\":{\"kind\":\"absolute\",\"max\":");
    jw_cell(w, mx);
    web_jw_raw(w, "}");
    return 0;
}

int web_wifi_channels_route(const web_m4_t *m, const char *query,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status) {
    if (!m || !m->tsdb)
        return answer_error(503, "no_time_series", NULL, body, cap, len, status);
    web_param_t ps[5] = {
        { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 },
        { "metric", "", 0 }, { "mix", "", 0 },
    };
    char err[48];
    if (web_params_parse(query, ps, 5, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    if (ps[4].seen) {
        if (strcmp(ps[4].val, "1"))
            return answer_error(400, "bad_mix", NULL, body, cap, len, status);
        if (ps[3].seen)
            return answer_error(400, "mix_takes_no_metric", NULL, body, cap, len,
                                status);
        if (!m->tsdb->mix)
            return answer_error(503, "no_channel_mix", NULL, body, cap, len, status);
        grid_t mg;
        const char *mwhy;
        if (web_grid_of(m, ps, now_s, &mg, &mwhy) != 0)
            return answer_error(400, mwhy, NULL, body, cap, len, status);
        WEB_M4_CHECKED(m, len, status);
        web_mix_ops_t ops;
        memset(&ops, 0, sizeof(ops));
        ops.mix = m->tsdb->mix;
        ops.ns = WEB_MIX_NS_WIFI;
        ops.metric = "wifi.mix";
        ops.unit = "frames";
        ops.rows_word = "channels";
        ops.kinds = 1u << WEB_TX_AP | 1u << WEB_TX_CLIENT;
        ops.use_db = 1;
        ops.key = wifi_mix_key;
        ops.row_extra = wifi_row_extra;
        ops.tx_json = wifi_tx_json;
        ops.clients = 1;
        return web_mix_answer(m, &mg, &ops, now_s, body, cap, len, status);
    }
    int metric = WM_WIFI_AP_COUNT;
    if (ps[3].seen) {
        if (!strcmp(ps[3].val, "ap_count")) metric = WM_WIFI_AP_COUNT;
        else if (!strcmp(ps[3].val, "ctrl_total")) metric = WM_WIFI_CTRL_TOTAL;
        else return answer_error(400, "unknown_metric", NULL, body, cap, len,
                                 status);
    }
    grid_t g;
    const char *why;
    if (web_grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    gbuf_t b;
    web_bl_cell_t *bl = malloc(WEB_BL_CELLS * sizeof(*bl));
    if (gbuf_alloc(&b) != 0 || !bl) { gbuf_free(&b); free(bl); return -1; }
    int nk = grid_keys(m, metric, &g, b.keys);
    /* G3's rows (§5): every channel seen in the last 30 days, not only
     * those the range holds, so a channel that went quiet keeps its row
     * and its silence is visible. */
    if (m->tsdb->store && m->tsdb->store->rd && nk < GRID_KEYS) {
        char (*sk)[WEB_KEY_MAX + 1] = malloc(256 * sizeof(*sk));
        int ns = sk ? web_store_keys(m->tsdb->store, WEB_TIER_HOUR, metric,
                                     now_s - CHAN_SEEN_S, now_s + 1, sk, 256) : 0;
        for (int i = 0; i < ns && nk < GRID_KEYS; i++) {
            int dup = 0;
            for (int j = 0; j < nk && !dup; j++) dup = !strcmp(b.keys[j], sk[i]);
            if (!dup) snprintf(b.keys[nk++], WEB_KEY_MAX + 1, "%s", sk[i]);
        }
        free(sk);
    }
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
        /* The scale member and a z per cell at 9 bytes ("-12345.67"). */
        if (w.len + row_max(&g, 96 + (size_t)g.ncol * 10) + 64 > cap) break;
        double total;
        if (grid_row(m, metric, &g, b.rows[i].key, b.pts, b.sum, b.cnt,
                     &total) != 0) {
            gbuf_free(&b);
            free(bl);
            return -1;
        }
        int rank;
        const char *band = web_channel_band(b.rows[i].key, &rank);
        if (shown++) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"key\":");  web_jw_str(&w, b.rows[i].key);
        web_jw_raw(&w, ",\"band\":"); web_jw_str(&w, band);
        web_jw_raw(&w, ",\"cells\":");
        cells_json(&w, metric, &g, b.sum, b.cnt);
        if (chan_scale_json(m, metric, &g, b.rows[i].key, b.sum, b.cnt, b.pts, bl,
                            &w) != 0) {
            gbuf_free(&b);
            free(bl);
            return -1;
        }
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"shown\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");    web_jw_raw(&w, shown < nk ? "true" : "false");
    /* What an absolute scale was read over (chan_scale_max()). */
    web_jw_raw(&w, ",\"scale_s\":");
    web_jw_int(&w, m->tsdb->store && m->tsdb->store->rd ? CHAN_SEEN_S : WEB_FINE_KEEP_S);
    web_jw_raw(&w, "}\n");
    gbuf_free(&b);
    free(bl);
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
    if (web_grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
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

/* ── /api/wifi/chain ─────────────────────────────────────────────────── */

typedef struct {
    web_jw_t *w;
    int       n, max, type, k;   /* type: the alert type this list takes */
} stage_t;

static int emit_stage(void *ctx, const web_sdb_item_t *it) {
    stage_t *s = ctx;
    if (it->n1 != s->type) return 0;
    s->k++;
    if (s->n >= s->max) return 0;
    web_jw_raw(s->w, s->n++ ? ",[" : "[");
    web_jw_int(s->w, it->first_seen);
    web_jw_raw(s->w, ",");
    web_jw_int(s->w, it->last_seen);
    web_jw_raw(s->w, ",");
    web_jw_int(s->w, it->n2 < 0 ? 0 : it->n2 > 2 ? 2 : it->n2);
    web_jw_raw(s->w, ",");
    web_jw_int(s->w, it->has_n3 && it->n3 > 0 ? it->n3 : 0);
    web_jw_raw(s->w, "]");
    return 0;
}

typedef struct {
    const grid_t *g;
    int          *cells;
    int           n;
} assoc_t;

static int take_assoc(void *ctx, const web_sdb_item_t *it) {
    assoc_t *a = ctx;
    long long c = (it->first_seen - a->g->from) / a->g->col_s;
    if (c >= 0 && c < a->g->ncol) { a->cells[c]++; a->n++; }
    return 0;
}

static void jw_ts_or_null(web_jw_t *w, long long ts) {
    if (ts > 0) web_jw_int(w, ts); else web_jw_raw(w, "null");
}

/* One BSSID's chain: its deauth row (as /api/wifi/deauth's), the other
 * stages sloth.db holds against it, the associations to it, and the
 * links the stream's twin_episode made. The stages counted: deauth (a
 * frame or a flood), twin, assoc (only beside a twin or a karma row),
 * karma. */
static void chain_row(const web_m4_t *m, web_sdb_conn_t *conn, int have_db,
                      const grid_t *g, const char *bssid, double total,
                      const double *sum, const int *cnt, int *acells,
                      web_jw_t *w) {
    int metric = WM_WIFI_DEAUTH, stages = 0, frames = 0, ok = 1;
    for (int c = 0; c < g->ncol; c++) if (cnt[c] && sum[c] > 0) frames = 1;
    web_jw_raw(w, "{\"bssid\":"); web_jw_str(w, bssid);
    web_jw_raw(w, ",\"total\":");  jw_cell(w, total);
    web_jw_raw(w, ",\"cells\":");
    cells_json(w, metric, g, sum, cnt);
    web_jw_raw(w, ",\"floods\":[");
    flood_t f = { w, 0, WEB_WIFI_FLOODS };
    int got = have_db ? web_sdb_deauth_floods(conn, bssid, g->from, g->to,
                                              WEB_WIFI_FLOODS + 1, emit_flood, &f) : 0;
    if (got < 0) ok = 0;
    web_jw_raw(w, "],\"floods_more\":");
    web_jw_raw(w, got > WEB_WIFI_FLOODS ? "true" : "false");
    if (frames || f.n) stages++;
    /* The two alert stages from one read each: the rows come back
     * oldest first, both types mixed, and each list takes its own. */
    static const struct { const char *name; int type; } ST[] = {
        { "twin", WEB_ALERT_EVIL_TWIN }, { "karma", WEB_ALERT_KARMA_AP },
    };
    int more = 0, accused = 0;
    for (size_t i = 0; i < sizeof(ST) / sizeof(ST[0]); i++) {
        web_jw_raw(w, ",\"");
        web_jw_raw(w, ST[i].name);
        web_jw_raw(w, "\":[");
        stage_t st = { w, 0, WEB_WIFI_FLOODS, ST[i].type, 0 };
        int r = have_db ? web_sdb_chain_stages(conn, bssid, g->from, g->to,
                                               WEB_WIFI_STAGE_READ, emit_stage, &st) : 0;
        if (r < 0) ok = 0;
        if (r >= WEB_WIFI_STAGE_READ || st.k > st.n) more = 1;
        web_jw_raw(w, "]");
        if (st.n) { stages++; accused = 1; }
    }
    web_jw_raw(w, ",\"stages_more\":"); web_jw_raw(w, more ? "true" : "false");
    memset(acells, 0, (size_t)g->ncol * sizeof(*acells));
    assoc_t as = { g, acells, 0 };
    int ar = have_db ? web_sdb_bssid_assocs(conn, bssid, g->from, g->to,
                                            WEB_WIFI_ASSOC_READ, take_assoc, &as) : 0;
    if (ar < 0) ok = 0;
    web_jw_raw(w, ",\"assoc\":[");
    for (int c = 0; c < g->ncol; c++) {
        if (c) web_jw_raw(w, ",");
        web_jw_int(w, acells[c]);
    }
    web_jw_raw(w, "],\"assoc_n\":"); web_jw_int(w, as.n);
    web_jw_raw(w, ",\"assoc_more\":");
    web_jw_raw(w, ar >= WEB_WIFI_ASSOC_READ ? "true" : "false");
    /* A station associating is the chain's stage only on a BSSID sloth
     * accused or caught luring (§5 G8: "a client associated to the twin
     * BSSID"): on any other AP it is a client joining, and with the
     * deauth frames every AP sends it would make each busy AP a chain. */
    if (as.n && accused) stages++;
    web_chain_pair_t lk[WEB_CHAIN_LINKS];
    long long since = 0;
    int nl = m->chain ? web_chain_links(m->chain, bssid, g->from, g->to, lk,
                                        WEB_CHAIN_LINKS, &since) : 0;
    web_jw_raw(w, ",\"links\":[");
    for (int i = 0; i < nl; i++) {
        web_jw_raw(w, i ? ",{\"real\":" : "{\"real\":"); web_jw_str(w, lk[i].real);
        web_jw_raw(w, ",\"twin\":");       web_jw_str(w, lk[i].twin);
        web_jw_raw(w, ",\"first\":");      web_jw_int(w, lk[i].first_ts);
        web_jw_raw(w, ",\"last\":");       web_jw_int(w, lk[i].last_ts);
        web_jw_raw(w, ",\"tainted\":");    jw_ts_or_null(w, lk[i].taint_ts);
        web_jw_raw(w, ",\"attributed\":"); jw_ts_or_null(w, lk[i].attr_ts);
        web_jw_raw(w, ",\"confidence\":");
        if (lk[i].confidence >= 0) web_jw_int(w, lk[i].confidence); else web_jw_raw(w, "null");
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"read\":");  web_jw_raw(w, ok ? "true" : "false");
    web_jw_raw(w, ",\"stages\":"); web_jw_int(w, stages);
    web_jw_raw(w, "}");
}

/* #195: a BSSID sloth.db holds an EVIL_TWIN or KARMA_AP row for in the
 * window is a candidate though no deauth key names it (a twin raised
 * without a deauth flood). web_sdb_ap_attacks() gives one item per
 * (BSSID, type), beacon_aps' BSSID; each BSSID it names is moved, or
 * added, to the front of the rows, ahead of the deauth-only ones, so
 * the WEB_WIFI_CHAINS rows read are the ones an alert names before the
 * merely busy ones. The front is then put in deauth order. */
typedef struct { krow_t *rows; int n, max, front; } atk_rows_t;

static int add_attacked(void *ctx, const web_sdb_item_t *it) {
    atk_rows_t *x = ctx;
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(it->a, mac) != 0) return 0;
    int at = -1;
    for (int i = 0; i < x->n && at < 0; i++)
        if (!strcmp(x->rows[i].key, mac)) at = i;
    if (at >= 0 && at < x->front) return 0;          /* already in front */
    krow_t r;
    if (at >= 0) {
        r = x->rows[at];
        memmove(&x->rows[x->front + 1], &x->rows[x->front],
                (size_t)(at - x->front) * sizeof(*x->rows));
    } else {
        if (x->n >= x->max) return 1;
        memset(&r, 0, sizeof(r));
        snprintf(r.key, sizeof(r.key), "%s", mac);
        memmove(&x->rows[x->front + 1], &x->rows[x->front],
                (size_t)(x->n - x->front) * sizeof(*x->rows));
        x->n++;
    }
    x->rows[x->front++] = r;
    return 0;
}

int web_wifi_chain_route(const web_m4_t *m, const char *query,
                         long long now_s, char *body, size_t cap,
                         size_t *len, int *status) {
    if (!m || !m->tsdb)
        return answer_error(503, "no_time_series", NULL, body, cap, len, status);
    web_param_t ps[4] = { { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 },
                          { "bssid", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    char one[WEB_KEY_MAX + 1] = "";
    if (ps[3].seen && web_key_mac(ps[3].val, one) != 0)
        return answer_error(400, "bad_bssid", NULL, body, cap, len, status);
    grid_t g;
    const char *why;
    if (web_grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    const int metric = WM_WIFI_DEAUTH;
    gbuf_t b;
    if (gbuf_alloc(&b) != 0) { gbuf_free(&b); return -1; }
    int *acells = malloc((size_t)WEB_WIFI_COLS * sizeof(*acells));
    if (!acells) { gbuf_free(&b); return -1; }
    int nk;
    if (one[0]) {
        nk = 1;
        snprintf(b.rows[0].key, sizeof(b.rows[0].key), "%s", one);
    } else {
        nk = grid_keys(m, metric, &g, b.keys);
        for (int i = 0; i < nk; i++) {
            snprintf(b.rows[i].key, sizeof(b.rows[i].key), "%s", b.keys[i]);
            if (grid_row(m, metric, &g, b.keys[i], b.pts, b.sum, b.cnt,
                         &b.rows[i].total) != 0) {
                free(acells);
                gbuf_free(&b);
                return -1;
            }
        }
        qsort(b.rows, (size_t)nk, sizeof(*b.rows), by_total);
    }

    web_sdb_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    char oerr[WEB_SDB_ERR_MAX] = "";
    int have_db = m->sdb && m->sdb->configured &&
                  web_slothdb_open(m->sdb, &conn, WEB_SDB_HTTP_MS, now_s, oerr,
                                   sizeof(oerr)) == 0;
    if (!one[0] && have_db) {
        atk_rows_t ar = { b.rows, nk, GRID_KEYS, 0 };
        /* A failed read leaves the deauth candidates as they were; the
         * row's own stage reads below say whether sloth.db answered. */
        (void)web_sdb_ap_attacks(&conn, g.from, g.to, 2 * GRID_KEYS, add_attacked, &ar);
        nk = ar.n;
        qsort(b.rows, (size_t)ar.front, sizeof(*b.rows), by_total);
    }
    web_sdb_stats_t sst;
    memset(&sst, 0, sizeof(sst));
    if (m->sdb) web_slothdb_stats(m->sdb, &sst);
    long long since = m->chain ? web_chain_since(m->chain) : 0;

    web_jw_t w;
    web_jw_init(&w, body, cap);
    grid_head(&w, metric, &g);
    web_jw_raw(&w, ",\"db\":");
    web_jw_str(&w, have_db ? "open" : m->sdb && m->sdb->configured
                   ? web_slothdb_state_word(sst.state) : "none");
    web_jw_raw(&w, ",\"links_from\":");
    web_jw_raw(&w, m->chain ? "\"stream\"" : "null");
    web_jw_raw(&w, ",\"links_since\":"); jw_ts_or_null(&w, since);
    web_jw_raw(&w, ",\"total_keys\":"); web_jw_int(&w, nk);
    web_jw_raw(&w, ",\"bssids\":[");
    int shown = 0;
    /* A row: its deauth cells and its association counts, the floods
     * and both stage lists at 48 bytes a row, and its links. */
    size_t extra = (size_t)g.ncol * 12 + (size_t)(3 * WEB_WIFI_FLOODS + 3) * 48 +
                   (size_t)WEB_CHAIN_LINKS * 220 + 160;
    for (int i = 0; i < nk && shown < WEB_WIFI_CHAINS; i++) {
        if (w.len + row_max(&g, extra) + 64 > cap) break;
        double total;
        if (grid_row(m, metric, &g, b.rows[i].key, b.pts, b.sum, b.cnt,
                     &total) != 0)
            break;
        if (shown++) web_jw_raw(&w, ",");
        chain_row(m, &conn, have_db, &g, b.rows[i].key, total, b.sum, b.cnt, acells, &w);
    }
    web_slothdb_close(&conn);
    web_jw_raw(&w, "],\"shown\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");    web_jw_raw(&w, shown < nk ? "true" : "false");
    web_jw_raw(&w, "}\n");
    free(acells);
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
    web_jw_ssid(s->w, it->a);
    web_jw_raw(s->w, ",\"first_seen\":"); web_jw_int(s->w, it->first_seen);
    web_jw_raw(s->w, ",\"last_seen\":");  web_jw_int(s->w, it->last_seen);
    web_jw_ssid_meta(s->w, "ssid", it->a);
    web_jw_raw(s->w, "}");
    return 0;
}

/* rf: the row's G2 trail (web_rf.h), its "rf" member; NULL for none. */
static void ap_json(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *c,
                    const web_sdb_ap_t *a, const web_rf_trail_t *rf, long long now_s) {
    web_jw_raw(w, "{\"bssid\":");    web_jw_str(w, a->bssid);
    web_jw_raw(w, ",\"ssid\":");     web_jw_ssid(w, a->ssid);
    web_jw_raw(w, ",\"signal\":");
    if (a->has_signal)
        web_jw_int(w, a->signal_dbm < -200 ? -200 : a->signal_dbm > 50 ? 50
                                                  : a->signal_dbm);
    else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"channel\":");  web_jw_int(w, a->channel & 0xffff);
    /* sloth_ch_width_t: 0 unknown, else MHz, 8080 for 80+80
     * non-contiguous (src/views/beacon.c's "36/80+"). Never clamped: an
     * unrecognised value is still the width sloth decoded. */
    web_jw_raw(w, ",\"operating_width\":");
    web_jw_int(w, a->operating_width);
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
    if (rf) web_rf_json(w, rf, m->frrs, a->bssid, now_s);
    web_jw_ssid_meta(w, "ssid", a->ssid);
    /* Designated by its BSSID or its SSID (sloth's --my-bssid,
     * --my-ssid, web_own.h); null until sloth has reported them. */
    int db = web_own_bssid(a->bssid);
    int ds = a->ssid[0] ? web_own_ssid(a->ssid, strlen(a->ssid)) : db;
    web_jw_raw(w, ",\"designated\":");
    web_own_jw(w, db > 0 || ds > 0 ? 1 : db < 0 ? -1 : 0);
    web_jw_raw(w, "}");
}

int web_wifi_aps_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status) {
    if (!m || !m->sdb || !m->sdb->configured || !web_slothdb_available())
        return answer_error(503, "no_sloth_db",
                            "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                            body, cap, len, status);
    web_param_t ps[4] = { { "sort", "", 0 }, { "limit", "", 0 },
                          { "offset", "", 0 }, { "dir", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    static const char *const SORT[WEB_AP_SORT_COUNT] = { "last", "ssids",
        "karma", "bssid", "ssid", "channel", "signal", "enc", "mfp",
        "downgrade", "first" };
    int sort = WEB_AP_SORT_LAST, dir = WEB_SORT_DEFAULT;
    if (ps[0].seen) {
        sort = -1;
        for (int i = 0; i < WEB_AP_SORT_COUNT; i++)
            if (!strcmp(ps[0].val, SORT[i])) sort = i;
        if (sort < 0) return answer_error(400, "bad_sort", NULL, body, cap, len, status);
    }
    if (ps[3].seen && (dir = web_sort_dir_find(ps[3].val)) < 0)
        return answer_error(400, "bad_dir", NULL, body, cap, len, status);
    long long limit = WEB_WIFI_AP_LIMIT, offset = 0;
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_WIFI_AP_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, 0, WEB_DEV_OFFSET_MAX, &offset) != 0)
        return answer_error(400, "bad_offset", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);

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
    int got = web_sdb_aps(&conn, WEB_SORT_PACK(sort, dir), limit + 1, offset,
                          collect_ap, &c);
    if (got < 0) {
        int to = conn.timed_out;
        web_slothdb_close(&conn);
        free(c.rows);
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error",
                            NULL, body, cap, len, status);
    }
    int show = c.n > limit ? (int)limit : c.n;
    /* G2 (web_rf.h): every row is a BSSID, so rf.rssi.bssid first. */
    char (*macs)[WEB_KEY_MAX + 1] = calloc((size_t)(show ? show : 1), sizeof(*macs));
    int *isap = calloc((size_t)(show ? show : 1), sizeof(*isap));
    web_rf_trail_t *rf = calloc((size_t)(show ? show : 1), sizeof(*rf));
    if (!macs || !isap || !rf) {
        free(macs); free(isap); free(rf);
        web_slothdb_close(&conn);
        free(c.rows);
        return -1;
    }
    for (int i = 0; i < show; i++) {
        snprintf(macs[i], sizeof(macs[i]), "%s", c.rows[i].bssid);
        isap[i] = 1;
    }
    web_rf_trails(m->tsdb ? m->tsdb->ru : NULL, m->sc,
                  (const char (*)[WEB_KEY_MAX + 1])macs, isap, show, now_s, rf);
    free(macs);
    free(isap);
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
        ap_json(&w, m, &conn, &c.rows[i], &rf[i], now_s);
        shown++;
    }
    free(rf);
    web_slothdb_close(&conn);
    int more = shown < c.n;
    web_jw_raw(&w, "],\"count\":");   web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");     web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    /* Only when asked for: an answer without dir is as it always was. */
    if (dir != WEB_SORT_DEFAULT)
        web_jw_raw(&w, dir == WEB_SORT_ASC ? ",\"dir\":\"asc\"" : ",\"dir\":\"desc\"");
    web_jw_raw(&w, "}\n");
    free(c.rows);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/wifi/local ─────────────────────────────────────────────────── */

typedef struct {
    web_jw_t *w;
    size_t    cap;
    int       n, max, cut;
} cardw_t;

/* Room for one more row of max: else cut, and the read stops. */
static int card_room(cardw_t *k) {
    if (k->n >= k->max || k->w->len + WEB_WIFI_AP_ROW_MAX + 256 > k->cap) {
        k->cut = 1;
        return 0;
    }
    if (k->n++) web_jw_raw(k->w, ",");
    return 1;
}

static int emit_card_ap(void *ctx, const web_sdb_card_ap_t *a) {
    cardw_t *k = ctx;
    if (!card_room(k)) return 1;
    web_jw_t *w = k->w;
    /* NL80211_BSS_STATUS_* (sloth.h WIFI_STATUS_*): the BSS the card is
     * on now, if any. */
    static const char *const ST[3] = { "authenticated", "associated", "ibss_joined" };
    web_jw_raw(w, "{\"bssid\":");  web_jw_str(w, a->bssid);
    web_jw_raw(w, ",\"ssid\":");   web_jw_ssid(w, a->ssid);
    web_jw_raw(w, ",\"signal\":");
    if (a->has_signal) web_jw_int(w, a->signal_dbm); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"channel\":"); web_jw_int(w, a->channel);
    web_jw_raw(w, ",\"enc\":");    jw_text_or_null(w, a->enc);
    web_jw_raw(w, ",\"status\":");
    if (a->has_status && a->status >= 0 && a->status <= 2) web_jw_str(w, ST[a->status]);
    else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, a->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, a->last_seen);
    web_jw_ssid_meta(w, "ssid", a->ssid);
    web_jw_raw(w, "}");
    return 0;
}

static int emit_card_sta(void *ctx, const web_sdb_card_sta_t *a) {
    cardw_t *k = ctx;
    if (!card_room(k)) return 1;
    web_jw_t *w = k->w;
    web_jw_raw(w, "{\"mac\":");    web_jw_str(w, a->mac);
    web_jw_raw(w, ",\"signal\":");
    if (a->has_signal) web_jw_int(w, a->signal_dbm); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"tx_kbps\":");     web_jw_int(w, a->tx_kbps);
    web_jw_raw(w, ",\"rx_kbps\":");     web_jw_int(w, a->rx_kbps);
    web_jw_raw(w, ",\"connected_s\":"); web_jw_int(w, a->connected_s);
    web_jw_raw(w, ",\"inactive_ms\":"); web_jw_int(w, a->inactive_ms);
    web_jw_raw(w, ",\"tx_bytes\":");    web_jw_int(w, a->tx_bytes);
    web_jw_raw(w, ",\"rx_bytes\":");    web_jw_int(w, a->rx_bytes);
    web_jw_raw(w, ",\"first_seen\":");  web_jw_int(w, a->first_seen);
    web_jw_raw(w, ",\"last_seen\":");   web_jw_int(w, a->last_seen);
    web_jw_raw(w, "}");
    return 0;
}

int web_wifi_local_route(const web_m4_t *m, const char *query, long long now_s,
                         char *body, size_t cap, size_t *len, int *status) {
    if (!m || !m->sdb || !m->sdb->configured || !web_slothdb_available())
        return answer_error(503, "no_sloth_db",
                            "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                            body, cap, len, status);
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    long long limit = WEB_WIFI_AP_MAX;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_WIFI_AP_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
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
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");       web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"limit\":");     web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    web_jw_raw(&w, ",\"aps\":[");
    cardw_t ka = { &w, cap, 0, (int)limit, 0 };
    int na = web_sdb_card_aps(&conn, limit + 1, emit_card_ap, &ka);
    web_jw_raw(&w, "],\"stas\":[");
    cardw_t ks = { &w, cap, 0, WEB_WIFI_STA_MAX, 0 };
    int ns = na < 0 ? -1 : web_sdb_card_stas(&conn, WEB_WIFI_STA_MAX + 1, emit_card_sta, &ks);
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (na < 0 || ns < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "],\"aps_more\":");
    web_jw_raw(&w, ka.cut ? "true" : "false");
    web_jw_raw(&w, ",\"stas_more\":"); web_jw_raw(&w, ks.cut ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/wifi/lastch ────────────────────────────────────────────────── */

typedef struct {
    web_jw_t *w;
    size_t    end;     /* this list's room: the writer's length it stops at */
    int       n, ssid, cut;
} lastw_t;

static int emit_lastch(void *ctx, const web_sdb_item_t *it) {
    lastw_t *k = ctx;
    /* a key at most WEB_SSID_JSON_MAX of a 63-octet name, ":", the
     * channel and a comma */
    if (k->n >= WEB_LASTCH_ROWS || k->w->len + WEB_SSID_JSON_MAX(WEB_SDB_TEXT_MAX) + 16 > k->end) {
        k->cut = 1;
        return 1;
    }
    if (!it->a[0] || it->n2 <= 0 || it->n2 > 255) return 0;
    if (k->n++) web_jw_raw(k->w, ",");
    if (k->ssid) web_jw_ssid(k->w, it->a); else web_jw_str(k->w, it->a);
    web_jw_raw(k->w, ":");
    web_jw_int(k->w, it->n2);
    return 0;
}

int web_wifi_lastch_route(const web_m4_t *m, const char *query, long long now_s,
                          char *body, size_t cap, size_t *len, int *status) {
    if (!m || !m->sdb || !m->sdb->configured || !web_slothdb_available())
        return answer_error(503, "no_sloth_db",
                            "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                            body, cap, len, status);
    char err[48];
    if (web_params_parse(query, NULL, 0, err, sizeof(err)) != 0)
        return answer_error(400, err, NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
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
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":");       web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, conn.schema);
    static const char *const NAME[3] = { "aps", "ssids", "stas" };
    static const int WHAT[3] = { WEB_LASTCH_AP, WEB_LASTCH_SSID, WEB_LASTCH_STA };
    size_t third = cap > 96 ? (cap - 96) / 3 : 0;
    int cut = 0, rc = 0;
    for (int i = 0; i < 3 && rc >= 0; i++) {
        web_jw_raw(&w, i ? "},\"" : ",\"");
        web_jw_raw(&w, NAME[i]);
        web_jw_raw(&w, "\":{");
        lastw_t k = { &w, w.len + third, 0, WHAT[i] == WEB_LASTCH_SSID, 0 };
        rc = web_sdb_last_channels(&conn, WHAT[i], WEB_LASTCH_ROWS + 1, emit_lastch, &k);
        cut |= k.cut;
    }
    int to = conn.timed_out;
    web_slothdb_close(&conn);
    if (rc < 0)
        return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                            body, cap, len, status);
    web_jw_raw(&w, "},\"cut\":");
    web_jw_raw(&w, cut ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
