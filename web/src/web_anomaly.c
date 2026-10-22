#include "web_anomaly.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_metrics.h"

/* ── names ───────────────────────────────────────────────────────────── */

static const char *const RULE_NAME[WEB_ANOM_RULE_COUNT] = {
    "A1", "A2", "A3", "A5", "A6", "A7", "A8", "A9", "A10"
};
static const char *const RULE_KIND[WEB_ANOM_RULE_COUNT] = {
    "rate", "new", "hours", "ident", "ident", "fanout", "dns", "proto",
    "sensor"
};
static const char *const KINDS[] = {
    "rate", "new", "hours", "ident", "fanout", "dns", "proto", "sensor", NULL
};

const char *web_anomaly_kind(int rule) {
    return rule >= 0 && rule < WEB_ANOM_RULE_COUNT ? RULE_KIND[rule] : "?";
}

const char *web_anomaly_rule(int rule) {
    return rule >= 0 && rule < WEB_ANOM_RULE_COUNT ? RULE_NAME[rule] : "?";
}

int web_anomaly_kind_find(const char *kind) {
    for (int i = 0; KINDS[i]; i++)
        if (!strcmp(KINDS[i], kind)) return i;
    return -1;
}

static int kind_index(int rule) {
    return web_anomaly_kind_find(web_anomaly_kind(rule));
}

static int rule_find(const char *name) {
    for (int i = 0; i < WEB_ANOM_RULE_COUNT; i++)
        if (!strcmp(RULE_NAME[i], name)) return i;
    return -1;
}

static int req_streak(int rule) {
    return rule == WEB_ANOM_A1_RATE ? WEB_ANOM_STREAK_MIN : 1;
}

/* ── small keyed tables ──────────────────────────────────────────────── */

/* A bounded (a, key) -> slot table, evicting the slot with the oldest t
 * when full. The payload lives in the caller's array at the same index. */
typedef struct {
    int       used, next, a;
    char      key[WEB_KEY_MAX + 1];
    long long t;
} kv_t;

typedef struct {
    kv_t         *e;
    int           cap, n, nhead;
    int          *head;
    unsigned long evictions;
} kvtab_t;

static unsigned kv_hash(int a, const char *k) {
    unsigned h = 2166136261u ^ (unsigned)a;
    for (const unsigned char *p = (const unsigned char *)k; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

static int kv_init(kvtab_t *t, int cap) {
    memset(t, 0, sizeof(*t));
    if (cap < 1) cap = 1;
    t->cap = cap;
    t->nhead = 1;
    while (t->nhead < cap * 2) t->nhead <<= 1;
    t->e = calloc((size_t)cap, sizeof(*t->e));
    t->head = malloc((size_t)t->nhead * sizeof(*t->head));
    if (!t->e || !t->head) return -1;
    for (int i = 0; i < t->nhead; i++) t->head[i] = -1;
    return 0;
}

static void kv_free(kvtab_t *t) {
    free(t->e);
    free(t->head);
    t->e = NULL;
    t->head = NULL;
}

static int kv_find(const kvtab_t *t, int a, const char *k) {
    for (int i = t->head[kv_hash(a, k) & (unsigned)(t->nhead - 1)]; i >= 0;
         i = t->e[i].next)
        if (t->e[i].a == a && !strcmp(t->e[i].key, k)) return i;
    return -1;
}

static void kv_unlink(kvtab_t *t, int i) {
    int *pp = &t->head[kv_hash(t->e[i].a, t->e[i].key) & (unsigned)(t->nhead - 1)];
    while (*pp >= 0 && *pp != i) pp = &t->e[*pp].next;
    if (*pp == i) *pp = t->e[i].next;
}

static void kv_del(kvtab_t *t, int i) {
    if (!t->e[i].used) return;
    kv_unlink(t, i);
    t->e[i].used = 0;
    t->n--;
}

/* The slot of (a, k), made if absent; *made says so, and *evicted holds
 * the key pushed out to make it ("" when none). */
static int kv_get(kvtab_t *t, int a, const char *k, long long now, int *made,
                  char evicted[WEB_KEY_MAX + 1]) {
    *made = 0;
    if (evicted) evicted[0] = '\0';
    int i = kv_find(t, a, k);
    if (i >= 0) return i;
    if (t->n < t->cap) {
        for (i = 0; i < t->cap; i++) if (!t->e[i].used) break;
    } else {
        i = 0;
        for (int j = 1; j < t->cap; j++) if (t->e[j].t < t->e[i].t) i = j;
        if (evicted) snprintf(evicted, WEB_KEY_MAX + 1, "%s", t->e[i].key);
        kv_del(t, i);
        t->evictions++;
    }
    kv_t *e = &t->e[i];
    e->used = 1;
    e->a = a;
    snprintf(e->key, sizeof(e->key), "%s", k);
    e->t = now;
    unsigned h = kv_hash(a, k) & (unsigned)(t->nhead - 1);
    e->next = t->head[h];
    t->head[h] = i;
    t->n++;
    *made = 1;
    return i;
}

/* ── the store thread's state ────────────────────────────────────────── */

typedef struct {
    int           used, next;
    int           tier, metric;
    char          key[WEB_KEY_MAX + 1];
    long long     t;
    double        sum, min, max;
    unsigned long n;
} agg_t;

typedef struct {
    long long win_t;
    double    win_max;
    long      windows;
    float     hist[WEB_ANOM_A7_BINS];
    int       dirty;
} fan_t;

typedef struct {
    int       metric;
    char      key[WEB_KEY_MAX + 1];
    int       ok;
    double    med, mad;
    int       n;
} mad_t;

typedef struct {
    int    rule, metric;
    char   key[WEB_KEY_MAX + 1];
    double score;
    char   ev[WEB_ANOM_EVIDENCE_MAX + 1];
} cand_t;

typedef struct {
    int  metric;
    char key[WEB_KEY_MAX + 1];
} pair_t;

#define MAD_CACHE   256
#define FAN_DEL_MAX 1024
#define COV_HOURS   4
#define COV_OK      1
#define COV_BAD     2
#define CAND_MAX    4096
#define ID_ROWS     4096

struct web_anom_priv {
    agg_t      *agg;
    int         agg_cap, agg_alloc, agg_free;
    int        *agg_head;
    int         agg_nhead;

    long long   start_s, done_minute, final_hour;
    long long   cov_hour[COV_HOURS];
    unsigned char cov[COV_HOURS][60];

    kvtab_t     fan_ix;
    fan_t      *fan;
    char      (*fan_del)[WEB_KEY_MAX + 1];
    int         fan_ndel;

    kvtab_t     rep;            /* A2: MACs reported (a = 0) */
    web_store_rep_t *rep_new;
    int         rep_nnew, rep_cap;

    kvtab_t     known;          /* A9: (flow metric, host) with history */

    mad_t       mad[MAD_CACHE];
    int         mad_n;
    long long   mad_hour;
    int         mad_q;          /* queries this minute */

    cand_t     *cand;
    int         cand_n;

    pair_t     *pairs;
    int         pairs_n, pairs_cap;
    int        *idx;
    int         idx_n, idx_cap;

    long long  *ep_del;
    int         ep_ndel;
    long long   next_id;
    web_store_ep_t *ep_out;

    web_id_new_t   *firsts;
    web_id_named_t *named;
    web_id_names_t *ipn;
    web_id_dns_t   *dns;
    web_bl_rec_t   *blrec;
};

/* ── init ────────────────────────────────────────────────────────────── */

static long long mono_default(void *ctx) {
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void web_anomaly_destroy(web_anomaly_t *a) {
    struct web_anom_priv *p = a->p;
    if (p) {
        free(p->agg); free(p->agg_head);
        kv_free(&p->fan_ix); free(p->fan); free(p->fan_del);
        kv_free(&p->rep); free(p->rep_new);
        kv_free(&p->known);
        free(p->cand); free(p->pairs); free(p->idx);
        free(p->ep_del); free(p->ep_out);
        free(p->firsts); free(p->named); free(p->ipn); free(p->dns);
        free(p->blrec);
        free(p);
    }
    a->p = NULL;
    free(a->ep);
    a->ep = NULL;
}

int web_anomaly_init(web_anomaly_t *a, int cap, const web_anom_cfg_t *cfg) {
    memset(a, 0, sizeof(*a));
    if (cap < 1) cap = 1;
    a->cap = cap;
    if (cfg) a->cfg = *cfg;
    if (!a->cfg.mono) a->cfg.mono = mono_default;
    int mk = a->cfg.max_keys;
    if (mk < WEB_MAX_KEYS_MIN) mk = WEB_MAX_KEYS_MIN;
    if (mk > WEB_MAX_KEYS_MAX) mk = WEB_MAX_KEYS_MAX;
    pthread_mutex_init(&a->mu, NULL);
    a->ep = calloc((size_t)cap, sizeof(*a->ep));
    struct web_anom_priv *p = calloc(1, sizeof(*p));
    a->p = p;
    if (!a->ep || !p) { web_anomaly_destroy(a); return -1; }
    /* Each series has at most a minute row or two and one hour row
     * waiting at a time. */
    p->agg_cap = web_baseline_cap_for(mk) * 3;
    p->agg_nhead = 1;
    while (p->agg_nhead < p->agg_cap) p->agg_nhead <<= 1;
    p->agg = calloc((size_t)p->agg_cap, sizeof(*p->agg));
    p->agg_head = malloc((size_t)p->agg_nhead * sizeof(*p->agg_head));
    int hosts = mk / 2;
    p->rep_cap = mk;
    p->fan = calloc((size_t)hosts, sizeof(*p->fan));
    p->fan_del = calloc(FAN_DEL_MAX, sizeof(*p->fan_del));
    p->rep_new = calloc((size_t)mk, sizeof(*p->rep_new));
    p->cand = calloc(CAND_MAX, sizeof(*p->cand));
    p->ep_del = calloc((size_t)cap * 2, sizeof(*p->ep_del));
    p->ep_out = calloc((size_t)cap, sizeof(*p->ep_out));
    p->firsts = calloc(ID_ROWS, sizeof(*p->firsts));
    p->named = calloc(ID_ROWS, sizeof(*p->named));
    p->ipn = calloc(ID_ROWS, sizeof(*p->ipn));
    p->dns = calloc(ID_ROWS, sizeof(*p->dns));
    p->blrec = calloc(512, sizeof(*p->blrec));
    if (!p->agg || !p->agg_head || !p->fan || !p->fan_del || !p->rep_new ||
        !p->cand || !p->ep_del || !p->ep_out || !p->firsts || !p->named ||
        !p->ipn || !p->dns || !p->blrec ||
        kv_init(&p->fan_ix, hosts) != 0 || kv_init(&p->rep, mk) != 0 ||
        kv_init(&p->known, hosts * 5) != 0) {
        web_anomaly_destroy(a);
        return -1;
    }
    for (int i = 0; i < p->agg_nhead; i++) p->agg_head[i] = -1;
    p->agg_free = -1;
    p->start_s = -1;
    p->done_minute = -1;
    p->final_hour = LLONG_MIN;
    p->mad_hour = -1;
    p->next_id = 1;
    for (int k = 0; k < COV_HOURS; k++) p->cov_hour[k] = -1;
    return 0;
}

/* ── merged rows ─────────────────────────────────────────────────────── */

static unsigned agg_hash(int tier, int metric, const char *key, long long t) {
    unsigned h = kv_hash(tier * 64 + metric, key);
    h ^= (unsigned)(t / 60) * 0x9e3779b1u;
    return h;
}

static int agg_find(struct web_anom_priv *p, int tier, int metric,
                    const char *key, long long t) {
    unsigned h = agg_hash(tier, metric, key, t) & (unsigned)(p->agg_nhead - 1);
    for (int i = p->agg_head[h]; i >= 0; i = p->agg[i].next) {
        const agg_t *g = &p->agg[i];
        if (g->tier == tier && g->metric == metric && g->t == t &&
            !strcmp(g->key, key))
            return i;
    }
    return -1;
}

static void agg_release(struct web_anom_priv *p, int i) {
    agg_t *g = &p->agg[i];
    unsigned h = agg_hash(g->tier, g->metric, g->key, g->t) &
                 (unsigned)(p->agg_nhead - 1);
    int *pp = &p->agg_head[h];
    while (*pp >= 0 && *pp != i) pp = &p->agg[*pp].next;
    if (*pp == i) *pp = g->next;
    g->used = 0;
    g->next = p->agg_free;
    p->agg_free = i;
}

static int agg_put(struct web_anom_priv *p, const web_qrow_t *r) {
    int i = agg_find(p, r->tier, r->metric, r->key, r->t);
    if (i >= 0) {
        agg_t *g = &p->agg[i];
        g->sum += r->sum;
        if (r->min < g->min) g->min = r->min;
        if (r->max > g->max) g->max = r->max;
        g->n += r->n;
        return 0;
    }
    if (p->agg_free >= 0) {
        i = p->agg_free;
        p->agg_free = p->agg[i].next;
    } else if (p->agg_alloc < p->agg_cap) {
        i = p->agg_alloc++;
    } else {
        return -1;
    }
    agg_t *g = &p->agg[i];
    g->used = 1;
    g->tier = r->tier;
    g->metric = r->metric;
    memcpy(g->key, r->key, sizeof(g->key));
    g->key[WEB_KEY_MAX] = '\0';
    g->t = r->t;
    g->sum = r->sum;
    g->min = r->min;
    g->max = r->max;
    g->n = r->n;
    unsigned h = agg_hash(g->tier, g->metric, g->key, g->t) &
                 (unsigned)(p->agg_nhead - 1);
    g->next = p->agg_head[h];
    p->agg_head[h] = i;
    return 0;
}

static web_point_t agg_point(const agg_t *g) {
    web_point_t pt = { g->t, g->sum, g->min, g->max, g->n };
    return pt;
}

/* ── coverage ────────────────────────────────────────────────────────── */

static unsigned char *cov_slot(struct web_anom_priv *p, long long minute,
                               int make) {
    long long t = minute * 60;
    long long hour = t - t % 3600;
    int k = (int)((hour / 3600) % COV_HOURS);
    if (k < 0) k += COV_HOURS;
    if (p->cov_hour[k] != hour) {
        if (!make) return NULL;
        p->cov_hour[k] = hour;
        memset(p->cov[k], 0, sizeof(p->cov[k]));
    }
    return &p->cov[k][(t % 3600) / 60];
}

static int minute_observed(web_anomaly_t *a, long long minute) {
    struct web_anom_priv *p = a->p;
    if (!a->cfg.live) return 1;
    if (minute * 60 < p->start_s) return 0;
    const unsigned char *c = cov_slot(p, minute, 0);
    return c && (*c & COV_OK) && !(*c & COV_BAD);
}

static int minutes_observed(web_anomaly_t *a, long long from_minute, int n) {
    int k = 0;
    for (int i = 0; i < n; i++) k += minute_observed(a, from_minute + i);
    return k;
}

static int hour_observed(web_anomaly_t *a, long long hour) {
    return minutes_observed(a, hour / 60, 60) >= (a->cfg.live ? WEB_ANOM_COVER_MIN : 1);
}

/* The socket connected and a record within the silence limit, counted
 * from the later of the last record and the connection. */
static long long silence_ms(web_anomaly_t *a, long long mono, int *connected) {
    web_live_sum_t s;
    web_live_summary(a->cfg.live, &s, mono);
    *connected = s.sock_state == WEB_SOCK_CONNECTED;
    return s.silence_ms;
}

/* ── candidates ──────────────────────────────────────────────────────── */

static void cand(web_anomaly_t *a, int rule, int metric, const char *key,
                 double score, const char *ev) {
    struct web_anom_priv *p = a->p;
    if (p->cand_n >= CAND_MAX) {
        pthread_mutex_lock(&a->mu);
        a->st.candidates_dropped++;
        pthread_mutex_unlock(&a->mu);
        return;
    }
    cand_t *c = &p->cand[p->cand_n++];
    c->rule = rule;
    c->metric = metric;
    snprintf(c->key, sizeof(c->key), "%s", key);
    c->score = score > 100 ? 100 : score < 0 ? 0 : score;
    web_utf8_copy(c->ev, WEB_ANOM_EVIDENCE_MAX, ev);
}

/* Names go into evidence cut on a code-point boundary, so that the
 * evidence is whole UTF-8 and short enough to keep its numbers. */
static const char *cut(char *buf, size_t max, const char *s) {
    web_utf8_copy(buf, max, s ? s : "");
    return buf;
}

static double z_score(double z) {
    double s = fabs(z) * 20.0;
    return s > 100.0 ? 100.0 : s;
}

/* ── A1's MAD ratio ──────────────────────────────────────────────────── */

static int cmp_dbl(const void *x, const void *y) {
    double a = *(const double *)x, b = *(const double *)y;
    return a < b ? -1 : a > b;
}

static double median(double *v, int n) {
    qsort(v, (size_t)n, sizeof(*v), cmp_dbl);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

/* The hour starts of the last WEB_ANOM_MAD_N weeks' same local hour of
 * the week as hour h: a week back, then an hour either side when a DST
 * change moved it. */
static int same_cells(long long h, long long *ts) {
    int cell = web_bl_cell_index(h);
    int n = 0;
    for (int k = 1; k <= WEB_ANOM_MAD_N; k++) {
        long long c = h - (long long)k * 7 * 86400;
        if (web_bl_cell_index(c) != cell) {
            if (web_bl_cell_index(c - 3600) == cell) c -= 3600;
            else if (web_bl_cell_index(c + 3600) == cell) c += 3600;
            else continue;
        }
        ts[n++] = c;
    }
    return n;
}

/* 1 when the MAD ratio confirms an A1 candidate (or cannot judge it),
 * 0 when it refutes it; *mz gets the modified z, or NAN. */
static int mad_confirms(web_anomaly_t *a, int metric, const char *key,
                        long long t, double v, double *mz) {
    struct web_anom_priv *p = a->p;
    *mz = NAN;
    if (!a->cfg.store || web_metric_defs[metric].kind != WEB_MK_COUNTER)
        return 1;
    long long h = t - t % 3600;
    if (p->mad_hour != h) { p->mad_hour = h; p->mad_n = 0; }
    mad_t *m = NULL;
    for (int i = 0; i < p->mad_n; i++)
        if (p->mad[i].metric == metric && !strcmp(p->mad[i].key, key)) {
            m = &p->mad[i];
            break;
        }
    if (!m) {
        if (p->mad_q >= WEB_ANOM_MAD_PER_MIN || p->mad_n >= MAD_CACHE) {
            pthread_mutex_lock(&a->mu);
            a->st.mad_skipped++;
            pthread_mutex_unlock(&a->mu);
            return 1;
        }
        p->mad_q++;
        m = &p->mad[p->mad_n++];
        memset(m, 0, sizeof(*m));
        m->metric = metric;
        snprintf(m->key, sizeof(m->key), "%s", key);
        long long ts[WEB_ANOM_MAD_N];
        web_point_t pts[WEB_ANOM_MAD_N];
        double vals[WEB_ANOM_MAD_N];
        int nt = same_cells(h, ts);
        int found = web_store_hours_at(a->cfg.store, metric, key, ts, nt, pts);
        pthread_mutex_lock(&a->mu);
        a->st.mad_queries++;
        pthread_mutex_unlock(&a->mu);
        int n = 0;
        for (int i = 0; found > 0 && i < nt; i++)
            if (pts[i].t >= 0) vals[n++] = web_bl_value(metric, &pts[i], 3600);
        m->n = n;
        if (n >= WEB_ANOM_MAD_MIN) {
            m->med = median(vals, n);
            for (int i = 0; i < n; i++) vals[i] = fabs(vals[i] - m->med);
            m->mad = median(vals, n);
            m->ok = 1;
        }
    }
    if (!m->ok) return 1;
    /* A MAD of 0 (most weeks identical) is floored like the sd is, on
     * the normal-equivalent scale (MAD = 0.6745 sd). */
    double fl = web_bl_sd_floor(metric, m->med) * 0.6745;
    double mad = m->mad > fl ? m->mad : fl;
    *mz = 0.6745 * fabs(v - m->med) / mad;
    return *mz >= WEB_ANOM_MAD_THRESHOLD;
}

/* ── the rules over one minute's rows ────────────────────────────────── */

static void a1_score(web_anomaly_t *a, int metric, const char *key,
                     long long t, double v) {
    web_bl_score_t sc;
    if (web_baseline_score(a->cfg.bl, metric, key, t, v, &sc) != 0 ||
        sc.warming)
        return;
    if (fabs(sc.z) < WEB_ANOM_Z_THRESHOLD) return;
    double mz;
    if (!mad_confirms(a, metric, key, t, v, &mz)) return;
    char ev[256], madtxt[32] = "";
    if (!isnan(mz)) snprintf(madtxt, sizeof(madtxt), " mad_z=%.1f", mz);
    snprintf(ev, sizeof(ev), "%s[%s] z=%.1f value=%.3g baseline=%.3g\xc2\xb1%.3g%s",
             web_metric_defs[metric].name, key, sc.z, v, sc.mean, sc.sd,
             madtxt);
    cand(a, WEB_ANOM_A1_RATE, metric, key, z_score(sc.z), ev);
}

static void a3_score(web_anomaly_t *a, const char *key, long long t) {
    web_bl_score_t sc;
    if (web_baseline_score(a->cfg.bl, WM_DEV_PRESENT, key, t, 1.0, &sc) != 0 ||
        sc.warming)
        return;
    if (sc.n < WEB_ANOM_A3_MIN_N || sc.mean >= WEB_ANOM_A3_MEAN_MAX) return;
    char ev[256];
    snprintf(ev, sizeof(ev), "dev.present[%s] present; this hour of the "
             "week it is normally absent (mean %.2f over %d weeks)", key,
             sc.mean, sc.n);
    cand(a, WEB_ANOM_A3_HOURS, WM_DEV_PRESENT, key, 70.0, ev);
}

static int is_flow(int m) {
    return m == WM_FLOW_SSH || m == WM_FLOW_RDP || m == WM_FLOW_SMB ||
           m == WM_FLOW_SNMP || m == WM_FLOW_MQTT;
}

static void a9_check(web_anomaly_t *a, int metric, const char *key,
                     long long t) {
    struct web_anom_priv *p = a->p;
    if (kv_find(&p->known, metric, key) >= 0) return;
    int r = web_store_any_before(a->cfg.store, metric, key, t);
    pthread_mutex_lock(&a->mu);
    a->st.a9_queries++;
    if (r < 0) a->st.a9_errors++;
    pthread_mutex_unlock(&a->mu);
    if (r < 0) return;
    int made;
    int i = kv_get(&p->known, metric, key, t, &made, NULL);
    p->known.e[i].t = t;
    if (r == 1) return;
    char ev[256];
    snprintf(ev, sizeof(ev), "%s[%s] first use the store has recorded",
             web_metric_defs[metric].name, key);
    cand(a, WEB_ANOM_A9_PROTO, metric, key, 50.0, ev);
}

/* A7: the 16 bins' lower bounds; bin i holds [L[i], L[i+1]). */
static const double FAN_L[WEB_ANOM_A7_BINS] = {
    0, 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129
};

static int fan_bin(double v) {
    int b = 0;
    while (b + 1 < WEB_ANOM_A7_BINS && v >= FAN_L[b + 1]) b++;
    return b;
}

/* The upper edge of the bin where the cumulative weight reaches 95%. */
static double fan_p95(const fan_t *f) {
    double tot = 0, cum = 0;
    for (int i = 0; i < WEB_ANOM_A7_BINS; i++) tot += f->hist[i];
    if (tot <= 0) return 0;
    for (int i = 0; i < WEB_ANOM_A7_BINS; i++) {
        cum += f->hist[i];
        if (cum >= 0.95 * tot)
            return i + 1 < WEB_ANOM_A7_BINS ? FAN_L[i + 1] - 1 : FAN_L[i];
    }
    return FAN_L[WEB_ANOM_A7_BINS - 1];
}

static void fan_window(web_anomaly_t *a, const char *key, double vmax,
                       long long t) {
    struct web_anom_priv *p = a->p;
    int made;
    char gone[WEB_KEY_MAX + 1];
    int i = kv_get(&p->fan_ix, 0, key, t, &made, gone);
    if (gone[0] && p->fan_ndel < FAN_DEL_MAX)
        snprintf(p->fan_del[p->fan_ndel++], WEB_KEY_MAX + 1, "%s", gone);
    p->fan_ix.e[i].t = t;
    fan_t *f = &p->fan[i];
    if (made) {
        memset(f, 0, sizeof(*f));
        f->win_t = -1;
    }
    long long ws = t - t % WEB_ANOM_A7_WINDOW_S;
    if (f->win_t != ws) {
        f->win_t = ws;
        f->win_max = vmax;
    } else if (vmax > f->win_max) {
        f->win_max = vmax;
    }
}

/* A7 at the close of window ws: score, then learn. */
static void a7_close(web_anomaly_t *a, long long ws) {
    struct web_anom_priv *p = a->p;
    static const double decay = 0.99931258; /* 2^(-1/1008) */
    for (int i = 0; i < p->fan_ix.cap; i++) {
        if (!p->fan_ix.e[i].used) continue;
        fan_t *f = &p->fan[i];
        if (f->win_t != ws) continue;
        double v = f->win_max, p95 = fan_p95(f);
        if (f->windows >= WEB_ANOM_A7_MIN_WINDOWS &&
            v > WEB_ANOM_A7_FACTOR * p95 && v >= p95 + WEB_ANOM_A7_MIN_EXCESS) {
            char ev[256];
            snprintf(ev, sizeof(ev), "host.conns[%s] %.0f flows at peak in "
                     "10 min; its p95 is %.0f over %ld windows",
                     p->fan_ix.e[i].key, v, p95, f->windows);
            double ratio = p95 > 0 ? v / p95 : v;
            cand(a, WEB_ANOM_A7_FANOUT, WM_HOST_CONNS, p->fan_ix.e[i].key,
                 40.0 + 10.0 * ratio, ev);
        }
        for (int b = 0; b < WEB_ANOM_A7_BINS; b++) f->hist[b] *= (float)decay;
        f->hist[fan_bin(v)] += 1.0f;
        if (f->windows < LONG_MAX) f->windows++;
        f->win_t = -1;
        f->dirty = 1;
    }
}

/* ── the rules over the identity tables ──────────────────────────────── */

static void a2_scan(web_anomaly_t *a, long long ts) {
    struct web_anom_priv *p = a->p;
    int n = web_ident_firsts(a->cfg.ident, p->firsts, ID_ROWS);
    for (int i = 0; i < n; i++) {
        const web_id_new_t *f = &p->firsts[i];
        long long age = ts - f->first_seen;
        if (age > WEB_ANOM_A2_WINDOW_S || age < -WEB_ANOM_A2_SKEW_S) continue;
        if (kv_find(&p->rep, 0, f->mac) >= 0) continue;
        char ev[256];
        snprintf(ev, sizeof(ev), "%s first seen by sloth %lld min ago (%s)",
                 f->mac, age > 0 ? age / 60 : 0LL, f->src);
        cand(a, WEB_ANOM_A2_NEW, -1, f->mac, 40.0, ev);
    }
}

static int cmp_named(const void *x, const void *y) {
    const web_id_named_t *a = x, *b = y;
    int c = strcmp(a->norm, b->norm);
    return c ? c : strcmp(a->mac, b->mac);
}

static void a5_scan(web_anomaly_t *a, long long ts) {
    struct web_anom_priv *p = a->p;
    int n = web_ident_named(a->cfg.ident, ts, p->named, ID_ROWS);
    qsort(p->named, (size_t)n, sizeof(*p->named), cmp_named);
    for (int i = 0; i < n;) {
        int j = i;
        while (j < n && !strcmp(p->named[j].norm, p->named[i].norm)) j++;
        for (int k = i; k < j; k++) {
            const web_id_named_t *r = &p->named[k];
            if (!r->random) continue;
            const web_id_named_t *other = NULL;
            for (int o = i; o < j && !other; o++)
                if (strcmp(p->named[o].mac, r->mac)) other = &p->named[o];
            if (!other) continue;
            char nb[48], ev[256];
            snprintf(ev, sizeof(ev), "randomised %s has %s name '%s', also "
                     "the name of %s", r->mac, web_ident_src_name(r->src),
                     cut(nb, 40, r->name), other->mac);
            cand(a, WEB_ANOM_A5_IDENT, -1, r->mac, 50.0, ev);
            /* One episode per MAC, however many sources name it. */
            while (k + 1 < j && !strcmp(p->named[k + 1].mac, r->mac)) k++;
        }
        i = j;
    }
}

static int names_agree(const char *x, int xs, const char *y, int ys) {
    char a[WEB_ID_NAME_MAX + 1], b[WEB_ID_NAME_MAX + 1];
    web_ident_norm(x, a);
    web_ident_norm(y, b);
    if (xs == WEB_ID_SRC_NBNS || ys == WEB_ID_SRC_NBNS) {
        a[WEB_ID_NBNS_MAX] = '\0';
        b[WEB_ID_NBNS_MAX] = '\0';
    }
    return !strcmp(a, b);
}

static void a6_scan(web_anomaly_t *a, long long ts) {
    struct web_anom_priv *p = a->p;
    int n = web_ident_ip_names(a->cfg.ident, ts, p->ipn, ID_ROWS);
    for (int i = 0; i < n; i++) {
        const web_id_names_t *r = &p->ipn[i];
        int bad = 0;
        for (int x = 0; x < WEB_ID_SRC_COUNT; x++)
            for (int y = x + 1; y < WEB_ID_SRC_COUNT; y++)
                if (r->name[x][0] && r->name[y][0] &&
                    !names_agree(r->name[x], x, r->name[y], y))
                    bad = 1;
        if (!bad) continue;
        char d[40], m[40], b[40], ev[256];
        snprintf(ev, sizeof(ev), "%s: dhcp '%s' mdns '%s' nbns '%s' disagree",
                 r->ip, cut(d, 32, r->name[WEB_ID_SRC_DHCP]),
                 cut(m, 32, r->name[WEB_ID_SRC_MDNS]),
                 cut(b, 15, r->name[WEB_ID_SRC_NBNS]));
        cand(a, WEB_ANOM_A6_NAMES, -1, r->ip, 40.0, ev);
    }
}

static void a8_scan(web_anomaly_t *a, long long to) {
    struct web_anom_priv *p = a->p;
    int n = web_ident_dns(a->cfg.ident, to, p->dns, ID_ROWS);
    for (int i = 0; i < n; i++) {
        const web_id_dns_t *d = &p->dns[i];
        if (d->q < WEB_ANOM_A8_MIN_Q) continue;
        double share = (double)d->nx / (double)d->q;
        if (share <= WEB_ANOM_A8_NX_SHARE) continue;
        char ev[256];
        snprintf(ev, sizeof(ev), "dns[%s] %u of %u queries answered NXDOMAIN "
                 "in %d min", d->ip, d->nx, d->q, WEB_ANOM_A8_WINDOW_S / 60);
        cand(a, WEB_ANOM_A8_DNS, -1, d->ip, 40.0 + 60.0 * (share > 1 ? 1 : share),
             ev);
    }
}

/* ── episodes ────────────────────────────────────────────────────────── */

static void ep_delete(web_anomaly_t *a, web_anom_ep_t *e) {
    struct web_anom_priv *p = a->p;
    if (e->state == WEB_EP_OPEN || e->state == WEB_EP_CLOSED) {
        if (p->ep_ndel < a->cap * 2) p->ep_del[p->ep_ndel++] = e->id;
    }
    memset(e, 0, sizeof(*e));
}

static void bump(web_anomaly_t *a, web_anom_ep_t *e) {
    e->seq = ++a->seq;
    e->dirty = 1;
}

/* A slot for a new episode: free, else the oldest closed. Never an open
 * one, and never a building one: builders taking each other's slots
 * would keep every one of them from reaching its streak. A building
 * episode that misses a bucket frees its slot at the next sweep. */
static int new_slot_locked(web_anomaly_t *a) {
    int closed_i = -1;
    for (int i = 0; i < a->cap; i++) {
        web_anom_ep_t *e = &a->ep[i];
        if (e->state == WEB_EP_FREE) return i;
        if (e->state == WEB_EP_CLOSED &&
            (closed_i < 0 || e->last_seen < a->ep[closed_i].last_seen))
            closed_i = i;
    }
    if (closed_i >= 0) {
        a->st.evicted_closed++;
        ep_delete(a, &a->ep[closed_i]);
        return closed_i;
    }
    return -1;
}

static web_anom_ep_t *active_locked(web_anomaly_t *a, int rule, int metric,
                                    const char *key) {
    for (int i = 0; i < a->cap; i++) {
        web_anom_ep_t *e = &a->ep[i];
        if ((e->state == WEB_EP_BUILDING || e->state == WEB_EP_OPEN) &&
            e->rule == rule && e->metric == metric && !strcmp(e->key, key))
            return e;
    }
    return NULL;
}

/* 1 when the candidate has an episode (new or advanced), 0 when the
 * table had no room for it. */
static int touch_locked(web_anomaly_t *a, const cand_t *c, long long bucket,
                        long long ts) {
    web_anom_ep_t *e = active_locked(a, c->rule, c->metric, c->key);
    if (!e) {
        int i = new_slot_locked(a);
        if (i < 0) { a->st.dropped++; return 0; }
        e = &a->ep[i];
        memset(e, 0, sizeof(*e));
        e->id = a->p->next_id++;
        e->state = WEB_EP_BUILDING;
        e->rule = c->rule;
        e->metric = c->metric;
        snprintf(e->key, sizeof(e->key), "%s", c->key);
        e->first_seen = ts;
        e->last_bucket = LLONG_MIN;
    }
    /* One bucket advances an episode once, however often it is scored. */
    if (e->last_bucket == bucket) return 1;
    e->last_bucket = bucket;
    e->hit_streak++;
    e->clear_streak = 0;
    e->last_seen = ts;
    e->score = c->score;
    if (c->score > e->peak) e->peak = c->score;
    snprintf(e->evidence, sizeof(e->evidence), "%s", c->ev);
    if (e->state == WEB_EP_BUILDING && e->hit_streak >= req_streak(e->rule)) {
        e->state = WEB_EP_OPEN;
        a->st.opened++;
        bump(a, e);
    } else if (e->state == WEB_EP_OPEN) {
        bump(a, e);
    }
    return 1;
}

/* Apply one evaluated bucket: every candidate, then the quiet sweep for
 * the rules that were evaluated, then the expiry of closed episodes. */
static void apply(web_anomaly_t *a, const int *evaluated, long long bucket,
                  long long ts) {
    struct web_anom_priv *p = a->p;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < p->cand_n; i++)
        /* A2 reports a MAC once: only one that got its episode counts as
         * reported, so a full table delays it rather than losing it. */
        if (touch_locked(a, &p->cand[i], bucket, ts) &&
            p->cand[i].rule == WEB_ANOM_A2_NEW) {
            int made;
            int k = kv_get(&p->rep, 0, p->cand[i].key, ts, &made, NULL);
            p->rep.e[k].t = ts;
            if (made && p->rep_nnew < p->rep_cap) {
                web_store_rep_t *r = &p->rep_new[p->rep_nnew++];
                snprintf(r->kind, sizeof(r->kind), "%s", RULE_NAME[WEB_ANOM_A2_NEW]);
                snprintf(r->key, sizeof(r->key), "%s", p->cand[i].key);
                r->t = ts;
            }
        }
    for (int i = 0; i < a->cap; i++) {
        web_anom_ep_t *e = &a->ep[i];
        if (e->state == WEB_EP_CLOSED) {
            if (ts - e->last_seen > WEB_ANOM_KEEP_S) ep_delete(a, e);
            continue;
        }
        if (e->state == WEB_EP_FREE || !evaluated[e->rule] ||
            e->last_bucket == bucket)
            continue;
        if (e->state == WEB_EP_BUILDING) {
            ep_delete(a, e);
            continue;
        }
        if (++e->clear_streak >= WEB_ANOM_CLEAR_TICKS) {
            e->state = WEB_EP_CLOSED;
            e->hit_streak = 0;
            a->st.closed++;
            bump(a, e);
        }
    }
    pthread_mutex_unlock(&a->mu);
    p->cand_n = 0;
}

/* ── the passes ──────────────────────────────────────────────────────── */

static int idx_push(struct web_anom_priv *p, int i) {
    if (p->idx_n == p->idx_cap) {
        int nc = p->idx_cap ? p->idx_cap * 2 : 1024;
        int *ni = realloc(p->idx, (size_t)nc * sizeof(*ni));
        if (!ni) return -1;
        p->idx = ni;
        p->idx_cap = nc;
    }
    p->idx[p->idx_n++] = i;
    return 0;
}

static void collect_counter(void *ctx, int metric, const char *key) {
    struct web_anom_priv *p = ctx;
    if (web_metric_defs[metric].kclass == WEB_KC_GLOBAL) return;
    if (p->pairs_n == p->pairs_cap) {
        int nc = p->pairs_cap ? p->pairs_cap * 2 : 1024;
        pair_t *np = realloc(p->pairs, (size_t)nc * sizeof(*np));
        if (!np) return;
        p->pairs = np;
        p->pairs_cap = nc;
    }
    p->pairs[p->pairs_n].metric = metric;
    snprintf(p->pairs[p->pairs_n].key, sizeof(p->pairs[0].key), "%s", key);
    p->pairs_n++;
}

static void minute_pass(web_anomaly_t *a, long long m, int latest,
                        long long mono) {
    struct web_anom_priv *p = a->p;
    long long t = m * 60, ts = t + 60;
    int evaluated[WEB_ANOM_RULE_COUNT] = { 0 };
    int observed = minute_observed(a, m);

    p->idx_n = 0;
    for (int i = 0; i < p->agg_alloc; i++)
        if (p->agg[i].used && p->agg[i].tier == WEB_TIER_MINUTE &&
            p->agg[i].t <= t)
            idx_push(p, i);
    if (p->mad_hour != t - t % 3600) p->mad_n = 0;
    p->mad_q = 0;

    if (observed) {
        evaluated[WEB_ANOM_A1_RATE] = evaluated[WEB_ANOM_A3_HOURS] = 1;
        if (a->cfg.store) evaluated[WEB_ANOM_A9_PROTO] = 1;
        for (int k = 0; k < p->idx_n; k++) {
            const agg_t *g = &p->agg[p->idx[k]];
            if (g->t != t) continue;
            web_point_t pt = agg_point(g);
            const web_metric_t *md = &web_metric_defs[g->metric];
            double v = web_bl_value(g->metric, &pt, 60);
            if (md->kind == WEB_MK_PRESENCE) {
                if (v >= 0.5) a3_score(a, g->key, t);
                continue;
            }
            if (md->kclass != WEB_KC_GLOBAL) a1_score(a, g->metric, g->key, t, v);
            if (a->cfg.store && is_flow(g->metric) && v > 0)
                a9_check(a, g->metric, g->key, t);
            if (g->metric == WM_HOST_CONNS) fan_window(a, g->key, g->max, t);
        }
        /* A counter with a baseline and no row counted nothing. */
        p->pairs_n = 0;
        web_baseline_each_counter(a->cfg.bl, collect_counter, p);
        for (int k = 0; k < p->pairs_n; k++)
            if (agg_find(p, WEB_TIER_MINUTE, p->pairs[k].metric,
                         p->pairs[k].key, t) < 0)
                a1_score(a, p->pairs[k].metric, p->pairs[k].key, t, 0.0);
    } else {
        pthread_mutex_lock(&a->mu);
        a->st.minutes_unobserved++;
        pthread_mutex_unlock(&a->mu);
    }
    if (ts % WEB_ANOM_A7_WINDOW_S == 0) {
        long long ws = ts - WEB_ANOM_A7_WINDOW_S;
        if (minutes_observed(a, ws / 60, WEB_ANOM_A7_WINDOW_S / 60) >=
            (a->cfg.live ? 8 : 1)) {
            evaluated[WEB_ANOM_A7_FANOUT] = 1;
            a7_close(a, ws);
        }
    }
    if (a->cfg.ident) {
        evaluated[WEB_ANOM_A2_NEW] = evaluated[WEB_ANOM_A5_IDENT] =
            evaluated[WEB_ANOM_A6_NAMES] = 1;
        a2_scan(a, ts);
        a5_scan(a, ts);
        a6_scan(a, ts);
        if (observed) {
            evaluated[WEB_ANOM_A8_DNS] = 1;
            a8_scan(a, ts);
        }
    }
    if (latest && a->cfg.live) {
        evaluated[WEB_ANOM_A10_SENSOR] = 1;
        int conn;
        long long sil = silence_ms(a, mono, &conn);
        if (conn && sil >= (long long)WEB_ANOM_A10_SILENCE_S * 1000) {
            char ev[160];
            snprintf(ev, sizeof(ev), "no record for %lld s while the socket "
                     "is connected", sil / 1000);
            cand(a, WEB_ANOM_A10_SENSOR, -1, "", 80.0, ev);
        }
    }
    for (int k = 0; k < p->idx_n; k++) agg_release(p, p->idx[k]);
    apply(a, evaluated, t, ts);
}

static void persist_baseline(web_anomaly_t *a) {
    struct web_anom_priv *p = a->p;
    long long ids[256];
    int n;
    if (!a->cfg.store) {
        while (web_baseline_take_deleted(a->cfg.bl, ids, 256) > 0) {}
        return;
    }
    while ((n = web_baseline_take_dirty(a->cfg.bl, p->blrec, 512)) > 0)
        if (web_store_bl_put(a->cfg.store, a->cfg.bl, p->blrec, n) != 0) {
            pthread_mutex_lock(&a->mu);
            a->st.persist_errors++;
            pthread_mutex_unlock(&a->mu);
            break;
        }
    while ((n = web_baseline_take_deleted(a->cfg.bl, ids, 256)) > 0)
        if (web_store_bl_del(a->cfg.store, ids, n) != 0) break;
}

static void hour_pass(web_anomaly_t *a, long long h) {
    struct web_anom_priv *p = a->p;
    int obs = hour_observed(a, h) && (!a->cfg.live || h >= p->start_s);
    p->idx_n = 0;
    for (int i = 0; i < p->agg_alloc; i++)
        if (p->agg[i].used && p->agg[i].tier == WEB_TIER_HOUR &&
            p->agg[i].t <= h)
            idx_push(p, i);
    for (int k = 0; obs && k < p->idx_n; k++) {
        const agg_t *g = &p->agg[p->idx[k]];
        web_point_t pt = agg_point(g);
        web_baseline_feed(a->cfg.bl, g->metric, g->key, g->t,
                          web_bl_value(g->metric, &pt, 3600), 1);
    }
    if (obs) web_baseline_zero_missing(a->cfg.bl, h);
    for (int k = 0; k < p->idx_n; k++) agg_release(p, p->idx[k]);
    web_baseline_age_out(a->cfg.bl, h - WEB_HOUR_KEEP_S);
    pthread_mutex_lock(&a->mu);
    if (obs) a->st.hours_fed++;
    else     a->st.hours_unobserved++;
    pthread_mutex_unlock(&a->mu);
    persist_baseline(a);
}

static void persist(web_anomaly_t *a) {
    struct web_anom_priv *p = a->p;
    int n = 0;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < a->cap && n < a->cap; i++) {
        web_anom_ep_t *e = &a->ep[i];
        if (!e->dirty) continue;
        e->dirty = 0;
        if (e->state != WEB_EP_OPEN && e->state != WEB_EP_CLOSED) continue;
        web_store_ep_t *o = &p->ep_out[n++];
        memset(o, 0, sizeof(*o));
        o->id = e->id;
        snprintf(o->kind, sizeof(o->kind), "%s", RULE_NAME[e->rule]);
        o->metric = e->metric;
        snprintf(o->key, sizeof(o->key), "%s", e->key);
        o->state = e->state;
        o->score = e->score;
        o->peak = e->peak;
        snprintf(o->evidence, sizeof(o->evidence), "%s", e->evidence);
        o->first_seen = e->first_seen;
        o->last_seen = e->last_seen;
        o->hit_streak = e->hit_streak;
        o->clear_streak = e->clear_streak;
        o->last_bucket = e->last_bucket;
    }
    /* ep_del is this thread's own; the lock only orders it with the
     * episodes it came from. */
    int nd = p->ep_ndel;
    p->ep_ndel = 0;
    pthread_mutex_unlock(&a->mu);
    if (!a->cfg.store) { p->rep_nnew = 0; p->fan_ndel = 0; return; }
    int bad = 0;
    if (nd && web_store_ep_del(a->cfg.store, p->ep_del, nd) != 0) bad = 1;
    if (n && web_store_ep_put(a->cfg.store, p->ep_out, n) != 0) bad = 1;
    if (p->rep_nnew && web_store_rep_put(a->cfg.store, p->rep_new,
                                         p->rep_nnew) != 0)
        bad = 1;
    p->rep_nnew = 0;
    if (p->fan_ndel &&
        web_store_fan_del(a->cfg.store, (const char (*)[WEB_KEY_MAX + 1])p->fan_del,
                          p->fan_ndel) != 0)
        bad = 1;
    p->fan_ndel = 0;
    if (bad) {
        pthread_mutex_lock(&a->mu);
        a->st.persist_errors++;
        pthread_mutex_unlock(&a->mu);
    }
}

static void persist_fanout(web_anomaly_t *a) {
    struct web_anom_priv *p = a->p;
    if (!a->cfg.store) return;
    web_store_fan_t batch[64];
    int n = 0;
    for (int i = 0; i < p->fan_ix.cap; i++) {
        if (!p->fan_ix.e[i].used || !p->fan[i].dirty) continue;
        fan_t *f = &p->fan[i];
        web_store_fan_t *o = &batch[n++];
        snprintf(o->key, sizeof(o->key), "%s", p->fan_ix.e[i].key);
        o->windows = f->windows;
        size_t off = 0;
        o->hist[0] = '\0';
        for (int b = 0; b < WEB_ANOM_A7_BINS; b++) {
            int w = snprintf(o->hist + off, sizeof(o->hist) - off, "%s%.6g",
                             b ? "," : "", (double)f->hist[b]);
            if (w < 0 || (size_t)w >= sizeof(o->hist) - off) break;
            off += (size_t)w;
        }
        f->dirty = 0;
        if (n == 64) {
            web_store_fan_put(a->cfg.store, batch, n);
            n = 0;
        }
    }
    if (n) web_store_fan_put(a->cfg.store, batch, n);
}

void web_anomaly_rows(void *ctx, const web_qrow_t *rows, size_t n) {
    web_anomaly_t *a = ctx;
    struct web_anom_priv *p = a->p;
    unsigned long dropped = 0, late = 0;
    for (size_t i = 0; i < n; i++) {
        const web_qrow_t *r = &rows[i];
        if (r->metric < 0 || r->metric >= WM_COUNT) continue;
        if (r->tier == WEB_TIER_MINUTE) {
            if (p->start_s >= 0 && r->t / 60 <= p->done_minute) {
                /* Released late (a key established after its first
                 * minute): too late to score, still a window sample. */
                if (r->metric == WM_HOST_CONNS) fan_window(a, r->key, r->max, r->t);
                late++;
                continue;
            }
        } else if (r->tier == WEB_TIER_HOUR) {
            if (p->final_hour != LLONG_MIN && r->t <= p->final_hour) {
                if (hour_observed(a, r->t) &&
                    (!a->cfg.live || r->t >= p->start_s)) {
                    web_point_t pt = { r->t, r->sum, r->min, r->max, r->n };
                    web_baseline_feed(a->cfg.bl, r->metric, r->key, r->t,
                                      web_bl_value(r->metric, &pt, 3600), 1);
                }
                late++;
                continue;
            }
        } else {
            continue;
        }
        if (agg_put(p, r) != 0) dropped++;
    }
    if (dropped || late) {
        pthread_mutex_lock(&a->mu);
        a->st.rows_dropped += dropped;
        a->st.late_rows += late;
        pthread_mutex_unlock(&a->mu);
    }
}

void web_anomaly_step(web_anomaly_t *a, long long now_s) {
    struct web_anom_priv *p = a->p;
    long long mono = a->cfg.mono(a->cfg.mono_ctx);
    long long m_now = now_s / 60;
    long long h_now = now_s - now_s % 3600;
    if (p->start_s < 0) {
        p->start_s = now_s;
        p->done_minute = m_now - 1;
        p->final_hour = h_now - 3600;
    }
    if (a->cfg.live) {
        int conn;
        long long sil = silence_ms(a, mono, &conn);
        unsigned char *c = cov_slot(p, m_now, 1);
        *c |= conn && sil >= 0 && sil <= (long long)WEB_ANOM_A10_SILENCE_S * 1000
            ? COV_OK : COV_BAD;
    }
    /* Minutes before hours: the hour's own last minute is scored
     * against the cell before that hour is fed into it. */
    if (m_now - 1 - p->done_minute > 60) {
        pthread_mutex_lock(&a->mu);
        a->st.minutes_unobserved += (unsigned long)(m_now - 61 - p->done_minute);
        pthread_mutex_unlock(&a->mu);
        p->done_minute = m_now - 61;
    }
    int ran = 0, fan_closed = 0;
    for (long long m = p->done_minute + 1; m < m_now; m++) {
        minute_pass(a, m, m == m_now - 1, mono);
        if (((m + 1) * 60) % WEB_ANOM_A7_WINDOW_S == 0) fan_closed = 1;
        ran = 1;
    }
    if (m_now - 1 > p->done_minute) p->done_minute = m_now - 1;
    if (p->final_hour < h_now - 3600) {
        hour_pass(a, h_now - 3600);
        p->final_hour = h_now - 3600;
        if (a->cfg.store)
            web_store_rep_prune(a->cfg.store,
                                now_s - WEB_ANOM_A2_WINDOW_S - WEB_ANOM_A2_SKEW_S);
        for (int i = 0; i < p->rep.cap; i++)
            if (p->rep.e[i].used &&
                p->rep.e[i].t < now_s - WEB_ANOM_A2_WINDOW_S - WEB_ANOM_A2_SKEW_S)
                kv_del(&p->rep, i);
    }
    if (ran) persist(a);
    if (fan_closed) persist_fanout(a);
    pthread_mutex_lock(&a->mu);
    a->st.fanout_evictions = p->fan_ix.evictions;
    a->st.reported_evictions = p->rep.evictions;
    a->st.known_evictions = p->known.evictions;
    a->st.fanout = p->fan_ix.n;
    a->st.reported = p->rep.n;
    pthread_mutex_unlock(&a->mu);
}

static void step_hook(void *ctx, long long now_s) {
    web_anomaly_step(ctx, now_s);
}

void web_anomaly_attach(web_anomaly_t *a, web_tsdb_t *t) {
    web_tsdb_set_rows_hook(t, web_anomaly_rows, a);
    web_tsdb_set_hook(t, step_hook, a);
}

/* ── restore ─────────────────────────────────────────────────────────── */

static void restore_ep(void *ctx, const web_store_ep_t *s) {
    web_anomaly_t *a = ctx;
    int rule = rule_find(s->kind);
    if (rule < 0 || (s->state != WEB_EP_OPEN && s->state != WEB_EP_CLOSED))
        return;
    int slot = -1;
    for (int i = 0; i < a->cap; i++)
        if (a->ep[i].state == WEB_EP_FREE) { slot = i; break; }
    if (slot < 0) return;
    web_anom_ep_t *e = &a->ep[slot];
    memset(e, 0, sizeof(*e));
    e->id = s->id;
    e->state = s->state;
    e->rule = rule;
    e->metric = s->metric;
    snprintf(e->key, sizeof(e->key), "%s", s->key);
    e->score = isfinite(s->score) ? s->score : 0;
    e->peak = isfinite(s->peak) ? s->peak : 0;
    web_utf8_copy(e->evidence, WEB_ANOM_EVIDENCE_MAX, s->evidence);
    e->first_seen = s->first_seen;
    e->last_seen = s->last_seen;
    e->hit_streak = s->hit_streak;
    e->clear_streak = s->clear_streak;
    e->last_bucket = s->last_bucket;
    e->seq = ++a->seq;
    if (s->id >= a->p->next_id) a->p->next_id = s->id + 1;
}

static void restore_fan(void *ctx, const web_store_fan_t *f) {
    web_anomaly_t *a = ctx;
    struct web_anom_priv *p = a->p;
    if (p->fan_ix.n >= p->fan_ix.cap) return;
    int made;
    int i = kv_get(&p->fan_ix, 0, f->key, 0, &made, NULL);
    fan_t *x = &p->fan[i];
    memset(x, 0, sizeof(*x));
    x->win_t = -1;
    x->windows = f->windows > 0 ? f->windows : 0;
    const char *s = f->hist;
    for (int b = 0; b < WEB_ANOM_A7_BINS && *s; b++) {
        char *end;
        double v = strtod(s, &end);
        if (end == s || !isfinite(v) || v < 0) break;
        x->hist[b] = (float)v;
        s = *end == ',' ? end + 1 : end;
    }
}

static void restore_rep(void *ctx, const web_store_rep_t *r) {
    web_anomaly_t *a = ctx;
    struct web_anom_priv *p = a->p;
    if (strcmp(r->kind, RULE_NAME[WEB_ANOM_A2_NEW])) return;
    if (p->rep.n >= p->rep.cap) return;
    int made;
    int i = kv_get(&p->rep, 0, r->key, r->t, &made, NULL);
    p->rep.e[i].t = r->t;
}

int web_anomaly_restore(web_anomaly_t *a, long long now_s) {
    if (!a->cfg.store) return 0;
    int bad = 0;
    if (web_store_bl_load(a->cfg.store, a->cfg.bl) < 0) bad = 1;
    pthread_mutex_lock(&a->mu);
    if (web_store_ep_load(a->cfg.store, now_s - WEB_ANOM_KEEP_S, restore_ep, a) < 0)
        bad = 1;
    pthread_mutex_unlock(&a->mu);
    if (web_store_fan_load(a->cfg.store, restore_fan, a) < 0) bad = 1;
    if (web_store_rep_load(a->cfg.store,
                           now_s - WEB_ANOM_A2_WINDOW_S - WEB_ANOM_A2_SKEW_S,
                           restore_rep, a) < 0)
        bad = 1;
    return bad ? -1 : 0;
}

/* ── readers ─────────────────────────────────────────────────────────── */

void web_anomaly_ep_json(web_jw_t *w, const web_anom_ep_t *e) {
    static const char *const STATE[] = { "free", "building", "open", "closed" };
    web_jw_raw(w, "{\"id\":");          web_jw_int(w, e->id);
    web_jw_raw(w, ",\"rule\":\"");       web_jw_raw(w, web_anomaly_rule(e->rule));
    web_jw_raw(w, "\",\"kind\":\"");     web_jw_raw(w, web_anomaly_kind(e->rule));
    web_jw_raw(w, "\",\"metric\":");
    if (e->metric >= 0 && e->metric < WM_COUNT) {
        web_jw_raw(w, "\"");
        web_jw_raw(w, web_metric_defs[e->metric].name);
        web_jw_raw(w, "\"");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"key\":");          web_jw_str(w, e->key);
    web_jw_raw(w, ",\"score\":");        web_jw_int(w, (long long)(e->score + 0.5));
    web_jw_raw(w, ",\"peak\":");         web_jw_int(w, (long long)(e->peak + 0.5));
    web_jw_raw(w, ",\"evidence\":");     web_jw_str(w, e->evidence);
    web_jw_raw(w, ",\"first_seen\":");   web_jw_int(w, e->first_seen);
    web_jw_raw(w, ",\"last_seen\":");    web_jw_int(w, e->last_seen);
    web_jw_raw(w, ",\"state\":\"");
    web_jw_raw(w, e->state >= 0 && e->state <= 3 ? STATE[e->state] : "?");
    web_jw_raw(w, "\",\"open\":");       web_jw_raw(w, e->state == WEB_EP_OPEN ? "true" : "false");
    web_jw_raw(w, "}");
}

static int cmp_listed(const void *x, const void *y) {
    const web_anom_ep_t *a = x, *b = y;
    int ao = a->state == WEB_EP_OPEN, bo = b->state == WEB_EP_OPEN;
    if (ao != bo) return ao ? -1 : 1;
    if (ao) {
        if (a->score != b->score) return a->score > b->score ? -1 : 1;
    }
    if (a->last_seen != b->last_seen) return a->last_seen > b->last_seen ? -1 : 1;
    return a->id < b->id ? -1 : a->id > b->id;
}

size_t web_anomaly_json(web_anomaly_t *a, long long now_s, long long since,
                        int kind, char *out, size_t cap) {
    if (cap < WEB_ANOM_EP_JSON_MAX + 128) return 0;
    web_anom_ep_t *list = malloc((size_t)a->cap * sizeof(*list));
    if (!list) return 0;
    int n = 0;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < a->cap; i++) {
        const web_anom_ep_t *e = &a->ep[i];
        if (e->state != WEB_EP_OPEN && e->state != WEB_EP_CLOSED) continue;
        if (kind >= 0 && kind_index(e->rule) != kind) continue;
        if (e->state == WEB_EP_CLOSED && e->last_seen < since) continue;
        list[n++] = *e;
    }
    pthread_mutex_unlock(&a->mu);
    qsort(list, (size_t)n, sizeof(*list), cmp_listed);
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"now\":");     web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"since\":");   web_jw_int(&w, since);
    web_jw_raw(&w, ",\"anomalies\":[");
    int shown = 0;
    /* Room for one more episode and the trailer, or stop with "more". */
    for (int i = 0; i < n; i++) {
        if (w.len + WEB_ANOM_EP_JSON_MAX + 96 >= cap) break;
        if (shown) web_jw_raw(&w, ",");
        web_anomaly_ep_json(&w, &list[i]);
        shown++;
    }
    free(list);
    web_jw_raw(&w, "],\"more\":");
    web_jw_raw(&w, shown < n ? "true" : "false");
    web_jw_raw(&w, ",\"omitted\":"); web_jw_int(&w, n - shown);
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

int web_anomaly_changes(web_anomaly_t *a, unsigned long long after,
                        web_anom_ep_t *out, int max,
                        unsigned long long *latest) {
    int n = 0;
    pthread_mutex_lock(&a->mu);
    *latest = a->seq;
    /* The newest max changes, oldest first: walk seq windows from the
     * top. Episodes are few (WEB_ANOM_CAP), so a selection is cheap. */
    unsigned long long floor_seq = after;
    for (;;) {
        int cnt = 0;
        unsigned long long lo = ULLONG_MAX;
        for (int i = 0; i < a->cap; i++) {
            const web_anom_ep_t *e = &a->ep[i];
            if ((e->state == WEB_EP_OPEN || e->state == WEB_EP_CLOSED) &&
                e->seq > floor_seq) {
                cnt++;
                if (e->seq < lo) lo = e->seq;
            }
        }
        if (cnt <= max) break;
        floor_seq = lo;
    }
    for (int i = 0; i < a->cap; i++) {
        const web_anom_ep_t *e = &a->ep[i];
        if ((e->state == WEB_EP_OPEN || e->state == WEB_EP_CLOSED) &&
            e->seq > floor_seq && n < max)
            out[n++] = *e;
    }
    pthread_mutex_unlock(&a->mu);
    for (int i = 1; i < n; i++) {
        web_anom_ep_t x = out[i];
        int j = i - 1;
        while (j >= 0 && out[j].seq > x.seq) { out[j + 1] = out[j]; j--; }
        out[j + 1] = x;
    }
    return n;
}

int web_anomaly_open_count(web_anomaly_t *a) {
    int n = 0;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < a->cap; i++) n += a->ep[i].state == WEB_EP_OPEN;
    pthread_mutex_unlock(&a->mu);
    return n;
}

void web_anomaly_stats(web_anomaly_t *a, web_anom_stats_t *out) {
    pthread_mutex_lock(&a->mu);
    *out = a->st;
    out->open = out->building = out->closed_kept = 0;
    for (int i = 0; i < a->cap; i++) {
        out->open += a->ep[i].state == WEB_EP_OPEN;
        out->building += a->ep[i].state == WEB_EP_BUILDING;
        out->closed_kept += a->ep[i].state == WEB_EP_CLOSED;
    }
    pthread_mutex_unlock(&a->mu);
}
