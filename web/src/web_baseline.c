#include "web_baseline.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same per-class caps web_rollup_init() uses (web_rollup.c), computed
 * again here rather than exposed from there: the baseline table's
 * worst case is "every class at its own cap, once per metric in that
 * class", which is exactly web_rollup_init()'s series_max. */
int web_baseline_cap_for(int max_keys) {
    if (max_keys < WEB_MAX_KEYS_MIN) max_keys = WEB_MAX_KEYS_MIN;
    if (max_keys > WEB_MAX_KEYS_MAX) max_keys = WEB_MAX_KEYS_MAX;
    const int caps[WEB_KC_COUNT] = {
        1, max_keys, max_keys / 2, WEB_IFACE_KEYS, WEB_CHANNEL_KEYS,
        WEB_ALERT_KEYS
    };
    size_t total = 0;
    for (int m = 0; m < WM_COUNT; m++)
        total += (size_t)caps[web_metric_defs[m].kclass];
    return total > (size_t)WEB_MAX_KEYS_MAX * 16
        ? (int)(WEB_MAX_KEYS_MAX * 16) : (int)total;
}

int web_bl_cell_index(long long t) {
    long long h = t / 3600;
    long long idx = h % WEB_BL_CELLS;
    if (idx < 0) idx += WEB_BL_CELLS;
    return (int)idx;
}

static unsigned hash_entry(int metric, const char *key) {
    unsigned h = 5381u ^ ((unsigned)metric * 0x9e3779b1u);
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        h = h * 33u + *p;
    return h;
}

int web_baseline_init(web_baseline_t *b, int cap) {
    memset(b, 0, sizeof(*b));
    if (cap < 1) cap = 1;
    b->cap = cap;
    pthread_mutex_init(&b->mu, NULL);
    b->nhead = 1;
    while (b->nhead < cap * 2) b->nhead <<= 1;
    b->e = calloc((size_t)cap, sizeof(*b->e));
    b->head = malloc((size_t)b->nhead * sizeof(*b->head));
    if (!b->e || !b->head) {
        web_baseline_destroy(b);
        return -1;
    }
    for (int i = 0; i < b->nhead; i++) b->head[i] = -1;
    for (int i = 0; i < cap; i++) b->e[i].next = -1;
    return 0;
}

void web_baseline_destroy(web_baseline_t *b) {
    free(b->e);
    free(b->head);
    b->e = NULL;
    b->head = NULL;
}

static int find_locked(web_baseline_t *b, int metric, const char *key) {
    unsigned h = hash_entry(metric, key) & (unsigned)(b->nhead - 1);
    for (int i = b->head[h]; i >= 0; i = b->e[i].next)
        if (b->e[i].used && b->e[i].metric == metric &&
            !strcmp(b->e[i].key, key))
            return i;
    return -1;
}

static void unlink_locked(web_baseline_t *b, int idx) {
    unsigned h = hash_entry(b->e[idx].metric, b->e[idx].key) &
                 (unsigned)(b->nhead - 1);
    int *pp = &b->head[h];
    while (*pp >= 0 && *pp != idx) pp = &b->e[*pp].next;
    if (*pp == idx) *pp = b->e[idx].next;
}

static int lru_victim(web_baseline_t *b) {
    int victim = -1;
    for (int i = 0; i < b->cap; i++) {
        if (!b->e[i].used) return i;
        if (victim < 0 || b->e[i].last_seen < b->e[victim].last_seen)
            victim = i;
    }
    return victim;
}

static int get_or_create_locked(web_baseline_t *b, int metric,
                                const char *key, long long now_s) {
    int idx = find_locked(b, metric, key);
    if (idx >= 0) return idx;
    idx = -1;
    for (int i = 0; i < b->cap; i++)
        if (!b->e[i].used) { idx = i; break; }
    if (idx < 0) {
        idx = lru_victim(b);
        unlink_locked(b, idx);
        b->evictions++;
    } else {
        b->n++;
    }
    memset(&b->e[idx], 0, sizeof(b->e[idx]));
    snprintf(b->e[idx].key, sizeof(b->e[idx].key), "%s", key);
    b->e[idx].metric = metric;
    b->e[idx].used = 1;
    b->e[idx].last_seen = now_s;
    unsigned h = hash_entry(metric, key) & (unsigned)(b->nhead - 1);
    b->e[idx].next = b->head[h];
    b->head[h] = idx;
    return idx;
}

void web_baseline_feed(web_baseline_t *b, int metric, const char *key,
                       long long t, double value) {
    if (!isfinite(value)) return;
    pthread_mutex_lock(&b->mu);
    int idx = get_or_create_locked(b, metric, key, t);
    b->e[idx].last_seen = t;
    web_bl_cell_t *c = &b->e[idx].cell[web_bl_cell_index(t)];
    if (c->n == 0) {
        c->mean = value;
        c->var = 0;
        c->n = 1;
    } else {
        static const double alpha = 0.15910358474628547; /* 1 - 2^(-1/4) */
        double delta = value - c->mean;
        c->mean += alpha * delta;
        c->var = (1.0 - alpha) * (c->var + alpha * delta * delta);
        if (c->n < 1000000) c->n++;
    }
    pthread_mutex_unlock(&b->mu);
}

int web_baseline_score(web_baseline_t *b, int metric, const char *key,
                       long long now_s, double value, web_bl_score_t *out) {
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&b->mu);
    int idx = find_locked(b, metric, key);
    if (idx < 0) {
        pthread_mutex_unlock(&b->mu);
        return -1;
    }
    web_bl_cell_t *c = &b->e[idx].cell[web_bl_cell_index(now_s)];
    out->mean = c->mean;
    out->n = c->n;
    out->warming = c->n < WEB_BL_WARM_N;
    out->sd = sqrt(c->var + WEB_BL_VAR_EPS);
    out->z = out->warming ? 0.0 : (value - c->mean) / out->sd;
    pthread_mutex_unlock(&b->mu);
    return 0;
}

unsigned long web_baseline_evictions(web_baseline_t *b) {
    pthread_mutex_lock(&b->mu);
    unsigned long v = b->evictions;
    pthread_mutex_unlock(&b->mu);
    return v;
}

int web_baseline_count(web_baseline_t *b) {
    pthread_mutex_lock(&b->mu);
    int v = b->n;
    pthread_mutex_unlock(&b->mu);
    return v;
}
