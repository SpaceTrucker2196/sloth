#include "web_baseline.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The same per-class caps web_rollup_init() uses: every class at its
 * own cap, once per metric in that class. */
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
    return (int)total;
}

int web_bl_cell_index(long long t) {
    time_t tt = (time_t)t;
    struct tm tm;
    if (!localtime_r(&tt, &tm)) return 0;
    int wd = (tm.tm_wday + 6) % 7;            /* Monday 0 */
    int h = tm.tm_hour;
    if (wd < 0 || wd > 6 || h < 0 || h > 23) return 0;
    return wd * 24 + h;
}

double web_bl_value(int metric, const web_point_t *p, int step) {
    if (metric < 0 || metric >= WM_COUNT || !p->n) return 0;
    switch (web_metric_defs[metric].kind) {
    case WEB_MK_COUNTER:  return step > 0 ? p->sum * 60.0 / (double)step : p->sum;
    case WEB_MK_PRESENCE: return p->max;
    default:              return p->sum / (double)p->n;
    }
}

double web_bl_sd_floor(int metric, double mean) {
    double unit = 1.0;
    if (metric >= 0 && metric < WM_COUNT &&
        !strcmp(web_metric_defs[metric].unit, "B/s"))
        unit = 1024.0;
    double rel = WEB_BL_SD_REL * fabs(mean);
    return rel > unit ? rel : unit;
}

static unsigned hash_entry(int metric, const char *key) {
    unsigned h = 5381u ^ ((unsigned)metric * 0x9e3779b1u);
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        h = h * 33u + *p;
    return h;
}

static web_bl_entry_t *E(web_baseline_t *b, int i) {
    return &b->chunk[i / WEB_BL_CHUNK][i % WEB_BL_CHUNK];
}

int web_baseline_init(web_baseline_t *b, int cap) {
    memset(b, 0, sizeof(*b));
    if (cap < 1) cap = 1;
    b->cap = cap;
    pthread_mutex_init(&b->mu, NULL);
    b->nchunk = (cap + WEB_BL_CHUNK - 1) / WEB_BL_CHUNK;
    b->chunk = calloc((size_t)b->nchunk, sizeof(*b->chunk));
    b->nhead = 1;
    while (b->nhead < cap * 2) b->nhead <<= 1;
    b->head = malloc((size_t)b->nhead * sizeof(*b->head));
    if (!b->chunk || !b->head) {
        web_baseline_destroy(b);
        return -1;
    }
    for (int i = 0; i < b->nhead; i++) b->head[i] = -1;
    b->free_head = -1;
    b->lru_head = b->lru_tail = -1;
    return 0;
}

void web_baseline_destroy(web_baseline_t *b) {
    if (b->chunk)
        for (int i = 0; i < b->nchunk; i++) free(b->chunk[i]);
    free(b->chunk);
    free(b->head);
    b->chunk = NULL;
    b->head = NULL;
}

static int find_locked(web_baseline_t *b, int metric, const char *key) {
    unsigned h = hash_entry(metric, key) & (unsigned)(b->nhead - 1);
    for (int i = b->head[h]; i >= 0; i = E(b, i)->hnext) {
        web_bl_entry_t *e = E(b, i);
        if (e->metric == metric && !strcmp(e->key, key)) return i;
    }
    return -1;
}

static void lru_unlink(web_baseline_t *b, int i) {
    web_bl_entry_t *e = E(b, i);
    if (e->lprev >= 0) E(b, e->lprev)->lnext = e->lnext;
    else               b->lru_head = e->lnext;
    if (e->lnext >= 0) E(b, e->lnext)->lprev = e->lprev;
    else               b->lru_tail = e->lprev;
    e->lprev = e->lnext = -1;
}

static void lru_push_front(web_baseline_t *b, int i) {
    web_bl_entry_t *e = E(b, i);
    e->lprev = -1;
    e->lnext = b->lru_head;
    if (b->lru_head >= 0) E(b, b->lru_head)->lprev = i;
    b->lru_head = i;
    if (b->lru_tail < 0) b->lru_tail = i;
}

/* Kept in last_active order. Feeds come an hour at a time in time
 * order, so a touched entry goes to the front; a restore, most recent
 * first, appends at the tail. Only a late row walks. */
static void lru_place(web_baseline_t *b, int i) {
    lru_unlink(b, i);
    long long la = E(b, i)->last_active;
    if (b->lru_tail >= 0 && E(b, b->lru_tail)->last_active >= la) {
        web_bl_entry_t *e = E(b, i);
        e->lprev = b->lru_tail;
        e->lnext = -1;
        E(b, b->lru_tail)->lnext = i;
        b->lru_tail = i;
        return;
    }
    int after = -1;
    for (int j = b->lru_head; j >= 0 && E(b, j)->last_active > la;
         j = E(b, j)->lnext)
        after = j;
    if (after < 0) { lru_push_front(b, i); return; }
    web_bl_entry_t *e = E(b, i), *a = E(b, after);
    e->lprev = after;
    e->lnext = a->lnext;
    if (a->lnext >= 0) E(b, a->lnext)->lprev = i;
    else               b->lru_tail = i;
    a->lnext = i;
}

static void unhash(web_baseline_t *b, int idx) {
    web_bl_entry_t *x = E(b, idx);
    unsigned h = hash_entry(x->metric, x->key) & (unsigned)(b->nhead - 1);
    int *pp = &b->head[h];
    while (*pp >= 0 && *pp != idx) pp = &E(b, *pp)->hnext;
    if (*pp == idx) *pp = x->hnext;
}

static void queue_delete(web_baseline_t *b, long long id) {
    if (id < 0) return;
    if (b->ndel >= WEB_BL_DEL_MAX) {
        memmove(b->del, b->del + 1, (WEB_BL_DEL_MAX - 1) * sizeof(b->del[0]));
        b->ndel--;
        b->del_lost++;
    }
    b->del[b->ndel++] = id;
}

static void drop_locked(web_baseline_t *b, int idx) {
    web_bl_entry_t *e = E(b, idx);
    unhash(b, idx);
    lru_unlink(b, idx);
    queue_delete(b, e->db_id);
    e->used = 0;
    e->hnext = b->free_head;
    b->free_head = idx;
    b->n--;
}

static int take_slot(web_baseline_t *b) {
    if (b->free_head < 0 && b->alloc < b->cap) {
        int c = b->alloc / WEB_BL_CHUNK;
        if (!b->chunk[c]) {
            b->chunk[c] = calloc(WEB_BL_CHUNK, sizeof(web_bl_entry_t));
            if (!b->chunk[c]) return -1;
        }
        int end = b->alloc + WEB_BL_CHUNK;
        if (end > b->cap) end = b->cap;
        for (int i = end - 1; i >= b->alloc; i--) {
            E(b, i)->hnext = b->free_head;
            b->free_head = i;
        }
        b->alloc = end;
    }
    if (b->free_head < 0) {
        if (b->lru_tail < 0) return -1;
        drop_locked(b, b->lru_tail);
        b->evictions++;
    }
    int idx = b->free_head;
    b->free_head = E(b, idx)->hnext;
    return idx;
}

static int create_locked(web_baseline_t *b, int metric, const char *key) {
    int idx = take_slot(b);
    if (idx < 0) return -1;
    web_bl_entry_t *e = E(b, idx);
    memset(e, 0, sizeof(*e));
    snprintf(e->key, sizeof(e->key), "%s", key);
    e->metric = metric;
    e->used = 1;
    e->db_id = -1;
    e->last_active = e->last_fed = -1;
    e->lprev = e->lnext = -1;
    unsigned h = hash_entry(metric, key) & (unsigned)(b->nhead - 1);
    e->hnext = b->head[h];
    b->head[h] = idx;
    lru_push_front(b, idx);
    b->n++;
    return idx;
}

static int valid_pair(int metric, const char *key) {
    return metric >= 0 && metric < WM_COUNT && key &&
           strlen(key) <= WEB_KEY_MAX;
}

static void feed_cell(web_bl_entry_t *e, int ci, double value) {
    web_bl_cell_t *c = &e->cell[ci];
    if (c->n == 0) {
        c->mean = (float)value;
        c->var = 0;
        c->n = 1;
    } else {
        static const double alpha = 0.15910358474628547; /* 1 - 2^(-1/4) */
        double mean = c->mean, var = c->var;
        double delta = value - mean;
        mean += alpha * delta;
        var = (1.0 - alpha) * (var + alpha * delta * delta);
        c->mean = (float)mean;
        c->var = (float)var;
        if (c->n < WEB_BL_N_MAX) c->n++;
    }
    e->dirty[ci / 8] |= (uint8_t)(1u << (ci % 8));
    e->dirty_meta = 1;
}

int web_baseline_feed(web_baseline_t *b, int metric, const char *key,
                      long long t, double value, int real) {
    if (!isfinite(value) || !valid_pair(metric, key)) return -1;
    if (value > WEB_VALUE_MAX) value = WEB_VALUE_MAX;
    if (value < -WEB_VALUE_MAX) value = -WEB_VALUE_MAX;
    pthread_mutex_lock(&b->mu);
    int idx = find_locked(b, metric, key);
    if (idx < 0) {
        if (!real) { pthread_mutex_unlock(&b->mu); return -1; }
        idx = create_locked(b, metric, key);
        if (idx < 0) { pthread_mutex_unlock(&b->mu); return -1; }
    }
    web_bl_entry_t *e = E(b, idx);
    if (t <= e->last_fed) {
        b->skipped_dup++;
        pthread_mutex_unlock(&b->mu);
        return -1;
    }
    feed_cell(e, web_bl_cell_index(t), value);
    e->last_fed = t;
    if (real) {
        b->fed++;
        if (t > e->last_active) {
            e->last_active = t;
            lru_place(b, idx);
        }
    } else {
        b->zero_fed++;
    }
    pthread_mutex_unlock(&b->mu);
    return 0;
}

int web_baseline_zero_missing(web_baseline_t *b, long long t) {
    int n = 0;
    pthread_mutex_lock(&b->mu);
    int ci = web_bl_cell_index(t);
    for (int i = b->lru_head; i >= 0; i = E(b, i)->lnext) {
        web_bl_entry_t *e = E(b, i);
        int k = web_metric_defs[e->metric].kind;
        if (k == WEB_MK_GAUGE || e->last_fed >= t) continue;
        feed_cell(e, ci, 0.0);
        e->last_fed = t;
        b->zero_fed++;
        n++;
    }
    pthread_mutex_unlock(&b->mu);
    return n;
}

int web_baseline_age_out(web_baseline_t *b, long long before) {
    int n = 0;
    pthread_mutex_lock(&b->mu);
    while (b->lru_tail >= 0 && E(b, b->lru_tail)->last_active < before) {
        drop_locked(b, b->lru_tail);
        b->aged_out++;
        n++;
    }
    pthread_mutex_unlock(&b->mu);
    return n;
}

int web_baseline_score(web_baseline_t *b, int metric, const char *key,
                       long long t, double value, web_bl_score_t *out) {
    memset(out, 0, sizeof(*out));
    if (!valid_pair(metric, key)) return -1;
    pthread_mutex_lock(&b->mu);
    int idx = find_locked(b, metric, key);
    if (idx < 0) {
        pthread_mutex_unlock(&b->mu);
        return -1;
    }
    const web_bl_cell_t *c = &E(b, idx)->cell[web_bl_cell_index(t)];
    out->mean = c->mean;
    out->n = c->n;
    out->warming = c->n < WEB_BL_WARM_N;
    double sd = sqrt(c->var > 0 ? (double)c->var : 0.0);
    double fl = web_bl_sd_floor(metric, out->mean);
    out->sd = sd > fl ? sd : fl;
    out->z = out->warming ? 0.0 : (value - out->mean) / out->sd;
    pthread_mutex_unlock(&b->mu);
    return 0;
}

int web_baseline_cells(web_baseline_t *b, int metric, const char *key,
                       web_bl_cell_t out[WEB_BL_CELLS]) {
    if (!valid_pair(metric, key)) return -1;
    pthread_mutex_lock(&b->mu);
    int idx = find_locked(b, metric, key);
    if (idx >= 0) memcpy(out, E(b, idx)->cell, sizeof(E(b, idx)->cell));
    pthread_mutex_unlock(&b->mu);
    return idx >= 0 ? 0 : -1;
}

void web_baseline_each_counter(web_baseline_t *b,
                               void (*fn)(void *ctx, int metric,
                                          const char *key),
                               void *ctx) {
    pthread_mutex_lock(&b->mu);
    for (int i = b->lru_head; i >= 0; i = E(b, i)->lnext) {
        web_bl_entry_t *e = E(b, i);
        if (web_metric_defs[e->metric].kind == WEB_MK_COUNTER)
            fn(ctx, e->metric, e->key);
    }
    pthread_mutex_unlock(&b->mu);
}

int web_baseline_take_dirty(web_baseline_t *b, web_bl_rec_t *out, int max) {
    int n = 0;
    pthread_mutex_lock(&b->mu);
    for (int i = b->lru_head; i >= 0 && n < max; i = E(b, i)->lnext) {
        web_bl_entry_t *e = E(b, i);
        if (!e->dirty_meta) continue;
        /* A new entry's row first: its cells need the id it gets. */
        int rows_needed = e->db_id < 0 ? 1 : 0;
        for (int c = 0; c < WEB_BL_CELLS; c++)
            if (e->dirty[c / 8] & (1u << (c % 8))) rows_needed++;
        if (rows_needed == 0) rows_needed = 1;
        if (n + rows_needed > max && n > 0) break;
        int wrote_meta = 0;
        for (int c = -1; c < WEB_BL_CELLS && n < max; c++) {
            if (c >= 0 && !(e->dirty[c / 8] & (1u << (c % 8)))) continue;
            if (c < 0 && wrote_meta) continue;
            web_bl_rec_t *r = &out[n++];
            r->db_id = e->db_id;
            r->metric = e->metric;
            memcpy(r->key, e->key, sizeof(r->key));
            r->last_active = e->last_active;
            r->last_fed = e->last_fed;
            r->cell = c;
            if (c >= 0) {
                r->mean = e->cell[c].mean;
                r->var = e->cell[c].var;
                r->n = e->cell[c].n;
                e->dirty[c / 8] &= (uint8_t)~(1u << (c % 8));
            } else {
                r->mean = r->var = 0;
                r->n = 0;
                wrote_meta = 1;
            }
        }
        int left = 0;
        for (size_t c = 0; c < sizeof(e->dirty); c++) left |= e->dirty[c];
        if (!left) e->dirty_meta = 0;
    }
    pthread_mutex_unlock(&b->mu);
    return n;
}

void web_baseline_set_dbid(web_baseline_t *b, int metric, const char *key,
                           long long id) {
    if (!valid_pair(metric, key)) return;
    pthread_mutex_lock(&b->mu);
    int idx = find_locked(b, metric, key);
    if (idx >= 0) E(b, idx)->db_id = id;
    pthread_mutex_unlock(&b->mu);
}

int web_baseline_take_deleted(web_baseline_t *b, long long *out, int max) {
    pthread_mutex_lock(&b->mu);
    int n = b->ndel < max ? b->ndel : max;
    memcpy(out, b->del, (size_t)n * sizeof(*out));
    memmove(b->del, b->del + n, (size_t)(b->ndel - n) * sizeof(b->del[0]));
    b->ndel -= n;
    pthread_mutex_unlock(&b->mu);
    return n;
}

int web_baseline_load(web_baseline_t *b, int metric, const char *key,
                      long long db_id, long long last_active,
                      long long last_fed) {
    if (!valid_pair(metric, key)) return -1;
    pthread_mutex_lock(&b->mu);
    int rc = -1;
    if (find_locked(b, metric, key) < 0 &&
        (b->free_head >= 0 || b->alloc < b->cap)) {
        int idx = create_locked(b, metric, key);
        if (idx >= 0) {
            web_bl_entry_t *e = E(b, idx);
            e->db_id = db_id;
            e->last_active = last_active;
            e->last_fed = last_fed;
            lru_place(b, idx);
            rc = 0;
        }
    }
    pthread_mutex_unlock(&b->mu);
    return rc;
}

int web_baseline_load_cell(web_baseline_t *b, int metric, const char *key,
                           int cell, double mean, double var, long n) {
    if (!valid_pair(metric, key) || cell < 0 || cell >= WEB_BL_CELLS ||
        !isfinite(mean) || !isfinite(var) || var < 0 || n < 1)
        return -1;
    pthread_mutex_lock(&b->mu);
    int idx = find_locked(b, metric, key);
    if (idx >= 0) {
        web_bl_cell_t *c = &E(b, idx)->cell[cell];
        c->mean = (float)mean;
        c->var = (float)var;
        c->n = (uint16_t)(n > WEB_BL_N_MAX ? WEB_BL_N_MAX : n);
    }
    pthread_mutex_unlock(&b->mu);
    return idx >= 0 ? 0 : -1;
}

void web_baseline_stats(web_baseline_t *b, web_bl_stats_t *out) {
    pthread_mutex_lock(&b->mu);
    out->entries = b->n;
    out->cap = b->cap;
    out->chunks = (b->alloc + WEB_BL_CHUNK - 1) / WEB_BL_CHUNK;
    out->evictions = b->evictions;
    out->aged_out = b->aged_out;
    out->zero_fed = b->zero_fed;
    out->fed = b->fed;
    out->skipped_dup = b->skipped_dup;
    out->del_lost = b->del_lost;
    pthread_mutex_unlock(&b->mu);
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
