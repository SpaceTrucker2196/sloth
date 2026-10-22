#include "web_rollup.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* §5.1 as sloth's stream allows it today. Every source named here is a
 * record src/jsonl.c writes; web_metrics.c is where each is derived. */
const web_metric_t web_metric_defs[WM_COUNT] = {
    [WM_IFACE_RX]   = { "iface.rx_rate", WEB_MK_GAUGE, WEB_KC_IFACE, "iface",
                        "iface rx_rate", "B/s" },
    [WM_IFACE_TX]   = { "iface.tx_rate", WEB_MK_GAUGE, WEB_KC_IFACE, "iface",
                        "iface tx_rate", "B/s" },
    [WM_HOST_RX]    = { "host.rx_rate", WEB_MK_GAUGE, WEB_KC_HOST, "ip",
                        "top_host rx_rate", "B/s" },
    [WM_HOST_TX]    = { "host.tx_rate", WEB_MK_GAUGE, WEB_KC_HOST, "ip",
                        "top_host tx_rate", "B/s" },
    [WM_HOST_CONNS] = { "host.conns", WEB_MK_GAUGE, WEB_KC_HOST, "ip",
                        "top_host conn_count", "conns" },
    [WM_DEV_FRAMES] = { "dev.frames", WEB_MK_COUNTER, WEB_KC_DEV, "mac",
                        "probe_client, assoc frame_count delta",
                        "frames" },
    [WM_DEV_PRESENT] = { "dev.present", WEB_MK_PRESENCE, WEB_KC_DEV, "mac",
                         "any record with mac or sta_mac, last_seen within 10 s",
                         "0/1" },
    [WM_DNS_QUERIES] = { "dns.queries", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                         "dns, is_resp 0, by src", "queries" },
    [WM_DNS_NXDOMAIN] = { "dns.nxdomain", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                          "dns, answer NXDOMAIN, by src (the responder)",
                          "answers" },
    [WM_TLS_HANDSHAKES] = { "tls.handshakes", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                            "tls, by src", "handshakes" },
    [WM_HTTP_REQUESTS] = { "http.requests", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                           "http without status, by src", "requests" },
    [WM_ALERTS_FIRED] = { "alerts.fired", WEB_MK_COUNTER, WEB_KC_ALERT,
                          "alert_type", "alert, by ty", "alerts" },
    [WM_WIFI_AP_COUNT] = { "wifi.ap_count", WEB_MK_GAUGE, WEB_KC_CHANNEL,
                           "channel", "channel_summary ap_count", "APs" },
    [WM_WIFI_CTRL_TOTAL] = { "wifi.ctrl_total", WEB_MK_COUNTER, WEB_KC_CHANNEL,
                             "channel", "channel_summary ctrl_total delta",
                             "frames" },
    [WM_WIFI_DEAUTH] = { "wifi.deauth", WEB_MK_COUNTER, WEB_KC_DEV, "mac",
                         "deauth count delta, by bssid", "frames" },
    [WM_WIFI_PROBE_CLIENTS] = { "wifi.probe_clients", WEB_MK_GAUGE,
                                WEB_KC_GLOBAL, "",
                                "probe_client rows per snapshot pass",
                                "clients" },
    [WM_CONNS_TOTAL] = { "conns.total", WEB_MK_GAUGE, WEB_KC_GLOBAL, "",
                         "connections rows per snapshot pass", "conns" },
    [WM_FLOW_SSH]  = { "flow.ssh", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                       "ssh_flow banner_count delta, by src_ip", "banners" },
    [WM_FLOW_RDP]  = { "flow.rdp", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                       "rdp_flow connect_req_count delta, by src_ip",
                       "requests" },
    [WM_FLOW_SMB]  = { "flow.smb", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                       "smb_session count delta, by client_ip", "messages" },
    [WM_FLOW_SNMP] = { "flow.snmp", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                       "snmp_flow PDU counts delta, by src_ip", "PDUs" },
    [WM_FLOW_MQTT] = { "flow.mqtt", WEB_MK_COUNTER, WEB_KC_HOST, "ip",
                       "mqtt_flow connect+subscribe+publish delta, by src_ip",
                       "packets" },
};

static const int TIER_STEP[WEB_TIER_COUNT] = { WEB_FINE_S, WEB_MINUTE_S, WEB_HOUR_S };
static const char *const TIER_NAME[WEB_TIER_COUNT] = { "fine", "minute", "hour" };
static const char *const KC_NAME[WEB_KC_COUNT] = {
    "global", "device", "host", "iface", "channel", "alert"
};

int web_metric_find(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < WM_COUNT; i++)
        if (!strcmp(web_metric_defs[i].name, name)) return i;
    return -1;
}

int web_tier_find(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < WEB_TIER_COUNT; i++)
        if (!strcmp(TIER_NAME[i], name)) return i;
    return -1;
}

const char *web_tier_name(int tier) {
    return tier >= 0 && tier < WEB_TIER_COUNT ? TIER_NAME[tier] : "?";
}

int web_tier_step(int tier) {
    return tier >= 0 && tier < WEB_TIER_COUNT ? TIER_STEP[tier] : 0;
}

const char *web_kclass_name(int kc) {
    return kc >= 0 && kc < WEB_KC_COUNT ? KC_NAME[kc] : "?";
}

double web_point_value(int metric, const web_point_t *p) {
    if (metric < 0 || metric >= WM_COUNT || !p->n) return 0;
    switch (web_metric_defs[metric].kind) {
    case WEB_MK_COUNTER:  return p->sum;
    case WEB_MK_PRESENCE: return p->max;
    default:              return p->sum / (double)p->n;
    }
}

/* ── keys ────────────────────────────────────────────────────────────── */

static unsigned hash_key(const char *k) {
    unsigned h = 5381;
    for (const unsigned char *p = (const unsigned char *)k; *p; p++)
        h = h * 33u + *p;
    return h;
}

static int class_init(web_kclass_t *c, int cap, int churnable) {
    c->cap = cap;
    c->n = 0;
    c->evictions = 0;
    c->churnable = churnable;
    c->nhead = 1;
    while (c->nhead < cap * 2) c->nhead <<= 1;
    c->k = calloc((size_t)cap, sizeof(*c->k));
    c->head = malloc((size_t)c->nhead * sizeof(*c->head));
    if (!c->k || !c->head) return -1;
    for (int i = 0; i < c->nhead; i++) c->head[i] = -1;
    /* nhead / 2 sets of four: two ghosts per hash head, at least four
     * per key slot. */
    c->nghost = churnable ? c->nhead / 2 : 0;
    if (c->nghost) {
        c->ghost = calloc((size_t)c->nghost * WEB_GHOST_WAYS, sizeof(*c->ghost));
        if (!c->ghost) return -1;
    }
    return 0;
}

/* The set an evicted key's ghost lives in. Bits of the hash the key
 * table's heads do not use, so keys that share a head spread out. */
static web_ghost_t *ghost_set(const web_kclass_t *c, const char *key) {
    unsigned h = hash_key(key);
    h ^= h >> 13;
    h *= 0x9e3779b1u;
    h ^= h >> 16;
    return &c->ghost[(size_t)(h & (unsigned)(c->nghost - 1)) * WEB_GHOST_WAYS];
}

/* Remember an evicted key's life. Its own entry is updated; otherwise a
 * free way, else the longest-gone unestablished one. An established
 * key may take the longest-gone established way when every way is
 * established; an unestablished one then is not kept. */
static void ghost_put(web_kclass_t *c, const web_rkey_t *k, long long now_s) {
    if (!c->nghost) return;
    web_ghost_t *set = ghost_set(c, k->key), *g = NULL;
    for (int w = 0; w < WEB_GHOST_WAYS && !g; w++)
        if (set[w].used && !strcmp(set[w].key, k->key)) g = &set[w];
    for (int w = 0; w < WEB_GHOST_WAYS && !g; w++)
        if (!set[w].used) g = &set[w];
    for (int pass = 0; pass < 2 && !g; pass++) {
        if (pass == 1 && !k->est) break;
        for (int w = 0; w < WEB_GHOST_WAYS; w++) {
            if (set[w].est != pass) continue;
            if (!g || set[w].gone < g->gone) g = &set[w];
        }
    }
    if (!g) return;
    g->used = 1;
    snprintf(g->key, sizeof(g->key), "%s", k->key);
    g->first_seen = k->first_seen;
    g->est = k->est;
    g->gone = now_s;
}

/* A returning key's ghost, taken out of the table: 1 with its
 * first_seen and est, 0 when it has none. */
static int ghost_take(web_kclass_t *c, const char *key, long long *first_seen,
                      int *est) {
    if (!c->nghost) return 0;
    web_ghost_t *set = ghost_set(c, key);
    for (int w = 0; w < WEB_GHOST_WAYS; w++) {
        if (!set[w].used || strcmp(set[w].key, key)) continue;
        *first_seen = set[w].first_seen;
        *est = set[w].est;
        set[w].used = 0;
        set[w].est = 0;
        c->ghost_hits++;
        return 1;
    }
    return 0;
}

static int key_find(const web_kclass_t *c, const char *key) {
    for (int i = c->head[hash_key(key) & (unsigned)(c->nhead - 1)]; i >= 0;
         i = c->k[i].next)
        if (!strcmp(c->k[i].key, key)) return i;
    return -1;
}

static void key_unlink(web_kclass_t *c, int idx) {
    int *pp = &c->head[hash_key(c->k[idx].key) & (unsigned)(c->nhead - 1)];
    while (*pp >= 0 && *pp != idx) pp = &c->k[*pp].next;
    if (*pp == idx) *pp = c->k[idx].next;
}

static void ring_push(web_rollup_t *ru, uint32_t sid, const web_agg_t *a) {
    web_ring_row_t *r = &ru->ring[ru->ring_head];
    r->sid = sid;
    r->t = a->t;
    r->sum = a->sum;
    r->min = a->min;
    r->max = a->max;
    r->n = a->n > 0xffffffffUL ? 0xffffffffU : (uint32_t)a->n;
    ru->ring_head = (ru->ring_head + 1) % ru->ring_cap;
    if (ru->ring_n < ru->ring_cap) ru->ring_n++;
}

/* The queue is a ring: logical row i (0 the oldest) is at
 * queue[(q_head + i) % q_cap], so a take moves only the rows taken and
 * never shifts the rest under the mutex. */
static web_qrow_t *q_at(web_rollup_t *ru, size_t i) {
    size_t p = ru->q_head + i;
    if (p >= ru->q_cap) p -= ru->q_cap;
    return &ru->queue[p];
}

/* Where a closed bucket of tier goes in the store queue, or NULL when
 * it is dropped. A full queue drops a fine row first: a minute or hour
 * row takes the place of the newest queued fine row, which is counted
 * as dropped; a fine row arriving at a full queue is dropped itself.
 * q_scan, a logical index, walks down from the newest row once the
 * queue is full and only moves down, since every row above it is a
 * minute or an hour row, so a run of these costs one pass over the
 * queue between two takes. */
static web_qrow_t *q_slot(web_rollup_t *ru, int tier) {
    if (ru->q_n < ru->q_cap) {
        web_qrow_t *q = q_at(ru, ru->q_n++);
        if (ru->q_n == ru->q_cap) ru->q_scan = ru->q_cap;
        return q;
    }
    ru->q_dropped++;
    if (tier == WEB_TIER_FINE) return NULL;
    while (ru->q_scan > 0) {
        web_qrow_t *q = q_at(ru, --ru->q_scan);
        if (q->tier == WEB_TIER_FINE) return q;
    }
    return NULL;
}

/* One closed bucket a of key k: to the ring (fine) and the store queue. */
static void emit_agg(web_rollup_t *ru, web_rkey_t *k, int m, int tier,
                     web_agg_t *a) {
    if (a->t < 0) return;
    if (tier == WEB_TIER_FINE) ring_push(ru, k->sid[m], a);
    if (ru->store_on) {
        web_qrow_t *q = q_slot(ru, tier);
        if (q) {
            q->tier = tier;
            q->metric = m;
            memcpy(q->key, k->key, sizeof(q->key));
            q->t = a->t;
            q->sum = a->sum;
            q->min = a->min;
            q->max = a->max;
            q->n = a->n;
        }
    }
    ru->rows_closed[tier]++;
    a->t = -1;
}

/* Close one open bucket. An unestablished key's minute or hour bucket
 * is held instead (see web_rollup.h). The held slot is free whenever
 * this runs on the clock as it should go: samples within one minute
 * cross at most one boundary per tier. Only a clock stepped back can
 * find it taken, and then the older row goes out rather than being
 * lost. */
static void emit(web_rollup_t *ru, web_rkey_t *k, int m, int tier) {
    web_agg_t *a = &k->open[m][tier];
    if (a->t < 0) return;
    if (tier == WEB_TIER_FINE || k->est) {
        emit_agg(ru, k, m, tier, a);
        return;
    }
    web_agg_t *h = &k->held[m][tier - 1];
    if (h->t >= 0) emit_agg(ru, k, m, tier, h);
    *h = *a;
    a->t = -1;
}

/* Every held bucket of k to the queue. */
static void release_held(web_rollup_t *ru, web_rkey_t *k) {
    for (int m = 0; m < WM_COUNT; m++) {
        if (!k->sid[m]) continue;
        for (int t = WEB_TIER_MINUTE; t < WEB_TIER_COUNT; t++)
            emit_agg(ru, k, m, t, &k->held[m][t - 1]);
    }
}

/* Flush an evicted key's buckets. An established key's go out as they
 * are. An unestablished one is what churn looks like, however many
 * samples it took: its fine rows go out (24 h, and the first the
 * --web-max-mb ceiling drops) but its held and open minute and hour
 * rows are dropped and counted (churn_dropped on /api/health). Kept,
 * they would be one row per key per metric per tier for 30 and 400
 * days, and would push real history out of the store. A real host
 * evicted in its first minute (LRU pressure) loses that minute's long
 * rows the same way, and only that minute's: its ghost keeps its
 * first_seen, so it is established once it has been seen a minute. */
static void key_flush(web_rollup_t *ru, web_rkey_t *k) {
    for (int m = 0; m < WM_COUNT; m++) {
        if (!k->sid[m]) continue;
        emit(ru, k, m, WEB_TIER_FINE);
        for (int t = WEB_TIER_MINUTE; t < WEB_TIER_COUNT; t++) {
            if (k->est) {
                emit(ru, k, m, t);
                continue;
            }
            web_agg_t *h = &k->held[m][t - 1], *a = &k->open[m][t];
            if (h->t >= 0) ru->churn_dropped++;
            if (a->t >= 0) ru->churn_dropped++;
            h->t = a->t = -1;
        }
    }
}

static void key_reset(web_rkey_t *k) {
    memset(k->sid, 0, sizeof(k->sid));
    k->est = 0;
    for (int m = 0; m < WM_COUNT; m++) {
        for (int t = 0; t < WEB_TIER_COUNT; t++) k->open[m][t].t = -1;
        for (int t = 0; t < WEB_TIER_COUNT - 1; t++) k->held[m][t].t = -1;
    }
}

/* The slot for key in class c, made (evicting the least recently seen
 * key when the class is full) if it is not there. A key of a class
 * no peer can churn is established from the start; one that comes
 * back to a churnable class gets its earlier life from its ghost. */
static web_rkey_t *key_get(web_rollup_t *ru, web_kclass_t *c, const char *key,
                           long long now_s) {
    int i = key_find(c, key);
    if (i >= 0) return &c->k[i];
    if (c->n < c->cap) {
        for (i = 0; i < c->cap; i++) if (!c->k[i].used) break;
        c->n++;
    } else {
        int lru = 0;
        for (int j = 1; j < c->cap; j++)
            if (c->k[j].last_seen < c->k[lru].last_seen) lru = j;
        i = lru;
        key_flush(ru, &c->k[i]);
        ghost_put(c, &c->k[i], now_s);
        key_unlink(c, i);
        c->evictions++;
    }
    web_rkey_t *k = &c->k[i];
    k->used = 1;
    snprintf(k->key, sizeof(k->key), "%s", key);
    key_reset(k);
    k->first_seen = k->last_seen = now_s;
    k->est = !c->churnable;
    long long fs;
    int est;
    if (ghost_take(c, k->key, &fs, &est)) {
        if (fs < k->first_seen) k->first_seen = fs;
        k->est = est;
    }
    unsigned h = hash_key(k->key) & (unsigned)(c->nhead - 1);
    k->next = c->head[h];
    c->head[h] = i;
    return k;
}

/* ── the rollup ──────────────────────────────────────────────────────── */

int web_rollup_init(web_rollup_t *ru, int max_keys, int store_on,
                    char *err, size_t errsz) {
    memset(ru, 0, sizeof(*ru));
    if (max_keys < WEB_MAX_KEYS_MIN) max_keys = WEB_MAX_KEYS_MIN;
    if (max_keys > WEB_MAX_KEYS_MAX) max_keys = WEB_MAX_KEYS_MAX;
    pthread_mutex_init(&ru->mu, NULL);
    const int caps[WEB_KC_COUNT] = {
        1, max_keys, max_keys / 2, WEB_IFACE_KEYS, WEB_CHANNEL_KEYS,
        WEB_ALERT_KEYS
    };
    int bad = 0;
    size_t series_max = 0;
    for (int c = 0; c < WEB_KC_COUNT; c++) {
        int churnable = c == WEB_KC_DEV || c == WEB_KC_HOST;
        if (class_init(&ru->cls[c], caps[c], churnable) != 0) bad = 1;
        for (int m = 0; m < WM_COUNT; m++)
            if (web_metric_defs[m].kclass == c) series_max += (size_t)caps[c];
    }
    ru->ring_cap = WEB_RING_ROWS;
    ru->ring = calloc(ru->ring_cap, sizeof(*ru->ring));
    ru->store_on = store_on;
    size_t qc = series_max * WEB_QROWS_PER_SERIES;
    if (qc < WEB_QUEUE_ROWS) qc = WEB_QUEUE_ROWS;
    ru->q_cap = store_on ? qc : 0;
    if (store_on) ru->queue = calloc(ru->q_cap, sizeof(*ru->queue));
    if (bad || !ru->ring || (store_on && !ru->queue)) {
        snprintf(err, errsz, "rollup: out of memory");
        web_rollup_destroy(ru);
        return -1;
    }
    ru->next_sid = 1;
    return 0;
}

void web_rollup_destroy(web_rollup_t *ru) {
    for (int c = 0; c < WEB_KC_COUNT; c++) {
        free(ru->cls[c].k);
        free(ru->cls[c].head);
        free(ru->cls[c].ghost);
        ru->cls[c].k = NULL;
        ru->cls[c].head = NULL;
        ru->cls[c].ghost = NULL;
    }
    free(ru->ring);
    free(ru->queue);
    ru->ring = NULL;
    ru->queue = NULL;
    pthread_mutex_destroy(&ru->mu);
}

static long long bucket_of(long long now, int step) {
    long long b = now - now % step;
    if (now < 0 && now % step) b -= step;
    return b;
}

void web_rollup_add(web_rollup_t *ru, int metric, const char *key, double v,
                    long long now_s) {
    if (metric < 0 || metric >= WM_COUNT || !key) return;
    if (!isfinite(v)) return;
    int clamped = 0;
    if (v >  WEB_VALUE_MAX) { v =  WEB_VALUE_MAX; clamped = 1; }
    if (v < -WEB_VALUE_MAX) { v = -WEB_VALUE_MAX; clamped = 1; }
    const web_metric_t *md = &web_metric_defs[metric];
    if (md->kclass == WEB_KC_GLOBAL) key = "";
    else if (!key[0] || strlen(key) > WEB_KEY_MAX) return;

    pthread_mutex_lock(&ru->mu);
    ru->samples++;
    if (clamped) ru->clamped++;
    web_kclass_t *c = &ru->cls[md->kclass];
    web_rkey_t *k = key_get(ru, c, key, now_s);
    k->last_seen = now_s;
    if (!k->sid[metric]) {
        k->sid[metric] = ru->next_sid++;
        if (!ru->next_sid) ru->next_sid = 1;
    }
    if (!k->est && now_s - k->first_seen >= WEB_MINUTE_S) {
        k->est = 1;
        release_held(ru, k);
    }
    for (int t = 0; t < WEB_TIER_COUNT; t++) {
        web_agg_t *a = &k->open[metric][t];
        long long b = bucket_of(now_s, TIER_STEP[t]);
        if (a->t != b) {
            emit(ru, k, metric, t);
            a->t = b;
            a->sum = v;
            a->min = v;
            a->max = v;
            a->n = 1;
            continue;
        }
        a->sum += v;
        if (v < a->min) a->min = v;
        if (v > a->max) a->max = v;
        a->n++;
    }
    pthread_mutex_unlock(&ru->mu);
}

static void close_where(web_rollup_t *ru, long long now_s, int all) {
    for (int c = 0; c < WEB_KC_COUNT; c++) {
        web_kclass_t *cl = &ru->cls[c];
        for (int i = 0; i < cl->cap; i++) {
            web_rkey_t *k = &cl->k[i];
            if (!k->used) continue;
            for (int m = 0; m < WM_COUNT; m++) {
                if (!k->sid[m]) continue;
                for (int t = 0; t < WEB_TIER_COUNT; t++) {
                    const web_agg_t *a = &k->open[m][t];
                    if (a->t < 0) continue;
                    if (all) {
                        emit_agg(ru, k, m, t, &k->open[m][t]);
                        continue;
                    }
                    /* Left open until the key is established or
                     * evicted. Closed here it would take the held slot,
                     * which the key's next boundary needs: two closed
                     * minutes would push the older one out. */
                    if (t != WEB_TIER_FINE && !k->est) continue;
                    if (a->t + TIER_STEP[t] <= now_s) emit(ru, k, m, t);
                }
            }
            if (all) release_held(ru, k);
        }
    }
}

void web_rollup_close_due(web_rollup_t *ru, long long now_s) {
    pthread_mutex_lock(&ru->mu);
    close_where(ru, now_s, 0);
    pthread_mutex_unlock(&ru->mu);
}

void web_rollup_close_all(web_rollup_t *ru) {
    pthread_mutex_lock(&ru->mu);
    close_where(ru, 0, 1);
    pthread_mutex_unlock(&ru->mu);
}

size_t web_rollup_take(web_rollup_t *ru, web_qrow_t *out, size_t max) {
    pthread_mutex_lock(&ru->mu);
    size_t n = ru->q_n < max ? ru->q_n : max;
    if (n) {
        /* At most two runs: up to the end of the array, then from 0. */
        size_t first = ru->q_cap - ru->q_head;
        if (first > n) first = n;
        memcpy(out, &ru->queue[ru->q_head], first * sizeof(*out));
        if (n > first) memcpy(out + first, ru->queue, (n - first) * sizeof(*out));
        ru->q_head = (ru->q_head + n) % ru->q_cap;
        ru->q_n -= n;
        /* Logical indexes shift down by n; q_scan is only read while the
         * queue is full and is reset when it fills again, but keep it
         * pointing at the same row meanwhile. */
        ru->q_scan = ru->q_scan > n ? ru->q_scan - n : 0;
    }
    pthread_mutex_unlock(&ru->mu);
    return n;
}

static int cmp_point_desc(const void *a, const void *b) {
    const web_point_t *x = a, *y = b;
    return x->t < y->t ? 1 : x->t > y->t ? -1 : 0;
}

static void merge_into(web_point_t *d, const web_point_t *s) {
    d->sum += s->sum;
    if (s->min < d->min) d->min = s->min;
    if (s->max > d->max) d->max = s->max;
    d->n += s->n;
}

int web_rollup_fine(web_rollup_t *ru, int metric, const char *key,
                    long long from, long long to, int with_open,
                    web_point_t *out, int max, int *more) {
    *more = 0;
    if (metric < 0 || metric >= WM_COUNT || max <= 0) return 0;
    const web_metric_t *md = &web_metric_defs[metric];
    if (md->kclass == WEB_KC_GLOBAL) key = "";
    pthread_mutex_lock(&ru->mu);
    web_kclass_t *c = &ru->cls[md->kclass];
    int i = key_find(c, key);
    uint32_t sid = i >= 0 ? c->k[i].sid[metric] : 0;
    if (!sid) { pthread_mutex_unlock(&ru->mu); return 0; }

    /* Two passes over the ring: count, then copy, so the buffer is
     * exactly as large as the matches. Duplicates are merged after the
     * sort, outside the lock. */
    size_t cnt = 0;
    for (size_t j = 0; j < ru->ring_n; j++) {
        const web_ring_row_t *r = &ru->ring[j];
        if (r->sid == sid && r->t >= from && r->t < to) cnt++;
    }
    web_point_t *tmp = malloc((cnt + 1) * sizeof(*tmp));
    if (!tmp) { pthread_mutex_unlock(&ru->mu); return 0; }
    size_t n = 0;
    for (size_t j = 0; j < ru->ring_n && n < cnt; j++) {
        const web_ring_row_t *r = &ru->ring[j];
        if (r->sid != sid || r->t < from || r->t >= to) continue;
        web_point_t p = { r->t, r->sum, r->min, r->max, r->n };
        tmp[n++] = p;
    }
    if (with_open) {
        const web_agg_t *a = &c->k[i].open[metric][WEB_TIER_FINE];
        if (a->t >= from && a->t < to) tmp[n++] = *a;
    }
    pthread_mutex_unlock(&ru->mu);

    qsort(tmp, n, sizeof(*tmp), cmp_point_desc);
    size_t u = 0;
    for (size_t j = 0; j < n; j++) {
        if (u && tmp[u - 1].t == tmp[j].t) merge_into(&tmp[u - 1], &tmp[j]);
        else tmp[u++] = tmp[j];
    }
    int k = (int)(u < (size_t)max ? u : (size_t)max);
    if (u > (size_t)max) *more = 1;
    memcpy(out, tmp, (size_t)k * sizeof(*out));
    free(tmp);
    return k;
}

static int cmp_key_desc(const void *a, const void *b) {
    const web_keyinfo_t *x = a, *y = b;
    if (x->last_seen != y->last_seen) return x->last_seen < y->last_seen ? 1 : -1;
    return strcmp(x->key, y->key);
}

int web_rollup_keys(web_rollup_t *ru, int metric, web_keyinfo_t *out,
                    int max, int *total) {
    *total = 0;
    if (metric < 0 || metric >= WM_COUNT) return 0;
    const web_metric_t *md = &web_metric_defs[metric];
    pthread_mutex_lock(&ru->mu);
    web_kclass_t *c = &ru->cls[md->kclass];
    web_keyinfo_t *all = malloc((size_t)c->cap * sizeof(*all));
    int n = 0;
    if (all) {
        for (int i = 0; i < c->cap; i++) {
            if (!c->k[i].used || !c->k[i].sid[metric]) continue;
            memcpy(all[n].key, c->k[i].key, sizeof(all[n].key));
            all[n].last_seen = c->k[i].last_seen;
            n++;
        }
    }
    pthread_mutex_unlock(&ru->mu);
    if (!all) return 0;
    qsort(all, (size_t)n, sizeof(*all), cmp_key_desc);
    *total = n;
    int k = n < max ? n : max;
    if (k > 0) memcpy(out, all, (size_t)k * sizeof(*out));
    free(all);
    return k;
}

void web_rollup_stats(web_rollup_t *ru, web_rollup_stats_t *st) {
    memset(st, 0, sizeof(*st));
    pthread_mutex_lock(&ru->mu);
    for (int c = 0; c < WEB_KC_COUNT; c++) {
        const web_kclass_t *cl = &ru->cls[c];
        st->keys[c] = cl->n;
        st->caps[c] = cl->cap;
        st->evictions[c] = cl->evictions;
        st->ghost_hits[c] = cl->ghost_hits;
        for (int i = 0; i < cl->cap; i++) {
            if (!cl->k[i].used) continue;
            for (int m = 0; m < WM_COUNT; m++) if (cl->k[i].sid[m]) st->series++;
        }
    }
    st->ring_rows = ru->ring_n;
    st->queue_rows = ru->q_n;
    st->queue_cap = ru->q_cap;
    st->q_dropped = ru->q_dropped;
    st->churn_dropped = ru->churn_dropped;
    st->clamped = ru->clamped;
    st->hw_evictions = ru->hw_evictions;
    st->samples = ru->samples;
    memcpy(st->rows_closed, ru->rows_closed, sizeof(st->rows_closed));
    pthread_mutex_unlock(&ru->mu);
}

size_t web_rollup_queued(web_rollup_t *ru) {
    pthread_mutex_lock(&ru->mu);
    size_t n = ru->q_n;
    pthread_mutex_unlock(&ru->mu);
    return n;
}

void web_rollup_note_hw_eviction(web_rollup_t *ru) {
    pthread_mutex_lock(&ru->mu);
    ru->hw_evictions++;
    pthread_mutex_unlock(&ru->mu);
}
