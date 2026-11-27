#include <pthread.h>
#include <string.h>

#include "probe_hist.h"
#include "sensor_health.h"

/* Open addressing over an index table twice the key capacity, so a
 * lookup stays short at full load. Keys are only ever removed by
 * compact(), which rebuilds the index, so there are no tombstones. */
#define PH_INDEX   (2 * PROBE_HIST_SLOTS)
#define PH_EMPTY   (-1)
/* Buckets held at once: the closing and the opening one, and room for
 * a wall clock that steps while keys are held. */
#define PH_BUCKETS 4

typedef char ph_index_is_pow2[((PH_INDEX & (PH_INDEX - 1)) == 0) ? 1 : -1];

static probe_hist_row_t g_row[PROBE_HIST_SLOTS];
static int16_t          g_idx[PH_INDEX];
static int              g_n;
static struct { time_t bucket; int n; } g_bk[PH_BUCKETS];
static time_t           g_newest;
static uint64_t         g_dropped;
static int              g_sink;
static int              g_ready;   /* the index has been emptied once */
static pthread_mutex_t  g_mu = PTHREAD_MUTEX_INITIALIZER;

typedef char ph_slots_fit_index[(PROBE_HIST_SLOTS <= 32767) ? 1 : -1];

static uint32_t key_hash(const uint8_t mac[6], const char *ssid, time_t bucket) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    for (const char *p = ssid; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
    uint64_t b = (uint64_t)bucket;
    for (int i = 0; i < 8; i++) { h ^= (uint8_t)(b >> (8 * i)); h *= 16777619u; }
    return h;
}

static int key_eq(const probe_hist_row_t *r, const uint8_t mac[6],
                  const char *ssid, time_t bucket) {
    return r->bucket == bucket && memcmp(r->mac, mac, 6) == 0 &&
           strcmp(r->ssid, ssid) == 0;
}

static void index_put(int i) {
    uint32_t h = key_hash(g_row[i].mac, g_row[i].ssid, g_row[i].bucket);
    uint32_t k = h & (PH_INDEX - 1);
    while (g_idx[k] != PH_EMPTY) k = (k + 1) & (PH_INDEX - 1);
    g_idx[k] = (int16_t)i;
}

static void reindex(void) {
    for (int k = 0; k < PH_INDEX; k++) g_idx[k] = PH_EMPTY;
    memset(g_bk, 0, sizeof(g_bk));
    for (int i = 0; i < g_n; i++) {
        index_put(i);
        for (int b = 0; b < PH_BUCKETS; b++) {
            if (g_bk[b].n && g_bk[b].bucket != g_row[i].bucket) continue;
            g_bk[b].bucket = g_row[i].bucket;
            g_bk[b].n++;
            break;
        }
    }
}

/* The key's bucket count slot, taking a free one for a new bucket; -1
 * when PH_BUCKETS buckets are already held. */
static int bucket_slot(time_t bucket) {
    int free_slot = -1;
    for (int b = 0; b < PH_BUCKETS; b++) {
        if (g_bk[b].n && g_bk[b].bucket == bucket) return b;
        if (!g_bk[b].n && free_slot < 0) free_slot = b;
    }
    if (free_slot >= 0) { g_bk[free_slot].bucket = bucket; g_bk[free_slot].n = 0; }
    return free_slot;
}

static void drop(void) {
    g_dropped++;
    sh_evict_note(SH_EVICT_PROBE_HIST);
}

void probe_hist_set_sink(int on) {
    pthread_mutex_lock(&g_mu);
    g_sink = on ? 1 : 0;
    pthread_mutex_unlock(&g_mu);
}

void probe_hist_note(const uint8_t mac[6], const char *ssid, time_t now) {
    if (!mac || !ssid || !ssid[0] || now < 0) return;
    char key[33];
    /* The PNL's SSIDs are 32 octets at most; one longer is cut there,
     * as the PNL compares it. */
    size_t len = 0;
    while (len < 32 && ssid[len]) len++;
    memcpy(key, ssid, len);
    key[len] = '\0';
    time_t bucket = now - now % PROBE_HIST_BUCKET_S;

    pthread_mutex_lock(&g_mu);
    if (!g_sink) { pthread_mutex_unlock(&g_mu); return; }
    if (!g_ready) { reindex(); g_ready = 1; }
    uint32_t k = key_hash(mac, key, bucket) & (PH_INDEX - 1);
    while (g_idx[k] != PH_EMPTY && !key_eq(&g_row[g_idx[k]], mac, key, bucket))
        k = (k + 1) & (PH_INDEX - 1);
    probe_hist_row_t *r;
    if (g_idx[k] != PH_EMPTY) {
        r = &g_row[g_idx[k]];
    } else {
        int b = bucket_slot(bucket);
        if (g_n >= PROBE_HIST_SLOTS || b < 0 ||
            g_bk[b].n >= PROBE_HIST_BUCKET_KEYS) {
            drop();
            pthread_mutex_unlock(&g_mu);
            return;
        }
        g_bk[b].n++;
        r = &g_row[g_n];
        memset(r, 0, sizeof(*r));
        memcpy(r->mac, mac, 6);
        memcpy(r->ssid, key, len + 1);
        r->bucket = bucket;
        g_idx[k] = (int16_t)g_n++;
    }
    if (r->count == 0 || now < r->first_seen) r->first_seen = now;
    if (r->count == 0 || now > r->last_seen)  r->last_seen  = now;
    r->count++;
    if (bucket > g_newest) g_newest = bucket;
    pthread_mutex_unlock(&g_mu);
}

/* Free the keys whose bucket has ended and whose counts are written. */
static void compact(void) {
    int w = 0;
    for (int i = 0; i < g_n; i++) {
        if (g_row[i].count == 0 && g_row[i].bucket < g_newest) continue;
        if (w != i) g_row[w] = g_row[i];
        w++;
    }
    if (w == g_n) return;
    g_n = w;
    reindex();
}

int probe_hist_drain(probe_hist_row_t *out, int max) {
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n && n < max; i++) {
        if (g_row[i].count == 0) continue;
        out[n++] = g_row[i];
        g_row[i].count = 0;
    }
    if (n == 0) compact();
    pthread_mutex_unlock(&g_mu);
    return n;
}

int probe_hist_keys(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

uint64_t probe_hist_dropped(void) {
    pthread_mutex_lock(&g_mu);
    uint64_t n = g_dropped;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void probe_hist_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    g_newest = 0;
    g_dropped = 0;
    g_sink = 0;
    reindex();
    g_ready = 1;
    pthread_mutex_unlock(&g_mu);
}
