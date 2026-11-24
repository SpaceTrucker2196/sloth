/* Several sensor radios: registry, de-duplication, hop split, CLI rules.
 * See mon_radios.h. */
#include "mon_radios.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "sloth.h"
#include "ble_hci.h"
#include "cov_timeline.h"
#include "sloth_clock.h"

/* ── Registry ─────────────────────────────────────────────── */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static mon_radio_t     g_r[MON_RADIO_MAX];
static int             g_n;
/* Written by mon_radios_add() before any reader thread exists, as
 * df.c's g_active is; read by every frame without the lock. */
static int             g_active;

/* ── De-duplication table ─────────────────────────────────── */

typedef struct {
    uint64_t hash;
    int64_t  ts_us;
    uint16_t len, fc, seq;
    uint8_t  addr[6];
    uint8_t  radio;
    uint8_t  used;
} dd_ent_t;

static dd_ent_t g_dd[MON_DEDUP_BUCKETS][MON_DEDUP_WAYS];
static uint64_t g_dd_evicted;

/* An eviction is counted when the entry it removes is this recent
 * beside the frame that needed the room: a reader up to a buffer
 * timeout behind could still have brought its copy. */
#define DD_LIVE_US 1000000

/* ── Hop state (main thread) ──────────────────────────────── */

static chanhop_t g_full;                 /* the whole list, as --hop gave it */
static chanhop_t g_hop[MON_RADIO_MAX];   /* radios 1.. ; [0] unused */
static unsigned  g_dealt;                /* bit k: radio k is in the deal */
static uint64_t  g_fed[MON_RADIO_MAX];   /* frames already fed to its scheduler */

void mon_radios_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_r, 0, sizeof(g_r));
    g_n = 0;
    g_active = 0;
    memset(g_dd, 0, sizeof(g_dd));
    g_dd_evicted = 0;
    memset(&g_full, 0, sizeof(g_full));
    memset(g_hop, 0, sizeof(g_hop));
    g_dealt = 0;
    memset(g_fed, 0, sizeof(g_fed));
    pthread_mutex_unlock(&g_mu);
}

int mon_radios_add(const char *iface) {
    if (!iface || !iface[0] || strlen(iface) >= sizeof(g_r[0].iface)) return -1;
    int idx = -1;
    pthread_mutex_lock(&g_mu);
    int dup = 0;
    for (int i = 0; i < g_n; i++) dup |= !strcmp(g_r[i].iface, iface);
    if (!dup && g_n < MON_RADIO_MAX) {
        idx = g_n++;
        memset(&g_r[idx], 0, sizeof(g_r[idx]));
        snprintf(g_r[idx].iface, sizeof(g_r[idx].iface), "%s", iface);
        g_active = g_n >= 2;
    }
    pthread_mutex_unlock(&g_mu);
    return idx;
}

int mon_radios_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int mon_radios_extra(void) {
    int n = mon_radios_count();
    return n > 1 ? n - 1 : 0;
}

int mon_radios_active(void) { return g_active; }

int mon_radios_get(int radio, mon_radio_t *out) {
    if (!out) return 0;
    int ok = 0;
    pthread_mutex_lock(&g_mu);
    if (radio >= 0 && radio < g_n) { *out = g_r[radio]; ok = 1; }
    pthread_mutex_unlock(&g_mu);
    return ok;
}

void mon_radios_set_state(int radio, mon_radio_state_t st, const char *err) {
    pthread_mutex_lock(&g_mu);
    if (radio >= 0 && radio < g_n) {
        g_r[radio].state = st;
        snprintf(g_r[radio].err, sizeof(g_r[radio].err), "%s", err ? err : "");
    }
    pthread_mutex_unlock(&g_mu);
}

const char *mon_radio_state_name(mon_radio_state_t st) {
    switch (st) {
    case MON_RADIO_NAMED:   return "not_open";
    case MON_RADIO_OPEN:    return "open";
    case MON_RADIO_RUNNING: return "running";
    case MON_RADIO_LOST:    return "lost";
    case MON_RADIO_STOPPED: return "stopped";
    }
    return "not_open";
}

int mon_radio_alive(mon_radio_state_t st) {
    return st == MON_RADIO_OPEN || st == MON_RADIO_RUNNING;
}

uint64_t mon_radios_dup_total(void) {
    uint64_t t = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n; i++) t += g_r[i].dup_dropped;
    pthread_mutex_unlock(&g_mu);
    return t;
}

uint64_t mon_dedup_evicted(void) {
    pthread_mutex_lock(&g_mu);
    uint64_t t = g_dd_evicted;
    pthread_mutex_unlock(&g_mu);
    return t;
}

/* ── De-duplication ───────────────────────────────────────── */

static uint64_t fnv64(const uint8_t *p, int n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

/* What is compared exactly beside the hash. Sequence Control is octets
 * 22..23 of a management or data frame; a control frame has none (its
 * octets there, when it is that long, are in the hash). The address is
 * Address 2 where the frame is long enough to hold one, else Address 1:
 * an ACK or CTS names only its receiver. */
static void dd_key(const uint8_t *f, int len, dd_ent_t *k) {
    memset(k, 0, sizeof(*k));
    k->hash = fnv64(f, len);
    k->len  = (uint16_t)(len > 0xFFFF ? 0xFFFF : len);
    if (len >= 2) k->fc = (uint16_t)(f[0] | ((uint16_t)f[1] << 8));
    const int type = len >= 1 ? (f[0] >> 2) & 3 : -1;
    if (type != 1 && len >= 24)
        k->seq = (uint16_t)(f[22] | ((uint16_t)f[23] << 8));
    if (len >= 16)      memcpy(k->addr, f + 10, 6);
    else if (len >= 10) memcpy(k->addr, f + 4, 6);
}

static int dd_same(const dd_ent_t *e, const dd_ent_t *k) {
    return e->used && e->hash == k->hash && e->len == k->len &&
           e->fc == k->fc && e->seq == k->seq &&
           memcmp(e->addr, k->addr, 6) == 0;
}

static dd_ent_t *dd_bucket(uint64_t hash, int64_t slot) {
    uint64_t x = hash ^ ((uint64_t)slot * 0x9E3779B97F4A7C15ULL);
    x ^= x >> 29;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 32;
    return g_dd[x & (MON_DEDUP_BUCKETS - 1)];
}

/* Under g_mu. 1 for a duplicate; otherwise the frame is this radio's,
 * and is entered unless this radio already owns its window. */
static int dd_check(int radio, const uint8_t *f, int len, int64_t ts_us, int insert) {
    dd_ent_t k;
    dd_key(f, len, &k);
    const int64_t slot = ts_us / MON_DEDUP_WINDOW_US;
    int mine = 0, theirs = 0;
    for (int d = -1; d <= 1; d++) {
        const dd_ent_t *b = dd_bucket(k.hash, slot + d);
        for (int w = 0; w < MON_DEDUP_WAYS; w++) {
            const dd_ent_t *e = &b[w];
            if (!dd_same(e, &k)) continue;
            int64_t dt = ts_us - e->ts_us;
            if (dt < 0) dt = -dt;
            if (dt > MON_DEDUP_WINDOW_US) continue;
            if (e->radio == (uint8_t)radio) mine = 1; else theirs = 1;
        }
    }
    /* Its own radio's window first: a frame is never held against the
     * radio that brought the one before it. */
    if (mine) return 0;
    if (theirs) return 1;
    if (!insert) return 0;
    dd_ent_t *b = dd_bucket(k.hash, slot);
    dd_ent_t *v = &b[0];
    for (int w = 0; w < MON_DEDUP_WAYS; w++) {
        if (!b[w].used) { v = &b[w]; break; }
        if (b[w].ts_us < v->ts_us) v = &b[w];
    }
    if (v->used) {
        int64_t age = ts_us - v->ts_us;
        if (age < 0) age = -age;
        if (age < DD_LIVE_US && g_dd_evicted < UINT64_MAX) g_dd_evicted++;
    }
    k.ts_us = ts_us;
    k.radio = (uint8_t)radio;
    k.used  = 1;
    *v = k;
    return 0;
}

int mon_dedup_is_dup(int radio, const uint8_t *dot11, int len, int64_t ts_us) {
    if (!dot11 || len <= 0 || ts_us <= 0 || radio < 0 || radio >= MON_RADIO_MAX)
        return 0;
    pthread_mutex_lock(&g_mu);
    int dup = dd_check(radio, dot11, len, ts_us, 1);
    pthread_mutex_unlock(&g_mu);
    return dup;
}

int mon_radio_frame(int radio, const uint8_t *dot11, int len, int64_t ts_us,
                    int freq_mhz) {
    if (!g_active) return 1;
    int dup = 0;
    pthread_mutex_lock(&g_mu);
    if (radio >= 0 && radio < g_n) {
        mon_radio_t *r = &g_r[radio];
        if (freq_mhz > 0) r->freq_mhz = freq_mhz;
        if (dot11 && len > 0 && ts_us > 0)
            dup = dd_check(radio, dot11, len, ts_us, 1);
        if (dup) r->dup_dropped++; else r->frames++;
    }
    pthread_mutex_unlock(&g_mu);
    return !dup;
}

/* ── Hopping ──────────────────────────────────────────────── */

/* Under no lock: the schedulers are the main thread's. */
static unsigned live_mask(void) {
    unsigned m = 1u;                     /* radio 0 is always dealt in */
    pthread_mutex_lock(&g_mu);
    for (int k = 1; k < g_n; k++)
        if (mon_radio_alive(g_r[k].state)) m |= 1u << k;
    pthread_mutex_unlock(&g_mu);
    return m;
}

static int deal(chanhop_t *h0) {
    unsigned m = live_mask();
    int radios = 0;
    for (int k = 0; k < MON_RADIO_MAX; k++) radios += (m >> k) & 1u;
    int share = 0;
    for (int k = 0; k < MON_RADIO_MAX; k++) {
        chanhop_t *h = k == 0 ? h0 : &g_hop[k];
        int n = 0;
        if ((m >> k) & 1u) n = chanhop_split(h, &g_full, radios, share++);
        else if (k > 0)    memset(h, 0, sizeof(*h));
        /* A radio dealt out stops dwelling anywhere (#246): its last
         * dwell must not go on covering its channel. */
        if (k > 0 && ((g_dealt >> k) & 1u) && !((m >> k) & 1u))
            cov_tl_hop_note(k, 0, sloth_wall_ms());
        pthread_mutex_lock(&g_mu);
        if (k < g_n) {
            g_r[k].hop_channels = n;
            if (!n) g_r[k].chan_requested = g_r[k].chan_confirmed = 0;
        }
        pthread_mutex_unlock(&g_mu);
    }
    g_dealt = m;
    return radios;
}

int mon_hop_setup(chanhop_t *h0) {
    if (!h0 || !g_active || h0->count == 0) return 1;
    g_full = *h0;
    return deal(h0);
}

int mon_hop_plan_mhz(int *mhz, int max) {
    if (!mhz || max <= 0) return 0;
    int n = 0;
    for (int i = 0; i < g_full.count && n < max; i++)
        mhz[n++] = g_full.slots[i].freq_mhz;
    return n;
}

const chanhop_t *mon_hop_sched(int radio) {
    if (radio < 1 || radio >= MON_RADIO_MAX || !((g_dealt >> radio) & 1u))
        return NULL;
    return g_hop[radio].count ? &g_hop[radio] : NULL;
}

uint32_t mon_hop_radio0_delta(void) {
    pthread_mutex_lock(&g_mu);
    uint64_t f = g_n ? g_r[0].frames : 0;
    pthread_mutex_unlock(&g_mu);
    uint32_t d = (uint32_t)(f - g_fed[0]);
    g_fed[0] = f;
    return d;
}

int mon_hop_service(chanhop_t *h0, uint64_t now_ms) {
    if (!h0 || !g_active || g_full.count == 0) return 0;
    int redealt = 0;
    if (live_mask() != g_dealt) { deal(h0); redealt = 1; }
    for (int k = 1; k < MON_RADIO_MAX; k++) {
        if (!((g_dealt >> k) & 1u)) continue;
        char iface[16];
        pthread_mutex_lock(&g_mu);
        uint64_t f = g_r[k].frames;
        memcpy(iface, g_r[k].iface, sizeof(iface));
        pthread_mutex_unlock(&g_mu);
        uint32_t delta = (uint32_t)(f - g_fed[k]);
        g_fed[k] = f;
        int requested = 0, err = 0;
        if (!chanhop_step(&g_hop[k], iface, now_ms, delta, &requested, &err))
            continue;
        /* Radio k's dwell history (#246), as chanhop_service() keeps
         * radio 0's. */
        if (!err) cov_tl_hop_note(k, chanhop_current_freq(&g_hop[k]), sloth_wall_ms());
        pthread_mutex_lock(&g_mu);
        chanhop_record_retune_err(requested, err, &g_r[k].chan_requested,
                                  &g_r[k].chan_confirmed,
                                  &g_r[k].retune_failures,
                                  &g_r[k].retune_last_errno);
        pthread_mutex_unlock(&g_mu);
    }
    return redealt;
}

/* ── Command line ─────────────────────────────────────────── */

int mon_cli_add(mon_cli_t *c, const char *name, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!c || !name) return 0;
    if (!name[0] || strlen(name) >= 16 /* IFNAMSIZ */ || strchr(name, '/')) {
        snprintf(err, errsz, "sloth: --monitor-iface %.40s: not an interface "
                             "name (1..15 chars, no '/')", name);
        return 0;
    }
    if (bt_dev_is_raw_hci(name)) {
        snprintf(err, errsz, "sloth: --monitor-iface %s refused: a raw HCI "
                             "device accepts injected packets; use "
                             "--bt-monitor", name);
        return 0;
    }
    for (int i = 0; i < c->n; i++) {
        if (!strcmp(c->name[i], name)) {
            snprintf(err, errsz, "sloth: --monitor-iface %s given twice; a "
                                 "radio is named once", name);
            return 0;
        }
    }
    if (c->n >= MON_RADIO_MAX) {
        snprintf(err, errsz, "sloth: too many --monitor-iface radios (max %d "
                             "beside the first)", MON_RADIO_MAX - 1);
        return 0;
    }
    c->name[c->n++] = name;
    return 1;
}

int mon_cli_check(const mon_cli_t *c, const char *const *df_names, int df_n,
                  int replay, int have_pcap, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    /* One radio is the run sloth has always made; main() words those
     * refusals. */
    if (!c || c->n < 2) return 1;
    if (!have_pcap) {
        snprintf(err, errsz, "sloth: --monitor-iface needs a build with "
                             "libpcap (this one is WITH_PCAP=0)");
        return 0;
    }
    if (replay) {
        snprintf(err, errsz, "sloth: --monitor-iface names live radios; it "
                             "cannot be combined with --replay");
        return 0;
    }
    for (int k = 1; k < c->n; k++) {
        for (int j = 0; df_names && j < df_n; j++) {
            if (df_names[j] && !strcmp(c->name[k], df_names[j])) {
                snprintf(err, errsz, "sloth: %s is named by --monitor-iface "
                                     "and by --df-iface; a radio is a sensor "
                                     "radio or a direction-finding radio, "
                                     "not both", c->name[k]);
                return 0;
            }
        }
    }
    return 1;
}
