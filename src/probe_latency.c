/* Probe-response latency per BSSID (#187 S3). Contract, clock choice,
 * validity rules and the reason this is an observation and not a
 * detector: probe_latency.h. */

#include "probe_latency.h"
#include "dot11_ie.h"

#include <pthread.h>
#include <string.h>

typedef struct {
    uint8_t  sta[6];
    uint8_t  addr3[6];
    int      to_any_bss;     /* addr3 is the wildcard BSSID */
    int      wildcard;       /* zero-length SSID element */
    char     ssid[33];
    int      seq;
    uint64_t dwell;
    int      has_tsft;
    uint64_t tsft_us;
    int64_t  pcap_us;
    int      dup;            /* heard twice under one seq: unpairable */
    int      answered;       /* some BSSID's answer was paired with it */
    int      used;
} plat_req_t;

typedef struct {
    uint8_t  bssid[6];
    int      src;
    uint64_t pairs_total;
    time_t   last_seen;
    uint32_t smp[PLAT_KIND_COUNT][PLAT_SAMPLES];
    int      n[PLAT_KIND_COUNT];
    int      head[PLAT_KIND_COUNT];
    /* The request this BSSID last answered: a second response to it is
     * an extra, not a latency. */
    uint8_t  last_sta[6];
    int      last_seq;
    uint64_t last_dwell;
} plat_row_t;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static plat_req_t      g_req[PLAT_PENDING];
static int             g_req_head;
static plat_row_t      g_row[PLAT_MAX_BSS];
static int             g_row_n;
static int             g_last_freq;
static uint64_t        g_dwell;
static plat_counters_t g_ct;

static int mac_group(const uint8_t m[6]) { return (m[0] & 0x01) != 0; }
static int mac_zero(const uint8_t m[6]) {
    static const uint8_t z[6] = {0};
    return memcmp(m, z, 6) == 0;
}
static int mac_unicast(const uint8_t *m) {
    return m && !mac_group(m) && !mac_zero(m);
}
static void bump(uint64_t *c) { if (*c < UINT64_MAX) (*c)++; }

/* The first SSID element's length, or -1 when there is none or it does
 * not fit. A probe request's wildcard is a zero-length SSID (§9.4.2.2),
 * which dot11_ie_ssid() cannot tell from an absent element. */
static int ssid_elem_len(const uint8_t *ies, int len) {
    int off = 0;
    while (off + 2 <= len) {
        int id = ies[off], el = ies[off + 1];
        if (off + 2 + el > len) return -1;
        if (id == 0) return el;
        off += 2 + el;
    }
    return -1;
}

static int64_t pcap_us_of(const plat_clock_t *c) {
    return (int64_t)c->ts_sec * 1000000 + (int64_t)c->ts_usec;
}

static plat_row_t *row_find(const uint8_t bssid[6]) {
    for (int i = 0; i < g_row_n; i++)
        if (memcmp(g_row[i].bssid, bssid, 6) == 0) return &g_row[i];
    return NULL;
}

static plat_row_t *row_get(const uint8_t bssid[6]) {
    plat_row_t *r = row_find(bssid);
    if (r) return r;
    if (g_row_n < PLAT_MAX_BSS) {
        r = &g_row[g_row_n++];
    } else {
        int old = 0;
        for (int i = 1; i < g_row_n; i++)
            if (g_row[i].last_seen < g_row[old].last_seen) old = i;
        r = &g_row[old];
        bump(&g_ct.evict_bss);
    }
    memset(r, 0, sizeof(*r));
    memcpy(r->bssid, bssid, 6);
    r->last_seq = -1;
    return r;
}

static int req_live(const plat_req_t *q, int64_t now_us) {
    return q->used && q->dwell == g_dwell &&
           now_us >= q->pcap_us &&
           now_us - q->pcap_us <= (int64_t)PLAT_PAIR_MAX_US;
}

static void on_request(const dot11_frame_t *f, const plat_clock_t *clk,
                       const uint8_t *body, int blen) {
    if (!mac_unicast(f->sa) || f->seq_num < 0) return;
    int sl = ssid_elem_len(body, blen);
    if (sl < 0 || sl > 32) return;
    int64_t now = pcap_us_of(clk);

    for (int i = 0; i < PLAT_PENDING; i++) {
        plat_req_t *q = &g_req[i];
        if (req_live(q, now) && q->seq == f->seq_num &&
            memcmp(q->sta, f->sa, 6) == 0) {
            q->dup = 1;
            bump(&g_ct.req_dup);
            return;
        }
    }

    plat_req_t *q = &g_req[g_req_head];
    g_req_head = (g_req_head + 1) % PLAT_PENDING;
    if (req_live(q, now) && !q->answered && !q->dup)
        bump(&g_ct.evict_pending);
    memset(q, 0, sizeof(*q));
    memcpy(q->sta, f->sa, 6);
    if (f->bssid) memcpy(q->addr3, f->bssid, 6);
    q->to_any_bss = !f->bssid || mac_group(f->bssid);
    q->wildcard   = (sl == 0);
    if (!q->wildcard) dot11_ie_ssid(body, blen, q->ssid, NULL);
    q->seq      = f->seq_num;
    q->dwell    = g_dwell;
    q->has_tsft = clk->has_tsft;
    q->tsft_us  = clk->tsft_us;
    q->pcap_us  = now;
    q->used     = 1;
}

static void row_add(plat_row_t *r, int kind, uint32_t us, int src,
                    time_t when) {
    if (r->src == PLAT_SRC_PCAP && src == PLAT_SRC_TSFT) {
        memset(r->n, 0, sizeof(r->n));
        memset(r->head, 0, sizeof(r->head));
        bump(&g_ct.src_switch);
    }
    if (r->src == PLAT_SRC_TSFT && src == PLAT_SRC_PCAP) {
        bump(&g_ct.src_mismatch);
        return;
    }
    r->src = src;
    r->smp[kind][r->head[kind]] = us;
    r->head[kind] = (r->head[kind] + 1) % PLAT_SAMPLES;
    if (r->n[kind] < PLAT_SAMPLES) r->n[kind]++;
    bump(&r->pairs_total);
    r->last_seen = when;
    bump(&g_ct.pairs);
}

static void on_response(const dot11_frame_t *f, const plat_clock_t *clk,
                        const uint8_t *body, int blen) {
    /* Probe Response fixed fields: Timestamp(8) Beacon Interval(2)
     * Capability(2) (§9.3.3.11), then elements. */
    if (blen < 12) return;
    if (!mac_unicast(f->da) || !mac_unicast(f->bssid)) return;
    if (f->retry) { bump(&g_ct.resp_retry); return; }
    char ssid[33];
    dot11_ie_ssid(body + 12, blen - 12, ssid, NULL);

    int64_t now = pcap_us_of(clk);
    plat_row_t *existing = row_find(f->bssid);
    plat_req_t *hit = NULL;
    int cands = 0, extra = 0, backwards = 0;
    for (int i = 0; i < PLAT_PENDING; i++) {
        plat_req_t *q = &g_req[i];
        if (!q->used || q->dwell != g_dwell) continue;
        if (memcmp(q->sta, f->da, 6) != 0) continue;
        if (!q->wildcard && strcmp(q->ssid, ssid) != 0) continue;
        if (!q->to_any_bss && memcmp(q->addr3, f->bssid, 6) != 0) continue;
        if (now < q->pcap_us && !(q->has_tsft && clk->has_tsft)) {
            backwards = 1;
            continue;
        }
        if (now - q->pcap_us > (int64_t)PLAT_PAIR_MAX_US) continue;
        if (q->has_tsft && clk->has_tsft && clk->tsft_us < q->tsft_us) {
            backwards = 1;
            continue;
        }
        if (existing && existing->last_seq == q->seq &&
            existing->last_dwell == q->dwell &&
            memcmp(existing->last_sta, q->sta, 6) == 0) {
            extra = 1;
            continue;
        }
        cands++;
        hit = q;
    }
    if (cands == 0) {
        if (extra)          bump(&g_ct.resp_extra);
        else if (backwards) bump(&g_ct.clock_backwards);
        else                bump(&g_ct.resp_unpaired);
        return;
    }
    if (cands > 1 || hit->dup) { bump(&g_ct.resp_ambiguous); return; }

    int      src;
    uint64_t us;
    if (hit->has_tsft && clk->has_tsft) {
        src = PLAT_SRC_TSFT;
        us  = clk->tsft_us - hit->tsft_us;
    } else {
        src = PLAT_SRC_PCAP;
        us  = (uint64_t)(now - hit->pcap_us);
    }
    if (us > PLAT_PAIR_MAX_US) { bump(&g_ct.resp_unpaired); return; }

    plat_row_t *r = row_get(f->bssid);
    memcpy(r->last_sta, hit->sta, 6);
    r->last_seq   = hit->seq;
    r->last_dwell = hit->dwell;
    hit->answered = 1;
    row_add(r, hit->wildcard ? PLAT_KIND_WILDCARD : PLAT_KIND_DIRECTED,
            (uint32_t)us, src, (time_t)clk->ts_sec);
}

void probe_latency_observe(const dot11_frame_t *f, const plat_clock_t *clk) {
    if (!f || !clk) return;
    pthread_mutex_lock(&g_mu);
    /* Dwell numbering from every frame shown, before any filter: the
     * boundary is where the radio's frequency changed, whatever the
     * frame was. */
    if (clk->freq_mhz <= 0) {
        bump(&g_ct.no_freq);
        pthread_mutex_unlock(&g_mu);
        return;
    }
    if (clk->freq_mhz != g_last_freq) {
        if (g_last_freq != 0) bump(&g_ct.dwells);
        g_dwell++;
        g_last_freq = clk->freq_mhz;
    }
    const uint8_t *body; int blen;
    if (!f->bad_fcs && f->proto == 0 && f->type == 0 &&
        (f->subtype == 4 || f->subtype == 5) &&
        dot11_frame_body(f, &body, &blen)) {
        if (f->subtype == 4) on_request(f, clk, body, blen);
        else                 on_response(f, clk, body, blen);
    }
    pthread_mutex_unlock(&g_mu);
}

static uint32_t rank(const uint32_t *sorted, int n, int pct) {
    int idx = (pct * n + 99) / 100 - 1;
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

static void stats_of(const plat_row_t *r, int kind, plat_stats_t *out) {
    memset(out, 0, sizeof(*out));
    int n = r->n[kind];
    if (n <= 0) return;
    uint32_t v[PLAT_SAMPLES];
    memcpy(v, r->smp[kind], sizeof(uint32_t) * (size_t)n);
    for (int i = 1; i < n; i++) {
        uint32_t x = v[i]; int j = i - 1;
        while (j >= 0 && v[j] > x) { v[j + 1] = v[j]; j--; }
        v[j + 1] = x;
    }
    out->n      = (uint32_t)n;
    out->min_us = v[0];
    out->p10_us = rank(v, n, 10);
    out->med_us = rank(v, n, 50);
    out->p90_us = rank(v, n, 90);
}

static void row_out(const plat_row_t *r, probe_latency_row_t *o) {
    memset(o, 0, sizeof(*o));
    memcpy(o->bssid, r->bssid, 6);
    o->src         = r->src;
    o->pairs_total = r->pairs_total;
    o->last_seen   = r->last_seen;
    for (int k = 0; k < PLAT_KIND_COUNT; k++) stats_of(r, k, &o->kind[k]);
}

int probe_latency_get(const uint8_t bssid[6], probe_latency_row_t *out) {
    if (!bssid || !out) return 0;
    pthread_mutex_lock(&g_mu);
    const plat_row_t *r = row_find(bssid);
    if (r) row_out(r, out);
    pthread_mutex_unlock(&g_mu);
    return r != NULL;
}

int probe_latency_snapshot(probe_latency_row_t *out, int max) {
    if (!out || max <= 0) return 0;
    pthread_mutex_lock(&g_mu);
    int n = g_row_n < max ? g_row_n : max;
    for (int i = 0; i < n; i++) row_out(&g_row[i], &out[i]);
    pthread_mutex_unlock(&g_mu);
    return n;
}

void probe_latency_counters(plat_counters_t *out) {
    if (!out) return;
    pthread_mutex_lock(&g_mu);
    *out = g_ct;
    pthread_mutex_unlock(&g_mu);
}

void probe_latency_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_req, 0, sizeof(g_req));
    memset(g_row, 0, sizeof(g_row));
    memset(&g_ct, 0, sizeof(g_ct));
    g_req_head  = 0;
    g_row_n     = 0;
    g_last_freq = 0;
    g_dwell     = 0;
    pthread_mutex_unlock(&g_mu);
}
