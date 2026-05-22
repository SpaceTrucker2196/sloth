#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "seqnum_track.h"

static seqnum_client_t g_tbl[MAX_SEQNUM_CLIENTS];
static int             g_n   = 0;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

void seqnum_track_observe(const uint8_t mac[6], uint16_t seqnum)
{
    /* Skip clearly invalid sources: NULL OUI, multicast, broadcast. */
    if (!mac) return;
    if ((mac[0] & 0x01) != 0) return;   /* multicast/broadcast — not a STA */

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    int idx = -1;
    for (int i = 0; i < g_n; i++) {
        if (mac_eq(g_tbl[i].mac, mac)) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_n >= MAX_SEQNUM_CLIENTS) {
            /* Evict least-recently-seen. */
            idx = 0;
            for (int i = 1; i < g_n; i++)
                if (g_tbl[i].last_seen < g_tbl[idx].last_seen) idx = i;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        } else {
            idx = g_n++;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        }
        memcpy(g_tbl[idx].mac, mac, 6);
        g_tbl[idx].mac_random = (mac[0] & 0x02) ? 1 : 0;
    }
    g_tbl[idx].last_seen = now;
    g_tbl[idx].frame_count++;

    /* Push to history ring (newest at index 0). */
    int n = g_tbl[idx].hist_n;
    if (n < SEQNUM_HISTORY_LEN) n++;
    for (int i = n - 1; i > 0; i--) {
        g_tbl[idx].hist[i]    = g_tbl[idx].hist[i - 1];
        g_tbl[idx].hist_ts[i] = g_tbl[idx].hist_ts[i - 1];
    }
    g_tbl[idx].hist[0]    = seqnum & 0x0FFF;
    g_tbl[idx].hist_ts[0] = now;
    g_tbl[idx].hist_n     = n;

    pthread_mutex_unlock(&g_mu);
}

/* 12-bit modular distance. The seqnum field is 12 bits — distance
 * 4095 -> 0 is 1, not 4095. */
static int seq_gap(uint16_t a, uint16_t b) {
    int diff = (int)a - (int)b;
    if (diff < 0) diff = -diff;
    if (diff > 2048) diff = 4096 - diff;
    return diff;
}

/* Heuristic: two clients are likely the same device if, across all
 * pairs of their seqnum entries, there exists a pair whose seqnum gap
 * is small and whose timestamp delta is moderate. */
static int try_correlate(const seqnum_client_t *a, const seqnum_client_t *b,
                          int *out_gap, long *out_dt_ms)
{
    if (mac_eq(a->mac, b->mac)) return 0;
    if (a->hist_n == 0 || b->hist_n == 0) return 0;
    int best_gap = 4096;
    long best_dt = 0;
    for (int i = 0; i < a->hist_n; i++) {
        for (int j = 0; j < b->hist_n; j++) {
            int g = seq_gap(a->hist[i], b->hist[j]);
            long dt = (long)(a->hist_ts[i] - b->hist_ts[j]) * 1000;
            if (dt < 0) dt = -dt;
            /* Within a few hundred seqnums and a few seconds is a hit. */
            if (g <= 64 && dt <= 30000 && g < best_gap) {
                best_gap = g;
                best_dt  = dt;
            }
        }
    }
    if (best_gap >= 4096) return 0;
    *out_gap   = best_gap;
    *out_dt_ms = best_dt;
    return 1;
}

void seqnum_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);

    /* Copy the per-MAC table, newest-activity first. */
    int n = g_n < MAX_SEQNUM_CLIENTS ? g_n : MAX_SEQNUM_CLIENTS;
    int order[MAX_SEQNUM_CLIENTS];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_tbl[order[j]].last_seen > g_tbl[order[best]].last_seen)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) s->seqnum_clients[i] = g_tbl[order[i]];
    s->seqnum_count = n;

    /* Pairwise correlation scan. O(n^2 * hist_len^2) — bounded since n
     * is capped at 256 and history at 8. */
    int corr_n = 0;
    for (int i = 0; i < n && corr_n < MAX_SEQNUM_CORRELATIONS; i++) {
        for (int j = i + 1; j < n && corr_n < MAX_SEQNUM_CORRELATIONS; j++) {
            int gap; long dt;
            if (!try_correlate(&g_tbl[i], &g_tbl[j], &gap, &dt)) continue;
            seqnum_correlation_t *c = &s->seqnum_correlations[corr_n++];
            memset(c, 0, sizeof(*c));
            memcpy(c->mac_a, g_tbl[i].mac, 6);
            memcpy(c->mac_b, g_tbl[j].mac, 6);
            c->mac_a_random = g_tbl[i].mac_random;
            c->mac_b_random = g_tbl[j].mac_random;
            c->gap     = gap;
            c->dt_ms   = dt;
            c->a_count = g_tbl[i].frame_count;
            c->b_count = g_tbl[j].frame_count;
        }
    }
    /* Sort correlations by ascending gap (most likely first). */
    for (int i = 0; i < corr_n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < corr_n; j++)
            if (s->seqnum_correlations[j].gap <
                s->seqnum_correlations[best].gap) best = j;
        if (best != i) {
            seqnum_correlation_t tmp = s->seqnum_correlations[i];
            s->seqnum_correlations[i]    = s->seqnum_correlations[best];
            s->seqnum_correlations[best] = tmp;
        }
    }
    s->seqnum_correlation_count = corr_n;
    if (s->seqnum_corr_sel >= corr_n && corr_n > 0)
        s->seqnum_corr_sel = corr_n - 1;

    pthread_mutex_unlock(&g_mu);
}

void seqnum_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}

int seqnum_client_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}
