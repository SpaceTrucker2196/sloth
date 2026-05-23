#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "assoc_track.h"
#include "beacon_snoop.h"

static assoc_t         g_tbl[MAX_ASSOC_ENTRIES];
static int             g_n   = 0;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static int pair_eq(const assoc_t *a, const uint8_t bssid[6],
                                       const uint8_t sta[6]) {
    return memcmp(a->bssid, bssid, 6) == 0 &&
           memcmp(a->sta_mac, sta, 6) == 0;
}

/* Promote source: ASSOC_SRC_EAPOL beats _ASSOC / _REASSOC, etc.
 * Same evidence or weaker doesn't downgrade an existing entry. */
static int source_rank(int s) {
    if (s == ASSOC_SRC_EAPOL)   return 3;
    if (s == ASSOC_SRC_ASSOC)   return 2;
    if (s == ASSOC_SRC_REASSOC) return 2;
    return 0;
}

void assoc_observe(const uint8_t bssid[6], const uint8_t sta[6],
                    const char *ssid, int source,
                    int8_t signal, int channel)
{
    if (!bssid || !sta) return;
    /* Reject broadcast / null / multicast addresses on either side
     * — we only track unicast STA <-> AP relationships. */
    if ((sta[0]   & 0x01) || (bssid[0] & 0x01)) return;
    int all0_bssid = 1, all0_sta = 1;
    for (int i = 0; i < 6; i++) {
        if (bssid[i]) all0_bssid = 0;
        if (sta[i])   all0_sta   = 0;
    }
    if (all0_bssid || all0_sta) return;

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    int idx = -1;
    for (int i = 0; i < g_n; i++) {
        if (pair_eq(&g_tbl[i], bssid, sta)) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_n >= MAX_ASSOC_ENTRIES) {
            /* Evict least-recently-seen. */
            idx = 0;
            for (int i = 1; i < g_n; i++)
                if (g_tbl[i].last_seen < g_tbl[idx].last_seen) idx = i;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        } else {
            idx = g_n++;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        }
        memcpy(g_tbl[idx].bssid,   bssid, 6);
        memcpy(g_tbl[idx].sta_mac, sta,   6);
        g_tbl[idx].first_seen = now;
        g_tbl[idx].sta_random = (sta[0] & 0x02) ? 1 : 0;
    }
    g_tbl[idx].last_seen = now;
    g_tbl[idx].frame_count++;
    g_tbl[idx].signal_dbm = signal;
    if (channel > 0) g_tbl[idx].channel = channel;
    if (source_rank(source) > source_rank(g_tbl[idx].source))
        g_tbl[idx].source = source;
    /* Fill SSID if we don't have it yet — prefer the caller-supplied
     * one, fall back to a beacon-table lookup. */
    if (!g_tbl[idx].ssid[0]) {
        if (ssid && ssid[0])
            snprintf(g_tbl[idx].ssid, sizeof(g_tbl[idx].ssid), "%s", ssid);
        else
            beacon_find_ssid(bssid, g_tbl[idx].ssid);
    }

    pthread_mutex_unlock(&g_mu);
}

void assoc_forget(const uint8_t bssid[6], const uint8_t sta[6])
{
    if (!bssid || !sta) return;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n; i++) {
        if (pair_eq(&g_tbl[i], bssid, sta)) {
            /* Swap with last and shrink. */
            if (i != g_n - 1) g_tbl[i] = g_tbl[g_n - 1];
            g_n--;
            memset(&g_tbl[g_n], 0, sizeof(g_tbl[g_n]));
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

void assoc_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_ASSOC_ENTRIES ? g_n : MAX_ASSOC_ENTRIES;
    /* Sort by last_seen DESC for the view. */
    int order[MAX_ASSOC_ENTRIES];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_tbl[order[j]].last_seen > g_tbl[order[best]].last_seen)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) {
        s->assocs[i] = g_tbl[order[i]];
        /* Backfill SSID lazily — beacon may have been observed after
         * the assoc itself. */
        if (!s->assocs[i].ssid[0])
            beacon_find_ssid(s->assocs[i].bssid, s->assocs[i].ssid);
    }
    s->assoc_count = n;
    if (s->assoc_sel >= n && n > 0) s->assoc_sel = n - 1;
    pthread_mutex_unlock(&g_mu);
}

void assoc_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}

int assoc_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}
