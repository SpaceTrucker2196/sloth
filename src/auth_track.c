#include "auth_track.h"
#include <string.h>
#include <pthread.h>

/* Ring of recent auth frames keyed by destination BSSID. Sized well above
 * the flood threshold so a burst fits inside the detection window. */
#define AUTH_RING 512
typedef struct { uint8_t bssid[6]; time_t ts; } auth_ev_t;

static auth_ev_t       g_ring[AUTH_RING];
static int             g_head;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void auth_observe(const uint8_t bssid[6], time_t now) {
    pthread_mutex_lock(&g_mu);
    memcpy(g_ring[g_head].bssid, bssid, 6);
    g_ring[g_head].ts = now;
    g_head = (g_head + 1) % AUTH_RING;
    pthread_mutex_unlock(&g_mu);
}

int auth_flood_bssid(time_t now, int window_s, int thresh, uint8_t out_bssid[6]) {
    int best = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < AUTH_RING; i++) {
        if (!g_ring[i].ts || now - g_ring[i].ts > window_s) continue;
        /* Only tally from a BSSID's first in-window slot so each distinct
         * BSSID is counted once. */
        int seen_earlier = 0;
        for (int j = 0; j < i; j++)
            if (g_ring[j].ts && now - g_ring[j].ts <= window_s &&
                memcmp(g_ring[j].bssid, g_ring[i].bssid, 6) == 0) {
                seen_earlier = 1;
                break;
            }
        if (seen_earlier) continue;

        int c = 0;
        for (int j = 0; j < AUTH_RING; j++)
            if (g_ring[j].ts && now - g_ring[j].ts <= window_s &&
                memcmp(g_ring[j].bssid, g_ring[i].bssid, 6) == 0)
                c++;
        if (c >= thresh && c > best) {
            best = c;
            memcpy(out_bssid, g_ring[i].bssid, 6);
        }
    }
    pthread_mutex_unlock(&g_mu);
    return best;
}

void auth_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_ring, 0, sizeof(g_ring));
    g_head = 0;
    pthread_mutex_unlock(&g_mu);
}
