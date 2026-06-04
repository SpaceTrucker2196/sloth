#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "bgp_snoop.h"

static bgp_session_t   g_tbl[MAX_BGP_SESSIONS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* RFC 4271 §4.1 — BGP common message header is 19 bytes:
 *   bytes  0..15  Marker (16 bytes of 0xFF in modern BGP)
 *   bytes 16..17  Length (network byte order; includes header)
 *   byte     18   Type (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE)
 *
 * Minimum total length is 19 (a bare KEEPALIVE); maximum is 4096
 * per the RFC. Anything outside that range is malformed. */
#define BGP_HDR_LEN         19
#define BGP_MIN_LEN         19
#define BGP_MAX_LEN       4096

#define BGP_TYPE_OPEN          1
#define BGP_TYPE_UPDATE        2
#define BGP_TYPE_NOTIFICATION  3
#define BGP_TYPE_KEEPALIVE     4

static int find_or_alloc(const char *peer_a, const char *peer_b) {
    /* Inputs to this function are already sorted lexically. */
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].peer_a, peer_a) == 0 &&
            strcmp(g_tbl[i].peer_b, peer_b) == 0) {
            return i;
        }
    }
    int slot;
    if (g_n < MAX_BGP_SESSIONS) {
        slot = g_n++;
    } else {
        /* Evict the oldest entry by last_seen. */
        slot = 0;
        for (int i = 1; i < g_n; i++) {
            if (g_tbl[i].last_seen < g_tbl[slot].last_seen) slot = i;
        }
    }
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    snprintf(g_tbl[slot].peer_a, sizeof(g_tbl[slot].peer_a), "%s", peer_a);
    snprintf(g_tbl[slot].peer_b, sizeof(g_tbl[slot].peer_b), "%s", peer_b);
    return slot;
}

int bgp_snoop_observe(const char *src_ip, uint16_t src_port,
                      const char *dst_ip, uint16_t dst_port,
                      const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < BGP_HDR_LEN) return 0;
    if (src_port != 179 && dst_port != 179) return 0;

    /* Walk the payload — TCP segments may carry several
     * back-to-back BGP messages. Stop on the first malformed
     * header so a corrupted segment can't loop forever. */
    int observed_any = 0;
    int seen_open = 0, seen_update = 0, seen_notif = 0, seen_keep = 0;
    int off = 0;

    while (off + BGP_HDR_LEN <= len) {
        /* Marker check: 16 bytes of 0xFF. */
        int marker_ok = 1;
        for (int i = 0; i < 16; i++) {
            if (payload[off + i] != 0xFF) { marker_ok = 0; break; }
        }
        if (!marker_ok) break;

        int mlen = ((int)payload[off + 16] << 8) | payload[off + 17];
        if (mlen < BGP_MIN_LEN || mlen > BGP_MAX_LEN) break;
        if (off + mlen > len) break;             /* truncated tail */

        uint8_t mtype = payload[off + 18];
        switch (mtype) {
        case BGP_TYPE_OPEN:         seen_open++;   break;
        case BGP_TYPE_UPDATE:       seen_update++; break;
        case BGP_TYPE_NOTIFICATION: seen_notif++;  break;
        case BGP_TYPE_KEEPALIVE:    seen_keep++;   break;
        default: goto walk_done;                 /* unknown type */
        }
        observed_any = 1;
        off += mlen;
    }
walk_done:
    if (!observed_any) return 0;

    /* Canonicalise the peer pair so messages in either direction
     * land on the same session entry. */
    const char *peer_a = src_ip, *peer_b = dst_ip;
    if (strcmp(peer_a, peer_b) > 0) {
        const char *t = peer_a; peer_a = peer_b; peer_b = t;
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    int idx = find_or_alloc(peer_a, peer_b);
    bgp_session_t *e = &g_tbl[idx];
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;
    e->open_count         += seen_open;
    e->update_count       += seen_update;
    e->notification_count += seen_notif;
    e->keepalive_count    += seen_keep;
    pthread_mutex_unlock(&g_mu);

    /* src_port silenced — kept in the public API for parity with
     * the other observers, even though BGP's symmetric port use
     * means we don't need it for client/server inference. */
    (void)src_port; (void)dst_port;
    return 1;
}

void bgp_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_BGP_SESSIONS ? g_n : MAX_BGP_SESSIONS;
    for (int i = 0; i < n; i++) s->bgp_sessions[i] = g_tbl[i];
    s->bgp_session_count = n;
    pthread_mutex_unlock(&g_mu);
}

void bgp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}
