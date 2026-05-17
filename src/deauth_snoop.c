#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "deauth_snoop.h"

static deauth_event_t  g_events[MAX_DEAUTH_ENTRIES];
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── 802.11 frame parser ─────────────────────────────────── */

int deauth_parse(const uint8_t *dot11, int len, int8_t signal,
                 uint8_t src_out[6], uint8_t dst_out[6], uint8_t bssid_out[6],
                 uint16_t *reason_out, uint8_t *subtype_out)
{
    if (len < 24) return 0;

    uint8_t fc0  = dot11[0];
    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t sub  = (fc0 >> 4) & 0x0f;

    if (type != 0) return 0;                /* management only */
    if (sub != 10 && sub != 12) return 0;   /* disassoc or deauth only */

    memcpy(dst_out,  dot11 + 4,  6);
    memcpy(src_out,  dot11 + 10, 6);
    memcpy(bssid_out, dot11 + 16, 6);

    /* reason code is the first 2 bytes of the frame body, after the 24-byte header */
    *reason_out  = (len >= 26) ? (uint16_t)(dot11[24] | ((uint16_t)dot11[25] << 8)) : 0;
    *subtype_out = sub;

    (void)signal;
    return 1;
}

/* ── Event table ─────────────────────────────────────────── */

void deauth_record(const uint8_t *src, const uint8_t *dst,
                   const uint8_t *bssid, uint16_t reason, uint8_t subtype)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    /* update existing (src, dst) pair */
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_events[i].src, src, 6) == 0 &&
            memcmp(g_events[i].dst, dst, 6) == 0)
        {
            deauth_event_t *e = &g_events[i];
            /* reset burst window if last frame was too long ago */
            if (now - e->last_seen > DEAUTH_FLOOD_WIN_SECS) {
                e->count = 1;
                e->flood = 0;
            } else {
                e->count++;
                if (e->count >= DEAUTH_FLOOD_THRESH)
                    e->flood = 1;
            }
            e->reason   = reason;
            e->subtype  = subtype;
            e->last_seen = now;
            memcpy(e->bssid, bssid, 6);
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }

    /* new entry — evict oldest if full */
    int slot = g_count < MAX_DEAUTH_ENTRIES ? g_count++ : 0;
    if (slot == 0 && g_count == MAX_DEAUTH_ENTRIES) {
        time_t oldest = g_events[0].last_seen;
        for (int i = 1; i < g_count; i++) {
            if (g_events[i].last_seen < oldest) {
                oldest = g_events[i].last_seen;
                slot   = i;
            }
        }
    }

    memset(&g_events[slot], 0, sizeof(g_events[slot]));
    memcpy(g_events[slot].src,   src,   6);
    memcpy(g_events[slot].dst,   dst,   6);
    memcpy(g_events[slot].bssid, bssid, 6);
    g_events[slot].reason     = reason;
    g_events[slot].subtype    = subtype;
    g_events[slot].first_seen = now;
    g_events[slot].last_seen  = now;
    g_events[slot].count      = 1;
    g_events[slot].flood      = 0;

    pthread_mutex_unlock(&g_mu);
}

void deauth_snapshot(sloth_state_t *s)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    /* age out stale entries */
    int i = 0;
    while (i < g_count) {
        if (now - g_events[i].last_seen > DEAUTH_AGE_SECS)
            g_events[i] = g_events[--g_count];
        else
            i++;
    }

    int n = g_count < MAX_DEAUTH_ENTRIES ? g_count : MAX_DEAUTH_ENTRIES;
    memcpy(s->deauth_events, g_events, (size_t)n * sizeof(deauth_event_t));
    s->deauth_count = n;
    if (s->deauth_sel >= n) s->deauth_sel = n > 0 ? n - 1 : 0;

    int flood = 0;
    for (i = 0; i < n; i++)
        if (s->deauth_events[i].flood) { flood = 1; break; }
    s->deauth_flood_active = flood;

    pthread_mutex_unlock(&g_mu);
}

void deauth_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
