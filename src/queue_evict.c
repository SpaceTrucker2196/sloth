#include <string.h>
#include <pthread.h>

#include "queue_evict.h"
#include "tune.h"
#include "dot11_data.h"
#include "sensor_health.h"

static queue_evict_t   g_tbl[MAX_QUEUE_EVICT_ENTRIES];
static int             g_count;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Caller holds g_mu. NULL when the pair has no row — the lookup half,
 * kept separate from entry_for() because the downlink path must never
 * create one. */
static queue_evict_t *find_pair(const uint8_t bssid[6], const uint8_t sta[6]) {
    for (int i = 0; i < MAX_QUEUE_EVICT_ENTRIES; i++)
        if (g_tbl[i].in_use &&
            memcmp(g_tbl[i].bssid, bssid, 6) == 0 &&
            memcmp(g_tbl[i].sta,   sta,   6) == 0)
            return &g_tbl[i];
    return NULL;
}

/* Caller holds g_mu. */
static queue_evict_t *entry_for(const uint8_t bssid[6], const uint8_t sta[6],
                                time_t now) {
    queue_evict_t *e = find_pair(bssid, sta);
    if (e) return e;

    int free_slot = -1, oldest = 0;
    for (int i = 0; i < MAX_QUEUE_EVICT_ENTRIES; i++) {
        if (!g_tbl[i].in_use && free_slot < 0) free_slot = i;
        if (g_tbl[i].last_seen < g_tbl[oldest].last_seen) oldest = i;
    }
    int slot = free_slot >= 0 ? free_slot : oldest;
    if (free_slot < 0) sh_evict_note(SH_EVICT_QUEUE_EVICT);
    else g_count++;
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    memcpy(g_tbl[slot].bssid, bssid, 6);
    memcpy(g_tbl[slot].sta,   sta,   6);
    g_tbl[slot].first_seen = now;
    g_tbl[slot].in_use     = 1;
    /* -1, not the memset's 0: sequence number 0 is legal, so a zeroed
     * field would make the very first frame of a burst look like a
     * repeat of itself. */
    g_tbl[slot].burst_last_seq = -1;
    return &g_tbl[slot];
}

static int64_t stamp_us(time_t sec, long usec) {
    return (int64_t)sec * 1000000 + (usec > 0 ? usec : 0);
}

void queue_evict_note_session_change(const uint8_t bssid[6],
                                     const uint8_t sta[6], int src,
                                     time_t now_sec, long now_usec) {
    if (!bssid || !sta) return;
    /* A broadcast deauth ends every session on the BSS at once and
     * names none of them; attributing it to ff:ff:ff:ff:ff:ff would
     * make one row that every station's downlink traffic then lands
     * in. */
    if (dot11_is_group_addr(sta)) return;
    if (src < QUEUE_EVICT_SRC_ASSOC || src > QUEUE_EVICT_SRC_DISCONNECT) return;

    pthread_mutex_lock(&g_mu);
    queue_evict_t *e = entry_for(bssid, sta, now_sec);
    e->event_us       = stamp_us(now_sec, now_usec);
    e->event_src      = src;
    e->event_ts       = now_sec;
    e->burst_frames   = 0;
    e->burst_first_us = 0;
    e->burst_last_us  = 0;
    /* A new session change starts a new burst, so the previous burst's
     * last sequence number must not suppress this one's first frame. */
    e->burst_last_seq = -1;
    e->last_seen      = now_sec;
    pthread_mutex_unlock(&g_mu);
}

void queue_evict_observe_downlink(const uint8_t *dot11, int len,
                                  time_t now_sec, long now_usec) {
    if (!dot11 || len < 24) return;
    if (((dot11[0] >> 2) & 0x03) != 2) return;   /* not a data frame */

    int to_ds   =  dot11[1]       & 0x01;
    int from_ds = (dot11[1] >> 1) & 0x01;
    /* AP -> STA only (IEEE 802.11-2020 §9.3.2.1 Table 9-26). A released
     * queue travels downstream; an uplink frame in the same window is
     * the station talking, which is not evidence about the AP's buffer.
     * The four-address (WDS/mesh) case is excluded by the same test. */
    if (to_ds || !from_ds) return;

    /* A retransmission delivers nothing that was not already delivered,
     * so it cannot be a distinct released frame. The Retry bit is
     * IEEE 802.11-2020 §9.2.4.1.6. Checked before the addresses are
     * parsed because it is the cheapest discriminator available. */
    if (dot11[1] & 0x08) return;

    int sub = (dot11[0] >> 4) & 0x0f;
    /* Null / QoS-Null family: no payload, so nothing was delivered.
     * These are how an AP polls and keeps a session alive, and counting
     * them would let housekeeping reach the threshold on its own. */
    if (sub & 0x04) return;

    uint8_t bssid[6], sa[6], da[6];
    if (dot11_data_addrs(dot11, len, bssid, sa, da) != 1) return;
    /* Group-addressed downlink traffic is buffered against the BSS's
     * own DTIM schedule, not against one station's queue, so it says
     * nothing about the pair this module tracks.
     *
     * This is a pre-lock filter, not a correctness gate, and deleting
     * it leaves the suite green — stated here rather than implied,
     * because the test that looks like it covers this cannot: a row is
     * only ever created for a non-group station (see the guard in
     * queue_evict_note_session_change), so find_pair() with a group DA
     * can never match one. What the line buys is not taking the mutex
     * for every broadcast and multicast frame on a busy BSS. */
    if (dot11_is_group_addr(da)) return;

    int64_t now_us = stamp_us(now_sec, now_usec);

    pthread_mutex_lock(&g_mu);
    queue_evict_t *e = find_pair(bssid, da);
    if (e) {
        e->last_seen = now_sec;
        /* `now_us >= event_us` rather than `>`: a flush can share the
         * capture timestamp of the frame that triggered it. The guard
         * is there for out-of-order delivery, which a capture pipeline
         * does produce — a frame stamped before the session change
         * cannot be part of what that change released, whatever order
         * the two reached this function in. */
        if (e->event_us > 0 && now_us >= e->event_us &&
            (now_us - e->event_us) <=
                (int64_t)tune_val(TUNE_QUEUE_EVICT_WINDOW_MS) * 1000) {
            /* Distinct frames only. A retry with the Retry bit clear is
             * unusual but not impossible (some drivers rebuild the frame),
             * and the sequence number is the authoritative identity of an
             * MSDU — so the Retry-bit test above and this are belt and
             * braces on the same question rather than duplicates. */
            const int seq = dot11_seq_num(dot11, len);
            if (seq >= 0 && seq == e->burst_last_seq) {
                pthread_mutex_unlock(&g_mu);
                return;
            }
            e->burst_last_seq = seq;
            e->burst_frames++;
            if (e->burst_frames == 1) e->burst_first_us = now_us;
            e->burst_last_us = now_us;
            const uint32_t min_frames =
                (uint32_t)tune_val(TUNE_QUEUE_EVICT_MIN_FRAMES);
            if (e->burst_frames == min_frames) {
                e->release_count++;
                e->last_release_ts  = now_sec;
                e->last_release_src = e->event_src;
            }
            if (e->burst_frames >= min_frames) {
                e->last_release_frames = e->burst_frames;
                /* Span of the burst itself, not of the window: how fast
                 * the frames arrived is the part that separates a queue
                 * being drained from traffic trickling in. */
                e->last_release_span_ms =
                    (int)((e->burst_last_us - e->burst_first_us) / 1000);
            }
        }
    }
    pthread_mutex_unlock(&g_mu);
}

int queue_evict_lookup(const uint8_t bssid[6], const uint8_t sta[6],
                       queue_evict_t *out) {
    if (!bssid || !sta || !out) return 0;
    pthread_mutex_lock(&g_mu);
    queue_evict_t *e = find_pair(bssid, sta);
    if (e) *out = *e;
    int found = e ? 1 : 0;
    pthread_mutex_unlock(&g_mu);
    return found;
}

int queue_evict_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_count;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int queue_evict_snapshot(queue_evict_t *out, int max) {
    if (!out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_QUEUE_EVICT_ENTRIES && n < max; i++)
        if (g_tbl[i].in_use) out[n++] = g_tbl[i];
    pthread_mutex_unlock(&g_mu);
    return n;
}

const char *queue_evict_src_name(int src) {
    switch (src) {
    case QUEUE_EVICT_SRC_ASSOC:      return "association";
    case QUEUE_EVICT_SRC_REASSOC:    return "reassociation";
    case QUEUE_EVICT_SRC_DISCONNECT: return "disassoc/deauth";
    default:                         return "";
    }
}

void queue_evict_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_tbl, 0, sizeof(g_tbl));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
