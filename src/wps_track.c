#include <string.h>
#include <pthread.h>

#include "wps_track.h"
#include "eap_parse.h"
#include "sensor_health.h"

static wps_session_t   g_sess[MAX_WPS_SESSIONS];
static int             g_count;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* M-number for a WSC message type, or 0 when it is not an Mn. The
 * WSC_MSG_* values are not contiguous in M-order — M2D (0x06) sits
 * between M2 and M3 — so the bit index has to be mapped, not
 * subtracted, or every message from M3 up lands one bit high and
 * msg_bits stops meaning what the header says it means. */
static int wsc_m_number(int msg_type) {
    switch (msg_type) {
    case WSC_MSG_M1: return 1;
    case WSC_MSG_M2: return 2;
    case WSC_MSG_M3: return 3;
    case WSC_MSG_M4: return 4;
    case WSC_MSG_M5: return 5;
    case WSC_MSG_M6: return 6;
    case WSC_MSG_M7: return 7;
    case WSC_MSG_M8: return 8;
    default:         return 0;   /* M2D, ACK, NACK, Done */
    }
}

/* Caller holds g_mu. */
static wps_session_t *session_for(const uint8_t bssid[6],
                                  const uint8_t sta[6], time_t now) {
    int free_slot = -1, oldest = 0;
    for (int i = 0; i < MAX_WPS_SESSIONS; i++) {
        if (g_sess[i].in_use &&
            memcmp(g_sess[i].bssid, bssid, 6) == 0 &&
            memcmp(g_sess[i].sta,   sta,   6) == 0) return &g_sess[i];
        if (!g_sess[i].in_use && free_slot < 0) free_slot = i;
        if (g_sess[i].last_seen < g_sess[oldest].last_seen) oldest = i;
    }
    int slot = free_slot >= 0 ? free_slot : oldest;
    if (free_slot < 0) sh_evict_note(SH_EVICT_WPS_SESSION);
    else g_count++;
    memset(&g_sess[slot], 0, sizeof(g_sess[slot]));
    memcpy(g_sess[slot].bssid, bssid, 6);
    memcpy(g_sess[slot].sta,   sta,   6);
    g_sess[slot].last_msg   = -1;
    g_sess[slot].first_seen = now;
    g_sess[slot].in_use     = 1;
    return &g_sess[slot];
}

/* Bits M4..M8 in msg_bits / attempt_bits: anything past M3. */
#define WPS_BITS_PAST_M3  (0x1F0u)
/* Bits M7..M8 plus attempt_bits bit 0 (Done): a registration that got
 * as far as the credentials. */
#define WPS_BITS_CRED     (0x180u | 0x1u)
/* Set once cred_ts has been stamped for the current attempt. Bit 9,
 * above every Mn, so it never reads as a message. */
#define WPS_BIT_CRED_STAMPED 0x200u
/* M1 and M3 in one attempt: the shape needs both, since a session first
 * heard mid-run at M3 says nothing about where that run began. */
#define WPS_BITS_M1_M3    ((1u << 1) | (1u << 3))

/* Caller holds g_mu. Close the current attempt on a re-arming M1:
 * an attempt that reached M3 and nothing past it, and did not finish,
 * is recorded as abandoned with the silence that followed it. */
static void attempt_close(wps_session_t *ss, time_t now) {
    if (ss->attempt_m3_ts &&
        (ss->attempt_bits & WPS_BITS_M1_M3) == WPS_BITS_M1_M3 &&
        !(ss->attempt_bits & (WPS_BITS_PAST_M3 | 0x1u))) {
        long q = (long)(now - ss->last_seen);
        if (q < 0) q = 0;
        if (q > 0x7fffffffL) q = 0x7fffffffL;
        ss->abandon_m3_ts   = ss->attempt_m3_ts;
        ss->abandon_quiet_s = (int)q;
        ss->abandon_n++;
    }
    ss->attempt_bits  = 0;
    ss->attempt_m3_ts = 0;
}

void wps_track_observe(const uint8_t bssid[6], const uint8_t sta[6],
                       const uint8_t *eap_pkt, int eap_len, time_t now) {
    if (!bssid || !sta) return;
    eap_wsc_info_t w;
    if (!eap_wsc_parse(eap_pkt, eap_len, &w)) return;

    pthread_mutex_lock(&g_mu);
    wps_session_t *ss = session_for(bssid, sta, now);
    /* Before last_seen moves: the closing attempt's silence is measured
     * from its own last frame to this M1. */
    if (w.msg_type == WSC_MSG_M1) attempt_close(ss, now);
    {
        wps_evt_t *e = &ss->ev[ss->ev_n % WPS_EVT_RING];
        e->ts  = now;
        e->op  = (int16_t)w.op_code;
        e->msg = (int16_t)w.msg_type;
        ss->ev_n++;
    }
    ss->last_seen   = now;
    ss->last_opcode = w.op_code;
    if (w.msg_type >= 0) ss->last_msg = w.msg_type;
    if (w.has_uuid_e) {
        memcpy(ss->uuid_e, w.uuid_e, 16);
        ss->has_uuid = 1;
    }
    int mn = wsc_m_number(w.msg_type);
    if (mn) {
        ss->msg_bits     |= 1u << mn;
        ss->attempt_bits |= 1u << mn;
    }
    if (w.op_code == WSC_OP_DONE || w.msg_type == WSC_MSG_DONE)
        ss->attempt_bits |= 1u;
    if (mn == 3 && !ss->attempt_m3_ts) ss->attempt_m3_ts = now;
    /* First arrival in this attempt only: a retransmitted M7 must not
     * move the completion later than it happened. */
    if ((ss->attempt_bits & WPS_BITS_CRED) &&
        !(ss->attempt_bits & WPS_BIT_CRED_STAMPED)) {
        ss->cred_ts       = now;
        ss->attempt_bits |= WPS_BIT_CRED_STAMPED;
    }

    /* Coarse state per the header contract. M1 always re-arms — that
     * is the restart Reaver's next PIN attempt begins with — and only
     * a NACK that arrives after M3 completes a countable cycle, since
     * M1→NACK without M3 is an ordinary M2D-style refusal. */
    if (w.msg_type == WSC_MSG_M1) {
        ss->state = WPS_S_M1_SEEN;
    } else if (w.msg_type == WSC_MSG_M3) {
        if (ss->state == WPS_S_M1_SEEN) ss->state = WPS_S_M3_SEEN;
    } else if (w.op_code == WSC_OP_NACK || w.msg_type == WSC_MSG_NACK) {
        if (ss->state == WPS_S_M3_SEEN) {
            /* Stamp before the increment so the cursor matches the
             * header's (cycle_count - 1) % WPS_CYCLE_RING. */
            ss->cycle_ts[ss->cycle_count % WPS_CYCLE_RING] = now;
            ss->cycle_count++;
        }
        if (ss->state != WPS_S_IDLE && ss->state != WPS_S_DONE)
            ss->state = WPS_S_NACKED;
    } else if (w.op_code == WSC_OP_DONE || w.msg_type == WSC_MSG_DONE ||
               w.msg_type == WSC_MSG_M8) {
        ss->state = WPS_S_DONE;
    }
    pthread_mutex_unlock(&g_mu);
}

int wps_track_session(const uint8_t bssid[6], const uint8_t sta[6],
                      wps_session_t *out) {
    if (!bssid || !sta || !out) return 0;
    int found = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_WPS_SESSIONS; i++) {
        if (g_sess[i].in_use &&
            memcmp(g_sess[i].bssid, bssid, 6) == 0 &&
            memcmp(g_sess[i].sta,   sta,   6) == 0) {
            *out = g_sess[i];
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return found;
}

int wps_track_snapshot(wps_session_t *out, int max) {
    if (!out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_WPS_SESSIONS && n < max; i++)
        if (g_sess[i].in_use) out[n++] = g_sess[i];
    pthread_mutex_unlock(&g_mu);
    return n;
}

int wps_track_cycles_since(const wps_session_t *sess, time_t now,
                           int window_s) {
    if (!sess || window_s <= 0) return 0;
    int have = sess->cycle_count < WPS_CYCLE_RING ? sess->cycle_count
                                                  : WPS_CYCLE_RING;
    time_t floor_t = now - (time_t)window_s;
    int n = 0;
    for (int i = 0; i < have; i++) {
        time_t t = sess->cycle_ts[i];
        /* A zero stamp is an unwritten slot, not the epoch; a stamp in
         * the future is a clock that stepped and is counted rather
         * than dropped — the alternative silences a live brute force
         * for a whole window. */
        if (t && t >= floor_t) n++;
    }
    return n;
}

int wps_track_m3_abandon(const wps_session_t *sess, time_t now,
                         time_t *m3_ts, int *quiet_s) {
    if (!sess) return 0;
    if (sess->attempt_m3_ts &&
        (sess->attempt_bits & WPS_BITS_M1_M3) == WPS_BITS_M1_M3 &&
        !(sess->attempt_bits & (WPS_BITS_PAST_M3 | 0x1u))) {
        long q = (long)(now - sess->last_seen);
        if (q < 0) q = 0;            /* a clock that stepped back */
        if (q > 0x7fffffffL) q = 0x7fffffffL;
        if (m3_ts)   *m3_ts   = sess->attempt_m3_ts;
        if (quiet_s) *quiet_s = (int)q;
        return 1;
    }
    if (sess->abandon_m3_ts) {
        if (m3_ts)   *m3_ts   = sess->abandon_m3_ts;
        if (quiet_s) *quiet_s = sess->abandon_quiet_s;
        return 1;
    }
    return 0;
}

int wps_track_events(const wps_session_t *sess, wps_evt_t *out, int max) {
    if (!sess || !out || max <= 0) return 0;
    int keep = max < WPS_EVT_RING ? max : WPS_EVT_RING;
    if (sess->ev_n < keep) keep = sess->ev_n;
    /* Slot k holds lifetime frame k % WPS_EVT_RING, so after a wrap the
     * oldest retained frame is not in slot 0. */
    int first = sess->ev_n - keep;
    for (int k = 0; k < keep; k++)
        out[k] = sess->ev[(first + k) % WPS_EVT_RING];
    return keep;
}

int wps_track_for_bssid(const uint8_t bssid[6], wps_session_t *out,
                        int max) {
    if (!bssid || !out || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_WPS_SESSIONS && n < max; i++)
        if (g_sess[i].in_use && memcmp(g_sess[i].bssid, bssid, 6) == 0)
            out[n++] = g_sess[i];
    pthread_mutex_unlock(&g_mu);
    /* Insertion sort, newest activity first: n <= MAX_WPS_SESSIONS. */
    for (int i = 1; i < n; i++) {
        wps_session_t t = out[i];
        int j = i - 1;
        while (j >= 0 && out[j].last_seen < t.last_seen) {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = t;
    }
    return n;
}

int wps_track_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_count;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void wps_track_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_sess, 0, sizeof(g_sess));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
