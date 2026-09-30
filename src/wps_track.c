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

void wps_track_observe(const uint8_t bssid[6], const uint8_t sta[6],
                       const uint8_t *eap_pkt, int eap_len, time_t now) {
    if (!bssid || !sta) return;
    eap_wsc_info_t w;
    if (!eap_wsc_parse(eap_pkt, eap_len, &w)) return;

    pthread_mutex_lock(&g_mu);
    wps_session_t *ss = session_for(bssid, sta, now);
    ss->last_seen   = now;
    ss->last_opcode = w.op_code;
    if (w.msg_type >= 0) ss->last_msg = w.msg_type;
    if (w.has_uuid_e) {
        memcpy(ss->uuid_e, w.uuid_e, 16);
        ss->has_uuid = 1;
    }
    int mn = wsc_m_number(w.msg_type);
    if (mn) ss->msg_bits |= 1u << mn;

    /* Coarse state per the header contract. M1 always re-arms — that
     * is the restart Reaver's next PIN attempt begins with — and only
     * a NACK that arrives after M3 completes a countable cycle, since
     * M1→NACK without M3 is an ordinary M2D-style refusal. */
    if (w.msg_type == WSC_MSG_M1) {
        ss->state = WPS_S_M1_SEEN;
    } else if (w.msg_type == WSC_MSG_M3) {
        if (ss->state == WPS_S_M1_SEEN) ss->state = WPS_S_M3_SEEN;
    } else if (w.op_code == WSC_OP_NACK || w.msg_type == WSC_MSG_NACK) {
        if (ss->state == WPS_S_M3_SEEN) ss->cycle_count++;
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
