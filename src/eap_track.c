#include "eap_track.h"
#include "eap_parse.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

static rogue_radius_ap_t g_tab[MAX_ROGUE_RADIUS];
static int               g_count = 0;
static pthread_mutex_t   g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Find the record for `bssid`, or create one (evicting the oldest when
 * full). Caller holds g_mu. */
static rogue_radius_ap_t *find_or_create(const uint8_t *bssid, time_t now) {
    for (int i = 0; i < g_count; i++)
        if (memcmp(g_tab[i].bssid, bssid, 6) == 0) return &g_tab[i];

    int slot;
    if (g_count < MAX_ROGUE_RADIUS) {
        slot = g_count++;
    } else {
        slot = 0;
        for (int i = 1; i < g_count; i++)
            if (g_tab[i].last_seen < g_tab[slot].last_seen) slot = i;
    }
    memset(&g_tab[slot], 0, sizeof(g_tab[slot]));
    memcpy(g_tab[slot].bssid, bssid, 6);
    g_tab[slot].first_seen = now;
    return &g_tab[slot];
}

/* ── TLS-in-EAP session tracking (#65, CVE-2023-52160) ─────
 *
 * One row per (BSSID, STA) conversation in flight. The question is
 * whether the AP ever presented a server identity before the client
 * accepted it, so the row exists only between the first TLS-bearing
 * frame and the EAP-Success that resolves it.
 *
 * Bounded and LRU-evicted: an attacker spraying half-finished
 * handshakes must not be able to make this allocate. */
#define EAP_SESSIONS_MAX 64

typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t eap_type;        /* PEAP / TLS / TTLS */
    uint8_t server_hello;    /* AP presented a ServerHello */
    uint8_t certificate;     /* AP presented a Certificate */
    uint8_t in_use;
    time_t  last_seen;
} eap_session_t;

static eap_session_t g_sess[EAP_SESSIONS_MAX];

/* Caller holds g_mu. */
static eap_session_t *session_for(const uint8_t *bssid, const uint8_t *sta,
                                  time_t now) {
    int free_slot = -1, oldest = 0;
    for (int i = 0; i < EAP_SESSIONS_MAX; i++) {
        if (g_sess[i].in_use &&
            memcmp(g_sess[i].bssid, bssid, 6) == 0 &&
            memcmp(g_sess[i].sta,   sta,   6) == 0) return &g_sess[i];
        if (!g_sess[i].in_use && free_slot < 0) free_slot = i;
        if (g_sess[i].last_seen < g_sess[oldest].last_seen) oldest = i;
    }
    int slot = free_slot >= 0 ? free_slot : oldest;
    memset(&g_sess[slot], 0, sizeof(g_sess[slot]));
    memcpy(g_sess[slot].bssid, bssid, 6);
    memcpy(g_sess[slot].sta,   sta,   6);
    g_sess[slot].in_use    = 1;
    g_sess[slot].last_seen = now;
    return &g_sess[slot];
}

void eap_track_observe(const uint8_t *bssid, const uint8_t *sta,
                       int from_ap, const uint8_t *eap_pkt,
                       int eap_len, time_t now) {
    eap_info_t info;
    if (!bssid || !eap_parse(eap_pkt, eap_len, &info)) return;

    /* Success resolves a session rather than describing a method, so it
     * is handled before the type check that drops it. */
    if (info.code == EAP_CODE_SUCCESS || info.code == EAP_CODE_FAILURE) {
        if (!sta) return;
        pthread_mutex_lock(&g_mu);
        eap_session_t *ss = NULL;
        for (int i = 0; i < EAP_SESSIONS_MAX; i++) {
            if (g_sess[i].in_use &&
                memcmp(g_sess[i].bssid, bssid, 6) == 0 &&
                memcmp(g_sess[i].sta,   sta,   6) == 0) { ss = &g_sess[i]; break; }
        }
        if (ss) {
            /* Only a Success counts. A Failure means the client refused
             * — which is the supplicant behaving correctly, and turning
             * that into a finding would alert on the safe outcome. */
            if (info.code == EAP_CODE_SUCCESS &&
                (!ss->server_hello || !ss->certificate)) {
                rogue_radius_ap_t *r = find_or_create(bssid, now);
                r->last_seen = now;
                r->nocert_sessions++;
                if (!ss->server_hello) r->nocert_no_hello++;
                memcpy(r->last_nocert_sta, sta, 6);
                r->last_nocert_ts = now;
            }
            ss->in_use = 0;      /* resolved either way */
        }
        pthread_mutex_unlock(&g_mu);
        return;
    }

    /* Only method-bearing frames carry a type; Success/Failure don't. */
    if (info.type < 0) return;

    pthread_mutex_lock(&g_mu);

    /* TLS-in-EAP: record what the AP presented. Only AP→STA frames can
     * establish a server identity — a Certificate travelling the other
     * way is the *client* authenticating, which is not this question. */
    if (sta && eap_type_is_tls_based(info.type)) {
        eap_session_t *ss = session_for(bssid, sta, now);
        ss->eap_type  = (uint8_t)info.type;
        ss->last_seen = now;
        if (from_ap && info.tls && info.tls_len > 0) {
            int sh = 0, cert = 0;
            tls_scan_handshake(info.tls, info.tls_len, &sh, &cert);
            if (sh)   ss->server_hello = 1;
            if (cert) ss->certificate  = 1;
        }
    }

    rogue_radius_ap_t *r = find_or_create(bssid, now);
    r->last_seen = now;
    if (info.type < 32) r->eap_types_seen |= (uint32_t)(1u << info.type);
    if (eap_type_is_weak(info.type)) r->weak_method = 1;
    if (info.code == EAP_CODE_RESPONSE && info.type == EAP_TYPE_IDENTITY &&
        info.identity[0]) {
        /* An identity that isn't an anonymous outer identity
         * (anonymous@..., @realm) is a real username leak. */
        const char *id = info.identity;
        int anon = (strncmp(id, "anonymous", 9) == 0) || id[0] == '@';
        if (!anon) {
            r->identity_leaks++;
            snprintf(r->last_identity, sizeof(r->last_identity), "%s", id);
        }
    }
    pthread_mutex_unlock(&g_mu);
}

void eap_track_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_ROGUE_RADIUS ? g_count : MAX_ROGUE_RADIUS;
    for (int i = 0; i < n; i++) s->rogue_radius[i] = g_tab[i];
    s->rogue_radius_count = n;
    pthread_mutex_unlock(&g_mu);
}

void eap_track_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_count = 0;
    memset(g_tab, 0, sizeof(g_tab));
    memset(g_sess, 0, sizeof(g_sess));
    pthread_mutex_unlock(&g_mu);
}
