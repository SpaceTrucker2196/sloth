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

void eap_track_observe(const uint8_t *bssid, const uint8_t *eap_pkt,
                       int eap_len, time_t now) {
    eap_info_t info;
    if (!bssid || !eap_parse(eap_pkt, eap_len, &info)) return;
    /* Only method-bearing frames carry a type; Success/Failure don't. */
    if (info.type < 0) return;

    pthread_mutex_lock(&g_mu);
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
    pthread_mutex_unlock(&g_mu);
}
