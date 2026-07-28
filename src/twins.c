#include <stdio.h>
#include <string.h>
#include <time.h>
#include "twins.h"
#include "alerts.h"
#include "wifi_oui_attacker.h"
#include "ownership.h"

/* Decide which half of a (a, b) twin pair is the "real" AP:
 *   1. If alerts marked one BSSID tainted, the *other* is real.
 *   2. Otherwise default to the lower-RSSI side — a real AP usually
 *      reaches us from further away than a freshly-placed rogue.
 *      Falls back to insertion order if both RSSIs are unknown. */
static void choose_sides(const beacon_ap_t *a, const beacon_ap_t *b,
                         const beacon_ap_t **real_out,
                         const beacon_ap_t **twin_out) {
    /* An operator-designated BSSID is never the impostor (#52). This
     * outranks the taint tracker and the RSSI heuristic below because
     * it is asserted, not inferred — and the RSSI rule would otherwise
     * often get it backwards: the operator's own AP is usually the
     * *closest* one, which is exactly what rule 2 reads as the rogue. */
    int a_mine = ownership_is_my_bssid(a->bssid);
    int b_mine = ownership_is_my_bssid(b->bssid);
    if (a_mine && !b_mine) { *real_out = a; *twin_out = b; return; }
    if (b_mine && !a_mine) { *real_out = b; *twin_out = a; return; }

    int a_tainted = evil_twin_bssid_is_tainted(a->bssid);
    int b_tainted = evil_twin_bssid_is_tainted(b->bssid);
    if (a_tainted && !b_tainted) { *real_out = b; *twin_out = a; return; }
    if (b_tainted && !a_tainted) { *real_out = a; *twin_out = b; return; }

    int a_sig = a->signal_dbm;
    int b_sig = b->signal_dbm;
    if (a_sig == 0 && b_sig == 0) { *real_out = a; *twin_out = b; return; }
    if (a_sig <= b_sig)           { *real_out = a; *twin_out = b; }
    else                          { *real_out = b; *twin_out = a; }
}

static int already_recorded(const sloth_state_t *s,
                            const uint8_t a[6], const uint8_t b[6]) {
    for (int i = 0; i < s->twin_episode_count; i++) {
        const twin_episode_t *e = &s->twin_episodes[i];
        if ((memcmp(e->real_bssid, a, 6) == 0 && memcmp(e->twin_bssid, b, 6) == 0) ||
            (memcmp(e->real_bssid, b, 6) == 0 && memcmp(e->twin_bssid, a, 6) == 0))
            return 1;
    }
    return 0;
}

void twins_snapshot(sloth_state_t *s) {
    s->twin_episode_count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (!a->ssid[0]) continue;
        if (!a->enc[0] || strcmp(a->enc, "OPEN") == 0) continue;
        for (int j = i + 1; j < s->beacon_count; j++) {
            const beacon_ap_t *b = &s->beacon_aps[j];
            if (strcmp(a->ssid, b->ssid) != 0) continue;
            if (strcmp(a->enc, b->enc) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
            if (memcmp(a->bssid, b->bssid, 3) == 0) continue; /* same OUI */
            /* Same reasoning as the evil-twin rule (#51): co-operating
             * infrastructure that happens to be cross-vendor is not a
             * twin pair. Kept in step with alerts.c so the [x] Twins
             * view and the alert never disagree about the same pair. */
            if (ap_infrastructure_peers(a, b)) continue;
            if (already_recorded(s, a->bssid, b->bssid)) continue;
            if (s->twin_episode_count >= MAX_TWIN_EPISODES) return;

            const beacon_ap_t *real, *twin;
            choose_sides(a, b, &real, &twin);

            twin_episode_t *e = &s->twin_episodes[s->twin_episode_count++];
            memset(e, 0, sizeof(*e));
            snprintf(e->ssid, sizeof(e->ssid), "%s", a->ssid);
            memcpy(e->real_bssid, real->bssid, 6);
            memcpy(e->twin_bssid, twin->bssid, 6);
            snprintf(e->enc, sizeof(e->enc), "%s", a->enc);
            e->real_rssi = real->signal_dbm;
            e->twin_rssi = twin->signal_dbm;
            /* RSSI swing — characterise the *twin* side (the suspected
             * rogue): a swing here is the proximity signal that drove
             * Phase 3. Skip if either bound is the 0-sentinel. */
            if (twin->rssi_min_60s && twin->rssi_max_60s) {
                int swing = twin->rssi_max_60s - twin->rssi_min_60s;
                if (swing < 0) swing = 0;
                if (swing > 255) swing = 255;
                e->rssi_swing_dbm = (uint8_t)swing;
            }
            e->attack_in_progress = evil_twin_bssid_is_tainted(twin->bssid)
                                  ? 1 : 0;
            e->attacker_oui = (oui_is_hak5(twin->fp.oui) ||
                               oui_is_espressif(twin->fp.oui))
                              ? 1 : 0;
            e->hash_mismatch = (a->fp.vendor_ies_hash &&
                                b->fp.vendor_ies_hash &&
                                a->fp.vendor_ies_hash != b->fp.vendor_ies_hash)
                               ? 1 : 0;
            e->last_seen = now;
        }
    }
    if (s->twin_episode_sel >= s->twin_episode_count)
        s->twin_episode_sel = s->twin_episode_count > 0
                              ? s->twin_episode_count - 1 : 0;
}

void twins_clear(void) {
    /* No process-wide state — episodes live on sloth_state_t. */
}
