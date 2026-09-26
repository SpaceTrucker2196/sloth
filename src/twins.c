#include <stdio.h>
#include <string.h>
#include <time.h>
#include "twins.h"
#include "alerts.h"
#include "wired_attach.h"

/* The attribution ladder that used to live here as choose_sides() moved
 * to src/alerts.c as twin_choose_sides() in #89 slice 3 — the rule and
 * this view already share twin_evidence_score, and keeping a second
 * copy of "which half is accused" is how the alert and the view start
 * disagreeing about a pair. Ranking and rationale: src/alerts.h. */

/* Largest 60s RSSI swing across the halves given (NULL skips a half).
 * A side whose bounds are both the 0-sentinel has no window yet. */
static int ap_swing(const beacon_ap_t *ap) {
    if (!ap || !ap->rssi_min_60s || !ap->rssi_max_60s) return 0;
    int swing = ap->rssi_max_60s - ap->rssi_min_60s;
    if (swing < 0)   swing = 0;
    if (swing > 255) swing = 255;
    return swing;
}

static int pair_swing(const beacon_ap_t *x, const beacon_ap_t *y) {
    int sx = ap_swing(x), sy = ap_swing(y);
    return sx > sy ? sx : sy;
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
            /* One scorer, shared with rule_evil_twin (#89), so the [x]
             * Twins view and the alert cannot disagree about a pair.
             * Neither a matching OUI nor an 802.11k neighbour claim
             * removes a candidate any more — both are confidence
             * deductions inside the score. What gates the episode is the
             * presence of positive impersonation evidence. */
            twin_evidence_t ev;
            if (!twin_evidence_score(s, a, b, now, &ev)) continue;
            if (already_recorded(s, a->bssid, b->bssid)) continue;
            if (s->twin_episode_count >= MAX_TWIN_EPISODES) return;

            const beacon_ap_t *real, *twin;
            int attributed = twin_choose_sides(a, b, &real, &twin);

            twin_episode_t *e = &s->twin_episodes[s->twin_episode_count++];
            memset(e, 0, sizeof(*e));
            snprintf(e->ssid, sizeof(e->ssid), "%s", a->ssid);
            memcpy(e->real_bssid, real->bssid, 6);
            memcpy(e->twin_bssid, twin->bssid, 6);
            snprintf(e->enc, sizeof(e->enc), "%s", a->enc);
            e->real_rssi   = real->signal_dbm;
            e->twin_rssi   = twin->signal_dbm;
            e->attributed  = attributed ? 1 : 0;
            e->confidence  = (uint8_t)ev.confidence;
            /* RSSI swing — the proximity signal that drove Phase 3.
             * Attributed to the twin side when we know which one that
             * is; on an unattributed pair the worse of the two, because
             * picking the half that sorted higher would be arbitrary.
             * Skip a side whose bounds are the 0-sentinel. */
            e->rssi_swing_dbm = (uint8_t)pair_swing(twin,
                                    attributed ? NULL : real);
            /* Flags characterise the pair, not "the rogue", whenever the
             * pair is unattributed — there is no rogue half to name. */
            e->attack_in_progress =
                (evil_twin_bssid_is_tainted(twin->bssid) ||
                 (!attributed && evil_twin_bssid_is_tainted(real->bssid)))
                ? 1 : 0;
            e->attacker_oui  = ev.attacker_oui  ? 1 : 0;
            e->hash_mismatch = ev.hashes_differ ? 1 : 0;
            /* What kind of AP this is, on the axis RF can speak to
             * (#89 slice 3). A label for the operator, never a gate —
             * the episode was already materialised above and no class
             * removes it. */
            e->ap_class = (uint8_t)twin_classify(&ev);
            /* And the axis RF cannot speak to. Asked only of the half
             * something has actually accused: on an unattributed pair
             * `real_bssid`/`twin_bssid` are just canonical order, so
             * asking about `twin` would attach a wired verdict to
             * whichever BSSID happened to sort higher. UNKNOWN there is
             * the honest answer, and with no correlator registered it
             * is the answer everywhere. */
            e->wired_attach = attributed
                ? (uint8_t)wired_attach_lookup(twin->bssid)
                : (uint8_t)WIRED_ATTACH_UNKNOWN;
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
