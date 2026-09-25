#include <stdio.h>
#include <string.h>
#include <time.h>
#include "twins.h"
#include "alerts.h"
#include "wifi_oui_attacker.h"
#include "ownership.h"
#include "inventory.h"

/* Decide which half of a (a, b) twin pair is the "real" AP, and say
 * honestly when we cannot. Returns 1 when the assignment is attributed
 * to evidence, 0 when the pair is merely ordered.
 *
 * Ranked by what the signal actually establishes:
 *   1. An operator-designated BSSID is never the impostor (#52), and
 *      neither is one the approved inventory declares for this SSID
 *      (#89 slice 2) — both are a human asserting ownership
 *      out-of-band, so they outrank everything inferred from the air.
 *   2. A BSSID the deauth chain tainted is the impostor — observed
 *      behaviour tied to that BSSID.
 *   3. An OUI in the Hak5 / Espressif attacker tables is the impostor —
 *      an observed device identity.
 *   4. Otherwise UNATTRIBUTED: canonical BSSID order, no verdict.
 *
 * What is deliberately gone (#89) is rule 4's predecessor, "the
 * stronger signal is the impostor". RSSI is not ownership: it is a fact
 * about distance and antennas, and in the commonest case it is exactly
 * backwards, because the operator's own AP is the closest radio in the
 * room. Naming a culprit from it made the view assert something it had
 * no basis for. Canonical ordering also stabilises the pair's identity —
 * the `twin_episodes` primary key used to swap, and so duplicate, the
 * moment two RSSIs crossed. */
static int choose_sides(const beacon_ap_t *a, const beacon_ap_t *b,
                        const beacon_ap_t **real_out,
                        const beacon_ap_t **twin_out) {
    /* inventory_verdict already unions --my-bssid into the approved
     * set, so the two operator statements are read together here
     * rather than ranked against each other. */
    int a_mine = ownership_is_my_bssid(a->bssid) ||
                 inventory_verdict(a->ssid, a->bssid) == INV_APPROVED;
    int b_mine = ownership_is_my_bssid(b->bssid) ||
                 inventory_verdict(b->ssid, b->bssid) == INV_APPROVED;
    if (a_mine && !b_mine) { *real_out = a; *twin_out = b; return 1; }
    if (b_mine && !a_mine) { *real_out = b; *twin_out = a; return 1; }

    int a_tainted = evil_twin_bssid_is_tainted(a->bssid);
    int b_tainted = evil_twin_bssid_is_tainted(b->bssid);
    if (a_tainted && !b_tainted) { *real_out = b; *twin_out = a; return 1; }
    if (b_tainted && !a_tainted) { *real_out = a; *twin_out = b; return 1; }

    int a_tool = oui_is_hak5(a->fp.oui) || oui_is_espressif(a->fp.oui);
    int b_tool = oui_is_hak5(b->fp.oui) || oui_is_espressif(b->fp.oui);
    if (a_tool && !b_tool) { *real_out = b; *twin_out = a; return 1; }
    if (b_tool && !a_tool) { *real_out = a; *twin_out = b; return 1; }

    twin_pair_order(a, b, real_out, twin_out);
    return 0;
}

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
            int attributed = choose_sides(a, b, &real, &twin);

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
