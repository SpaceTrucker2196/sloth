#include "karma_detect.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Correlation window for the deauth-then-lure chain — matches the
 * KARMA_AP alert rule (issue #30). */
#define KARMA_DEAUTH_WIN_SECS 60

/* Distinct advertised SSIDs from this BSSID that appear in the union of
 * nearby clients' preferred-network lists. PineAP Beacon Response answers
 * exactly what clients probe for, so a high overlap separates an active
 * lure from a benign SSID-cycling AP. */
static int pnl_overlap(const sloth_state_t *s, const beacon_ap_t *a) {
    int hits = 0;
    for (int h = 0; h < a->ssid_history_n && h < MAX_AP_SSID_HISTORY; h++) {
        const char *name = a->ssid_history[h];
        if (!name[0]) continue;
        for (int c = 0; c < s->pnl_count; c++) {
            const pnl_client_t *cli = &s->pnl_clients[c];
            for (int k = 0; k < cli->ssid_count &&
                            k < MAX_PNL_SSIDS_PER_CLI; k++) {
                if (strcmp(name, cli->ssids[k]) == 0) { hits++; goto next; }
            }
        }
        next:;
    }
    return hits;
}

/* Is a deauth flood active within the correlation window? */
static int deauth_active(const sloth_state_t *s, time_t now) {
    for (int k = 0; k < s->deauth_count; k++) {
        const deauth_event_t *e = &s->deauth_events[k];
        if (e->flood && now - e->last_seen <= KARMA_DEAUTH_WIN_SECS) return 1;
    }
    return 0;
}

void karma_update(sloth_state_t *s) {
    time_t now = time(NULL);
    int chain = deauth_active(s, now);
    s->karma_count = 0;

    for (int i = 0; i < s->beacon_count &&
                    s->karma_count < MAX_KARMA_APS; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (a->ssid_history_n < KARMA_SSID_THRESH) continue;

        karma_ap_t *k = &s->karma_aps[s->karma_count++];
        memset(k, 0, sizeof(*k));
        memcpy(k->bssid, a->bssid, 6);
        k->ssid_count   = a->ssid_history_n;
        k->pnl_overlap  = pnl_overlap(s, a);
        k->deauth_chain = chain;
        k->score        = 1 + (k->pnl_overlap > 0 ? 2 : 0) + (chain ? 3 : 0);
        k->last_seen    = a->last_seen;
        snprintf(k->top_ssid, sizeof(k->top_ssid), "%s",
                 a->ssid[0] ? a->ssid : a->ssid_history[0]);
    }

    /* Rank strongest-first (insertion sort — the table is small and
     * near-sorted poll to poll). Ties keep beacon order. */
    for (int i = 1; i < s->karma_count; i++) {
        karma_ap_t tmp = s->karma_aps[i];
        int j = i - 1;
        while (j >= 0 && s->karma_aps[j].score < tmp.score) {
            s->karma_aps[j + 1] = s->karma_aps[j];
            j--;
        }
        s->karma_aps[j + 1] = tmp;
    }

    if (s->karma_sel >= s->karma_count)
        s->karma_sel = s->karma_count > 0 ? s->karma_count - 1 : 0;
}
