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

/* Size of the union of all nearby clients' PNL SSID sets — the |B| in
 * the Jaccard denominator. Deduplicated across clients. */
static int pnl_union_size(const sloth_state_t *s) {
    int n = 0;
    for (int c = 0; c < s->pnl_count; c++) {
        const pnl_client_t *cli = &s->pnl_clients[c];
        for (int k = 0; k < cli->ssid_count && k < MAX_PNL_SSIDS_PER_CLI; k++) {
            const char *name = cli->ssids[k];
            if (!name[0]) continue;
            int seen = 0;
            for (int pc = 0; pc <= c && !seen; pc++) {
                const pnl_client_t *p = &s->pnl_clients[pc];
                int klim = (pc == c) ? k : p->ssid_count;
                for (int j = 0; j < klim && j < MAX_PNL_SSIDS_PER_CLI; j++)
                    if (strcmp(name, p->ssids[j]) == 0) { seen = 1; break; }
            }
            if (!seen) n++;
        }
    }
    return n;
}

/* Jaccard similarity between the BSSID's advertised SSID set (A) and the
 * client-PNL union (B), in parts-per-million: 1e6 * |A∩B| / |A∪B|.
 * PineAP Beacon Response drives this toward 1.0 (1e6) — it advertises
 * exactly the union of what clients probe for. `inter` is the already-
 * computed intersection (pnl_overlap). */
static int jaccard_ppm(int a_count, int b_count, int inter) {
    int uni = a_count + b_count - inter;
    if (uni <= 0) return 0;
    return (int)((long)inter * 1000000L / uni);
}

/* 1 if every SSID this BSSID beaconed carried an identical, known IE
 * fingerprint — the PineAP tell. Legit multi-VAP APs vary RSN/vendor
 * IEs per VAP; a single spoofing radio does not. Requires >= 2 SSIDs
 * and non-zero (actually observed) fingerprints; all-unknown stays 0. */
static int ie_uniform(const beacon_ap_t *a) {
    int n = a->ssid_history_n;
    if (n < 2) return 0;
    uint32_t first = a->ssid_history_fp[0];
    if (first == 0) return 0;
    for (int i = 1; i < n && i < MAX_AP_SSID_HISTORY; i++)
        if (a->ssid_history_fp[i] != first) return 0;
    return 1;
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
    int b_count = pnl_union_size(s);   /* |PNL union| — same for every BSSID */
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
        k->pnl_jaccard_ppm = jaccard_ppm(k->ssid_count, b_count, k->pnl_overlap);
        k->ie_uniform   = ie_uniform(a);
        k->deauth_chain = chain;
        k->score        = 1 + (k->pnl_overlap > 0 ? 2 : 0)
                            + (k->ie_uniform ? 1 : 0) + (chain ? 3 : 0);
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
