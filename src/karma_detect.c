#include "karma_detect.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

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

/* Deauth-then-lure with a shared victim (#90) — see the declaration in
 * karma_detect.h for why a global "some flood happened recently" check
 * was replaced. */
int karma_deauth_lure_victim(const sloth_state_t *s,
                             const beacon_ap_t *candidate, time_t now,
                             uint8_t victim_out[6]) {
    if (!s || !candidate) return 0;

    for (int k = 0; k < s->deauth_victim_count; k++) {
        const deauth_victim_t *v = &s->deauth_victims[k];
        /* When the threshold was last met, not when the last frame came
         * (#88): trailing frames after a flood do not extend it. */
        if (!v->flood_last || now - v->flood_last > KARMA_DEAUTH_WIN_SECS)
            continue;
        /* Deauthed from the candidate itself isn't a lure — a rogue
         * flooding its own clients isn't luring them to itself. */
        if (memcmp(v->bssid, candidate->bssid, 6) == 0) continue;

        int interest = 0;
        for (int c = 0; c < s->pnl_count && !interest; c++) {
            const pnl_client_t *cli = &s->pnl_clients[c];
            if (memcmp(cli->mac, v->victim, 6) != 0) continue;
            for (int h = 0; h < candidate->ssid_history_n &&
                            h < MAX_AP_SSID_HISTORY && !interest; h++) {
                const char *name = candidate->ssid_history[h];
                if (!name[0]) continue;
                for (int p = 0; p < cli->ssid_count &&
                                p < MAX_PNL_SSIDS_PER_CLI; p++)
                    if (strcmp(name, cli->ssids[p]) == 0) { interest = 1; break; }
            }
        }
        if (!interest) {
            /* Or the lure already worked and the victim is sitting on
             * the candidate, seen no earlier than the flood that
             * knocked it off its real AP. */
            for (int as = 0; as < s->assoc_count; as++) {
                const assoc_t *as_e = &s->assocs[as];
                if (memcmp(as_e->bssid, candidate->bssid, 6) == 0 &&
                    memcmp(as_e->sta_mac, v->victim, 6) == 0 &&
                    as_e->last_seen >= v->flood_last) {
                    interest = 1;
                    break;
                }
            }
        }
        if (!interest) continue;

        if (victim_out) memcpy(victim_out, v->victim, 6);
        return 1;
    }
    return 0;
}

void karma_update(sloth_state_t *s) {
    time_t now = time(NULL);
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
        k->deauth_chain = karma_deauth_lure_victim(s, a, now, NULL);
        k->score        = 1 + (k->pnl_overlap > 0 ? 2 : 0)
                            + (k->ie_uniform ? 1 : 0)
                            + (k->deauth_chain ? 3 : 0);
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
