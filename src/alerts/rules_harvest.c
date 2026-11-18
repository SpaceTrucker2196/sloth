/* Key-material harvesting (#172): PMKID_HARVEST and HANDSHAKE_HARVEST.
 *
 * Their own file rather than rules_wifi_mgmt.c beside DEAUTH_FLOOD and
 * ASSOC_FLOOD, because what they report is not a flood: both shapes are
 * built to stay under those thresholds, and both read the harvest
 * tracker (src/harvest_track.c), which correlates three frame streams
 * — association requests, EAPOL-Key messages and deauthentications —
 * that no existing rule joins. Two kinds, not one with two shapes: the
 * EAPOL side of the engine already reports per mechanism (FRAG_EAPOL_
 * RELAY, FRAG_AMSDU_EAPOL) and the deauth side per mechanism
 * (DEAUTH_FLOOD, the twin chain), and the two shapes here have
 * different subjects — a soliciting station for one, an AP's address
 * for the other — so one key could not name both.
 *
 * Bases: research/papers/steube-2018-pmkid.md (the PMKID attack),
 * research/tools/hcxdumptool.md (both shapes as the tool's attack
 * vectors), research/ieee/802.11-2020-12.7-eapol-key.md (the messages
 * and the KDE). Passive: these rules read counts, and the handshake
 * capture and hashcat-22000 export (--collect-handshakes) are not
 * touched. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "alerts.h"
#include "harvest_track.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

static void mac_str(const uint8_t m[6], char out[20]) {
    snprintf(out, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* PMKID_HARVEST — hcxdumptool's "Connecting to an ACCESS POINT to get a
 * PMKID". A station asked HARVEST_MIN_BSSIDS (3) or more BSSIDs to
 * associate, each answered with an M1, and it left at least
 * HARVEST_UNANSWERED_PCT (50 %) of those M1s without an M2.
 *
 * WARN for that solicitation pattern. CRIT when it is corroborated by
 * the material itself: HARVEST_MIN_BSSIDS of the unanswered M1s carried
 * a PMKID KDE, and the station sent no M2 to any BSSID it asked. A
 * station that holds a key answers with an M2; one that never does,
 * while several APs hand it the one value Steube showed can be attacked
 * offline, has collected crackable material from each of them.
 *
 * The detail names the station row's cluster (#172 follow-up), the id
 * its EAPOL records and harvest_station record carry, and, when a
 * QUEUE_EVICT release landed on one of its (BSSID, station) pairs
 * inside the window, that pair: Framing Frames and the harvest in one
 * incident (harvest_track.h, "Clusters"). Severity does not move. */
void rule_pmkid_harvest(const sloth_state_t *s, time_t now) {
    int min_bssids = HARVEST_MIN_BSSIDS;
    int pct        = HARVEST_UNANSWERED_PCT;
    for (int i = 0; s->harvest_sta && i < s->harvest_sta_count; i++) {
        const harvest_sta_t *h = &s->harvest_sta[i];
        if (h->unanswered < min_bssids) continue;
        if (h->unanswered * 100 < pct * h->m1_bssids) continue;

        int corroborated = h->pmkid_unanswered >= min_bssids &&
                           h->answered == 0;
        alert_sev_t sev = corroborated ? ALERT_SEV_CRIT : ALERT_SEV_WARN;

        char sta[20];
        mac_str(h->sta, sta);
        int unanswered = h->unanswered;
        int m1_bssids  = h->m1_bssids;
        int solicited  = h->solicited;
        int pmkids     = h->pmkid_unanswered;
        int answered   = h->answered;
        unsigned cluster = (unsigned)h->cluster_id;
        int qevict = h->qevict;
        const char *tail = corroborated
                         ? " - PMKIDs handed to a station that never answered"
                         : " - solicitation pattern, uncorroborated";
        char detail[ALERT_DETAIL_LEN];
        if (qevict > 0) {
            char tgt[20];
            mac_str(h->qevict_bssid, tgt);
            snprintf(detail, sizeof detail,
                     "PMKID harvest STA %s: %d of %d BSSIDs that answered "
                     "its association with an M1 got no M2 (%d asked, %d "
                     "with PMKID, %d answered)%s - cluster #%u - "
                     "QUEUE_EVICT release on %s at %s in the window "
                     "(%d pairs)",
                     sta, unanswered, m1_bssids, solicited, pmkids,
                     answered, tail, cluster, sta, tgt, qevict);
        } else {
            snprintf(detail, sizeof detail,
                     "PMKID harvest STA %s: %d of %d BSSIDs that answered "
                     "its association with an M1 got no M2 (%d asked, %d "
                     "with PMKID, %d answered)%s - cluster #%u",
                     sta, unanswered, m1_bssids, solicited, pmkids,
                     answered, tail, cluster);
        }

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof key, "pmkidharvest");
        akey_mac(&k, h->sta);
        if (!akey_end(&k)[0]) continue;
        fire_ev(ALERT_TYPE_PMKID_HARVEST, sev, h->ev, h->ev_n,
                "PMKID_HARVEST", detail, key, NULL, 0, now);
    }
}

/* HANDSHAKE_HARVEST — hcxdumptool's "Disconnecting a CLIENT from an
 * associated ACCESS POINT to get a complete handshake". At least
 * HARVEST_DEAUTH_MIN (2) distinct deauthentication or disassociation
 * frames claimed from the BSSID to a station (or to broadcast), then,
 * within HARVEST_RECONNECT_S (30 s), that station's fresh M1/M2 pair
 * with the same BSSID: a crackable handshake captured on demand.
 *
 * WARN for one victim: an AP band-steering a client with repeated
 * deauths, and the client coming back to the same BSSID, has the same
 * shape. CRIT at HARVEST_CHAIN_CRIT_VICTIMS (2) distinct victims of one
 * BSSID inside the window, the harvesting run across a BSS's clients.
 * Fires alongside DEAUTH_FLOOD when a burst is also a flood: the two
 * report different things (an outage, a captured handshake), and the
 * engine has no cross-kind suppression to lean on.
 *
 * The detail names the chain's cluster and, when a victim's queue was
 * released on this BSSID inside the window (QUEUE_EVICT), that victim:
 * the deauthentication that knocked it off is the session change that
 * route of Framing Frames waits for. Severity does not move. */
void rule_handshake_harvest(const sloth_state_t *s, time_t now) {
    for (int i = 0; s->harvest_chain && i < s->harvest_chain_count; i++) {
        const harvest_chain_t *c = &s->harvest_chain[i];
        if (c->victims < 1) continue;
        alert_sev_t sev = c->victims >= HARVEST_CHAIN_CRIT_VICTIMS
                        ? ALERT_SEV_CRIT : ALERT_SEV_WARN;

        char bssid[20];
        mac_str(c->bssid, bssid);
        int victims = c->victims;
        int frames  = c->deauth_frames;
        int recon   = (int)HARVEST_RECONNECT_S;
        unsigned cluster = (unsigned)c->cluster_id;
        int qevict = c->qevict;
        const char *tail = sev == ALERT_SEV_WARN
                         ? " - one station, uncorroborated" : "";
        char detail[ALERT_DETAIL_LEN];
        if (qevict > 0) {
            char psta[20];
            mac_str(c->qevict_sta, psta);
            snprintf(detail, sizeof detail,
                     "Handshake harvest BSSID %s: %d stations reconnected "
                     "through a fresh M1/M2 within %d s of %d deauths "
                     "claimed from the AP%s - cluster #%u - QUEUE_EVICT "
                     "release on %s at %s in the window (%d victims)",
                     bssid, victims, recon, frames, tail, cluster, psta,
                     bssid, qevict);
        } else {
            snprintf(detail, sizeof detail,
                     "Handshake harvest BSSID %s: %d stations reconnected "
                     "through a fresh M1/M2 within %d s of %d deauths "
                     "claimed from the AP%s - cluster #%u",
                     bssid, victims, recon, frames, tail, cluster);
        }

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof key, "hsharvest");
        akey_mac(&k, c->bssid);
        if (!akey_end(&k)[0]) continue;
        fire_ev(ALERT_TYPE_HANDSHAKE_HARVEST, sev, c->ev, c->ev_n,
                "HANDSHAKE_HARVEST", detail, key, NULL, 0, now);
    }
}
