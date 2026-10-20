/* Regulatory-envelope rules (#101 slice A): COUNTRY_ABSENT and
 * DFS_MASKING.
 *
 * Their own file rather than rules_wifi_mgmt.c so the regulatory work
 * on #101 lands in parallel slices without sharing a hunk: the TPC rule
 * that came first stays where it shipped, and these two read the
 * compiled-in channel table (src/reg_table.c) that nothing else in the
 * engine needs to see.
 *
 * Both are heuristics and say so in their detail text. Neither has a
 * public advisory behind it — the issue records that for both — so the
 * citation is the clause that makes the observation meaningful (IEEE
 * 802.11d for the Country element; 47 CFR 15.407 and EN 301 893 for
 * DFS), and the finding is "this departs from what the clause leads one
 * to expect", never "this is a rogue". A passive sensor corroborates;
 * it does not confirm (#145, owner ruling 2). */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rules.h"
#include "engine_internal.h"
#include "alert_key.h"
#include "beacon_snoop.h"   /* ap_band_label() */
#include "ownership.h"
#include "reg_table.h"
#include "wifi_baseline.h"

/* Is this BSSID either half of a materialised evil-twin episode? The
 * episodes are what the twin rules already decided is a same-SSID,
 * different-radio pair, so this adds no judgement of its own. */
static int bssid_in_twin_episode(const sloth_state_t *s,
                                 const uint8_t bssid[6]) {
    for (int i = 0; i < s->twin_episode_count; i++) {
        const twin_episode_t *e = &s->twin_episodes[i];
        if (memcmp(e->twin_bssid, bssid, 6) == 0 ||
            memcmp(e->real_bssid, bssid, 6) == 0) return 1;
    }
    return 0;
}

/* Country element absent on a 5 GHz AP — IEEE 802.11d (now 802.11-2020
 * §9.4.2.8 and §11.8).
 *
 * The Country element is how a BSS tells its stations which regulatory
 * domain they are in: 802.11d added it so a station need not be
 * configured per country, and the beacon carries it whenever
 * dot11MultiDomainCapabilityActivated or dot11SpectrumManagementRequired
 * is true. In the 5 GHz band almost every regulatory domain requires
 * spectrum management (radar detection on 52-144), so a conformant AP
 * there sends it. hostapd with `ieee80211d=0` does not, and nor do the
 * stripped OpenWrt images rogue kits are built from.
 *
 * Its own kind, not a flag on TPC_ABSENT_HIGH_BAND (owner ruling on
 * #145): the TPC rule is about the *power* ceiling and is ownership-
 * gated because only the operator can fix it, while this one is about
 * the *domain* claim and is worth seeing on any AP in range — a
 * country-less 5 GHz AP is the cheap, high-specificity tell for a
 * lab-built rogue that the issue describes. So it runs ungated at LOW
 * and rises to WARN only when the AP touches something designated.
 *
 * Heuristic, and the detail says so. No CVE or advisory covers it, an
 * AP made before 802.11d (phy "legacy") is suppressed as the TPC rule
 * suppresses it, and nothing here claims the AP is unlawful — only that
 * it named no domain at all.
 *
 * 5 GHz only, decided by ap_band_label() and never by the bare number:
 * the 6 GHz regulatory envelope is a different element set and a
 * different slice, and 6 GHz channel numbers overlap these. 2.4 GHz is
 * out because the 2.4 GHz plan is the one band where a station can get
 * by without being told. */
void rule_country_absent(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];

        if (a->reg.country_present) continue;
        if (strcmp(ap_band_label(a->channel, a->channel_source),
                   "5 GHz") != 0) continue;
        if (strcmp(a->phy, "legacy") == 0) continue;

        /* Absence needs observation behind it: time AND readings, for
         * the reason TPC_ABSENT_MIN_BEACONS records. */
        if (!a->first_seen ||
            now - a->first_seen < COUNTRY_ABSENT_MIN_OBSERVED_S) continue;
        if (a->frame_count < COUNTRY_ABSENT_MIN_BEACONS) continue;

        const int my_bssid = ownership_is_my_bssid(a->bssid);
        const int my_ssid  = !my_bssid && a->ssid[0] &&
                             ownership_is_my_ssid(a->ssid);

        char bss[20];
        mac_to_str(a->bssid, bss, sizeof(bss));

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "countryabsent");
        akey_mac(&k, a->bssid);
        if (!akey_end(&k)[0]) continue;

        /* A malformed Country element is a different statement from no
         * element: the AP tried. Say which, so an operator does not go
         * looking for a missing config line that is actually present
         * and broken. */
        char malformed[48] = "";
        if (a->reg.malformed_country > 0)
            snprintf(malformed, sizeof(malformed),
                     " (%d malformed Country element(s) seen)",
                     a->reg.malformed_country);

        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%.17s \"%.20s\" ch%d: no Country element (802.11d, tag 7)"
                 " in %lds over %u beacons%s - heuristic, no advisory;"
                 " names no regulatory domain, not proof of a rogue%s",
                 bss, a->ssid[0] ? a->ssid : "<hidden>", a->channel,
                 (long)(now - a->first_seen), (unsigned)a->frame_count,
                 malformed,
                 my_bssid ? " - YOUR network"
                 : my_ssid ? " - carries YOUR SSID from a BSSID not"
                             " confirmed yours"
                 : "");
        fire(ALERT_TYPE_COUNTRY_ABSENT,
             (my_bssid || my_ssid) ? ALERT_SEV_WARN : ALERT_SEV_LOW,
             "COUNTRY_ABSENT", detail, key, NULL, 0, now);
    }
}

/* Did a Channel Switch Announcement lead this AP to `channel`?
 *
 * "Leading there" is a CSA naming `channel` as its target, heard no
 * later than DFS_MASK_CSA_SLACK_S after the AP's first beacon, from
 * either the AP's own BSSID or a BSSID beaconing the same non-empty
 * SSID — an ESS moving off a radar hit takes every radio with it, and
 * the one sloth heard announce may not be the one it then hears land.
 *
 * Bounded by the CSA ring (SLOTH_CSA_MAX_EVENTS, newest first): a move
 * announced long enough ago to have been pushed out reads as "no CSA".
 * That errs toward reporting, which a LOW finding can afford. */
static int csa_led_to(const sloth_state_t *s, const beacon_ap_t *a,
                      int channel) {
    for (int i = 0; i < s->csa_count; i++) {
        const sloth_csa_event_t *e = &s->csa_events[i];
        if (e->new_channel != channel) continue;
        if (!e->ts || e->ts > a->first_seen + DFS_MASK_CSA_SLACK_S) continue;
        if (memcmp(e->bssid, a->bssid, 6) == 0) return 1;
        if (!a->ssid[0]) continue;
        for (int j = 0; j < s->beacon_count; j++) {
            const beacon_ap_t *b = &s->beacon_aps[j];
            if (memcmp(b->bssid, e->bssid, 6) != 0) continue;
            if (strcmp(b->ssid, a->ssid) == 0) return 1;
        }
    }
    return 0;
}

/* DFS-masking — a BSSID that appears for the first time on a DFS
 * channel with no CSA leading there.
 *
 * On 52-64 and 100-144 a transmitter must listen for radar before it
 * may start (47 CFR 15.407(h)(2); EN 301 893 §4.2.6): a 60 s channel
 * availability check, ten minutes on 120-128 under ETSI. The common
 * ways a BSS arrives on such a channel are therefore "it was there
 * before we were" and "it moved there by announcing a switch". A BSSID
 * that turns up there after the RF picture settled, with no
 * announcement leading there, came up cold on a channel most clients
 * scan only passively and many WIDS cover lightly — the evasion the
 * issue describes, an evil twin on hostapd with `ieee80211h=0`.
 *
 * It is also what a legitimate AP does when it reboots onto a DFS
 * channel after its CAC, so this is a heuristic and LOW by default. No
 * public advisory names the pattern; the detail says so, verbatim from
 * the issue's caveat. It rises to WARN only on corroboration from
 * outside this rule: the AP carries a designated SSID from a BSSID
 * that is not designated, or it is already half of an evil-twin
 * episode.
 *
 * "New" means absent from the session's RF baseline (src/wifi_baseline.c,
 * frozen once the picture has settled). Before a baseline exists every
 * AP is new and the rule is inert. The DFS set comes from the compiled-
 * in table (reg_channel_is_dfs()), keyed by the AP's own Country
 * element where that names a jurisdiction the table has a source for
 * and by the union of every table where it does not.
 *
 * Known limit: on a --hop run a channel visited late in the cycle can
 * yield a first sighting after the baseline froze. The baseline waits
 * long enough for a normal cycle to complete, but a radio that dwells
 * long on busy channels can still miss a quiet DFS AP until later; that
 * AP reads as new. */
void rule_dfs_masking(const sloth_state_t *s, time_t now) {
    if (!wifi_baseline_ready()) return;

    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        const int ch = a->first_seen_channel;

        if (ch <= 0) continue;
        if (strcmp(ap_band_label(ch, a->channel_source), "5 GHz") != 0)
            continue;
        if (a->frame_count < DFS_MASK_MIN_BEACONS) continue;
        if (wifi_baseline_has_bssid(a->bssid)) continue;

        reg_jurisdiction_t which = REG_JUR_NONE;
        int cac_s = 0;
        const char *cc = a->reg.country_present ? a->reg.country : NULL;
        if (!reg_channel_is_dfs(cc, ch, &which, &cac_s)) continue;

        if (csa_led_to(s, a, ch)) continue;

        const int my_bssid = ownership_is_my_bssid(a->bssid);
        const int ssid_impostor = !my_bssid && a->ssid[0] &&
                                  ownership_is_my_ssid(a->ssid);
        const int twin = bssid_in_twin_episode(s, a->bssid);

        char bss[20];
        mac_to_str(a->bssid, bss, sizeof(bss));

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "dfsmask");
        akey_mac(&k, a->bssid);
        if (!akey_end(&k)[0]) continue;

        const reg_table_t *t = reg_table_get(which);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%.17s \"%.20s\" first heard on DFS ch%d (%s table, "
                 REG_TABLE_AS_OF "; %ds CAC) after the RF baseline, no CSA"
                 " leading there - heuristic, no public advisory%s%s%s",
                 bss, a->ssid[0] ? a->ssid : "<hidden>", ch,
                 t ? t->name : "FCC+ETSI", cac_s,
                 ssid_impostor ? " - carries YOUR SSID from a BSSID not"
                                 " confirmed yours" : "",
                 twin ? " - half of an evil-twin pair" : "",
                 my_bssid ? " - YOUR network" : "");
        fire(ALERT_TYPE_DFS_MASKING,
             (ssid_impostor || twin) ? ALERT_SEV_WARN : ALERT_SEV_LOW,
             "DFS_MASKING", detail, key, NULL, 0, now);
    }
}
