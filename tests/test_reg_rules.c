#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "beacon_snoop.h"
#include "ownership.h"
#include "sloth_clock.h"
#include "wifi_baseline.h"

/*
 * COUNTRY_ABSENT and DFS_MASKING — issue #101 slice A.
 *
 * Two layers. Most cases seed beacon_ap_t rows directly, the way
 * tests/test_alerts.c drives every other rule, because each is about
 * one guard and the row is the rule's whole input. The end-to-end cases
 * at the bottom build Beacon frames byte by byte per IEEE 802.11-2020
 * §9.3.3.3 and push them through beacon_parse() and beacon_record(), so
 * the Country element's presence and first_seen_channel both arrive the
 * way they do in production. No captures (agents/AGENTS.md).
 *
 * The wall clock is pinned throughout: alerts_update() and
 * beacon_record() both read sloth_wall(), and the observation floors
 * are measured against it.
 */

#define T0 ((time_t)1760000000)

static time_t g_now = T0;
static time_t pinned_wall(void) { return g_now; }

static sloth_state_t g_s;

static void begin(void) {
    g_now = T0;
    sloth_clock_test_set(NULL, pinned_wall);
    alerts_clear();
    ownership_clear();
    wifi_baseline_clear();
    beacon_clear();
    memset(&g_s, 0, sizeof(g_s));
}

static void end(void) {
    alerts_clear();
    ownership_clear();
    wifi_baseline_clear();
    beacon_clear();
    sloth_clock_test_set(NULL, NULL);
}

static int find_alert(const sloth_state_t *s, alert_type_t type) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) return i;
    return -1;
}

static int count_alerts(const sloth_state_t *s, alert_type_t type) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) n++;
    return n;
}

/* One AP as the rules see it after a snapshot. Defaults are the
 * "fires" shape for both rules — 5 GHz by DS Parameter Set, an HT tier,
 * past both observation floors, no Country element — so each case
 * changes only the field it is about. */
static beacon_ap_t *add_ap(const char *ssid, const uint8_t bssid[6],
                           int channel) {
    beacon_ap_t *a = &g_s.beacon_aps[g_s.beacon_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    memcpy(a->bssid, bssid, 6);
    snprintf(a->enc, sizeof(a->enc), "WPA2");
    snprintf(a->phy, sizeof(a->phy), "Wi-Fi 5");
    a->channel            = channel;
    a->first_seen_channel = channel;
    a->channel_source     = CH_SRC_DS_PARAM;
    a->signal_dbm         = -60;
    a->first_seen         = T0;
    a->last_seen          = T0;
    a->frame_count        = 10;
    return a;
}

static const uint8_t BSS_A[6] = {0x02,0x11,0x22,0x33,0x44,0x01};
static const uint8_t BSS_B[6] = {0x02,0x11,0x22,0x33,0x44,0x02};
static const uint8_t BSS_C[6] = {0x02,0x11,0x22,0x33,0x44,0x03};

/* ── COUNTRY_ABSENT ─────────────────────────────────────────── */

static void test_country_absent_fires_low_on_any_5ghz_ap(void) {
    begin();
    add_ap("CafeNet", BSS_A, 36);
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_LOW);
        ASSERT_STR(g_s.alerts[i].key, "countryabsent:02:11:22:33:44:01");
        ASSERT(strstr(g_s.alerts[i].detail, "no Country element") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "802.11d") != NULL);
        /* The heuristic caveat rides in the alert text itself. */
        ASSERT(strstr(g_s.alerts[i].detail, "heuristic") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "no advisory") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "ch36") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "YOUR") == NULL);
        ASSERT_STR(g_s.alerts[i].technique, "");
    }
    end();
}

static void test_country_absent_quiet_when_country_present(void) {
    begin();
    beacon_ap_t *a = add_ap("CafeNet", BSS_A, 36);
    a->reg.country_present = 1;
    snprintf(a->reg.country, sizeof(a->reg.country), "US");
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT), -1);
    end();
}

static void test_country_absent_quiet_off_5ghz(void) {
    begin();
    add_ap("TwoFour", BSS_A, 6);                      /* 2.4 GHz */
    beacon_ap_t *six = add_ap("SixG", BSS_B, 37);     /* 6 GHz number */
    six->channel_source = CH_SRC_HE_6GHZ;
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT), -1);
    /* The control: the same 6 GHz row read as 5 GHz by its source
     * fires, so the case above is held by the band, not by luck. */
    six->channel_source = CH_SRC_DS_PARAM;
    alerts_update(&g_s);
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_COUNTRY_ABSENT), 1);
    end();
}

static void test_country_absent_quiet_for_legacy_phy(void) {
    begin();
    beacon_ap_t *a = add_ap("Old11a", BSS_A, 36);
    snprintf(a->phy, sizeof(a->phy), "legacy");
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT), -1);
    end();
}

static void test_country_absent_needs_time_and_beacons(void) {
    begin();
    beacon_ap_t *a = add_ap("CafeNet", BSS_A, 36);
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S - 1;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT), -1);

    /* Old enough, but read too few times. */
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    a->frame_count = COUNTRY_ABSENT_MIN_BEACONS - 1;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT), -1);

    a->frame_count = COUNTRY_ABSENT_MIN_BEACONS;
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT) >= 0);
    end();
}

static void test_country_absent_warn_on_designated_bssid(void) {
    begin();
    ASSERT(ownership_add_bssid("02:11:22:33:44:01"));
    add_ap("CorpWiFi", BSS_A, 36);
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "YOUR network") != NULL);
    }
    end();
}

static void test_country_absent_ssid_only_is_not_claimed_yours(void) {
    /* An SSID is attacker-writable (#89): WARN, but the detail must not
     * call the BSSID the operator's. */
    begin();
    ASSERT(ownership_add_ssid("CorpWiFi"));
    add_ap("CorpWiFi", BSS_B, 36);
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "YOUR network") == NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "not confirmed yours") != NULL);
    }
    end();
}

static void test_country_absent_names_malformed_elements(void) {
    begin();
    beacon_ap_t *a = add_ap("CafeNet", BSS_A, 36);
    a->reg.malformed_country = 4;
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT);
    ASSERT(i >= 0);
    if (i >= 0)
        ASSERT(strstr(g_s.alerts[i].detail,
                      "4 malformed Country element(s)") != NULL);
    end();
}

static void test_country_absent_one_alert_per_bssid(void) {
    begin();
    add_ap("Mesh", BSS_A, 36);
    add_ap("Mesh", BSS_B, 149);
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    alerts_update(&g_s);
    alerts_update(&g_s);
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_COUNTRY_ABSENT), 2);
    end();
}

/* ── DFS_MASKING ────────────────────────────────────────────── */

/* Freeze the RF baseline over whatever rows exist now; rows added
 * afterwards are "new since the picture settled". */
static void freeze_baseline(void) { wifi_baseline_capture(&g_s); }

static void test_dfs_masking_inert_before_baseline(void) {
    begin();
    add_ap("Hidden5", BSS_A, 100);
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    /* The control: the same row after a baseline that lacks it. */
    g_s.beacon_count = 0;
    freeze_baseline();
    add_ap("Hidden5", BSS_A, 100);
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_fires_low_on_new_bssid(void) {
    begin();
    add_ap("Office", BSS_C, 36);
    freeze_baseline();
    add_ap("Hidden5", BSS_A, 100);
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_DFS_MASKING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_LOW);
        ASSERT_STR(g_s.alerts[i].key, "dfsmask:02:11:22:33:44:01");
        ASSERT(strstr(g_s.alerts[i].detail, "DFS ch100") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail,
                      "heuristic, no public advisory") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "no CSA") != NULL);
        /* No Country element: the union of both tables, dated. */
        ASSERT(strstr(g_s.alerts[i].detail, "FCC+ETSI table") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "2026-10-20") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "60s CAC") != NULL);
        ASSERT_STR(g_s.alerts[i].technique, "");
    }
    /* The AP already in the baseline is on a non-DFS channel anyway;
     * exactly one finding. */
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_DFS_MASKING), 1);
    end();
}

static void test_dfs_masking_quiet_for_baseline_member(void) {
    begin();
    add_ap("Hospital", BSS_A, 100);
    freeze_baseline();
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    end();
}

static void test_dfs_masking_reads_first_channel_not_current(void) {
    begin();
    freeze_baseline();
    /* Started on 36, moved to 100 later: where it started is the claim. */
    beacon_ap_t *a = add_ap("Mover", BSS_A, 100);
    a->first_seen_channel = 36;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    /* And the converse: started on 100, now on 36, still reported. */
    a->first_seen_channel = 100;
    a->channel = 36;
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_quiet_for_6ghz_numbering(void) {
    /* A 6 GHz primary channel is never a multiple of 4, so no honest
     * one lands on a DFS row — but a crafted HE 6 GHz Operation field
     * can carry any octet. The band decides, never the number. */
    begin();
    freeze_baseline();
    beacon_ap_t *a = add_ap("SixG", BSS_A, 100);
    a->channel_source = CH_SRC_HE_6GHZ;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    /* The control: the same row read as 5 GHz. */
    a->channel_source = CH_SRC_DS_PARAM;
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_quiet_on_non_dfs_channels(void) {
    begin();
    freeze_baseline();
    add_ap("U1", BSS_A, 48);
    add_ap("U3", BSS_B, 149);
    add_ap("TwoFour", BSS_C, 11);
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    end();
}

static sloth_csa_event_t *add_csa(const uint8_t bssid[6], int to, time_t ts) {
    sloth_csa_event_t *e = &g_s.csa_events[g_s.csa_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->bssid, bssid, 6);
    memcpy(e->ta, bssid, 6);
    e->new_channel  = (uint8_t)to;
    e->switch_count = 5;
    e->source       = CSA_SRC_BEACON;
    e->from_channel = 36;
    e->ts           = ts;
    return e;
}

static void test_dfs_masking_quiet_when_own_csa_led_there(void) {
    begin();
    freeze_baseline();
    add_ap("Mover", BSS_A, 100);
    add_csa(BSS_A, 100, T0 - 1);
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    end();
}

static void test_dfs_masking_csa_must_name_that_channel(void) {
    begin();
    freeze_baseline();
    add_ap("Mover", BSS_A, 100);
    add_csa(BSS_A, 104, T0 - 1);        /* led somewhere else */
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_csa_must_precede_arrival(void) {
    begin();
    freeze_baseline();
    add_ap("Mover", BSS_A, 100);
    /* Inside the slack: still "leading there". */
    add_csa(BSS_A, 100, T0 + DFS_MASK_CSA_SLACK_S);
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    /* Past it: a later announcement did not bring the AP here. */
    g_s.csa_events[0].ts = T0 + DFS_MASK_CSA_SLACK_S + 1;
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_quiet_when_ssid_peer_announced(void) {
    begin();
    add_ap("Clinic", BSS_B, 36);
    freeze_baseline();
    add_ap("Clinic", BSS_A, 100);
    add_csa(BSS_B, 100, T0 - 1);        /* the ESS moved off a radar hit */
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    /* A peer of a different SSID does not count. */
    snprintf(g_s.beacon_aps[0].ssid, sizeof(g_s.beacon_aps[0].ssid),
             "Elsewhere");
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_hidden_ssid_has_no_peers(void) {
    /* Two hidden networks share the SSID "", which is not an ESS. */
    begin();
    add_ap("", BSS_B, 36);
    freeze_baseline();
    add_ap("", BSS_A, 100);
    add_csa(BSS_B, 100, T0 - 1);
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_needs_beacons(void) {
    begin();
    freeze_baseline();
    beacon_ap_t *a = add_ap("Hidden5", BSS_A, 100);
    a->frame_count = DFS_MASK_MIN_BEACONS - 1;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_DFS_MASKING), -1);
    a->frame_count = DFS_MASK_MIN_BEACONS;
    alerts_update(&g_s);
    ASSERT(find_alert(&g_s, ALERT_TYPE_DFS_MASKING) >= 0);
    end();
}

static void test_dfs_masking_uses_the_named_countrys_table(void) {
    begin();
    freeze_baseline();
    beacon_ap_t *a = add_ap("Wetter", BSS_A, 120);
    a->reg.country_present = 1;
    snprintf(a->reg.country, sizeof(a->reg.country), "DE");
    /* 144 is DFS under the FCC but absent from EN 301 893: for an AP
     * naming DE the ETSI table answers, and it does not list 144. */
    beacon_ap_t *b = add_ap("Edge", BSS_B, 144);
    b->reg.country_present = 1;
    snprintf(b->reg.country, sizeof(b->reg.country), "DE");
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_DFS_MASKING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT(strstr(g_s.alerts[i].detail, "ETSI table") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "600s CAC") != NULL);
    }
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_DFS_MASKING), 1);
    /* The control: no country, so the union, which lists 144. */
    b->reg.country_present = 0;
    b->reg.country[0] = '\0';
    alerts_update(&g_s);
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_DFS_MASKING), 2);
    end();
}

static void test_dfs_masking_warn_on_designated_ssid_impostor(void) {
    begin();
    ASSERT(ownership_add_ssid("CorpWiFi"));
    freeze_baseline();
    add_ap("CorpWiFi", BSS_A, 100);
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_DFS_MASKING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "not confirmed yours") != NULL);
    }
    end();
}

static void test_dfs_masking_designated_bssid_stays_low(void) {
    /* The operator's own AP coming up on a DFS channel is the benign
     * reading, not the impostor one. */
    begin();
    ASSERT(ownership_add_ssid("CorpWiFi"));
    ASSERT(ownership_add_bssid("02:11:22:33:44:01"));
    freeze_baseline();
    add_ap("CorpWiFi", BSS_A, 100);
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_DFS_MASKING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_LOW);
        ASSERT(strstr(g_s.alerts[i].detail, "YOUR network") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "not confirmed") == NULL);
    }
    end();
}

static void test_dfs_masking_warn_when_half_of_twin_pair(void) {
    begin();
    freeze_baseline();
    add_ap("Lobby", BSS_A, 100);
    g_s.twin_episode_count = 1;
    memcpy(g_s.twin_episodes[0].twin_bssid, BSS_A, 6);
    memcpy(g_s.twin_episodes[0].real_bssid, BSS_C, 6);
    snprintf(g_s.twin_episodes[0].ssid, sizeof(g_s.twin_episodes[0].ssid),
             "Lobby");
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_DFS_MASKING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "evil-twin pair") != NULL);
    }
    end();
}

/* ── End to end, from hand-built Beacon frames ────────────────
 *
 * IEEE 802.11-2020 §9.3.3.2 management header, §9.3.3.3 Beacon body:
 *   FC(2) Duration(2) A1(6) A2(6) A3(6) SeqCtl(2)
 *   Timestamp(8) Beacon Interval(2) Capability Information(2)
 *   then elements, in Table 9-32 order: SSID (0), Supported Rates (1),
 *   DS Parameter Set (3), Country (7), HT Capabilities (45).
 */
static int build_beacon(uint8_t *f, int cap, const uint8_t bssid[6],
                        const char *ssid, int channel, int with_country) {
    int o = 0;
    uint8_t hdr[24] = {
        0x80, 0x00,                         /* FC: mgmt, subtype 8 Beacon */
        0x00, 0x00,                         /* Duration                   */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* A1 = broadcast DA          */
        0, 0, 0, 0, 0, 0,                   /* A2 = SA, filled below      */
        0, 0, 0, 0, 0, 0,                   /* A3 = BSSID, filled below   */
        0x10, 0x00,                         /* SeqCtl                     */
    };
    memcpy(hdr + 10, bssid, 6);
    memcpy(hdr + 16, bssid, 6);
    uint8_t fixed[12] = {
        0, 0, 0, 0, 0, 0, 0, 0,             /* Timestamp                  */
        0x64, 0x00,                         /* Beacon Interval: 100 TU    */
        0x01, 0x00,                         /* Capability: ESS            */
    };
    /* 6(B) 9 12(B) 18 24(B) 36 48 54 Mb/s, §9.4.2.3 */
    static const uint8_t rates[8] = {0x8c,0x12,0x98,0x24,0xb0,0x48,0x60,0x6c};
    /* §9.4.2.8: "US", environment ' ' (all), one subband triplet —
     * first channel 36, 8 channels, 23 dBm. 3 + 3 octets, even. */
    static const uint8_t country[6] = {'U','S',' ', 36, 8, 23};
    size_t slen = strlen(ssid);
    int need = 24 + 12 + 2 + (int)slen + 2 + 8 + 3 +
               (with_country ? 2 + 6 : 0) + 2 + 26;
    if (need > cap) return 0;

    memcpy(f + o, hdr, 24);   o += 24;
    memcpy(f + o, fixed, 12); o += 12;
    f[o++] = 0;  f[o++] = (uint8_t)slen; memcpy(f + o, ssid, slen); o += (int)slen;
    f[o++] = 1;  f[o++] = 8; memcpy(f + o, rates, 8); o += 8;
    f[o++] = 3;  f[o++] = 1; f[o++] = (uint8_t)channel;
    if (with_country) {
        f[o++] = 7; f[o++] = 6; memcpy(f + o, country, 6); o += 6;
    }
    /* HT Capabilities (§9.4.2.55), 26 octets, contents irrelevant here:
     * its presence is what makes the PHY tier not "legacy". */
    f[o++] = 45; f[o++] = 26; memset(f + o, 0, 26); o += 26;
    return o;
}

static void hear(const uint8_t bssid[6], const char *ssid, int channel,
                 int with_country) {
    uint8_t f[128];
    int len = build_beacon(f, (int)sizeof(f), bssid, ssid, channel,
                           with_country);
    ASSERT(len > 0);
    if (len <= 0) return;
    char s_out[33], enc[10];
    uint8_t b_out[6];
    int ch = 0;
    uint16_t bi = 0;
    beacon_rsn_t rsn;
    ASSERT_EQ(beacon_parse(f, len, -50, s_out, b_out, &ch, enc, &bi, &rsn), 1);
    ASSERT_EQ(ch, channel);
    beacon_record(b_out, s_out, -50, ch, enc, bi, &rsn);
}

static void test_e2e_country_element_decides_country_absent(void) {
    begin();
    for (int k = 0; k < 3; k++) {
        g_now = T0 + k;
        hear(BSS_A, "Stripped", 36, 0);
        hear(BSS_B, "Compliant", 36, 1);
    }
    g_now = T0 + COUNTRY_ABSENT_MIN_OBSERVED_S;
    beacon_snapshot(&g_s);
    ASSERT_EQ(g_s.beacon_count, 2);
    alerts_update(&g_s);
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_COUNTRY_ABSENT), 1);
    int i = find_alert(&g_s, ALERT_TYPE_COUNTRY_ABSENT);
    ASSERT(i >= 0);
    if (i >= 0)
        ASSERT_STR(g_s.alerts[i].key, "countryabsent:02:11:22:33:44:01");
    end();
}

static void test_e2e_first_seen_channel_is_set_once(void) {
    begin();
    g_now = T0;
    hear(BSS_A, "Mover", 100, 1);
    g_now = T0 + 1;
    hear(BSS_A, "Mover", 36, 1);
    beacon_snapshot(&g_s);
    ASSERT_EQ(g_s.beacon_count, 1);
    ASSERT_EQ(g_s.beacon_aps[0].channel, 36);
    ASSERT_EQ(g_s.beacon_aps[0].first_seen_channel, 100);
    end();
}

static void test_e2e_dfs_masking_from_frames(void) {
    begin();
    /* Settle: one AP on 36, baseline frozen over it. */
    for (int k = 0; k < 3; k++) { g_now = T0 + k; hear(BSS_C, "Office", 36, 1); }
    beacon_snapshot(&g_s);
    freeze_baseline();
    /* Then a newcomer, cold on 100, naming US. */
    for (int k = 0; k < 3; k++) { g_now = T0 + 40 + k; hear(BSS_A, "Office", 100, 1); }
    beacon_snapshot(&g_s);
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_DFS_MASKING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_STR(g_s.alerts[i].key, "dfsmask:02:11:22:33:44:01");
        ASSERT(strstr(g_s.alerts[i].detail, "FCC table") != NULL);
    }
    ASSERT_EQ(count_alerts(&g_s, ALERT_TYPE_DFS_MASKING), 1);
    end();
}

void run_reg_rules_tests(void) {
    TEST_SUITE("COUNTRY_ABSENT (#101 slice A)");
    RUN_TEST(test_country_absent_fires_low_on_any_5ghz_ap);
    RUN_TEST(test_country_absent_quiet_when_country_present);
    RUN_TEST(test_country_absent_quiet_off_5ghz);
    RUN_TEST(test_country_absent_quiet_for_legacy_phy);
    RUN_TEST(test_country_absent_needs_time_and_beacons);
    RUN_TEST(test_country_absent_warn_on_designated_bssid);
    RUN_TEST(test_country_absent_ssid_only_is_not_claimed_yours);
    RUN_TEST(test_country_absent_names_malformed_elements);
    RUN_TEST(test_country_absent_one_alert_per_bssid);
    TEST_SUITE("DFS_MASKING (#101 slice A)");
    RUN_TEST(test_dfs_masking_inert_before_baseline);
    RUN_TEST(test_dfs_masking_fires_low_on_new_bssid);
    RUN_TEST(test_dfs_masking_quiet_for_baseline_member);
    RUN_TEST(test_dfs_masking_reads_first_channel_not_current);
    RUN_TEST(test_dfs_masking_quiet_on_non_dfs_channels);
    RUN_TEST(test_dfs_masking_quiet_for_6ghz_numbering);
    RUN_TEST(test_dfs_masking_quiet_when_own_csa_led_there);
    RUN_TEST(test_dfs_masking_csa_must_name_that_channel);
    RUN_TEST(test_dfs_masking_csa_must_precede_arrival);
    RUN_TEST(test_dfs_masking_quiet_when_ssid_peer_announced);
    RUN_TEST(test_dfs_masking_hidden_ssid_has_no_peers);
    RUN_TEST(test_dfs_masking_needs_beacons);
    RUN_TEST(test_dfs_masking_uses_the_named_countrys_table);
    RUN_TEST(test_dfs_masking_warn_on_designated_ssid_impostor);
    RUN_TEST(test_dfs_masking_designated_bssid_stays_low);
    RUN_TEST(test_dfs_masking_warn_when_half_of_twin_pair);
    TEST_SUITE("regulatory rules from hand-built beacons (#101 slice A)");
    RUN_TEST(test_e2e_country_element_decides_country_absent);
    RUN_TEST(test_e2e_first_seen_channel_is_set_once);
    RUN_TEST(test_e2e_dfs_masking_from_frames);
}
