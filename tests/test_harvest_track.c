#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "assoc_track.h"
#include "deauth_snoop.h"
#include "dot11_frame.h"
#include "eapol_log.h"
#include "harvest_track.h"
#include "sloth_clock.h"
#include "tune.h"
#include "frame_build.h"

/* PMKID_HARVEST and HANDSHAKE_HARVEST (#172).
 *
 * Every frame is built per IEEE 802.11-2020 with tests/frame_build.h
 * and handed to the observer the capture path hands it to:
 *   - (Re)Association Request (§9.3.3.6 / §9.3.3.8): A1 = BSSID,
 *     A2 = SA (the station), A3 = BSSID; Capability, Listen Interval
 *     [, Current AP], then SSID, Supported Rates and an RSNE (§9.4.2.24)
 *     -> assoc_request_parse_frame() -> assoc_request_observe();
 *   - EAPOL-Key in a data frame (§9.3.2, LLC/SNAP 88-8E; the Key frame
 *     of §12.7.2 with a PMKID KDE 00-0F-AC:4 in M1's Key Data when the
 *     test says so): M1 FromDS (A1 = STA, A2 = A3 = BSSID), M2 ToDS
 *     (A1 = BSSID, A2 = STA, A3 = BSSID) -> eapol_observe_frame();
 *   - Deauthentication (§9.3.3.12): Reason Code body
 *     -> deauth_parse_frame() -> deauth_record().
 * The monotonic clock is the test's, so every window is driven
 * exactly; the collector's own `now` follows it in whole seconds. */

static uint64_t g_hv_mono = 5000000;
static uint64_t hv_mono(void) { return g_hv_mono; }
static time_t   hv_now(void)  { return (time_t)(1700000000 + g_hv_mono / 1000); }

static void hv_begin(void) {
    sloth_clock_test_set(hv_mono, NULL);
    g_hv_mono = 5000000;
    tune_reset();
    harvest_clear();
    eapol_clear();
    deauth_clear();
    assoc_request_clear();
    alerts_clear();
}

static void hv_end(void) {
    harvest_clear();
    eapol_clear();
    deauth_clear();
    assoc_request_clear();
    tune_reset();
    sloth_clock_test_set(NULL, NULL);
}

static void hv_advance_ms(uint64_t ms) { g_hv_mono += ms; }

static uint16_t g_seq = 1;

static void hv_assoc_req(const uint8_t sta[6], const uint8_t bssid[6],
                         int reassoc) {
    uint8_t f[128];
    fb_t b; fb_init(&b, f, (int)sizeof f);
    fb_mgmt(&b, reassoc ? 2 : 0, 0, bssid, sta, bssid,
            (uint16_t)(g_seq++ << 4), 0);
    fb_le16(&b, 0x0431);                 /* Capability */
    fb_le16(&b, 10);                     /* Listen Interval */
    if (reassoc) fb_mac(&b, bssid);      /* Current AP */
    fb_ssid(&b, "corp");
    static const uint8_t rates[4] = {0x82, 0x84, 0x8b, 0x96};
    fb_ie(&b, 1, rates, 4);
    fb_rsn(&b, 4, 4, 2, 0x0000);         /* CCMP / CCMP / PSK */
    ASSERT(fb_ok(&b));
    dot11_frame_t fr;
    dot11_frame_decode(f, b.len, NULL, &fr);
    assoc_req_t req;
    if (assoc_request_parse_frame(&fr, &req))
        assoc_request_observe(&req, -50, 6);
}

/* EAPOL-Key body (§12.7.2): descriptor 2 (RSN), Key Information, Key
 * Length, Replay Counter, Nonce, IV, RSC, reserved, MIC, Key Data. */
#define KI_M1 ((1 << 7) | (1 << 3) | 0x02)   /* Ack | Pairwise | v2 */
#define KI_M2 ((1 << 8) | (1 << 3) | 0x02)   /* MIC | Pairwise | v2 */

static int hv_eapol_key(uint8_t *out, uint16_t ki, uint8_t rc, uint8_t nonce,
                        int pmkid) {
    int p = 0;
    out[p++] = 0x02; out[p++] = 0x03; out[p++] = 0; out[p++] = 0;
    out[p++] = 0x02;
    out[p++] = (uint8_t)(ki >> 8); out[p++] = (uint8_t)(ki & 0xff);
    out[p++] = 0x00; out[p++] = 0x10;
    for (int i = 0; i < 7; i++) out[p++] = 0;
    out[p++] = rc;                                   /* Replay Counter */
    for (int i = 0; i < 32; i++) out[p++] = (uint8_t)(nonce + i);
    memset(out + p, 0, 16 + 8 + 8); p += 32;         /* IV, RSC, rsvd */
    for (int i = 0; i < 16; i++)                     /* MIC */
        out[p++] = (ki & (1 << 8)) ? (uint8_t)(0xe0 + i) : 0;
    int kdl = pmkid ? 22 : 0;
    out[p++] = (uint8_t)(kdl >> 8); out[p++] = (uint8_t)(kdl & 0xff);
    if (pmkid) {
        out[p++] = 0xDD; out[p++] = 0x14;
        out[p++] = 0x00; out[p++] = 0x0F; out[p++] = 0xAC; out[p++] = 0x04;
        for (int i = 0; i < 16; i++) out[p++] = (uint8_t)(0x11 * (i + 1));
    }
    int body = p - 4;
    out[2] = (uint8_t)(body >> 8); out[3] = (uint8_t)(body & 0xff);
    return p;
}

static void hv_eapol(const uint8_t sta[6], const uint8_t bssid[6],
                     int msg, uint8_t rc, uint8_t nonce, int pmkid,
                     uint64_t ev, int truncate_to) {
    uint8_t key[160];
    int kn = hv_eapol_key(key, msg == 1 ? KI_M1 : KI_M2, rc, nonce, pmkid);
    uint8_t f[256];
    fb_t b; fb_init(&b, f, (int)sizeof f);
    fb_hdr_t h; memset(&h, 0, sizeof h);
    h.type = 2; h.subtype = 0;
    h.flags = (uint8_t)(msg == 1 ? FB_FROMDS : FB_TODS);
    if (msg == 1) { h.a1 = sta;   h.a2 = bssid; }
    else          { h.a1 = bssid; h.a2 = sta;   }
    h.a3 = bssid;
    h.seq_ctl = (uint16_t)(g_seq++ << 4);
    fb_dot11_hdr(&b, &h);
    fb_llc_snap(&b, 0x888E);
    fb_bytes(&b, key, kn);
    ASSERT(fb_ok(&b));
    int len = truncate_to > 0 ? truncate_to : b.len;
    dot11_frame_t fr;
    dot11_frame_decode(f, len, NULL, &fr);
    fr.event_id = ev;
    eapol_observe_frame(&fr, -50, 6, hv_now(), 0);
}

/* A completed handshake's first half: M1 and the station's M2. */
static void hv_m1m2(const uint8_t sta[6], const uint8_t bssid[6],
                    uint8_t rc, int pmkid) {
    hv_eapol(sta, bssid, 1, rc, 0x40, pmkid, 0, 0);
    hv_advance_ms(20);
    hv_eapol(sta, bssid, 2, rc, 0x80, 0, 0, 0);
}

static void hv_deauth_flags(const uint8_t da[6], const uint8_t sa[6],
                            const uint8_t bssid[6], uint8_t flags,
                            uint16_t seq, uint64_t ev) {
    uint8_t f[32];
    fb_t b; fb_init(&b, f, (int)sizeof f);
    fb_mgmt(&b, 12, flags, da, sa, bssid, (uint16_t)(seq << 4), 0);
    fb_le16(&b, 7);                      /* Class 3 frame from nonassoc STA */
    ASSERT(fb_ok(&b));
    dot11_frame_t fr;
    dot11_frame_decode(f, b.len, NULL, &fr);
    deauth_frame_t df;
    if (deauth_parse_frame(&fr, &df)) {
        df.event_id = ev;
        deauth_record(&df);
    }
}

static void hv_deauth(const uint8_t da[6], const uint8_t sa[6],
                      const uint8_t bssid[6]) {
    hv_deauth_flags(da, sa, bssid, 0, g_seq++, 0);
}

static void hv_poll(sloth_state_t *s) {
    memset(s, 0, sizeof *s);
    harvest_snapshot(s);
    deauth_snapshot(s);
    alerts_clear();
    alerts_update(s);
}

static int hv_find(const sloth_state_t *s, alert_type_t t) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) return i;
    return -1;
}

static const uint8_t HCX[6]   = {0x02,0xcc,0x00,0x00,0x00,0x01};
static const uint8_t PHONE[6] = {0x02,0xdd,0x00,0x00,0x00,0x01};
static const uint8_t PHONE2[6]= {0x02,0xdd,0x00,0x00,0x00,0x02};
static const uint8_t BCAST[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

static void ap(uint8_t out[6], int i) {
    const uint8_t b[6] = {0x02,0x00,0x5e,0x00,0x01,(uint8_t)i};
    memcpy(out, b, 6);
}

/* The clientless shape: `n` BSSIDs asked, each answering with an M1,
 * none answered. */
static void hv_solicit(const uint8_t sta[6], int first, int n, int pmkid) {
    for (int i = first; i < first + n; i++) {
        uint8_t b[6]; ap(b, i);
        hv_assoc_req(sta, b, 0);
        hv_advance_ms(5);
        hv_eapol(sta, b, 1, 1, (uint8_t)i, pmkid, (uint64_t)(9000 + i), 0);
        hv_advance_ms(200);
    }
}

#define PAST_GRACE() hv_advance_ms((uint64_t)EAPOL_PAIR_WINDOW_S * 1000u + 1)

/* hcxdumptool's clientless run against three APs that send no PMKID:
 * WARN, the solicitation pattern alone. */
static void test_clientless_solicitation_warns(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 3, 0);
    PAST_GRACE();
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_PMKID_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(s.alerts[i].detail, "3 of 3 BSSIDs") != NULL);
        ASSERT(strstr(s.alerts[i].detail, "0 with PMKID") != NULL);
        ASSERT(strstr(s.alerts[i].detail, "uncorroborated") != NULL);
        ASSERT_STR(s.alerts[i].key, "pmkidharvest:02:cc:00:00:00:01");
        ASSERT_EQ((int)s.alerts[i].evidence_id_count, 3);
    }
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) < 0);
    hv_end();
}

/* The same run where every AP put a PMKID KDE in M1, and the station
 * never sent an M2 anywhere: CRIT. The two halves of the gate are each
 * seen to matter elsewhere: with the PMKID term dropped the no-PMKID
 * run above reads CRIT, and with `answered == 0` dropped
 * test_answered_station_is_never_crit does; each then restored. */
static void test_pmkids_to_a_never_answering_station_is_crit(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 3, 1);
    PAST_GRACE();
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_PMKID_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_CRIT);
        ASSERT(strstr(s.alerts[i].detail, "3 with PMKID") != NULL);
    }
    hv_end();
}

/* Two unanswered PMKIDs is not three: WARN-level evidence stays WARN
 * with one PMKID short, and the pattern needs its three BSSIDs. Seen
 * to fail with HARVEST_MIN_BSSIDS_DEFAULT at 2 and at 4 and with the
 * rule's `<` made `<=`, each then restored. */
static void test_bssid_count_boundary(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 2, 1);
    PAST_GRACE();
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);

    hv_solicit(HCX, 3, 1, 0);           /* the third: no PMKID */
    PAST_GRACE();
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_PMKID_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);

    ASSERT_EQ(tune_set_id(TUNE_HARVEST_MIN_BSSIDS, 4), 1);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    hv_end();
}

/* The ratio's edge. Six BSSIDs answered with an M1: three left
 * unanswered is exactly half and fires; with a seventh answered, three
 * of seven does not. A station that answered anything is never CRIT,
 * PMKIDs or not. Seen to fail with HARVEST_UNANSWERED_PCT_DEFAULT at
 * 51 and with the rule's `<` made `<=`, each then restored. At 49 it
 * passes, and cannot do otherwise: with at most HARVEST_MAX_TGT (16)
 * targets the nearest ratio under one half is 7/15, so 47..50 are one
 * setting to any test this table can hold. */
static void test_unanswered_ratio_boundary(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 3, 1);
    for (int i = 10; i < 13; i++) {
        uint8_t b[6]; ap(b, i);
        hv_assoc_req(HCX, b, 0);
        hv_m1m2(HCX, b, 1, 1);
        hv_advance_ms(200);
    }
    PAST_GRACE();
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_PMKID_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(s.alerts[i].detail, "3 of 6 BSSIDs") != NULL);
        ASSERT(strstr(s.alerts[i].detail, "3 answered") != NULL);
    }

    uint8_t b[6]; ap(b, 13);
    hv_assoc_req(HCX, b, 0);
    hv_m1m2(HCX, b, 1, 0);
    PAST_GRACE();
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    hv_end();
}

static void test_answered_station_is_never_crit(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 4, 1);
    uint8_t b[6]; ap(b, 20);
    hv_assoc_req(HCX, b, 0);
    hv_m1m2(HCX, b, 1, 0);
    PAST_GRACE();
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_PMKID_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
    hv_end();
}

/* An M1 is unanswered only after the collector's pairing window,
 * EAPOL_PAIR_WINDOW_S (10 s): on the edge it is still answerable. Seen
 * to fail with the snapshot's `>` made `>=`, then restored. */
static void test_m2_grace_boundary(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 3, 0);
    hv_advance_ms(10000 - 200);         /* the last M1 is exactly 10 s old */
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    hv_advance_ms(1);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) >= 0);
    hv_end();
}

/* The negative controls #172 names.
 *   - A phone roaming a mesh: five BSSIDs, each association completing
 *     an M1/M2 (PMKIDs in M1 included).
 *   - A station retrying one AP: six requests and M1s, one BSSID.
 *   - Enterprise PMK caching: reassociation requests to three BSSIDs,
 *     M1 carrying the cached PMKID, the station's M2 each time. */
static void test_legitimate_stations_do_not_fire(void) {
    hv_begin();
    static sloth_state_t s;
    for (int i = 1; i <= 5; i++) {
        uint8_t b[6]; ap(b, i);
        hv_assoc_req(PHONE, b, 0);
        hv_m1m2(PHONE, b, (uint8_t)i, 1);
        hv_advance_ms(30000);
    }
    uint8_t one[6]; ap(one, 40);
    for (int r = 0; r < 6; r++) {
        hv_assoc_req(PHONE2, one, 0);
        hv_eapol(PHONE2, one, 1, (uint8_t)(r + 1), (uint8_t)r, 0, 0, 0);
        hv_advance_ms(2000);
    }
    const uint8_t ent[6] = {0x02,0xee,0x00,0x00,0x00,0x01};
    for (int i = 50; i < 53; i++) {
        uint8_t b[6]; ap(b, i);
        hv_assoc_req(ent, b, 1);
        hv_m1m2(ent, b, 1, 1);
        hv_advance_ms(5000);
    }
    PAST_GRACE();
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) < 0);
    hv_end();
}

/* An M1 to a station the sensor never heard ask counts for nothing:
 * the request is what proves the station was audible, so a station
 * whose M2s are lost to range cannot look like one that sent none.
 * Seen to fail with harvest_note_eapol() opening rows on M1, then
 * restored. */
static void test_m1_without_a_heard_request_is_not_counted(void) {
    hv_begin();
    static sloth_state_t s;
    for (int i = 1; i <= 4; i++) {
        uint8_t b[6]; ap(b, i);
        hv_eapol(PHONE, b, 1, 1, (uint8_t)i, 1, 0, 0);
    }
    PAST_GRACE();
    hv_poll(&s);
    ASSERT_EQ(s.harvest_sta_count, 0);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    hv_end();
}

/* Truncated frames add nothing: an M1 cut inside its fixed Key frame
 * (the collector refuses it before classifying), and an association
 * request shorter than its fixed fields (no row). */
static void test_truncated_frames_count_nothing(void) {
    hv_begin();
    static sloth_state_t s;
    for (int i = 1; i <= 3; i++) {
        uint8_t b[6]; ap(b, i);
        hv_assoc_req(HCX, b, 0);
        /* 24 header + 8 LLC + 4 EAPOL header + 50: inside the fixed
         * Key frame, short of the 99 octets the parser needs. */
        hv_eapol(HCX, b, 1, 1, (uint8_t)i, 1, 0, 24 + 8 + 4 + 50);
    }
    /* A runt association request: header and 2 octets. */
    uint8_t f[26];
    fb_t bb; fb_init(&bb, f, (int)sizeof f);
    uint8_t b9[6]; ap(b9, 9);
    fb_mgmt(&bb, 0, 0, b9, HCX, b9, 0, 0);
    fb_le16(&bb, 0x0431);
    dot11_frame_t fr;
    dot11_frame_decode(f, bb.len, NULL, &fr);
    assoc_req_t req;
    ASSERT_EQ(assoc_request_parse_frame(&fr, &req), 0);
    PAST_GRACE();
    hv_poll(&s);
    ASSERT_EQ(s.harvest_sta_count, 1);
    if (s.harvest_sta_count == 1) {
        ASSERT_EQ(s.harvest_sta[0].solicited, 3);
        ASSERT_EQ(s.harvest_sta[0].m1_bssids, 0);
    }
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    hv_end();
}

/* The window. A target idle for harvest.window_s (900 s) still counts;
 * a millisecond later it goes, and the row with it. And the slow
 * harvest the issue says is missed today: three BSSIDs, five minutes
 * apart, all inside the window — DEAUTH/ASSOC/PROBE floods never see
 * it, this does. Seen to fail with HARVEST_WINDOW_DEFAULT_S at 60 (the
 * issue's figure: the slow run falls apart) and at 901/899 against
 * the edge, each then restored. */
static void test_window_holds_a_slow_harvest_and_ages_out(void) {
    hv_begin();
    static sloth_state_t s;
    for (int i = 1; i <= 3; i++) {
        uint8_t b[6]; ap(b, i);
        hv_assoc_req(HCX, b, 0);
        hv_eapol(HCX, b, 1, 1, (uint8_t)i, 0, 0, 0);
        if (i < 3) hv_advance_ms(300000);
    }
    PAST_GRACE();
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) >= 0);

    /* The first target is now 600 s + grace old. To 900 s exactly: */
    hv_advance_ms(900000 - 600000 - ((uint64_t)EAPOL_PAIR_WINDOW_S * 1000u + 1));
    hv_poll(&s);
    ASSERT_EQ(s.harvest_sta_count, 1);
    if (s.harvest_sta_count == 1) ASSERT_EQ(s.harvest_sta[0].solicited, 3);
    hv_advance_ms(1);
    hv_poll(&s);
    if (s.harvest_sta_count == 1) ASSERT_EQ(s.harvest_sta[0].solicited, 2);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) < 0);
    hv_end();
}

/* Bounded, and the eviction is the one documented: past
 * HARVEST_MAX_STA rows a flood of single-request random MACs displaces
 * the rows with the least harvest evidence, never the harvester; past
 * HARVEST_MAX_TGT targets an answered target goes before an unanswered
 * one, even when it is not the oldest. Seen to fail with sta_get()
 * evicting the least recent row regardless of evidence (the harvester,
 * oldest, is lost), and with tgt_get() evicting the least recent target
 * regardless of answer (the oldest unanswered one goes), each then
 * restored. */
static void test_tables_are_bounded_and_keep_the_harvester(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 3, 1);
    for (int i = 0; i < HARVEST_MAX_STA + 10; i++) {
        const uint8_t r[6] = {0x02,0x77,0x00,0x00,(uint8_t)(i >> 8),(uint8_t)i};
        uint8_t b[6]; ap(b, 100);
        hv_assoc_req(r, b, 0);
        hv_advance_ms(10);
    }
    PAST_GRACE();
    hv_poll(&s);
    ASSERT_EQ(s.harvest_sta_count, HARVEST_MAX_STA);
    ASSERT_EQ((long long)harvest_evictions(), 11);
    ASSERT(hv_find(&s, ALERT_TYPE_PMKID_HARVEST) >= 0);

    harvest_clear();
    hv_solicit(PHONE, 1, HARVEST_MAX_TGT - 1, 0);
    uint8_t answered[6]; ap(answered, 60);
    hv_assoc_req(PHONE, answered, 0);
    hv_m1m2(PHONE, answered, 1, 0);
    hv_advance_ms(10);
    hv_solicit(PHONE, HARVEST_MAX_TGT, 1, 0);
    PAST_GRACE();
    hv_poll(&s);
    ASSERT_EQ(s.harvest_sta_count, 1);
    if (s.harvest_sta_count == 1) {
        ASSERT_EQ(s.harvest_sta[0].solicited, HARVEST_MAX_TGT);
        ASSERT_EQ(s.harvest_sta[0].answered, 0);     /* the answered one went */
        ASSERT_EQ(s.harvest_sta[0].unanswered, HARVEST_MAX_TGT);
        ASSERT_EQ(s.harvest_sta[0].dropped, 1);
    }
    hv_end();
}

/* ── HANDSHAKE_HARVEST ───────────────────────────────────────── */

/* Two deauths claimed from the AP, then the victim's fresh M1/M2:
 * WARN, one station. DEAUTH_FLOOD is not involved — two frames is far
 * under its threshold, which is the slow case the issue describes. */
static void test_deauth_then_handshake_warns(void) {
    hv_begin();
    static sloth_state_t s;
    uint8_t b[6]; ap(b, 1);
    hv_deauth_flags(PHONE, b, b, 0, 100, 7001);
    hv_advance_ms(100);
    hv_deauth_flags(PHONE, b, b, 0, 101, 7002);
    hv_advance_ms(3000);
    hv_assoc_req(PHONE, b, 0);
    hv_m1m2(PHONE, b, 5, 0);
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT(strstr(s.alerts[i].detail, "1 stations") != NULL);
        ASSERT(strstr(s.alerts[i].detail, "of 2 deauths") != NULL);
        ASSERT_STR(s.alerts[i].key, "hsharvest:02:00:5e:00:01:01");
        ASSERT_EQ((int)s.alerts[i].evidence_id_count, 2);
    }
    ASSERT(hv_find(&s, ALERT_TYPE_DEAUTH_FLOOD) < 0);
    hv_end();
}

/* Two victims of one BSSID, one knocked off by broadcast deauths: CRIT.
 * Seen to fail with HARVEST_CHAIN_CRIT_VICTIMS at 3 and with the `>=`
 * made `>`, each then restored. */
static void test_two_victims_is_crit(void) {
    hv_begin();
    static sloth_state_t s;
    uint8_t b[6]; ap(b, 1);
    hv_deauth(BCAST, b, b);
    hv_deauth(BCAST, b, b);
    hv_advance_ms(2000);
    hv_m1m2(PHONE, b, 5, 0);
    hv_advance_ms(500);
    hv_m1m2(PHONE2, b, 9, 0);
    hv_poll(&s);
    int i = hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_CRIT);
        ASSERT(strstr(s.alerts[i].detail, "2 stations") != NULL);
    }
    hv_end();
}

/* The deauth count's edge: one frame and a retransmission of it (Retry
 * set, same sequence number) is one distinct frame, and does not
 * count; a second distinct frame does. With harvest.deauth_min at 3,
 * two do not. Seen to fail with HARVEST_DEAUTH_MIN_DEFAULT at 1 and at
 * 3, each then restored. */
static void test_deauth_count_boundary(void) {
    hv_begin();
    static sloth_state_t s;
    uint8_t b[6]; ap(b, 1);
    hv_deauth_flags(PHONE, b, b, 0, 200, 0);
    hv_deauth_flags(PHONE, b, b, FB_RETRY, 200, 0);
    hv_advance_ms(1000);
    hv_m1m2(PHONE, b, 5, 0);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) < 0);

    /* Exactly two distinct frames, on a station of their own. */
    hv_deauth_flags(PHONE2, b, b, 0, 201, 0);
    hv_deauth_flags(PHONE2, b, b, 0, 202, 0);
    hv_advance_ms(1000);
    hv_m1m2(PHONE2, b, 7, 0);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) >= 0);

    harvest_clear();
    ASSERT_EQ(tune_set_id(TUNE_HARVEST_DEAUTH_MIN, 3), 1);
    const uint8_t third[6] = {0x02,0xdd,0x00,0x00,0x00,0x03};
    hv_deauth_flags(third, b, b, 0, 300, 0);
    hv_deauth_flags(third, b, b, 0, 301, 0);
    hv_advance_ms(1000);
    hv_m1m2(third, b, 5, 0);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) < 0);
    hv_end();
}

/* The reconnect window: a pair completing harvest.reconnect_s (30 s)
 * after the last deauth counts; one a millisecond later does not. Seen
 * to fail with the comparison made >= and with
 * HARVEST_RECONNECT_DEFAULT_S at 29 and 31, each then restored. */
static void test_reconnect_window_boundary(void) {
    hv_begin();
    static sloth_state_t s;
    uint8_t b[6]; ap(b, 1);
    hv_deauth(PHONE, b, b);
    hv_deauth(PHONE, b, b);
    hv_advance_ms(30000 - 20);          /* hv_m1m2 adds 20 ms before M2 */
    hv_m1m2(PHONE, b, 5, 0);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) >= 0);

    harvest_clear();
    hv_deauth(PHONE2, b, b);
    hv_deauth(PHONE2, b, b);
    hv_advance_ms(30000 - 20 + 1);
    hv_m1m2(PHONE2, b, 5, 0);
    hv_poll(&s);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) < 0);
    hv_end();
}

/* What is not a harvested handshake:
 *   - a station leaving its own AP (deauths from the station, not the
 *     AP) and rejoining;
 *   - a deauth burst at one station while a different one reconnects;
 *   - a retransmitted M2 after a pair already completed (not fresh);
 *   - a plain association with no deauth at all.
 * The first is seen to fail with harvest_note_deauth()'s src == bssid
 * check removed, the third with `fresh_pair` passed as "any M2", each
 * then restored. */
static void test_not_a_harvested_handshake(void) {
    hv_begin();
    static sloth_state_t s;
    uint8_t b[6]; ap(b, 1);
    hv_deauth(b, PHONE, b);              /* PHONE -> AP */
    hv_deauth(b, PHONE, b);
    hv_advance_ms(1000);
    hv_m1m2(PHONE, b, 5, 0);

    uint8_t b2[6]; ap(b2, 2);
    hv_deauth(PHONE, b2, b2);
    hv_deauth(PHONE, b2, b2);
    hv_advance_ms(1000);
    hv_m1m2(PHONE2, b2, 5, 0);

    uint8_t b3[6]; ap(b3, 3);
    hv_m1m2(PHONE, b3, 3, 0);
    hv_advance_ms(100);
    hv_deauth(PHONE, b3, b3);
    hv_deauth(PHONE, b3, b3);
    hv_advance_ms(100);
    hv_eapol(PHONE, b3, 2, 3, 0x80, 0, 0, 0);   /* the same M2 again */

    uint8_t b4[6]; ap(b4, 4);
    hv_assoc_req(PHONE2, b4, 0);
    hv_m1m2(PHONE2, b4, 1, 0);

    hv_poll(&s);
    ASSERT_EQ(s.harvest_chain_count, 0);
    ASSERT(hv_find(&s, ALERT_TYPE_HANDSHAKE_HARVEST) < 0);
    hv_end();
}

/* Victims age out of a chain after harvest.window_s, and an empty
 * chain row goes. */
static void test_chain_ages_out(void) {
    hv_begin();
    static sloth_state_t s;
    uint8_t b[6]; ap(b, 1);
    hv_deauth(PHONE, b, b);
    hv_deauth(PHONE, b, b);
    hv_advance_ms(1000);
    hv_m1m2(PHONE, b, 5, 0);
    hv_poll(&s);
    ASSERT_EQ(s.harvest_chain_count, 1);
    hv_advance_ms(900000);
    hv_poll(&s);
    ASSERT_EQ(s.harvest_chain_count, 1);
    hv_advance_ms(1);
    hv_poll(&s);
    ASSERT_EQ(s.harvest_chain_count, 0);
    hv_end();
}

/* The capture and export are untouched: a harvested handshake is still
 * an ordinary EAPOL event in the collector's ring, with the pairing it
 * always had. */
static void test_collector_records_are_unchanged(void) {
    hv_begin();
    static sloth_state_t s;
    hv_solicit(HCX, 1, 1, 1);
    memset(&s, 0, sizeof s);
    eapol_snapshot(&s);
    ASSERT_EQ(s.eapol_count, 1);
    if (s.eapol_count == 1) {
        ASSERT_EQ(s.eapol_events[0].msg_num, 1);
        ASSERT_EQ(s.eapol_events[0].has_pmkid, 1);
        ASSERT_EQ(s.eapol_events[0].handshake_complete, 0);
    }
    hv_end();
}

void run_harvest_track_tests(void) {
    TEST_SUITE("PMKID / handshake harvesting (#172)");
    RUN_TEST(test_clientless_solicitation_warns);
    RUN_TEST(test_pmkids_to_a_never_answering_station_is_crit);
    RUN_TEST(test_bssid_count_boundary);
    RUN_TEST(test_unanswered_ratio_boundary);
    RUN_TEST(test_answered_station_is_never_crit);
    RUN_TEST(test_m2_grace_boundary);
    RUN_TEST(test_legitimate_stations_do_not_fire);
    RUN_TEST(test_m1_without_a_heard_request_is_not_counted);
    RUN_TEST(test_truncated_frames_count_nothing);
    RUN_TEST(test_window_holds_a_slow_harvest_and_ages_out);
    RUN_TEST(test_tables_are_bounded_and_keep_the_harvester);
    RUN_TEST(test_deauth_then_handshake_warns);
    RUN_TEST(test_two_victims_is_crit);
    RUN_TEST(test_deauth_count_boundary);
    RUN_TEST(test_reconnect_window_boundary);
    RUN_TEST(test_not_a_harvested_handshake);
    RUN_TEST(test_chain_ages_out);
    RUN_TEST(test_collector_records_are_unchanged);
}
