#include <string.h>
#include <stdio.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "alerts.h"
#include "tune.h"
#include "tui.h"
#include "wps_track.h"
#include "eap_parse.h"
#include "beacon_snoop.h"
#include "views/beacon.h"

/* ── Pixie-Dust detection, probe-response WSC walk, WPS sessions on
 *    the [b] detail screen — issue #82, 2026-10-19 plan ────────────
 *
 * Source: Bongard, "Offline bruteforce attack on WiFi Protected Setup"
 * (Hack.lu 2014), research/papers/bongard-pixie-dust-2014.md. The two
 * observable steps are "Do the WPS protocol up to message M3" and "Do
 * the full WPS protocol to get the credentials".
 *
 * Every frame here is hand-built from the spec — EAP Expanded Type 254
 * per RFC 3748 §5.7, the WSC header and TLVs per WSC 2.0 §7.7/§12, the
 * probe-response body per IEEE 802.11-2020 §9.3.3.10 — and fed through
 * the entry points the capture path calls. No captures (agents/
 * AGENTS.md). The wall clock is pinned through sloth_clock_test_set so
 * the silence and success windows are exact. */

static const uint8_t PB[6]  = { 0x3c, 0x84, 0x6a, 0x77, 0x88, 0x99 };
static const uint8_t PB2[6] = { 0x3c, 0x84, 0x6a, 0x77, 0x88, 0xaa };
static const uint8_t SA[6]  = { 0x02, 0xbe, 0xef, 0x00, 0x00, 0x01 };
static const uint8_t SB[6]  = { 0x02, 0xbe, 0xef, 0x00, 0x00, 0x02 };

static time_t g_wall;
static time_t px_wall(void) { return g_wall; }

static void px_begin(time_t at) {
    alerts_clear();
    wps_track_clear();
    tune_reset();
    g_wall = at;
    sloth_clock_test_set(NULL, px_wall);
}

static void px_end(void) {
    sloth_clock_test_set(NULL, NULL);
    wps_track_clear();
    tune_reset();
    alerts_clear();
}

/* One EAP-WSC frame: Request, Expanded Type, WFA SMI 0x00372A /
 * SimpleConfig 1, then Op-Code, Flags 0, Version 1.0 (0x104A) and a
 * Message Type (0x1022) attribute. EAP Length 24 covers all of it. */
static void px_feed(const uint8_t bssid[6], const uint8_t sta[6],
                    int op, int msg, time_t now) {
    uint8_t f[24] = {
        0x01, 0x20, 0x00, 0x18, 0xFE,             /* Request, Expanded  */
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, /* WFA / SimpleConfig */
        0x00, 0x00,                               /* Op-Code, Flags     */
        0x10, 0x4A, 0x00, 0x01, 0x10,             /* Version 1.0        */
        0x10, 0x22, 0x00, 0x01, 0x00,             /* Message Type       */
    };
    f[12] = (uint8_t)op;
    f[23] = (uint8_t)msg;
    wps_track_observe(bssid, sta, f, (int)sizeof(f), now);
}
static void px_msg(const uint8_t b[6], const uint8_t s[6], int m, time_t t) {
    px_feed(b, s, WSC_OP_MSG, m, t);
}

/* The registrar's half of Bongard's step one: the AP (enrollee) sends
 * M1 and M3, the registrar M2 — and then no M4. */
static void px_probe_run(const uint8_t b[6], const uint8_t s[6], time_t t) {
    px_msg(b, s, WSC_MSG_M1, t);
    px_msg(b, s, WSC_MSG_M2, t);
    px_msg(b, s, WSC_MSG_M3, t + 1);
}

/* A run that reaches the credentials: M1..M8 then Done. */
static void px_full_run(const uint8_t b[6], const uint8_t s[6], time_t t) {
    static const int seq[] = { WSC_MSG_M1, WSC_MSG_M2, WSC_MSG_M3,
                               WSC_MSG_M4, WSC_MSG_M5, WSC_MSG_M6,
                               WSC_MSG_M7, WSC_MSG_M8 };
    for (int i = 0; i < 8; i++) px_msg(b, s, seq[i], t + i);
    px_feed(b, s, WSC_OP_DONE, WSC_MSG_DONE, t + 8);
}

static int px_find(const sloth_state_t *s, alert_type_t t) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) return i;
    return -1;
}

static int px_count(const sloth_state_t *s, alert_type_t t) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) n++;
    return n;
}

static sloth_state_t g_s;

static void px_update(void) {
    memset(&g_s, 0, sizeof(g_s));
    alerts_update(&g_s);
}

/* ── Tracker: the per-attempt shape ─────────────────────────── */

static void test_m3_without_m4_is_the_shape(void) {
    wps_track_clear();
    px_probe_run(PB, SA, 1000);
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    time_t m3 = 0; int q = -1;
    ASSERT_EQ(wps_track_m3_abandon(&w, 1071, &m3, &q), 1);
    ASSERT_EQ((long long)m3, 1001);
    /* Silence runs from the attempt's last frame (M3 at 1001). */
    ASSERT_EQ(q, 70);
    /* Both out pointers are optional. */
    ASSERT_EQ(wps_track_m3_abandon(&w, 1071, NULL, NULL), 1);
    wps_track_clear();
}

static void test_m4_in_the_attempt_is_not_the_shape(void) {
    /* The online brute force always sends M4 — R-Hash1 is the guess —
       so an attempt that reached M4 is VU#723755, not Bongard. Seen
       red by dropping WPS_BITS_PAST_M3 from both checks in
       wps_track.c. */
    wps_track_clear();
    px_probe_run(PB, SA, 1000);
    px_msg(PB, SA, WSC_MSG_M4, 1002);
    px_feed(PB, SA, WSC_OP_NACK, WSC_MSG_NACK, 1003);
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ(wps_track_m3_abandon(&w, 5000, NULL, NULL), 0);
    wps_track_clear();
}

static void test_m3_heard_without_m1_is_not_the_shape(void) {
    /* A session first heard mid-run at M3 says nothing about where the
       run began. Seen red by dropping the WPS_BITS_M1_M3 term from
       wps_track_m3_abandon(). */
    wps_track_clear();
    px_msg(PB, SA, WSC_MSG_M3, 1000);
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ(wps_track_m3_abandon(&w, 5000, NULL, NULL), 0);
    wps_track_clear();
}

static void test_done_after_m3_is_not_abandoned(void) {
    /* A run that finished was not abandoned, whatever was missed in
       between. Seen red by dropping the Done bit (0x1) from the
       current-attempt check. */
    wps_track_clear();
    px_probe_run(PB, SA, 1000);
    px_feed(PB, SA, WSC_OP_DONE, WSC_MSG_DONE, 1002);
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ(wps_track_m3_abandon(&w, 5000, NULL, NULL), 0);
    wps_track_clear();
}

static void test_a_rearming_m1_closes_the_attempt_with_its_silence(void) {
    wps_track_clear();
    px_probe_run(PB, SA, 1000);            /* M3 at 1001 */
    px_msg(PB, SA, WSC_MSG_M1, 1090);      /* rerun 89 s later */
    px_msg(PB, SA, WSC_MSG_M2, 1090);
    px_msg(PB, SA, WSC_MSG_M3, 1091);
    px_msg(PB, SA, WSC_MSG_M4, 1091);      /* this one is online */
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ(w.abandon_n, 1);
    time_t m3 = 0; int q = 0;
    /* The current attempt is not the shape, so the closed one answers,
       with the silence measured when the M1 closed it — not now. */
    ASSERT_EQ(wps_track_m3_abandon(&w, 9999, &m3, &q), 1);
    ASSERT_EQ((long long)m3, 1001);
    ASSERT_EQ(q, 89);
    wps_track_clear();
}

static void test_cred_ts_is_the_first_credential_frame(void) {
    wps_track_clear();
    px_full_run(PB, SA, 2000);             /* M7 at 2006 */
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ((long long)w.cred_ts, 2006);
    /* A retransmitted M7 does not move the completion later. */
    px_msg(PB, SA, WSC_MSG_M7, 2100);
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ((long long)w.cred_ts, 2006);
    /* A new attempt that completes stamps its own time. */
    px_full_run(PB, SA, 3000);
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ((long long)w.cred_ts, 3006);
    wps_track_clear();
}

static void test_event_ring_is_oldest_first_and_clamped(void) {
    wps_track_clear();
    for (int i = 0; i < 20; i++)           /* 20 frames, ring of 16 */
        px_msg(PB, SA, WSC_MSG_M2, 4000 + i);
    wps_session_t w;
    ASSERT_EQ(wps_track_session(PB, SA, &w), 1);
    ASSERT_EQ(w.ev_n, 20);
    wps_evt_t ev[WPS_EVT_RING + 4];
    int n = wps_track_events(&w, ev, WPS_EVT_RING + 4);
    /* Clamped to the ring: asking for more must not fabricate rows. */
    ASSERT_EQ(n, WPS_EVT_RING);
    ASSERT_EQ((long long)ev[0].ts, 4004);
    ASSERT_EQ((long long)ev[n - 1].ts, 4019);
    ASSERT_EQ(ev[0].op, WSC_OP_MSG);
    ASSERT_EQ(ev[0].msg, WSC_MSG_M2);
    /* A smaller request gets the newest that many, still oldest first. */
    ASSERT_EQ(wps_track_events(&w, ev, 3), 3);
    ASSERT_EQ((long long)ev[0].ts, 4017);
    ASSERT_EQ(wps_track_events(&w, ev, 0), 0);
    ASSERT_EQ(wps_track_events(NULL, ev, 3), 0);
    wps_track_clear();
}

static void test_for_bssid_filters_and_orders_newest_first(void) {
    wps_track_clear();
    px_msg(PB,  SA, WSC_MSG_M1, 100);
    px_msg(PB2, SA, WSC_MSG_M1, 150);
    px_msg(PB,  SB, WSC_MSG_M1, 200);
    wps_session_t out[MAX_WPS_SESSIONS];
    ASSERT_EQ(wps_track_for_bssid(PB, out, MAX_WPS_SESSIONS), 2);
    ASSERT(memcmp(out[0].sta, SB, 6) == 0);   /* 200 before 100 */
    ASSERT(memcmp(out[1].sta, SA, 6) == 0);
    ASSERT_EQ(wps_track_for_bssid(PB, out, 1), 1);
    ASSERT_EQ(wps_track_for_bssid(PB2, out, MAX_WPS_SESSIONS), 1);
    ASSERT_EQ(wps_track_for_bssid(NULL, out, 4), 0);
    wps_track_clear();
}

/* ── WPS_PIXIE_PROBE ─────────────────────────────────────────── */

static void test_pixie_probe_fires_after_the_silence(void) {
    px_begin(1700000000);
    px_probe_run(PB, SA, g_wall - 61);       /* M3 at wall - 60 */
    px_update();
    int i = px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_STR(g_s.alerts[i].key,
                   "wpspixie:3c:84:6a:77:88:99:02:be:ef:00:00:01");
        ASSERT(strstr(g_s.alerts[i].detail, "stopped after M3") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "Bongard 2014") != NULL);
        /* Corroborate, never confirm (#145 ruling 2). */
        ASSERT(strstr(g_s.alerts[i].detail, "does not confirm") != NULL);
    }
    ASSERT_EQ(px_count(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS), 0);
    px_end();
}

static void test_pixie_probe_quiet_inside_the_silence(void) {
    /* One second short. Seen red by deleting `if (quiet < silence)
       continue;` from rule_wps_pixie_probe(). */
    px_begin(1700000000);
    px_probe_run(PB, SA, g_wall - 60);       /* M3 at wall - 59 */
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE), -1);
    px_end();
}

static void test_pixie_probe_ignores_an_online_brute(void) {
    /* An hour of silence after a run that sent M4 is not this rule's. */
    px_begin(1700000000);
    px_probe_run(PB, SA, g_wall - 3600);
    px_msg(PB, SA, WSC_MSG_M4, g_wall - 3599);
    px_feed(PB, SA, WSC_OP_NACK, WSC_MSG_NACK, g_wall - 3599);
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE), -1);
    px_end();
}

static void test_pixie_silence_is_tunable(void) {
    px_begin(1700000000);
    char err[128];
    ASSERT_EQ(tune_set("wps.pixie_silence_s=120", err, sizeof(err)), 0);
    px_probe_run(PB, SA, g_wall - 61);       /* 60 s quiet: below 120 */
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE), -1);
    g_wall += 60;                            /* 120 s quiet */
    px_update();
    int i = px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE);
    ASSERT(i >= 0);
    /* The detail names the live threshold, not the shipped one. */
    if (i >= 0) ASSERT(strstr(g_s.alerts[i].detail, ">= 120s") != NULL);
    px_end();
}

/* ── WPS_PIXIE_LIKELY_SUCCESS ────────────────────────────────── */

static void test_pixie_success_fires_on_a_later_full_run(void) {
    px_begin(1700000000);
    px_probe_run(PB, SA, g_wall - 7200);     /* M3 at wall - 7199 */
    px_full_run(PB, SB, g_wall - 20);        /* M7 at wall - 14 */
    px_update();
    int i = px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_CRIT);
        ASSERT_STR(g_s.alerts[i].key,
                   "wpspixieok:3c:84:6a:77:88:99:02:be:ef:00:00:02");
        /* Both runs are named, so an operator can judge the pairing. */
        ASSERT(strstr(g_s.alerts[i].detail, "02:be:ef:00:00:01") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "02:be:ef:00:00:02") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "7185s") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "not confirmed") != NULL);
    }
    /* The probing run also qualifies on its own (two hours quiet). */
    ASSERT(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE) >= 0);
    px_end();
}

static void test_pixie_success_needs_no_silence(void) {
    /* The tool reruns with the cracked PIN seconds later, from the
       same MAC: the probe rule cannot fire (2 s of quiet), and the
       success rule must not depend on it. */
    px_begin(1700000000);
    px_probe_run(PB, SA, g_wall - 30);       /* M3 at wall - 29 */
    px_full_run(PB, SA, g_wall - 27);        /* M1 re-arms 2 s later */
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE), -1);
    ASSERT(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS) >= 0);
    px_end();
}

static void test_pixie_success_respects_the_window(void) {
    /* One second past the 24 h look-back. Seen red by deleting the
       `> window` check from rule_wps_pixie_likely_success(). */
    px_begin(1700000000);
    time_t cred = g_wall - 10;               /* M7 lands here */
    px_probe_run(PB, SA, cred - WPS_PIXIE_SUCCESS_WINDOW_S - 2);
    px_full_run(PB, SB, cred - 6);
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS), -1);
    px_end();
}

static void test_pixie_success_window_is_tunable(void) {
    px_begin(1700000000);
    char err[128];
    ASSERT_EQ(tune_set("wps.pixie_success_window_s=3600", err, sizeof(err)), 0);
    px_probe_run(PB, SA, g_wall - 7200);
    px_full_run(PB, SB, g_wall - 20);
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS), -1);
    px_end();
}

static void test_pixie_success_ignores_an_abandon_after_the_completion(void) {
    /* Order matters: a run abandoned AFTER the registration completed
       cannot have produced its PIN. Seen red by deleting the
       `m3 >= cred_ts` check. */
    px_begin(1700000000);
    px_full_run(PB, SB, g_wall - 7200);
    px_probe_run(PB, SA, g_wall - 3600);
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS), -1);
    px_end();
}

static void test_pixie_success_does_not_cross_bssids(void) {
    /* Seen red by deleting the BSSID memcmp in the inner loop. */
    px_begin(1700000000);
    px_probe_run(PB2, SA, g_wall - 7200);
    px_full_run(PB, SB, g_wall - 20);
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS), -1);
    px_end();
}

static void test_pixie_success_silent_on_an_ordinary_enrolment(void) {
    /* A full registration with no abandoned run anywhere. Note what
       this cannot isolate: if the abandon guard in the inner loop were
       deleted, m3 stays 0 and the window check rejects it anyway, so
       mutating either guard alone leaves this green — the two guards
       are redundant for this case by construction, and only removing
       both turns it red (verified). */
    px_begin(1700000000);
    px_full_run(PB, SB, g_wall - 20);
    px_full_run(PB, SA, g_wall - 10);
    px_update();
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS), -1);
    ASSERT_EQ(px_find(&g_s, ALERT_TYPE_WPS_PIXIE_PROBE), -1);
    px_end();
}

/* ── --tune rows ─────────────────────────────────────────────── */

static void test_pixie_tune_rows_default_to_their_macros(void) {
    tune_reset();
    ASSERT_EQ((long long)tune_val(TUNE_WPS_PIXIE_SILENCE_S), WPS_PIXIE_SILENCE_S);
    ASSERT_EQ((long long)tune_val(TUNE_WPS_PIXIE_SUCCESS_WINDOW_S),
              WPS_PIXIE_SUCCESS_WINDOW_S);
    ASSERT_EQ(WPS_PIXIE_SILENCE_S, 60);           /* owner ruling */
    ASSERT_EQ(WPS_PIXIE_SUCCESS_WINDOW_S, 86400);
    ASSERT_STR(tune_spec(TUNE_WPS_PIXIE_SILENCE_S)->name, "wps.pixie_silence_s");
    ASSERT_STR(tune_spec(TUNE_WPS_PIXIE_SUCCESS_WINDOW_S)->name,
               "wps.pixie_success_window_s");
    char err[128];
    /* Zero silence would call M3 abandoned before M4 could arrive. */
    ASSERT_EQ(tune_set("wps.pixie_silence_s=0", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("wps.pixie_success_window_s=60", err, sizeof(err)), -1);
    ASSERT_EQ(tune_non_default(), 0);
    tune_reset();
}

/* ── Probe-response WSC walk ─────────────────────────────────── */

/* Element list of a probe response after its 12-octet fixed body
 * (IEEE 802.11-2020 §9.3.3.10): an SSID element, then the WSC vendor
 * element 221 / 00:50:F2 / type 4 whose body is WSC 2.0 §12 TLVs —
 * Version, WPS State = Configured, AP Setup Locked = 0 (unlocked), an
 * all-zero UUID-E, Manufacturer, Model Name, Serial Number, and Device
 * Password ID = 0x0004 (PBC). Returns the length written. */
static int px_wsc_ies(uint8_t *b) {
    int o = 0;
    b[o++] = 0x00; b[o++] = 4; memcpy(b + o, "wpsx", 4); o += 4;
    b[o++] = 0xDD;
    int lenpos = o++;
    b[o++] = 0x00; b[o++] = 0x50; b[o++] = 0xF2; b[o++] = 0x04;
    static const uint8_t attrs[] = {
        0x10, 0x4A, 0x00, 0x01, 0x10,                  /* Version 1.0    */
        0x10, 0x44, 0x00, 0x01, 0x02,                  /* State: Conf.   */
        0x10, 0x57, 0x00, 0x01, 0x00,                  /* Locked: no     */
        0x10, 0x47, 0x00, 0x10,                        /* UUID-E, 16 x 0 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x10, 0x21, 0x00, 0x04, 'A', 'c', 'm', 'e',    /* Manufacturer   */
        0x10, 0x23, 0x00, 0x05, 'R', 'X', '-', '1', '0', /* Model Name   */
        0x10, 0x42, 0x00, 0x03, 'S', 'N', '9',         /* Serial         */
        0x10, 0x12, 0x00, 0x02, 0x00, 0x04,            /* Dev Pwd ID PBC */
    };
    memcpy(b + o, attrs, sizeof(attrs));
    o += (int)sizeof(attrs);
    b[lenpos] = (uint8_t)(o - lenpos - 1);
    return o;
}

static const beacon_ap_t *px_ap(const uint8_t *bssid) {
    static sloth_state_t st;
    beacon_snapshot(&st);
    for (int i = 0; i < st.beacon_count; i++)
        if (memcmp(st.beacon_aps[i].bssid, bssid, 6) == 0)
            return &st.beacon_aps[i];
    return NULL;
}

static void px_beacon_locked(const uint8_t *bssid) {
    beacon_rsn_t rsn;
    memset(&rsn, 0, sizeof(rsn));
    rsn.has_wps    = 1;
    rsn.wps_state  = 2;
    rsn.wps_locked = 2;            /* the beacon says LOCKED */
    beacon_record(bssid, "wpsx", -50, 6, "WPA2", 100, &rsn);
}

static void test_probe_resp_wsc_merges_into_the_beaconing_ap(void) {
    beacon_clear();
    px_beacon_locked(PB);
    uint8_t ies[128];
    int n = px_wsc_ies(ies);
    ASSERT_EQ(beacon_note_probe_resp_ies(PB, ies, n, 1, 1700000000), 1);
    const beacon_ap_t *a = px_ap(PB);
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->wps_probe_resp_n, 1);
        ASSERT_STR(a->wps_manufacturer, "Acme");
        ASSERT_STR(a->wps_model_name, "RX-10");
        ASSERT_STR(a->wps_serial, "SN9");
        ASSERT((a->fp.flags & AP_FP_FLAG_WPS_UUID_ZERO) != 0);
        /* The probe response's AP Setup Locked went through the same
           transition ring the beacon path feeds: locked -> unlocked. */
        ASSERT_EQ(a->wps_locked, 1);
        ASSERT_EQ(a->wps_lock_n, 1);
        ASSERT_EQ(a->wps_lock_cycles, 1);
        /* Beacon-owned: the live PBC window is not opened by a unicast
           reply. Seen red by merging rsn.wps_device_pwd_id. */
        ASSERT_EQ((int)a->wps_device_pwd_id, 0);
        ASSERT_EQ((int)a->wps_config_methods, 0);
    }
    beacon_clear();
}

static void test_probe_resp_from_an_unknown_bssid_is_a_nop(void) {
    /* No entry is created and the AP that IS on file is untouched.
       Seen red by deleting the BSSID memcmp in
       beacon_note_probe_resp_ies(). */
    beacon_clear();
    px_beacon_locked(PB2);
    uint8_t ies[128];
    int n = px_wsc_ies(ies);
    ASSERT_EQ(beacon_note_probe_resp_ies(PB, ies, n, 1, 1700000000), 0);
    sloth_state_t *st = &g_s;
    memset(st, 0, sizeof(*st));
    beacon_snapshot(st);
    ASSERT_EQ(st->beacon_count, 1);
    const beacon_ap_t *a = px_ap(PB2);
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->wps_probe_resp_n, 0);
        ASSERT_STR(a->wps_manufacturer, "");
    }
    beacon_clear();
}

static void test_probe_resp_without_wsc_changes_nothing(void) {
    beacon_clear();
    px_beacon_locked(PB);
    uint8_t ies[] = { 0x00, 0x04, 'w', 'p', 's', 'x' };   /* SSID only */
    ASSERT_EQ(beacon_note_probe_resp_ies(PB, ies, (int)sizeof(ies), 1,
                                         1700000000), 0);
    const beacon_ap_t *a = px_ap(PB);
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->wps_probe_resp_n, 0);
    ASSERT_EQ(beacon_note_probe_resp_ies(PB, NULL, 4, 1, 1700000000), 0);
    ASSERT_EQ(beacon_note_probe_resp_ies(PB, ies, 0, 1, 1700000000), 0);
    beacon_clear();
}

/* ── [b] detail: WPS SESSIONS ────────────────────────────────── */

static char g_out[TEST_SCREEN_ROWS * (TEST_SCREEN_COLS + 1) * 4 + 1];

static void px_detail(sloth_state_t *s, const uint8_t bssid[6], int has_wps) {
    memset(s, 0, sizeof(*s));
    s->beacon_count = 1;
    beacon_ap_t *ap = &s->beacon_aps[0];
    memcpy(ap->bssid, bssid, 6);
    snprintf(ap->ssid, sizeof(ap->ssid), "wpsx");
    ap->has_wps     = has_wps;
    s->beacon_detail = 1;
    s->beacon_sel    = 0;
}

static void px_draw(const sloth_state_t *s) {
    tui_test_erase();
    view_beacon_draw(s);
    tui_test_screen(g_out, sizeof(g_out));
}

static void test_detail_renders_the_session_timeline(void) {
    px_begin(1700000000);
    beacon_clear();
    px_probe_run(PB, SA, g_wall - 91);        /* M3 at wall - 90 */
    px_detail(&g_s, PB, 1);
    g_s.beacon_aps[0].wps_probe_resp_n = 2;
    px_draw(&g_s);
    ASSERT(strstr(g_out, "WPS SESSIONS (1)") != NULL);
    ASSERT(strstr(g_out, "02:be:ef:00:00:01") != NULL);
    /* The M-strip shows the gap at M4. */
    ASSERT(strstr(g_out, "msgs 123.....") != NULL);
    ASSERT(strstr(g_out, "stopped after M3, no M4: quiet 90s/60s") != NULL);
    ASSERT(strstr(g_out, "WPS_PIXIE_PROBE") != NULL);
    /* The opcode timeline, oldest first. */
    ASSERT(strstr(g_out, "MSG M1") != NULL);
    ASSERT(strstr(g_out, "MSG M3") != NULL);
    ASSERT(strstr(g_out, "MSG M1") < strstr(g_out, "MSG M3"));
    ASSERT(strstr(g_out, "from 2 probe responses") != NULL);
    ASSERT(strstr(g_out, "reached the credentials") == NULL);
    px_end();
}

static void test_detail_marks_a_completed_run(void) {
    px_begin(1700000000);
    px_full_run(PB, SB, g_wall - 200);
    px_detail(&g_s, PB, 1);
    px_draw(&g_s);
    ASSERT(strstr(g_out, "msgs 12345678") != NULL);
    ASSERT(strstr(g_out, "reached the credentials (M7/M8/Done)") != NULL);
    ASSERT(strstr(g_out, "Done") != NULL);
    /* A finished run is not the Pixie shape. */
    ASSERT(strstr(g_out, "stopped after M3") == NULL);
    px_end();
}

static void test_detail_bounds_sessions_and_frames(void) {
    px_begin(1700000000);
    uint8_t sta[6] = { 0x02, 0xbe, 0xef, 0x00, 0x01, 0x00 };
    for (int k = 0; k < 5; k++) {            /* five sessions */
        sta[5] = (uint8_t)k;
        for (int j = 0; j < 10; j++)         /* ten frames each */
            px_msg(PB, sta, WSC_MSG_M2, g_wall - 100 + k * 10 + j);
    }
    px_detail(&g_s, PB, 1);
    px_draw(&g_s);
    ASSERT(strstr(g_out, "WPS SESSIONS (5)") != NULL);
    ASSERT(strstr(g_out, "... and 1 more session") != NULL);
    ASSERT(strstr(g_out, "(2 earlier frames not shown)") != NULL);
    px_end();
}

static void test_detail_says_when_no_exchange_was_heard(void) {
    px_begin(1700000000);
    px_detail(&g_s, PB, 1);
    px_draw(&g_s);
    ASSERT(strstr(g_out, "WPS SESSIONS (0)") != NULL);
    ASSERT(strstr(g_out, "no EAP-WSC registration heard") != NULL);
    px_end();
}

static void test_detail_block_absent_without_wps_or_sessions(void) {
    /* Seen red by deleting the `n == 0 && !ap->has_wps` early return. */
    px_begin(1700000000);
    px_msg(PB2, SA, WSC_MSG_M1, g_wall - 5);  /* another AP's session */
    px_detail(&g_s, PB, 0);
    px_draw(&g_s);
    ASSERT(strstr(g_out, "AP DETAIL") != NULL);
    ASSERT(strstr(g_out, "WPS SESSIONS") == NULL);
    px_end();
}

static void test_detail_shows_sessions_even_without_a_wps_ie(void) {
    /* The other term of the guard: an EAP-WSC exchange is evidence of
       WPS whatever the latest beacon advertised. */
    px_begin(1700000000);
    px_msg(PB, SA, WSC_MSG_M1, g_wall - 5);
    px_detail(&g_s, PB, 0);
    px_draw(&g_s);
    ASSERT(strstr(g_out, "WPS SESSIONS (1)") != NULL);
    px_end();
}

void run_wps_pixie_tests(void) {
    TEST_SUITE("wps pixie — per-attempt shape (#82)");
    RUN_TEST(test_m3_without_m4_is_the_shape);
    RUN_TEST(test_m4_in_the_attempt_is_not_the_shape);
    RUN_TEST(test_m3_heard_without_m1_is_not_the_shape);
    RUN_TEST(test_done_after_m3_is_not_abandoned);
    RUN_TEST(test_a_rearming_m1_closes_the_attempt_with_its_silence);
    RUN_TEST(test_cred_ts_is_the_first_credential_frame);
    RUN_TEST(test_event_ring_is_oldest_first_and_clamped);
    RUN_TEST(test_for_bssid_filters_and_orders_newest_first);

    TEST_SUITE("wps pixie — WPS_PIXIE_PROBE (#82)");
    RUN_TEST(test_pixie_probe_fires_after_the_silence);
    RUN_TEST(test_pixie_probe_quiet_inside_the_silence);
    RUN_TEST(test_pixie_probe_ignores_an_online_brute);
    RUN_TEST(test_pixie_silence_is_tunable);

    TEST_SUITE("wps pixie — WPS_PIXIE_LIKELY_SUCCESS (#82)");
    RUN_TEST(test_pixie_success_fires_on_a_later_full_run);
    RUN_TEST(test_pixie_success_needs_no_silence);
    RUN_TEST(test_pixie_success_respects_the_window);
    RUN_TEST(test_pixie_success_window_is_tunable);
    RUN_TEST(test_pixie_success_ignores_an_abandon_after_the_completion);
    RUN_TEST(test_pixie_success_does_not_cross_bssids);
    RUN_TEST(test_pixie_success_silent_on_an_ordinary_enrolment);
    RUN_TEST(test_pixie_tune_rows_default_to_their_macros);

    TEST_SUITE("wps pixie — probe-response WSC walk (#82)");
    RUN_TEST(test_probe_resp_wsc_merges_into_the_beaconing_ap);
    RUN_TEST(test_probe_resp_from_an_unknown_bssid_is_a_nop);
    RUN_TEST(test_probe_resp_without_wsc_changes_nothing);

    TEST_SUITE("wps pixie — [b] detail WPS SESSIONS (#82)");
    RUN_TEST(test_detail_renders_the_session_timeline);
    RUN_TEST(test_detail_marks_a_completed_run);
    RUN_TEST(test_detail_bounds_sessions_and_frames);
    RUN_TEST(test_detail_says_when_no_exchange_was_heard);
    RUN_TEST(test_detail_block_absent_without_wps_or_sessions);
    RUN_TEST(test_detail_shows_sessions_even_without_a_wps_ie);
}
