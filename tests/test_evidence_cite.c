/* Evidence citation beyond DEAUTH_FLOOD — issue #92 slice 4.
 *
 * Each wireless detector family that fires from monitor frames now
 * carries the evidence-ring event IDs of the frames behind its alert.
 * These tests pin the whole chain per family: hand-built frames (per
 * the IEEE 802.11-2020 clause each builder names) carrying a chosen
 * event ID reach the detector, the rule fires, the alert's
 * evidence_ids name exactly those frames, and the JSONL sink emits
 * them as evidence_id_N.
 *
 * The event IDs are seeded on the frame view (dot11_frame_t.event_id)
 * or passed to the *_ev entry points directly, the way on_probe_frame()
 * does after evidence_ring_note(). That the callback really stamps them
 * is pinned separately, through the real pcap_dispatch() path, in
 * tests/test_capture_path.c.
 *
 * Every rule here reads the wall clock through alerts_update(), so each
 * test pins it with sloth_clock_test_set() (8a7c8e3's second-boundary
 * flake is the reason).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "alerts.h"
#include "jsonl.h"
#include "dot11_frame.h"
#include "beacon_snoop.h"
#include "pm_forge.h"
#include "queue_evict.h"
#include "auth_track.h"
#include "assoc_track.h"
#include "action_snoop.h"
#include "ev_cite.h"
#include "tmp_dir.h"

TEST_STATE(g_s);

static time_t g_wall;
static time_t pinned_wall(void) { return g_wall; }

static void pin_wall(time_t t) {
    g_wall = t;
    sloth_clock_test_set(NULL, pinned_wall);
}

static int find_alert(const sloth_state_t *s, alert_type_t type) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) return i;
    return -1;
}

/* ── JSONL sink ─────────────────────────────────────────── */

static char g_jpath[TEST_TMP_MAX];

static void jsonl_fresh(void) {
    int fd = mkstemp(test_tmp_tpl(g_jpath, sizeof(g_jpath), "sloth_evcite_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_jpath);
    ASSERT(jsonl_open(g_jpath));
}

static char *jsonl_body(void) {
    jsonl_close();
    FILE *fp = fopen(g_jpath, "r");
    if (!fp) return NULL;
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    unlink(g_jpath);
    return buf;
}

/* The `alert` line (legacy record) with this dedup key, copied out so
 * the assertions below look at that one record and not a neighbour's —
 * two EVIL_TWIN alerts share a title. */
static int jsonl_alert_line(const char *body, const char *key,
                            char *out, size_t n) {
    char needle[ALERT_KEY_LEN + 16];
    snprintf(needle, sizeof(needle), "\"key\":\"%s\"", key);
    const char *p = body;
    while ((p = strstr(p, "\"type\":\"alert\"")) != NULL) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len < n) {
            memcpy(out, p, len);
            out[len] = '\0';
            if (strstr(out, needle)) return 1;
        }
        p += len;
    }
    return 0;
}

/* Asserts that the alert names `ids[0..n)`, in order and nothing else,
 * and that its JSONL record says the same. */
static void assert_cites(const alert_t *a, const char *body,
                         const uint64_t *ids, int n) {
    ASSERT_EQ((int)a->evidence_id_count, n);
    for (int i = 0; i < n && i < ALERT_EVIDENCE_IDS; i++)
        ASSERT_EQ((long long)a->evidence_ids[i], (long long)ids[i]);
    if (n < ALERT_EVIDENCE_IDS)
        ASSERT_EQ((long long)a->evidence_ids[n], 0LL);

    ASSERT(body != NULL);
    if (!body) return;
    char line[4096];
    ASSERT(jsonl_alert_line(body, a->key, line, sizeof(line)));
    char kv[64];
    snprintf(kv, sizeof(kv), "\"evidence_count\":%d", n);
    ASSERT(strstr(line, kv) != NULL);
    for (int i = 0; i < n; i++) {
        snprintf(kv, sizeof(kv), "\"evidence_id_%d\":%llu", i,
                 (unsigned long long)ids[i]);
        ASSERT(strstr(line, kv) != NULL);
    }
    snprintf(kv, sizeof(kv), "\"evidence_id_%d\"", n);
    ASSERT(strstr(line, kv) == NULL);
}

/* Decode a hand-built frame and stamp it the way on_probe_frame() does
 * after evidence_ring_note(). */
static dot11_frame_t view_of(const uint8_t *f, int len, uint64_t event_id) {
    dot11_frame_t v;
    dot11_frame_decode(f, len, NULL, &v);
    v.event_id = event_id;
    return v;
}

/* ── PM-bit forgery (#107 shape A) ──────────────────────── */

/* STA -> AP data header (IEEE 802.11-2020 §9.3.2.1, Table 9-26: ToDS=1,
 * A1 = BSSID, A2 = SA). PwrMgt is FC B12 (§9.2.4.1.7). A QoS subtype
 * carries QoS Control at offset 24 with the TID in B0-B3 (§9.2.4.5). */
static int sta_frame(uint8_t *f, int sub, int pm, const uint8_t bssid[6],
                     const uint8_t sta[6], int tid, int seq) {
    memset(f, 0, 26);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0));
    memcpy(f + 4,  bssid, 6);
    memcpy(f + 10, sta,   6);
    memcpy(f + 16, bssid, 6);
    f[22] = (uint8_t)((seq & 0x0f) << 4);
    f[23] = (uint8_t)((seq >> 4) & 0xff);
    if (sub & 0x08) { f[24] = (uint8_t)(tid & 0x0f); return 26; }
    return 24;
}

static void test_pm_forge_alert_cites_the_contradicting_pair(void) {
    pin_wall(1000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t STA[6]   = {0x02,0xaa,0x00,0x00,0x00,0x01};
    beacon_record(BSSID, "Net", -50, 6, "WPA2", 100, NULL);

    uint8_t f[26]; int len; dot11_frame_t v;
    /* An unrelated PM=0 frame first: it is not part of the pair and
       must not be cited. */
    len = sta_frame(f, 0x8, 0, BSSID, STA, 5, 1);
    v = view_of(f, len, 700);
    pm_forge_observe_frame(&v, 999, 0);
    /* The sleep declaration (QoS-Null, PM=1, TID 0)... */
    len = sta_frame(f, 0xC, 1, BSSID, STA, 0, 2);
    v = view_of(f, len, 701);
    pm_forge_observe_frame(&v, 1000, 0);
    /* ...and the awake data frame on TID 5, 50 ms later. */
    len = sta_frame(f, 0x8, 0, BSSID, STA, 5, 3);
    v = view_of(f, len, 702);
    pm_forge_observe_frame(&v, 1000, 50000);

    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 701, 702 };
        assert_cites(&g_s.alerts[i], body, want, 2);
    }
}

/* A second contradiction against the same sleep declaration cites the
 * new data frame and not the Null twice — the dedup in ev_cite_push().
 * The re-push moves the Null to its newest use, just before 803. */
static void test_pm_forge_shared_null_is_cited_once(void) {
    pin_wall(1000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x11,0x22,0x33,0x44,0x56};
    static const uint8_t STA[6]   = {0x02,0xaa,0x00,0x00,0x00,0x02};
    beacon_record(BSSID, "Net", -50, 6, "WPA2", 100, NULL);

    uint8_t f[26]; int len; dot11_frame_t v;
    len = sta_frame(f, 0xC, 1, BSSID, STA, 0, 1);
    v = view_of(f, len, 801);
    pm_forge_observe_frame(&v, 1000, 0);
    len = sta_frame(f, 0x8, 0, BSSID, STA, 5, 2);
    v = view_of(f, len, 802);
    pm_forge_observe_frame(&v, 1000, 20000);
    len = sta_frame(f, 0x8, 0, BSSID, STA, 6, 3);
    v = view_of(f, len, 803);
    pm_forge_observe_frame(&v, 1000, 40000);

    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 802, 801, 803 };
        assert_cites(&g_s.alerts[i], body, want, 3);
    }
}

/* The Framing Frames shape over a longer run: one spoofed sleep
 * declaration, then the real station keeps transmitting. Every
 * contradiction re-pushes the same Null; without ev_cite_push() moving
 * it to newest, the Null is the oldest entry and the eighth
 * contradiction evicts it, leaving eight PM=0 frames — none of which is
 * a finding on its own. */
static void test_pm_forge_long_run_keeps_the_sleep_declaration(void) {
    pin_wall(1000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    pm_forge_clear();
    static const uint8_t BSSID[6] = {0x00,0x11,0x22,0x33,0x44,0x57};
    static const uint8_t STA[6]   = {0x02,0xaa,0x00,0x00,0x00,0x03};
    beacon_record(BSSID, "Net", -50, 6, "WPA2", 100, NULL);

    uint8_t f[26]; int len; dot11_frame_t v;
    len = sta_frame(f, 0xC, 1, BSSID, STA, 0, 1);
    v = view_of(f, len, 901);
    pm_forge_observe_frame(&v, 1000, 0);
    /* Eight QoS data frames on TID 5, 5..40 ms later: all inside the
       100 ms beacon interval, each one a contradiction of 901. */
    for (int k = 0; k < 8; k++) {
        len = sta_frame(f, 0x8, 0, BSSID, STA, 5, 2 + k);
        v = view_of(f, len, (uint64_t)(910 + k));
        pm_forge_observe_frame(&v, 1000, (long)(k + 1) * 5000);
    }

    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) {
        /* The Null sits where its newest contradiction put it: just
           before 917. 910, the oldest data frame, is the one evicted. */
        static const uint64_t want[] = { 911, 912, 913, 914,
                                         915, 916, 901, 917 };
        assert_cites(&g_s.alerts[i], body, want, 8);
    }
    pm_forge_clear();
}

/* ── Queued-frame release (#107 shape B) ────────────────── */

/* AP -> STA QoS data: FromDS=1, A1 = DA, A2 = BSSID (Table 9-26). */
static int downlink(uint8_t *f, const uint8_t bssid[6], const uint8_t sta[6],
                    int seq, int retry) {
    memset(f, 0, 26);
    f[0] = (uint8_t)((0x8 << 4) | (2 << 2));
    f[1] = (uint8_t)(0x02 | (retry ? 0x08 : 0));
    memcpy(f + 4,  sta,   6);
    memcpy(f + 10, bssid, 6);
    memcpy(f + 16, bssid, 6);
    f[22] = (uint8_t)((seq & 0x0f) << 4);
    f[23] = (uint8_t)((seq >> 4) & 0xff);
    return 26;
}

static void test_queue_evict_alert_cites_session_change_and_burst(void) {
    pin_wall(1003);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x11,0x22,0x33,0x44,0x11};
    static const uint8_t STA[6]   = {0x02,0xa1,0x00,0x00,0x00,0x01};

    /* The reassociation response that opened the window (event 900),
       then four distinct downlink frames inside it, plus a repeat of the
       second. The repeat has its Retry bit CLEAR — a driver that rebuilt
       the frame — so only the sequence-number filter stands between it
       and a citation; with Retry set the early return would catch it
       first and this case could not tell the two guards apart. */
    queue_evict_note_session_change_ev(BSSID, STA, QUEUE_EVICT_SRC_REASSOC,
                                       1002, 0, 900);
    uint8_t f[26]; int len; dot11_frame_t v;
    len = downlink(f, BSSID, STA, 200, 0);
    v = view_of(f, len, 901); queue_evict_observe_downlink_frame(&v, 1002, 10000);
    len = downlink(f, BSSID, STA, 201, 0);
    v = view_of(f, len, 902); queue_evict_observe_downlink_frame(&v, 1002, 20000);
    len = downlink(f, BSSID, STA, 201, 0);
    v = view_of(f, len, 903); queue_evict_observe_downlink_frame(&v, 1002, 25000);
    len = downlink(f, BSSID, STA, 202, 0);
    v = view_of(f, len, 904); queue_evict_observe_downlink_frame(&v, 1002, 30000);
    len = downlink(f, BSSID, STA, 203, 0);
    v = view_of(f, len, 905); queue_evict_observe_downlink_frame(&v, 1002, 40000);

    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_QUEUE_EVICT);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 900, 901, 902, 904, 905 };
        assert_cites(&g_s.alerts[i], body, want, 5);
        /* Uncorroborated: the confidence ladder survived the switch to
           fire_inv(). */
        ASSERT_EQ((int)g_s.alerts[i].confidence, 25);
    }
}

/* A later session change with one stray frame is not a release, and
 * must not take the reported release's citations away. */
static void test_queue_evict_later_change_keeps_release_citations(void) {
    pin_wall(1003);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x11,0x22,0x33,0x44,0x12};
    static const uint8_t STA[6]   = {0x02,0xa1,0x00,0x00,0x00,0x02};

    queue_evict_note_session_change_ev(BSSID, STA, QUEUE_EVICT_SRC_ASSOC,
                                       1002, 0, 910);
    uint8_t f[26]; int len; dot11_frame_t v;
    for (int k = 0; k < 3; k++) {
        len = downlink(f, BSSID, STA, 300 + k, 0);
        v = view_of(f, len, (uint64_t)(911 + k));
        queue_evict_observe_downlink_frame(&v, 1002, (long)(10 + k) * 1000);
    }
    queue_evict_note_session_change_ev(BSSID, STA, QUEUE_EVICT_SRC_DISCONNECT,
                                       1002, 500000, 920);
    len = downlink(f, BSSID, STA, 400, 0);
    v = view_of(f, len, 921);
    queue_evict_observe_downlink_frame(&v, 1002, 510000);

    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_QUEUE_EVICT);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 910, 911, 912, 913 };
        assert_cites(&g_s.alerts[i], body, want, 4);
    }
}

/* ── Management-frame floods and the Action-frame detectors ── */

/* A management header (IEEE 802.11-2020 §9.3.3.1): FC, Duration,
 * A1 = DA, A2 = SA, A3 = BSSID, Sequence Control. */
static int mgmt_hdr(uint8_t *f, int subtype, const uint8_t a1[6],
                    const uint8_t a2[6], const uint8_t a3[6], int seq) {
    memset(f, 0, 24);
    f[0] = (uint8_t)(subtype << 4);          /* type 0, protocol 0 */
    memcpy(f + 4,  a1, 6);
    memcpy(f + 10, a2, 6);
    memcpy(f + 16, a3, 6);
    f[22] = (uint8_t)((seq & 0x0f) << 4);
    f[23] = (uint8_t)((seq >> 4) & 0xff);
    return 24;
}

static void test_auth_flood_alert_cites_the_newest_counted_frames(void) {
    pin_wall(5000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x55,0x01};
    static const uint8_t OTHER[6] = {0x00,0x22,0x33,0x44,0x55,0x02};
    /* 32 auth frames at one AP inside the 5 s window, with one frame to
       a different AP in among the newest — it is not this flood's
       evidence. auth_observe_ev() is the call on_probe_frame() makes for
       an Authentication frame (subtype 11), with addr3 as the BSSID. */
    for (int i = 0; i < 32; i++) {
        auth_observe_ev(BSSID, 4998 + i / 16, (uint64_t)(1001 + i));
        if (i == 28) auth_observe_ev(OTHER, 4999, 9999);
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_AUTH_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 1025, 1026, 1027, 1028,
                                         1029, 1030, 1031, 1032 };
        assert_cites(&g_s.alerts[i], body, want, 8);
    }
}

/* (Re)Association Request (§9.3.3.6): Capability Information, Listen
 * Interval, then an SSID element. */
static int assoc_req(uint8_t *f, const uint8_t bssid[6], const uint8_t sta[6],
                     int seq) {
    int n = mgmt_hdr(f, 0, bssid, sta, bssid, seq);
    f[n++] = 0x31; f[n++] = 0x04;            /* capabilities */
    f[n++] = 0x0a; f[n++] = 0x00;            /* listen interval */
    f[n++] = 0x00; f[n++] = 3;               /* SSID element */
    memcpy(f + n, "net", 3); n += 3;
    return n;
}

static void test_assoc_flood_alert_cites_the_newest_requests(void) {
    pin_wall(6000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x66,0x01};
    static const uint8_t OTHER[6] = {0x00,0x22,0x33,0x44,0x66,0x02};
    uint8_t f[64];
    for (int i = 0; i < 24; i++) {
        uint8_t sta[6] = {0x02,0x10,0x00,0x00,0x00,(uint8_t)i};
        int len = assoc_req(f, BSSID, sta, i);
        dot11_frame_t v = view_of(f, len, (uint64_t)(2001 + i));
        assoc_req_t req;
        ASSERT(assoc_request_parse_frame(&v, &req));
        assoc_request_observe(&req, -40, 6);
        if (i == 20) {
            len = assoc_req(f, OTHER, sta, 99);
            v = view_of(f, len, 9998);
            if (assoc_request_parse_frame(&v, &req))
                assoc_request_observe(&req, -40, 6);
        }
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_ASSOC_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 2017, 2018, 2019, 2020,
                                         2021, 2022, 2023, 2024 };
        assert_cites(&g_s.alerts[i], body, want, 8);
    }
}

/* WNM BSS Transition Management Request (§9.6.13.9): Category 10,
 * Action 7, Dialog Token, Request Mode, Disassociation Timer (2),
 * Validity Interval. AP -> STA, so A1 = the station. */
static int btm_req(uint8_t *f, const uint8_t bssid[6], const uint8_t sta[6],
                   int mode, int seq) {
    int n = mgmt_hdr(f, 13, sta, bssid, bssid, seq);
    f[n++] = 10; f[n++] = 7; f[n++] = (uint8_t)seq;
    f[n++] = (uint8_t)mode;
    f[n++] = 0x0a; f[n++] = 0x00;
    f[n++] = 0xff;
    return n;
}

static void test_btm_abuse_alert_cites_only_the_imminent_requests(void) {
    pin_wall(7000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x77,0x01};
    static const uint8_t STA[6]   = {0x02,0x20,0x00,0x00,0x00,0x01};
    uint8_t f[64];
    for (int i = 0; i < 4; i++) {
        int len = btm_req(f, BSSID, STA, BTM_REQ_DISASSOC_IMM, i);
        dot11_frame_t v = view_of(f, len, (uint64_t)(3001 + i));
        action_observe_frame(&v, 6990 + i);
        if (i == 2) {
            /* An ordinary steer, no Disassociation Imminent: counted in
               the total, never toward the threshold, so not evidence. */
            len = btm_req(f, BSSID, STA, BTM_REQ_PREF_CANDIDATE, 50);
            v = view_of(f, len, 3100);
            action_observe_frame(&v, 6993);
        }
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 3001, 3002, 3003, 3004 };
        assert_cites(&g_s.alerts[i], body, want, 4);
    }
}

/* SA Query Request (§9.6.9): Category 8, Action 0, Transaction ID (2).
 * Sent by the AP, so A1 = the station and A2 = A3 = the BSSID. */
static int saq_frame(uint8_t *f, const uint8_t bssid[6], const uint8_t sta[6],
                     int seq) {
    int n = mgmt_hdr(f, 13, sta, bssid, bssid, seq);
    f[n++] = 8; f[n++] = 0;
    f[n++] = (uint8_t)seq; f[n++] = 0x00;
    return n;
}

static void test_sa_query_flood_alert_cites_the_pairs_frames(void) {
    pin_wall(8000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x88,0x01};
    static const uint8_t STA[6]   = {0x02,0x30,0x00,0x00,0x00,0x01};
    static const uint8_t STA2[6]  = {0x02,0x30,0x00,0x00,0x00,0x02};
    uint8_t f[64];
    /* The same AP querying another station is another pair, and it is
       heard FIRST so its row is the one a lookup that ignored the pair
       would land on. */
    int len = saq_frame(f, BSSID, STA2, 60);
    dot11_frame_t v = view_of(f, len, 4500);
    action_observe_frame(&v, 7995);
    for (int i = 0; i < 12; i++) {
        len = saq_frame(f, BSSID, STA, i);
        v = view_of(f, len, (uint64_t)(4001 + i));
        action_observe_frame(&v, 7995 + i / 4);
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_SA_QUERY_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 4005, 4006, 4007, 4008,
                                         4009, 4010, 4011, 4012 };
        assert_cites(&g_s.alerts[i], body, want, 8);
    }
}

/* ── The window test in the four flood citation queries ──────
 *
 * The walk collects up to ALERT_EVIDENCE_IDS ids, newest first, so once
 * eight in-window frames carry an id it never reaches anything older
 * and the window test is invisible. It matters when fewer do — the
 * evidence ring retained nothing for most of the burst (ring down, or
 * frames dropped), or the threshold is below eight — because the walk
 * then reaches back into stale entries from an earlier burst at the
 * same key. Each test below seeds that: frames with ids from OUTSIDE
 * the window, then an in-window burst that is enough to fire but
 * carries few ids. Only the in-window ids may be cited. */

static void test_auth_flood_never_cites_a_frame_outside_the_window(void) {
    pin_wall(15000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    auth_clear();
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x55,0x11};
    /* An earlier burst at the same AP, 10 s ago — outside the 5 s
       window, so not counted and not evidence. */
    for (int k = 0; k < 3; k++)
        auth_observe_ev(BSSID, 14990, (uint64_t)(1501 + k));
    /* 32 frames in the window; the ring kept only the last three. */
    for (int k = 0; k < 32; k++)
        auth_observe_ev(BSSID, 14999,
                        k >= 29 ? (uint64_t)(1601 + (k - 29)) : 0);
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_AUTH_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 1601, 1602, 1603 };
        assert_cites(&g_s.alerts[i], body, want, 3);
    }
    auth_clear();
}

static void test_btm_abuse_never_cites_a_request_outside_the_window(void) {
    pin_wall(17000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    btm_clear();
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x77,0x11};
    static const uint8_t STA[6]   = {0x02,0x20,0x00,0x00,0x00,0x11};
    uint8_t f[64];
    /* Two Disassociation-Imminent requests to the same pair 100 s ago,
       outside the 60 s window. The threshold is four, so the in-window
       burst alone never fills the eight slots. */
    for (int k = 0; k < 2; k++) {
        int len = btm_req(f, BSSID, STA, BTM_REQ_DISASSOC_IMM, 70 + k);
        dot11_frame_t v = view_of(f, len, (uint64_t)(3501 + k));
        action_observe_frame(&v, 16900);
    }
    for (int k = 0; k < 4; k++) {
        int len = btm_req(f, BSSID, STA, BTM_REQ_DISASSOC_IMM, 80 + k);
        dot11_frame_t v = view_of(f, len, (uint64_t)(3601 + k));
        action_observe_frame(&v, 16990 + k);
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_BTM_ABUSE);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 3601, 3602, 3603, 3604 };
        assert_cites(&g_s.alerts[i], body, want, 4);
    }
    btm_clear();
}

static void test_sa_query_flood_never_cites_a_frame_outside_the_window(void) {
    pin_wall(18000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    saq_clear();
    static const uint8_t BSSID[6] = {0x00,0x22,0x33,0x44,0x88,0x11};
    static const uint8_t STA[6]   = {0x02,0x30,0x00,0x00,0x00,0x11};
    uint8_t f[64];
    /* Same pair, 20 s ago: outside the 10 s window. */
    for (int k = 0; k < 3; k++) {
        int len = saq_frame(f, BSSID, STA, 90 + k);
        dot11_frame_t v = view_of(f, len, (uint64_t)(4501 + k));
        action_observe_frame(&v, 17980);
    }
    /* Twelve in the window, the threshold; only the last two have ids. */
    for (int k = 0; k < 12; k++) {
        int len = saq_frame(f, BSSID, STA, 100 + k);
        dot11_frame_t v = view_of(f, len,
                                  k >= 10 ? (uint64_t)(4601 + (k - 10)) : 0);
        action_observe_frame(&v, 17995);
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_SA_QUERY_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 4601, 4602 };
        assert_cites(&g_s.alerts[i], body, want, 2);
    }
    saq_clear();
}

/* ── Beacon-sourced rules ─────────────────────────────────── */

/* beacon_record_ev() is the call on_probe_frame() makes for every
 * beacon beacon_parse_frame() accepts, with the frame's evidence-ring
 * id; these seed it directly. The beacon parser itself is pinned
 * against hand-built frames in tests/test_beacon_snoop.c, and the
 * callback's stamp in tests/test_capture_path.c. */
static void beacon_ev(const uint8_t bssid[6], const char *ssid,
                      const char *enc, uint64_t id) {
    beacon_record_ev(bssid, ssid, -50, 6, enc, 100, NULL, id);
}

static int find_alert_key(const sloth_state_t *s, alert_type_t type,
                          const char *prefix) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type &&
            strncmp(s->alerts[i].key, prefix, strlen(prefix)) == 0)
            return i;
    return -1;
}

static void test_beacon_flood_alert_cites_each_new_bssids_first_beacon(void) {
    pin_wall(9000);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t OLD[6] = {0x00,0x33,0x00,0x00,0x00,0xff};
    beacon_ev(OLD, "Home", "WPA2", 5000);
    for (int i = 0; i < 45; i++) {
        uint8_t b[6] = {0x02,0x33,0x00,0x00,0x00,(uint8_t)i};
        beacon_ev(b, "flood", "OPEN", (uint64_t)(5001 + i));
        /* A known AP beaconing again is not a new BSSID, so it is not
           the flood's evidence even when it lands among the newest. */
        if (i == 41) beacon_ev(OLD, "Home", "WPA2", 5900);
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_BEACON_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 5038, 5039, 5040, 5041,
                                         5042, 5043, 5044, 5045 };
        assert_cites(&g_s.alerts[i], body, want, 8);
    }
}

/* The fourth window test (see the block above the beacon section). */
static void test_beacon_flood_never_cites_a_bssid_outside_the_window(void) {
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    beacon_clear();
    /* Three BSSIDs first heard 20 s ago, outside the 10 s window.
       beacon_record_ev() stamps arrivals from the wall clock. */
    pin_wall(19980);
    for (int k = 0; k < 3; k++) {
        uint8_t b[6] = {0x02,0x3a,0x00,0x00,0x00,(uint8_t)k};
        beacon_ev(b, "stale", "OPEN", (uint64_t)(5501 + k));
    }
    /* 45 new BSSIDs now; the ring kept only the last two. */
    pin_wall(20000);
    for (int k = 0; k < 45; k++) {
        uint8_t b[6] = {0x02,0x3b,0x00,0x00,0x00,(uint8_t)k};
        beacon_ev(b, "flood", "OPEN",
                  k >= 43 ? (uint64_t)(5601 + (k - 43)) : 0);
    }
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_BEACON_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 5601, 5602 };
        assert_cites(&g_s.alerts[i], body, want, 2);
    }
    beacon_clear();
}

/* Weak/strong twin: an OPEN clone of a WPA2 SSID. Each half's newest
 * BEACON_EVIDENCE_IDS beacons, the accused (weak) half first. */
static void test_evil_twin_alert_cites_both_halves_beacons(void) {
    pin_wall(9100);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t WEAK[6]   = {0x02,0x44,0x00,0x00,0x00,0x01};
    static const uint8_t STRONG[6] = {0x00,0x44,0x00,0x00,0x00,0x02};
    static const uint8_t OTHER[6]  = {0x00,0x44,0x00,0x00,0x00,0x03};
    for (int k = 0; k < 5; k++) {
        beacon_ev(WEAK, "Corp", "OPEN", (uint64_t)(6001 + k));
        /* A third AP under another name beacons in between. */
        beacon_ev(OTHER, "Guest", "WPA2", (uint64_t)(6201 + k));
    }
    for (int k = 0; k < 3; k++)
        beacon_ev(STRONG, "Corp", "WPA2", (uint64_t)(6101 + k));
    beacon_snapshot(&g_s);
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert_key(&g_s, ALERT_TYPE_EVIL_TWIN, "twin:");
    ASSERT(i >= 0);
    if (i >= 0) {
        /* 6001 is the weak half's fifth-newest beacon: past its ring. */
        static const uint64_t want[] = { 6002, 6003, 6004, 6005,
                                         6101, 6102, 6103 };
        assert_cites(&g_s.alerts[i], body, want, 7);
    }
}

/* Same-security twin, same SSID and cipher, different vendor OUI.
 * Nothing in this pair decides which half is the impostor (no
 * inventory, no taint, no tool OUI), so the citation takes the
 * canonical order: the lower BSSID's beacons first. The higher BSSID is
 * given the stronger signal, so the snapshot's signal sort walks from
 * it — a rule citing (a, b) as it walked would put 6401 first. */
static void test_same_security_twin_alert_cites_lower_bssid_first(void) {
    pin_wall(9200);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    beacon_clear();
    static const uint8_t A[6] = {0x00,0x55,0x00,0x00,0x00,0x01};
    static const uint8_t B[6] = {0x00,0x66,0x00,0x00,0x00,0x02};
    beacon_record_ev(A, "Corp", -70, 6, "WPA2", 100, NULL, 6301);
    beacon_record_ev(A, "Corp", -70, 6, "WPA2", 100, NULL, 6302);
    beacon_record_ev(B, "Corp", -40, 6, "WPA2", 100, NULL, 6401);
    beacon_snapshot(&g_s);
    ASSERT(g_s.beacon_count == 2 &&
           memcmp(g_s.beacon_aps[0].bssid, B, 6) == 0);
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert_key(&g_s, ALERT_TYPE_EVIL_TWIN, "twin-fp:");
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 6301, 6302, 6401 };
        assert_cites(&g_s.alerts[i], body, want, 3);
    }
    beacon_clear();
}

/* When twin_choose_sides() does decide — here, one half is an Espressif
 * OUI (24:0a:c4, src/wifi_oui_attacker.c), the ESP32 tooling the
 * ladder ranks as the impostor — that half is cited first. It is the
 * HIGHER BSSID and the weaker signal, so neither lo/hi order nor the
 * walk order would put it first. */
static void test_same_security_twin_alert_cites_the_accused_half_first(void) {
    pin_wall(9250);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    beacon_clear();
    static const uint8_t REAL[6] = {0x00,0x55,0x00,0x00,0x00,0x03};
    static const uint8_t TOOL[6] = {0x24,0x0a,0xc4,0x00,0x00,0x04};
    beacon_record_ev(REAL, "Corp", -40, 6, "WPA2", 100, NULL, 6501);
    beacon_record_ev(REAL, "Corp", -40, 6, "WPA2", 100, NULL, 6502);
    beacon_record_ev(TOOL, "Corp", -70, 6, "WPA2", 100, NULL, 6601);
    beacon_snapshot(&g_s);
    ASSERT(g_s.beacon_count == 2 &&
           memcmp(g_s.beacon_aps[0].bssid, REAL, 6) == 0);
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert_key(&g_s, ALERT_TYPE_EVIL_TWIN, "twin-fp:");
    ASSERT(i >= 0);
    if (i >= 0) {
        static const uint64_t want[] = { 6601, 6501, 6502 };
        assert_cites(&g_s.alerts[i], body, want, 3);
    }
    beacon_clear();
}

/* Attack chain: the deauth flood against the real AP plus the twin's
 * beacons — both observations the conclusion rests on. */
static void test_twin_chain_alert_cites_twin_beacons_and_the_flood(void) {
    pin_wall(9300);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t REAL[6] = {0x00,0x77,0x00,0x00,0x00,0x01};
    static const uint8_t TWIN[6] = {0x00,0x88,0x00,0x00,0x00,0x02};
    static const uint8_t STA[6]  = {0x02,0x77,0x00,0x00,0x00,0x09};
    beacon_ev(REAL, "Corp", "WPA2", 7201);
    beacon_ev(TWIN, "Corp", "WPA2", 7101);
    beacon_ev(TWIN, "Corp", "WPA2", 7102);
    beacon_snapshot(&g_s);
    deauth_victim_t *v = &g_s.deauth_victims[g_s.deauth_victim_count++];
    memcpy(v->bssid,  REAL, 6);
    memcpy(v->victim, STA,  6);
    v->flood = 1; v->flood_last = 9300; v->frames = 30; v->peak_win = 30;
    for (int k = 0; k < 8; k++) v->evidence_ids[k] = (uint64_t)(7001 + k);
    v->evidence_id_count = 8;
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert_key(&g_s, ALERT_TYPE_EVIL_TWIN, "twin-chain:");
    ASSERT(i >= 0);
    if (i >= 0) {
        /* Two twin beacons, then the newest six of the eight flood
           frames — the real AP's beacon is not the chain's evidence. */
        static const uint64_t want[] = { 7101, 7102, 7003, 7004,
                                         7005, 7006, 7007, 7008 };
        assert_cites(&g_s.alerts[i], body, want, 8);
    }
}

/* KARMA: one frame per distinct SSID — the newest one carrying it, so
 * on a long-lived AP the citation is a frame the FIFO evidence ring
 * still holds rather than the AP's first beacon. A repeat moves that
 * SSID's citation forward and adds no second one; a repeat with no id
 * (the ring retained nothing) keeps the older id. */
static void test_karma_alert_cites_the_newest_frame_of_each_distinct_ssid(void) {
    pin_wall(9400);
    jsonl_fresh();
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t K[6] = {0x02,0x99,0x00,0x00,0x00,0x01};
    beacon_ev(K, "alpha",   "OPEN", 8001);
    beacon_ev(K, "bravo",   "OPEN", 8002);
    beacon_ev(K, "alpha",   "OPEN", 8010);
    beacon_ev(K, "charlie", "OPEN", 8003);
    beacon_ev(K, "charlie", "OPEN", 8011);
    beacon_ev(K, "delta",   "OPEN", 8004);
    beacon_ev(K, "delta",   "OPEN", 8012);
    beacon_ev(K, "bravo",   "OPEN", 0);
    beacon_snapshot(&g_s);
    alerts_update(&g_s);
    char *body = jsonl_body();
    int i = find_alert(&g_s, ALERT_TYPE_KARMA_AP);
    ASSERT(i >= 0);
    if (i >= 0) {
        /* ssid_history[] order: alpha, bravo, charlie, delta. */
        static const uint64_t want[] = { 8010, 8002, 8011, 8012 };
        assert_cites(&g_s.alerts[i], body, want, 4);
    }
}

/* ── ev_cite ring ───────────────────────────────────────── */

static void test_ev_cite_keeps_newest_oldest_first(void) {
    uint64_t ids[4] = {0};
    uint8_t n = 0, head = 0;
    for (uint64_t id = 1; id <= 6; id++)
        ev_cite_push(ids, 4, &n, &head, id);
    ev_cite_push(ids, 4, &n, &head, 0);      /* never stored */
    ev_cite_push(ids, 4, &n, &head, 6);      /* already held */
    uint64_t out[8];
    int k = ev_cite_flatten(ids, 4, n, head, out, 8);
    ASSERT_EQ(k, 4);
    ASSERT_EQ((long long)out[0], 3LL);
    ASSERT_EQ((long long)out[3], 6LL);
    /* Fewer slots than held: the newest two. */
    k = ev_cite_flatten(ids, 4, n, head, out, 2);
    ASSERT_EQ(k, 2);
    ASSERT_EQ((long long)out[0], 5LL);
    ASSERT_EQ((long long)out[1], 6LL);
}

/* An id already held moves to newest instead of staying where it was
 * first pushed — before the ring has filled and after it has wrapped. */
static void test_ev_cite_repush_moves_an_id_to_newest(void) {
    uint64_t ids[4] = {0};
    uint8_t n = 0, head = 0;
    uint64_t out[4];
    ev_cite_push(ids, 4, &n, &head, 1);
    ev_cite_push(ids, 4, &n, &head, 2);
    ev_cite_push(ids, 4, &n, &head, 3);
    ev_cite_push(ids, 4, &n, &head, 1);      /* not full yet */
    int k = ev_cite_flatten(ids, 4, n, head, out, 4);
    ASSERT_EQ(k, 3);
    ASSERT_EQ((long long)out[0], 2LL);
    ASSERT_EQ((long long)out[1], 3LL);
    ASSERT_EQ((long long)out[2], 1LL);
    ev_cite_push(ids, 4, &n, &head, 4);      /* fills: 2 3 1 4 */
    ev_cite_push(ids, 4, &n, &head, 5);      /* wraps: 3 1 4 5 */
    ev_cite_push(ids, 4, &n, &head, 1);      /* moves: 3 4 5 1 */
    k = ev_cite_flatten(ids, 4, n, head, out, 4);
    ASSERT_EQ(k, 4);
    ASSERT_EQ((long long)out[0], 3LL);
    ASSERT_EQ((long long)out[1], 4LL);
    ASSERT_EQ((long long)out[2], 5LL);
    ASSERT_EQ((long long)out[3], 1LL);
    /* And the move did not make room: the next push still evicts 3. */
    ev_cite_push(ids, 4, &n, &head, 6);
    k = ev_cite_flatten(ids, 4, n, head, out, 4);
    ASSERT_EQ(k, 4);
    ASSERT_EQ((long long)out[0], 4LL);
    ASSERT_EQ((long long)out[3], 6LL);
}

void run_evidence_cite_tests(void) {
    TEST_SUITE("evidence citation beyond DEAUTH_FLOOD (#92 slice 4)");
    RUN_TEST(test_ev_cite_keeps_newest_oldest_first);
    RUN_TEST(test_ev_cite_repush_moves_an_id_to_newest);
    RUN_TEST(test_pm_forge_alert_cites_the_contradicting_pair);
    RUN_TEST(test_pm_forge_shared_null_is_cited_once);
    RUN_TEST(test_pm_forge_long_run_keeps_the_sleep_declaration);
    RUN_TEST(test_queue_evict_alert_cites_session_change_and_burst);
    RUN_TEST(test_queue_evict_later_change_keeps_release_citations);
    RUN_TEST(test_auth_flood_alert_cites_the_newest_counted_frames);
    RUN_TEST(test_assoc_flood_alert_cites_the_newest_requests);
    RUN_TEST(test_btm_abuse_alert_cites_only_the_imminent_requests);
    RUN_TEST(test_sa_query_flood_alert_cites_the_pairs_frames);
    RUN_TEST(test_auth_flood_never_cites_a_frame_outside_the_window);
    RUN_TEST(test_btm_abuse_never_cites_a_request_outside_the_window);
    RUN_TEST(test_sa_query_flood_never_cites_a_frame_outside_the_window);
    RUN_TEST(test_beacon_flood_alert_cites_each_new_bssids_first_beacon);
    RUN_TEST(test_beacon_flood_never_cites_a_bssid_outside_the_window);
    RUN_TEST(test_evil_twin_alert_cites_both_halves_beacons);
    RUN_TEST(test_same_security_twin_alert_cites_lower_bssid_first);
    RUN_TEST(test_same_security_twin_alert_cites_the_accused_half_first);
    RUN_TEST(test_twin_chain_alert_cites_twin_beacons_and_the_flood);
    RUN_TEST(test_karma_alert_cites_the_newest_frame_of_each_distinct_ssid);
}
