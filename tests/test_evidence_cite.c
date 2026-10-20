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
#include "ev_cite.h"

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

static char g_jpath[] = "/tmp/sloth_evcite_XXXXXX";

static void jsonl_fresh(void) {
    int fd = mkstemp(g_jpath);
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

/* The `alert` line (legacy record) for `title`, copied out so the
 * assertions below look at that one record and not a neighbour's. */
static int jsonl_alert_line(const char *body, const char *title,
                            char *out, size_t n) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"title\":\"%s\"", title);
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
    ASSERT(jsonl_alert_line(body, a->title, line, sizeof(line)));
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
 * new data frame and not the Null twice — the dedup in ev_cite_push(). */
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
        static const uint64_t want[] = { 801, 802, 803 };
        assert_cites(&g_s.alerts[i], body, want, 3);
    }
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

void run_evidence_cite_tests(void) {
    TEST_SUITE("evidence citation beyond DEAUTH_FLOOD (#92 slice 4)");
    RUN_TEST(test_ev_cite_keeps_newest_oldest_first);
    RUN_TEST(test_pm_forge_alert_cites_the_contradicting_pair);
    RUN_TEST(test_pm_forge_shared_null_is_cited_once);
    RUN_TEST(test_queue_evict_alert_cites_session_change_and_burst);
    RUN_TEST(test_queue_evict_later_change_keeps_release_citations);
}
