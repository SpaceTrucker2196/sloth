/* The credential-lure records (JSONL 1.3.0, #187 / #172):
 * `karma_suspect`, `harvest_station` and `harvest_chain`, written from
 * the tables the KARMA and harvest rules read (src/jsonl.c
 * jsonl_emit_lures()).
 *
 * The rows are seeded directly, as tests/test_alerts.c seeds the
 * tables its rules read: what is under test is the record, not the
 * trackers that fill the tables (tests/test_karma.c,
 * tests/test_harvest_track.c). Absence assertions name the mutation
 * each was seen red under. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"
#include "jsonl.h"
#include "sloth_clock.h"
#include "harvest_track.h"

static time_t g_lw;
static time_t lw(void) { return g_lw; }
static char   g_lpath[TEST_TMP_MAX];
static sloth_state_t g_ls;
static harvest_sta_t   g_hs[4];
static harvest_chain_t g_hc[2];

static void lure_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_lpath, sizeof(g_lpath), "sloth_lure_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_lpath);
    ASSERT(jsonl_open(g_lpath));
    jsonl_dedup_reset();
    jsonl_lures_reset();
    g_lw = 1800000000;
    sloth_clock_test_set(NULL, lw);
    memset(&g_ls, 0, sizeof(g_ls));
    memset(g_hs, 0, sizeof(g_hs));
    memset(g_hc, 0, sizeof(g_hc));
}

static const char *lure_read(void) {
    static char buf[16384];
    jsonl_close();
    FILE *fp = fopen(g_lpath, "r");
    size_t n = fp ? fread(buf, 1, sizeof(buf) - 1, fp) : 0;
    buf[n] = '\0';
    if (fp) fclose(fp);
    unlink(g_lpath);
    sloth_clock_test_set(NULL, NULL);
    jsonl_lures_reset();
    return buf;
}

static int count_of(const char *b, const char *needle) {
    int n = 0;
    for (const char *p = b; (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

static void seed_karma(int i, uint8_t last, int forged) {
    karma_ap_t *k = &g_ls.karma_aps[i];
    const uint8_t b[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, last };
    memcpy(k->bssid, b, 6);
    k->ssid_count = 1;
    k->ie_fp_distinct = 1;
    k->forged = forged;
    k->forge_stations = 2;
    k->score = 4;
    snprintf(k->top_ssid, sizeof(k->top_ssid), "Cafe \"Free\"\x01");
    snprintf(k->tool, sizeof(k->tool), "airbase-ng");
    k->last_seen = 1799999990;
    if (i >= g_ls.karma_count) g_ls.karma_count = i + 1;
}

/* Every column, in order, with the SSID through the stream's escaping
 * (a quote as \", a control byte as \u0001, never the raw byte). */
static void test_karma_suspect_record(void) {
    lure_open();
    seed_karma(0, 0x55, 3);
    g_ls.karma_aps[0].pnl_best = 2;
    g_ls.karma_aps[0].deauth_chain = 1;
    jsonl_emit_lures(&g_ls);
    const char *b = lure_read();
    ASSERT(strstr(b, "{\"type\":\"karma_suspect\",\"ts\":1800000000,"
                     "\"bssid\":\"02:11:22:33:44:55\",\"state\":\"live\","
                     "\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,"
                     "\"forged\":3,\"forge_stations\":2,\"pnl_best\":2,"
                     "\"lure_chain\":1,\"score\":4,"
                     "\"top_ssid\":\"Cafe \\\"Free\\\"\\u0001\","
                     "\"tool\":\"airbase-ng\",\"last_seen\":1799999990}\n") != NULL);
    ASSERT(strchr(b, '\x01') == NULL);
}

/* A station row is written only with an M1 left unanswered: one that
 * answered every M1 is a station joining its own network. Seen red
 * (two lines) with the unanswered >= 1 guard removed. The member names
 * carry none of slothweb's credential words: `pmkid` would. */
static void test_harvest_records(void) {
    lure_open();
    const uint8_t h1[6] = { 0x02, 0xaa, 0, 0, 0, 1 };
    const uint8_t h2[6] = { 0x02, 0xaa, 0, 0, 0, 2 };
    memcpy(g_hs[0].sta, h1, 6);
    g_hs[0].solicited = 5; g_hs[0].m1_bssids = 4; g_hs[0].unanswered = 4;
    g_hs[0].pmkid_unanswered = 3; g_hs[0].answered = 0;
    g_hs[0].first_seen = 1799999000; g_hs[0].last_seen = 1799999900;
    memcpy(g_hs[1].sta, h2, 6);
    g_hs[1].solicited = 1; g_hs[1].m1_bssids = 1; g_hs[1].answered = 1;
    g_ls.harvest_sta = g_hs;
    g_ls.harvest_sta_count = 2;
    const uint8_t ap[6] = { 0x0a, 0xbb, 0, 0, 0, 9 };
    memcpy(g_hc[0].bssid, ap, 6);
    g_hc[0].victims = 2; g_hc[0].deauth_frames = 6;
    memcpy(g_hc[0].victim[0], h2, 6);
    g_hc[0].first_seen = 1799999500; g_hc[0].last_seen = 1799999800;
    g_ls.harvest_chain = g_hc;
    g_ls.harvest_chain_count = 1;
    jsonl_emit_lures(&g_ls);
    const char *b = lure_read();
    ASSERT(strstr(b, "{\"type\":\"harvest_station\",\"ts\":1800000000,"
                     "\"sta\":\"02:aa:00:00:00:01\",\"state\":\"live\","
                     "\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,"
                     "\"unanswered_kde\":3,\"answered\":0,\"dropped\":0,"
                     "\"first_seen\":1799999000,\"last_seen\":1799999900}\n") != NULL);
    ASSERT_EQ(count_of(b, "\"type\":\"harvest_station\""), 1);
    ASSERT(strstr(b, "02:aa:00:00:00:02\",\"state\":\"live\"") == NULL);
    ASSERT(strstr(b, "{\"type\":\"harvest_chain\",\"ts\":1800000000,"
                     "\"bssid\":\"0a:bb:00:00:00:09\",\"state\":\"live\","
                     "\"victims\":2,\"disconnects\":6,\"dropped\":0,"
                     "\"first_seen\":1799999500,\"last_seen\":1799999800}\n") != NULL);
    /* The victim's address is not exported: counts only. */
    ASSERT(strstr(b, "02:aa:00:00:00:02") == NULL);
    ASSERT(strstr(b, "pmk") == NULL);
    ASSERT(strstr(b, "auth") == NULL);
}

/* Change-only: nothing while the counts stand still inside the 300 s
 * heartbeat (last_seen moving is not a change), a line when one moves,
 * a line on the heartbeat. Seen red (a line per pass) with last_seen
 * signed. */
static void test_lures_change_only(void) {
    lure_open();
    seed_karma(0, 0x55, 2);
    jsonl_emit_lures(&g_ls);
    g_lw += 10;
    g_ls.karma_aps[0].last_seen += 10;
    jsonl_emit_lures(&g_ls);                /* suppressed */
    g_ls.karma_aps[0].forged = 3;
    jsonl_emit_lures(&g_ls);                /* changed: written */
    g_lw += 299;
    jsonl_emit_lures(&g_ls);                /* 299 s: suppressed */
    g_lw += 1;
    jsonl_emit_lures(&g_ls);                /* heartbeat */
    const char *b = lure_read();
    ASSERT_EQ(count_of(b, "\"type\":\"karma_suspect\""), 3);
}

/* A row that leaves its table is written once as gone, key alone; a
 * row that comes back with the same counts is written live again.
 * Seen red (no gone line) with lure_retire() not called for karma, and
 * (no second live line) with lure_retire() not re-signing the slot. */
static void test_lures_gone(void) {
    lure_open();
    seed_karma(0, 0x55, 2);
    seed_karma(1, 0x66, 2);
    jsonl_emit_lures(&g_ls);
    g_ls.karma_count = 1;                   /* 0x66 left the table */
    g_lw += 1;
    jsonl_emit_lures(&g_ls);
    g_lw += 1;
    jsonl_emit_lures(&g_ls);                /* nothing: gone once */
    seed_karma(1, 0x66, 2);                 /* back, same counts */
    g_lw += 1;
    jsonl_emit_lures(&g_ls);
    const char *b = lure_read();
    ASSERT_EQ(count_of(b, "{\"type\":\"karma_suspect\",\"ts\":1800000001,"
                          "\"bssid\":\"02:11:22:33:44:66\",\"state\":\"gone\"}\n"), 1);
    ASSERT_EQ(count_of(b, "\"bssid\":\"02:11:22:33:44:66\",\"state\":\"gone\""), 1);
    ASSERT_EQ(count_of(b, "\"bssid\":\"02:11:22:33:44:66\",\"state\":\"live\""), 2);
    ASSERT_EQ(count_of(b, "\"bssid\":\"02:11:22:33:44:55\""), 1);
}

/* A station whose unanswered M1s aged to none leaves the record set
 * too, though its row is still in the table. */
static void test_station_gone_when_answered(void) {
    lure_open();
    const uint8_t h1[6] = { 0x02, 0xaa, 0, 0, 0, 1 };
    memcpy(g_hs[0].sta, h1, 6);
    g_hs[0].m1_bssids = 1; g_hs[0].unanswered = 1;
    g_ls.harvest_sta = g_hs;
    g_ls.harvest_sta_count = 1;
    jsonl_emit_lures(&g_ls);
    g_hs[0].unanswered = 0; g_hs[0].answered = 1;
    jsonl_emit_lures(&g_ls);
    const char *b = lure_read();
    ASSERT(strstr(b, "{\"type\":\"harvest_station\",\"ts\":1800000000,"
                     "\"sta\":\"02:aa:00:00:00:01\",\"state\":\"gone\"}\n") != NULL);
}

/* No sink: no work and nothing remembered, so a row seen while nobody
 * listened is not retired as gone once someone does. Seen red with the
 * any_sink() test dropped from the early return. */
static void test_lures_no_sink(void) {
    jsonl_close();
    jsonl_lures_reset();
    memset(&g_ls, 0, sizeof(g_ls));
    seed_karma(0, 0x55, 2);
    jsonl_emit_lures(&g_ls);
    jsonl_emit_lures(NULL);
    memset(&g_ls, 0, sizeof(g_ls));
    int fd = mkstemp(test_tmp_tpl(g_lpath, sizeof(g_lpath), "sloth_lure_XXXXXX"));
    if (fd >= 0) close(fd);
    unlink(g_lpath);
    ASSERT(jsonl_open(g_lpath));
    jsonl_dedup_reset();
    jsonl_emit_lures(&g_ls);                /* empty tables */
    const char *b = lure_read();
    ASSERT(strstr(b, "gone") == NULL);
}

void run_jsonl_lures_tests(void) {
    TEST_SUITE("jsonl: the credential-lure records (JSONL 1.3.0)");
    RUN_TEST(test_karma_suspect_record);
    RUN_TEST(test_harvest_records);
    RUN_TEST(test_lures_change_only);
    RUN_TEST(test_lures_gone);
    RUN_TEST(test_station_gone_when_answered);
    RUN_TEST(test_lures_no_sink);
}
