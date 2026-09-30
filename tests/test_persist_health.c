#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "persist_health.h"
#include "jsonl.h"
#include "alert_pcap.h"
#include "eapol_log.h"

/* ── Cannot-persist state — issue #96 ───────────────────────
 *
 * The per-sink failure counters and their JSONL sum already exist;
 * what #96 adds is the state snapshot and the tab-bar badge, so a
 * console operator sees a failing export from any view. The badge is
 * pure string formatting over the snapshot — testable with seeded
 * counts, no terminal, no failing disk. */

static void test_badge_empty_when_healthy(void) {
    persist_health_t p;
    memset(&p, 0, sizeof(p));
    char buf[96];
    memset(buf, 'x', sizeof(buf));
    ASSERT_EQ(persist_badge(&p, buf, sizeof(buf)), 0);
    ASSERT_STR(buf, "");
}

static void test_badge_names_only_failing_sinks(void) {
    persist_health_t p;
    memset(&p, 0, sizeof(p));
    p.jsonl = 3;
    p.eapol = 2;
    char buf[96];
    ASSERT_EQ(persist_badge(&p, buf, sizeof(buf)), 5);
    ASSERT_STR(buf, "!persist jsonl:3 eapol:2");
    p.jsonl = 0; p.eapol = 0; p.alert_pcap = 1;
    ASSERT_EQ(persist_badge(&p, buf, sizeof(buf)), 1);
    ASSERT_STR(buf, "!persist pcap:1");
}

static void test_badge_all_sinks_in_stable_order(void) {
    persist_health_t p;
    p.jsonl = 1; p.alert_pcap = 2; p.eapol = 3;
    char buf[96];
    ASSERT_EQ(persist_badge(&p, buf, sizeof(buf)), 6);
    ASSERT_STR(buf, "!persist jsonl:1 pcap:2 eapol:3");
}

static void test_badge_truncates_safely(void) {
    persist_health_t p;
    p.jsonl = 12345; p.alert_pcap = 67890; p.eapol = 11111;
    char buf[10];
    /* Total still reported; the string is cut, never overrun. */
    ASSERT_EQ(persist_badge(&p, buf, sizeof(buf)), 12345 + 67890 + 11111);
    ASSERT_EQ((int)strlen(buf) < (int)sizeof(buf), 1);
    char one[1];
    ASSERT_EQ(persist_badge(&p, one, sizeof(one)) > 0, 1);
    ASSERT_STR(one, "");
}

static void test_badge_null_arguments(void) {
    persist_health_t p;
    memset(&p, 0, sizeof(p));
    char buf[8];
    ASSERT_EQ(persist_badge(NULL, buf, sizeof(buf)), 0);
    ASSERT_STR(buf, "");
    ASSERT_EQ(persist_badge(&p, NULL, 8), 0);
    ASSERT_EQ(persist_badge(&p, buf, 0), 0);
}

static void test_poll_mirrors_module_counters(void) {
    /* The poll is a copy of the sinks' own lifetime accessors — the
     * same sources the JSONL sensor_health record sums, so the badge
     * and the log can never disagree. */
    persist_health_t p;
    memset(&p, 0xff, sizeof(p));
    persist_health_poll(&p);
    ASSERT_EQ(p.jsonl,      jsonl_write_failures());
    ASSERT_EQ(p.alert_pcap, alert_pcap_failures());
    ASSERT_EQ(p.eapol,      eapol_export_failures());
    persist_health_poll(NULL);   /* no-op, no crash */
}

void run_persist_health_tests(void) {
    TEST_SUITE("persist health — cannot-persist badge (#96)");
    RUN_TEST(test_badge_empty_when_healthy);
    RUN_TEST(test_badge_names_only_failing_sinks);
    RUN_TEST(test_badge_all_sinks_in_stable_order);
    RUN_TEST(test_badge_truncates_safely);
    RUN_TEST(test_badge_null_arguments);
    RUN_TEST(test_poll_mirrors_module_counters);
}
