/* Alert identity (#112): the engine's key lookup, the incident side
 * state that survives slot reuse, and the typed key builder.
 *
 * Driven through alerts_fire_for_test() → the real fire()/fire_inv()
 * path, then alerts_update() on an empty state to snapshot. No rule's
 * trigger is contrived here: what is under test is what the engine does
 * with a key, not whether a detector produces one. The per-rule key
 * tests live beside each rule's existing tests in test_alerts.c. */
#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "sloth_clock.h"

TEST_STATE(g_s);

static void snap(void) {
    memset(&g_s, 0, sizeof(g_s));
    alerts_update(&g_s);
}

static int find_key(const char *key) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (strcmp(g_s.alerts[i].key, key) == 0) return i;
    return -1;
}

/* Two keys of the full stored length, ALERT_KEY_LEN - 1 = 191 bytes,
 * identical through byte 189 and differing only in the last one. */
static void long_pair(char a[ALERT_KEY_LEN], char b[ALERT_KEY_LEN]) {
    memset(a, 'k', ALERT_KEY_LEN - 1);
    a[ALERT_KEY_LEN - 1] = '\0';
    memcpy(b, a, ALERT_KEY_LEN);
    a[ALERT_KEY_LEN - 2] = 'A';
    b[ALERT_KEY_LEN - 2] = 'B';
}

/* ── Hash-first find_by_key ─────────────────────────────── */

static void test_long_keys_differing_in_the_last_byte_are_two_incidents(void) {
    alerts_clear();
    char a[ALERT_KEY_LEN], b[ALERT_KEY_LEN];
    long_pair(a, b);
    ASSERT_EQ((int)strlen(a), ALERT_KEY_LEN - 1);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, a, "a", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, b, "b", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, a, "a", NULL, 0);
    snap();
    ASSERT_EQ(g_s.alert_count, 2);
    int ia = find_key(a), ib = find_key(b);
    ASSERT(ia >= 0);
    ASSERT(ib >= 0);
    if (ia >= 0) ASSERT_EQ(g_s.alerts[ia].count, 2);
    if (ib >= 0) ASSERT_EQ(g_s.alerts[ib].count, 1);
    alerts_clear();
}

/* The hash only filters; strcmp decides. With every hash forced to one
 * value the two keys collide, and they must still be two incidents —
 * a collision merging two findings is the bug class #112 removes.
 * Mutation-proved: dropping the strcmp from find_by_key() reddens the
 * count and the per-key evaluation counts. */
static void test_find_by_key_still_compares_the_full_key(void) {
    alerts_clear();
    alerts_test_key_hash_mask(0);
    char a[ALERT_KEY_LEN], b[ALERT_KEY_LEN];
    long_pair(a, b);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, a, "a", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, b, "b", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, b, "b", NULL, 0);
    snap();
    ASSERT_EQ(g_s.alert_count, 2);
    int ia = find_key(a), ib = find_key(b);
    ASSERT(ia >= 0);
    ASSERT(ib >= 0);
    if (ia >= 0) ASSERT_EQ(g_s.alerts[ia].count, 1);
    if (ib >= 0) ASSERT_EQ(g_s.alerts[ib].count, 2);
    alerts_clear();
}

/* A key longer than the slot used to be stored truncated and compared
 * in full, so it never matched its own entry: one new incident per
 * tick. Mutation-proved: removing the normalisation in fire_inv()
 * leaves two entries here. */
static void test_an_overlong_key_still_dedupes(void) {
    alerts_clear();
    char k[ALERT_KEY_LEN + 64];
    memset(k, 'z', sizeof(k) - 1);
    k[sizeof(k) - 1] = '\0';
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, k, "d", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, k, "d", NULL, 0);
    snap();
    ASSERT_EQ(g_s.alert_count, 1);
    if (g_s.alert_count == 1) {
        ASSERT_EQ(g_s.alerts[0].count, 2);
        ASSERT_EQ((int)strlen(g_s.alerts[0].key), ALERT_KEY_LEN - 1);
    }
    alerts_clear();
}

/* ── Incident side state (#112) ─────────────────────────── */

/* Frozen clocks, both advanced together. Sentinel epoch: nothing here
 * depends on what time the host thinks it is. */
static uint64_t g_mono;
static time_t   g_wall;
static uint64_t k_mono(void) { return g_mono; }
static time_t   k_wall(void) { return g_wall; }
static void k_clock(void) {
    g_mono = 5000000;
    g_wall = 1700000000;
    sloth_clock_test_set(k_mono, k_wall);
}
static void k_advance(long secs) {
    g_mono += (uint64_t)secs * 1000u;
    g_wall += (time_t)secs;
}

#define SIDE_KEY "side-test:one"

static void test_reopen_count_counts_earlier_incidents(void) {
    alerts_clear();
    k_clock();
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    snap();
    int i = find_key(SIDE_KEY);
    ASSERT(i >= 0);
    if (i < 0) { alerts_clear(); return; }
    ASSERT_EQ((int)g_s.alerts[i].reopen_count, 0);
    char first[ALERT_INCIDENT_ID_LEN];
    snprintf(first, sizeof(first), "%s", g_s.alerts[i].incident_id);

    for (int round = 1; round <= 2; round++) {
        /* Quiet for the full resolve period: the incident expires, and
         * the next fire of the key opens a new one. */
        k_advance(ALERT_RESOLVE_AFTER_S + 1);
        snap();
        alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
        snap();
        i = find_key(SIDE_KEY);
        ASSERT(i >= 0);
        if (i < 0) break;
        ASSERT_EQ((int)g_s.alerts[i].reopen_count, round);
        ASSERT(!g_s.alerts[i].resolved);
        /* A new incident: new id, and its counters are its own. */
        ASSERT(strcmp(g_s.alerts[i].incident_id, first) != 0);
        ASSERT_EQ((int)g_s.alerts[i].evaluations, 1);
    }
    sloth_clock_test_set(NULL, NULL);
    alerts_clear();
}

/* Expiry is the condition ending. The re-fire is a new episode and
 * keeps its own first_seen. Mutation-proved: restoring first_seen on
 * every reopen (dropping the `evicted` condition) reddens this. */
static void test_first_seen_is_fresh_after_expiry(void) {
    alerts_clear();
    k_clock();
    time_t t0 = g_wall;
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    k_advance(ALERT_RESOLVE_AFTER_S + 1);
    snap();
    time_t t1 = g_wall;
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    snap();
    int i = find_key(SIDE_KEY);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((long)g_s.alerts[i].first_seen, (long)t1);
        ASSERT(g_s.alerts[i].first_seen != t0);
        ASSERT_EQ((long)g_s.alerts[i].first_detected, (long)t1);
    }
    sloth_clock_test_set(NULL, NULL);
    alerts_clear();
}

/* Eviction is the engine running out of room, not the finding ending.
 * Before #112 the slot memset gave the re-fire a new first_seen, and
 * first_seen is half the `--db` alerts primary key, so every
 * evict→refire cycle wrote a new row for one finding.
 * Mutation-proved: removing the restore reddens the first_seen check. */
static void test_first_seen_survives_eviction(void) {
    alerts_clear();
    k_clock();
    time_t t0 = g_wall;
    /* The key under test is the OLDEST entry of the type holding the
     * most slots, so per-type fair eviction picks it first. */
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, SIDE_KEY, "x", NULL, 0);
    k_advance(1);
    char k[32];
    for (int n = 0; n < MAX_ALERTS; n++) {
        snprintf(k, sizeof(k), "side-filler:%d", n);
        alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, k, "f", NULL, 0);
    }
    snap();
    /* Precondition: it really was evicted, not merely resolved in place. */
    ASSERT(find_key(SIDE_KEY) < 0);

    k_advance(1);
    time_t t2 = g_wall;
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, SIDE_KEY, "x", NULL, 0);
    snap();
    int i = find_key(SIDE_KEY);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((long)g_s.alerts[i].first_seen, (long)t0);
        /* Still a new incident — only the key's history carried over. */
        ASSERT_EQ((long)g_s.alerts[i].first_detected, (long)t2);
        ASSERT_EQ((int)g_s.alerts[i].reopen_count, 1);
    }
    sloth_clock_test_set(NULL, NULL);
    alerts_clear();
}

/* alerts_clear() is a fresh start for the key's history too. */
static void test_clear_forgets_the_side_state(void) {
    alerts_clear();
    k_clock();
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    k_advance(ALERT_RESOLVE_AFTER_S + 1);
    snap();
    alerts_clear();
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    snap();
    int i = find_key(SIDE_KEY);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ((int)g_s.alerts[i].reopen_count, 0);
    sloth_clock_test_set(NULL, NULL);
    alerts_clear();
}

void run_alert_key_tests(void) {
    TEST_SUITE("alert identity: hash-first lookup (#112)");
    RUN_TEST(test_long_keys_differing_in_the_last_byte_are_two_incidents);
    RUN_TEST(test_find_by_key_still_compares_the_full_key);
    RUN_TEST(test_an_overlong_key_still_dedupes);

    TEST_SUITE("alert identity: incident side state (#112)");
    RUN_TEST(test_reopen_count_counts_earlier_incidents);
    RUN_TEST(test_first_seen_is_fresh_after_expiry);
    RUN_TEST(test_first_seen_survives_eviction);
    RUN_TEST(test_clear_forgets_the_side_state);
}
