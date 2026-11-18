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
#include "alert_key.h"

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

/* Expiry ends the incident, not the finding (#170). The re-fire is a
 * new incident - its own first_detected and id - on a finding that keeps
 * its first_seen, which is what keeps it one `--db` row. #112 restored
 * first_seen after an eviction only, and reopens after the resolve
 * period were most of the owner's duplicate rows after that. Mutation-proved: dropping the
 * restore in fire_inv() reddens the first_seen check. */
static void test_first_seen_survives_expiry(void) {
    alerts_clear();
    k_clock();
    time_t t0 = g_wall;
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    snap();
    char first[ALERT_INCIDENT_ID_LEN] = "";
    int i = find_key(SIDE_KEY);
    if (i >= 0) snprintf(first, sizeof(first), "%s", g_s.alerts[i].incident_id);
    k_advance(ALERT_RESOLVE_AFTER_S + 1);
    snap();
    time_t t1 = g_wall;
    alerts_fire_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT, SIDE_KEY, "x", NULL, 0);
    snap();
    i = find_key(SIDE_KEY);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((long)g_s.alerts[i].first_seen, (long)t0);
        ASSERT_EQ((long)g_s.alerts[i].first_detected, (long)t1);
        ASSERT(strcmp(g_s.alerts[i].incident_id, first) != 0);
        ASSERT_EQ((int)g_s.alerts[i].reopen_count, 1);
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

/* ── The typed builder ──────────────────────────────────── */

static const char *build1(char *buf, size_t n) {
    akey_t k;
    static const uint8_t mac[6] = {0x02,0x00,0x5e,0x10,0x20,0x30};
    static const uint8_t raw[3] = {0x00,0xab,0xff};
    akey_begin(&k, buf, n, "rule");
    akey_mac(&k, mac);
    akey_ip(&k, "192.0.2.7");
    akey_ip(&k, "2001:db8::1");
    akey_u(&k, 443);
    akey_tok(&k, "HTTP-Basic");
    akey_hex(&k, raw, sizeof(raw));
    return akey_end(&k);
}

static void test_akey_component_shapes(void) {
    char buf[ALERT_KEY_LEN];
    ASSERT_STR(build1(buf, sizeof(buf)),
               "rule:02:00:5e:10:20:30:192.0.2.7:[2001:db8::1]:443:HTTP-Basic:00abff");
}

/* FNV-1a 64 published vectors ("a" → af63dc4c8601ec8c, "foobar" →
 * 85944171f73967e8), so the suffix is checked against the algorithm's
 * definition rather than against this file's own implementation. */
static void test_akey_remote_is_prefix_plus_full_hash(void) {
    char buf[ALERT_KEY_LEN];
    akey_t k;
    akey_begin(&k, buf, sizeof(buf), "r");
    akey_remote(&k, "a", 8);
    ASSERT_STR(akey_end(&k), "r:a:af63dc4c8601ec8c");
    akey_begin(&k, buf, sizeof(buf), "r");
    akey_remote(&k, "foobar", 3);
    ASSERT_STR(akey_end(&k), "r:foo:85944171f73967e8");
}

/* The merge #112 removes: two strings equal for 40 bytes, kept to 30.
 * A precision makes them one key; the builder must not. */
static void test_akey_remote_long_prefix_pair_stays_distinct(void) {
    char a[64], b[64], ka[ALERT_KEY_LEN], kb[ALERT_KEY_LEN];
    memset(a, 'S', 40); a[40] = 'x'; a[41] = '\0';
    memset(b, 'S', 40); b[40] = 'y'; b[41] = '\0';
    akey_t k;
    akey_begin(&k, ka, sizeof(ka), "r"); akey_remote(&k, a, 30); akey_end(&k);
    akey_begin(&k, kb, sizeof(kb), "r"); akey_remote(&k, b, 30); akey_end(&k);
    ASSERT(ka[0] != '\0');
    ASSERT(strcmp(ka, kb) != 0);
    /* Bounded: rule, ':', 30 kept, ':', 16 hex. */
    ASSERT_EQ((int)strlen(ka), 1 + 1 + 30 + 1 + 16);
    ASSERT(strncmp(ka, "r:SSSS", 6) == 0);
}

/* Sanitising is lossy, so it must not be what decides identity: two
 * strings that sanitise alike still differ by their hash. And the
 * separator cannot be smuggled in from the remote side. */
static void test_akey_remote_sanitises_without_merging(void) {
    char ka[ALERT_KEY_LEN], kb[ALERT_KEY_LEN];
    akey_t k;
    akey_begin(&k, ka, sizeof(ka), "r"); akey_remote(&k, "a:b\x01", 16); akey_end(&k);
    akey_begin(&k, kb, sizeof(kb), "r"); akey_remote(&k, "a:b\x02", 16); akey_end(&k);
    ASSERT(strncmp(ka, "r:a_b_:", 7) == 0);
    ASSERT(strncmp(kb, "r:a_b_:", 7) == 0);
    ASSERT(strcmp(ka, kb) != 0);
    /* Exactly two separators: after the rule, after the prefix. None
     * came from the input. */
    int colons = 0;
    for (const char *p = ka; *p; p++) if (*p == ':') colons++;
    ASSERT_EQ(colons, 2);
}

static void test_akey_set_is_order_independent(void) {
    const char *ab[2] = {"10.0.0.1", "10.0.0.2"};
    const char *ba[2] = {"10.0.0.2", "10.0.0.1"};
    char k1[ALERT_KEY_LEN], k2[ALERT_KEY_LEN];
    akey_t k;
    akey_begin(&k, k1, sizeof(k1), "s"); akey_set(&k, ab, 2); akey_end(&k);
    akey_begin(&k, k2, sizeof(k2), "s"); akey_set(&k, ba, 2); akey_end(&k);
    ASSERT(k1[0] != '\0');
    ASSERT_STR(k1, k2);
    ASSERT(strncmp(k1, "s:2:", 4) == 0);
    ASSERT_EQ((int)strlen(k1), 4 + 16);
    /* Joined with a terminator, so member boundaries count. */
    const char *x[2] = {"ab", "c"};
    const char *y[2] = {"a", "bc"};
    akey_begin(&k, k1, sizeof(k1), "s"); akey_set(&k, x, 2); akey_end(&k);
    akey_begin(&k, k2, sizeof(k2), "s"); akey_set(&k, y, 2); akey_end(&k);
    ASSERT(strcmp(k1, k2) != 0);
}

/* An "address" the parser did not produce stays bounded: keyed as a
 * remote string kept to AKEY_IP_FALLBACK_KEEP, never longer than an
 * IPv6 literal would have been. */
static void test_akey_ip_falls_back_for_non_addresses(void) {
    char buf[ALERT_KEY_LEN];
    char junk[120];
    memset(junk, 'q', sizeof(junk) - 1); junk[sizeof(junk) - 1] = '\0';
    akey_t k;
    akey_begin(&k, buf, sizeof(buf), "r");
    akey_ip(&k, junk);
    ASSERT_EQ((int)strlen(akey_end(&k)), 1 + 1 + AKEY_IP_FALLBACK_KEEP + 1 + 16);
    ASSERT((int)strlen(buf) <= 1 + 1 + 47);
    akey_begin(&k, buf, sizeof(buf), "r");
    akey_ip(&k, "host:evil");
    ASSERT(strncmp(akey_end(&k), "r:host_evil:", 12) == 0);
}

/* Overflow is all-or-nothing: "" rather than a shortened key that could
 * equal some other finding's. */
static void test_akey_overflow_yields_empty(void) {
    char buf[ALERT_KEY_LEN];
    char small[12];
    ASSERT_STR(build1(small, sizeof(small)), "");
    akey_t k;
    akey_begin(&k, buf, sizeof(buf), "r");
    akey_tok(&k, "not a token");
    ASSERT_STR(akey_end(&k), "");
    akey_begin(&k, buf, sizeof(buf), "bad rule");
    ASSERT_STR(akey_end(&k), "");
    const char *many[AKEY_SET_MAX + 1];
    for (int i = 0; i <= AKEY_SET_MAX; i++) many[i] = "x";
    akey_begin(&k, buf, sizeof(buf), "s");
    akey_set(&k, many, AKEY_SET_MAX + 1);
    ASSERT_STR(akey_end(&k), "");
}

/* The engine refuses an empty key, so a rule that ignored akey_end()'s
 * "" cannot pile every overflow into one shared incident.
 * Mutation-proved: removing the guard in fire_inv() reddens this. */
static void test_fire_refuses_an_empty_key(void) {
    alerts_clear();
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "", "a", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "", "b", NULL, 0);
    snap();
    ASSERT_EQ(g_s.alert_count, 0);
    alerts_clear();
}

void run_alert_key_tests(void) {
    TEST_SUITE("alert identity: hash-first lookup (#112)");
    RUN_TEST(test_long_keys_differing_in_the_last_byte_are_two_incidents);
    RUN_TEST(test_find_by_key_still_compares_the_full_key);
    RUN_TEST(test_an_overlong_key_still_dedupes);

    TEST_SUITE("alert identity: incident side state (#112)");
    RUN_TEST(test_reopen_count_counts_earlier_incidents);
    RUN_TEST(test_first_seen_survives_expiry);
    RUN_TEST(test_first_seen_survives_eviction);
    RUN_TEST(test_clear_forgets_the_side_state);

    TEST_SUITE("alert identity: typed key builder (#112)");
    RUN_TEST(test_akey_component_shapes);
    RUN_TEST(test_akey_remote_is_prefix_plus_full_hash);
    RUN_TEST(test_akey_remote_long_prefix_pair_stays_distinct);
    RUN_TEST(test_akey_remote_sanitises_without_merging);
    RUN_TEST(test_akey_set_is_order_independent);
    RUN_TEST(test_akey_ip_falls_back_for_non_addresses);
    RUN_TEST(test_akey_overflow_yields_empty);
    RUN_TEST(test_fire_refuses_an_empty_key);
}
