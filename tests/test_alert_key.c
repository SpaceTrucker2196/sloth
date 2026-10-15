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

void run_alert_key_tests(void) {
    TEST_SUITE("alert identity: hash-first lookup (#112)");
    RUN_TEST(test_long_keys_differing_in_the_last_byte_are_two_incidents);
    RUN_TEST(test_find_by_key_still_compares_the_full_key);
    RUN_TEST(test_an_overlong_key_still_dedupes);
}
