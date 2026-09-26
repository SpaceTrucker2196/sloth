/* Wired-attachment correlation seam (#89 slice 3).
 *
 * The contract under test is mostly a contract about *not* answering:
 * sloth must never claim a radio is attached to the wired network on RF
 * evidence, because RF carries none. So most of these assert that the
 * default is UNKNOWN and that only a registered correlator can move it.
 *
 * No frames here on purpose — this module has no parser. The frame-level
 * behaviour that consumes it is pinned in tests/test_twins.c and
 * tests/test_alerts.c against hand-built beacon state. */

#include <string.h>
#include "runner.h"
#include "wired_attach.h"

static const uint8_t BSSID_A[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
static const uint8_t BSSID_B[6] = {0x11,0x22,0x33,0x44,0x55,0x66};

/* Enum values are stored as uint8_t in twin_episode_t / alert_t (sloth.h
 * cannot include module headers from src/), so the numbering is a
 * cross-file contract and pinned here rather than assumed. */
static void test_wired_enum_values_are_pinned(void) {
    ASSERT_EQ((int)WIRED_ATTACH_UNKNOWN,      0);
    ASSERT_EQ((int)WIRED_ATTACH_ATTACHED,     1);
    ASSERT_EQ((int)WIRED_ATTACH_NOT_ATTACHED, 2);
}

/* The default, and the whole point of the slice: with nothing that can
 * see the wire, every BSSID is UNKNOWN. */
static void test_wired_default_is_unknown(void) {
    wired_attach_clear();
    ASSERT_EQ(wired_attach_have_correlator(), 0);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_UNKNOWN);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_B), (int)WIRED_ATTACH_UNKNOWN);
}

static void test_wired_null_bssid_is_unknown(void) {
    wired_attach_clear();
    ASSERT_EQ((int)wired_attach_lookup(NULL), (int)WIRED_ATTACH_UNKNOWN);
}

static wired_attach_t only_a_is_attached(const uint8_t bssid[6], void *ctx) {
    (void)ctx;
    if (memcmp(bssid, BSSID_A, 6) == 0) return WIRED_ATTACH_ATTACHED;
    return WIRED_ATTACH_NOT_ATTACHED;
}

/* The seam works: a registered correlator's verdict reaches the caller,
 * per BSSID. This is the future controller/switch/DHCP integration the
 * issue asked to be left room for. */
static void test_wired_registered_correlator_answers(void) {
    wired_attach_clear();
    wired_attach_register(only_a_is_attached, NULL);
    ASSERT_EQ(wired_attach_have_correlator(), 1);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_ATTACHED);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_B), (int)WIRED_ATTACH_NOT_ATTACHED);
    wired_attach_clear();
    /* And unregistering really takes the answer away rather than
     * leaving a stale one cached. */
    ASSERT_EQ(wired_attach_have_correlator(), 0);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_UNKNOWN);
}

static wired_attach_t ctx_says(const uint8_t bssid[6], void *ctx) {
    (void)bssid;
    return *(wired_attach_t *)ctx;
}

static void test_wired_context_is_passed_through(void) {
    wired_attach_clear();
    wired_attach_t answer = WIRED_ATTACH_ATTACHED;
    wired_attach_register(ctx_says, &answer);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_ATTACHED);
    answer = WIRED_ATTACH_NOT_ATTACHED;
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_NOT_ATTACHED);
    wired_attach_clear();
}

static wired_attach_t always_attached(const uint8_t bssid[6], void *ctx) {
    (void)bssid; (void)ctx;
    return WIRED_ATTACH_ATTACHED;
}

/* One slot, no stacking. Two correlators disagreeing about a BSSID is an
 * unresolved question, not a vote — so registering a second replaces the
 * first outright instead of being tallied against it. */
static void test_wired_second_register_replaces_first(void) {
    wired_attach_clear();
    wired_attach_register(only_a_is_attached, NULL);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_B), (int)WIRED_ATTACH_NOT_ATTACHED);
    wired_attach_register(always_attached, NULL);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_B), (int)WIRED_ATTACH_ATTACHED);
    wired_attach_clear();
}

static void test_wired_register_null_clears(void) {
    wired_attach_clear();
    wired_attach_register(always_attached, NULL);
    ASSERT_EQ(wired_attach_have_correlator(), 1);
    wired_attach_register(NULL, NULL);
    ASSERT_EQ(wired_attach_have_correlator(), 0);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_UNKNOWN);
}

static wired_attach_t returns_garbage(const uint8_t bssid[6], void *ctx) {
    (void)bssid; (void)ctx;
    return (wired_attach_t)77;
}

/* A correlator bug must cost sloth an answer, never manufacture one.
 * "There is a rogue AP on your wired network" is the claim in this
 * module with the heaviest operational consequence — it gets a switch
 * port shut — so an unrecognised value degrades to UNKNOWN rather than
 * being passed through to the UI as some truthy non-zero state. */
static void test_wired_unrecognised_value_degrades_to_unknown(void) {
    wired_attach_clear();
    wired_attach_register(returns_garbage, NULL);
    ASSERT_EQ((int)wired_attach_lookup(BSSID_A), (int)WIRED_ATTACH_UNKNOWN);
    wired_attach_clear();
}

static void test_wired_labels(void) {
    ASSERT(strcmp(wired_attach_label(WIRED_ATTACH_UNKNOWN),      "?")   == 0);
    ASSERT(strcmp(wired_attach_label(WIRED_ATTACH_ATTACHED),     "yes") == 0);
    ASSERT(strcmp(wired_attach_label(WIRED_ATTACH_NOT_ATTACHED), "no")  == 0);
    /* Out-of-range is "?" and not a NULL a caller would deref. */
    ASSERT(strcmp(wired_attach_label((wired_attach_t)99), "?") == 0);
}

void run_wired_attach_tests(void);
void run_wired_attach_tests(void) {
    TEST_SUITE("wired-attachment hook");
    RUN_TEST(test_wired_enum_values_are_pinned);
    RUN_TEST(test_wired_default_is_unknown);
    RUN_TEST(test_wired_null_bssid_is_unknown);
    RUN_TEST(test_wired_registered_correlator_answers);
    RUN_TEST(test_wired_context_is_passed_through);
    RUN_TEST(test_wired_second_register_replaces_first);
    RUN_TEST(test_wired_register_null_clears);
    RUN_TEST(test_wired_unrecognised_value_degrades_to_unknown);
    RUN_TEST(test_wired_labels);
}
