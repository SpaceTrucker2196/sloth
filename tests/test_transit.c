/* Recurring-transit tracking (#54).
 *
 * Every timestamp is supplied, so pass coalescing and windowing are
 * exercised across hours without waiting for any. */

#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "transit.h"
#include "mle.h"

#define T0 1700000000L
#define MIN 60L

static const uint8_t MAC_A[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x01};
static const uint8_t MAC_B[6] = {0x06,0x11,0x22,0x33,0x44,0x02};

/* ── pass coalescing ─────────────────────────────────────── */

/* The false positive that would make the alert untrustworthy: a slow
 * drive-by, or a vehicle stopped at a light inside RF range, produces a
 * run of transit verdicts. Counting each as an approach would
 * manufacture a circuit out of one event. */
static void test_burst_of_observations_is_one_pass(void) {
    transit_clear();
    for (int i = 0; i < 20; i++)
        transit_observe(MAC_A, T0 + i * 3, -50);   /* one minute of samples */
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + 60, TRANSIT_WINDOW_SECS), 1);
}

/* Observations separated by more than the gap are separate passes. */
static void test_separated_observations_are_separate_passes(void) {
    transit_clear();
    transit_observe(MAC_A, T0,             -50);
    transit_observe(MAC_A, T0 + 30 * MIN,  -48);
    transit_observe(MAC_A, T0 + 60 * MIN,  -52);
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + 60 * MIN, TRANSIT_WINDOW_SECS), 3);
}

/* Exactly at the gap threshold is a new pass; one second under is not.
 * Pins the boundary instead of trusting it. */
static void test_gap_threshold_boundary(void) {
    transit_clear();
    transit_observe(MAC_A, T0, -50);
    transit_observe(MAC_A, T0 + TRANSIT_GAP_SECS, -50);
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + TRANSIT_GAP_SECS,
                                 TRANSIT_WINDOW_SECS), 2);

    transit_clear();
    transit_observe(MAC_A, T0, -50);
    transit_observe(MAC_A, T0 + TRANSIT_GAP_SECS - 1, -50);
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + TRANSIT_GAP_SECS,
                                 TRANSIT_WINDOW_SECS), 1);
}

/* ── windowing ───────────────────────────────────────────── */

/* Recurrence is only interesting if it is recent — someone who passed
 * twice this morning and once tonight is commuting. */
static void test_passes_outside_window_drop_out_of_the_count(void) {
    transit_clear();
    transit_observe(MAC_A, T0,            -50);
    transit_observe(MAC_A, T0 + 30 * MIN, -50);
    transit_observe(MAC_A, T0 + 60 * MIN, -50);
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + 60 * MIN, TRANSIT_WINDOW_SECS), 3);

    /* Four hours later the first three have aged out entirely. */
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + 240 * MIN, TRANSIT_WINDOW_SECS), 0);
}

static void test_unknown_device_counts_zero(void) {
    transit_clear();
    ASSERT_EQ(transit_pass_count(MAC_A, T0, TRANSIT_WINDOW_SECS), 0);
    ASSERT_EQ(transit_pass_count(NULL, T0, TRANSIT_WINDOW_SECS), 0);
}

/* A clock stepped backwards must not produce a negative age and silently
 * drop live passes. */
static void test_backwards_clock_is_safe(void) {
    transit_clear();
    transit_observe(MAC_A, T0, -50);
    ASSERT_EQ(transit_pass_count(MAC_A, T0 - 5000, TRANSIT_WINDOW_SECS), 1);
}

/* ── device identity ─────────────────────────────────────── */

static void test_devices_are_tracked_independently(void) {
    transit_clear();
    transit_observe(MAC_A, T0,            -50);
    transit_observe(MAC_A, T0 + 30 * MIN, -50);
    transit_observe(MAC_B, T0,            -60);
    ASSERT_EQ(transit_pass_count(MAC_A, T0 + 30 * MIN, TRANSIT_WINDOW_SECS), 2);
    ASSERT_EQ(transit_pass_count(MAC_B, T0 + 30 * MIN, TRANSIT_WINDOW_SECS), 1);
}

/* Closest approach across every pass, with 0 as the unknown sentinel
 * that must never win. */
static void test_best_rssi_is_closest_approach(void) {
    transit_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    transit_observe(MAC_A, T0,            -80);
    transit_observe(MAC_A, T0 + 30 * MIN, -42);   /* closest */
    transit_observe(MAC_A, T0 + 60 * MIN, -70);
    transit_snapshot(&s, T0 + 60 * MIN);
    ASSERT_EQ(s.transit_count, 1);
    ASSERT_EQ((int)s.transits[0].best_rssi, -42);

    transit_clear();
    transit_observe(MAC_A, T0, 0);                /* unknown */
    transit_observe(MAC_A, T0 + 30 * MIN, -70);
    transit_snapshot(&s, T0 + 30 * MIN);
    ASSERT_EQ((int)s.transits[0].best_rssi, -70);
}

/* ── canonical identity (the randomisation gap) ──────────── */

/* A randomising device rotates its MAC between passes, so keying on the
 * raw address would give it two half-counts that never reach the
 * threshold. seqnum correlation already pairs the addresses of one
 * physical radio; this resolves through it. */
static void test_correlated_macs_resolve_to_one_identity(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_correlation_t *c = &s.seqnum_correlations[s.seqnum_correlation_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac_a, MAC_A, 6);
    memcpy(c->mac_b, MAC_B, 6);

    uint8_t ida[6], idb[6];
    transit_canonical_mac(&s, MAC_A, ida);
    transit_canonical_mac(&s, MAC_B, idb);
    /* Both sides of the pair must land on the same key whichever is
     * seen first, or the device accumulates two half-counts. */
    ASSERT_EQ(memcmp(ida, idb, 6), 0);
    /* Specifically the numerically smaller of the pair. */
    ASSERT_EQ(memcmp(ida, MAC_A, 6), 0);
}

/* End to end: three passes split across two rotated MACs still trips
 * the threshold once they are canonicalised. Without this the device
 * would show as 2 + 1 and never alert — the whole point of the
 * correlation hop. */
static void test_rotated_macs_accumulate_to_one_count(void) {
    transit_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_correlation_t *c = &s.seqnum_correlations[s.seqnum_correlation_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac_a, MAC_A, 6);
    memcpy(c->mac_b, MAC_B, 6);

    const uint8_t *seen[] = { MAC_A, MAC_B, MAC_A };
    for (int i = 0; i < 3; i++) {
        uint8_t id[6];
        transit_canonical_mac(&s, seen[i], id);
        transit_observe(id, T0 + i * 30 * MIN, -50);
    }
    uint8_t id[6];
    transit_canonical_mac(&s, MAC_B, id);
    ASSERT_EQ(transit_pass_count(id, T0 + 60 * MIN, TRANSIT_WINDOW_SECS),
              TRANSIT_RECUR_THRESH);
}

/* An uncorrelated MAC resolves to itself, so the common case costs
 * nothing and behaves as if the table were absent. */
static void test_uncorrelated_mac_resolves_to_itself(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t id[6];
    transit_canonical_mac(&s, MAC_A, id);
    ASSERT_EQ(memcmp(id, MAC_A, 6), 0);
    transit_canonical_mac(NULL, MAC_A, id);
    ASSERT_EQ(memcmp(id, MAC_A, 6), 0);
}

/* ── snapshot ────────────────────────────────────────────── */

static void test_snapshot_drops_devices_past_the_window(void) {
    transit_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    transit_observe(MAC_A, T0, -50);
    transit_snapshot(&s, T0);
    ASSERT_EQ(s.transit_count, 1);

    transit_snapshot(&s, T0 + TRANSIT_WINDOW_SECS + 60);
    ASSERT_EQ(s.transit_count, 0);
}

static void test_snapshot_is_idempotent(void) {
    transit_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    transit_observe(MAC_A, T0, -50);
    transit_snapshot(&s, T0);
    transit_snapshot(&s, T0);
    ASSERT_EQ(s.transit_count, 1);
    ASSERT_EQ(s.transits[0].pass_n, 1);
}

static void test_snapshot_null_state_is_safe(void) {
    transit_clear();
    transit_observe(MAC_A, T0, -50);
    transit_snapshot(NULL, T0);          /* must not crash */
    ASSERT_EQ(transit_pass_count(MAC_A, T0, TRANSIT_WINDOW_SECS), 1);
}

/* ── bounds ──────────────────────────────────────────────── */

/* An attacker spraying randomised MACs must not be able to make a
 * passive monitor allocate without limit, nor push the device that is
 * actually circling out of the table ahead of stale one-off passers. */
static void test_device_table_is_bounded_and_evicts_stalest(void) {
    transit_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));

    /* Fill with old one-off passers. */
    for (int i = 0; i < MAX_TRANSIT_DEVICES; i++) {
        uint8_t m[6] = {0x02, 0, 0, 0, (uint8_t)(i >> 8), (uint8_t)i};
        transit_observe(m, T0, -70);
    }
    /* A recent, active device arrives after the table is full. */
    transit_observe(MAC_B, T0 + 60 * MIN, -40);

    transit_snapshot(&s, T0 + 60 * MIN);
    ASSERT(s.transit_count <= MAX_TRANSIT_DEVICES);
    ASSERT_EQ(transit_pass_count(MAC_B, T0 + 60 * MIN, TRANSIT_WINDOW_SECS), 1);
}

/* More passes than the per-device array holds must not overflow it; the
 * oldest is dropped, which changes nothing since the device is already
 * far past the alert threshold. */
static void test_pass_array_is_bounded(void) {
    transit_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_TRANSIT_PASSES + 10; i++)
        transit_observe(MAC_A, T0 + (long)i * TRANSIT_GAP_SECS * 2, -50);
    transit_snapshot(&s, T0 + (long)(MAX_TRANSIT_PASSES + 10)
                             * TRANSIT_GAP_SECS * 2);
    ASSERT_EQ(s.transit_count, 1);
    ASSERT_EQ(s.transits[0].pass_n, MAX_TRANSIT_PASSES);
}

static void test_clear_empties_everything(void) {
    transit_clear();
    transit_observe(MAC_A, T0, -50);
    ASSERT_EQ(transit_pass_count(MAC_A, T0, TRANSIT_WINDOW_SECS), 1);
    transit_clear();
    ASSERT_EQ(transit_pass_count(MAC_A, T0, TRANSIT_WINDOW_SECS), 0);
}


/* ── MLO takes precedence over seqnum inference (#67) ─────── */

static void test_canonical_prefers_the_mld_assertion(void) {
    /* An MLE is the protocol *asserting* that these addresses are one
     * device; a seqnum correlation is sloth inferring it. Assertion
     * beats inference — and here they disagree deliberately, so the
     * test says which one won rather than only that something did. */
    mle_clear();
    static const uint8_t MLD[6]  = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    static const uint8_t LINK[6] = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x11 };
    static const uint8_t OTHER[6]= { 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

    sloth_mld_t m;
    memset(&m, 0, sizeof(m));
    memcpy(m.mld_mac, MLD, 6);
    memcpy(m.link_mac[0], LINK, 6);
    m.link_count = 1;
    mle_observe(&m, 1000);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* A seqnum correlation pointing somewhere else, and numerically
     * smaller — so it would win under the seqnum rule alone. */
    seqnum_correlation_t *c = &s.seqnum_correlations[s.seqnum_correlation_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac_a, LINK,  6);
    memcpy(c->mac_b, OTHER, 6);

    uint8_t out[6];
    transit_canonical_mac(&s, LINK, out);
    ASSERT(memcmp(out, MLD, 6) == 0);
    mle_clear();
}

static void test_canonical_falls_back_to_seqnum_without_an_mle(void) {
    /* No MLE for this address: the seqnum correlation is all there is,
     * and it must still work. */
    mle_clear();
    static const uint8_t A[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x77 };
    static const uint8_t B[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x11 };
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_correlation_t *c = &s.seqnum_correlations[s.seqnum_correlation_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac_a, A, 6);
    memcpy(c->mac_b, B, 6);
    uint8_t out[6];
    transit_canonical_mac(&s, A, out);
    ASSERT(memcmp(out, B, 6) == 0);      /* numerically smaller wins */
    mle_clear();
}

void run_transit_tests(void) {
    TEST_SUITE("transit: pass coalescing");
    RUN_TEST(test_burst_of_observations_is_one_pass);
    RUN_TEST(test_separated_observations_are_separate_passes);
    RUN_TEST(test_gap_threshold_boundary);

    TEST_SUITE("transit: windowing");
    RUN_TEST(test_passes_outside_window_drop_out_of_the_count);
    RUN_TEST(test_unknown_device_counts_zero);
    RUN_TEST(test_backwards_clock_is_safe);

    TEST_SUITE("transit: device identity");
    RUN_TEST(test_devices_are_tracked_independently);
    RUN_TEST(test_best_rssi_is_closest_approach);
    RUN_TEST(test_correlated_macs_resolve_to_one_identity);
    RUN_TEST(test_rotated_macs_accumulate_to_one_count);
    RUN_TEST(test_uncorrelated_mac_resolves_to_itself);

    TEST_SUITE("transit: snapshot");
    RUN_TEST(test_snapshot_drops_devices_past_the_window);
    RUN_TEST(test_snapshot_is_idempotent);
    RUN_TEST(test_snapshot_null_state_is_safe);

    TEST_SUITE("transit: bounds");
    RUN_TEST(test_device_table_is_bounded_and_evicts_stalest);
    RUN_TEST(test_pass_array_is_bounded);
    RUN_TEST(test_clear_empties_everything);
    TEST_SUITE("MLO canonical identity (#67)");
    RUN_TEST(test_canonical_prefers_the_mld_assertion);
    RUN_TEST(test_canonical_falls_back_to_seqnum_without_an_mle);
}
