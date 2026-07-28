/* Presence classification (#53).
 *
 * Trajectories are hand-built from first principles — a vehicle pass, a
 * device that arrived and stayed, a wake-up, a sleep — rather than
 * captured and replayed. Same rule as the protocol parsers: a test that
 * feeds the classifier its own output proves nothing. */

#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "presence.h"

#define NOW 1700000000L

/* Build a ring from an RSSI series, one sample per second ending at
 * `now`. Writes through the ring the way rssi_ring_push does, so a
 * series longer than the ring wraps exactly as it would in production. */
static void ring_from(rssi_ring_t *r, const int *dbm, int n, time_t now) {
    memset(r, 0, sizeof(*r));
    for (int i = 0; i < n; i++) {
        r->dbm[r->head] = (int8_t)dbm[i];
        r->ts [r->head] = now - (n - 1 - i);
        r->head = (r->head + 1) % RSSI_WIN_SAMPLES;
        if (r->count < RSSI_WIN_SAMPLES) r->count++;
    }
}

/* ── transit shape ───────────────────────────────────────── */

/* The signature this module exists for: a vehicle entering RF range,
 * passing, and leaving. */
static void test_vehicle_pass_has_transit_shape(void) {
    rssi_ring_t r;
    const int pass[] = { -85, -78, -70, -58, -47, -44, -52, -66, -79, -88 };
    ring_from(&r, pass, 10, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 1);
}

/* A device that arrived and stayed rises and then plateaus. It never
 * recedes, so it is not a pass — this is the case a dwell-only rule
 * would get wrong in the other direction. */
static void test_arrived_and_stayed_is_not_transit(void) {
    rssi_ring_t r;
    const int arrive[] = { -85, -76, -64, -52, -48, -47, -48, -47, -49, -48 };
    ring_from(&r, arrive, 10, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

/* A stationary emitter wobbles a few dB and goes nowhere. */
static void test_stationary_is_not_transit(void) {
    rssi_ring_t r;
    const int flat[] = { -61, -60, -62, -59, -61, -60, -63, -60, -61, -62 };
    ring_from(&r, flat, 10, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

/* One-sided moves are not passes. A rise with no fall is a device
 * waking or switching on; a fall with no rise is one going to sleep or
 * being switched off. Neither moved, and reporting either as "passing"
 * would be a confident wrong answer. */
static void test_one_sided_rise_is_not_transit(void) {
    rssi_ring_t r;
    const int rise[] = { -88, -80, -72, -64, -56, -48, -44 };
    ring_from(&r, rise, 7, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

static void test_one_sided_fall_is_not_transit(void) {
    rssi_ring_t r;
    const int fall[] = { -44, -48, -56, -64, -72, -80, -88 };
    ring_from(&r, fall, 7, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

/* A pass has to actually be a pass. A 3 dB bump is a person shifting in
 * a chair, not a vehicle crossing the beam. */
static void test_shallow_bump_is_not_transit(void) {
    rssi_ring_t r;
    const int bump[] = { -62, -61, -60, -59, -60, -61, -62 };
    ring_from(&r, bump, 7, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

/* Exactly at the threshold on both sides counts; one dB under on
 * either side does not. Pins the boundary rather than trusting it. */
static void test_transit_threshold_boundary(void) {
    rssi_ring_t r;
    int at[]    = { -70, -70 + PRESENCE_SWING_DBM, -70 };
    ring_from(&r, at, 3, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 1);

    int under[] = { -70, -70 + PRESENCE_SWING_DBM - 1, -70 };
    ring_from(&r, under, 3, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);

    /* Asymmetric: a strong rise and a weak fall is still not a pass. */
    int lopsided[] = { -90, -50, -85 + PRESENCE_SWING_DBM };
    (void)lopsided;
    int weak_fall[] = { -90, -50, -53 };
    ring_from(&r, weak_fall, 3, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

/* An anomalous reading at one end must not mask a clean pass — the
 * comparison is against the weakest sample on each side, not the
 * endpoint. */
static void test_outlier_endpoint_does_not_mask_transit(void) {
    rssi_ring_t r;
    /* First sample is unusually strong for a device still far away. */
    const int pass[] = { -55, -85, -70, -46, -44, -68, -86, -84 };
    ring_from(&r, pass, 8, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 1);
}

/* ── evidence thresholds ─────────────────────────────────── */

/* Below three samples no trajectory claim is made — three is the
 * minimum that can express rise-peak-fall at all. */
static void test_too_few_samples_no_claim(void) {
    rssi_ring_t r;
    const int two[] = { -85, -45 };
    ring_from(&r, two, 2, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);

    const int one[] = { -45 };
    ring_from(&r, one, 1, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
}

static void test_null_and_empty_ring_safe(void) {
    ASSERT_EQ(presence_has_transit_shape(NULL, NOW), 0);
    rssi_ring_t r; memset(&r, 0, sizeof(r));
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 0);
    ASSERT_EQ((int)presence_classify(NULL, NOW - 10, NOW, NOW),
              (int)PRESENCE_UNKNOWN);
}

/* Stale samples are not evidence about now. A pass that happened ten
 * minutes ago must not still read as a pass. */
static void test_stale_samples_are_ignored(void) {
    rssi_ring_t r;
    const int pass[] = { -85, -70, -46, -44, -68, -86 };
    ring_from(&r, pass, 6, NOW);
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 1);
    /* Same ring, evaluated well past the window. */
    ASSERT_EQ(presence_has_transit_shape(&r, NOW + RSSI_WIN_SECS + 60), 0);
}

/* A ring that has wrapped must still read in chronological order.
 * Reading the raw array in index order would scramble the series and
 * turn a clean pass into noise — the bug this test exists to catch. */
static void test_wrapped_ring_reads_in_order(void) {
    rssi_ring_t r;
    /* More samples than the ring holds: a long approach that wraps,
     * leaving only the peak-and-recede portion live. */
    int series[RSSI_WIN_SAMPLES + 6];
    int n = 0;
    for (int i = 0; i < 8; i++)  series[n++] = -90 + i;          /* far */
    for (int i = 0; i < 6; i++)  series[n++] = -82 + i * 6;      /* rise */
    series[n++] = -44;                                           /* peak */
    for (int i = 0; i < 7; i++)  series[n++] = -50 - i * 6;      /* recede */
    ring_from(&r, series, n, NOW);
    ASSERT_EQ(r.count, RSSI_WIN_SAMPLES);      /* it really did wrap */
    ASSERT_EQ(presence_has_transit_shape(&r, NOW), 1);
}

/* ── classification ──────────────────────────────────────── */

static void test_classify_vehicle_is_transient(void) {
    rssi_ring_t r;
    const int pass[] = { -85, -72, -58, -45, -44, -60, -75, -88 };
    ring_from(&r, pass, 8, NOW);
    ASSERT_EQ((int)presence_classify(&r, NOW - 30, NOW, NOW),
              (int)PRESENCE_TRANSIENT);
}

static void test_classify_long_dwell_is_resident(void) {
    rssi_ring_t r;
    const int flat[] = { -61, -60, -62, -59, -61, -60 };
    ring_from(&r, flat, 6, NOW);
    ASSERT_EQ((int)presence_classify(&r, NOW - 3600, NOW, NOW),
              (int)PRESENCE_RESIDENT);
}

static void test_classify_medium_dwell_is_visitor(void) {
    rssi_ring_t r;
    const int flat[] = { -61, -60, -62, -59, -61, -60 };
    ring_from(&r, flat, 6, NOW);
    ASSERT_EQ((int)presence_classify(&r, NOW - 300, NOW, NOW),
              (int)PRESENCE_VISITOR);
}

/* Dwell alone may promote to visitor or resident — "was here a while"
 * is a weak claim a long span already supports, even with no RSSI
 * history at all. */
static void test_dwell_alone_promotes_without_samples(void) {
    rssi_ring_t r; memset(&r, 0, sizeof(r));
    ASSERT_EQ((int)presence_classify(&r, NOW - 3600, NOW, NOW),
              (int)PRESENCE_RESIDENT);
    ASSERT_EQ((int)presence_classify(&r, NOW - 300, NOW, NOW),
              (int)PRESENCE_VISITOR);
}

/* ...but a device heard once is never TRANSIENT. Calling something
 * "just passing" asserts it moved, and one sample cannot show that.
 * This asymmetry is the heart of the design. */
static void test_single_observation_is_unknown_not_transient(void) {
    rssi_ring_t r;
    const int one[] = { -45 };
    ring_from(&r, one, 1, NOW);
    ASSERT_EQ((int)presence_classify(&r, NOW, NOW, NOW),
              (int)PRESENCE_UNKNOWN);
    ASSERT_NE((int)presence_classify(&r, NOW, NOW, NOW),
              (int)PRESENCE_TRANSIENT);
}

/* A transit shape stretched over a long dwell is not a pass — it is
 * something that came and went and came back, or an intermittently
 * blocked signal. The dwell gate is what keeps "passing" meaning
 * passing. */
static void test_transit_shape_over_long_dwell_is_not_transient(void) {
    rssi_ring_t r;
    const int pass[] = { -85, -72, -58, -45, -44, -60, -75, -88 };
    ring_from(&r, pass, 8, NOW);
    presence_class_t c = presence_classify(&r, NOW - 7200, NOW, NOW);
    ASSERT_NE((int)c, (int)PRESENCE_TRANSIENT);
    ASSERT_EQ((int)c, (int)PRESENCE_RESIDENT);
}

/* Transit outranks a merely-long-enough dwell inside the transient
 * window: a device that demonstrably passed by should not be reported
 * as a visitor for having been audible either side of the pass. */
static void test_transit_outranks_visitor_dwell(void) {
    rssi_ring_t r;
    const int pass[] = { -85, -72, -58, -45, -44, -60, -75, -88 };
    ring_from(&r, pass, 8, NOW);
    /* Exactly at the transient ceiling, which is also the visitor floor. */
    ASSERT_EQ((int)presence_classify(&r, NOW - PRESENCE_TRANSIENT_MAX_S,
                                     NOW, NOW),
              (int)PRESENCE_TRANSIENT);
}

/* A clock stepped backwards must not produce a negative dwell and a
 * nonsense verdict. */
static void test_negative_dwell_is_safe(void) {
    rssi_ring_t r; memset(&r, 0, sizeof(r));
    ASSERT_EQ((int)presence_classify(&r, NOW, NOW - 5000, NOW),
              (int)PRESENCE_UNKNOWN);
}

static void test_dwell_boundaries(void) {
    rssi_ring_t r; memset(&r, 0, sizeof(r));
    ASSERT_EQ((int)presence_classify(&r, NOW - PRESENCE_RESIDENT_MIN_S,
                                     NOW, NOW), (int)PRESENCE_RESIDENT);
    ASSERT_EQ((int)presence_classify(&r, NOW - PRESENCE_RESIDENT_MIN_S + 1,
                                     NOW, NOW), (int)PRESENCE_VISITOR);
    ASSERT_EQ((int)presence_classify(&r, NOW - PRESENCE_VISITOR_MIN_S,
                                     NOW, NOW), (int)PRESENCE_VISITOR);
    ASSERT_EQ((int)presence_classify(&r, NOW - PRESENCE_VISITOR_MIN_S + 1,
                                     NOW, NOW), (int)PRESENCE_UNKNOWN);
}

static void test_labels(void) {
    ASSERT_STR(presence_label(PRESENCE_TRANSIENT), "passing");
    ASSERT_STR(presence_label(PRESENCE_VISITOR),   "visitor");
    ASSERT_STR(presence_label(PRESENCE_RESIDENT),  "resident");
    ASSERT_STR(presence_label(PRESENCE_UNKNOWN),   "?");
    ASSERT_STR(presence_label((presence_class_t)99), "?");
}

void run_presence_tests(void) {
    TEST_SUITE("presence: transit shape");
    RUN_TEST(test_vehicle_pass_has_transit_shape);
    RUN_TEST(test_arrived_and_stayed_is_not_transit);
    RUN_TEST(test_stationary_is_not_transit);
    RUN_TEST(test_one_sided_rise_is_not_transit);
    RUN_TEST(test_one_sided_fall_is_not_transit);
    RUN_TEST(test_shallow_bump_is_not_transit);
    RUN_TEST(test_transit_threshold_boundary);
    RUN_TEST(test_outlier_endpoint_does_not_mask_transit);

    TEST_SUITE("presence: evidence thresholds");
    RUN_TEST(test_too_few_samples_no_claim);
    RUN_TEST(test_null_and_empty_ring_safe);
    RUN_TEST(test_stale_samples_are_ignored);
    RUN_TEST(test_wrapped_ring_reads_in_order);

    TEST_SUITE("presence: classification");
    RUN_TEST(test_classify_vehicle_is_transient);
    RUN_TEST(test_classify_long_dwell_is_resident);
    RUN_TEST(test_classify_medium_dwell_is_visitor);
    RUN_TEST(test_dwell_alone_promotes_without_samples);
    RUN_TEST(test_single_observation_is_unknown_not_transient);
    RUN_TEST(test_transit_shape_over_long_dwell_is_not_transient);
    RUN_TEST(test_transit_outranks_visitor_dwell);
    RUN_TEST(test_negative_dwell_is_safe);
    RUN_TEST(test_dwell_boundaries);
    RUN_TEST(test_labels);
}
