#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "seqnum_track.h"
#include "views/seqnum.h"

static void mac(uint8_t out[6], uint8_t la, uint8_t b1, uint8_t b2,
                                  uint8_t b3, uint8_t b4, uint8_t b5) {
    out[0] = la; out[1] = b1; out[2] = b2;
    out[3] = b3; out[4] = b4; out[5] = b5;
}

static void test_empty(void) {
    seqnum_clear();
    ASSERT_EQ(seqnum_client_count(), 0);
}

static void test_multicast_skipped(void) {
    seqnum_clear();
    uint8_t m[6]; mac(m, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01);  /* mcast */
    seqnum_track_observe(m, 1000);
    ASSERT_EQ(seqnum_client_count(), 0);
}

static void test_single_client_history(void) {
    seqnum_clear();
    uint8_t m[6]; mac(m, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    seqnum_track_observe(m, 100);
    seqnum_track_observe(m, 101);
    seqnum_track_observe(m, 102);
    ASSERT_EQ(seqnum_client_count(), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_count, 1);
    /* Newest first. */
    ASSERT_EQ((int)s.seqnum_clients[0].hist[0], 102);
    ASSERT_EQ((int)s.seqnum_clients[0].hist[1], 101);
    ASSERT_EQ((int)s.seqnum_clients[0].hist[2], 100);
    ASSERT_EQ(s.seqnum_clients[0].hist_n, 3);
    ASSERT_EQ(s.seqnum_clients[0].frame_count, 3);
}

static void test_random_flag(void) {
    seqnum_clear();
    uint8_t real[6];   mac(real,   0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t random[6]; mac(random, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
    seqnum_track_observe(real,   100);
    seqnum_track_observe(random, 200);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_count, 2);
    /* Find each by MAC. */
    int found_real = 0, found_random = 0;
    for (int i = 0; i < s.seqnum_count; i++) {
        if (memcmp(s.seqnum_clients[i].mac, real, 6) == 0) {
            ASSERT_EQ(s.seqnum_clients[i].mac_random, 0); found_real = 1;
        } else if (memcmp(s.seqnum_clients[i].mac, random, 6) == 0) {
            ASSERT_EQ(s.seqnum_clients[i].mac_random, 1); found_random = 1;
        }
    }
    ASSERT_EQ(found_real,   1);
    ASSERT_EQ(found_random, 1);
}

static void test_correlation_detects_adjacent_seqnums(void) {
    seqnum_clear();
    uint8_t real[6];   mac(real,   0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t random[6]; mac(random, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    /* Same physical device burning monotonic seqnums across a MAC
     * rotation: 100, 101 (real) then 102, 103 (randomised). */
    seqnum_track_observe(real,   100);
    seqnum_track_observe(real,   101);
    seqnum_track_observe(random, 102);
    seqnum_track_observe(random, 103);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_correlation_count, 1);
    const seqnum_correlation_t *c = &s.seqnum_correlations[0];
    /* Gap between 101 (newest of real) and 102 (oldest of random) = 1.
     * try_correlate looks across all pairs; it could be even less. */
    ASSERT_LT(c->gap, 5);
    /* At least one side is randomised. */
    ASSERT(c->mac_a_random || c->mac_b_random);
}

static void test_no_correlation_when_far_apart(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe(a, 100);
    /* gap 2000 — well outside the 64-seqnum window. */
    seqnum_track_observe(b, 2100);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_correlation_count, 0);
}

static void test_history_caps_at_ring_size(void) {
    seqnum_clear();
    uint8_t m[6]; mac(m, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    for (int i = 0; i < SEQNUM_HISTORY_LEN + 5; i++) {
        seqnum_track_observe(m, (uint16_t)(1000 + i));
    }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_clients[0].hist_n, SEQNUM_HISTORY_LEN);
    /* Newest = last value pushed. */
    int last = 1000 + SEQNUM_HISTORY_LEN + 5 - 1;
    ASSERT_EQ((int)s.seqnum_clients[0].hist[0], last);
}

/* ── Correlation honesty (#94) ───────────────────────────────
 *
 * Everything below drives the injected-clock API so expiry and ordering
 * are tested at the second, not waited out. T0 is an arbitrary fixed
 * epoch — the module must never consult the real clock on this path. */

#define T0 1700000000L

/* Two histories that once sat next to each other must stop producing a
 * *current* correlation once the evidence has aged out. Before #94
 * nothing expired, so a pair observed at boot was still being offered
 * as a live suggestion hours after both devices had left. */
static void test_stale_histories_expire(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe_at(a, 100, T0);
    seqnum_track_observe_at(a, 101, T0);
    seqnum_track_observe_at(b, 102, T0 + 1);
    seqnum_track_observe_at(b, 103, T0 + 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 5);
    ASSERT_EQ(s.seqnum_correlation_count, 1);

    /* One second past the retention window: the same table, no claim. */
    memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + SEQNUM_CORR_RETAIN_S + 2);
    ASSERT_EQ(s.seqnum_correlation_count, 0);
}

/* Retention is operator-settable because it is a retention decision,
 * not only a tuning one. */
static void test_retention_is_configurable(void) {
    seqnum_clear();
    seqnum_corr_set_retain_secs(10);
    ASSERT_EQ(seqnum_corr_retain_secs(), 10);
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe_at(a, 100, T0);
    seqnum_track_observe_at(b, 101, T0);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 5);
    ASSERT_EQ(s.seqnum_correlation_count, 1);

    memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 20);
    ASSERT_EQ(s.seqnum_correlation_count, 0);

    /* Nonsense values are ignored rather than disabling expiry. */
    seqnum_corr_set_retain_secs(0);
    ASSERT_EQ(seqnum_corr_retain_secs(), 10);
}

/* A counter that runs *backwards* across the transition is not one
 * radio's counter. Absolute modular distance cannot tell the two apart,
 * which is why the old rule accepted either direction. */
static void test_correlation_requires_forward_transition(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    /* a runs 200,201 and stops; b starts later at 190,191 — 10 behind.
     * Distance 9, direction wrong. */
    seqnum_track_observe_at(a, 200, T0);
    seqnum_track_observe_at(a, 201, T0);
    seqnum_track_observe_at(b, 190, T0 + 3);
    seqnum_track_observe_at(b, 191, T0 + 3);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 5);
    ASSERT_EQ(s.seqnum_correlation_count, 0);
}

/* One radio holds one address at a time. Two MACs transmitting through
 * the same seconds are two radios however close their counters sit —
 * this is the "concurrently active incompatible observations" exclusion,
 * and it is the check that does most of the work in a dense room. */
static void test_concurrent_activity_excludes_pair(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    /* Interleaved: a at t+0 and t+4, b at t+2 and t+6. Counters one
     * apart at the seam, activity overlapping. */
    seqnum_track_observe_at(a, 100, T0);
    seqnum_track_observe_at(b, 101, T0 + 2);
    seqnum_track_observe_at(a, 102, T0 + 4);
    seqnum_track_observe_at(b, 103, T0 + 6);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 8);
    ASSERT_EQ(s.seqnum_correlation_count, 0);
}

/* A pair that is reported must carry the window it was decided on, so a
 * consumer reading one out of an archive can see it rests on four frames
 * in a few seconds rather than on a day of traffic. */
static void test_correlation_reports_evidence_window(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe_at(a, 100, T0);
    seqnum_track_observe_at(a, 101, T0 + 1);
    seqnum_track_observe_at(b, 102, T0 + 3);
    seqnum_track_observe_at(b, 103, T0 + 4);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 5);
    ASSERT_EQ(s.seqnum_correlation_count, 1);
    const seqnum_correlation_t *c = &s.seqnum_correlations[0];
    ASSERT_EQ((long)c->window_start, T0);
    ASSERT_EQ((long)c->window_end,   T0 + 4);
    ASSERT_EQ(c->fwd_gap, 1);
    ASSERT_EQ(c->a_hist_n, 2);
    ASSERT_EQ(c->b_hist_n, 2);
    ASSERT_EQ(c->dt_ms, 2000L);
}

/* Nothing observed over the air makes identity certain, so the scale
 * does not reach 100 — and a reported pair is never below the floor. */
static void test_confidence_is_scored_never_certain(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    for (int i = 0; i < 4; i++) seqnum_track_observe_at(a, (uint16_t)(500 + i), T0);
    for (int i = 0; i < 4; i++) seqnum_track_observe_at(b, (uint16_t)(504 + i), T0 + 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 2);
    ASSERT_EQ(s.seqnum_correlation_count, 1);
    const seqnum_correlation_t *c = &s.seqnum_correlations[0];
    ASSERT_GE(c->confidence, SEQNUM_CORR_CONF_MIN);
    ASSERT(c->confidence <= SEQNUM_CORR_CONF_MAX);
    ASSERT_LT(c->confidence, 100);
}

/* The score has to move with the evidence or it is decoration: a tight,
 * deep, immediate transition must outrank a loose, shallow, slow one. */
static void test_tighter_evidence_scores_higher(void) {
    seqnum_clear();
    uint8_t a1[6]; mac(a1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01);
    uint8_t b1[6]; mac(b1, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01);
    for (int i = 0; i < 8; i++) seqnum_track_observe_at(a1, (uint16_t)(100 + i), T0);
    for (int i = 0; i < 8; i++) seqnum_track_observe_at(b1, (uint16_t)(108 + i), T0);

    uint8_t a2[6]; mac(a2, 0x00, 0x11, 0x22, 0x33, 0x44, 0x02);
    uint8_t b2[6]; mac(b2, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02);
    seqnum_track_observe_at(a2, 2000, T0);
    seqnum_track_observe_at(a2, 2001, T0 + 1);
    seqnum_track_observe_at(b2, 2030, T0 + 12);
    seqnum_track_observe_at(b2, 2031, T0 + 13);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 30);
    ASSERT_EQ(s.seqnum_correlation_count, 2);
    /* Sorted most-likely-first. */
    ASSERT_GT(s.seqnum_correlations[0].confidence,
              s.seqnum_correlations[1].confidence);
    /* And the tight pair is the one on top. */
    ASSERT(memcmp(s.seqnum_correlations[0].mac_a, a1, 6) == 0 ||
           memcmp(s.seqnum_correlations[0].mac_b, a1, 6) == 0);
}

/* Longitudinal correlation is a separate purpose from watching the air,
 * so it switches separately. Off: histories still render, no pair is
 * linked, stored or exported. */
static void test_correlation_can_be_disabled(void) {
    seqnum_clear();
    seqnum_corr_set_enabled(0);
    ASSERT_EQ(seqnum_corr_enabled(), 0);
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe_at(a, 100, T0);
    seqnum_track_observe_at(b, 101, T0);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 1);
    ASSERT_EQ(s.seqnum_correlation_count, 0);
    ASSERT_EQ(s.seqnum_count, 2);          /* observation is unaffected */
    seqnum_clear();
    ASSERT_EQ(seqnum_corr_enabled(), 1);   /* clear restores the default */
}

/* Records age out on snapshot. Eviction-on-fill alone meant a quiet
 * sensor kept every MAC it had ever heard for the life of the process. */
static void test_stale_clients_age_out_of_table(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe_at(a, 100, T0);
    seqnum_track_observe_at(b, 900, T0 + SEQNUM_CLIENT_RETAIN_S);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + SEQNUM_CLIENT_RETAIN_S + 1);
    /* `a` is over the horizon, `b` is not. */
    ASSERT_EQ(s.seqnum_count, 1);
    ASSERT(memcmp(s.seqnum_clients[0].mac, b, 6) == 0);
    ASSERT_EQ(seqnum_client_count(), 1);
}

/* Raising the correlation window must not starve the correlator: client
 * retention is the larger of the two horizons. */
static void test_client_retention_follows_a_longer_corr_window(void) {
    seqnum_clear();
    seqnum_corr_set_retain_secs(SEQNUM_CLIENT_RETAIN_S * 2);
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    seqnum_track_observe_at(a, 100, T0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + SEQNUM_CLIENT_RETAIN_S + 60);
    ASSERT_EQ(s.seqnum_count, 1);
    seqnum_clear();
}

/* ── Measured false-pair rate ────────────────────────────────
 *
 * The issue offers scale intuition — for two independent uniform 12-bit
 * values, 129/4096 differences fall within modular distance 64, about
 * 3.15 % per comparison. Real histories are dependent, so that number is
 * an estimate about a model, not a measurement of this code. This test
 * builds a dense fixture of independent radios with deliberately
 * repeated sequence values, runs the production acceptance test over
 * every pair, and prints the rate it actually measures.
 *
 * Every pair here is false by construction: 64 distinct radios, each
 * with its own counter, active in its own time slot. The bound asserted
 * is above the measured value with headroom, so this fails if the
 * acceptance test is ever loosened — it does not encode the estimate. */
#define DENSE_MACS 64

static void test_dense_environment_false_pair_rate(void) {
    seqnum_clear();

    /* Deterministic LCG (Numerical Recipes constants) — no rand(), so
     * the measured rate is reproducible across hosts and runs. The
     * modulus is deliberately small: 512 positions over 64 radios
     * guarantees repeated sequence values, which is the case the issue
     * asks to be measured. */
    uint32_t seed = 12345u;
    for (int k = 0; k < DENSE_MACS; k++) {
        uint8_t m[6];
        mac(m, 0x02, 0xde, 0xad, 0x00, (uint8_t)(k >> 8), (uint8_t)k);
        seed = seed * 1664525u + 1013904223u;
        uint16_t base = (uint16_t)((seed >> 16) % 512u);
        /* Each radio runs its own monotonic counter — a fixture whose
         * trails were themselves incoherent would be rejected for the
         * wrong reason and would measure nothing. Each occupies its own
         * four-second slot, so no two are concurrently active: the
         * exclusion that would trivially reject them is out of the
         * picture and what remains being measured is counter
         * coincidence, which is the issue's question. */
        for (int i = 0; i < SEQNUM_HISTORY_LEN; i++) {
            seqnum_track_observe_at(m, (uint16_t)((base + i) & 0x0FFF),
                                    (time_t)(T0 + k * 4 + i / 2));
        }
    }
    ASSERT_EQ(seqnum_client_count(), DENSE_MACS);

    int accepted = 0, max_conf = 0;
    int compared = seqnum_corr_candidate_pairs(T0 + DENSE_MACS * 4 + 1,
                                               &accepted, &max_conf);
    ASSERT_EQ(compared, DENSE_MACS * (DENSE_MACS - 1) / 2);

    /* Report it. Every accepted pair is a false pair here. */
    printf("      dense fixture: %d/%d candidate pairs accepted "
           "= %.3f%% false-pair rate, top score %d%% "
           "(%d independent radios, 512 sequence positions)\n",
           accepted, compared,
           compared ? (100.0 * accepted) / compared : 0.0,
           max_conf, DENSE_MACS);

    /* Bound, not estimate: set from the measurement with headroom, so
     * this fails if the acceptance test is ever loosened. */
    ASSERT_LT(accepted * 1000, compared * 40);   /* < 4 % */
    /* And no coincidence may be scored as certainty. */
    ASSERT(max_conf <= SEQNUM_CORR_CONF_MAX);

    /* The measured coincidences reach into the upper band numerically —
     * a close forward seam between two independent radios looks exactly
     * like a rotation. What keeps them out of the strongest reading is
     * structural: every radio here uses a locally-administered address,
     * so no pair has the anchor shape. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + DENSE_MACS * 4 + 1);
    ASSERT_GT(s.seqnum_correlation_count, 0);
    int strong = 0;
    for (int i = 0; i < s.seqnum_correlation_count; i++)
        if (seqnum_corr_is_strong(&s.seqnum_correlations[i])) strong++;
    ASSERT_EQ(strong, 0);
}

/* ── What the operator is told ───────────────────────────────
 *
 * The wording is the finding in #94, so it is pinned here rather than
 * left to a docs page nobody reads at the terminal. Same technique as
 * test_help.c: TPRINT is printf in the test build. */
static void capture_draw(void (*draw)(const sloth_state_t *),
                         const sloth_state_t *st, char *buf, int sz) {
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    draw(st);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
}

static void test_view_never_claims_identity(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    for (int i = 0; i < 8; i++) seqnum_track_observe_at(a, (uint16_t)(100 + i), T0);
    for (int i = 0; i < 8; i++) seqnum_track_observe_at(b, (uint16_t)(108 + i), T0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 1);
    ASSERT_EQ(s.seqnum_correlation_count, 1);

    char buf[8192];
    capture_draw(view_seqnum_draw, &s, buf, sizeof(buf));

    /* This pair is the strongest shape there is — one randomised address
     * beside a burned-in one, counters adjacent, full trails. Even here
     * the panel must not assert identity. */
    ASSERT(seqnum_corr_is_strong(&s.seqnum_correlations[0]));
    ASSERT(strstr(buf, "SAME DEVICE")  == NULL);
    ASSERT(strstr(buf, "same device")  == NULL);
    ASSERT(strstr(buf, "same person")  == NULL);
    /* What it must say instead: possible, scored, and bounded in use.
     * The word "person" appears exactly once and only to disclaim it. */
    ASSERT(strstr(buf, "Possible device correlation")         != NULL);
    ASSERT(strstr(buf, "possible rotation")                   != NULL);
    ASSERT(strstr(buf, "Not an identification of a person")    != NULL);
    ASSERT(strstr(buf, "personnel action")                     != NULL);
}

/* With correlation off the panel says so, instead of looking like a
 * sensor that found nothing. */
static void test_view_states_when_correlation_is_off(void) {
    seqnum_clear();
    seqnum_corr_set_enabled(0);
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    seqnum_track_observe_at(a, 100, T0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot_at(&s, T0 + 1);

    char buf[8192];
    capture_draw(view_seqnum_draw, &s, buf, sizeof(buf));
    ASSERT(strstr(buf, "--no-correlate") != NULL);
    ASSERT(strstr(buf, "disabled")       != NULL);
    seqnum_clear();
}

/* The strongest reading needs an anchor address, not just a high score. */
static void test_strong_reading_requires_an_anchor_address(void) {
    seqnum_correlation_t c;

    memset(&c, 0, sizeof(c));
    c.confidence = SEQNUM_CORR_CONF_MAX;
    c.mac_a_random = 1; c.mac_b_random = 1;
    ASSERT_EQ(seqnum_corr_is_strong(&c), 0);   /* no anchor */

    c.mac_b_random = 0;
    ASSERT_EQ(seqnum_corr_is_strong(&c), 1);   /* rotating vs burned-in */

    c.confidence = SEQNUM_CORR_CONF_STRONG - 1;
    ASSERT_EQ(seqnum_corr_is_strong(&c), 0);   /* right shape, thin evidence */

    ASSERT_EQ(seqnum_corr_is_strong(NULL), 0);
}

void run_seqnum_track_tests(void) {
    TEST_SUITE("seqnum_track");
    RUN_TEST(test_empty);
    RUN_TEST(test_multicast_skipped);
    RUN_TEST(test_single_client_history);
    RUN_TEST(test_random_flag);
    RUN_TEST(test_correlation_detects_adjacent_seqnums);
    RUN_TEST(test_no_correlation_when_far_apart);
    RUN_TEST(test_history_caps_at_ring_size);

    TEST_SUITE("seqnum_track: correlation honesty (#94)");
    RUN_TEST(test_stale_histories_expire);
    RUN_TEST(test_retention_is_configurable);
    RUN_TEST(test_correlation_requires_forward_transition);
    RUN_TEST(test_concurrent_activity_excludes_pair);
    RUN_TEST(test_correlation_reports_evidence_window);
    RUN_TEST(test_confidence_is_scored_never_certain);
    RUN_TEST(test_tighter_evidence_scores_higher);
    RUN_TEST(test_correlation_can_be_disabled);
    RUN_TEST(test_stale_clients_age_out_of_table);
    RUN_TEST(test_client_retention_follows_a_longer_corr_window);
    RUN_TEST(test_dense_environment_false_pair_rate);
    RUN_TEST(test_strong_reading_requires_an_anchor_address);
    RUN_TEST(test_view_never_claims_identity);
    RUN_TEST(test_view_states_when_correlation_is_off);
}
