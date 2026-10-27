/* RSSI distance data point (owner request 2026-10-26).
 *
 * Every expected number is computed by hand from ITU-R P.1238-10 eq.
 * (1) solved for d, with the constants research/papers/rssi-distance-
 * estimation.md cites, and written down here as the arithmetic rather
 * than read back from the implementation:
 *
 *   L(1 m) at 2437 MHz = 20 log10 2437 - 28 = 39.737 dB
 *   AP assumed 20 dBm heard at -60 dBm, N = 28:
 *     d = 10 ^ ((20 + 60 - 39.737) / 28) = 10 ^ 1.43796 = 27.41 m
 *   interval: sigma 8 (P.1238-10 Table 4) and the assumed-power 6 in
 *     quadrature = 10 dB -> factor 10 ^ (10 / 28) = 2.2758:
 *     12.05 .. 62.39 m
 *
 * The track is fed hand-built sample series, never a capture. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "rf_distance.h"
#include "ownership.h"
#include "tune.h"
#include "jsonl.h"
#include "sloth_clock.h"
#include "tmp_dir.h"

#define T0 1700000000L

static void ctx_ap_assumed_6(rf_ctx_t *c) {
    rf_ctx_assumed(c, 6, WIFI_BAND_UNKNOWN, RF_PTX_AP_ASSUMED);
}

/* ── context ─────────────────────────────────────────────── */

static void test_ctx_frequency_from_channel_and_band(void) {
    rf_ctx_t c;
    rf_ctx_wifi(&c, 6, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.freq_mhz, 2437);
    ASSERT_EQ(c.radio, RF_RADIO_WIFI_2G);
    rf_ctx_wifi(&c, 36, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.freq_mhz, 5180);
    ASSERT_EQ(c.radio, RF_RADIO_WIFI_5G);
    /* 6 GHz channel 37 is 5950 + 5 x 37; a bare 37 would be 5 GHz. */
    rf_ctx_wifi(&c, 37, WIFI_BAND_6GHZ);
    ASSERT_EQ(c.freq_mhz, 6135);
    ASSERT_EQ(c.radio, RF_RADIO_WIFI_6G);
    /* No channel: no frequency, so no estimate later - not a guess. */
    rf_ctx_wifi(&c, 0, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.freq_mhz, 0);
    ASSERT_EQ(c.radio, RF_RADIO_NONE);
}

static void test_ctx_ap_prefers_tpc_then_country_then_assumed(void) {
    reg_ie_t r;
    memset(&r, 0, sizeof(r));
    rf_ctx_t c;
    rf_ctx_ap(&c, &r, 44, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_ASSUMED);
    ASSERT_EQ(c.ptx_dbm, RF_PTX_AP_ASSUMED);

    /* Country "US", subband 36 x 4 at 23 dBm, Power Constraint 3 dB:
     * the local ceiling on channel 44 is 23 - 3 = 20 dBm. */
    r.country_present = 1;
    r.triplet_count = 1;
    r.triplets[0].first_channel = 36;
    r.triplets[0].num_channels  = 4;
    r.triplets[0].max_tx_power_dbm = 23;
    r.power_constraint_present = 1;
    r.power_constraint_db = 3;
    rf_ctx_ap(&c, &r, 44, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_COUNTRY_MAX);
    ASSERT_EQ(c.ptx_dbm, 20);

    /* 52 is past 36 + 3 x 4 = 48, and 38 is not on the 4-channel grid:
     * neither is covered, so neither inherits the ceiling. */
    rf_ctx_ap(&c, &r, 52, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_ASSUMED);
    rf_ctx_ap(&c, &r, 38, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_ASSUMED);

    /* 2.4 GHz subbands step one channel: 1 x 13 covers 6. */
    r.triplets[0].first_channel = 1;
    r.triplets[0].num_channels  = 13;
    r.triplets[0].max_tx_power_dbm = 20;
    r.power_constraint_present = 0;
    int p = 0;
    ASSERT_EQ(rf_country_max_dbm(&r, 6, &p), 1);
    ASSERT_EQ(p, 20);
    ASSERT_EQ(rf_country_max_dbm(&r, 14, &p), 0);

    /* A TPC Report outranks the ceiling: it is the frame's own power. */
    r.tpc_present = 1;
    r.tpc_tx_power_dbm = 14;
    rf_ctx_ap(&c, &r, 6, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_TPC_REPORT);
    ASSERT_EQ(c.ptx_dbm, 14);

    /* A ceiling above the assumed default is not used: US 2.4 GHz
     * allows 30 dBm where an AP typically sends 20, and estimating at
     * 30 would put every such AP 2.3x too far. Seen red with the
     * `p <= RF_PTX_AP_ASSUMED` term removed from rf_ctx_ap(). */
    r.tpc_present = 0;
    r.triplets[0].max_tx_power_dbm = 30;
    rf_ctx_ap(&c, &r, 6, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_ASSUMED);
    ASSERT_EQ(c.ptx_dbm, RF_PTX_AP_ASSUMED);
    r.triplets[0].max_tx_power_dbm = 17;
    rf_ctx_ap(&c, &r, 6, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_COUNTRY_MAX);
    ASSERT_EQ(c.ptx_dbm, 17);

    /* Never on 6 GHz, where the limit is the Transmit Power Envelope's
     * and a 1 x 13 subband read with 2.4 GHz steps would cover 6 GHz
     * channel 5. Seen red with the RF_RADIO_WIFI_6G term removed. */
    rf_ctx_ap(&c, &r, 5, WIFI_BAND_6GHZ);
    ASSERT_EQ(c.radio, RF_RADIO_WIFI_6G);
    ASSERT_EQ(c.freq_mhz, 5975);
    ASSERT_EQ(c.ptx_source, RF_PTX_ASSUMED);
    ASSERT_EQ(c.ptx_dbm, RF_PTX_AP_ASSUMED);
    /* A TPC Report is the frame's own power on any band. */
    r.tpc_present = 1;
    rf_ctx_ap(&c, &r, 5, WIFI_BAND_6GHZ);
    ASSERT_EQ(c.ptx_source, RF_PTX_TPC_REPORT);

    /* An operating triplet carries no power and covers nothing. */
    memset(&r, 0, sizeof(r));
    r.country_present = 1;
    r.triplet_count = 1;
    r.triplets[0].is_operating = 1;
    r.triplets[0].ext_id = 201;
    ASSERT_EQ(rf_country_max_dbm(&r, 1, &p), 0);
    ASSERT_EQ(rf_country_max_dbm(NULL, 1, &p), 0);
}

static void test_ctx_ble_prefers_extended_header(void) {
    rf_ctx_t c;
    rf_ctx_ble(&c, 1, 8, 1, 4);
    ASSERT_EQ(c.ptx_source, RF_PTX_BLE_EXT);
    ASSERT_EQ(c.ptx_dbm, 8);
    ASSERT_EQ(c.freq_mhz, 2440);
    ASSERT_EQ(c.radio, RF_RADIO_BLE);
    rf_ctx_ble(&c, 0, 0, 1, 4);
    ASSERT_EQ(c.ptx_source, RF_PTX_BLE_AD);
    ASSERT_EQ(c.ptx_dbm, 4);
    rf_ctx_ble(&c, 0, 0, 0, 0);
    ASSERT_EQ(c.ptx_source, RF_PTX_ASSUMED);
    ASSERT_EQ(c.ptx_dbm, RF_PTX_BLE_ASSUMED);
}

/* ── arithmetic ──────────────────────────────────────────── */

static void test_median_and_spread(void) {
    /* sorted -90 -62 -61 -60 -58: median -61; |deviations| 29 1 0 1 3,
     * sorted 0 1 1 3 29: MAD 1, x 1.4826 = 1.48 -> 1. The -90 outlier
     * moves neither. */
    const int8_t a[] = { -60, -62, -58, -61, -90 };
    int med = 0, sp = -1;
    ASSERT_EQ(rf_median_spread(a, 5, &med, &sp), 5);
    ASSERT_EQ(med, -61);
    ASSERT_EQ(sp, 1);
    /* Even count: the mean of the middle pair, -60.5, rounds to -61. */
    const int8_t b[] = { -60, -61 };
    ASSERT_EQ(rf_median_spread(b, 2, &med, &sp), 2);
    ASSERT_EQ(med, -61);
    /* -50 -50 -70 -70: median -60, deviations all 10, MAD 10 -> 15. */
    const int8_t c[] = { -50, -70, -50, -70 };
    rf_median_spread(c, 4, &med, &sp);
    ASSERT_EQ(med, -60);
    ASSERT_EQ(sp, 15);
    med = 99;
    ASSERT_EQ(rf_median_spread(a, 0, &med, &sp), 0);
    ASSERT_EQ(med, 99);
    ASSERT_EQ(rf_median_spread(NULL, 3, &med, &sp), 0);
}

static void test_distance_formula_fixed_numbers(void) {
    ASSERT_NEAR(rf_ref_loss_db(2437), 39.737, 0.001);
    ASSERT_NEAR(rf_distance_m(20, -60, 2437, 28, 0.0), 27.413, 0.001);
    /* 5180 MHz, TPC 15 dBm, -50 dBm, N = 30:
     * 10 ^ ((65 - 46.287) / 30) = 4.205 m. */
    ASSERT_NEAR(rf_distance_m(15, -50, 5180, 30, 0.0), 4.205, 0.001);
    /* An offset of 11.834 dB puts -40 dBm at exactly 2 m. */
    ASSERT_NEAR(rf_distance_m(20, -40, 2437, 28, 11.834), 2.0, 0.001);
    /* Unusable inputs are refused, never turned into a distance: an
     * RSSI of 0 would otherwise read 10^((20-39.7)/28) = 0.2 m. Seen
     * red with the rssi_dbm == 0 term removed from rf_distance_m(). */
    ASSERT(rf_distance_m(20, 0, 2437, 28, 0.0) < 0);
    ASSERT(rf_distance_m(20, -60, 0, 28, 0.0) < 0);
    ASSERT(rf_distance_m(20, -60, 2437, 0, 0.0) < 0);
}

static void test_reference_offset(void) {
    /* Model at 2 m: 39.737 + 28 log10 2 = 48.166; measured 20 - (-40)
     * = 60; offset 11.834. */
    double off = 0;
    ASSERT_EQ(rf_ref_offset_db(20, -40, 2437, 28, 2.0, &off), 1);
    ASSERT_NEAR(off, 11.834, 0.001);
    /* 120 dB of path loss at a stated 1 m is an 80 dB "correction":
     * not a gain error, so refused and *off untouched. */
    off = 7.0;
    ASSERT_EQ(rf_ref_offset_db(20, -100, 2437, 28, 1.0, &off), 0);
    ASSERT_NEAR(off, 7.0, 1e-9);
    ASSERT_EQ(rf_ref_offset_db(20, 0, 2437, 28, 1.0, &off), 0);
    ASSERT_EQ(rf_ref_offset_db(20, -40, 2437, 28, 0.0, &off), 0);
}

static void test_band_boundaries(void) {
    ASSERT_EQ(rf_band_of(-1.0),  RF_DIST_NONE);
    ASSERT_EQ(rf_band_of(0.99),  RF_DIST_IMMEDIATE);
    ASSERT_EQ(rf_band_of(1.0),   RF_DIST_NEAR);
    ASSERT_EQ(rf_band_of(2.99),  RF_DIST_NEAR);
    ASSERT_EQ(rf_band_of(3.0),   RF_DIST_ROOM);
    ASSERT_EQ(rf_band_of(9.99),  RF_DIST_ROOM);
    ASSERT_EQ(rf_band_of(10.0),  RF_DIST_BUILDING);
    ASSERT_EQ(rf_band_of(29.99), RF_DIST_BUILDING);
    ASSERT_EQ(rf_band_of(30.0),  RF_DIST_FAR);
}

static void test_band_hysteresis(void) {
    /* 3 dB at N = 2.8 is a factor of 10 ^ (3 / 28) = 1.2794: leaving
     * "room" outward needs 12.79 m, inward from "building" 7.82 m. */
    ASSERT_EQ(rf_band_hyst(RF_DIST_ROOM, 10.5, 3.0, 28), RF_DIST_ROOM);
    ASSERT_EQ(rf_band_hyst(RF_DIST_ROOM, 12.7, 3.0, 28), RF_DIST_ROOM);
    ASSERT_EQ(rf_band_hyst(RF_DIST_ROOM, 12.9, 3.0, 28), RF_DIST_BUILDING);
    ASSERT_EQ(rf_band_hyst(RF_DIST_BUILDING, 7.9, 3.0, 28), RF_DIST_BUILDING);
    ASSERT_EQ(rf_band_hyst(RF_DIST_BUILDING, 7.7, 3.0, 28), RF_DIST_ROOM);
    /* A wider margin holds further: 6 dB is 1.6379, so 12.9 m stays. */
    ASSERT_EQ(rf_band_hyst(RF_DIST_ROOM, 12.9, 6.0, 28), RF_DIST_ROOM);
    ASSERT_EQ(rf_band_hyst(RF_DIST_ROOM, 16.5, 6.0, 28), RF_DIST_BUILDING);
    /* A jump lands where it lands, not one band at a time. */
    ASSERT_EQ(rf_band_hyst(RF_DIST_IMMEDIATE, 50.0, 3.0, 28), RF_DIST_FAR);
    ASSERT_EQ(rf_band_hyst(RF_DIST_FAR, 0.5, 3.0, 28), RF_DIST_IMMEDIATE);
    ASSERT_EQ(rf_band_hyst(RF_DIST_NONE, 10.5, 3.0, 28), RF_DIST_BUILDING);

    /* The margin: the floor, until two standard errors of the median
     * exceed it. spread 6 over 8 samples: 2 x 1.2533 x 6 / 2.8284 =
     * 5.317 dB; spread 2 over 8 is 1.77, under the 3 dB floor. */
    ASSERT_NEAR(rf_band_hyst_db(6, 8), 5.317, 0.001);
    ASSERT_NEAR(rf_band_hyst_db(2, 8), RF_BAND_HYST_DB, 1e-9);
    ASSERT_NEAR(rf_band_hyst_db(0, 0), RF_BAND_HYST_DB, 1e-9);
}

/* The hold. K = 1 so each sample is the median and its spread is 0:
 * the margin is the 3 dB floor and only the hold is under test. At an
 * AP assumed 20 dBm on channel 6, -60 dBm is 27.4 m (building) and
 * -44 dBm 7.36 m (room, past the 7.82 m inward margin). */
static void test_track_band_change_is_held(void) {
    tune_reset();
    rf_calibration_reset();
    char err[160];
    ASSERT_EQ(tune_set("rf.median_k=1", err, sizeof(err)), 0);
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_track_observe(&t, -60, T0, &c);
    ASSERT_EQ(t.band, RF_DIST_BUILDING);        /* the first takes at once */
    for (int i = 1; i < RF_BAND_HOLD_S; i++) {
        rf_track_observe(&t, -44, T0 + i, &c);
        ASSERT_EQ(t.band, RF_DIST_BUILDING);
    }
    rf_track_observe(&t, -44, T0 + RF_BAND_HOLD_S + 1, &c);
    ASSERT_EQ(t.band, RF_DIST_ROOM);
    ASSERT_EQ(t.band_cand, RF_DIST_NONE);

    /* One sample back inside the old band restarts the hold. Seen red
     * with the `want == prev` reset removed from band_step(): the five
     * seconds before the -60 carried over and the band moved at T0 + 12. */
    memset(&t, 0, sizeof(t));
    rf_track_observe(&t, -60, T0, &c);
    rf_track_observe(&t, -44, T0 + 1, &c);
    rf_track_observe(&t, -44, T0 + 6, &c);
    rf_track_observe(&t, -60, T0 + 7, &c);
    rf_track_observe(&t, -44, T0 + 8, &c);
    rf_track_observe(&t, -44, T0 + 12, &c);
    ASSERT_EQ(t.band, RF_DIST_BUILDING);
    rf_track_observe(&t, -44, T0 + 8 + RF_BAND_HOLD_S, &c);
    ASSERT_EQ(t.band, RF_DIST_ROOM);

    /* A clock stepping back adds nothing to the hold, and stalls it
     * neither: the next forward seconds count. */
    memset(&t, 0, sizeof(t));
    rf_track_observe(&t, -60, T0 + 100, &c);
    rf_track_observe(&t, -44, T0 + 101, &c);
    rf_track_observe(&t, -44, T0 + 50, &c);
    ASSERT_EQ(t.band, RF_DIST_BUILDING);
    rf_track_observe(&t, -44, T0 + 50 + RF_BAND_HOLD_S, &c);
    ASSERT_EQ(t.band, RF_DIST_ROOM);
    tune_reset();
}

static void test_slope_and_trend_hysteresis(void) {
    const int8_t y[] = { -70, -68, -66, -64 };
    const time_t x[] = { T0, T0 + 2, T0 + 4, T0 + 6 };
    ASSERT_NEAR(rf_slope_db10(y, x, 4), 10.0, 1e-9);   /* 1 dB/s */
    ASSERT_NEAR(rf_slope_db10(y, x, 1), 0.0, 1e-9);
    const time_t same[] = { T0, T0, T0, T0 };
    ASSERT_NEAR(rf_slope_db10(y, same, 4), 0.0, 1e-9);

    ASSERT_EQ(rf_trend_hyst(RF_TREND_UNKNOWN, 3.0, 1), RF_TREND_APPROACHING);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_STEADY, 2.9, 1), RF_TREND_STEADY);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_APPROACHING, 2.0, 1), RF_TREND_APPROACHING);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_APPROACHING, 1.4, 1), RF_TREND_STEADY);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_APPROACHING, -3.0, 1), RF_TREND_LEAVING);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_LEAVING, -1.5, 1), RF_TREND_LEAVING);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_LEAVING, 0.0, 1), RF_TREND_STEADY);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_LEAVING, 3.0, 1), RF_TREND_APPROACHING);
    ASSERT_EQ(rf_trend_hyst(RF_TREND_APPROACHING, 9.0, 0), RF_TREND_UNKNOWN);
}

static void test_quantise(void) {
    ASSERT_NEAR(rf_quantise_m(4.26), 4.5, 1e-9);
    ASSERT_NEAR(rf_quantise_m(4.24), 4.0, 1e-9);
    ASSERT_NEAR(rf_quantise_m(27.41), 27.0, 1e-9);
    ASSERT_NEAR(rf_quantise_m(154.0), 150.0, 1e-9);
    ASSERT_NEAR(rf_quantise_m(155.0), 160.0, 1e-9);
}

/* ── the track ───────────────────────────────────────────── */

static void test_track_first_sample_fixed_numbers(void) {
    tune_reset();
    rf_calibration_reset();
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);
    rf_track_observe(&t, -60, T0, &c);
    ASSERT_EQ(t.valid, 1);
    ASSERT_EQ(t.est_dm, 274);    /* 27.41 m */
    ASSERT_EQ(t.lo_dm, 120);     /* 12.05 m */
    ASSERT_EQ(t.hi_dm, 624);     /* 62.39 m */
    ASSERT_EQ(t.band, RF_DIST_BUILDING);
    ASSERT_EQ(t.trend, RF_TREND_UNKNOWN);
    ASSERT_EQ(t.ptx_source, RF_PTX_ASSUMED);
    ASSERT_EQ(t.rssi_med, -60);
    ASSERT_EQ(t.samples, 1);
    ASSERT_EQ(t.calibrated, 0);
    ASSERT_EQ(t.radio, RF_RADIO_WIFI_2G);
}

static void test_track_announced_power_narrows_the_interval(void) {
    tune_reset();
    rf_calibration_reset();
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    reg_ie_t r;
    memset(&r, 0, sizeof(r));
    r.tpc_present = 1;
    r.tpc_tx_power_dbm = 15;
    rf_ctx_t c;
    rf_ctx_ap(&c, &r, 36, WIFI_BAND_UNKNOWN);
    rf_track_observe(&t, -50, T0, &c);
    /* 4.205 m; sigma 12 alone (no assumed term), N 30: x/ 2.512 ->
     * 1.674 .. 10.563 m. */
    ASSERT_EQ(t.est_dm, 42);
    ASSERT_EQ(t.lo_dm, 17);
    ASSERT_EQ(t.hi_dm, 106);
    ASSERT_EQ(t.band, RF_DIST_ROOM);
    ASSERT_EQ(t.ptx_source, RF_PTX_TPC_REPORT);
}

/* A Country ceiling is an upper bound on P_tx, so the distance it
 * gives is one too: the AP may be nearer, never farther. Channel 6,
 * ceiling 20 dBm, -60 dBm: 27.41 m as for the assumed case, but only
 * the low side carries the 6 dB term - hi is 27.41 x 10 ^ (8 / 28) =
 * 52.92 m where the assumed case reaches 62.39 m; lo stays 12.05 m.
 * Seen red with the term added to both sides (hi read 624). */
static void test_track_country_ceiling_widens_downward_only(void) {
    tune_reset();
    rf_calibration_reset();
    reg_ie_t r;
    memset(&r, 0, sizeof(r));
    r.country_present = 1;
    r.triplet_count = 1;
    r.triplets[0].first_channel = 1;
    r.triplets[0].num_channels  = 13;
    r.triplets[0].max_tx_power_dbm = 20;
    rf_ctx_t c;
    rf_ctx_ap(&c, &r, 6, WIFI_BAND_UNKNOWN);
    ASSERT_EQ(c.ptx_source, RF_PTX_COUNTRY_MAX);
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_track_observe(&t, -60, T0, &c);
    ASSERT_EQ(t.est_dm, 274);
    ASSERT_EQ(t.lo_dm, 120);
    ASSERT_EQ(t.hi_dm, 529);
    ASSERT_EQ(t.ptx_source, RF_PTX_COUNTRY_MAX);
}

/* RSSI 0 is "unseen" on every Wi-Fi row. It must not enter the ring:
 * after -60 then seven zeros, a -70 has to give the median of -60 and
 * -70 (-65), not the median of a ring of zeros. Seen red with the
 * rssi_dbm == 0 term removed from rf_track_observe(): the zeros went
 * in, the median was 0, the estimate was refused and rssi_med stayed
 * -60. (On a fresh track the two guards overlap - rf_distance_m()
 * refuses a 0 median too - so "0 gives no estimate" is asserted here
 * on both, and each guard's own red is the one named at it.) */
static void test_track_zero_rssi_is_no_sample(void) {
    tune_reset();
    rf_calibration_reset();
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);
    rf_track_observe(&t, 0, T0, &c);
    ASSERT_EQ(t.valid, 0);
    ASSERT_EQ(t.raw_n, 0);
    rf_track_observe(&t, -60, T0, &c);
    for (int i = 0; i < 7; i++) rf_track_observe(&t, 0, T0 + 1, &c);
    ASSERT_EQ(t.raw_n, 1);
    rf_track_observe(&t, -70, T0 + 2, &c);
    ASSERT_EQ(t.rssi_med, -65);
    ASSERT_EQ(t.samples, 2);
    /* Out of the HCI range: not a sample either. */
    rf_track_observe(&t, 21, T0 + 3, &c);
    rf_track_observe(&t, -128, T0 + 3, &c);
    ASSERT_EQ(t.raw_n, 2);
}

static void test_track_without_frequency_is_no_estimate(void) {
    tune_reset();
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_ctx_t c;
    rf_ctx_assumed(&c, 0, WIFI_BAND_UNKNOWN, 15);
    rf_track_observe(&t, -60, T0, &c);
    ASSERT_EQ(t.valid, 0);
    ASSERT_EQ(t.raw_n, 0);
}

static void test_track_median_k_and_window(void) {
    tune_reset();
    rf_calibration_reset();
    char err[160];
    ASSERT_EQ(tune_set("rf.median_k=3", err, sizeof(err)), 0);
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);
    rf_track_observe(&t, -50, T0, &c);
    rf_track_observe(&t, -60, T0, &c);
    rf_track_observe(&t, -70, T0, &c);
    rf_track_observe(&t, -80, T0, &c);
    /* The newest three: -60 -70 -80. */
    ASSERT_EQ(t.rssi_med, -70);
    ASSERT_EQ(t.samples, 3);
    ASSERT_EQ(t.spread_db, 15);   /* MAD 10 */

    /* A sample 61 s after the rest stands alone: the window is 60 s
     * from the newest sample. */
    tune_reset();
    rf_track_observe(&t, -40, T0 + RF_WINDOW_S + 1, &c);
    ASSERT_EQ(t.samples, 1);
    ASSERT_EQ(t.rssi_med, -40);
    tune_reset();
}

static void test_track_trend_series(void) {
    tune_reset();
    rf_calibration_reset();
    char err[160];
    /* K = 1 so each trend point is the raw sample and the slope is the
     * series' own: 2 dB every 2 s = 10 dB per 10 s. */
    ASSERT_EQ(tune_set("rf.median_k=1", err, sizeof(err)), 0);
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);

    rf_track_t t;
    memset(&t, 0, sizeof(t));
    for (int i = 0; i < 3; i++) rf_track_observe(&t, -80 + 2 * i, T0 + 2 * i, &c);
    ASSERT_EQ(t.trend, RF_TREND_UNKNOWN);     /* three points, 4 s */
    rf_track_observe(&t, -74, T0 + 6, &c);
    ASSERT_EQ(t.trend, RF_TREND_APPROACHING);

    memset(&t, 0, sizeof(t));
    for (int i = 0; i < 6; i++) rf_track_observe(&t, -50 - 2 * i, T0 + 2 * i, &c);
    ASSERT_EQ(t.trend, RF_TREND_LEAVING);

    memset(&t, 0, sizeof(t));
    for (int i = 0; i < 6; i++) rf_track_observe(&t, -60, T0 + 2 * i, &c);
    ASSERT_EQ(t.trend, RF_TREND_STEADY);

    /* Samples inside one 2 s step make one point, not four. */
    memset(&t, 0, sizeof(t));
    for (int i = 0; i < 6; i++) rf_track_observe(&t, -80 + 2 * i, T0 + (i / 4), &c);
    ASSERT_EQ(t.pt_n, 1);
    ASSERT_EQ(t.trend, RF_TREND_UNKNOWN);
    tune_reset();
}

static void test_calibration_from_my_bssid(void) {
    tune_reset();
    rf_calibration_reset();
    ownership_clear();
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    beacon_ap_t *ap = &s.beacon_aps[0];
    const uint8_t mine[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
    memcpy(ap->bssid, mine, 6);
    ap->channel = 6;
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);
    rf_track_observe(&ap->dist, -40, T0, &c);
    s.beacon_count = 1;

    /* Off by default, and an unowned AP calibrates nothing. */
    rf_calibration_update(&s);
    ASSERT_EQ(rf_calibration_get(RF_RADIO_WIFI_2G, NULL), 0);
    char err[160];
    ASSERT_EQ(tune_set("rf.ref_dist_dm=20", err, sizeof(err)), 0);
    rf_calibration_update(&s);
    ASSERT_EQ(rf_calibration_get(RF_RADIO_WIFI_2G, NULL), 0);

    ASSERT_EQ(ownership_add_bssid("02:aa:bb:cc:dd:01"), 1);
    rf_calibration_update(&s);
    double off = 0;
    ASSERT_EQ(rf_calibration_get(RF_RADIO_WIFI_2G, &off), 1);
    ASSERT_NEAR(off, 11.834, 0.001);
    ASSERT_EQ(rf_calibration_get(RF_RADIO_WIFI_5G, NULL), 0);
    ASSERT_EQ(rf_calibration_get(RF_RADIO_BLE, NULL), 0);

    /* The reference AP now reads its stated 2 m, and says calibrated. */
    rf_track_t t;
    memset(&t, 0, sizeof(t));
    rf_track_observe(&t, -40, T0, &c);
    ASSERT_EQ(t.est_dm, 20);
    ASSERT_EQ(t.calibrated, 1);
    /* BLE is a different receiver: a Wi-Fi offset never reaches it. */
    rf_ctx_t b;
    rf_ctx_ble(&b, 0, 0, 0, 0);
    memset(&t, 0, sizeof(t));
    rf_track_observe(&t, -55, T0, &b);
    ASSERT_EQ(t.calibrated, 0);
    ASSERT_EQ(t.est_dm, 35);    /* 3.505 m uncalibrated */

    /* Knob back to 0: cleared on the next poll. */
    tune_reset();
    rf_calibration_update(&s);
    ASSERT_EQ(rf_calibration_get(RF_RADIO_WIFI_2G, NULL), 0);
    ownership_clear();
    rf_calibration_reset();
}

/* ── labels and cells ────────────────────────────────────── */

static void fill(rf_track_t *t, uint16_t dm, int band, int trend) {
    memset(t, 0, sizeof(*t));
    t->valid = 1; t->est_dm = dm; t->lo_dm = dm / 2; t->hi_dm = dm * 2;
    t->band = (uint8_t)band; t->trend = (uint8_t)trend;
    t->ptx_source = RF_PTX_ASSUMED; t->ptx_dbm = 20;
}

static void test_cells(void) {
    rf_track_t t;
    char b[64];
    fill(&t, 274, RF_DIST_BUILDING, RF_TREND_APPROACHING);
    ASSERT_EQ(rf_dist_cell(&t, b, sizeof(b), RF_CELL_FULL), RF_CELL_FULL);
    ASSERT_STR(b, "~27m bldg \xe2\x86\x98 ");
    ASSERT_EQ(rf_dist_cell(&t, b, sizeof(b), RF_CELL_SHORT), RF_CELL_SHORT);
    ASSERT_STR(b, "~27m\xe2\x86\x98 ");
    fill(&t, 5, RF_DIST_IMMEDIATE, RF_TREND_UNKNOWN);
    rf_dist_cell(&t, b, sizeof(b), RF_CELL_FULL);
    ASSERT_STR(b, "~<1m imm    ");
    fill(&t, 20000, RF_DIST_FAR, RF_TREND_LEAVING);
    rf_dist_cell(&t, b, sizeof(b), RF_CELL_FULL);
    ASSERT_STR(b, "~>1km far \xe2\x86\x97 ");
    t.valid = 0;
    ASSERT_EQ(rf_dist_cell(&t, b, sizeof(b), RF_CELL_SHORT), RF_CELL_SHORT);
    ASSERT_STR(b, "-     ");
    ASSERT_EQ(rf_dist_cell(NULL, b, sizeof(b), 3), RF_CELL_SHORT);

    /* The detail line from a real track, not hand-set bounds: an AP
     * assumed 20 dBm on channel 6 heard steadily at -38 dBm is
     * 10 ^ (18.263 / 28) = 4.49 m, and the assumed-power interval
     * (10 dB, x/ 2.2758) is 1.97 .. 10.22 m. */
    tune_reset();
    rf_calibration_reset();
    rf_ctx_t c;
    ctx_ap_assumed_6(&c);
    memset(&t, 0, sizeof(t));
    for (int i = 0; i < 4; i++) rf_track_observe(&t, -38, T0 + 2 * i, &c);
    rf_dist_describe(&t, b, sizeof(b));
    ASSERT_STR(b, "~4.5m (2.0-10m) room steady, Ptx 20 assumed");
    reg_ie_t r;
    memset(&r, 0, sizeof(r));
    r.country_present = 1;
    r.triplet_count = 1;
    r.triplets[0].first_channel = 1;
    r.triplets[0].num_channels  = 13;
    r.triplets[0].max_tx_power_dbm = 20;
    rf_ctx_ap(&c, &r, 6, WIFI_BAND_UNKNOWN);
    memset(&t, 0, sizeof(t));
    for (int i = 0; i < 4; i++) rf_track_observe(&t, -38, T0 + 2 * i, &c);
    t.calibrated = 1;
    rf_dist_describe(&t, b, sizeof(b));
    ASSERT_STR(b, "~4.5m (2.0-8.7m) room steady, Ptx 20 ceiling cal");
    t.valid = 0;
    rf_dist_describe(&t, b, sizeof(b));
    ASSERT_STR(b, "no estimate");
}

static void test_labels(void) {
    ASSERT_STR(rf_band_name(RF_DIST_IMMEDIATE), "immediate");
    ASSERT_STR(rf_band_name(RF_DIST_BUILDING), "building");
    ASSERT_STR(rf_band_name(RF_DIST_NONE), "");
    ASSERT_STR(rf_trend_name(RF_TREND_APPROACHING), "approaching");
    ASSERT_STR(rf_trend_name(RF_TREND_UNKNOWN), "unknown");
    ASSERT_STR(rf_ptx_source_name(RF_PTX_TPC_REPORT), "tpc_report");
    ASSERT_STR(rf_ptx_source_name(RF_PTX_COUNTRY_MAX), "country_max");
    ASSERT_STR(rf_ptx_source_name(RF_PTX_BLE_EXT), "ble_ext_tx_power");
    ASSERT_STR(rf_ptx_source_name(RF_PTX_BLE_AD), "ble_ad_tx_power");
    ASSERT_STR(rf_ptx_source_name(RF_PTX_ASSUMED), "assumed");
}

static void test_tune_knobs_bounded(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_val(TUNE_RF_PATH_LOSS_N_2G), RF_N_2G_X10);
    ASSERT_EQ(tune_val(TUNE_RF_PATH_LOSS_N_5G), RF_N_5G_X10);
    ASSERT_EQ(tune_val(TUNE_RF_REF_DIST_DM), 0);
    ASSERT_EQ(tune_set("rf.path_loss_n_2g=15", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("rf.path_loss_n_2g=61", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("rf.median_k=17", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("rf.median_k=0", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("rf.path_loss_n_2g=40", err, sizeof(err)), 0);
    /* N = 4.0: 10 ^ (40.263 / 40) = 10.15 m for the 27.41 m case. */
    ASSERT_NEAR(rf_distance_m(20, -60, 2437, rf_n_x10(RF_RADIO_WIFI_2G), 0), 10.15, 0.01);
    ASSERT_EQ(rf_n_x10(RF_RADIO_BLE), 40);
    tune_reset();
}

/* ── JSONL ───────────────────────────────────────────────── */

static char g_tmp[TEST_TMP_MAX];

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_tmp, sizeof(g_tmp), "sloth_rfdist_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_tmp);
    ASSERT(jsonl_open(g_tmp));
}

static char *jl_read(void) {
    static char buf[65536];
    FILE *fp = fopen(g_tmp, "r");
    size_t n = 0;
    if (fp) { n = fread(buf, 1, sizeof(buf) - 1, fp); fclose(fp); }
    buf[n] = '\0';
    return buf;
}

static int count_str(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

/* The fields ride on the record with the RSSI, quantised, and are
 * absent - not zero - with no estimate. Seen red with the !t->valid
 * return removed from emit_dist(): the invalid row then carried
 * "est_dist_m":0.00. */
static void test_jsonl_fields_present_only_with_an_estimate(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    jl_open();
    s.probe_count = 2;
    probe_client_t *p = &s.probe_clients[0];
    p->mac[0] = 0x02; p->mac[5] = 1;
    fill(&p->dist, 274, RF_DIST_BUILDING, RF_TREND_LEAVING);
    s.probe_clients[1].mac[0] = 0x02;
    s.probe_clients[1].mac[5] = 2;
    jsonl_emit_probe_clients(&s);
    char *out = jl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"probe_client\""), 2);
    ASSERT_EQ(count_str(out, "\"est_dist_m\":"), 1);
    ASSERT(strstr(out, "\"est_dist_m\":27.00") != NULL);
    ASSERT(strstr(out, "\"est_dist_band\":\"building\"") != NULL);
    ASSERT(strstr(out, "\"est_dist_trend\":\"leaving\"") != NULL);
    ASSERT(strstr(out, "\"est_ptx_source\":\"assumed\"") != NULL);
    ASSERT_EQ(count_str(out, "\"est_dist_band\""), 1);
    jsonl_close();
    unlink(g_tmp);
}

static void test_jsonl_beacon_assoc_device_carry_the_fields(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    jl_open();
    s.beacon_count = 1;
    fill(&s.beacon_aps[0].dist, 42, RF_DIST_ROOM, RF_TREND_STEADY);
    s.beacon_aps[0].dist.ptx_source = RF_PTX_TPC_REPORT;
    s.assoc_count = 1;
    fill(&s.assocs[0].dist, 95, RF_DIST_ROOM, RF_TREND_UNKNOWN);
    s.device_count = 1;
    fill(&s.devices[0].dist, 7, RF_DIST_IMMEDIATE, RF_TREND_APPROACHING);
    jsonl_emit_beacons(&s);
    jsonl_emit_assocs(&s);
    jsonl_emit_devices(&s);
    char *out = jl_read();
    ASSERT(strstr(out, "\"est_dist_m\":4.00,\"est_dist_band\":\"room\",\"est_dist_trend\":\"steady\",\"est_ptx_source\":\"tpc_report\"") != NULL);
    ASSERT(strstr(out, "\"est_dist_m\":9.50,\"est_dist_band\":\"room\",\"est_dist_trend\":\"unknown\"") != NULL);
    ASSERT(strstr(out, "\"est_dist_m\":0.50,\"est_dist_band\":\"immediate\",\"est_dist_trend\":\"approaching\"") != NULL);
    jsonl_close();
    unlink(g_tmp);
}

/* ble_device is change-only. The estimate's metres move on every
 * report and must never write a record; nor does its trend, which is
 * written but not signed. Its band may. The metres half is seen red
 * with d->dist.est_dm added to the signature bytes (a second record
 * per metre change); the trend half with the approaching / leaving
 * byte put back (a record for the trend change). */
static void test_jsonl_ble_signature_bands_the_distance(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    jl_open();
    s.ble_device_count = 1;
    ble_device_t *d = &s.ble_devices[0];
    d->addr[0] = 0xc2; d->addr[5] = 7;
    d->has_rssi = 1; d->rssi = -60; d->rssi_best = -60;
    snprintf(d->sensor_iface, sizeof(d->sensor_iface), "bluetooth-monitor");
    fill(&d->dist, 40, RF_DIST_ROOM, RF_TREND_STEADY);
    jsonl_emit_ble_devices(&s);
    d->dist.est_dm = 55;     /* 5.5 m, still room, still steady */
    jsonl_emit_ble_devices(&s);
    d->dist.est_dm = 80;
    jsonl_emit_ble_devices(&s);
    char *out = jl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 1);
    d->dist.trend = RF_TREND_LEAVING;
    jsonl_emit_ble_devices(&s);
    d->dist.trend = RF_TREND_APPROACHING;
    jsonl_emit_ble_devices(&s);
    out = jl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 1);

    d->dist.band = RF_DIST_BUILDING;
    jsonl_emit_ble_devices(&s);
    out = jl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 2);
    /* The trend still rides the record the band change wrote. */
    ASSERT(strstr(out, "\"est_dist_trend\":\"approaching\"") != NULL);
    jsonl_close();
    unlink(g_tmp);
}

/* A stationary advertiser under ordinary RSSI noise rides the 300 s
 * heartbeat: one record, then one per heartbeat, over an hour. Each
 * case sits its mean on a band boundary, where noise moves the median
 * across the line most often - room/building at 10 m (-67.75 dBm),
 * near/room at 3 m (-53.08) and building/far at 30 m (-81.11), for a
 * BLE row with an AD TX power of 0 dBm (L(1 m) at 2440 MHz is 39.75 dB,
 * N 2.8). 10 advertisements a second, Gaussian sigma 6 dB from a fixed
 * seed, so the run is the same every time.
 *
 * Seen red before the band hysteresis was sized from the median's
 * spread and held for RF_BAND_HOLD_S, and the trend left the signature:
 * each 10/s case wrote over 1,300 records in the hour. Each part is
 * also seen red alone: the trend put back in the signature, ~260 per
 * case; RF_BAND_HOLD_S 0, ~560; RF_BAND_HYST_SE 0 (the 3 dB floor
 * only), the two 1/s cases at 18-19 while the 10/s ones held. */
static uint32_t g_rng;
static double rng_gauss(void) {
    /* Irwin-Hall: twelve uniforms less six, sigma 1. */
    double sum = 0;
    for (int i = 0; i < 12; i++) {
        g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
        sum += (double)(g_rng >> 8) / 16777216.0;
    }
    return sum - 6.0;
}

static time_t g_fake_now;
static time_t fake_wall(void) { return g_fake_now; }

static int count_lines_of(const char *needle) {
    FILE *fp = fopen(g_tmp, "r");
    if (!fp) return -1;
    static char line[16384];
    int n = 0;
    while (fgets(line, sizeof(line), fp))
        if (strstr(line, needle)) n++;
    fclose(fp);
    return n;
}

static int stationary_hour(double mean_dbm, int per_s, double sd_db, uint8_t id) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    jl_open();
    s.ble_device_count = 1;
    ble_device_t *d = &s.ble_devices[0];
    d->addr[0] = 0xc2; d->addr[5] = id;
    d->has_tx_power = 1; d->tx_power = 0;
    d->has_rssi = 1; d->rssi_best = -40;
    snprintf(d->sensor_iface, sizeof(d->sensor_iface), "bluetooth-monitor");
    rf_ctx_t c;
    rf_ctx_ble(&c, 0, 0, 1, 0);
    g_rng = 0x9e3779b9u ^ id;
    for (int sec = 0; sec < 3600; sec++) {
        g_fake_now = T0 + sec;
        for (int k = 0; k < per_s; k++) {
            double x = mean_dbm + sd_db * rng_gauss();
            int r = (int)(x < 0 ? x - 0.5 : x + 0.5);
            if (r == 0) r = -1;
            d->rssi = (int8_t)r;
            rf_track_observe(&d->dist, r, g_fake_now, &c);
        }
        jsonl_emit_ble_devices(&s);
    }
    jsonl_close();
    int n = count_lines_of("\"type\":\"ble_device\"");
    unlink(g_tmp);
    return n;
}

static void test_jsonl_ble_stationary_noise_rides_the_heartbeat(void) {
    tune_reset();
    rf_calibration_reset();
    sloth_clock_test_set(NULL, fake_wall);
    /* The heartbeat alone writes 12: the first record, then one each
     * 300 s up to 3300. A few more are allowed, not a rate. */
    const int beat = 12, budget = beat + 4;
    int a = stationary_hour(-68.0, 10, 6.0, 1);
    int b = stationary_hour(-53.0, 10, 6.0, 2);
    int f = stationary_hour(-81.0, 10, 6.0, 3);
    /* One advertisement a second at sigma 8: eight samples now span
     * eight seconds, so consecutive medians share most of their
     * samples and a noisy excursion can outlast the hold. This is the
     * case the spread-sized margin is for. */
    int g = stationary_hour(-81.0, 1, 8.0, 4);
    int h = stationary_hour(-53.0, 1, 8.0, 5);
    if (a < beat || a > budget || b < beat || b > budget || f < beat || f > budget ||
        g < beat || g > budget || h < beat || h > budget)
        fprintf(stderr, "    stationary hour: 10/s sd 6: room/bldg %d, near/room %d, "
                "bldg/far %d; 1/s sd 8: bldg/far %d, near/room %d records\n",
                a, b, f, g, h);
    ASSERT(a >= beat && a <= budget);
    ASSERT(b >= beat && b <= budget);
    ASSERT(f >= beat && f <= budget);
    ASSERT(g >= beat && g <= budget);
    ASSERT(h >= beat && h <= budget);
    sloth_clock_test_set(NULL, NULL);
}

void run_rf_distance_tests(void) {
    TEST_SUITE("rf distance: context");
    RUN_TEST(test_ctx_frequency_from_channel_and_band);
    RUN_TEST(test_ctx_ap_prefers_tpc_then_country_then_assumed);
    RUN_TEST(test_ctx_ble_prefers_extended_header);

    TEST_SUITE("rf distance: arithmetic (P.1238-10 eq. 1, fixed numbers)");
    RUN_TEST(test_median_and_spread);
    RUN_TEST(test_distance_formula_fixed_numbers);
    RUN_TEST(test_reference_offset);
    RUN_TEST(test_band_boundaries);
    RUN_TEST(test_band_hysteresis);
    RUN_TEST(test_slope_and_trend_hysteresis);
    RUN_TEST(test_quantise);

    TEST_SUITE("rf distance: the per-row track");
    RUN_TEST(test_track_first_sample_fixed_numbers);
    RUN_TEST(test_track_announced_power_narrows_the_interval);
    RUN_TEST(test_track_country_ceiling_widens_downward_only);
    RUN_TEST(test_track_zero_rssi_is_no_sample);
    RUN_TEST(test_track_without_frequency_is_no_estimate);
    RUN_TEST(test_track_median_k_and_window);
    RUN_TEST(test_track_trend_series);
    RUN_TEST(test_track_band_change_is_held);
    RUN_TEST(test_calibration_from_my_bssid);
    RUN_TEST(test_tune_knobs_bounded);

    TEST_SUITE("rf distance: cells, labels, JSONL");
    RUN_TEST(test_cells);
    RUN_TEST(test_labels);
    RUN_TEST(test_jsonl_fields_present_only_with_an_estimate);
    RUN_TEST(test_jsonl_beacon_assoc_device_carry_the_fields);
    RUN_TEST(test_jsonl_ble_signature_bands_the_distance);
    RUN_TEST(test_jsonl_ble_stationary_noise_rides_the_heartbeat);
}
