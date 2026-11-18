#include "runner.h"
#include "df.h"
#include <string.h>

static const uint8_t TX_A[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
static const uint8_t TX_B[6] = {0x02,0xBB,0xCC,0xDD,0xEE,0xFF};
static const uint8_t GROUP[6] = {0x01,0x00,0x5E,0x00,0x00,0x01};

/* Three radios on a 2 m baseline, 1 m apart: the beta-site row. */
static void three_in_a_row(void) {
    df_reset();
    ASSERT_EQ(df_radio_add("alfa0", 1, 0.0), 0);
    ASSERT_EQ(df_radio_add("alfa1", 1, 1.0), 1);
    ASSERT_EQ(df_radio_add("alfa2", 1, 2.0), 2);
}

static void feed(int radio, const uint8_t *mac, int rssi, int n, time_t t) {
    for (int i = 0; i < n; i++) df_note(radio, mac, rssi, 6, t);
}

static void test_spec_parses_name_and_metres(void) {
    char n[16]; int hp; double p;
    ASSERT_EQ(df_parse_spec("alfa1", n, sizeof(n), &hp, &p), 1);
    ASSERT_STR(n, "alfa1");
    ASSERT_EQ(hp, 0);
    ASSERT_EQ(df_parse_spec("alfa2@1.5", n, sizeof(n), &hp, &p), 1);
    ASSERT_STR(n, "alfa2");
    ASSERT(hp == 1 && p > 1.4999 && p < 1.5001);
    ASSERT_EQ(df_parse_spec("alfa2@-0.5", n, sizeof(n), &hp, &p), 1);
    ASSERT(p < -0.4999 && p > -0.5001);
    ASSERT_EQ(df_parse_spec("", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("@1", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("alfa1@", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("alfa1@1m", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("alfa1@nan", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("alfa1@5000", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("a/b", n, sizeof(n), &hp, &p), 0);
    ASSERT_EQ(df_parse_spec("sixteen-chars-xx", n, sizeof(n), &hp, &p), 0);
}

static void test_radio_table_is_bounded_and_unique(void) {
    df_reset();
    ASSERT_EQ(df_radio_add("r0", 0, 0), 0);
    ASSERT_EQ(df_radio_add("r0", 0, 0), -1);         /* twice */
    ASSERT_EQ(df_radio_add("", 0, 0), -1);
    ASSERT_EQ(df_radio_add("r1", 0, 0), 1);
    ASSERT_EQ(df_radio_add("r2", 0, 0), 2);
    ASSERT_EQ(df_radio_add("r3", 0, 0), 3);
    ASSERT_EQ(df_radio_add("r4", 0, 0), -1);         /* DF_MAX_RADIOS */
    ASSERT_EQ(df_radio_count(), DF_MAX_RADIOS);
    ASSERT_EQ(df_radio_find("r2"), 2);
    ASSERT_EQ(df_radio_find("nope"), -1);
}

/* One radio is no direction: the single-radio sensor's every
 * transmitter reads `none` and is not in the snapshot. */
static void test_one_radio_says_nothing(void) {
    three_in_a_row();
    feed(0, TX_A, -50, 10, 1000);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.heard_by, 1);
    ASSERT_EQ(e.quality, DF_NONE);
    ASSERT_EQ(e.has_along, 0);
    df_est_t out[4];
    ASSERT_EQ(df_snapshot(out, 4, 1000), 0);
}

/* Loud at the 0 m end, 20 dB down at the 2 m end: a lean toward radio
 * 0, and a point along the baseline well inside its half. */
static void test_lean_toward_the_loud_end(void) {
    three_in_a_row();
    feed(0, TX_A, -40, 5, 1000);
    feed(1, TX_A, -52, 5, 1000);
    feed(2, TX_A, -60, 5, 1000);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.heard_by, 3);
    ASSERT_EQ(e.best_radio, 0);
    ASSERT(e.margin_db > 19.99 && e.margin_db < 20.01);
    ASSERT_EQ(e.quality, DF_LEAN);
    ASSERT_EQ(e.has_along, 1);
    /* Weights 1e-4, 6.31e-6, 1e-6: (6.31e-6 + 2e-6) / 1.0731e-4. */
    ASSERT(e.along_m > 0.07 && e.along_m < 0.09);
    ASSERT_EQ(e.channel, 6);
}

/* Equal strength everywhere - a far transmitter - is `weak`, centred,
 * and still reported: that the radios agree is the finding. */
static void test_agreeing_radios_are_weak_not_absent(void) {
    three_in_a_row();
    feed(0, TX_A, -70, 5, 1000);
    feed(1, TX_A, -71, 5, 1000);
    feed(2, TX_A, -69, 5, 1000);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_WEAK);
    ASSERT(e.margin_db > 1.99 && e.margin_db < 2.01);
    ASSERT(e.along_m > 0.9 && e.along_m < 1.2);
    df_est_t out[4];
    ASSERT_EQ(df_snapshot(out, 4, 1000), 1);
}

/* A radio with fewer than DF_MIN_SAMPLES frames, or whose last frame is
 * older than DF_FRESH_S, is not part of the estimate. */
static void test_thin_and_stale_readings_are_left_out(void) {
    three_in_a_row();
    feed(0, TX_A, -40, 5, 1000);
    feed(1, TX_A, -60, DF_MIN_SAMPLES - 1, 1000);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.heard_by, 1);
    ASSERT_EQ(e.has[1], 0);
    df_note(1, TX_A, -60, 6, 1000);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.heard_by, 2);
    /* Radio 0 goes quiet; radio 1 keeps hearing it. */
    feed(1, TX_A, -60, 3, 1000 + DF_FRESH_S + 1);
    ASSERT_EQ(df_estimate(TX_A, 1000 + DF_FRESH_S + 1, &e), 1);
    ASSERT_EQ(e.heard_by, 1);
    ASSERT_EQ(e.has[0], 0);
    ASSERT_EQ(e.quality, DF_NONE);
}

/* The mean follows a transmitter that moved: after a stale gap it
 * starts over, and within a run it converges on the new level. */
static void test_mean_tracks_and_restarts(void) {
    three_in_a_row();
    feed(0, TX_A, -40, 5, 1000);
    feed(1, TX_A, -60, 5, 1000);
    feed(0, TX_A, -80, 40, 1010);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1010, &e), 1);
    ASSERT(e.rssi[0] < -79.0 && e.rssi[0] > -80.01);
    ASSERT_EQ(e.best_radio, 1);
    feed(0, TX_A, -45, 3, 1010 + DF_FRESH_S + 5);      /* after a gap: no -80 left in it */
    feed(1, TX_A, -60, 3, 1010 + DF_FRESH_S + 5);
    ASSERT_EQ(df_estimate(TX_A, 1010 + DF_FRESH_S + 5, &e), 1);
    ASSERT(e.rssi[0] > -45.01 && e.rssi[0] < -44.99);
}

/* No position on a radio: the loudest radio and the margin stand, the
 * point along the baseline does not. */
static void test_no_positions_no_along(void) {
    df_reset();
    df_radio_add("alfa0", 0, 0);
    df_radio_add("alfa1", 1, 1.0);
    feed(0, TX_A, -40, 5, 1000);
    feed(1, TX_A, -55, 5, 1000);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_LEAN);
    ASSERT_EQ(e.best_radio, 0);
    ASSERT_EQ(e.has_along, 0);
}

/* What is not a reading is not noted: a group address, a zero or
 * positive level, a radio that was never registered. */
static void test_non_readings_are_ignored(void) {
    three_in_a_row();
    feed(0, GROUP, -40, 5, 1000);
    feed(0, TX_A, 0, 5, 1000);
    feed(0, TX_A, 10, 5, 1000);
    feed(7, TX_A, -40, 5, 1000);
    feed(-1, TX_A, -40, 5, 1000);
    ASSERT_EQ(df_emitter_count(), 0);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 0);
}

/* A full table drops a new transmitter while every row is fresh, and
 * gives the quietest row away once it is stale. */
static void test_full_table_drops_then_recycles(void) {
    three_in_a_row();
    uint8_t m[6] = {0x02, 0, 0, 0, 0, 0};
    for (int i = 0; i < DF_MAX_EMITTERS; i++) {
        m[4] = (uint8_t)(i >> 8); m[5] = (uint8_t)i;
        df_note(0, m, -50, 1, 1000);
    }
    ASSERT_EQ(df_emitter_count(), DF_MAX_EMITTERS);
    df_note(0, TX_A, -50, 1, 1001);
    ASSERT_EQ((long long)df_dropped(), 1);
    df_est_t e;
    ASSERT_EQ(df_estimate(TX_A, 1001, &e), 0);
    df_note(0, TX_A, -50, 1, 1000 + DF_FRESH_S + 1);
    ASSERT_EQ(df_estimate(TX_A, 1000 + DF_FRESH_S + 1, &e), 1);
    ASSERT_EQ(df_emitter_count(), DF_MAX_EMITTERS);
    ASSERT_EQ((long long)df_dropped(), 1);
}

static void test_snapshot_is_newest_first_and_bounded(void) {
    three_in_a_row();
    feed(0, TX_A, -40, 3, 1000); feed(1, TX_A, -50, 3, 1000);
    feed(0, TX_B, -40, 3, 1005); feed(1, TX_B, -50, 3, 1005);
    df_est_t out[4];
    ASSERT_EQ(df_snapshot(out, 4, 1005), 2);
    ASSERT(!memcmp(out[0].mac, TX_B, 6));
    ASSERT(!memcmp(out[1].mac, TX_A, 6));
    ASSERT_EQ(df_snapshot(out, 1, 1005), 1);
    ASSERT(!memcmp(out[0].mac, TX_B, 6));
    df_radio_t r;
    ASSERT_EQ(df_radio_get(0, &r), 1);
    ASSERT_EQ((long long)r.frames, 6);
    ASSERT_STR(df_quality_name(DF_LEAN), "lean");
    df_reset();
}

/* Two radios that read 14 dB apart on everything (the beta-site pair):
 * with DF_CAL_MIN transmitters heard equally by both, the bias is the
 * median difference, and a transmitter is judged less it. Under
 * DF_CAL_MIN nothing is taken and levels are compared as measured. */
static void test_bias_is_measured_from_the_air(void) {
    three_in_a_row();
    uint8_t m[6] = {0x02, 0x10, 0, 0, 0, 0};
    for (int i = 0; i < DF_CAL_MIN - 1; i++) {
        m[5] = (uint8_t)i;
        feed(0, m, -60 - i, 4, 1000);
        feed(1, m, -74 - i, 4, 1000);
    }
    df_est_t out[32], e;
    ASSERT_EQ(df_snapshot(out, 32, 1000), DF_CAL_MIN - 1);
    df_radio_t r;
    ASSERT_EQ(df_radio_get(1, &r), 1);
    ASSERT_EQ(r.calibrated, 0);
    ASSERT_EQ(out[0].quality, DF_LEAN);                  /* 14 dB, uncorrected */
    m[5] = 0x40;
    feed(0, m, -50, 4, 1000);
    feed(1, m, -64, 4, 1000);
    ASSERT_EQ(df_snapshot(out, 32, 1000), DF_CAL_MIN);
    ASSERT_EQ(df_radio_get(1, &r), 1);
    ASSERT_EQ(r.calibrated, 1);
    ASSERT(r.bias_db > -14.01 && r.bias_db < -13.99);
    ASSERT_EQ(df_radio_get(0, &r), 1);
    ASSERT(r.calibrated == 1 && r.bias_db == 0);
    /* The far ones now agree. */
    ASSERT_EQ(df_estimate(m, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_WEAK);
    ASSERT(e.margin_db < 0.01);
    ASSERT(e.rssi[1] < -63.99 && e.rssi[1] > -64.01);    /* as measured */
    ASSERT(e.level[1] < -49.99 && e.level[1] > -50.01);  /* as compared */
    /* One near radio 1: measured 2 dB DOWN on it, really 12 dB up. */
    feed(0, TX_A, -60, 4, 1000);
    feed(1, TX_A, -62, 4, 1000);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_LEAN);
    ASSERT_EQ(e.best_radio, 1);
    ASSERT(e.margin_db > 11.99 && e.margin_db < 12.01);
    ASSERT(e.along_m > 0.9 && e.along_m < 1.0);
    /* A reset forgets the bias. */
    df_reset();
    df_radio_add("a", 0, 0); df_radio_add("b", 0, 0);
    ASSERT_EQ(df_radio_get(1, &r), 1);
    ASSERT_EQ(r.calibrated, 0);
}

/* Hand-built 802.11 headers (IEEE 802.11-2020 9.2.4.1, 9.3): Frame
 * Control, Duration, Address 1, Address 2. The transmitter is Address 2
 * of a management or data frame. */
static void test_frame_ta(void) {
    uint8_t ta[6];
    /* Beacon: type 0 subtype 8 -> FC 0x80 0x00; RA broadcast; TA TX_A. */
    uint8_t beacon[24] = { 0x80,0x00, 0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                           0x00,0x11,0x22,0x33,0x44,0x55 };
    ASSERT_EQ(df_frame_ta(beacon, sizeof(beacon), ta), 1);
    ASSERT(!memcmp(ta, TX_A, 6));
    /* QoS Data: type 2 subtype 8 -> FC 0x88 0x01. */
    uint8_t data[26] = { 0x88,0x01, 0x00,0x00, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
                         0x02,0xBB,0xCC,0xDD,0xEE,0xFF };
    ASSERT_EQ(df_frame_ta(data, sizeof(data), ta), 1);
    ASSERT(!memcmp(ta, TX_B, 6));
    /* Exactly through Address 2 is enough; one octet short is not. */
    ASSERT_EQ(df_frame_ta(beacon, 16, ta), 1);
    ASSERT_EQ(df_frame_ta(beacon, 15, ta), 0);
    /* ACK: type 1 subtype 13 -> FC 0xD4; ten octets, no transmitter. */
    uint8_t ack[10] = { 0xD4,0x00, 0x00,0x00, 0x00,0x11,0x22,0x33,0x44,0x55 };
    ASSERT_EQ(df_frame_ta(ack, sizeof(ack), ta), 0);
    /* RTS (type 1 subtype 11, FC 0xB4) has a TA, and is left out with
     * the other control frames. */
    uint8_t rts[16] = { 0xB4,0x00, 0x00,0x00, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
                        0x00,0x11,0x22,0x33,0x44,0x55 };
    ASSERT_EQ(df_frame_ta(rts, sizeof(rts), ta), 0);
    /* Protocol version 1 is not this header. */
    beacon[0] = 0x81;
    ASSERT_EQ(df_frame_ta(beacon, sizeof(beacon), ta), 0);
    ASSERT_EQ(df_frame_ta(NULL, 24, ta), 0);
}

/* df_active() is the sensor radio's one check per frame: off with one
 * radio, on with two, off again after a reset. */
static void test_active_needs_two_radios(void) {
    df_reset();
    ASSERT_EQ(df_active(), 0);
    df_radio_add("alfa0", 0, 0);
    ASSERT_EQ(df_active(), 0);
    df_radio_add("alfa1", 0, 0);
    ASSERT_EQ(df_active(), 1);
    df_reset();
    ASSERT_EQ(df_active(), 0);
}

/* The beta-site triangle (2026-11-17), 2 m sides, in the order the
 * sensor registers it: radio 0 the sensor radio at the east corner,
 * radio 1 north, radio 2 south-west. Metres east, metres north. */
static void triangle(void) {
    df_reset();
    ASSERT_EQ(df_radio_add_xy("alfa0", 1.0, -0.58), 0);
    ASSERT_EQ(df_radio_add_xy("alfa1", 0.0, 1.15), 1);
    ASSERT_EQ(df_radio_add_xy("alfa2", -1.0, -0.58), 2);
}

static void tri_feed(const uint8_t *mac, int l0, int l1, int l2, int n) {
    feed(0, mac, l0, n, 1000);
    feed(1, mac, l1, n, 1000);
    feed(2, mac, l2, n, 1000);
}

static void test_place_parses_one_number_or_two(void) {
    char n[16]; df_pos_t p;
    ASSERT_EQ(df_parse_place("alfa1", n, sizeof(n), &p), 1);
    ASSERT_STR(n, "alfa1");
    ASSERT_EQ(p.form, DF_POS_NONE);
    ASSERT_EQ(df_parse_place("alfa1@1.5", n, sizeof(n), &p), 1);
    ASSERT(p.form == DF_POS_LINE && p.a > 1.4999 && p.a < 1.5001);
    ASSERT_EQ(df_parse_place("alfa2@-1.0,-0.58", n, sizeof(n), &p), 1);
    ASSERT_STR(n, "alfa2");
    ASSERT_EQ(p.form, DF_POS_XY);
    ASSERT(p.a < -0.9999 && p.a > -1.0001 && p.b < -0.5799 && p.b > -0.5801);
    ASSERT_EQ(df_parse_place("alfa1@0,1.15", n, sizeof(n), &p), 1);
    ASSERT(p.form == DF_POS_XY && p.a == 0.0 && p.b > 1.1499 && p.b < 1.1501);
    ASSERT_EQ(df_parse_place("alfa1@1,", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@,1", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@1,2,3", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@1,2m", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@1,nan", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@inf,1", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@5000,0", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("alfa1@0,-1000.5", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("@1,2", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("a/b@1,2", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place("sixteen-chars-xx@1,2", n, sizeof(n), &p), 0);
    ASSERT_EQ(df_parse_place(NULL, n, sizeof(n), &p), 0);
}

/* The command line: every refusal is a line, and one command line
 * holds positions of one form. */
static void test_cli_takes_one_form(void) {
    df_cli_t c; char err[200];
    memset(&c, 0, sizeof(c));
    ASSERT_EQ(df_cli_form(&c), DF_POS_NONE);
    ASSERT_EQ(df_cli_add(&c, "alfa1@0,1.15", err, sizeof(err)), 1);
    ASSERT_STR(err, "");
    ASSERT_EQ(df_cli_add(&c, "alfa2@-1.0,-0.58", err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_origin(&c, "1.0,-0.58", err, sizeof(err)), 1);
    ASSERT_EQ(c.n, 2);
    ASSERT_STR(c.name[1], "alfa2");
    ASSERT(c.origin_set == 1 && c.origin.form == DF_POS_XY);
    ASSERT(c.origin.a > 0.9999 && c.origin.a < 1.0001);
    ASSERT_EQ(df_cli_check(&c, err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_form(&c), DF_POS_XY);
    /* A radio with no position beside placed ones is not a second form. */
    ASSERT_EQ(df_cli_add(&c, "alfa3", err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_check(&c, err, sizeof(err)), 1);
    /* A fourth is one too many beside the sensor radio. */
    ASSERT_EQ(df_cli_add(&c, "alfa4", err, sizeof(err)), 0);
    ASSERT(strstr(err, "too many --df-iface radios (max 3") != NULL);
    ASSERT_EQ(c.n, 3);

    memset(&c, 0, sizeof(c));
    ASSERT_EQ(df_cli_add(&c, "alfa1@1.0", err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_check(&c, err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_form(&c), DF_POS_LINE);
    ASSERT_EQ(df_cli_add(&c, "alfa2@2,0", err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_check(&c, err, sizeof(err)), 0);
    ASSERT(strstr(err, "one command line uses one form") != NULL);

    /* The origin alone can be the odd one out. */
    memset(&c, 0, sizeof(c));
    ASSERT_EQ(df_cli_add(&c, "alfa1@0,1", err, sizeof(err)), 1);
    ASSERT_EQ(df_cli_origin(&c, "0.5", err, sizeof(err)), 1);
    ASSERT_EQ(c.origin.form, DF_POS_LINE);
    ASSERT_EQ(df_cli_check(&c, err, sizeof(err)), 0);

    memset(&c, 0, sizeof(c));
    ASSERT_EQ(df_cli_add(&c, "alfa1@1,", err, sizeof(err)), 0);
    ASSERT(strstr(err, "--df-iface alfa1@1,: want NAME, NAME@METRES or NAME@X,Y") != NULL);
    ASSERT_EQ(c.n, 0);
    ASSERT_EQ(df_cli_origin(&c, "", err, sizeof(err)), 0);
    ASSERT(strstr(err, "--df-origin : want METRES or X,Y") != NULL);
    ASSERT_EQ(df_cli_origin(&c, "1,2,3", err, sizeof(err)), 0);
    ASSERT_EQ(df_cli_origin(&c, "east", err, sizeof(err)), 0);
    ASSERT_EQ(c.origin_set, 0);
}

/* A transmitter beside one corner: the bearing is that corner's
 * direction from the middle, to the nearest of eight points. The
 * corners sit at 120, 0 and 240 degrees. */
static void test_bearing_points_at_the_loud_corner(void) {
    df_est_t e;
    triangle();
    ASSERT_EQ(df_array_has_bearing(), 1);
    tri_feed(TX_A, -60, -40, -60, 5);                /* north corner */
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_LEAN);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 0);
    ASSERT_EQ(e.bearing_err_deg, 15);                /* 0.5 degrees, rounded up */
    ASSERT_EQ(e.has_along, 0);                       /* never both */

    triangle();
    tri_feed(TX_A, -40, -60, -60, 5);                /* east corner: 120 */
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 135);

    triangle();
    tri_feed(TX_A, -60, -60, -40, 5);                /* south-west corner: 240 */
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 225);

    /* Between two corners, away from the quiet third: 60 degrees, and
     * a 3 dB error on one radio moves it 40.9. */
    triangle();
    tri_feed(TX_A, -50, -50, -56, 5);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 45);
    ASSERT_EQ(e.bearing_err_deg, 45);
    /* The snapshot carries the same. */
    df_est_t out[2];
    ASSERT_EQ(df_snapshot(out, 2, 1000), 1);
    ASSERT_EQ(out[0].has_bearing, 1);
    ASSERT_EQ(out[0].bearing_deg, 45);
}

/* Withheld is the common case: each condition in df.h, one at a time. */
static void test_bearing_is_withheld(void) {
    df_est_t e;
    /* The radios agree: weak, no direction to lean in. */
    triangle();
    tri_feed(TX_A, -70, -71, -69, 5);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_WEAK);
    ASSERT_EQ(e.has_bearing, 0);

    /* A lean at the 6 dB floor that a 3 dB error on one radio would
     * move 48 degrees: more than one point. */
    triangle();
    tri_feed(TX_A, -50, -51, -56, 5);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_LEAN);
    ASSERT_EQ(e.has_bearing, 0);

    /* Two of the three heard it. */
    triangle();
    feed(0, TX_A, -40, 5, 1000);
    feed(1, TX_A, -60, 5, 1000);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.quality, DF_LEAN);
    ASSERT_EQ(e.has_bearing, 0);

    /* A fourth radio with no position heard it too. */
    triangle();
    ASSERT_EQ(df_radio_add("alfa3", 0, 0), 3);
    ASSERT_EQ(df_array_has_bearing(), 1);
    tri_feed(TX_A, -60, -40, -60, 5);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);                     /* it did not hear this one */
    feed(3, TX_A, -55, 5, 1000);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 0);

    /* Three placed radios on one line, and nearly on one. */
    df_reset();
    df_radio_add_xy("a", 0, 0); df_radio_add_xy("b", 1, 1); df_radio_add_xy("c", 2, 2);
    ASSERT_EQ(df_array_has_bearing(), 0);
    tri_feed(TX_A, -40, -60, -60, 5);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 0);
    df_reset();
    df_radio_add_xy("a", 0, 0); df_radio_add_xy("b", 2, 0); df_radio_add_xy("c", 1, 0.4);
    ASSERT_EQ(df_array_has_bearing(), 0);            /* 0.4 deep on a 2 m side */
    df_reset();
    df_radio_add_xy("a", 0, 0); df_radio_add_xy("b", 2, 0); df_radio_add_xy("c", 1, 0.5);
    ASSERT_EQ(df_array_has_bearing(), 1);            /* DF_MIN_ASPECT, exactly */

    /* Two placed radios, or all three at one spot. */
    df_reset();
    df_radio_add_xy("a", 0, 0); df_radio_add_xy("b", 2, 0);
    ASSERT_EQ(df_array_has_bearing(), 0);
    df_reset();
    df_radio_add_xy("a", 1, 1); df_radio_add_xy("b", 1, 1); df_radio_add_xy("c", 1, 1);
    ASSERT_EQ(df_array_has_bearing(), 0);

    /* The baseline form never has one. */
    three_in_a_row();
    ASSERT_EQ(df_array_has_bearing(), 0);
    tri_feed(TX_A, -40, -52, -60, 5);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_along, 1);
    ASSERT_EQ(e.has_bearing, 0);
}

/* A point once given stands until the direction is 11.25 degrees past
 * the edge of its sector; a transmitter first seen there gets the
 * nearer point. */
static void test_bearing_point_is_held(void) {
    df_est_t e;
    triangle();
    tri_feed(TX_A, -50, -48, -56, 5);                /* 34.1 degrees */
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 45);
    tri_feed(TX_A, -50, -46, -56, 80);               /* the mean settles on 19.0 */
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 45);                    /* 26 from 45: held */
    tri_feed(TX_B, -50, -46, -56, 5);                /* the same place, new */
    ASSERT_EQ(df_estimate(TX_B, 1000, &e), 1);
    ASSERT_EQ(e.bearing_deg, 0);
    feed(1, TX_A, -44, 80, 1000);                    /* 10.7: 34.3 from 45 */
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 1);
    ASSERT_EQ(e.bearing_deg, 0);
    /* Withheld once, the hold is gone. */
    tri_feed(TX_A, -50, -50, -50, 80);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.has_bearing, 0);
    tri_feed(TX_A, -50, -46, -56, 80);
    ASSERT_EQ(df_estimate(TX_A, 1000, &e), 1);
    ASSERT_EQ(e.bearing_deg, 0);
}

void run_df_tests(void) {
    TEST_SUITE("df - direction finding across monitor radios");
    RUN_TEST(test_spec_parses_name_and_metres);
    RUN_TEST(test_radio_table_is_bounded_and_unique);
    RUN_TEST(test_one_radio_says_nothing);
    RUN_TEST(test_lean_toward_the_loud_end);
    RUN_TEST(test_agreeing_radios_are_weak_not_absent);
    RUN_TEST(test_thin_and_stale_readings_are_left_out);
    RUN_TEST(test_mean_tracks_and_restarts);
    RUN_TEST(test_no_positions_no_along);
    RUN_TEST(test_non_readings_are_ignored);
    RUN_TEST(test_full_table_drops_then_recycles);
    RUN_TEST(test_snapshot_is_newest_first_and_bounded);
    RUN_TEST(test_bias_is_measured_from_the_air);
    RUN_TEST(test_frame_ta);
    RUN_TEST(test_active_needs_two_radios);
    RUN_TEST(test_place_parses_one_number_or_two);
    RUN_TEST(test_cli_takes_one_form);
    RUN_TEST(test_bearing_points_at_the_loud_corner);
    RUN_TEST(test_bearing_is_withheld);
    RUN_TEST(test_bearing_point_is_held);
}
