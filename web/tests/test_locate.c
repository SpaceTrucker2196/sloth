/* Locating an emitter from two or more sensors (#192 I5, web_locate.h):
 * the geometry against answers worked by hand (two circles crossing at
 * two points, tangent outside and inside, apart, one inside the other,
 * concentric; a least-squares fix on synthetic ranges to a known point,
 * and the collinear case that has none), the local plane's round trip
 * against the haversine at the 2026-11 W9FJC / beta-site baseline, the
 * model's ranges and bands from sloth's own coefficients, and the
 * receiver calibration's accept / refuse / median. The route over a
 * store, a sloth.db and the own-radio links is test_fleet.c's
 * (test_locate_route), beside the pull it reads. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "rf_model.h"
#include "web_fleet.h"
#include "web_locate.h"
#include "wtest.h"

#define NEAR(a, b, eps) (fabs((double)(a) - (double)(b)) <= (eps))

/* A(0,0) r 5 and B(8,0) r 5 cross at (4,-3) and (4,3); r 3 and r 5 at
 * 8 apart touch at (3,0); r 10 and r 6 at 4 apart touch inside at
 * (10,0); r 2 and r 2 at 8 apart, and r 10 around r 2 at 1 apart, do
 * not meet; one centre is no baseline. Seen red with the h term's sign
 * swapped in the first point (both crossings then at y = +3 order
 * reversed: out[0] = (4,3)) and with the inside test dropped (r 10 / r 2
 * then reported crossing). */
static void test_circles(void) {
    double p[2][2];
    WT_EQ(web_loc_circles(0, 0, 5, 8, 0, 5, p), 2);
    WT_ASSERT(NEAR(p[0][0], 4, 1e-9) && NEAR(p[0][1], -3, 1e-9));
    WT_ASSERT(NEAR(p[1][0], 4, 1e-9) && NEAR(p[1][1], 3, 1e-9));
    /* Rotated: B north of A. */
    WT_EQ(web_loc_circles(0, 0, 5, 0, 8, 5, p), 2);
    WT_ASSERT(NEAR(p[0][0], 3, 1e-9) && NEAR(p[0][1], 4, 1e-9));
    WT_ASSERT(NEAR(p[1][0], -3, 1e-9) && NEAR(p[1][1], 4, 1e-9));
    WT_EQ(web_loc_circles(0, 0, 3, 8, 0, 5, p), 1);
    WT_ASSERT(NEAR(p[0][0], 3, 1e-9) && NEAR(p[0][1], 0, 1e-9));
    WT_EQ(web_loc_circles(0, 0, 10, 4, 0, 6, p), 1);
    WT_ASSERT(NEAR(p[0][0], 10, 1e-9) && NEAR(p[0][1], 0, 1e-9));
    WT_EQ(web_loc_circles(0, 0, 2, 8, 0, 2, p), 0);
    WT_EQ(web_loc_circles(0, 0, 10, 1, 0, 2, p), 0);
    WT_EQ(web_loc_circles(5, 5, 3, 5, 5, 4, p), -1);
}

/* Four sites on a 30 m square and an emitter at (12, 7): the exact
 * ranges give the point back with no residual; one range 3 m long moves
 * it and leaves a residual; three sites in a line with the emitter on
 * the line have no fix (the normal equations are singular). Seen red
 * with the Gauss-Newton step's sign flipped (the fix walked away: px
 * far from 12, and no fix at all) and with both singular guards
 * removed, the step's and the result's (collinear then answered 0;
 * either guard alone refuses it). */
static void test_lsq(void) {
    double x[4] = { 0, 30, 0, 30 }, y[4] = { 0, 0, 30, 30 }, r[4], w[4] = { 2, 2, 2, 2 };
    for (int i = 0; i < 4; i++) r[i] = hypot(12 - x[i], 7 - y[i]);
    double px, py, res, rad;
    WT_EQ(web_loc_lsq(x, y, r, w, 4, &px, &py, &res, &rad), 0);
    WT_ASSERT(NEAR(px, 12, 1e-4) && NEAR(py, 7, 1e-4));
    WT_ASSERT(res < 1e-4);
    WT_ASSERT(rad > 0.5 && rad < 4);           /* a few bands' worth, of 2 m each */
    /* Three of them suffice. */
    WT_EQ(web_loc_lsq(x, y, r, w, 3, &px, &py, &res, &rad), 0);
    WT_ASSERT(NEAR(px, 12, 1e-4) && NEAR(py, 7, 1e-4));
    r[3] += 3;
    WT_EQ(web_loc_lsq(x, y, r, w, 4, &px, &py, &res, &rad), 0);
    WT_ASSERT(res > 0.3);
    WT_ASSERT(hypot(px - 12, py - 7) > 0.3 && hypot(px - 12, py - 7) < 3);
    /* Three sites in a line: no fix (the mirror images are equal). */
    double xl[3] = { 0, 10, 20 }, yl[3] = { 0, 0, 0 }, rl[3] = { 5, 5, 15 };
    WT_EQ(web_loc_lsq(xl, yl, rl, w, 3, &px, &py, &res, &rad), -1);
    WT_EQ(web_loc_lsq(x, y, r, w, 2, &px, &py, &res, &rad), -1);
}

static double lsq_cost(const double *x, const double *y, const double *r, const double *w,
                       int n, double px, double py) {
    double c = 0;
    for (int i = 0; i < n; i++) {
        double f = hypot(px - x[i], py - y[i]) - r[i];
        c += f * f / (w[i] * w[i]);
    }
    return c;
}

/* Ranges that disagree (#192 I5 review): a full Gauss-Newton step from
 * the centroid overshoots, and the undamped iteration was still
 * oscillating after its 50 steps; the step it stopped on, (19.35,
 * 28.97), was reported as the fix at a weighted cost of 19.2 against
 * the minimum's 4.68. The fix now is a minimum: no 1 cm move lowers the
 * cost. Seen red with the damping removed (lam held at 0 and every step
 * taken: no fix within the bound) and, that way, with the convergence
 * test dropped as well (the last step reported: a cost above 4.7, and
 * a 1 cm move lowering it). */
static void test_lsq_disagreeing_ranges(void) {
    double x[3] = { 18.65, 37.46, 5.04 }, y[3] = { 17.2, 35.7, 9.63 };
    double r[3] = { 2.78, 8.36, 18.88 }, w[3] = { 2.224, 6.688, 15.104 };
    double px = 0, py = 0, res = 0, rad = 0;
    WT_EQ(web_loc_lsq(x, y, r, w, 3, &px, &py, &res, &rad), 0);
    double c0 = lsq_cost(x, y, r, w, 3, px, py);
    WT_ASSERT(c0 < 4.7);
    static const double mv[4][2] = { { .01, 0 }, { -.01, 0 }, { 0, .01 }, { 0, -.01 } };
    for (int k = 0; k < 4; k++)
        WT_ASSERT(lsq_cost(x, y, r, w, 3, px + mv[k][0], py + mv[k][1]) >= c0);
    WT_ASSERT(isfinite(res) && isfinite(rad) && rad > 0);
}

/* The plane at the two sites' centroid: each site out and back to its
 * own coordinates, and their separation equal to the haversine's 16.8 m
 * to a centimetre. Seen red with cos(lat0) dropped from the east axis
 * (the separation then 18.7 m). */
static void test_enu(void) {
    double la0 = (33.32922 + 33.32910) / 2, lo0 = (-111.87006 + -111.86995) / 2;
    double ea, na, eb, nb, la, lo;
    web_loc_enu(la0, lo0, 33.32922, -111.87006, &ea, &na);
    web_loc_enu(la0, lo0, 33.32910, -111.86995, &eb, &nb);
    web_loc_geo(la0, lo0, ea, na, &la, &lo);
    WT_ASSERT(NEAR(la, 33.32922, 1e-10) && NEAR(lo, -111.87006, 1e-10));
    web_loc_geo(la0, lo0, eb, nb, &la, &lo);
    WT_ASSERT(NEAR(la, 33.32910, 1e-10) && NEAR(lo, -111.86995, 1e-10));
    double hv = web_fleet_dist_m(33.32922, -111.87006, 33.32910, -111.86995);
    WT_ASSERT(NEAR(hv, 16.8, 0.05));
    WT_ASSERT(NEAR(hypot(ea - eb, na - nb), hv, 0.01));
    /* W9FJC is west and north of beta-site. */
    WT_ASSERT(ea < eb && na > nb);
    /* Origin at the origin. */
    web_loc_enu(la0, lo0, la0, lo0, &ea, &na);
    WT_ASSERT(ea == 0 && na == 0);
}

/* The model is sloth's (rf_model.h): a Wi-Fi client at -52 dBm, 15 dBm
 * assumed at 2437 MHz, N 2.8: 10^((67 - 39.737) / 28) = 9.41 m; its band
 * sigma sqrt(8^2 + 6^2 + 6^2) = 11.66 dB uncalibrated (shadow fading,
 * assumed power, unknown receiver), a factor 10^(11.66/28) = 2.61 each
 * way, and 10 dB calibrated (2.28); a calibration offset of -7 dB puts
 * it 10^(7/28) = 1.78 times farther. A 5 GHz AP takes N 3.0 and 12 dB
 * and no calibration; BLE 2440 MHz, 0 dBm, none either. 0 dBm is not a
 * reading. Seen red with the uncalibrated receiver term dropped (the
 * band then 2.28 for both). */
static void test_model(void) {
    web_loc_model_t m;
    web_loc_model(WEB_LOC_WIFI, 0, &m);
    WT_EQ(m.ptx_dbm, 15);
    WT_EQ(m.freq_mhz, 2437);
    WT_EQ(m.n_x10, 28);
    WT_EQ(m.cal_ok, 1);
    double lo, hi, sg;
    double d = web_loc_range(&m, -52, 0, 0, &lo, &hi, &sg);
    WT_ASSERT(NEAR(d, 9.41, 0.01));
    WT_ASSERT(NEAR(sg, 11.66, 0.01));
    WT_ASSERT(NEAR(hi / d, 2.61, 0.01) && NEAR(d / lo, 2.61, 0.01));
    double dc = web_loc_range(&m, -52, 1, -7.0, &lo, &hi, &sg);
    WT_ASSERT(NEAR(dc / d, 1.778, 0.002));
    WT_ASSERT(NEAR(sg, 10.0, 1e-9));
    WT_ASSERT(NEAR(hi / dc, 2.277, 0.002));
    /* The offset is ignored uncalibrated. */
    WT_ASSERT(NEAR(web_loc_range(&m, -52, 0, -7.0, NULL, NULL, NULL), d, 1e-9));
    WT_ASSERT(web_loc_range(&m, 0, 0, 0, &lo, &hi, &sg) < 0);
    WT_ASSERT(web_loc_range(&m, 5, 0, 0, &lo, &hi, &sg) < 0);
    web_loc_model(WEB_LOC_AP, 36, &m);
    WT_EQ(m.ptx_dbm, 20);
    WT_EQ(m.freq_mhz, 5180);
    WT_EQ(m.n_x10, 30);
    WT_ASSERT(m.sigma_db == 12.0);
    WT_EQ(m.cal_ok, 0);
    web_loc_model(WEB_LOC_AP, 6, &m);
    WT_EQ(m.freq_mhz, 2437);
    WT_EQ(m.cal_ok, 1);
    web_loc_model(WEB_LOC_BLE, 0, &m);
    WT_EQ(m.ptx_dbm, 0);
    WT_EQ(m.freq_mhz, 2440);
    WT_EQ(m.cal_ok, 0);
}

/* One link inside RF_CAL_MAX_DB calibrates; one outside is refused and
 * its offset reported; a mix takes the median of the accepted only;
 * none is none. Seen red with the bound test removed (29 dB then
 * "calibrated"). */
static void test_calibrate(void) {
    double off, a[] = { -7.04 }, b[] = { 28.96 }, c[] = { -7.0, 28.96, -9.0 };
    WT_EQ(web_loc_calibrate(a, 1, &off), 1);
    WT_ASSERT(NEAR(off, -7.04, 1e-9));
    WT_EQ(web_loc_calibrate(b, 1, &off), 2);
    WT_ASSERT(NEAR(off, 28.96, 1e-9));
    WT_EQ(web_loc_calibrate(c, 3, &off), 1);
    WT_ASSERT(NEAR(off, -8.0, 1e-9));
    WT_EQ(web_loc_calibrate(c, 0, &off), 0);
    /* The link itself: the own card heard at -52 dBm 16.8 m away is a
     * receiver 7.0 dB above a 0 dBi one (the 9 dBi antenna, less the
     * model's and the power's error); at -88 dBm, 29 dB below: refused. */
    WT_EQ(rf_ref_offset_raw(RF_PTX_STA_ASSUMED, -52, 2437, 28, 16.8, &off), 1);
    WT_ASSERT(NEAR(off, -7.04, 0.01));
    WT_EQ(rf_ref_offset_db(RF_PTX_STA_ASSUMED, -88, 2437, 28, 16.8, &off), 0);
}

/* The own-radio list: canonical unicast MACs, comma-separated, at most
 * WEB_FLEET_OWN_MAX; anything else refused whole. */
static void test_own_parse(void) {
    char own[WEB_FLEET_OWN_MAX][WEB_FLEET_MAC_SZ];
    int n = -1;
    WT_EQ(web_fleet_own_parse("24:41:8c:30:97:a1,00:c0:ca:bb:51:82", own, &n), 0);
    WT_EQ(n, 2);
    WT_ASSERT(!strcmp(own[1], "00:c0:ca:bb:51:82"));
    WT_EQ(web_fleet_own_parse("", own, &n), 0);
    WT_EQ(n, 0);
    static const char *const bad[] = {
        "24:41:8C:30:97:A1", "24:41:8c:30:97", "01:00:5e:00:00:01", "00:00:00:00:00:00",
        "24:41:8c:30:97:a1,", ",24:41:8c:30:97:a1", "24:41:8c:30:97:a1,,00:c0:ca:bb:51:82",
        "02:00:00:00:00:01,02:00:00:00:00:02,02:00:00:00:00:03,02:00:00:00:00:04,"
        "02:00:00:00:00:05,02:00:00:00:00:06,02:00:00:00:00:07,02:00:00:00:00:08,"
        "02:00:00:00:00:09",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        WT_EQ(web_fleet_own_parse(bad[i], own, &n), -1);
}

void run_locate_tests(void) {
    WT_RUN(test_circles);
    WT_RUN(test_lsq);
    WT_RUN(test_lsq_disagreeing_ranges);
    WT_RUN(test_enu);
    WT_RUN(test_model);
    WT_RUN(test_calibrate);
    WT_RUN(test_own_parse);
}
