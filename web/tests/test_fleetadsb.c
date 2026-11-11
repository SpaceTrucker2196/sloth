/* Aircraft across the sites (#192 I7, web_fleetadsb.h): the geometry
 * (bearing, sector, the 4/3-earth horizon), the coverage a receiver
 * demonstrates, and web_fa_classify() on hand-built two-receiver data,
 * one case per verdict and per reason, with a stale, cut or deaf second
 * receiver never read as "should have heard". The export, the import,
 * the pull and the route are test_fleet.c's, beside the other kinds. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "web_fleetadsb.h"
#include "wtest.h"

#define T0 1792627000LL
#define M_DEG 111194.9                 /* metres in a degree of latitude */
#define B_LAT 33.0
#define B_LON (-112.0)

static void test_geometry(void) {
    WT_ASSERT(fabs(web_fa_bearing(33, -112, 34, -112)) < 1e-6);
    WT_ASSERT(fabs(web_fa_bearing(33, -112, 33, -111) - 89.7) < 0.5);
    WT_ASSERT(fabs(web_fa_bearing(33, -112, 32, -112) - 180) < 1e-6);
    WT_ASSERT(fabs(web_fa_bearing(33, -112, 33, -113) - 270.3) < 0.5);
    WT_EQ(web_fa_sector(0), 0);
    WT_EQ(web_fa_sector(29.99), 0);
    WT_EQ(web_fa_sector(30), 1);
    WT_EQ(web_fa_sector(359.9), 11);
    WT_EQ(web_fa_sector(360), 0);
    WT_EQ(web_fa_sector(-1), 11);
    WT_EQ(web_fa_sector(NAN), 0);
    /* 4.12 km x (sqrt 10 + sqrt 10000) = 425,028 m; nothing negative or
     * not finite reaches the root. */
    WT_ASSERT(fabs(web_fa_horizon_m(10, 10000) - 425028.4) < 1);
    WT_ASSERT(fabs(web_fa_horizon_m(100, 0) - 41200) < 1e-6);
    WT_EQ(web_fa_horizon_m(-5, NAN) == 0, 1);
    WT_ASSERT(isfinite(web_fa_bearing(NAN, 0, 0, 0)));
}

/* Each position into its sector as the farthest heard there; one beyond
 * the horizon of an aircraft at 50,000 ft (521 km from a 10 m antenna)
 * and one not finite are not counted. */
static void test_coverage(void) {
    web_fa_cov_t c;
    memset(&c, 0, sizeof(c));
    WT_EQ(web_fa_cov_add(&c, B_LAT, B_LON, B_LAT + 20000 / M_DEG, B_LON), 1);
    WT_EQ(web_fa_cov_add(&c, B_LAT, B_LON, B_LAT + 50000 / M_DEG, B_LON), 1);
    WT_EQ(web_fa_cov_add(&c, B_LAT, B_LON, B_LAT - 30000 / M_DEG, B_LON), 1);
    WT_EQ(web_fa_cov_add(&c, B_LAT, B_LON, B_LAT + 600000 / M_DEG, B_LON), 0);
    WT_EQ(web_fa_cov_add(&c, B_LAT, B_LON, NAN, B_LON), 0);
    WT_EQ(web_fa_cov_add(&c, B_LAT, B_LON, B_LAT, INFINITY), 0);
    WT_EQ(c.n, 3);
    WT_EQ(c.sec_n[0], 2);
    WT_EQ(c.sec_n[6], 1);
    WT_ASSERT(fabs(c.sec_m[0] - 50000) < 5);
    WT_ASSERT(fabs(c.sec_m[6] - 30000) < 5);
    WT_ASSERT(fabs(c.max_m - 50000) < 5);
    for (int k = 0; k < WEB_FA_SECTORS; k++) WT_ASSERT(isfinite(c.sec_m[k]));
}

/* Two receivers: [0] A, which reported the aircraft; [1] B, 17 m away,
 * which demonstrably hears the north sector to 50 km (20 positions),
 * answered past the window, was not cut, and heard three other aircraft
 * around the time. */
static long long g_aa[3], g_ab[3];

static void two(web_fa_site_t s[2], web_fa_obs_t o[2], double north_m, int alt_ft) {
    memset(s, 0, sizeof(web_fa_site_t) * 2);
    memset(o, 0, sizeof(web_fa_obs_t) * 2);
    for (int i = 0; i < 2; i++) {
        s[i].receiver = 1;
        s[i].has_pos = 1;
        s[i].lat = B_LAT + i * 0.00015;
        s[i].lon = B_LON;
        s[i].through = T0 + 3600;
    }
    s[1].cov.n = 20;
    s[1].cov.sec_n[0] = 20;
    s[1].cov.sec_m[0] = 50000;
    s[1].cov.max_m = 50000;
    for (int i = 0; i < 3; i++) { g_aa[i] = T0 - 900 + i; g_ab[i] = T0 + 60; }
    s[1].nact = 3;
    s[1].act_a = g_aa;
    s[1].act_b = g_ab;
    o[0].present = 1;
    o[0].first = o[0].visit_first = T0 - 600;
    o[0].last = T0;
    o[0].has_pos = 1;
    o[0].lat = B_LAT + north_m / M_DEG;
    o[0].lon = B_LON;
    o[0].pos_ts = T0;
    o[0].has_alt = 1;
    o[0].alt_ft = alt_ft;
}

static void test_single_receiver(void) {
    web_fa_site_t s[2];
    web_fa_obs_t o[2];
    web_fa_verdict_t v;
    two(s, o, 20000, 10000);
    s[1].receiver = 0;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.single, 1);
    WT_EQ(v.ref, 0);
}

static void test_confirmed(void) {
    web_fa_site_t s[2];
    web_fa_obs_t o[2];
    web_fa_verdict_t v;
    two(s, o, 20000, 10000);
    o[1].present = 1;
    o[1].first = o[1].visit_first = T0 - 300;
    o[1].last = T0 - 200;               /* within the heartbeat of A's */
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_CONFIRMED);
    WT_EQ(v.bstate[1], WEB_FA_B_HEARD);
    WT_EQ(v.inconsistent, 0);
}

/* Inside B's sector at 0.8 x 50 km and inside 0.8 x the horizon: B
 * should have heard it, and did not. */
static void test_unconfirmed(void) {
    web_fa_site_t s[2];
    web_fa_obs_t o[2];
    web_fa_verdict_t v;
    two(s, o, 20000, 10000);
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNCONFIRMED);
    WT_EQ(v.ref, 0);
    WT_EQ(v.bstate[1], WEB_FA_B_SHOULD);
    WT_ASSERT(fabs(v.dist_m[1] - 20000) < 30);
    WT_ASSERT(fabs(v.sec_max_m[1] - 50000) < 1e-6);
    WT_ASSERT(fabs(v.horizon_m[1] - 240488.4) < 1);   /* 10,000 ft */
    /* B heard it long before the window: still unheard now. */
    o[1].present = 1;
    o[1].first = o[1].visit_first = T0 - 5000;
    o[1].last = T0 - 4000;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNCONFIRMED);
}

/* Past 0.8 of B's farthest in that sector; and, low, past 0.8 of the
 * horizon though inside the sector; and in a sector B never showed
 * enough positions in. */
static void test_out_of_coverage(void) {
    web_fa_site_t s[2];
    web_fa_obs_t o[2];
    web_fa_verdict_t v;
    two(s, o, 45000, 10000);
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_OUT_OF_COVERAGE);
    WT_EQ(v.bstate[1], WEB_FA_B_OUTSIDE);
    /* 0 ft: 4.12 x sqrt 10 = 13.0 km, 0.8 of it 10.4 km < 20 km. */
    two(s, o, 20000, 0);
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_OUT_OF_COVERAGE);
    WT_ASSERT(fabs(v.horizon_m[1] - 13028.6) < 1);
    /* 9 positions in the sector: not demonstrated. */
    two(s, o, 20000, 10000);
    s[1].cov.sec_n[0] = WEB_FA_SECTOR_MIN - 1;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_OUT_OF_COVERAGE);
    WT_EQ(v.bstate[1], WEB_FA_B_NOCOV);
}

/* Every reason B's silence says nothing: undetermined, never
 * unconfirmed. Each seen red by its own guard's removal from
 * web_fa_classify() (the stale case with `B->through < t1` dropped, the
 * cut case with the cut_at line dropped, the deaf case with the
 * active() line dropped, the later case with the o->last test dropped):
 * each then read unconfirmed. */
static void test_undetermined_never_unconfirmed(void) {
    web_fa_site_t s[2];
    web_fa_obs_t o[2];
    web_fa_verdict_t v;
    /* B's newest answer is older than the window's end. */
    two(s, o, 20000, 10000);
    s[1].through = T0 + WEB_FA_WINDOW_S - 1;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.why, WEB_FA_B_PENDING);
    /* B's answer covering the window was cut. */
    two(s, o, 20000, 10000);
    s[1].cut_at = T0 - WEB_FA_WINDOW_S;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.why, WEB_FA_B_CUT);
    /* B heard one other aircraft: not demonstrably receiving. */
    two(s, o, 20000, 10000);
    s[1].nact = WEB_FA_HEALTH_MIN - 1;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.why, WEB_FA_B_QUIET);
    /* ... and none at all. */
    s[1].nact = 0;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    /* B heard it later, its newest visit after the window. */
    two(s, o, 20000, 10000);
    o[1].present = 1;
    o[1].first = o[1].visit_first = T0 + 1000;
    o[1].last = T0 + 1100;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.why, WEB_FA_B_LATER);
    /* B has no position; A's report has none; no altitude; on the
     * ground. */
    two(s, o, 20000, 10000);
    s[1].has_pos = 0;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.why, WEB_FA_B_NOPOS);
    two(s, o, 20000, 10000);
    o[0].has_pos = 0;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    two(s, o, 20000, 10000);
    o[0].has_alt = 0;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
    WT_EQ(v.why, WEB_FA_B_NOALT);
    two(s, o, 20000, 10000);
    o[0].on_ground = 1;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_UNDETERMINED);
}

/* Two receivers' positions for one address 100 km apart a minute apart
 * at 450 kt: further than it could fly (60 s x (231.5 x 1.25 + 30) +
 * 2 km = 21.2 km). 10 km apart is within it. */
static void test_inconsistent(void) {
    web_fa_site_t s[2];
    web_fa_obs_t o[2];
    web_fa_verdict_t v;
    two(s, o, 20000, 10000);
    o[0].has_gs = 1;
    o[0].gs_kt = 450;
    o[1] = o[0];
    o[1].pos_ts = T0 - 60;
    o[1].lat = o[0].lat + 100000 / M_DEG;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.verdict, WEB_FA_CONFIRMED);
    WT_EQ(v.inconsistent, 1);
    WT_ASSERT(fabs(v.sep_m - 100000) < 50);
    WT_ASSERT(fabs(v.allow_m - (60 * (450 * 0.514444 * 1.25 + 30) + 2000)) < 1);
    o[1].lat = o[0].lat + 10000 / M_DEG;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.inconsistent, 0);
    /* Further apart in time than WEB_FA_PAIR_DT_S: not compared. */
    o[1].lat = o[0].lat + 100000 / M_DEG;
    o[1].pos_ts = T0 - WEB_FA_PAIR_DT_S - 1;
    web_fa_classify(s, 2, o, &v);
    WT_EQ(v.inconsistent, 0);
}

void run_fleetadsb_tests(void) {
    WT_RUN(test_geometry);
    WT_RUN(test_coverage);
    WT_RUN(test_single_receiver);
    WT_RUN(test_confirmed);
    WT_RUN(test_unconfirmed);
    WT_RUN(test_out_of_coverage);
    WT_RUN(test_undetermined_never_unconfirmed);
    WT_RUN(test_inconsistent);
}
