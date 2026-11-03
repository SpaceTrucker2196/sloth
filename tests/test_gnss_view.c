#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "gps.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/gnss.h"

/* [#] GNSS view (2026-11-02): rendered through the test screen the way
 * tests/test_gps.c renders the alerts detail. The sky is hand-built on
 * sloth_state_t directly (the copy gps_health_poll() makes), so these
 * are view tests and nothing here needs the parser. */

#define S(lit) lit, sizeof(lit) - 1

static char g_buf[32768];

static const char *render(const sloth_state_t *s) {
    tui_test_erase();
    view_gnss_draw(s);
    tui_test_screen(g_buf, sizeof(g_buf));
    return g_buf;
}

static void add_sat(gnss_sky_t *k, int gnssid, int svid, int prn, int el, int az,
                    double cn0, int used, int health) {
    gnss_sat_t *a = &k->sats[k->n++];
    memset(a, 0, sizeof(*a));
    a->gnssid = (int8_t)gnssid;
    a->svid = (int16_t)svid;
    a->prn = (int16_t)prn;
    a->sigid = -1;
    a->el = (int16_t)el;
    a->az = (int16_t)az;
    if (cn0 >= 0) { a->has_cn0 = 1; a->cn0_x10 = (int16_t)(cn0 * 10 + 0.5); }
    a->used = (uint8_t)used;
    a->health = (int8_t)health;
}

static time_t g_wall;
static time_t   tw(void) { return g_wall; }
static uint64_t tm_(void) { return (uint64_t)g_wall * 1000u; }

static void seed(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    s->gps.configured = s->gps.has_gps = 1;
    snprintf(s->gps.src, sizeof(s->gps.src), "gpsd:127.0.0.1:2947");
    gnss_sky_t *k = &s->gnss_sky;
    k->valid = 1;
    k->ts = 1793059200;
    k->nsat = 5;
    k->usat = 3;
    k->hdop = 1.1; k->pdop = 1.9; k->vdop = 1.5;
    add_sat(k, 0, 5, 5, 45, 120, 41.0, 1, 1);
    add_sat(k, 0, 7, 7, -1, -1, 22.5, 0, 1);
    add_sat(k, 6, 9, 73, 30, 300, 47.5, 1, 1);
    add_sat(k, 1, 131, 131, 10, 200, -1, 0, 0);
    add_sat(k, 2, 12, 312, 60, 40, 33.0, 1, 2);
    k->cn0_n = 4;
    k->cn0_mean = 36.0;
    k->cn0_max = 47.5;
    gnss_fix_t *f = &s->gnss_fix;
    f->valid = 1;
    f->ts = 1793059200;
    f->mode = 3;
    f->status = 2;
    f->has_pos = 1; f->lat = 51.5; f->lon = -0.1;
    f->has_eph = 1; f->eph = 4.2;
    f->has_speed = 1; f->speed = 0.0;
    f->has_time_off = 1; f->time_off_ms = 120;
    f->leap = 18;
    f->jam = 0;
}

/* No receiver: the empty state names the flag and the page, and draws
 * no table. Seen red with the has_gps guard removed (a header with
 * "fix none" appeared). */
static void test_gnss_empty_without_receiver(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    const char *b = render(&s);
    ASSERT(strstr(b, "no receiver") != NULL);
    ASSERT(strstr(b, "--gps gpsd://") != NULL);
    ASSERT(strstr(b, "docs/wiki/gnss.md") != NULL);
    ASSERT(strstr(b, "GNSS    ") == NULL);           /* no table header */
    ASSERT(strstr(b, "fix none") == NULL);
    /* --location alone is not a receiver either. */
    s.gps.configured = s.gps.has_fixed = 1;
    b = render(&s);
    ASSERT(strstr(b, "no receiver") != NULL);
}

/* A receiver with no SKY yet: the header draws, the table waits. */
static void test_gnss_waiting_for_sky(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    s.gps.configured = s.gps.has_gps = 1;
    snprintf(s.gps.src, sizeof(s.gps.src), "nmea:/dev/ttyUSB0");
    snprintf(s.gps.err, sizeof(s.gps.err), "open: Permission denied");
    const char *b = render(&s);
    ASSERT(strstr(b, "GNSS: fix none") != NULL);
    ASSERT(strstr(b, "sats 0/0") != NULL);
    ASSERT(strstr(b, "src nmea:/dev/ttyUSB0") != NULL);
    ASSERT(strstr(b, "waiting for the receiver's first satellite list") != NULL);
    ASSERT(strstr(b, "err open: Permission denied") != NULL);
    ASSERT(strstr(b, "clock off -") != NULL);
}

/* The populated table: the header's figures, rows sorted by C/N0 with
 * the untracked satellite last, the used / health cells, the bar. */
static void test_gnss_populated_render_sorted(void) {
    TEST_STATE(s);
    seed(&s);
    g_wall = 1793059201;
    sloth_clock_test_set(tm_, tw);
    const char *b = render(&s);
    ASSERT(strstr(b, "GNSS: fix 3D") != NULL);
    ASSERT(strstr(b, "sats 3/5") != NULL);
    ASSERT(strstr(b, "HDOP 1.1 PDOP 1.9") != NULL);
    ASSERT(strstr(b, "acc ±4 m") != NULL);
    ASSERT(strstr(b, "speed 0.0 m/s") != NULL);
    ASSERT(strstr(b, "clock off +120 ms") != NULL);
    ASSERT(strstr(b, "src gpsd:127.0.0.1:2947  age 1s") != NULL);
    ASSERT(strstr(b, "status DGPS  leap 18  jam 0  C/N0 mean 36.0 max 47.5") != NULL);
    ASSERT(strstr(b, "GNSS        SV   PRN   EL   AZ   C/N0  USED  HLTH  SIGNAL") != NULL);
    const char *r1 = strstr(b, "GLONASS      9    73   30  300   47.5   yes    ok  ");
    const char *r2 = strstr(b, "GPS          5     5   45  120   41.0   yes    ok  ");
    const char *r3 = strstr(b, "Galileo     12   312   60   40   33.0   yes   BAD  ");
    const char *r4 = strstr(b, "GPS          7     7    -    -   22.5     -    ok  ");
    const char *r5 = strstr(b, "SBAS       131   131   10  200      -     -     ?");
    ASSERT(r1 && r2 && r3 && r4 && r5);
    if (r1 && r2 && r3 && r4 && r5) {
        ASSERT(r1 < r2);
        ASSERT(r2 < r3);
        ASSERT(r3 < r4);
        ASSERT(r4 < r5);
        /* The bar: 47.5 of 50 fills most of it, 22.5 under half,
         * the untracked row none. */
        const char *e1 = strchr(r1, '\n'), *e4 = strchr(r4, '\n'), *e5 = strchr(r5, '\n');
        int b1 = 0, b4 = 0, b5 = 0;
        for (const char *p = r1; e1 && p < e1; p++) b1 += *p == '|';
        for (const char *p = r4; e4 && p < e4; p++) b4 += *p == '|';
        for (const char *p = r5; e5 && p < e5; p++) b5 += *p == '|';
        ASSERT(b1 > b4);
        ASSERT(b4 > 0);
        ASSERT_EQ(b5, 0);
    }
    ASSERT(strstr(b, ">GLONASS") != NULL);           /* row 0 selected */
    ASSERT(strstr(b, "bright: used in the solution") != NULL);
    ASSERT(strstr(b, "more satellites than the table holds") == NULL);
    s.gnss_sky.overflow = 2;
    b = render(&s);
    ASSERT(strstr(b, "more satellites than the table holds") != NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* Up / down stay inside the sorted rows; Enter opens the selected
 * row's detail, Esc / Enter close it; the detail names the row the
 * cursor was on in sorted order, not in the sky's order. */
static void test_gnss_nav_and_detail(void) {
    TEST_STATE(s);
    seed(&s);
    view_gnss_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.gnss_sel, 0);
    for (int i = 0; i < 10; i++) view_gnss_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.gnss_sel, 4);
    view_gnss_key(&s, SLOTH_KEY_UP);
    view_gnss_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.gnss_sel, 2);                        /* Galileo 312 */
    view_gnss_key(&s, '\n');
    ASSERT_EQ(s.gnss_detail, 1);
    const char *b = render(&s);
    ASSERT(strstr(b, "GNSS satellite") != NULL);
    ASSERT(strstr(b, "constellation    Galileo (gnssid 2)") != NULL);
    ASSERT(strstr(b, "svid             12") != NULL);
    ASSERT(strstr(b, "PRN              312") != NULL);
    ASSERT(strstr(b, "elevation        60 deg") != NULL);
    ASSERT(strstr(b, "azimuth          40 deg true") != NULL);
    ASSERT(strstr(b, "C/N0             33.0 dB-Hz") != NULL);
    ASSERT(strstr(b, "used in solution yes") != NULL);
    ASSERT(strstr(b, "health           BAD") != NULL);
    ASSERT(strstr(b, "pass (unix)      1793059200") != NULL);
    view_gnss_key(&s, SLOTH_KEY_DOWN);               /* ignored in detail */
    ASSERT_EQ(s.gnss_sel, 2);
    view_gnss_key(&s, 27);
    ASSERT_EQ(s.gnss_detail, 0);
    /* The untracked row's detail says so. */
    s.gnss_sel = 4;
    view_gnss_key(&s, '\r');
    b = render(&s);
    ASSERT(strstr(b, "C/N0             - (not tracked)") != NULL);
    ASSERT(strstr(b, "health           ?") != NULL);
    view_gnss_key(&s, '\n');
    ASSERT_EQ(s.gnss_detail, 0);
    /* A sky that emptied under an open detail: the detail says the row
     * left, and Enter on an empty sky opens nothing. */
    s.gnss_detail = 1;
    s.gnss_sky.n = 0;
    b = render(&s);
    ASSERT(strstr(b, "the row has left the sky") != NULL);
    s.gnss_detail = 0;
    s.gnss_sel = 0;
    view_gnss_key(&s, '\n');
    ASSERT_EQ(s.gnss_detail, 0);
    view_gnss_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.gnss_sel, 0);
}

/* The header's words for the receiver's states and an unknown offset. */
static void test_gnss_header_states(void) {
    TEST_STATE(s);
    seed(&s);
    s.gnss_fix.mode = 1;
    s.gnss_fix.status = -1;
    s.gnss_fix.has_time_off = 0;
    s.gnss_fix.has_eph = 0;
    s.gnss_fix.has_speed = 0;
    s.gnss_fix.leap = -1;
    s.gnss_fix.jam = 200;
    s.gnss_fix.has_gst = 1;
    s.gnss_fix.gst_rms = 1.6;
    const char *b = render(&s);
    ASSERT(strstr(b, "GNSS: fix no fix") != NULL);
    ASSERT(strstr(b, "clock off -") != NULL);
    ASSERT(strstr(b, "acc ") == NULL);
    ASSERT(strstr(b, "status -  jam 200") != NULL);
    ASSERT(strstr(b, "leap") == NULL);
    ASSERT(strstr(b, "GST rms 1.6 m") != NULL);
    s.gnss_fix.mode = 2;
    s.gnss_fix.status = 1;
    s.gnss_fix.has_time_off = 1;
    s.gnss_fix.time_off_ms = -3500;
    b = render(&s);
    ASSERT(strstr(b, "GNSS: fix 2D") != NULL);
    ASSERT(strstr(b, "clock off -3500 ms") != NULL);
    ASSERT(strstr(b, "status normal") != NULL);
}

void run_gnss_view_tests(void) {
    TEST_SUITE("views: [#] GNSS (2026-11-02)");
    RUN_TEST(test_gnss_empty_without_receiver);
    RUN_TEST(test_gnss_waiting_for_sky);
    RUN_TEST(test_gnss_populated_render_sorted);
    RUN_TEST(test_gnss_nav_and_detail);
    RUN_TEST(test_gnss_header_states);
}
