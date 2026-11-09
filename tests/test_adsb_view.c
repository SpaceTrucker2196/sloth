#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "adsb.h"
#include "gps.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/adsb.h"
#include "views/iface.h"

/* [^] ADS-B view (#186, 2026-11-07): rendered through the test screen
 * the way tests/test_gnss_view.c renders the GNSS sky.
 *
 * Every row is built by hand from the field definitions in src/adsb.h
 * (readsb's README-json.md), never by feeding the parser its own
 * output: most tests put adsb_aircraft_t rows straight on
 * sloth_state_t, which is where adsb_health_poll() leaves its copy, and
 * one feeds a hand-built adsb_doc_t through the module so the view is
 * also seen against what the real poll produces. The addresses,
 * callsigns, squawks and positions are invented; none is a receiver's,
 * and neither is the sensor position (docs/wiki/adsb.md § Privacy). */

static char g_buf[65536];

static const char *render(const sloth_state_t *s) {
    tui_test_erase();
    view_adsb_draw(s);
    tui_test_screen(g_buf, sizeof(g_buf));
    return g_buf;
}

static time_t g_wall;
static time_t   tw(void) { return g_wall; }
static uint64_t tm_(void) { return (uint64_t)g_wall * 1000u; }

#define WALL0 1800000100

/* The sensor's own position, invented. 53.1 km / 033 deg to the first
 * aircraft and 23.1 km / 262 deg to the third: both computed from the
 * haversine and initial-bearing formulae independently of sloth (see
 * test_bearing in tests/test_gps.c for the same vectors' provenance). */
#define SENSOR_LAT 51.5000
#define SENSOR_LON (-0.1200)

static adsb_aircraft_t g_rows[4];

/* Four aircraft, freshest last in the array so the view's own sort is
 * what puts them in order:
 *   [0] a1b2c3  airliner at FL370 with a position, heard 1 s ago
 *   [1] 4ca2d1  geometric altitude only, no track, no position, squawk
 *               7700 and the decoder's `emergency` set, heard 35 s ago
 *   [2] ~7fab01 a non-ICAO (TIS-B) address on the ground, no callsign,
 *               no squawk, no RSSI, with a position, heard 5 s ago
 *   [3] 00ffee  a light aircraft with no position, heard 5 s ago — the
 *               same instant as [2], so the address tie-break orders
 *               the pair (non-ICAO last) */
static void seed(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    memset(g_rows, 0, sizeof(g_rows));
    g_wall = WALL0;
    sloth_clock_test_set(tm_, tw);

    adsb_aircraft_t *a = &g_rows[0];
    a->icao = 0xa1b2c3u;
    snprintf(a->type, sizeof(a->type), "adsb_icao");
    snprintf(a->flight, sizeof(a->flight), "BAW117");
    snprintf(a->squawk, sizeof(a->squawk), "2000");
    snprintf(a->category, sizeof(a->category), "A3");
    a->emergency = ADSB_EMERG_NONE;
    a->has_alt_baro = 1; a->alt_baro = 37000;
    a->has_gs = 1; a->gs = 452.3;
    a->has_track = 1; a->track = 285.4;
    a->has_rssi = 1; a->rssi = -18.34;
    a->has_pos = 1; a->lat = 51.9; a->lon = 0.3;
    a->first_seen = WALL0 - 600;
    a->last_seen = WALL0 - 1;

    a = &g_rows[1];
    a->icao = 0x4ca2d1u;
    snprintf(a->type, sizeof(a->type), "mode_s");
    snprintf(a->flight, sizeof(a->flight), "EIN24B");
    snprintf(a->squawk, sizeof(a->squawk), "7700");
    a->emergency = ADSB_EMERG_GENERAL;
    a->has_alt_geom = 1; a->alt_geom = 12000;
    a->has_gs = 1; a->gs = 210.6;
    a->has_rssi = 1; a->rssi = -27.8;
    a->first_seen = WALL0 - 300;
    a->last_seen = WALL0 - 35;

    a = &g_rows[2];
    a->icao = 0x7fab01u;
    a->non_icao = 1;
    snprintf(a->type, sizeof(a->type), "tisb_other");
    a->emergency = ADSB_EMERG_ABSENT;
    a->on_ground = 1;
    a->has_pos = 1; a->lat = 51.47; a->lon = -0.45;
    a->first_seen = WALL0 - 60;
    a->last_seen = WALL0 - 5;

    a = &g_rows[3];
    a->icao = 0x00ffeeu;
    snprintf(a->type, sizeof(a->type), "adsb_icao");
    snprintf(a->flight, sizeof(a->flight), "N12345");
    snprintf(a->squawk, sizeof(a->squawk), "1200");
    a->emergency = ADSB_EMERG_ABSENT;
    a->has_alt_baro = 1; a->alt_baro = 2500;
    a->has_gs = 1; a->gs = 95.4;
    a->has_track = 1; a->track = 10.6;
    a->has_rssi = 1; a->rssi = -3.05;
    a->first_seen = WALL0 - 120;
    a->last_seen = WALL0 - 5;

    s->adsb.configured = 1;
    s->adsb.state = ADSB_LIVE;
    s->adsb.aircraft = 4;
    s->adsb.age_s = 0;
    s->adsb.fresh_bucket = 0;
    s->adsb.messages = 1234567u;
    s->adsb.reads = 12;
    s->adsb.expired = 1;
    s->adsb.last_read = WALL0;
    snprintf(s->adsb.src, sizeof(s->adsb.src), "file:/run/readsb/aircraft.json");
    s->adsb_rows = g_rows;
    s->adsb_count = 4;
}

static void fixed_sensor(void) {
    char err[160];
    ASSERT_EQ(gps_location_set_fixed(SENSOR_LAT, SENSOR_LON, 0, 0,
                                     err, sizeof(err)), 0);
}

/* No decoder: the empty state names the flag and the page, says who
 * owns the SDR, and draws no table.
 *
 * The two absences were seen to fail (2026-11-07): `if
 * (!s->adsb.configured)` -> `if (0)` in view_adsb_draw() reddens this
 * test alone, because the health header and its tally line then draw
 * over an unconfigured feed. */
static void test_adsb_empty_without_decoder(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    const char *b = render(&s);
    ASSERT(strstr(b, "ADS-B: no decoder") != NULL);
    ASSERT(strstr(b, "--adsb /run/readsb/aircraft.json") != NULL);
    ASSERT(strstr(b, "docs/wiki/adsb.md") != NULL);
    ASSERT(strstr(b, "never opens or tunes the SDR") != NULL);
    ASSERT(strstr(b, "ICAO ") == NULL);              /* no table header */
    ASSERT(strstr(b, "docs 0") == NULL);             /* no health line */
}

/* Configured with nothing read yet: the health header draws, the table
 * says what it is waiting for, and no column header is drawn.
 *
 * The absent column header was seen to fail (2026-11-07): dropping the
 * `if (n == 0)` early return reddens this test and
 * test_adsb_stale_error_and_empty_states, which is the pair that pins
 * an empty table saying why rather than heading a table of nothing. */
static void test_adsb_waiting_for_the_first_document(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    g_wall = WALL0;
    sloth_clock_test_set(tm_, tw);
    s.adsb.configured = 1;
    s.adsb.state = ADSB_WAITING;
    s.adsb.age_s = -1;
    snprintf(s.adsb.src, sizeof(s.adsb.src), "file:/run/readsb/aircraft.json");
    const char *b = render(&s);
    ASSERT(strstr(b, "ADS-B: waiting") != NULL);
    ASSERT(strstr(b, "aircraft 0") != NULL);
    ASSERT(strstr(b, "age -") != NULL);
    ASSERT(strstr(b, "src file:/run/readsb/aircraft.json") != NULL);
    ASSERT(strstr(b, "docs 0  read err 0  parse err 0  overflow 0"
                     "  bad 0  expired 0") != NULL);
    ASSERT(strstr(b, "waiting for the decoder's first document") != NULL);
    ASSERT(strstr(b, "ICAO ") == NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* An sbs:// source (2026-11-09): the header counts lines, not
 * documents, and the empty states speak of the stream - waiting for a
 * first line, stale as no line for ADSB_SBS_STALE_S - not of a file's
 * clock. The "docs" absence was seen red with the header's label fixed
 * at "docs"; the file-clock absence with the stream's stale branch
 * guarded `if (0)`. */
static void test_adsb_sbs_source_states(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    g_wall = WALL0;
    sloth_clock_test_set(tm_, tw);
    s.adsb.configured = 1;
    s.adsb.state = ADSB_WAITING;
    s.adsb.age_s = -1;
    snprintf(s.adsb.src, sizeof(s.adsb.src), "sbs:127.0.0.1:30003");
    const char *b = render(&s);
    ASSERT(strstr(b, "src sbs:127.0.0.1:30003") != NULL);
    ASSERT(strstr(b, " lines 0  read err 0  parse err 0") != NULL);
    ASSERT(strstr(b, " docs 0") == NULL);
    ASSERT(strstr(b, "waiting for the decoder's first SBS line") != NULL);
    s.adsb.state = ADSB_STALE;
    s.adsb.age_s = 140;
    b = render(&s);
    ASSERT(strstr(b, "sent no line, not even its heartbeat") != NULL);
    ASSERT(strstr(b, "clock has stopped advancing") == NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* The populated table with no sensor position: the header's figures,
 * rows freshest first with the address tie-break, the per-field cells
 * and absences, the RSSI bar, the dim row, and the legend.
 *
 * Its two absences were each seen to fail (2026-11-07), with one
 * mutation apiece: the overflow note's `s->adsb.overflow ?` forced true
 * reddens only the `== NULL` below, and dropping the bar's `has_rssi`
 * guard reddens only ASSERT_EQ(b3, 0) — a row with no RSSI then reads
 * rssi 0 dBFS, the top of the span, and draws a full bar. */
static void test_adsb_populated_render_sorted(void) {
    TEST_STATE(s);
    seed(&s);
    const char *b = render(&s);
    ASSERT(strstr(b, "ADS-B: live  aircraft 4  emerg 1  msgs 1234567"
                     "  age 0s  src file:/run/readsb/aircraft.json") != NULL);
    ASSERT(strstr(b, "docs 12  read err 0  parse err 0  overflow 0"
                     "  bad 0  expired 1") != NULL);
    ASSERT(strstr(b, " ICAO     FLIGHT    SQWK     ALT     GS   TRK"
                     "    RSSI   AGE  SIGNAL") != NULL);
    const char *r1 = strstr(b, ">a1b2c3   BAW117    2000   37000    452   285"
                               "   -18.3    1s  ");
    const char *r2 = strstr(b, " 00ffee   N12345    1200    2500     95    11"
                               "    -3.1    5s  ");
    const char *r3 = strstr(b, " ~7fab01  -            -  ground      -     -"
                               "       -    5s");
    const char *r4 = strstr(b, " 4ca2d1   EIN24B    7700   12000    211     -"
                               "   -27.8   35s  ");
    ASSERT(r1 && r2 && r3 && r4);
    if (r1 && r2 && r3 && r4) {
        /* Freshest first; [2] and [3] were heard in the same second, so
         * the address tie-break puts the ICAO row above the non-ICAO
         * one rather than leaving the pair's order to qsort. */
        ASSERT(r1 < r2);
        ASSERT(r2 < r3);
        ASSERT(r3 < r4);
        /* The bar: -3.1 dBFS nearly fills it, -18.3 is a third of it,
         * -27.8 a little, and the row with no RSSI has none. */
        const char *e1 = strchr(r1, '\n'), *e2 = strchr(r2, '\n');
        const char *e3 = strchr(r3, '\n'), *e4 = strchr(r4, '\n');
        int b1 = 0, b2 = 0, b3 = 0, b4 = 0;
        for (const char *p = r1; e1 && p < e1; p++) b1 += *p == '|';
        for (const char *p = r2; e2 && p < e2; p++) b2 += *p == '|';
        for (const char *p = r3; e3 && p < e3; p++) b3 += *p == '|';
        for (const char *p = r4; e4 && p < e4; p++) b4 += *p == '|';
        ASSERT(b2 > b1);
        ASSERT(b1 > b4);
        ASSERT(b4 > 0);
        ASSERT_EQ(b3, 0);
    }
    /* The oldest row is dim (not heard for 30 s or more); the selected
     * row is in reverse video whatever its age. */
    int y = runner_screen_find(" 4ca2d1");
    ASSERT(y >= 0);
    if (y >= 0) ASSERT_EQ(tui_test_pair(y, runner_find_col(y, "4ca2d1")), CP_DIM);
    y = runner_screen_find(">a1b2c3");
    ASSERT(y >= 0);
    if (y >= 0) ASSERT_EQ(tui_test_is_reverse(y, runner_find_col(y, "a1b2c3")), 1);
    ASSERT(strstr(b, " dim: not heard for 30s or more"
                     "  SIGNAL: RSSI over -30..0 dBFS") != NULL);
    ASSERT(strstr(b, "ALT ft  GS kt  TRK deg") != NULL);
    ASSERT(strstr(b, "more aircraft than the table holds") == NULL);
    s.adsb.overflow = 3;
    b = render(&s);
    ASSERT(strstr(b, "more aircraft than the table holds") != NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* The distance and bearing columns exist only while the SENSOR's
 * position is known — gps_location_current() returning a stamp. Without
 * one they are absent entirely, not drawn as a column of dashes that
 * still spends width; with one, a row whose own position the decoder
 * has not sent reads "-" in both while the columns stand.
 *
 * Both halves were seen to fail (2026-11-07), and they need separate
 * mutations because they pin opposite properties. `have_loc` forced to
 * 1 reddens the no-fix half here — and also
 * test_adsb_populated_render_sorted and
 * test_adsb_renders_a_polled_table, correctly: those two pin the plain
 * row layout, which is the same claim from the other side. `have_loc`
 * forced to 0 reddens this test alone, for the columns that must appear
 * once a fix exists. */
static void test_adsb_distance_and_bearing_need_a_sensor_position(void) {
    TEST_STATE(s);
    seed(&s);
    /* No --location and no --gps: gps_location_current() has nothing. */
    loc_stamp_t l;
    ASSERT_EQ(gps_location_current(&l, WALL0), LOC_SRC_NONE);
    const char *b = render(&s);
    ASSERT(strstr(b, "DIST") == NULL);
    ASSERT(strstr(b, "BRG") == NULL);
    ASSERT(strstr(b, "sensor at") == NULL);
    ASSERT(strstr(b, "no sensor position: --location or --gps") != NULL);
    /* The row cells are the plain ones: RSSI follows TRK directly. */
    ASSERT(strstr(b, ">a1b2c3   BAW117    2000   37000    452   285"
                     "   -18.3    1s  ") != NULL);

    /* A fixed --location is a known sensor position. */
    fixed_sensor();
    ASSERT_EQ(gps_location_current(&l, WALL0), LOC_SRC_FIXED);
    b = render(&s);
    ASSERT(strstr(b, " sensor at 51.50000, -0.12000 (fixed)") != NULL);
    ASSERT(strstr(b, " ICAO     FLIGHT    SQWK     ALT     GS   TRK"
                     "     DIST  BRG    RSSI   AGE  SIGNAL") != NULL);
    /* 53.1 km on bearing 033, and 23.1 km on 262, both computed from
     * the formulae outside sloth (the fixture comment). */
    ASSERT(strstr(b, ">a1b2c3   BAW117    2000   37000    452   285"
                     "     53.1  033   -18.3    1s  ") != NULL);
    ASSERT(strstr(b, " ~7fab01  -            -  ground      -     -"
                     "     23.1  262       -    5s") != NULL);
    /* A row the decoder has sent no position for: both cells "-", the
     * columns still there. */
    ASSERT(strstr(b, " 00ffee   N12345    1200    2500     95    11"
                     "        -    -    -3.1    5s  ") != NULL);
    ASSERT(strstr(b, "DIST km BRG deg true from the sensor") != NULL);
    ASSERT(strstr(b, "no sensor position") == NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* The decoder's three fault states, each said as itself rather than as
 * "nothing in range", and a live decoder with an empty table said as
 * that.
 *
 * The one absence — a stale feed must NOT read as quiet sky — was seen
 * to fail (2026-11-07): `else if (s->adsb.state == ADSB_STALE)` -> `else
 * if (0)` drops the empty table through to the generic branch and
 * reddens this test alone. */
static void test_adsb_stale_error_and_empty_states(void) {
    TEST_STATE(s);
    seed(&s);
    s.adsb_rows = NULL;
    s.adsb_count = 0;
    s.adsb.aircraft = 0;
    const char *b = render(&s);
    ASSERT(strstr(b, "the decoder lists no aircraft") != NULL);

    s.adsb.state = ADSB_STALE;
    s.adsb.age_s = 94;
    b = render(&s);
    ASSERT(strstr(b, "ADS-B: stale") != NULL);
    ASSERT(strstr(b, "age 94s") != NULL);
    ASSERT(strstr(b, "the decoder's clock has stopped advancing") != NULL);
    ASSERT(strstr(b, "the decoder lists no aircraft") == NULL);

    s.adsb.state = ADSB_ERROR;
    snprintf(s.adsb.err, sizeof(s.adsb.err), "open: No such file or directory");
    s.adsb.read_errors = 7;
    b = render(&s);
    ASSERT(strstr(b, "ADS-B: error") != NULL);
    ASSERT(strstr(b, " err open: No such file or directory") != NULL);
    ASSERT(strstr(b, "read err 7") != NULL);
    ASSERT(strstr(b, "the last read failed") != NULL);

    /* A stale decoder whose rows are still listed: the table draws, the
     * header says stale. The rows are what sloth last heard, which is
     * the honest thing to show, and their age says how long ago. */
    s.adsb.state = ADSB_STALE;
    s.adsb.err[0] = '\0';
    s.adsb_rows = g_rows;
    s.adsb_count = 4;
    s.adsb.aircraft = 4;
    b = render(&s);
    ASSERT(strstr(b, "ADS-B: stale") != NULL);
    ASSERT(strstr(b, ">a1b2c3   BAW117") != NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* Up / down stay inside the table, and the cursor follows the aircraft
 * rather than the row index: the table is re-sorted every poll, and an
 * aircraft heard again moves to the top.
 *
 * Seen to fail (2026-11-07): cursor_row()'s `if (s->adsb_sel_key)` ->
 * `if (0)`, so the cursor is the row index alone, reddens this test
 * alone — the '>' stays on the row number while the aircraft under it
 * changes. */
static void test_adsb_nav_follows_the_aircraft(void) {
    TEST_STATE(s);
    seed(&s);
    view_adsb_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.adsb_sel, 0);
    for (int i = 0; i < 10; i++) view_adsb_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.adsb_sel, 3);
    view_adsb_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.adsb_sel, 2);                        /* ~7fab01 */
    ASSERT_EQ(s.adsb_sel_key, (int)(0x7fab01u | 0x1000000u) + 1);
    const char *b = render(&s);
    ASSERT(strstr(b, ">~7fab01") != NULL);
    /* ~7fab01 is heard again and sorts to the top; the cursor goes with
     * it, not with row 2. */
    g_rows[2].last_seen = WALL0;
    b = render(&s);
    ASSERT(strstr(b, ">~7fab01") != NULL);
    const char *sel = strstr(b, ">~7fab01"), *next = strstr(b, " a1b2c3");
    ASSERT(sel && next && sel < next);
    /* Down from there lands on the row now below it. */
    view_adsb_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.adsb_sel, 1);
    b = render(&s);
    ASSERT(strstr(b, ">a1b2c3") != NULL);
    /* The remembered aircraft leaves the table: the index stands in. */
    s.adsb_sel_key = (int)(0x010203u) + 1;
    b = render(&s);
    ASSERT(strstr(b, ">a1b2c3") != NULL);
    /* An empty table takes no cursor and moves nowhere. */
    s.adsb_rows = NULL;
    s.adsb_count = 0;
    view_adsb_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.adsb_sel, 0);
    sloth_clock_test_set(NULL, NULL);
}

/* The same view against what the module's own poll produces, from a
 * hand-built document (not the parser's output): adsb_set_source() and
 * adsb_feed_doc() then adsb_health_poll(), so the row pointers, the
 * state and the figures the header reads are the real ones. */
static void test_adsb_renders_a_polled_table(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    g_wall = WALL0;
    sloth_clock_test_set(tm_, tw);
    static adsb_doc_t doc;
    memset(&doc, 0, sizeof(doc));
    doc.has_now = 1;
    doc.now = (double)WALL0;
    doc.has_messages = 1;
    doc.messages = 98765u;
    doc.n = 2;
    doc.ac[0].icao = 0x3c6444u;
    snprintf(doc.ac[0].flight, sizeof(doc.ac[0].flight), "DLH9LK");
    snprintf(doc.ac[0].squawk, sizeof(doc.ac[0].squawk), "1000");
    doc.ac[0].emergency = ADSB_EMERG_NONE;
    doc.ac[0].has_alt_baro = 1; doc.ac[0].alt_baro = 24000;
    doc.ac[0].has_gs = 1; doc.ac[0].gs = 398.0;
    doc.ac[0].has_track = 1; doc.ac[0].track = 97.5;
    doc.ac[0].has_rssi = 1; doc.ac[0].rssi = -11.2;
    doc.ac[0].has_seen = 1; doc.ac[0].seen = 0.4;
    doc.ac[1].icao = 0x400a11u;
    doc.ac[1].on_ground = 1;
    doc.ac[1].emergency = ADSB_EMERG_ABSENT;
    doc.ac[1].has_seen = 1; doc.ac[1].seen = 2.0;

    adsb_set_source("file:/run/readsb/aircraft.json");
    adsb_feed_doc(&doc, 0, WALL0 - 1, 500000);
    doc.now = (double)WALL0 + 1;
    adsb_feed_doc(&doc, 0, WALL0, 501000);
    adsb_health_poll(&s, WALL0, 501000);
    ASSERT_EQ(s.adsb.configured, 1);
    ASSERT_EQ(s.adsb.state, ADSB_LIVE);
    ASSERT_EQ(s.adsb_count, 2);

    const char *b = render(&s);
    ASSERT(strstr(b, "ADS-B: live  aircraft 2") != NULL);
    ASSERT(strstr(b, "msgs 98765") != NULL);
    ASSERT(strstr(b, "src file:/run/readsb/aircraft.json") != NULL);
    ASSERT(strstr(b, ">3c6444   DLH9LK    1000   24000    398    98"
                     "   -11.2    0s  ") != NULL);
    ASSERT(strstr(b, " 400a11   -            -  ground      -     -"
                     "       -    2s") != NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* The health strip's adsb token: present whenever --adsb is given,
 * absent otherwise (a default run's strip is unchanged), with the
 * aircraft count while live and the stalled age and the reader's error
 * on fault — the same shape as the gps token beside it.
 *
 * Both absences were seen to fail (2026-11-07), one mutation apiece.
 * `if (s->adsb.configured)` -> `if (1)` in iface_fmt_health_strip()
 * reddens this test and the nineteen existing health-strip tests in
 * tests/test_state.c, which is the point: the strip is shared, and a
 * token that is not opt-in costs every other row its exact text.
 * `a->aircraft > 0` -> `>= 0` reddens only the "0ac" absence below. */
static void test_adsb_health_strip_token(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    char buf[512];
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "adsb") == NULL);

    s.adsb.configured = 1;
    s.adsb.state = ADSB_LIVE;
    s.adsb.aircraft = 9;
    s.adsb.age_s = 1;
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  adsb live 9ac") != NULL);

    s.adsb.state = ADSB_STALE;
    s.adsb.age_s = 128;
    snprintf(s.adsb.err, sizeof(s.adsb.err), "read: Input/output error");
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  adsb stale 128s err read: Input/output error") != NULL);

    /* Live with an empty table says only the state: a count of 0 is not
     * news, the same way the gps token drops the satellite count. */
    s.adsb.state = ADSB_LIVE;
    s.adsb.aircraft = 0;
    s.adsb.err[0] = '\0';
    iface_fmt_health_strip(&s, buf, (int)sizeof(buf));
    ASSERT(strstr(buf, "  adsb live") != NULL);
    ASSERT(strstr(buf, "0ac") == NULL);
}

void run_adsb_view_tests(void) {
    TEST_SUITE("views: [^] ADS-B (#186, 2026-11-07)");
    RUN_TEST(test_adsb_empty_without_decoder);
    RUN_TEST(test_adsb_waiting_for_the_first_document);
    RUN_TEST(test_adsb_populated_render_sorted);
    RUN_TEST(test_adsb_distance_and_bearing_need_a_sensor_position);
    RUN_TEST(test_adsb_stale_error_and_empty_states);
    RUN_TEST(test_adsb_nav_follows_the_aircraft);
    RUN_TEST(test_adsb_renders_a_polled_table);
    RUN_TEST(test_adsb_health_strip_token);
    RUN_TEST(test_adsb_sbs_source_states);
}
