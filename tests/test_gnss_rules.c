#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "gps.h"
#include "sloth_clock.h"
#include "tune.h"

/*
 * The four GNSS rules (src/alerts/rules_gnss.c, 2026-11-03).
 *
 * Most inputs are hand-built sequences on the snapshot the rules read
 * (the one-second points and positioned fixes s->gnss_hist points at,
 * and s->gnss_sky), the way a gps_health_poll() copy would leave it: no
 * receiver, no capture, no fixture. The jamming feed tests and the
 * history test instead hand gpsd JSON lines, built here, to src/gps.c's
 * own parser and feed, so the series the rule reads is the one gps.c
 * computes. The figures are the shapes the research names
 * (research/gnss/): a nominal sky of 37..45 dB-Hz, a collapse to the
 * 27 dB-Hz signal-loss line, gpsd's TPV time and leapseconds, a 1024-week
 * rollover.
 *
 * Both clocks are pinned. The rules measure every window on the
 * monotonic clock the points carry; the wall clock is pinned only so the
 * engine's stamps are deterministic.
 *
 * Every "does not fire" below names the mutation it was seen red under
 * (agents/AGENTS.md: an absence assertion is worthless until seen to
 * fail).
 */

TEST_STATE(g_s);
static gnss_hist_t g_hist;     /* what s->gnss_hist points at here */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static uint64_t g_seq;
static long long g_rx;          /* the receiver's clock, unix ms */
static long long g_hostwall;    /* the host's wall clock, ms */

#define T0_WALL 1800000000LL

static void begin(void) {
    g_mono = 5000000;
    g_wall = (time_t)T0_WALL;
    sloth_clock_test_set(pin_mono, pin_wall);
    tune_reset();
    alerts_clear();             /* also rules_gnss_forget() at g_mono */
    memset(&g_hist, 0, sizeof(g_hist));
    g_s.gnss_hist = &g_hist;
    memset(&g_s.gnss_sky, 0, sizeof(g_s.gnss_sky));
    memset(&g_s.gnss_fix, 0, sizeof(g_s.gnss_fix));
    g_s.alert_count = 0;
    g_mono += 1000;             /* every point below is after the forget */
    g_seq = 0;
    g_rx = T0_WALL * 1000 + 400;      /* a USB receiver ~400 ms ahead */
    g_hostwall = T0_WALL * 1000;
}

static void end(void) {
    alerts_clear();
    tune_reset();
    sloth_clock_test_set(NULL, NULL);
}

static void evaluate(void) { alerts_update(&g_s); }

static int find_type(alert_type_t t) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == t) return i;
    return -1;
}

/* ── the one-second series ─────────────────────────────────────── */

/* One one-second point: the tracked rows' median C/N0 x 10 and count
 * (gps.c push_sec()), the used and listed counts, jam and mode. */
static void sec(int med_x10, int trk, int usat, int nsat, int jam, int mode) {
    gnss_hist_t *h = &g_hist;
    gnss_sec_pt_t *p = &h->secs[h->sec_head];
    memset(p, 0, sizeof(*p));
    p->ts = g_wall;
    p->mono_ms = g_mono;
    p->cn0_med_x10 = (int16_t)med_x10;
    p->trk = (uint8_t)trk;
    p->usat = (uint8_t)usat;
    p->nsat = (uint8_t)nsat;
    p->jam = (int16_t)jam;
    p->mode = (uint8_t)mode;
    h->sec_head = (h->sec_head + 1) % GNSS_SERIES_S;
    if (h->sec_n < GNSS_SERIES_S) h->sec_n++;
}

/* n one-second points of a steady sky, the clocks advancing with them. */
static void secs(int n, int med_x10, int trk, int usat, int nsat, int jam,
                 int mode) {
    for (int i = 0; i < n; i++) {
        g_mono += 1000;
        g_wall += 1;
        sec(med_x10, trk, usat, nsat, jam, mode);
    }
}

/* A nominal sky (42 dB-Hz, 10 of 14 tracked and used, 3D) for 120 s:
 * a baseline. */
static void nominal_sky(void) { secs(120, 420, 10, 10, 14, -1, 3); }

/* ── positioned fixes ──────────────────────────────────────────── */

typedef struct {
    double lat, lon, eph, speed, eps;
    int    has_eph, has_speed, has_eps, leap, reacq, has_rx;
} fixopt_t;

static fixopt_t nominal_fix(void) {
    fixopt_t o;
    memset(&o, 0, sizeof(o));
    o.lat = 51.5007400;
    o.lon = -0.1246900;
    o.eph = 3.0;
    o.has_eph = 1;
    o.has_speed = 1;            /* speed 0: a fixed sensor */
    o.leap = 18;
    o.has_rx = 1;
    return o;
}

static void put_fix(const fixopt_t *o) {
    gnss_hist_t *h = &g_hist;
    gnss_fix_pt_t *p = &h->fixes[h->fix_head];
    memset(p, 0, sizeof(*p));
    p->ts = g_wall;
    p->seq = ++g_seq;
    p->mono_ms = g_mono;
    p->wall_ms = g_hostwall;
    p->lat = o->lat;
    p->lon = o->lon;
    p->mode = 3;
    p->usat = 10;
    p->has_eph = o->has_eph;
    p->eph = o->eph;
    p->has_speed = o->has_speed;
    p->speed = o->speed;
    p->has_eps = o->has_eps;
    p->eps = o->eps;
    p->has_rx_time = o->has_rx;
    p->rx_time_ms = g_rx;
    p->has_time_off = o->has_rx;
    p->time_off_ms = g_rx - g_hostwall;
    p->leap = o->leap;
    p->reacq = o->reacq || h->fix_n == 0;
    h->fix_head = (h->fix_head + 1) % GNSS_FIX_HIST;
    if (h->fix_n < GNSS_FIX_HIST) h->fix_n++;
}

/* One positioned fix one second after the last: every clock advances
 * one second unless the caller moved g_rx / g_hostwall first. */
static void fix(const fixopt_t *o) {
    g_mono += 1000;
    g_wall += 1;
    g_rx += 1000;
    g_hostwall += 1000;
    put_fix(o);
}

/* A fix for the receiver epoch rx_ms after the last one, read by sloth
 * mono_ms after the last read: a reader that stalls and then drains
 * what gpsd queued reads epochs a second apart a millisecond apart. The
 * host's wall clock moves with its monotonic one, as the framing stamp
 * does. */
static void fix_read(const fixopt_t *o, uint64_t mono_ms, long long rx_ms) {
    g_mono += mono_ms;
    g_hostwall += (long long)mono_ms;
    g_wall = (time_t)(g_hostwall / 1000);
    g_rx += rx_ms;
    put_fix(o);
}

static void fixes(int n, const fixopt_t *o) {
    for (int i = 0; i < n; i++) fix(o);
}

/* 0.001 degree of latitude is 111.2 m on the mean radius. */
#define DLAT_100M (100.0 / 111195.0)

/* ── a sky snapshot ────────────────────────────────────────────── */

static void sky(const int *cn0_db, int n, int used) {
    gnss_sky_t *k = &g_s.gnss_sky;
    memset(k, 0, sizeof(*k));
    k->valid = 1;
    k->ts = g_wall;
    k->mono_ms = g_mono;
    k->nsat = n;
    k->usat = used ? n : 0;
    k->n = n;
    for (int i = 0; i < n; i++) {
        gnss_sat_t *s = &k->sats[i];
        s->prn = (int16_t)(i + 1);
        s->gnssid = 0;
        s->svid = (int16_t)(i + 1);
        s->used = (uint8_t)used;
        s->has_cn0 = 1;
        s->cn0_x10 = (int16_t)(cn0_db[i] * 10);
    }
}

/* ══ GNSS_JAMMING ══════════════════════════════════════════════════ */

static void test_jam_collapse_fires_warn(void) {
    begin();
    nominal_sky();
    secs(5, 250, 10, 6, 14, -1, 3);         /* every bird down to 25 dB-Hz */
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "tracked median C/N0 42.0 -> 25.0 dB-Hz") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail,
                      "tracked 10 -> 10, used 10 -> 6, 14 still listed") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "interference or jamming") != NULL);
        ASSERT_STR(g_s.alerts[i].technique, "T1464");
    }
    end();
}

static void test_jam_fix_lost_is_crit(void) {
    begin();
    nominal_sky();
    secs(5, 120, 10, 0, 14, -1, 1);         /* mode 1, nothing used, sky listed */
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_CRIT);
        ASSERT(strstr(g_s.alerts[i].detail, "fix lost") != NULL);
    }
    end();
}

/* A TPV with no mode (gpsd's 0, "unknown") is not a lost fix: the
 * collapse is still WARN, not CRIT. Seen red with fix_lost back at
 * mode < 2. */
static void test_jam_unknown_mode_is_not_fix_lost(void) {
    begin();
    nominal_sky();
    secs(5, 250, 10, 6, 14, -1, 0);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_WARN);
    end();
}

/* Every satellite lost from tracking at once (ss 0 on all 14), the sky
 * still listed and the fix gone: the research's end state, a level of
 * 0 against the baseline. */
static void test_jam_every_satellite_lost_fires_crit(void) {
    begin();
    nominal_sky();
    secs(5, 0, 0, 0, 14, -1, 1);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_CRIT);
        ASSERT(strstr(g_s.alerts[i].detail, "42.0 -> 0.0 dB-Hz") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "tracked 10 -> 0") != NULL);
    }
    end();
}

/* The list itself shrinks with the drop (14 listed -> 8, six tracked at
 * 25 dB-Hz, used 10 -> 4): satellites leaving the sky, which a raised
 * noise floor does not do ("while nSat is unchanged"). Seen red with the
 * nSat condition (nsat_held) removed from rule_gnss_jamming. */
static void test_jam_with_the_list_falling_does_not_fire(void) {
    begin();
    nominal_sky();
    secs(5, 250, 6, 4, 8, -1, 3);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* A sky falling 20 dB over five minutes (0.07 dB/s, used 10 -> 4): the
 * newest point is 25 dB-Hz, 17 under where it started, but only ~3 dB
 * under the 60 s before the window. Seen red with the baseline taken
 * over every point before the window (lo = 0 in rule_gnss_jamming):
 * that mean is ~35 dB-Hz and the "drop" passes 10 dB. */
static void test_jam_slow_decline_does_not_fire(void) {
    begin();
    for (int t = 0; t < 300; t++) {
        g_mono += 1000;
        g_wall += 1;
        int cn0 = 450 - (200 * t) / 299;
        int used = 10 - (6 * t) / 299;
        sec(cn0, 10, used, 14, -1, 3);
    }
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* Under trees: the mean falls 12 dB in a few seconds but the receiver
 * keeps its solution (used 10 -> 9). Seen red with the used-set
 * condition dropped (collapse on the C/N0 drop alone). */
static void test_jam_drop_without_used_fall_does_not_fire(void) {
    begin();
    nominal_sky();
    secs(5, 300, 10, 9, 14, -1, 3);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* The antenna pulled: the sky empties (nsat 0) rather than every bird
 * fading in place. Two guards hold it since the nSat condition arrived:
 * seen red with both the cur->nsat > 0 condition and nsat_held removed
 * (either alone keeps it quiet). */
static void test_jam_empty_sky_does_not_fire(void) {
    begin();
    nominal_sky();
    secs(5, 0, 0, 0, 0, -1, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* Twenty seconds of history is no baseline. Seen red with
 * GNSS_JAM_BASELINE_MIN set to 1. */
static void test_jam_without_a_baseline_does_not_fire(void) {
    begin();
    secs(20, 420, 10, 10, 14, -1, 3);
    secs(5, 120, 10, 0, 14, -1, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* The receiver went quiet ten seconds ago: its last word is not now.
 * Seen red with the GNSS_LIVE_MS check removed. */
static void test_jam_stale_series_does_not_fire(void) {
    begin();
    nominal_sky();
    secs(5, 120, 10, 0, 14, -1, 1);
    g_mono += 10000;
    g_wall += 10;
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* A standing jam stays asserted after its collapse has aged into what
 * would be the baseline: the onset baseline is held while the mean
 * stays down. Seen red with the held baseline dropped (jam_active never
 * consulted): the count stops rising once the jammed points fill the
 * baseline window. */
static void test_jam_held_while_down(void) {
    begin();
    nominal_sky();
    secs(5, 250, 10, 6, 14, -1, 3);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    for (int t = 0; t < 120; t++) {
        secs(1, 250, 10, 6, 14, -1, 3);
        evaluate();
    }
    i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT(g_s.alerts[i].count >= 121);
    end();
}

static void test_jam_indicator_held_fires(void) {
    begin();
    secs(40, 420, 10, 10, 14, 200, 3);      /* jamInd 200 for 40 s, sky steady */
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_JAMMING);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "u-blox jamInd >= 200 for 40 s") != NULL);
    }
    end();
}

/* Twenty seconds of a high jamInd is not gnss.jam_hold_s (30). Seen red
 * with the hold test reduced to "a run exists" (held = run_from != 0). */
static void test_jam_indicator_short_does_not_fire(void) {
    begin();
    secs(60, 420, 10, 10, 14, 10, 3);
    secs(20, 420, 10, 10, 14, 200, 3);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    /* and the knob reaches the rule */
    ASSERT_EQ(tune_set("gnss.jam_hold_s=15", NULL, 0), 0);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_JAMMING) >= 0);
    end();
}

/* A gap of ten seconds with no TPV inside a high run breaks it: the
 * hold is not known across it. Seen red with the GNSS_JAM_GAP_MS break
 * removed. */
static void test_jam_indicator_gap_breaks_the_hold(void) {
    begin();
    secs(20, 420, 10, 10, 14, 200, 3);
    g_mono += 10000;
    g_wall += 10;
    secs(15, 420, 10, 10, 14, 200, 3);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    end();
}

/* One second through gps.c as gpsd sends it: a SKY listing n
 * satellites, the first trk tracked at ss, the rest at ss 0 (gpsd's
 * listed-but-untracked rows), the first used of them used; then a TPV
 * of the given mode. */
static void feed_second(int n, int trk, double ss, int used, int mode) {
    char sky[4096];
    int off = snprintf(sky, sizeof(sky),
                       "{\"class\":\"SKY\",\"nSat\":%d,\"uSat\":%d,\"satellites\":[",
                       n, used);
    for (int i = 0; i < n && off < (int)sizeof(sky) - 128; i++)
        off += snprintf(sky + off, sizeof(sky) - (size_t)off,
                        "%s{\"PRN\":%d,\"el\":%d,\"az\":%d,\"ss\":%.1f,\"used\":%s}",
                        i ? "," : "", i + 1, 15 + 5 * i, (40 * i) % 360,
                        i < trk ? ss : 0.0, i < used ? "true" : "false");
    snprintf(sky + off, sizeof(sky) - (size_t)off, "]}");
    char tpv[256];
    snprintf(tpv, sizeof(tpv),
             "{\"class\":\"TPV\",\"mode\":%d,\"lat\":51.50074,"
             "\"lon\":-0.12469,\"eph\":3.0}", mode);
    g_mono += 1000;
    g_wall += 1;
    g_hostwall += 1000;
    gpsd_msg_t m;
    ASSERT_EQ(gpsd_json_parse(sky, strlen(sky), &m), 1);
    gps_location_feed_gpsd_ms(&m, g_hostwall);
    ASSERT_EQ(gpsd_json_parse(tpv, strlen(tpv), &m), 1);
    gps_location_feed_gpsd_ms(&m, g_hostwall);
}

static void feed_begin(void) {
    begin();
    gps_location_reset();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
}

static void feed_end(void) {
    gps_location_reset();
    memset(&g_s.gps, 0, sizeof(g_s.gps));
    end();
}

/* Every tracked satellite down 17 dB at once through the real feed, the
 * sky listed and the used set falling: the collapse fires. */
static void test_jam_collapse_through_the_feed_fires(void) {
    feed_begin();
    for (int t = 0; t < 120; t++) feed_second(14, 10, 42.0, 9, 3);
    for (int t = 0; t < 5; t++) feed_second(14, 10, 25.0, 5, 3);
    gps_health_poll(&g_s, g_wall);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_JAMMING) >= 0);
    feed_end();
}

/* A building blocks part of the sky: four of the ten tracked satellites
 * go to ss 0 and the other six stay at exactly 42 dB-Hz, the used set
 * 9 -> 6, all 14 still listed. No tracked satellite's C/N0 fell. The
 * first draft averaged the ss-0 rows into the mean (30.0 -> 18.0
 * dB-Hz) and fired WARN. Seen red with push_sec() taking the median over every row with
 * an ss, the untracked ss 0 rows included (and on the rule's first draft). */
static void test_jam_partial_obstruction_does_not_fire(void) {
    feed_begin();
    for (int t = 0; t < 120; t++) feed_second(14, 10, 42.0, 9, 3);
    for (int t = 0; t < 5; t++) feed_second(14, 6, 42.0, 6, 3);
    gps_health_poll(&g_s, g_wall);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_JAMMING), -1);
    feed_end();
}

/* ══ GNSS_TIME_JUMP ════════════════════════════════════════════════ */

static void test_time_jump_fires(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 5000;                       /* the receiver's clock moves 5 s */
    fixes(2, &o);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_TIME_JUMP);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "stepped +5000 ms") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "clock offset +400 -> +5400 ms") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "host clock step +0 ms") != NULL);
        ASSERT_STR(g_s.alerts[i].technique, "");
    }
    end();
}

/* The host's clock is stepped 5 s (an NTP step, `date -s`): the offset
 * moves 5 s, the receiver did not. Seen red with rx_step() taking the
 * wall clock in place of the monotonic one ((rx - wall_ms) deltas). */
static void test_time_jump_host_step_does_not_fire(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_hostwall += 5000;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* The first fix after a no-fix TPV has no prior to step from. Seen red
 * with the b->reacq skip removed. */
static void test_time_jump_first_fix_after_loss_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 30000;
    o.reacq = 1;
    fix(&o);
    o.reacq = 0;
    fixes(2, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* A leap second inserted: TPV leapseconds 18 -> 19 and UTC steps back
 * one second. Seen red with the Δleap branch of time_step_benign()
 * removed. */
static void test_time_jump_leap_second_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx -= 1000;
    o.leap = 19;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* After a cold boot the receiver has no leap count (gpsd leapseconds
 * absent) and its UTC is off by the firmware's assumption; when the
 * subframe arrives it steps by whole seconds and leapseconds appears.
 * Seen red with the unknown -> known branch removed. */
static void test_time_jump_leap_count_arriving_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    o.leap = -1;
    fixes(10, &o);
    g_rx -= 2000;
    o.leap = 18;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* A leap second whose leapseconds change rides a later TPV: a
 * one-second step at UTC midnight. Seen red with the midnight branch
 * removed. */
static void test_time_jump_at_utc_midnight_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    g_rx = (T0_WALL / 86400 + 1) * 86400LL * 1000 - 10000;  /* 10 s before midnight */
    fixes(10, &o);
    g_rx -= 1000;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* The receiver's date falls back 1024 weeks: the rollover fault the
 * research says to name as a fault, not an attack. Seen red with the
 * rollover loop of time_step_benign() removed. */
static void test_time_jump_week_rollover_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx -= 1024LL * 7 * 86400 * 1000;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* A step that does not hold on the next fix (a TPV framed late, then
 * the stream back on time) is not a moved clock. Seen red with the
 * next-fix confirmation removed (fire on the pair alone). */
static void test_time_jump_must_hold(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 5000;
    fix(&o);
    g_rx -= 5000;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* The pair is judged only once the fix after it is in: none on the tick
 * the step arrives, the finding on the tick after. The first-tick
 * absence seen red with the next-fix confirmation replaced by a direct
 * fire on the pair. */
static void test_time_jump_waits_for_the_next_fix(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 5000;
    fix(&o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    fix(&o);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_TIME_JUMP) >= 0);
    end();
}

/* 800 ms is under the 1000 ms default (USB wobble by the HOWTO's
 * account) and over a tuned 500. The first half's absence seen red with
 * thr hard-coded to 500 in rule_gnss_time_jump (the knob not read). */
static void test_time_jump_threshold_is_the_knob(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 800;
    fixes(2, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();

    begin();
    ASSERT_EQ(tune_set("gnss.time_jump_ms=500", NULL, 0), 0);
    ASSERT(tune_set("gnss.time_jump_ms=199", NULL, 0) != 0);   /* the HOWTO's floor */
    fixes(10, &o);
    g_rx += 800;
    fixes(2, &o);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_TIME_JUMP) >= 0);
    end();
}

/* 'c' clears the alerts; a jump already judged is not judged again.
 * Seen red with the b->mono_ms <= g_gnss.forget_mono test removed from
 * rule_gnss_time_jump. */
static void test_time_jump_not_replayed_after_clear(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 5000;
    fixes(2, &o);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_TIME_JUMP) >= 0);
    alerts_clear();
    g_s.alert_count = 0;
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* A receiver whose clock steps back 5 s at the ordinary cadence: the
 * queued-read skip below must not swallow a backward step. */
static void test_time_jump_backward_step_fires(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx -= 5000;
    fixes(2, &o);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_TIME_JUMP);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT(strstr(g_s.alerts[i].detail, "stepped -5000 ms") != NULL);
    end();
}

/* The reader stalls four seconds (the TUI stopped with Ctrl-Z, a loaded
 * Pi) and then drains the four TPVs gpsd queued, a millisecond apart.
 * Receipt time is not the epoch's time, so the queued fixes read -3000,
 * -2001, -1002 and -3 ms against the host's monotonic clock and the
 * stream is on time again after them. The first draft fired on this (+1998 ms
 * "held"): it measured the pair after an outlier from the fix before
 * it, which was itself an outlier. Seen red on the rule's first draft, and here
 * with both the queued-read skip and the next-fix hold removed (either
 * one alone keeps it quiet). */
static void test_time_jump_reader_stall_does_not_fire(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    fix_read(&o, 4000, 1000);
    fix_read(&o, 1, 1000);
    fix_read(&o, 1, 1000);
    fix_read(&o, 1, 1000);
    fixes(5, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* The same drain under gnss.time_jump_ms=3000 after a six-second stall:
 * the queued fixes step back toward the anchor by 999 ms each, under
 * half the threshold, so the next-fix hold reads the first of them as a
 * held -5000 ms step. Only the queued-read skip tells them apart. Seen
 * red with the queued-read skip removed (and on the rule's first draft). */
static void test_time_jump_backlog_under_a_raised_threshold_does_not_fire(void) {
    begin();
    ASSERT_EQ(tune_set("gnss.time_jump_ms=3000", NULL, 0), 0);
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    fix_read(&o, 6000, 1000);
    for (int k = 0; k < 5; k++) fix_read(&o, 1, 1000);
    fixes(5, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* The host suspended for a minute: CLOCK_MONOTONIC stopped, the
 * receiver's clock and the host's wall clock did not, and nothing marks
 * the next fix a reacquisition unless gpsd sent a no-fix TPV. Both
 * independent clocks moving 60 s past the monotonic one is the host's
 * clock stopping, not the receiver's moving. Seen red with
 * host_suspended() returning 0 (and on the rule's first draft). */
static void test_time_jump_host_suspend_does_not_fire(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 60000;
    g_hostwall += 60000;
    fixes(3, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_TIME_JUMP), -1);
    end();
}

/* ══ GNSS_POSITION_JUMP ════════════════════════════════════════════ */

static void test_pos_jump_fires(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    o.lat += DLAT_100M;                 /* 100 m in one second, speed 0 */
    fix(&o);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_POSITION_JUMP);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "fix moved 100 m in 1.0 s, past the 18 m bound") != NULL);
        ASSERT_STR(g_s.alerts[i].technique, "");
    }
    end();
}

/* A vehicle at 30 m/s moves 30 m a second; the reported speed is in the
 * bound. Seen red with the speed term dropped (v = 0 in pos_bound_m()). */
static void test_pos_jump_moving_vehicle_does_not_fire(void) {
    begin();
    fixopt_t o = nominal_fix();
    o.speed = 30.0;
    for (int i = 0; i < 20; i++) {
        o.lat += 30.0 / 111195.0;
        fix(&o);
    }
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_POSITION_JUMP), -1);
    end();
}

/* A cold start's first fix lands 5 km from the last one: there is no
 * prior to jump from. Seen red with the b->reacq skip removed. */
static void test_pos_jump_cold_start_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    o.lat += 50 * DLAT_100M;
    o.reacq = 1;
    fix(&o);
    o.reacq = 0;
    fixes(2, &o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_POSITION_JUMP), -1);
    end();
}

/* No eph, no bound, no claim. Seen red with a missing eph read as 0 m
 * (pos_bound_m() not returning -1). */
static void test_pos_jump_without_eph_not_judged(void) {
    begin();
    fixopt_t o = nominal_fix();
    o.has_eph = 0;
    fixes(10, &o);
    o.lat += DLAT_100M;
    fix(&o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_POSITION_JUMP), -1);
    end();
}

/* 20 m against eph 3 + 3: over k = 3 (18 m), under k = 4 (24 m). The
 * k = 4 absence seen red with tune_val(TUNE_GNSS_POS_JUMP_K) replaced by
 * the constant 3 in rule_gnss_position_jump. */
static void test_pos_jump_k_is_the_knob(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    o.lat += 20.0 / 111195.0;
    fix(&o);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_POSITION_JUMP) >= 0);
    end();

    begin();
    ASSERT_EQ(tune_set("gnss.pos_jump_k=4", NULL, 0), 0);
    o = nominal_fix();
    fixes(10, &o);
    o.lat += 20.0 / 111195.0;
    fix(&o);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_POSITION_JUMP), -1);
    end();
}

/* A vehicle at 30 m/s (eph 3) whose reader stalls three seconds and
 * then drains three queued TPVs a millisecond apart: the fixes are a
 * second apart in the receiver's time and 30 m apart on the road, but
 * the first draft took dt from receipt, 0.001 s, and its bound shrank
 * to the 18 m of the error estimates ("fix moved 30 m in 0.0 s"). Then at
 * 35 m/s (eph 2) one TPV read 400 ms late and the next on time: a 0.6 s
 * receipt gap made a 33 m bound against 35 m of travel. Seen red with
 * fix_dt_s() returning the monotonic gap (and on the rule's first draft). */
static void test_pos_jump_queued_fixes_of_a_moving_receiver_do_not_fire(void) {
    begin();
    fixopt_t o = nominal_fix();
    o.speed = 30.0;
    for (int i = 0; i < 10; i++) {
        o.lat += 30.0 / 111195.0;
        fix(&o);
    }
    o.lat += 30.0 / 111195.0;
    fix_read(&o, 3000, 1000);
    for (int i = 0; i < 2; i++) {
        o.lat += 30.0 / 111195.0;
        fix_read(&o, 1, 1000);
    }
    for (int i = 0; i < 3; i++) {
        o.lat += 30.0 / 111195.0;
        fix(&o);
    }
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_POSITION_JUMP), -1);
    end();

    begin();
    o = nominal_fix();
    o.speed = 35.0;
    o.eph = 2.0;
    for (int i = 0; i < 10; i++) {
        o.lat += 35.0 / 111195.0;
        fix(&o);
    }
    o.lat += 35.0 / 111195.0;
    fix_read(&o, 1400, 1000);
    o.lat += 35.0 / 111195.0;
    fix_read(&o, 600, 1000);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_POSITION_JUMP), -1);
    end();
}

/* The receiver's clock stepping an hour forward must not stretch dt to
 * an hour and the bound with it: a spoofer moving the time and the
 * position together would hide the jump. Seen red with the plausibility
 * cap on the receiver's dt removed (dt 3601 s, bound 1818 m). */
static void test_pos_jump_time_step_does_not_widen_the_bound(void) {
    begin();
    fixopt_t o = nominal_fix();
    o.has_eps = 1;
    o.eps = 0.5;
    fixes(10, &o);
    g_rx += 3600000;
    o.lat += 10 * DLAT_100M;            /* 1 km */
    fix(&o);
    evaluate();
    ASSERT(find_type(ALERT_TYPE_GNSS_POSITION_JUMP) >= 0);
    end();
}

/* ══ GNSS_SPOOF_SUSPECT ════════════════════════════════════════════ */

static const int UNIFORM_HIGH[8] = { 54, 54, 54, 54, 54, 54, 54, 54 };
static const int HIGH_SPREAD[8]  = { 55, 54, 53, 53, 46, 41, 38, 34 };
static const int UNIFORM_MID[8]  = { 47, 47, 47, 47, 47, 47, 47, 47 };
static const int INDOOR[8]       = { 30, 30, 30, 30, 30, 30, 30, 30 };
static const int NOMINAL[8]      = { 46, 44, 43, 41, 39, 37, 33, 29 };

/* A reacquisition 5 km from the last good fix: heuristic 3. */
static void reacquire_far(void) {
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    o.lat += 50 * DLAT_100M;
    o.reacq = 1;
    fix(&o);
}

static void test_spoof_high_and_uniform_fires_low(void) {
    begin();
    sky(UNIFORM_HIGH, 8, 1);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_LOW);
        ASSERT(strstr(g_s.alerts[i].detail, "2 of 3 spoofing heuristics") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "[1] 8 used >= 53 dB-Hz (max 54.0)") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "[2] 8 used, mean 54.0 sd 0.0") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "[3]") == NULL);
        ASSERT_STR(g_s.alerts[i].technique, "");
    }
    end();
}

/* One heuristic alone (four birds over 53 dB-Hz, the set spread as an
 * authentic sky is) is never a finding. Seen red with the combination
 * gate lowered to one (nseen < 1). */
static void test_spoof_one_heuristic_does_not_fire(void) {
    begin();
    sky(HIGH_SPREAD, 8, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    begin();
    sky(UNIFORM_MID, 8, 1);             /* heuristic 2 alone */
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

/* Indoors every signal arrives through the same wall: uniform and low.
 * With a reacquisition jump beside it, heuristic 2 must still not count.
 * Seen red with the mean gate (gnss.spoof_cn0_mean_db) removed. */
static void test_spoof_indoor_uniform_does_not_count(void) {
    begin();
    reacquire_far();
    sky(INDOOR, 8, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

/* Satellites in view but not in the solution do not count: a spoofer
 * has to be in the fix to move it. Seen red with the a->used filter
 * removed. */
static void test_spoof_unused_satellites_do_not_count(void) {
    begin();
    sky(UNIFORM_HIGH, 8, 0);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

static void test_spoof_reacquisition_and_high_fires(void) {
    begin();
    reacquire_far();
    sky(HIGH_SPREAD, 8, 1);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_LOW);
        ASSERT(strstr(g_s.alerts[i].detail, "[1] 4 used") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "[3] reacquired 5000 m away") != NULL);
    }
    end();
}

static void test_spoof_all_three_is_warn_never_crit(void) {
    begin();
    reacquire_far();
    sky(UNIFORM_HIGH, 8, 1);
    evaluate();
    int i = find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].sev, ALERT_SEV_WARN);
        ASSERT(strstr(g_s.alerts[i].detail, "3 of 3") != NULL);
    }
    end();
}

/* A reacquisition jump, then a high sky 400 s later: outside one
 * gnss.spoof_window_s (300). Seen red with the window test removed. */
static void test_spoof_heuristics_outside_one_window_do_not_fire(void) {
    begin();
    reacquire_far();
    sky(NOMINAL, 8, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    g_mono += 400000;
    g_wall += 400;
    sky(HIGH_SPREAD, 8, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

/* A reacquisition to the same place, with the same time, is the
 * ordinary case: no heuristic 3. Seen red with heuristic 3 taking any
 * reacquisition (the moved / stepped test removed). */
static void test_spoof_ordinary_reacquisition_is_not_heuristic_3(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    o.reacq = 1;
    fix(&o);
    sky(HIGH_SPREAD, 8, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

/* A host suspend across a reacquisition: the receiver's clock and the
 * host wall clock both moved 60 s past the monotonic one. Heuristic 3
 * must not read that as a time step, so with a high sky alone there is
 * one heuristic and no alert. Seen red without host_suspended() in
 * heuristic 3's step test. */
static void test_spoof_host_suspend_is_not_heuristic_3(void) {
    begin();
    fixopt_t o = nominal_fix();
    fixes(10, &o);
    g_rx += 60000;
    g_hostwall += 60000;
    o.reacq = 1;
    fix(&o);
    sky(HIGH_SPREAD, 8, 1);
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

/* A stale sky is not evaluated: the receiver is not being heard. Seen
 * red with the sky's GNSS_LIVE_MS check removed. */
static void test_spoof_stale_sky_not_evaluated(void) {
    begin();
    sky(UNIFORM_HIGH, 8, 1);
    g_mono += 10000;
    g_wall += 10;
    evaluate();
    ASSERT_EQ(find_type(ALERT_TYPE_GNSS_SPOOF_SUSPECT), -1);
    end();
}

/* ══ the history the rules read ════════════════════════════════════ */

/* gps.c fills the fields the rules need: the monotonic and wall clocks
 * at receipt, the receiver's time, eps, leapseconds, and reacq on the
 * first positioned fix and on the first after a no-fix TPV or a lost
 * source; gps_health_poll() copies the rings onto the state. */
static void test_history_carries_what_the_rules_read(void) {
    begin();
    gps_location_reset();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gpsd_msg_t m;
    const char *tpv =
        "{\"class\":\"TPV\",\"mode\":3,\"time\":\"2027-01-15T08:00:00.000Z\","
        "\"lat\":51.50074,\"lon\":-0.12469,\"eph\":2.5,\"speed\":0.1,"
        "\"eps\":0.4,\"leapseconds\":18}";
    ASSERT_EQ(gpsd_json_parse(tpv, strlen(tpv), &m), 1);
    gps_location_feed_gpsd_ms(&m, T0_WALL * 1000 + 250);
    g_mono += 1000;
    gps_location_feed_gpsd_ms(&m, T0_WALL * 1000 + 1250);
    const char *nofix = "{\"class\":\"TPV\",\"mode\":1}";
    gpsd_msg_t n;
    ASSERT_EQ(gpsd_json_parse(nofix, strlen(nofix), &n), 1);
    g_mono += 1000;
    gps_location_feed_gpsd_ms(&n, T0_WALL * 1000 + 2250);
    g_mono += 1000;
    gps_location_feed_gpsd_ms(&m, T0_WALL * 1000 + 3250);
    gps_location_source_lost();
    g_mono += 1000;
    gps_location_feed_gpsd_ms(&m, T0_WALL * 1000 + 4250);
    gps_health_poll(&g_s, g_wall);
    const gnss_hist_t *h = g_s.gnss_hist;
    ASSERT(h != NULL && h != &g_hist);   /* gps.c's own per-poll copy */
    if (!h) { end(); return; }
    ASSERT_EQ(h->fix_n, 4);
    ASSERT_EQ(h->sec_n, 5);
    const gnss_fix_pt_t *f0 = &h->fixes[0], *f1 = &h->fixes[1];
    ASSERT_EQ(f0->reacq, 1);            /* the first */
    ASSERT_EQ(f1->reacq, 0);
    ASSERT_EQ(h->fixes[2].reacq, 1);    /* after mode 1 */
    ASSERT_EQ(h->fixes[3].reacq, 1);    /* after the source was lost */
    ASSERT_EQ(f1->mono_ms - f0->mono_ms, 1000);
    ASSERT_EQ(f0->wall_ms, T0_WALL * 1000 + 250);
    ASSERT(f0->has_rx_time);
    ASSERT_EQ(f0->leap, 18);
    ASSERT(f0->has_eps);
    ASSERT(f0->eps > 0.39 && f0->eps < 0.41);
    ASSERT(f0->has_speed && f0->has_eph);
    ASSERT_EQ(f0->seq + 1, f1->seq);
    ASSERT_EQ(h->secs[2].mode, 1);
    ASSERT_EQ(h->secs[3].mode, 3);
    ASSERT_EQ(h->secs[1].mono_ms, f1->mono_ms);
    gps_location_reset();
    memset(&g_s.gps, 0, sizeof(g_s.gps));
    end();
}

void run_gnss_rules_tests(void) {
    TEST_SUITE("GNSS rules: jamming, spoofing suspect, time and position jumps");
    RUN_TEST(test_jam_collapse_fires_warn);
    RUN_TEST(test_jam_fix_lost_is_crit);
    RUN_TEST(test_jam_unknown_mode_is_not_fix_lost);
    RUN_TEST(test_jam_every_satellite_lost_fires_crit);
    RUN_TEST(test_jam_with_the_list_falling_does_not_fire);
    RUN_TEST(test_jam_slow_decline_does_not_fire);
    RUN_TEST(test_jam_drop_without_used_fall_does_not_fire);
    RUN_TEST(test_jam_empty_sky_does_not_fire);
    RUN_TEST(test_jam_without_a_baseline_does_not_fire);
    RUN_TEST(test_jam_stale_series_does_not_fire);
    RUN_TEST(test_jam_held_while_down);
    RUN_TEST(test_jam_indicator_held_fires);
    RUN_TEST(test_jam_indicator_short_does_not_fire);
    RUN_TEST(test_jam_indicator_gap_breaks_the_hold);
    RUN_TEST(test_jam_collapse_through_the_feed_fires);
    RUN_TEST(test_jam_partial_obstruction_does_not_fire);
    RUN_TEST(test_time_jump_fires);
    RUN_TEST(test_time_jump_host_step_does_not_fire);
    RUN_TEST(test_time_jump_first_fix_after_loss_not_judged);
    RUN_TEST(test_time_jump_leap_second_not_judged);
    RUN_TEST(test_time_jump_leap_count_arriving_not_judged);
    RUN_TEST(test_time_jump_at_utc_midnight_not_judged);
    RUN_TEST(test_time_jump_week_rollover_not_judged);
    RUN_TEST(test_time_jump_must_hold);
    RUN_TEST(test_time_jump_waits_for_the_next_fix);
    RUN_TEST(test_time_jump_threshold_is_the_knob);
    RUN_TEST(test_time_jump_not_replayed_after_clear);
    RUN_TEST(test_time_jump_backward_step_fires);
    RUN_TEST(test_time_jump_reader_stall_does_not_fire);
    RUN_TEST(test_time_jump_backlog_under_a_raised_threshold_does_not_fire);
    RUN_TEST(test_time_jump_host_suspend_does_not_fire);
    RUN_TEST(test_pos_jump_fires);
    RUN_TEST(test_pos_jump_moving_vehicle_does_not_fire);
    RUN_TEST(test_pos_jump_cold_start_not_judged);
    RUN_TEST(test_pos_jump_without_eph_not_judged);
    RUN_TEST(test_pos_jump_k_is_the_knob);
    RUN_TEST(test_pos_jump_queued_fixes_of_a_moving_receiver_do_not_fire);
    RUN_TEST(test_pos_jump_time_step_does_not_widen_the_bound);
    RUN_TEST(test_spoof_high_and_uniform_fires_low);
    RUN_TEST(test_spoof_one_heuristic_does_not_fire);
    RUN_TEST(test_spoof_indoor_uniform_does_not_count);
    RUN_TEST(test_spoof_unused_satellites_do_not_count);
    RUN_TEST(test_spoof_reacquisition_and_high_fires);
    RUN_TEST(test_spoof_all_three_is_warn_never_crit);
    RUN_TEST(test_spoof_heuristics_outside_one_window_do_not_fire);
    RUN_TEST(test_spoof_ordinary_reacquisition_is_not_heuristic_3);
    RUN_TEST(test_spoof_host_suspend_is_not_heuristic_3);
    RUN_TEST(test_spoof_stale_sky_not_evaluated);
    RUN_TEST(test_history_carries_what_the_rules_read);
}
