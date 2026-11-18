#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "tui_glyph.h"
#include "dev_how.h"
#include "rf_distance.h"
#include "views/alerts.h"
#include "views/channel.h"
#include "views/devices.h"
#include "views/twins.h"

/*
 * The TUI forms of the glyph set (#195; docs/web-visual-spec.md §5,
 * R12). The pure functions in src/tui_glyph.c first, against the web's
 * numbers (web/ui/glyph.js smDbm() and the rest), then each view that
 * draws one, read back from the offscreen screen at 80 x 24.
 */

#define FULL "\xe2\x96\x88"
#define LOW1 "\xe2\x96\x81"
#define HALF "\xe2\x96\x84"

static time_t g_now;
static time_t now_fn(void) { return g_now; }
static void pin(time_t t) { g_now = t; sloth_clock_test_set(NULL, now_fn); }

TEST_STATE(g_s);

static void cells_str(const tg_cell_t *c, int n, char *out, size_t sz) {
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++)
        o += (size_t)snprintf(out + o, sz - o, "%s", c[i].glyph);
}

/* ── G2 ─────────────────────────────────────────────────── */

static void test_sm_scale_per_band(void) {
    int known = -1;
    ASSERT_EQ(tg_sm_s9(RF_RADIO_WIFI_2G, &known), -47); ASSERT_EQ(known, 1);
    ASSERT_EQ(tg_sm_s9(RF_RADIO_WIFI_5G, &known), -54); ASSERT_EQ(known, 1);
    ASSERT_EQ(tg_sm_s9(RF_RADIO_WIFI_6G, &known), -56); ASSERT_EQ(known, 1);
    ASSERT_EQ(tg_sm_s9(RF_RADIO_BLE, &known), -47);     ASSERT_EQ(known, 1);
    /* No band: the 2.4 GHz row, and said so. */
    ASSERT_EQ(tg_sm_s9(RF_RADIO_NONE, &known), -47);    ASSERT_EQ(known, 0);
}

static void test_sm_words_step_as_the_face(void) {
    char w[16];
    tg_sm_word(-47, -47, w, sizeof(w)); ASSERT_STR(w, "S9");
    tg_sm_word(-48, -47, w, sizeof(w)); ASSERT_STR(w, "S8");
    tg_sm_word(-59, -47, w, sizeof(w)); ASSERT_STR(w, "S7");
    tg_sm_word(-37, -47, w, sizeof(w)); ASSERT_STR(w, "S9+10");
    tg_sm_word(-27, -47, w, sizeof(w)); ASSERT_STR(w, "S9+20");
    /* The 5 GHz face sits 7 dB lower: -54 is S9 there and S7 on 2.4. */
    tg_sm_word(-54, -54, w, sizeof(w)); ASSERT_STR(w, "S9");
    tg_sm_word(-54, -47, w, sizeof(w)); ASSERT_STR(w, "S7");
    /* Past either end: drawn at the end and counted. */
    tg_sm_word(-110, -47, w, sizeof(w)); ASSERT_STR(w, "S1");
    ASSERT_EQ(tg_sm_clamped(-110, -47), 1);
    ASSERT_EQ(tg_sm_clamped(-10, -47), 1);
    ASSERT_EQ(tg_sm_clamped(-60, -47), 0);
    /* 0 dBm is sloth's "unseen": no reading at all. */
    tg_sm_word(0, -47, w, sizeof(w)); ASSERT_STR(w, "-");
    ASSERT_EQ(tg_sm_level(0, -47), 0);
}

static void test_sm_cells_are_the_emitter_report_line(void) {
    tg_cell_t c[TG_SM_CELLS];
    char s[128];
    int n = tg_sm_cells(-59, -47, c);
    ASSERT_EQ(n, TG_SM_CELLS);
    cells_str(c, n, s, sizeof(s));
    ASSERT_STR(s, FULL FULL FULL FULL FULL FULL FULL LOW1 LOW1 " " LOW1 LOW1);
    ASSERT_EQ(c[0].tone, TG_NORMAL);
    ASSERT_EQ(c[7].tone, TG_DIM);
    /* Past S9 the lit run is heat. */
    n = tg_sm_cells(-30, -47, c);
    ASSERT_EQ(c[10].tone, TG_HEAT_HI);
    ASSERT_EQ(c[11].tone, TG_DIM);
    ASSERT_EQ(tg_sm_cells(0, -47, c), 0);
}

/* ── G3 ─────────────────────────────────────────────────── */

static void test_hz_two_bands_split_at_half(void) {
    ASSERT_EQ(tg_hz_level(TG_HZ_UNSEEN, 10), -1);
    ASSERT_EQ(tg_hz_level(0, 10), 0);
    ASSERT_EQ(tg_hz_level(5, 10), 1);
    ASSERT_EQ(tg_hz_level(6, 10), 2);
    ASSERT_EQ(tg_hz_level(10, 10), 2);
    /* An odd scale: 3 of 7 is under half, 4 over. */
    ASSERT_EQ(tg_hz_level(3, 7), 1);
    ASSERT_EQ(tg_hz_level(4, 7), 2);
    ASSERT_STR(tg_hz_cell(TG_HZ_UNSEEN, 10).glyph, " ");
    ASSERT_STR(tg_hz_cell(0, 10).glyph, "_");
    ASSERT_STR(tg_hz_cell(5, 10).glyph, HALF);
    ASSERT_STR(tg_hz_cell(9, 10).glyph, FULL);
    ASSERT_EQ(tg_hz_cell(9, 10).tone, TG_HEAT_MID);
}

static void test_channel_minutes_from_the_cumulative_total(void) {
    time_t t0 = 1700000000 - (1700000000 % 60);
    memset(&g_s, 0, sizeof(g_s));
    g_s.channel_count = 1;
    g_s.channels[0].channel = 6;
    g_s.channels[0].ctrl_total = 100;
    uint32_t c[CHAN_HZ_CELLS], max = 0;
    ASSERT_EQ(channel_hz_cells(6, c, &max), 0);
    channel_hz_update(&g_s, t0);              /* baseline only */
    ASSERT_EQ(channel_hz_cells(6, c, &max), 1);
    ASSERT_EQ(c[CHAN_HZ_CELLS - 1], 0u);
    ASSERT_EQ(c[0], TG_HZ_UNSEEN);
    g_s.channels[0].ctrl_total = 160;
    channel_hz_update(&g_s, t0 + 30);
    g_s.channels[0].ctrl_total = 190;
    channel_hz_update(&g_s, t0 + 60);
    channel_hz_cells(6, c, &max);
    ASSERT_EQ(c[CHAN_HZ_CELLS - 2], 60u);
    ASSERT_EQ(c[CHAN_HZ_CELLS - 1], 30u);
    ASSERT_EQ(max, 60u);
    /* A quiet minute is a zero, not a gap, and the scale holds (R11). */
    channel_hz_update(&g_s, t0 + 120);
    channel_hz_cells(6, c, &max);
    ASSERT_EQ(c[CHAN_HZ_CELLS - 1], 0u);
    ASSERT_EQ(c[CHAN_HZ_CELLS - 3], 60u);
    ASSERT_EQ(max, 60u);
    /* The counter restarted (ctrl_frames.c evicted the channel): the
     * new total is all new. */
    g_s.channels[0].ctrl_total = 7;
    channel_hz_update(&g_s, t0 + 121);
    channel_hz_cells(6, c, &max);
    ASSERT_EQ(c[CHAN_HZ_CELLS - 1], 7u);
}

static void test_channel_view_draws_the_strip_at_80x24(void) {
    time_t t0 = 1700000000 - (1700000000 % 60);
    pin(t0 + 60);
    memset(&g_s, 0, sizeof(g_s));
    g_s.channel_count = 1;
    g_s.channels[0].channel = 6;
    g_s.channels[0].ap_count = 2;
    g_s.channels[0].best_signal = -50;
    g_s.channels[0].retry_pct = -1;
    g_s.channels[0].last_seen = t0;
    snprintf(g_s.channels[0].top_ssid, sizeof(g_s.channels[0].top_ssid), "x");
    g_s.channels[0].ctrl_total = 100;
    channel_hz_update(&g_s, t0);
    g_s.channels[0].ctrl_total = 160;
    channel_hz_update(&g_s, t0 + 1);
    g_s.channels[0].ctrl_total = 190;
    channel_hz_update(&g_s, t0 + 60);

    ASSERT_EQ(tui_init_offscreen(24, 220), 0);
    tui_test_erase();
    view_channel_draw(&g_s);
    ASSERT_SCREEN_HAS(FULL HALF " 60");
    ASSERT_SCREEN_HAS("ctrl/min, last 24 min");
    ASSERT_SCREEN_HAS("each row 0 to its busiest minute");

    /* 80 columns: the row is cut, not wrapped, so nothing falls off. */
    ASSERT_EQ(tui_init_offscreen(24, 80), 0);
    tui_test_erase();
    view_channel_draw(&g_s);
    ASSERT_EQ(tui_test_overflow(), 0);
    ASSERT_EQ(runner_screen_find(" 6      "), 3);
}

/* ── G4 ─────────────────────────────────────────────────── */

static void test_how_levels(void) {
    ASSERT_EQ(tg_how_level(0.0, 1.0), 0);
    ASSERT_EQ(tg_how_level(0.01, 1.0), 1);
    ASSERT_EQ(tg_how_level(0.25, 1.0), 1);
    ASSERT_EQ(tg_how_level(0.26, 1.0), 2);
    ASSERT_EQ(tg_how_level(1.0, 1.0), 4);
    /* Against the grid's maximum, not against 1. */
    ASSERT_EQ(tg_how_level(0.5, 0.5), 4);
    ASSERT_STR(tg_how_cell(0, 0.0, 1.0).glyph, " ");
    ASSERT_STR(tg_how_cell(1, 0.0, 1.0).glyph, "\xc2\xb7");
    ASSERT_STR(tg_how_cell(1, 0.5, 1.0).glyph, "\xe2\x96\xaa");
    ASSERT_EQ(tg_how_cell(1, 1.0, 1.0).tone, TG_HEAT_PEAK);
}

static void test_dev_how_counts_an_hour_once(void) {
    time_t t = 1700000000;
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x42 };
    memcpy(g_s.devices[0].mac, mac, 6);
    g_s.devices[0].last_seen = t;
    g_s.device_count = 1;
    uint16_t p[DEV_HOW_CELLS], w[DEV_HOW_CELLS];
    int cell = dev_how_cell(t);
    dev_how_observe(&g_s, t);
    dev_how_observe(&g_s, t + 5);
    ASSERT_EQ(dev_how_get(mac, p, w), 1);
    ASSERT_EQ(p[cell], 1);
    ASSERT_EQ(w[cell], 1);
    /* The next hour: watched, but the record was not refreshed, so the
     * device was absent in it. */
    int next = dev_how_cell(t + 3600);
    dev_how_observe(&g_s, t + 3600);
    dev_how_get(mac, p, w);
    ASSERT_EQ(w[next], 1);
    ASSERT_EQ(p[next], 0);
    static const uint8_t other[6] = { 0x02, 0, 0, 0, 0, 0x43 };
    ASSERT_EQ(dev_how_get(other, p, w), 0);
}

static void test_devices_detail_meter_and_grid_at_80x24(void) {
    time_t t = 1700000000;
    pin(t);
    memset(&g_s, 0, sizeof(g_s));
    static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x42 };
    device_t *d = &g_s.devices[0];
    memcpy(d->mac, mac, 6);
    d->last_seen = t;
    d->signal_dbm = -61;                     /* S9 - 7 dB on 5 GHz: S7 */
    d->dist.radio = RF_RADIO_WIFI_5G;
    d->dist.raw_dbm[0] = -61; d->dist.raw_dbm[1] = -70; d->dist.raw_dbm[2] = -58;
    d->dist.raw_n = 3;
    g_s.device_count = 1;
    dev_how_observe(&g_s, t);
    g_s.device_detail = 1;
    memcpy(g_s.device_detail_mac, mac, 6);

    ASSERT_EQ(tui_init_offscreen(24, 80), 0);
    tui_test_erase();
    view_devices_draw(&g_s);
    ASSERT_SCREEN_HAS("Signal   " FULL FULL FULL FULL FULL FULL FULL LOW1 LOW1
                      " " LOW1 LOW1 "  S7      -61 dBm  5 GHz scale");
    ASSERT_SCREEN_HAS("range S6 -70 to S8 -58 dBm over the last 3 samples");
    ASSERT_SCREEN_HAS("HOUR OF WEEK");
    ASSERT_SCREEN_HAS("seen in 1 of 1 hours watched");
    ASSERT_EQ(tui_test_overflow(), 0);
    /* The present cell is a heat square, at its day and hour. */
    int cell = dev_how_cell(t);
    static const char *const day[7] =
        { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    int y = runner_screen_find(day[cell / 24]);
    ASSERT(y > 0);
    ASSERT_EQ(tui_test_pair(y, 6 + cell % 24), CP_HEAT_PEAK);

    /* No band on the record: the 2.4 GHz row, and the words say so. */
    d->dist.radio = RF_RADIO_NONE;
    tui_test_erase();
    view_devices_draw(&g_s);
    ASSERT_SCREEN_HAS("band unknown: 2.4 GHz scale");
    /* No reading: no meter. */
    d->signal_dbm = 0;
    tui_test_erase();
    view_devices_draw(&g_s);
    ASSERT_SCREEN_LACKS("Signal   ");
}

/* ── G7 ─────────────────────────────────────────────────── */

static void test_rug_bins_and_levels(void) {
    time_t ts[5] = { 100, 101, 150, 199, 200 };
    int out[4];
    ASSERT_EQ(tg_rug_bin(ts, 5, 100, 200, out, 4), 2);
    ASSERT_EQ(out[0], 2);
    ASSERT_EQ(out[2], 1);
    ASSERT_EQ(out[3], 1);                    /* 200 is outside [100, 200) */
    ASSERT_EQ(tg_rug_level(0, 5), 0);
    ASSERT_EQ(tg_rug_level(1, 100), 1);      /* any count is a tick */
    ASSERT_EQ(tg_rug_level(5, 5), 8);
    ASSERT_STR(tg_rug_cell(0, 5, TG_NORMAL).glyph, " ");
}

static void add_alert(sloth_state_t *s, alert_type_t ty, alert_sev_t sev,
                      const char *key, time_t opened, time_t last) {
    alert_t *a = &s->alerts[s->alert_count++];
    a->type = ty;
    a->sev = sev;
    snprintf(a->key, sizeof(a->key), "%s", key);
    snprintf(a->title, sizeof(a->title), "T");
    a->first_detected = opened;
    a->first_seen = opened;
    a->last_seen = last;
    a->count = 1;
}

static void test_alerts_begun_rug_lanes(void) {
    time_t t = 1700000000;
    pin(t);
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(tui_init_offscreen(24, 80), 0);
    tui_test_erase();
    view_alerts_draw(&g_s);
    ASSERT_SCREEN_HAS("begun: none in the last 60 min");

    add_alert(&g_s, ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_CRIT, "a", t - 100, t);
    add_alert(&g_s, ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "b", t - 3000, t);
    add_alert(&g_s, ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "c", t - 3000, t);
    add_alert(&g_s, ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_LOW,  "d", t - 7200, t);
    tui_test_erase();
    view_alerts_draw(&g_s);
    int yc = runner_screen_find("  crit  ");
    int yw = runner_screen_find("  warn  ");
    ASSERT(yc > 0);
    ASSERT_EQ(yw, yc + 1);
    /* Older than the hour: no low lane at all (P3). */
    ASSERT_SCREEN_LACKS("  low   ");
    ASSERT_SCREEN_HAS("tallest 2");
    /* The crit tick: 100 s before now in a 3600 s window of 60 columns,
     * in the crit colour; the warn column is twice its height. */
    int col = 8 + (int)((3500.0 * 60) / 3601);
    ASSERT_EQ(tui_test_pair(yc, col), CP_HEAT_PEAK);
    ASSERT_EQ(tui_test_overflow(), 0);
}

/* ── G8 ─────────────────────────────────────────────────── */

static void test_lane_bar_ends(void) {
    tg_lane_t l;
    tg_lane_init(&l, 10);
    tg_lane_bar(&l, 20, 50, 0, 100, TG_SEV_CRIT);
    char s[256];
    cells_str(l.cell, l.n, s, sizeof(s));
    ASSERT_STR(s, "\xe2\x94\x80\xe2\x94\x80"
                     "\xe2\x97\x8f\xe2\x94\x81\xe2\x94\x81\xe2\x97\x8f"
                     "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80");
    /* An end the window cut off is not drawn as an observation. */
    tg_lane_init(&l, 10);
    tg_lane_bar(&l, -50, 50, 0, 100, TG_SEV_CRIT);
    ASSERT_STR(l.cell[0].glyph, "\xe2\x94\x81");
    ASSERT_STR(l.cell[5].glyph, "\xe2\x97\x8f");
    ASSERT_EQ(l.cell[0].tone, TG_SEV_CRIT);
}

static void seed_pair(sloth_state_t *s) {
    static const uint8_t a[6] = { 0x02, 0xaa, 0, 0, 0, 0x01 };
    static const uint8_t b[6] = { 0x02, 0xbb, 0, 0, 0, 0x02 };
    twin_episode_t *e = &s->twin_episodes[0];
    snprintf(e->ssid, sizeof(e->ssid), "cafe");
    memcpy(e->real_bssid, a, 6);
    memcpy(e->twin_bssid, b, 6);
    e->attributed = 1;
    e->attack_in_progress = 1;
    s->twin_episode_count = 1;
}

static void test_twins_chain_lanes(void) {
    time_t t = 1700000000;
    pin(t);
    memset(&g_s, 0, sizeof(g_s));
    seed_pair(&g_s);
    add_alert(&g_s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT,
              "twin:02:aa:00:00:00:01:02:bb:00:00:00:02:site:wpa2",
              t - 300, t);
    add_alert(&g_s, ALERT_TYPE_KARMA_AP, ALERT_SEV_WARN,
              "karma:02:bb:00:00:00:02", t - 200, t - 100);
    add_alert(&g_s, ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_LOW,
              "deauth:ff:ff:ff:ff:ff:ff@02:aa:00:00:00:01", t - 400, t);
    assoc_t *as = &g_s.assocs[g_s.assoc_count++];
    memcpy(as->bssid, g_s.twin_episodes[0].twin_bssid, 6);
    as->first_seen = t - 150;
    as->last_seen = t;

    ASSERT_EQ(tui_init_offscreen(24, 80), 0);
    tui_test_erase();
    view_twins_draw(&g_s);
    ASSERT_SCREEN_HAS("chain of the selected pair, by stage");
    ASSERT_SCREEN_HAS("twin CRIT");
    ASSERT_SCREEN_HAS("karma WARN");
    ASSERT_SCREEN_HAS("deauth LOW");
    ASSERT_SCREEN_HAS("10 min, 1 assoc");
    ASSERT_SCREEN_HAS("links: deauth taint, attack in progress;"
                      " impostor attributed");
    /* The twin bar runs to now in the crit colour, ending in a dot. */
    int y = runner_screen_find("twin CRIT");
    ASSERT_EQ(tui_test_pair(y, 2 + 12 + 1 + 23), CP_HEAT_PEAK);
    ASSERT(runner_line_has(y, "\xe2\x94\x81\xe2\x97\x8f"));
    /* The legend still fits under the lanes. */
    ASSERT_SCREEN_HAS("needs controller/switch/DHCP correlation");
    ASSERT_EQ(tui_test_overflow(), 0);
}

static void test_twins_chain_matches_keys_at_their_fields(void) {
    time_t t = 1700000000;
    pin(t);
    memset(&g_s, 0, sizeof(g_s));
    seed_pair(&g_s);
    /* The BSSID's text inside an SSID, and across a pair's two halves:
     * neither is a stage of this pair. */
    add_alert(&g_s, ALERT_TYPE_KARMA_AP, ALERT_SEV_WARN,
              "karma:02:cc:00:00:00:09 02:bb:00:00:00:02", t - 200, t);
    add_alert(&g_s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT,
              "twin-fp:02:cc:00:00:00:09:02:dd:00:00:00:09:02:aa:00:00:00:01",
              t - 300, t);
    tui_test_erase();
    view_twins_draw(&g_s);
    ASSERT_SCREEN_LACKS("karma WARN");
    ASSERT_SCREEN_LACKS("twin CRIT");
    ASSERT_SCREEN_HAS("  karma  ");
}

void run_tui_glyph_tests(void) {
    TEST_SUITE("tui glyph forms (#195)");
    RUN_TEST(test_sm_scale_per_band);
    RUN_TEST(test_sm_words_step_as_the_face);
    RUN_TEST(test_sm_cells_are_the_emitter_report_line);
    RUN_TEST(test_hz_two_bands_split_at_half);
    RUN_TEST(test_channel_minutes_from_the_cumulative_total);
    RUN_TEST(test_channel_view_draws_the_strip_at_80x24);
    RUN_TEST(test_how_levels);
    RUN_TEST(test_dev_how_counts_an_hour_once);
    RUN_TEST(test_devices_detail_meter_and_grid_at_80x24);
    RUN_TEST(test_rug_bins_and_levels);
    RUN_TEST(test_alerts_begun_rug_lanes);
    RUN_TEST(test_lane_bar_ends);
    RUN_TEST(test_twins_chain_lanes);
    RUN_TEST(test_twins_chain_matches_keys_at_their_fields);
}
