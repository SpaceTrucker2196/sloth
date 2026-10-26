#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "jsonl.h"
#include "reg_obs.h"
#include "views/beacon.h"

/*
 * Regulatory readings for the operator — issue #101 slice B: the REG
 * column on the [b] list, the REGULATORY block with its observed-vs-
 * claimed power delta on the detail screen, and the change-only
 * wifi_regulatory JSONL record.
 *
 * State is seeded on a beacon_ap_t directly: these read the retained
 * envelope and nothing else, and the parse that fills it has its own
 * frame-level tests in test_reg_ie.c and test_reg_6g.c.
 */

static time_t fixed_wall(void) { return (time_t)1700000000; }

static sloth_state_t g_s;


static beacon_ap_t *seed(int detail) {
    memset(&g_s, 0, sizeof(g_s));
    g_s.beacon_count = 1;
    beacon_ap_t *ap = &g_s.beacon_aps[0];
    static const uint8_t b[6] = { 0x02, 0x70, 0x00, 0x00, 0x00, 0x01 };
    memcpy(ap->bssid, b, 6);
    snprintf(ap->ssid, sizeof(ap->ssid), "reg-test");
    snprintf(ap->enc, sizeof(ap->enc), "WPA2");
    ap->channel    = 36;
    ap->signal_dbm = -40;
    ap->last_seen  = fixed_wall();
    g_s.beacon_detail = detail;
    g_s.beacon_sel    = 0;
    return ap;
}

static void set_country(beacon_ap_t *ap, const char *cc, uint8_t env) {
    ap->reg.country_present = 1;
    memcpy(ap->reg.country, cc, 2);
    ap->reg.country[2] = '\0';
    ap->reg.env = env;
}

/* ── REG column ──────────────────────────────────────────── */

static void test_column_dash_when_nothing_was_ever_parsed(void) {
    reg_ie_t r; memset(&r, 0, sizeof(r));
    reg_6g_t g; memset(&g, 0, sizeof(g));
    char out[32];
    reg_obs_column(&r, &g, 20, out, sizeof(out));
    ASSERT_STR(out, "-");
    ASSERT_EQ(reg_obs_any(&r, &g), 0);
}

static void test_column_tokens_in_priority_order(void) {
    beacon_ap_t *ap = seed(0);
    set_country(ap, "US", REG_ENV_INDOOR);
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 17;
    ap->reg.power_constraint_present = 1; ap->reg.power_constraint_db = 3;
    ap->reg6g.he6_present = 1; ap->reg6g.he6_reg_info = REG_6G_STANDARD_AP;
    ap->reg6g.tpe_count = 2;
    char out[32];
    reg_obs_column(&ap->reg, &ap->reg6g, 28, out, sizeof(out));
    ASSERT_STR(out, "US/I 6G:SP TPC17 PC3 TPE2");

    /* The column flexes: the first token that does not fit ends it. */
    reg_obs_column(&ap->reg, &ap->reg6g, 16, out, sizeof(out));
    ASSERT_STR(out, "US/I 6G:SP TPC17");
    reg_obs_column(&ap->reg, &ap->reg6g, 15, out, sizeof(out));
    ASSERT_STR(out, "US/I 6G:SP");
    reg_obs_column(&ap->reg, &ap->reg6g, 4, out, sizeof(out));
    ASSERT_STR(out, "US/I");
    /* The country token alone truncates rather than vanishing. */
    reg_obs_column(&ap->reg, &ap->reg6g, 2, out, sizeof(out));
    ASSERT_STR(out, "US");
    /* sz bounds width. */
    char small[6];
    reg_obs_column(&ap->reg, &ap->reg6g, 40, small, sizeof(small));
    ASSERT_STR(small, "US/I");
}

static void test_column_environment_suffixes(void) {
    static const struct { uint8_t env; const char *want; } c[] = {
        { REG_ENV_ANY, "DE" }, { REG_ENV_INDOOR, "DE/I" },
        { REG_ENV_OUTDOOR, "DE/O" }, { REG_ENV_NON_COUNTRY, "DE/X" },
        { REG_ENV_OPCLASS_TABLE, "DE/T" }, { REG_ENV_UNKNOWN, "DE/?" },
    };
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        reg_ie_t r; memset(&r, 0, sizeof(r));
        r.country_present = 1; memcpy(r.country, "DE", 3); r.env = c[i].env;
        char out[16];
        reg_obs_column(&r, NULL, 10, out, sizeof(out));
        ASSERT_STR(out, c[i].want);
    }
}

/* No Country element but another regulatory element: "--" says the
 * country is what is missing, which "-" (nothing at all) would not. */
static void test_column_missing_country_beside_other_claims(void) {
    reg_ie_t r; memset(&r, 0, sizeof(r));
    r.tpc_present = 1; r.tpc_tx_power_dbm = -3;
    char out[16];
    reg_obs_column(&r, NULL, 12, out, sizeof(out));
    ASSERT_STR(out, "-- TPC-3");
}

/* The country octets are the transmitter's; only what could be a code
 * reaches the screen. A malformed element outranks every claim token,
 * because it is the one reading that is itself a signal. */
static void test_column_filters_country_and_ranks_malformed_first(void) {
    reg_ie_t r; memset(&r, 0, sizeof(r));
    r.country_present = 1;
    r.country[0] = '\x1b'; r.country[1] = 'Z'; r.country[2] = '\0';
    r.env = REG_ENV_ANY;
    r.tpc_present = 1; r.tpc_tx_power_dbm = 20;
    reg_6g_t g; memset(&g, 0, sizeof(g));
    g.malformed_tpe = 1;
    char out[16];
    reg_obs_column(&r, &g, 8, out, sizeof(out));
    ASSERT_STR(out, "?Z MAL");
    reg_obs_column(&r, &g, 12, out, sizeof(out));
    ASSERT_STR(out, "?Z MAL TPC20");

    /* Malformed alone is still "something was parsed". */
    memset(&r, 0, sizeof(r));
    r.malformed_country = 1;
    ASSERT_EQ(reg_obs_any(&r, NULL), 1);
    reg_obs_column(&r, NULL, 8, out, sizeof(out));
    ASSERT_STR(out, "-- MAL");
}

static void test_column_reserved_6ghz_value_is_named_by_number(void) {
    reg_6g_t g; memset(&g, 0, sizeof(g));
    g.he6_present = 1; g.he6_reg_info = 4;
    char out[16];
    reg_obs_column(NULL, &g, 12, out, sizeof(out));
    ASSERT_STR(out, "-- 6G:R4");
    g.he6_reg_info = REG_6G_INDOOR_AP;
    reg_obs_column(NULL, &g, 12, out, sizeof(out));
    ASSERT_STR(out, "-- 6G:IN");
}

/* ── power delta arithmetic ──────────────────────────────── */

static void test_frequency_follows_the_band_rule(void) {
    ASSERT_EQ(reg_obs_freq_mhz(1, CH_SRC_DS_PARAM), 2412);
    ASSERT_EQ(reg_obs_freq_mhz(6, CH_SRC_DS_PARAM), 2437);
    ASSERT_EQ(reg_obs_freq_mhz(14, CH_SRC_DS_PARAM), 2484);
    ASSERT_EQ(reg_obs_freq_mhz(36, CH_SRC_HT_OPER), 5180);
    ASSERT_EQ(reg_obs_freq_mhz(165, CH_SRC_DS_PARAM), 5825);
    /* 37 is a 5 GHz-range number and a 6 GHz channel; only the source
     * decides (#66, #91). */
    ASSERT_EQ(reg_obs_freq_mhz(37, CH_SRC_HE_6GHZ), 6135);
    ASSERT_EQ(reg_obs_freq_mhz(1, CH_SRC_HE_6GHZ), 5955);
    ASSERT_EQ(reg_obs_freq_mhz(2, CH_SRC_HE_6GHZ), 5935);
    ASSERT_EQ(reg_obs_freq_mhz(233, CH_SRC_HE_6GHZ), 7115);
    ASSERT_EQ(reg_obs_freq_mhz(0, CH_SRC_DS_PARAM), 0);
    ASSERT_EQ(reg_obs_freq_mhz(20, CH_SRC_DS_PARAM), 0);
    ASSERT_EQ(reg_obs_freq_mhz(234, CH_SRC_HE_6GHZ), 0);
}

/* FSPL(1 m) = 20 log10(f_MHz) - 27.55: 2412 MHz -> 40.10 dB,
 * 5180 MHz -> 46.74 dB, 6135 MHz -> 48.21 dB. */
static void test_free_space_loss_at_one_metre(void) {
    ASSERT_NEAR(reg_obs_fspl_1m_db(2412), 40.10, 0.01);
    ASSERT_NEAR(reg_obs_fspl_1m_db(5180), 46.74, 0.01);
    ASSERT_NEAR(reg_obs_fspl_1m_db(6135), 48.21, 0.01);
    ASSERT_NEAR(reg_obs_fspl_1m_db(0), 0.0, 0.001);
}

static void test_power_consistent_with_tpc_claim(void) {
    beacon_ap_t *ap = seed(0);
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 17;
    reg_power_obs_t o;
    ASSERT_EQ(reg_obs_power(ap, &o), 1);
    ASSERT_EQ((int)o.src, REG_PWR_SRC_TPC);
    ASSERT_EQ(o.heard_dbm, -40);
    ASSERT_EQ(o.freq_mhz, 5180);
    ASSERT_NEAR(o.claimed_dbm, 17.0, 0.001);
    ASSERT_NEAR(o.apparent_loss_db, 57.0, 0.001);
    ASSERT_NEAR(o.excess_db, 46.74 - 57.0, 0.01);
}

/* Heard at -20 dBm from a TPC claim of 0 dBm on channel 36: 20 dB of
 * apparent loss where 1 m of free space alone is 46.7 dB. */
static void test_power_stronger_than_claim_allows(void) {
    beacon_ap_t *ap = seed(0);
    ap->signal_dbm = -20;
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 0;
    reg_power_obs_t o;
    ASSERT_EQ(reg_obs_power(ap, &o), 1);
    ASSERT_NEAR(o.excess_db, 26.74, 0.01);
    ASSERT_EQ(o.beyond_margin, 1);
}

/* A positive excess inside the stated margin is not "beyond" it: the
 * ±5 dB TPC tolerance and a few dBi of receive gain produce that much
 * on their own. 46.74 - 40 = 6.74 dB over, under the 10 dB margin; the
 * margin itself is not beyond (strictly greater). Seen to fail with
 * beyond_margin set on excess_db > 0. */
static void test_power_small_excess_is_within_margin(void) {
    beacon_ap_t *ap = seed(0);
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 0;
    reg_power_obs_t o;
    ASSERT_EQ(reg_obs_power(ap, &o), 1);
    ASSERT_NEAR(o.excess_db, 6.74, 0.01);
    ASSERT_EQ(o.beyond_margin, 0);
    ap->signal_dbm = -36;              /* 10.74 dB over */
    ASSERT_EQ(reg_obs_power(ap, &o), 1);
    ASSERT_EQ(o.beyond_margin, 1);
}

/* With no TPC Report the default-category local EIRP TPE is the claim;
 * its 20 MHz value in half dB. TPC outranks it when both exist. */
static void test_power_falls_back_to_tpe_local_eirp(void) {
    beacon_ap_t *ap = seed(0);
    ap->channel = 37; ap->channel_source = CH_SRC_HE_6GHZ;
    ap->reg6g.tpe_count = 2;
    ap->reg6g.tpe[0].interp = REG_TPE_REG_CLIENT_EIRP_PSD;
    ap->reg6g.tpe[0].n_values = 1; ap->reg6g.tpe[0].values_half_db[0] = -2;
    ap->reg6g.tpe[1].interp = REG_TPE_LOCAL_EIRP;
    ap->reg6g.tpe[1].n_values = 1; ap->reg6g.tpe[1].values_half_db[0] = 47;
    reg_power_obs_t o;
    ASSERT_EQ(reg_obs_power(ap, &o), 1);
    ASSERT_EQ((int)o.src, REG_PWR_SRC_TPE);
    ASSERT_NEAR(o.claimed_dbm, 23.5, 0.001);
    ASSERT_EQ(o.freq_mhz, 6135);

    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 10;
    ASSERT_EQ(reg_obs_power(ap, &o), 1);
    ASSERT_EQ((int)o.src, REG_PWR_SRC_TPC);
}

/* Nothing to compare — no claim of the AP's own power, no reading, no
 * known band. A regulatory-client or PSD envelope is a ceiling for the
 * clients or per MHz, not the AP's own EIRP, and must not stand in.
 * Seen to fail with the interp check dropped from the TPE loop (the
 * PSD entry became the claim), and with `signal_dbm >= 0` dropped. */
static void test_power_has_nothing_to_compare(void) {
    reg_power_obs_t o;
    beacon_ap_t *ap = seed(0);
    ASSERT_EQ(reg_obs_power(ap, &o), 0);
    ASSERT_EQ((int)o.src, REG_PWR_SRC_NONE);

    ap->reg6g.tpe_count = 2;
    ap->reg6g.tpe[0].interp = REG_TPE_REG_CLIENT_EIRP_PSD;
    ap->reg6g.tpe[0].n_values = 1; ap->reg6g.tpe[0].values_half_db[0] = 40;
    ap->reg6g.tpe[1].interp = REG_TPE_LOCAL_EIRP;
    ap->reg6g.tpe[1].category = REG_TPE_CAT_SUBORDINATE;
    ap->reg6g.tpe[1].n_values = 1; ap->reg6g.tpe[1].values_half_db[0] = 40;
    ASSERT_EQ(reg_obs_power(ap, &o), 0);
    ap->reg6g.tpe[1].category = REG_TPE_CAT_DEFAULT;
    ap->reg6g.tpe[1].n_values = 0;   /* reserved encoding, no values */
    ASSERT_EQ(reg_obs_power(ap, &o), 0);

    ap = seed(0);
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 17;
    ap->signal_dbm = 0;
    ASSERT_EQ(reg_obs_power(ap, &o), 0);
    ap->signal_dbm = -50; ap->channel = 0;
    ASSERT_EQ(reg_obs_power(ap, &o), 0);
    ASSERT_NEAR(o.claimed_dbm, 0.0, 0.001);
    ASSERT_EQ(reg_obs_power(NULL, &o), 0);
}

/* ── [b] list and detail rendering ───────────────────────── */

static void draw_at(int rows, int cols) {
    ASSERT_EQ(tui_init_offscreen(rows, cols), 0);
    g_s.active_view = VIEW_BEACON;
    sloth_clock_test_set(NULL, fixed_wall);
    tui_test_erase();
    tui_draw(&g_s);
    sloth_clock_test_set(NULL, NULL);
}

static void restore_screen(void) {
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* The AP's list row ends with its age ("0s" at the pinned clock) on the
 * same screen row as its SSID — i.e. the row did not wrap. */
static int list_row_on_one_line(void) {
    char line[512];
    for (int y = 0; y < tui_test_rows(); y++) {
        int n = tui_test_line(y, line, sizeof(line));
        if (n < 0 || !strstr(line, "reg-test")) continue;
        return n >= 3 && strcmp(line + n - 3, " 0s") == 0;
    }
    return 0;
}

static void test_list_reg_column_flexes_with_width(void) {
    beacon_ap_t *ap = seed(0);
    set_country(ap, "US", REG_ENV_OUTDOOR);
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 17;
    ap->reg.power_constraint_present = 1; ap->reg.power_constraint_db = 3;

    draw_at(40, 220);
    ASSERT_SCREEN_HAS("REG");
    ASSERT_SCREEN_HAS("US/O TPC17 PC3");
    ASSERT(list_row_on_one_line());

    /* 159 columns leave 159 - 146 = 13 for REG: room for two tokens.
     * (146: the row before REG gained the 14-cell distance column.) */
    draw_at(40, 159);
    ASSERT_SCREEN_HAS("US/O TPC17");
    ASSERT_SCREEN_LACKS("PC3");
    ASSERT(list_row_on_one_line());

    /* 150 is the narrowest that fits the 4-cell floor on one line. */
    draw_at(40, 150);
    ASSERT_SCREEN_HAS("US/O");
    ASSERT(list_row_on_one_line());

    /* Below it the column is dropped, not forced in: rows that fit
     * without REG (143-149 columns) must not start wrapping because of
     * it. Seen to fail with the floor clamped up (REG drawn at 4 cells)
     * instead of dropped. */
    draw_at(40, 149);
    ASSERT_SCREEN_LACKS("US/O");
    ASSERT_SCREEN_LACKS("REG");
    ASSERT(list_row_on_one_line());
    draw_at(40, 144);
    ASSERT_SCREEN_LACKS("US/O");
    ASSERT(list_row_on_one_line());

    /* At the 100-column minimum rows wrap with or without REG; it is
     * not drawn. */
    draw_at(40, 100);
    ASSERT_SCREEN_LACKS("US/O");
    ASSERT_SCREEN_LACKS("TPC17");
    restore_screen();
}

static void test_list_reg_column_dash_for_a_silent_ap(void) {
    seed(0);
    draw_at(40, 220);
    ASSERT_SCREEN_HAS("REG");
    ASSERT_SCREEN_LACKS("TPC");
    ASSERT_SCREEN_LACKS("US/");
    restore_screen();
}

static void test_detail_regulatory_block_and_power_caveat(void) {
    beacon_ap_t *ap = seed(1);
    set_country(ap, "US", REG_ENV_INDOOR);
    ap->reg.env_raw = 'I';
    ap->reg.triplet_count = 1;
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 0;
    ap->signal_dbm = -20;
    ap->reg6g.he6_present = 1; ap->reg6g.he6_reg_info = REG_6G_INDOOR_AP;
    ap->reg6g.tpe_count = 1;
    ap->reg6g.tpe[0].interp = REG_TPE_REG_CLIENT_EIRP_PSD;
    ap->reg6g.tpe[0].n_values = 1; ap->reg6g.tpe[0].values_half_db[0] = -2;

    draw_at(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    ASSERT_SCREEN_HAS("REGULATORY (claimed by the AP; observation, not an alert)");
    ASSERT_SCREEN_HAS("Country:     US  indoor (0x49), 1 triplet");
    ASSERT_SCREEN_HAS("no Power Constraint   TPC Report 0 dBm");
    ASSERT_SCREEN_HAS("Regulatory Info 0 (Indoor AP)");
    ASSERT_SCREEN_HAS("reg_client_eirp_psd -1.0 dBm/MHz");
    ASSERT_SCREEN_HAS("heard -20 dBm vs TPC Report 0.0 dBm: apparent loss 20.0 dB");
    ASSERT_SCREEN_HAS("26.7 dB stronger than the claim allows at 1 m");
    ASSERT_SCREEN_HAS("(FSPL 1 m @ 5180 MHz: 46.7 dB)");
    ASSERT_SCREEN_HAS("Assumes free-space loss and 0 dBi antennas; distance "
                      "unknown, so never an alert.");
    /* Drawn below the handshakes, never in front of them. */
    ASSERT(runner_screen_find("REGULATORY") >
           runner_screen_find("CAPTURED HANDSHAKES"));
    restore_screen();
}

static void test_detail_power_consistent_and_nothing_to_compare(void) {
    beacon_ap_t *ap = seed(1);
    set_country(ap, "GB", REG_ENV_ANY);
    draw_at(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    ASSERT_SCREEN_HAS("Power delta: nothing to compare");
    ASSERT_SCREEN_HAS("never an alert");

    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = 17;
    draw_at(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    ASSERT_SCREEN_HAS("consistent with the claim at 1 m or more");
    ASSERT_SCREEN_LACKS("stronger than the claim");

    /* 6.7 dB over at 1 m: printed as a number, not as "stronger". */
    ap->reg.tpc_tx_power_dbm = 0;
    draw_at(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    ASSERT_SCREEN_HAS("6.7 dB over the 1 m figure, within the 10 dB margin");
    ASSERT_SCREEN_LACKS("stronger than the claim");
    restore_screen();
}

/* An AP that never sent a regulatory element gets no block: an empty
 * one would cost rows on a screen that does not scroll and say nothing.
 * Seen to fail with the reg_obs_any() guard on the call forced to 1. */
static void test_detail_no_block_for_a_silent_ap(void) {
    seed(1);
    draw_at(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    ASSERT_SCREEN_HAS("CAPTURED HANDSHAKES");
    ASSERT_SCREEN_LACKS("REGULATORY");
    ASSERT_SCREEN_LACKS("Power delta");
    restore_screen();
}

/* The block gives way before the back hint, the same contract the
 * stack block keeps. Seen to fail with reg_block_fits() forced to 1. */
static void test_detail_block_gives_way_on_a_short_screen(void) {
    beacon_ap_t *ap = seed(1);
    set_country(ap, "US", REG_ENV_ANY);
    draw_at(40, 100);
    ASSERT_SCREEN_HAS("[Enter / Esc] back to beacons list");
    ASSERT_SCREEN_LACKS("REGULATORY");
    draw_at(60, 100);
    ASSERT_SCREEN_HAS("REGULATORY");
    ASSERT_SCREEN_HAS("[Enter / Esc] back to beacons list");
    restore_screen();
}

/* Worst case at the 100-column minimum: every TPE slot full, a
 * non-country environment, sixteen triplets, a reserved 6 GHz value and
 * the stronger-than-claimed branch. No row may wrap, or the back hint
 * goes off the bottom of a screen measured as having room. Run twice:
 * shortest TPE names first, and longest first — the second is the one
 * that reaches the width with both "; +N more" and "; more dropped"
 * still to print. Seen to fail with the TPE row printing every entry
 * regardless of width, and (longest-first order only) with the row
 * budget ignoring the prefix and the tails (COLS - 16 - 14). */
static void worst_case_detail(const uint8_t order[REG_6G_MAX_TPE][2]) {
    beacon_ap_t *ap = seed(1);
    set_country(ap, "XX", REG_ENV_NON_COUNTRY);
    ap->reg.env_raw = 'X';
    ap->reg.triplet_count = 16; ap->reg.triplets_truncated = 1;
    ap->reg.power_constraint_present = 1; ap->reg.power_constraint_db = 255;
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = -128;
    ap->signal_dbm = -1;
    ap->reg6g.he6_present = 1; ap->reg6g.he6_reg_info = 7;
    ap->reg6g.tpe_count = REG_6G_MAX_TPE; ap->reg6g.tpe_truncated = 1;
    for (int i = 0; i < REG_6G_MAX_TPE; i++) {
        ap->reg6g.tpe[i].interp   = order[i][0];
        ap->reg6g.tpe[i].category = order[i][1];
        ap->reg6g.tpe[i].n_values = 1;
        ap->reg6g.tpe[i].values_half_db[0] = -128;
    }
    draw_at(60, 100);
    int rows = tui_test_rows();
    char line[512];
    int hint = -1, title = -1, tpe = -1, pd = -1, last_reg = -1;
    int widest = 0;
    for (int y = 0; y < rows; y++) {
        int n = tui_test_line(y, line, sizeof(line));
        if (n < 0) continue;
        if (strstr(line, "[Enter / Esc]"))  hint = y;
        if (strstr(line, "REGULATORY"))     title = y;
        if (strstr(line, "TPE:         "))  tpe = y;
        if (strstr(line, "Power delta: "))  pd = y;
        if (strstr(line, "never an alert")) last_reg = y;
        if (title >= 0 && last_reg < 0 && n > widest) widest = n;
    }
    /* Every row a fixed count below the title: one screen row each,
     * the power delta taking its two. */
    ASSERT(title > 0);
    ASSERT_EQ(tpe, title + 4);
    ASSERT_EQ(pd, title + 5);
    ASSERT_EQ(last_reg, title + 7);
    ASSERT(hint > last_reg);
    ASSERT(widest < 100);
    ASSERT_SCREEN_HAS("; +");
    ASSERT_SCREEN_HAS("more dropped");
    ASSERT_SCREEN_HAS("reserved in 802.11ax-2021");
    if (hint < 0 || tpe != title + 4) tui_test_dump(stderr);
    restore_screen();
}

static void test_detail_worst_case_does_not_wrap(void) {
    static const uint8_t shortest_first[REG_6G_MAX_TPE][2] = {
        {0,0},{1,0},{2,0},{3,0},{0,1},{1,1},{2,1},{3,1} };
    static const uint8_t longest_first[REG_6G_MAX_TPE][2] = {
        {3,1},{2,1},{3,0},{1,1},{2,0},{1,0},{0,1},{0,0} };
    worst_case_detail(shortest_first);
    worst_case_detail(longest_first);
}

/* ── wifi_regulatory JSONL ───────────────────────────────── */

static char g_path[] = "/tmp/sloth_regjsonl_XXXXXX";

static void open_fresh(void) {
    int fd = mkstemp(g_path);
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_path);
    ASSERT(jsonl_open(g_path));
    jsonl_dedup_reset();
}

static char *slurp(void) {
    FILE *fp = fopen(g_path, "r");
    if (!fp) return NULL;
    static char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

static time_t g_t;
static time_t step_wall(void) { return g_t; }

static void emit_tick(time_t t) {
    g_t = t;
    sloth_clock_test_set(NULL, step_wall);
    jsonl_emit_wifi_regulatory(&g_s);
    sloth_clock_test_set(NULL, NULL);
}

static void seed_full(void) {
    beacon_ap_t *ap = seed(0);
    set_country(ap, "US", REG_ENV_INDOOR);
    ap->reg.env_raw = 'I';
    ap->reg.triplet_count = 2;
    ap->reg.triplets[0].first_channel = 36;
    ap->reg.triplets[0].num_channels  = 4;
    ap->reg.triplets[0].max_tx_power_dbm = 23;
    ap->reg.triplets[1].is_operating = 1;
    ap->reg.triplets[1].ext_id = 201;
    ap->reg.triplets[1].operating_class = 131;
    ap->reg.power_constraint_present = 1; ap->reg.power_constraint_db = 3;
    ap->reg.tpc_present = 1; ap->reg.tpc_tx_power_dbm = -2;
    ap->reg6g.he6_present = 1; ap->reg6g.he6_reg_info = REG_6G_STANDARD_AP;
    ap->reg6g.he6_control_raw = 0x0a;   /* 160 MHz, Regulatory Info 1 */
    ap->reg6g.tpe_count = 1;
    ap->reg6g.tpe[0].interp = REG_TPE_REG_CLIENT_EIRP_PSD;
    ap->reg6g.tpe[0].info_raw = 0x1a;
    ap->reg6g.tpe[0].count = 2;
    ap->reg6g.tpe[0].n_values = 2;
    ap->reg6g.tpe[0].values_half_db[0] = -2;
    ap->reg6g.tpe[0].values_half_db[1] = 5;
}

static void test_jsonl_record_carries_every_claim(void) {
    open_fresh();
    seed_full();
    emit_tick(1700000000);
    jsonl_close();
    char *body = slurp();
    ASSERT(body != NULL);
    ASSERT(strstr(body, "{\"type\":\"wifi_regulatory\",\"ts\":1700000000,"
                        "\"bssid\":\"02:70:00:00:00:01\"") != NULL);
    ASSERT(strstr(body, "\"country_present\":1,\"country\":\"US\","
                        "\"env\":\"indoor\",\"env_raw\":73") != NULL);
    ASSERT(strstr(body, "\"triplets\":[{\"first_channel\":36,"
                        "\"num_channels\":4,\"max_tx_power_dbm\":23},"
                        "{\"ext_id\":201,\"operating_class\":131,"
                        "\"coverage_class\":0}]") != NULL);
    ASSERT(strstr(body, "\"power_constraint_present\":1,"
                        "\"power_constraint_db\":3") != NULL);
    ASSERT(strstr(body, "\"tpc_present\":1,\"tpc_tx_power_dbm\":-2,"
                        "\"tpc_link_margin_db\":0") != NULL);
    ASSERT(strstr(body, "\"he6_present\":1,\"he6_reg_info\":1,"
                        "\"he6_reg_info_name\":\"standard_power\"") != NULL);
    ASSERT(strstr(body, "\"tpe\":[{\"interp\":3,\"interp_name\":"
                        "\"reg_client_eirp_psd\",\"category\":0,\"count\":2,"
                        "\"reserved\":0,\"ext_octets\":0,"
                        "\"values_half_db\":[-2,5]}]") != NULL);
    ASSERT(strstr(body, "\"malformed_tpe\":0}") != NULL);
}

/* No regulatory element ever parsed: no record. A line of zeros would
 * read as a claim of no country and no limit. Seen to fail with the
 * reg_obs_any() skip removed. */
static void test_jsonl_silent_ap_writes_nothing(void) {
    open_fresh();
    seed(0);
    emit_tick(1700000000);
    jsonl_close();
    char *body = slurp();
    ASSERT(body != NULL);
    ASSERT_EQ(count_of(body, "wifi_regulatory"), 0);
}

/* Change-only: an unchanged claim is written once until the heartbeat;
 * a changed claim is written at once; RSSI, which is not in the record,
 * moves nothing. */
static void test_jsonl_change_only_on_claims(void) {
    open_fresh();
    seed_full();
    emit_tick(1700000000);
    g_s.beacon_aps[0].signal_dbm = -71;
    g_s.beacon_aps[0].last_seen  = 1700000001;
    emit_tick(1700000001);
    emit_tick(1700000002);
    g_s.beacon_aps[0].reg.tpc_tx_power_dbm = 5;
    emit_tick(1700000003);
    g_s.beacon_aps[0].reg6g.tpe[0].values_half_db[1] = 6;
    emit_tick(1700000004);
    /* Standard Power -> Indoor, as the parser stores it: the Control
     * octet and the B3-B5 field it holds move together. The one path by
     * which a Regulatory Info change produces a record. Seen to fail
     * with he6_control_raw replaced by 0 in the signature. */
    g_s.beacon_aps[0].reg6g.he6_reg_info    = REG_6G_INDOOR_AP;
    g_s.beacon_aps[0].reg6g.he6_control_raw = 0x02;
    emit_tick(1700000005);
    emit_tick(1700000005 + 300);   /* heartbeat */
    jsonl_close();
    char *body = slurp();
    ASSERT(body != NULL);
    ASSERT_EQ(count_of(body, "\"type\":\"wifi_regulatory\""), 5);
    ASSERT(strstr(body, "\"he6_reg_info_name\":\"indoor\"") != NULL);
    ASSERT(strstr(body, "\"tpc_tx_power_dbm\":5") != NULL);
    ASSERT(strstr(body, "\"values_half_db\":[-2,6]") != NULL);
}

/* The malformed counters climb on every crafted frame; they ride the
 * heartbeat and enter the signature only as "any malformed". Seen to
 * fail with r->malformed_tpc hashed raw (three records instead of two). */
static void test_jsonl_malformed_counts_do_not_churn(void) {
    open_fresh();
    seed_full();
    emit_tick(1700000000);
    g_s.beacon_aps[0].reg.malformed_tpc = 1;     /* 0 -> some: news */
    emit_tick(1700000001);
    g_s.beacon_aps[0].reg.malformed_tpc = 2;     /* more of the same */
    emit_tick(1700000002);
    g_s.beacon_aps[0].reg6g.malformed_tpe = 9;
    emit_tick(1700000003);
    jsonl_close();
    char *body = slurp();
    ASSERT(body != NULL);
    ASSERT_EQ(count_of(body, "\"type\":\"wifi_regulatory\""), 2);
    ASSERT(strstr(body, "\"malformed_tpc\":1") != NULL);
    ASSERT(strstr(body, "\"malformed_tpc\":2") == NULL);
}

/* Lines in the sink, counted without slurp()'s 16 KiB ceiling: a full
 * beacon table writes far more than that. */
static int count_lines_of_type(const char *type) {
    FILE *fp = fopen(g_path, "r");
    if (!fp) return -1;
    char needle[64];
    snprintf(needle, sizeof(needle), "{\"type\":\"%s\"", type);
    static char line[8192];
    int n = 0;
    while (fgets(line, sizeof(line), fp))
        if (strncmp(line, needle, strlen(needle)) == 0) n++;
    fclose(fp);
    return n;
}

/* A full beacon table of random BSSIDs, unchanged for ten ticks, writes
 * exactly one baseline line per AP. The change cache is shared by every
 * keyed emitter; when it was direct-mapped, two live keys landing in one
 * slot evicted each other on every tick and both re-emitted forever
 * (this population gave 832 lines, not 256). Sequential BSSIDs cannot
 * show it — FNV spreads a varying last octet over distinct low bits —
 * hence the LCG. Seen to fail with JSONL_DEDUP_WAYS 1 and
 * JSONL_DEDUP_SETS 1024, the old direct-mapped table. */
static void test_jsonl_full_table_does_not_ping_pong(void) {
    open_fresh();
    memset(&g_s, 0, sizeof(g_s));
    g_s.beacon_count = MAX_BEACON_APS;
    uint32_t x = 0x2545f491u;
    for (int i = 0; i < MAX_BEACON_APS; i++) {
        beacon_ap_t *ap = &g_s.beacon_aps[i];
        for (int k = 0; k < 6; k++) {
            x = x * 1664525u + 1013904223u;
            ap->bssid[k] = (uint8_t)(x >> 24);
        }
        ap->bssid[0] = (uint8_t)((ap->bssid[0] & 0xfc) | 0x02);
        ap->bssid[5] = (uint8_t)i;   /* distinct whatever the LCG does */
        set_country(ap, "US", REG_ENV_ANY);
    }
    for (int t = 0; t < 10; t++) emit_tick(1700000000 + t);
    jsonl_close();
    ASSERT_EQ(count_lines_of_type("wifi_regulatory"), MAX_BEACON_APS);
}

void run_reg_obs_tests(void) {
    TEST_SUITE("REG column on [b] (#101 slice B)");
    RUN_TEST(test_column_dash_when_nothing_was_ever_parsed);
    RUN_TEST(test_column_tokens_in_priority_order);
    RUN_TEST(test_column_environment_suffixes);
    RUN_TEST(test_column_missing_country_beside_other_claims);
    RUN_TEST(test_column_filters_country_and_ranks_malformed_first);
    RUN_TEST(test_column_reserved_6ghz_value_is_named_by_number);

    TEST_SUITE("Observed-vs-claimed power delta (#101 slice B)");
    RUN_TEST(test_frequency_follows_the_band_rule);
    RUN_TEST(test_free_space_loss_at_one_metre);
    RUN_TEST(test_power_consistent_with_tpc_claim);
    RUN_TEST(test_power_stronger_than_claim_allows);
    RUN_TEST(test_power_small_excess_is_within_margin);
    RUN_TEST(test_power_falls_back_to_tpe_local_eirp);
    RUN_TEST(test_power_has_nothing_to_compare);

    TEST_SUITE("[b] REG column and REGULATORY block (#101 slice B)");
    RUN_TEST(test_list_reg_column_flexes_with_width);
    RUN_TEST(test_list_reg_column_dash_for_a_silent_ap);
    RUN_TEST(test_detail_regulatory_block_and_power_caveat);
    RUN_TEST(test_detail_power_consistent_and_nothing_to_compare);
    RUN_TEST(test_detail_no_block_for_a_silent_ap);
    RUN_TEST(test_detail_block_gives_way_on_a_short_screen);
    RUN_TEST(test_detail_worst_case_does_not_wrap);

    TEST_SUITE("wifi_regulatory JSONL record (#101 slice B)");
    RUN_TEST(test_jsonl_record_carries_every_claim);
    RUN_TEST(test_jsonl_silent_ap_writes_nothing);
    RUN_TEST(test_jsonl_change_only_on_claims);
    RUN_TEST(test_jsonl_malformed_counts_do_not_churn);
    RUN_TEST(test_jsonl_full_table_does_not_ping_pong);
}
