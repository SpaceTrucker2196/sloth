/* Palette mapping shared by the ncurses and ANSI tui backends (#48).
 *
 * The expected xterm-256 indices are written out from the palette's
 * design intent — the Fallout phosphor ramp, the brand logo colours,
 * the earth tones — not read back from the table under test. That is
 * what makes this a guard against the ANSI fallback silently drifting
 * away from the real UI rather than a restatement of it. */

#include "runner.h"
#include "tui.h"
#include "tui_palette.h"

static short fg_of(int pair) {
    short fg = -999, bg = -999;
    if (!tui_pair_colors(pair, &fg, &bg)) return -1;
    return fg;
}

static short bg_of(int pair) {
    short fg = -999, bg = -999;
    if (!tui_pair_colors(pair, &fg, &bg)) return -1;
    return bg;
}

/* ── scalar pairs ────────────────────────────────────────── */

static void test_phosphor_scalars(void) {
    ASSERT_EQ(fg_of(CP_BRIGHT), 49);    /* #00ffaf */
    ASSERT_EQ(fg_of(CP_NORMAL), 43);    /* #00d7af */
    ASSERT_EQ(fg_of(CP_DIM),    29);    /* #00875f */
    /* The border deliberately reuses the original dim phosphor. */
    ASSERT_EQ(fg_of(CP_BORDER), fg_of(CP_DIM));
}

static void test_heat_gradient_ascends(void) {
    ASSERT_EQ(fg_of(CP_HEAT_LO),   241);   /* grey   */
    ASSERT_EQ(fg_of(CP_HEAT_MID),  178);   /* amber  */
    ASSERT_EQ(fg_of(CP_HEAT_HI),   208);   /* orange */
    ASSERT_EQ(fg_of(CP_HEAT_PEAK), 196);   /* red    */
}

static void test_alert_hot_tiers(void) {
    ASSERT_EQ(fg_of(CP_ALERT_HOT_LOW),  220);   /* #ffd700 */
    ASSERT_EQ(fg_of(CP_ALERT_HOT_WARN), 208);   /* #ff8700 */
    ASSERT_EQ(fg_of(CP_ALERT_HOT_CRIT), 196);   /* #ff0000 */
    /* WARN and CRIT share the heat gradient's top two so escalation
     * reads the same way in both places. */
    ASSERT_EQ(fg_of(CP_ALERT_HOT_WARN), fg_of(CP_HEAT_HI));
    ASSERT_EQ(fg_of(CP_ALERT_HOT_CRIT), fg_of(CP_HEAT_PEAK));
}

/* ── backgrounds ─────────────────────────────────────────── */

static void test_highlight_is_the_only_pair_with_a_bg(void) {
    /* Row backgrounds were retired: everything renders on the terminal
     * default. CP_HIGHLIGHT is the documented exception. */
    ASSERT_EQ(bg_of(CP_HIGHLIGHT), 22);      /* #005f00 */
    ASSERT_EQ(fg_of(CP_HIGHLIGHT), 255);     /* white   */

    for (int p = 1; p <= CP_BR_EXTRA_BASE + 7; p++) {
        short fg = 0, bg = 0;
        if (!tui_pair_colors(p, &fg, &bg)) continue;
        if (p == CP_HIGHLIGHT) continue;
        ASSERT_EQ(bg, -1);
    }
}

/* ── banded pairs ────────────────────────────────────────── */

static void test_ip_palette_values(void) {
    static const short want[8] = { 50, 80, 121, 156, 178, 215, 174, 110 };
    for (int i = 0; i < 8; i++)
        ASSERT_EQ(fg_of(CP_IP_BASE_OTHER + i), want[i]);
}

/* Every row-category band resolves to the same foreground for a given
 * colour index — the category used to pick a background, and those are
 * gone. A fallback that reintroduced per-category hues would break the
 * "same IP, same colour everywhere" rule. */
static void test_ip_bands_agree_across_categories(void) {
    static const int bases[] = {
        CP_IP_BASE_OTHER, CP_IP_BASE_TCP, CP_IP_BASE_UDP, CP_IP_BASE_DNS,
        CP_IP_BASE_ICMP,  CP_IP_BASE_HTTP, CP_IP_BASE_TLS,
    };
    for (int i = 0; i < 8; i++) {
        short want = fg_of(CP_IP_BASE_OTHER + i);
        for (unsigned b = 0; b < sizeof(bases) / sizeof(bases[0]); b++)
            ASSERT_EQ(fg_of(bases[b] + i), want);
    }
}

static void test_brand_palette_values(void) {
    /* Google logo order: blue, red, yellow, green. */
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_GOOGLE_BLUE),    33);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_GOOGLE_RED),    167);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_GOOGLE_YELLOW), 220);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_GOOGLE_GREEN),   35);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_FIREFOX),       208);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_CLOUDFLARE),    196);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_EXAMPLE),       244);
    ASSERT_EQ(fg_of(CP_BR_BASE_OTHER + BR_DISCORD),        99);
}

static void test_brand_bands_agree_across_categories(void) {
    static const int bases[] = {
        CP_BR_BASE_OTHER, CP_BR_BASE_TCP, CP_BR_BASE_UDP, CP_BR_BASE_DNS,
        CP_BR_BASE_ICMP,  CP_BR_BASE_HTTP, CP_BR_BASE_TLS,
    };
    for (int i = 0; i < 8; i++) {
        short want = fg_of(CP_BR_BASE_OTHER + i);
        for (unsigned b = 0; b < sizeof(bases) / sizeof(bases[0]); b++)
            ASSERT_EQ(fg_of(bases[b] + i), want);
    }
}

/* Slots 8..15 live in their own default-bg-only bank, offset by 8 into
 * the same 16-entry brand table — an off-by-eight here would silently
 * paint Facebook with Google's blue. */
static void test_brand_extra_bank_offset(void) {
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_FACEBOOK  - 8)),  27);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_SPOTIFY   - 8)),  41);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_TWITCH    - 8)), 135);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_AMAZON    - 8)), 214);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_LINKEDIN  - 8)),  31);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_NETFLIX   - 8)), 124);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_REDDIT    - 8)), 202);
    ASSERT_EQ(fg_of(CP_BR_EXTRA_BASE + (BR_INSTAGRAM - 8)), 169);
    /* The two banks must not overlap. */
    ASSERT_NE(fg_of(CP_BR_EXTRA_BASE), fg_of(CP_BR_BASE_OTHER));
}

static void test_info_palette_values(void) {
    static const short want[8] = { 95, 101, 137, 144, 173, 179, 138, 102 };
    for (int i = 0; i < 8; i++)
        ASSERT_EQ(fg_of(CP_INFO_BASE + i), want[i]);
}

/* ── unmapped input ──────────────────────────────────────── */

static void test_retired_pkt_band_is_unmapped(void) {
    /* Row backgrounds were removed; these pairs are never initialised.
     * The fallback must report them unmapped rather than invent a
     * colour or read off the end of a table. */
    short fg = 0, bg = 0;
    ASSERT_EQ(tui_pair_colors(CP_PKT_TCP,  &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(CP_PKT_UDP,  &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(CP_PKT_DNS,  &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(CP_PKT_ICMP, &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(CP_PKT_HTTP, &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(CP_PKT_TLS,  &fg, &bg), 0);
}

static void test_out_of_range_is_unmapped(void) {
    short fg = 0, bg = 0;
    ASSERT_EQ(tui_pair_colors(0,     &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(-1,    &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(14,    &fg, &bg), 0);   /* gap below IP base */
    ASSERT_EQ(tui_pair_colors(9999,  &fg, &bg), 0);
    ASSERT_EQ(tui_pair_colors(CP_BR_EXTRA_BASE + 8, &fg, &bg), 0);
}

/* Unmapped lookups must leave the caller's variables untouched, since
 * the ANSI backend seeds them with its own default before calling. */
static void test_unmapped_leaves_outputs_alone(void) {
    short fg = 77, bg = 66;
    ASSERT_EQ(tui_pair_colors(CP_PKT_TCP, &fg, &bg), 0);
    ASSERT_EQ(fg, 77);
    ASSERT_EQ(bg, 66);
}

static void test_null_outputs_are_safe(void) {
    ASSERT_EQ(tui_pair_colors(CP_NORMAL, NULL, NULL), 1);
    short only_fg = 0;
    ASSERT_EQ(tui_pair_colors(CP_NORMAL, &only_fg, NULL), 1);
    ASSERT_EQ(only_fg, 43);
    short only_bg = 0;
    ASSERT_EQ(tui_pair_colors(CP_HIGHLIGHT, NULL, &only_bg), 1);
    ASSERT_EQ(only_bg, 22);
}

/* Every colour the palette hands out must be a legal xterm-256 index —
 * an out-of-range value would emit a broken SGR sequence. */
static void test_all_mapped_colors_in_range(void) {
    for (int p = 1; p <= CP_BR_EXTRA_BASE + 7; p++) {
        short fg = 0, bg = 0;
        if (!tui_pair_colors(p, &fg, &bg)) continue;
        ASSERT(fg >= 0 && fg <= 255);
        ASSERT(bg == -1 || (bg >= 0 && bg <= 255));
    }
}

void run_tui_palette_tests(void) {
    TEST_SUITE("tui palette (shared by ncurses + ANSI backends)");
    RUN_TEST(test_phosphor_scalars);
    RUN_TEST(test_heat_gradient_ascends);
    RUN_TEST(test_alert_hot_tiers);
    RUN_TEST(test_highlight_is_the_only_pair_with_a_bg);
    RUN_TEST(test_ip_palette_values);
    RUN_TEST(test_ip_bands_agree_across_categories);
    RUN_TEST(test_brand_palette_values);
    RUN_TEST(test_brand_bands_agree_across_categories);
    RUN_TEST(test_brand_extra_bank_offset);
    RUN_TEST(test_info_palette_values);

    TEST_SUITE("tui palette (unmapped input)");
    RUN_TEST(test_retired_pkt_band_is_unmapped);
    RUN_TEST(test_out_of_range_is_unmapped);
    RUN_TEST(test_unmapped_leaves_outputs_alone);
    RUN_TEST(test_null_outputs_are_safe);
    RUN_TEST(test_all_mapped_colors_in_range);
}
