#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "views/iface.h"
#include "views/conns.h"
#include "views/wifi.h"
#include "views/packets.h"
#include "views/procs.h"
#include "views/stats.h"
#include "views/probe.h"
#include "views/arp.h"
#include "views/mdns.h"
#include "views/nbns.h"
#include "views/dhcp_snoop.h"
#include "views/ssdp.h"
#include "views/beacon.h"
#include "views/deauth.h"
#include "views/http.h"
#include "views/tls.h"
#include "views/quic.h"
#include "views/dns_log.h"
#include "views/ntp.h"
#include "views/icmp.h"
#include "views/alerts.h"
#include "views/devices.h"
#include "views/help.h"
#include "views/dashboard.h"
#include "views/pnl.h"
#include "views/eapol.h"
#include "views/seqnum.h"
#include "views/assoc.h"
#include "views/channel.h"
#include "views/osi.h"
#include "views/twins.h"
#include "views/karma.h"
#include "views/rogue_radius.h"
#include "views/research.h"
#include "views/fragattack.h"

/* Every view through the shipped renderer (#116).
 *
 * Driven from include/sloth_views.def, the list tui.c's dispatch is
 * generated from (#117), so a view added there is covered here without
 * an edit. tui_draw() is the entry point, not view_<x>_draw(): what is
 * under test is the tab bar, the dispatch switch and the view together,
 * none of which had a test while the suite linked a no-op renderer —
 * tui_draw() was an empty function in that binary. */

typedef void (*draw_fn)(const sloth_state_t *);

static const struct {
    view_t      id;
    const char *slug;
    draw_fn     draw;
} VIEWS[] = {
#define X(id, label, key, slug) { VIEW_##id, #slug, view_##slug##_draw },
#include "sloth_views.def"
#undef X
};
#define N_VIEWS ((int)(sizeof(VIEWS) / sizeof(VIEWS[0])))

TEST_STATE(g_vs);

static sloth_state_t *fresh(view_t v) {
    memset(&g_vs, 0, sizeof(g_vs));
    g_vs.active_view = v;
    return &g_vs;
}

/* The tab bar ends at the first row that starts with the U+2500 rule
 * tui_draw() puts under it; -1 when there is none (the dashboard). */
static int rule_row(void) {
    char line[4096];
    for (int y = 0; y < tui_test_rows(); y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) return -1;
        if (strncmp(line, "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", 9) == 0)
            return y;
    }
    return -1;
}

/* Row and column of `needle` within rows [0, below). */
static int find_above(int below, const char *needle, int *col) {
    for (int y = 0; y < below; y++) {
        int c = runner_find_col(y, needle);
        if (c >= 0) { *col = c; return y; }
    }
    return -1;
}

static void test_the_list_covers_every_view(void) {
    ASSERT_EQ(N_VIEWS, (int)VIEW_COUNT);
    for (int i = 0; i < N_VIEWS; i++)
        ASSERT_EQ((int)VIEWS[i].id, i);
}

/* For every view but the dashboard: the tab bar is drawn, every label is
 * in it, and exactly the active one is in reverse video. That is the
 * selection logic in draw_tabbar() and the dispatch's view_t, checked
 * for all 35 rather than for whichever one a smoke test happened to set.
 * Seen to fail with draw_tabbar()'s `i == (int)s->active_view` test
 * changed to `i == 0`: every view but [1] reads the wrong tab. */
static void test_every_view_selects_its_own_tab(void) {
    for (int v = 0; v < N_VIEWS; v++) {
        if (VIEWS[v].id == VIEW_DASH) continue;
        tui_test_erase();
        tui_draw(fresh(VIEWS[v].id));
        int rule = rule_row();
        ASSERT(rule > 0);
        if (rule <= 0) { if (v == 0) tui_test_dump(stderr); continue; }
        ASSERT_LINE_HAS(0, " sloth v" SLOTH_VERSION);
        int reversed = 0, selected_ok = 0, missing = 0;
        for (int t = 0; t < N_VIEWS; t++) {
            int col = -1;
            int y = find_above(rule, view_label(VIEWS[t].id), &col);
            if (y < 0) { missing++; continue; }
            int rev = tui_test_is_reverse(y, col);
            if (rev == 1) reversed++;
            if (t == v && rev == 1) selected_ok = 1;
        }
        if (missing || reversed != 1 || !selected_ok) {
            fprintf(stderr, "    view %s: missing=%d reversed=%d selected=%d\n",
                    VIEWS[v].slug, missing, reversed, selected_ok);
            tui_test_dump(stderr);
        }
        ASSERT_EQ(missing, 0);
        ASSERT_EQ(reversed, 1);
        ASSERT(selected_ok);
    }
}

/* The dispatch sends each view_t to its own draw: what tui_draw() puts
 * under the rule is what view_<slug>_draw() renders on its own, line for
 * line. A swapped or missing case in the generated switch shows up as a
 * body that belongs to another view, or none. Seen to fail with the
 * dispatch's VIEW_ARP case pointed at view_mdns_draw. */
static void test_every_view_body_comes_from_its_own_draw(void) {
    enum { K = 4 };
    char want[K][1024], got[1024];
    for (int v = 0; v < N_VIEWS; v++) {
        if (VIEWS[v].id == VIEW_DASH) continue;
        tui_test_erase();
        VIEWS[v].draw(fresh(VIEWS[v].id));
        int nonempty = 0;
        for (int j = 0; j < K; j++) {
            tui_test_line(j, want[j], sizeof(want[j]));
            if (want[j][0]) nonempty++;
        }
        /* An empty view would make the comparison below vacuous. */
        if (nonempty == 0)
            fprintf(stderr, "    view %s draws nothing on an empty state\n",
                    VIEWS[v].slug);
        ASSERT(nonempty > 0);

        tui_test_erase();
        tui_draw(fresh(VIEWS[v].id));
        int rule = rule_row();
        ASSERT(rule > 0);
        if (rule <= 0) continue;
        int same = 1;
        for (int j = 0; j < K; j++) {
            tui_test_line(rule + 1 + j, got, sizeof(got));
            if (strcmp(got, want[j]) != 0) {
                fprintf(stderr, "    view %s line %d:\n      want |%s|\n      got  |%s|\n",
                        VIEWS[v].slug, j, want[j], got);
                same = 0;
            }
        }
        ASSERT(same);
    }
}

/* The dashboard owns the whole screen: no banner, no tab bar, no rule.
 * Seen to fail with tui_draw()'s VIEW_DASH early return removed. */
static void test_the_dashboard_draws_no_tab_bar(void) {
    tui_draw(fresh(VIEW_DASH));
    ASSERT_SCREEN_LACKS(" sloth v" SLOTH_VERSION);
    ASSERT_EQ(rule_row(), -1);
    ASSERT_SCREEN_HAS("\xe2\x94\x80\xe2\x94\x80 Interfaces \xe2\x94\x80");
}

/* At 100 columns the 35 labels cannot share a row: draw_tabbar() wraps
 * and every label still lands above the rule, none split across a wrap
 * (a split label is found by neither half). */
static void test_the_tab_bar_wraps_without_splitting_a_label(void) {
    ASSERT_EQ(tui_init_offscreen(40, 100), 0);
    tui_test_erase();
    tui_draw(fresh(VIEW_HELP));
    int rule = rule_row();
    ASSERT(rule > 1);
    int missing = 0;
    for (int t = 0; t < N_VIEWS; t++) {
        int col;
        if (find_above(rule, view_label(VIEWS[t].id), &col) < 0) missing++;
    }
    if (missing) tui_test_dump(stderr);
    ASSERT_EQ(missing, 0);
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
}

/* view_channel_draw() and view_eapol_draw() were the two draws nothing
 * called (#116's audit). One seeded row each, asserted cell by cell. */
static void test_channel_view_renders_a_seeded_row(void) {
    sloth_state_t *s = fresh(VIEW_CHANNEL);
    channel_summary_t *c = &s->channels[0];
    c->channel     = 11;
    c->ap_count    = 3;
    c->assoc_count = 2;
    c->best_signal = -48;
    c->retry_pct   = -1;
    c->last_seen   = time(NULL);
    snprintf(c->top_ssid, sizeof(c->top_ssid), "Chan-Seed");
    s->channel_count = 1;
    s->channel_sel   = -1;
    tui_draw(s);
    ASSERT_SCREEN_HAS("Channel activity: 1 channels (3 APs / 2 clients)");
    int y = runner_screen_find("Chan-Seed");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, " 11 ");
    ASSERT_LINE_HAS(y, "     3     2   -48");
    ASSERT_SCREEN_LACKS("(no channel activity observed yet)");
}

static void test_eapol_view_renders_a_seeded_row(void) {
    sloth_state_t *s = fresh(VIEW_EAPOL);
    eapol_event_t *e = &s->eapol_events[0];
    const uint8_t bssid[6] = {0x02, 0x00, 0x5e, 0x10, 0x20, 0x30};
    const uint8_t sta[6]   = {0x02, 0x00, 0x5e, 0x40, 0x50, 0x60};
    memcpy(e->bssid, bssid, 6);
    memcpy(e->sta_mac, sta, 6);
    snprintf(e->ssid, sizeof(e->ssid), "Eapol-Seed");
    e->msg_num    = 1;
    e->has_pmkid  = 1;
    e->channel    = 6;
    e->signal_dbm = -50;
    e->ts         = time(NULL);
    s->eapol_count = 1;
    tui_draw(s);
    ASSERT_SCREEN_HAS("EAPOL events: 1 (1 PMKID / 0 full handshake)");
    int y = runner_screen_find("Eapol-Seed");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "02:00:5e:10:20:30");
    ASSERT_LINE_HAS(y, "02:00:5e:40:50:60");
    ASSERT_LINE_HAS(y, "PMKID (offline-crackable M1)");
    /* eapol_sel is 0, so the one row is the selected one. */
    ASSERT_EQ(tui_test_is_reverse(y, 1), 1);
}

/* ── ASSERT(1) ratchet ───────────────────────────────────────
 *
 * A view test that ends in ASSERT(1) proves the draw returned, nothing
 * about what it drew. #116 converts them file by file to rendered-output
 * assertions; this keeps a converted file converted and the total from
 * growing back. The needle is split so this file does not count itself. */
#define SMOKE_NEEDLE "ASSERT(" "1);"

static int smoke_count_in(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f))
        if (strstr(line, SMOKE_NEEDLE)) n++;
    fclose(f);
    return n;
}

/* Converted files: none may reintroduce a smoke assert. */
static const char *const CONVERTED[] = {
    "tests/test_dashboard.c",
    "tests/test_probe.c",
    "tests/test_iface_graph.c",
    "tests/test_tree.c",
    "tests/test_views_render.c",
};

static void test_no_smoke_asserts_in_converted_files(void) {
    for (size_t i = 0; i < sizeof(CONVERTED) / sizeof(CONVERTED[0]); i++) {
        int n = smoke_count_in(CONVERTED[i]);
        if (n != 0)
            fprintf(stderr, "    %s: %d smoke assert(s)\n", CONVERTED[i], n);
        ASSERT_EQ(n, 0);
    }
}

/* What remains across tests/, as a ceiling that only moves down. Lower
 * it in the commit that converts a file; never raise it. */
#define SMOKE_CEILING 60

static void test_smoke_asserts_do_not_grow(void) {
    DIR *d = opendir("tests");
    ASSERT(d != NULL);
    if (!d) return;
    int total = 0, files = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len < 3 || strcmp(de->d_name + len - 2, ".c") != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "tests/%s", de->d_name);
        int n = smoke_count_in(path);
        if (n > 0) total += n;
        files++;
    }
    closedir(d);
    ASSERT(files > 100);
    if (total > SMOKE_CEILING)
        fprintf(stderr, "    %d smoke asserts under tests/, ceiling %d\n",
                total, SMOKE_CEILING);
    ASSERT(total <= SMOKE_CEILING);
}

void run_views_render_tests(void) {
    TEST_SUITE("views through tui_draw (#116)");
    RUN_TEST(test_the_list_covers_every_view);
    RUN_TEST(test_every_view_selects_its_own_tab);
    RUN_TEST(test_every_view_body_comes_from_its_own_draw);
    RUN_TEST(test_the_dashboard_draws_no_tab_bar);
    RUN_TEST(test_the_tab_bar_wraps_without_splitting_a_label);
    RUN_TEST(test_channel_view_renders_a_seeded_row);
    RUN_TEST(test_eapol_view_renders_a_seeded_row);
    RUN_TEST(test_no_smoke_asserts_in_converted_files);
    RUN_TEST(test_smoke_asserts_do_not_grow);
}
