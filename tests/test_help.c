#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "views/help.h"

/* Read view_help_draw()'s rendered screen (#116) into `buf` so we can
 * assert on what the card actually renders. */
static void capture_help(char *buf, int sz) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* Rendered through ncurses into the offscreen screen (#116), and
     * read back from the cells rather than from a redirected stdout. */
    tui_test_erase();
    view_help_draw(&s);
    tui_test_screen(buf, (size_t)sz);
}

/* The card's view list is rendered straight from view_label(), so every
 * view that exists must show up — the guard against the pre-#39 drift
 * where seven WiFi-SIGINT keys were missing from the help screen. */
static void test_help_lists_every_view(void) {
    char buf[8192];
    capture_help(buf, sizeof(buf));
    /* Asserting only inside the failure branch (#114) runs zero
     * assertions on the normal, all-present path — exactly the
     * "silently correct" shape this view exists to guard against.
     * Assert the condition itself every iteration instead, so VIEW_COUNT
     * assertions always run and the missing label still gets named. */
    for (int v = 0; v < VIEW_COUNT; v++) {
        const char *label = view_label((view_t)v);
        if (!strstr(buf, label))
            fprintf(stderr, "help card missing view label: %s\n", label);
        ASSERT(strstr(buf, label) != NULL);
    }
}

/* The embedded IOC list is synthetic demo data. The help card is the
 * operator-facing place that has to say so — a docs-only disclosure does
 * not reach someone reading the TUI (#96). */
static void test_help_labels_threat_intel_as_demo(void) {
    char buf[8192];
    capture_help(buf, sizeof(buf));
    ASSERT(strstr(buf, "SYNTHETIC DEMO LIST") != NULL);
    ASSERT(strstr(buf, "THREAT_DOMAIN")       != NULL);
    ASSERT(strstr(buf, "THREAT_IP")           != NULL);
}

/* view_label() is well-formed for every view and safe out of range. */
static void test_view_label_bounds(void) {
    for (int v = 0; v < VIEW_COUNT; v++) {
        const char *l = view_label((view_t)v);
        ASSERT(l != NULL);
        ASSERT(l[0] == '[');          /* "[k] Name" shape */
    }
    ASSERT_STR(view_label((view_t)-1), "?");
    ASSERT_STR(view_label((view_t)VIEW_COUNT), "?");
}

void run_help_tests(void) {
    TEST_SUITE("help card / view_label sync (#39)");
    RUN_TEST(test_help_lists_every_view);
    RUN_TEST(test_help_labels_threat_intel_as_demo);
    RUN_TEST(test_view_label_bounds);
}
