#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "views/help.h"

/* Capture view_help_draw()'s stdout (TPRINT is printf in the test
 * build) into `buf` so we can assert on what the card actually renders. */
static void capture_help(char *buf, int sz) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    view_help_draw(&s);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
}

/* The card's view list is rendered straight from view_label(), so every
 * view that exists must show up — the guard against the pre-#39 drift
 * where seven WiFi-SIGINT keys were missing from the help screen. */
static void test_help_lists_every_view(void) {
    char buf[8192];
    capture_help(buf, sizeof(buf));
    for (int v = 0; v < VIEW_COUNT; v++) {
        const char *label = view_label((view_t)v);
        if (!strstr(buf, label)) {
            fprintf(stderr, "help card missing view label: %s\n", label);
            ASSERT(0);
        }
    }
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
    RUN_TEST(test_view_label_bounds);
}
