#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "rf_moved.h"

/*
 * The six decoder flags sloth-wifi refuses (#216, src/rf_moved.h).
 *
 * The exit code and the fact of refusal are the binary's, and are held
 * on the binary by tests/replay/rf_refusals.sh (`make replay-check`).
 * What is held here is the list and the line: an operator whose sensor
 * will not start after the upgrade reads exactly one line in the
 * journal, and it has to name the flag, the daemon that takes it, the
 * tool that moves it and where the steps are.
 */

/* Exactly the six, spelt exactly. A near miss is not refused as one of
 * them (it falls through to the usage text), and the receiver's flags
 * are not on the list: sloth-wifi keeps --gps and --location.
 * (Seen red with "--victron" taken off rf_moved_flags[].) */
static void test_the_six_flags_and_no_other(void) {
    static const char *const six[] = {
        "--adsb", "--aprs", "--aprs-freq", "--aprs-silent-hours",
        "--rtl433", "--victron",
    };
    int n = 0;
    while (rf_moved_flags[n]) n++;
    ASSERT_EQ(n, 6);
    for (int i = 0; i < 6; i++) {
        ASSERT(rf_moved_flag(six[i]));
        ASSERT_STR(rf_moved_flags[i], six[i]);
    }
    static const char *const kept[] = {
        "--gps", "--gps-allow-remote", "--gps-baud", "--location",
        "--bt-monitor", "--iface", "--db", "--data-socket", "--headless",
        "--adsb=", "--adsbx", "-adsb", "adsb", "--APRS", "--aprs-", "",
    };
    for (size_t i = 0; i < sizeof(kept) / sizeof(kept[0]); i++)
        ASSERT(!rf_moved_flag(kept[i]));
    ASSERT(!rf_moved_flag(NULL));
}

/* One line, no newline, naming the flag, sloth-rf, sloth-migrate-rf
 * and the section; and it fits the buffer src/main.c gives it. */
static void test_the_line_names_the_daemon_and_the_tool(void) {
    for (int i = 0; rf_moved_flags[i]; i++) {
        char m[400];
        rf_moved_message(rf_moved_flags[i], m, sizeof(m));
        char lead[64];
        snprintf(lead, sizeof(lead), "sloth-wifi: %s is sloth-rf's flag",
                 rf_moved_flags[i]);
        ASSERT_EQ(strncmp(m, lead, strlen(lead)), 0);
        ASSERT(strstr(m, "sloth-migrate-rf --apply") != NULL);
        ASSERT(strstr(m, "/etc/default/sloth-rf") != NULL);
        ASSERT(strstr(m, "docs/wiki/deployment.md section 11.4") != NULL);
        ASSERT(strstr(m, "JSONL 2.0.0") != NULL);
        ASSERT(strchr(m, '\n') == NULL);
        ASSERT_LT(strlen(m), sizeof(m) - 1);     /* not truncated */
    }
    /* A short buffer is terminated, not overrun; none is a no-op. */
    char small[16];
    memset(small, 'x', sizeof(small));
    rf_moved_message("--adsb", small, sizeof(small));
    ASSERT_EQ(strlen(small), sizeof(small) - 1);
    rf_moved_message("--adsb", NULL, 0);
    rf_moved_message(NULL, small, sizeof(small));
    ASSERT_EQ(strncmp(small, "sloth-wifi: ", 12), 0);
}

void run_rf_moved_tests(void) {
    TEST_SUITE("sloth-wifi: the decoder flags it refuses (#216)");
    RUN_TEST(test_the_six_flags_and_no_other);
    RUN_TEST(test_the_line_names_the_daemon_and_the_tool);
}
