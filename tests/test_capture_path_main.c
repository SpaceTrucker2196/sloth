#include <stdio.h>
#include "runner.h"

/* Entry point for sloth_test_pcap (#95). Deliberately runs only the
 * capture-path suite: the rest of tests/ is compiled into this binary
 * to satisfy the link, but those cases assert the behaviour of the
 * no-WITH_PCAP build and do not hold here. See the Makefile note on
 * CAPTURE_PATH_SRCS (#115: now a wildcard over tests/). */

/* The counters live in main_test.c, which this binary deliberately
 * excludes; runner.h expects them at file scope somewhere. No default
 * setUp here (#114) — this suite's tests already manage their own
 * state via explicit probe_clear()/probe_pnl_clear() calls. Since #115
 * src/reset_all.c is linked here too (TEST_ONLY_SRCS); the poll_tick
 * cases (#113) call sloth_reset_all() + probe_clear() themselves,
 * because a whole tick touches every module's table. */
int g_pass      = 0;
int g_fail      = 0;
int g_test_fail = 0;
int g_test_total = 0;
void (*g_test_setup)(void) = NULL;

void run_capture_path_tests(void);
void run_poll_capture_path_tests(void);   /* tests/test_poll.c (#113) */

int main(void) {
    printf("sloth capture-path suite (WITH_PCAP)\n");
    printf("====================================\n");

    run_capture_path_tests();
    run_poll_capture_path_tests();

    RUNNER_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
