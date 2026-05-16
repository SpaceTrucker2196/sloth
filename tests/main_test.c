#include <stdio.h>
#include "runner.h"

/* Shared counters — all test files reference these via extern */
int g_pass     = 0;
int g_fail     = 0;
int g_test_fail = 0;

void run_parse_tests(void);
void run_rate_tests(void);
void run_state_tests(void);
void run_scenario_tests(void);
void run_conns_tests(void);

int main(void) {
    printf("ntop test suite\n");
    printf("===============\n");

    run_parse_tests();
    run_rate_tests();
    run_state_tests();
    run_scenario_tests();
    run_conns_tests();

    RUNNER_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
