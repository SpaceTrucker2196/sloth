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
void run_wifi_tests(void);
void run_packets_tests(void);
void run_procs_tests(void);
void run_bw_tests(void);
void run_dns_tests(void);
void run_stats_tests(void);
void run_probe_tests(void);
void run_oui_tests(void);
void run_services_tests(void);

int main(void) {
    printf("ntop test suite\n");
    printf("===============\n");

    run_parse_tests();
    run_rate_tests();
    run_state_tests();
    run_scenario_tests();
    run_conns_tests();
    run_wifi_tests();
    run_packets_tests();
    run_procs_tests();
    run_bw_tests();
    run_dns_tests();
    run_stats_tests();
    run_probe_tests();
    run_oui_tests();
    run_services_tests();

    RUNNER_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
