#include <signal.h>
#include <stdlib.h>
#include <time.h>

#include "wtest.h"

int wt_pass, wt_fail;

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    /* The baselines index the local hour of the week: the suite pins the
     * zone, as it pins the clock, so a cell is the same on every host. */
    setenv("TZ", "UTC0", 1);
    tzset();
    run_acl_tests();
    run_config_tests();
    run_http_tests();
    run_routes_tests();
    run_tui_colors_tests();
    run_server_tests();
    run_json_tests();
    run_jsonl_tests();
    run_live_tests();
    run_ingest_tests();
    run_rollup_tests();
    run_metrics_tests();
    run_store_tests();
    run_series_tests();
    run_baseline_tests();
    run_ident_tests();
    run_anomaly_tests();
    run_replay_tests();
    run_oui_tests();
    run_query_tests();
    run_ptr_tests();
    run_slothdb_tests();
    run_devices_tests();
    run_parity_tests();
    run_wifi_tests();
    run_chmix_tests();
    run_history_tests();
    run_flows_tests();
    run_readme_tests();
    run_sqlbox_tests();
    printf("slothweb tests: %d passed, %d failed\n", wt_pass, wt_fail);
    return wt_fail ? 1 : 0;
}
