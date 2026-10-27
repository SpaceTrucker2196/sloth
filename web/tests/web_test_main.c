#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtest.h"

int wt_pass, wt_fail;

/* WT_ONLY=alerts runs the suites whose name holds it: a developer's
 * shortcut, never how the gate runs. */
static int wanted(const char *name) {
    const char *only = getenv("WT_ONLY");
    return !only || !*only || strstr(name, only) != NULL;
}
#define SUITE(fn) do { if (wanted(#fn)) fn(); } while (0)

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    /* The baselines index the local hour of the week: the suite pins the
     * zone, as it pins the clock, so a cell is the same on every host. */
    setenv("TZ", "UTC0", 1);
    tzset();
    SUITE(run_acl_tests);
    SUITE(run_config_tests);
    SUITE(run_http_tests);
    SUITE(run_routes_tests);
    SUITE(run_tui_colors_tests);
    SUITE(run_server_tests);
    SUITE(run_json_tests);
    SUITE(run_jsonl_tests);
    SUITE(run_live_tests);
    SUITE(run_ingest_tests);
    SUITE(run_rollup_tests);
    SUITE(run_metrics_tests);
    SUITE(run_store_tests);
    SUITE(run_series_tests);
    SUITE(run_baseline_tests);
    SUITE(run_ident_tests);
    SUITE(run_anomaly_tests);
    SUITE(run_replay_tests);
    SUITE(run_oui_tests);
    SUITE(run_query_tests);
    SUITE(run_ptr_tests);
    SUITE(run_slothdb_tests);
    SUITE(run_devices_tests);
    SUITE(run_parity_tests);
    SUITE(run_wifi_tests);
    SUITE(run_chmix_tests);
    SUITE(run_tables_tests);
    SUITE(run_history_tests);
    SUITE(run_flows_tests);
    SUITE(run_readme_tests);
    SUITE(run_alertfmt_tests);
    SUITE(run_alertkb_tests);
    SUITE(run_alerts_tests);
    SUITE(run_sqlbox_tests);
    printf("slothweb tests: %d passed, %d failed\n", wt_pass, wt_fail);
    return wt_fail ? 1 : 0;
}
