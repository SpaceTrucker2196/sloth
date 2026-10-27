#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "wtest.h"
#include "wt_tmp.h"

int wt_pass, wt_fail;

/* The run directory (wt_tmp.h): every temporary path a suite makes lands
 * here, and what is left after the last suite fails the run. Removed at
 * exit only by the process that made it, so a fork child that leaves
 * through exit() cannot take it from the parent still testing.
 * SLOTH_TEST_KEEP_TMP=1 keeps it. */
static char  g_run_dir[TEST_TMP_MAX];
static pid_t g_run_owner;
static int   g_run_keep;

/* A run directory that cannot be removed fails the run, even one whose
 * suites all passed: _exit() from an atexit handler sets the status. */
static void run_dir_cleanup(void) {
    if (getpid() == g_run_owner &&
        tmp_run_dir_close(g_run_dir, "slothweb_test") != 0) {
        /* _exit() skips stdio's flush: the summary line would be lost
         * on a pipe in exactly the run that fails for this. */
        fflush(NULL);
        _exit(1);
    }
}

/* Ctrl-C, or a TERM from make or timeout(1), skips atexit(): remove the
 * tree here, then die of the same signal so the caller sees it. */
static void run_dir_on_signal(int sig) {
    if (getpid() == g_run_owner && !g_run_keep)
        tmp_run_dir_signal_rm(g_run_dir);
    raise(sig);
}

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
    if (tmp_run_dir_open(g_run_dir, sizeof(g_run_dir), "slothweb_test",
                         "slothweb_test") != 0)
        return 2;
    g_run_owner = getpid();
    g_run_keep  = tmp_run_dir_keep();
    atexit(run_dir_cleanup);
    tmp_run_dir_trap_signals(run_dir_on_signal);
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
    SUITE(run_scope_tests);
    SUITE(run_prefs_tests);
    SUITE(run_glyph_tests);
    /* The leak guard, under WT_ONLY too: a path still here is one a
     * suite made and did not remove. */
    if (tmp_run_dir_check(g_run_dir, "slothweb_test") != 0) wt_fail++;
    printf("slothweb tests: %d passed, %d failed\n", wt_pass, wt_fail);
    return wt_fail ? 1 : 0;
}
