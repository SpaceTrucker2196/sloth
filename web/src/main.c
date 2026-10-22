/* slothweb (#157 W0, #158 M0, #159 M1, #160 M2): the allow list and
 * its refusals, the embedded page, /api/health, /api/live, the /events
 * stream, the data-socket client that feeds them, and the time series
 * behind /api/series. See web/README.md. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_config.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_server.h"
#include "web_store.h"
#include "web_tsdb.h"

static web_server_t  g_srv;   /* ~2.3 MB: static, not on the stack */
static web_live_t    g_live;
static web_ingest_t  g_ingest;
static web_rollup_t  g_rollup;
static web_metrics_t g_metrics;
static web_store_t   g_store;
static web_tsdb_t    g_tsdb;

static void on_signal(int sig) {
    (void)sig;
    web_server_stop(&g_srv);
}

int main(int argc, char **argv) {
    web_config_t cfg;
    int rc = web_config_parse(&cfg, argc, argv, stdout, stderr);
    if (rc == 1) return 0;
    if (rc != 0) return 2;
    web_config_announce(&cfg, stderr);

    char err[512];
    if (web_server_open(&g_srv, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "slothweb: %s\n", err);
        web_server_close(&g_srv);
        return 1;
    }

    /* The store is the operator's file: a refusal (sloth.db, a newer
     * schema, a permissive mode, a symlink) stops slothweb rather than
     * running on without the history it was asked to keep. */
    int have_store = 0;
    if (web_store_available()) {
        if (web_store_open(&g_store, cfg.store_path, err, sizeof(err)) != 0) {
            fprintf(stderr, "slothweb: store: %s\n", err);
            web_store_close(&g_store);
            web_server_close(&g_srv);
            return 1;
        }
        have_store = 1;
    }
    if (web_rollup_init(&g_rollup, cfg.max_keys, have_store, err,
                        sizeof(err)) != 0 ||
        web_metrics_init(&g_metrics, &g_rollup, NULL, NULL) != 0 ||
        web_tsdb_init(&g_tsdb, &g_rollup, have_store ? &g_store : NULL,
                      cfg.retain_days, cfg.max_mb, NULL, NULL) != 0) {
        fprintf(stderr, "slothweb: time series: out of memory\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    char spec[160];
    web_sockspec_format(&cfg.sock, spec, sizeof(spec));
    web_live_init(&g_live, spec);
    web_server_set_live(&g_srv, &g_live);
    web_server_set_tsdb(&g_srv, &g_tsdb);
    web_ingest_set_metrics(&g_ingest, &g_metrics);
    if (web_tsdb_start(&g_tsdb, err, sizeof(err)) != 0 ||
        web_ingest_start(&g_ingest, &cfg.sock, cfg.sock_backoff_min_ms,
                         cfg.sock_backoff_max_ms, &g_live,
                         err, sizeof(err)) != 0) {
        fprintf(stderr, "slothweb: %s\n", err);
        web_tsdb_stop(&g_tsdb);
        web_server_close(&g_srv);
        web_live_destroy(&g_live);
        web_store_close(&g_store);
        return 1;
    }

    char where[64];
    web_format_bind(cfg.bind_family, cfg.bind_addr, web_server_port(&g_srv),
                    where, sizeof(where));
    fprintf(stderr, "slothweb: listening on http://%s/ "
                    "(/, /api/health, /api/live, /api/series, /api/keys, "
                    "/api/metrics, /events)\n", where);
    fprintf(stderr, "slothweb: reading %s (read-only; reconnects on its "
                    "own)\n", spec);
    if (have_store)
        fprintf(stderr, "slothweb: time series in %s (10 s for 24 h, 1 min "
                        "for %d d, 1 h for 400 d; ceiling %d MB)\n",
                cfg.store_path, cfg.retain_days, cfg.max_mb);
    else
        fprintf(stderr, "slothweb: built without SQLite: time series in "
                        "memory only (10 s buckets, no minute or hour tier)\n");

    rc = web_server_run(&g_srv);
    web_ingest_stop(&g_ingest);
    web_tsdb_stop(&g_tsdb);

    web_stats_t st;
    web_server_stats(&g_srv, &st);
    fprintf(stderr, "slothweb: stopped: %lu admitted, %lu refused at accept, "
                    "%lu busy, %lu served, %lu timed out, %lu accept back-offs\n",
            st.accepted, st.refused, st.busy, st.served, st.timeouts,
            st.accept_paused);
    web_server_close(&g_srv);
    web_live_destroy(&g_live);
    web_tsdb_destroy(&g_tsdb);
    web_metrics_destroy(&g_metrics);
    web_rollup_destroy(&g_rollup);
    web_store_close(&g_store);
    return rc == 0 ? 0 : 1;
}
