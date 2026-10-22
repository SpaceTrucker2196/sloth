/* slothweb (#157 W0, #158 M0, #159 M1, #160 M2, #161 M3): the allow
 * list and its refusals, the embedded page, /api/health, /api/live, the
 * /events stream, the data-socket client that feeds them, the time
 * series behind /api/series, and the baselines and anomaly rules behind
 * /api/baseline and /api/anomalies. See web/README.md. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_config.h"
#include "web_ident.h"
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
static web_baseline_t g_baseline;
static web_anomaly_t  g_anomaly;
static web_ident_t    g_ident;

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
    /* Without a store the rollup still queues its minute and hour rows:
     * the anomaly engine reads them off the queue (web_tsdb.h), so the
     * baselines and every rule but A9 run in memory. */
    web_anom_cfg_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.bl = &g_baseline;
    acfg.store = have_store ? &g_store : NULL;
    acfg.live = &g_live;
    acfg.ident = &g_ident;
    acfg.max_keys = cfg.max_keys;
    if (web_rollup_init(&g_rollup, cfg.max_keys,
                        have_store ? 1 : WEB_ROLLUP_Q_LONG, err,
                        sizeof(err)) != 0 ||
        web_metrics_init(&g_metrics, &g_rollup, NULL, NULL) != 0 ||
        web_tsdb_init(&g_tsdb, &g_rollup, have_store ? &g_store : NULL,
                      cfg.retain_days, cfg.max_mb, NULL, NULL) != 0 ||
        web_baseline_init(&g_baseline,
                          web_baseline_cap_for(cfg.max_keys)) != 0 ||
        web_ident_init(&g_ident, cfg.max_keys, cfg.max_keys / 2) != 0 ||
        web_anomaly_init(&g_anomaly, WEB_ANOM_CAP, &acfg) != 0) {
        fprintf(stderr, "slothweb: time series: out of memory\n");
        return 1;
    }
    /* Before any thread starts: the restore runs on the store's writer
     * connection, which the store thread owns from then on. */
    if (web_anomaly_restore(&g_anomaly, (long long)time(NULL)) != 0)
        fprintf(stderr, "slothweb: store: the saved baselines or anomaly "
                        "episodes could not all be read; starting from what "
                        "was\n");
    web_metrics_set_ident(&g_metrics, &g_ident);
    web_anomaly_attach(&g_anomaly, &g_tsdb);

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
    web_server_set_anomaly(&g_srv, &g_anomaly);
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
                    "/api/metrics, /api/baseline, /api/anomalies, /events)\n",
            where);
    fprintf(stderr, "slothweb: reading %s (read-only; reconnects on its "
                    "own)\n", spec);
    if (have_store) {
        fprintf(stderr, "slothweb: time series in %s (10 s for 24 h, 1 min "
                        "for %d d, 1 h for 400 d; ceiling %d MB)\n",
                cfg.store_path, cfg.retain_days, cfg.max_mb);
        fprintf(stderr, "slothweb: baselines (%d restored) and anomaly "
                        "rules A1-A3, A5-A10 active, kept in %s; A4 needs "
                        "#162's OUI table\n", web_baseline_count(&g_baseline),
                cfg.store_path);
        /* The ceiling counts the analysis state but can only drop
         * time-series rows (web_store.h): below this it would drop all
         * of them and still be over. */
        long long an = web_store_analysis_max_bytes(
            web_baseline_cap_for(cfg.max_keys), WEB_ANOM_CAP,
            cfg.max_keys / 2, cfg.max_keys);
        if ((long long)cfg.max_mb * 1024 * 1024 < an)
            fprintf(stderr, "slothweb: warning: --web-max-mb %d is below what "
                            "the baselines and episodes can take at "
                            "--web-max-keys %d (about %lld MB); once they do, "
                            "the ceiling drops every time-series row and the "
                            "file stays over it. Raise --web-max-mb or lower "
                            "--web-max-keys.\n", cfg.max_mb, cfg.max_keys,
                    an / (1024 * 1024) + 1);
    } else {
        fprintf(stderr, "slothweb: built without SQLite: time series in "
                        "memory only (10 s buckets, no minute or hour tier "
                        "to read back); baselines and anomaly episodes in "
                        "memory, lost at exit; rules A1 (z only, no MAD), "
                        "A2, A3, A5-A8 and A10 active, A9 needs the store, "
                        "A4 #162\n");
    }

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
    web_anomaly_destroy(&g_anomaly);
    web_baseline_destroy(&g_baseline);
    web_ident_destroy(&g_ident);
    web_store_close(&g_store);
    return rc == 0 ? 0 : 1;
}
