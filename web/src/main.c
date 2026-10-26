/* slothweb (#157 W0, #158 M0, #159 M1, #160 M2, #161 M3, #162 M4, #163
 * M5): the allow list and its refusals, the embedded page, /api/health,
 * /api/live, the /events stream, the data-socket client that feeds
 * them, the time series behind /api/series, and the baselines and
 * anomaly rules behind /api/baseline and /api/anomalies, the Devices
 * and Lookup routes over a read-only sloth.db, the WiFi and History
 * routes, and the SQL box behind --web-allow-sql. See web/README.md. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_chmix.h"
#include "web_config.h"
#include "web_devices.h"
#include "web_ident.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_oui.h"
#include "web_ptr.h"
#include "web_rollup.h"
#include "web_server.h"
#include "web_slothdb.h"
#include "web_sqlbox.h"
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
static web_ptr_t      g_ptr;
static web_slothdb_t  g_sdb;
static web_m4_t       g_m4;
static web_sqlbox_t   g_sql;
static web_chmix_t    g_chmix;

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
        /* web_config_check() refused a --web-max-mb below the analysis
         * state's estimate plus this (web_store.h). */
        web_store_set_history_allowance(&g_store, web_store_history_bytes(
            web_baseline_cap_for(cfg.max_keys)));
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
    /* M4: the vendor table, sloth.db (read-only), the passive PTR cache.
     * sloth.db absent or refused is not fatal: it may appear when sloth
     * starts, and every request opens it afresh. */
    acfg.oui = web_oui_builtin();
    acfg.sdb = cfg.sloth_db[0] ? &g_sdb : NULL;
    acfg.ptr = &g_ptr;
    web_sdb_fns_t fns = { acfg.oui, &g_anomaly, &g_ptr };
    web_slothdb_init(&g_sdb, cfg.sloth_db, &fns);
    if (web_rollup_init(&g_rollup, cfg.max_keys,
                        have_store ? 1 : WEB_ROLLUP_Q_LONG, err,
                        sizeof(err)) != 0 ||
        web_metrics_init(&g_metrics, &g_rollup, NULL, NULL) != 0 ||
        web_tsdb_init(&g_tsdb, &g_rollup, have_store ? &g_store : NULL,
                      cfg.retain_days, cfg.max_mb, NULL, NULL) != 0 ||
        web_baseline_init(&g_baseline,
                          web_baseline_cap_for(cfg.max_keys)) != 0 ||
        web_ident_init(&g_ident, cfg.max_keys, cfg.max_keys / 2) != 0 ||
        web_ptr_init(&g_ptr, WEB_PTR_CAP) != 0 ||
        web_anomaly_init(&g_anomaly, WEB_ANOM_CAP, &acfg) != 0 ||
        web_chmix_init(&g_chmix, have_store) != 0) {
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
    web_metrics_set_mix(&g_metrics, &g_chmix);
    web_tsdb_set_mix(&g_tsdb, &g_chmix);
    web_ident_set_ptr(&g_ident, &g_ptr);
    g_m4.sdb = cfg.sloth_db[0] ? &g_sdb : NULL;
    g_m4.oui = acfg.oui;
    g_m4.ptr = &g_ptr;
    g_m4.ident = &g_ident;
    g_m4.anomaly = &g_anomaly;
    g_m4.tsdb = &g_tsdb;
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
    web_server_set_m4(&g_srv, &g_m4);
    /* The SQL box: its own thread, its own one-answer buffer, only with
     * --web-allow-sql (web_config_check() refused it under --strict
     * and without --sloth-db). */
    err[0] = '\0';
    if (web_sqlbox_init(&g_sql, &g_sdb, cfg.allow_sql) != 0 ||
        web_sqlbox_start(&g_sql, err, sizeof(err)) != 0) {
        fprintf(stderr, "slothweb: SQL box: %s\n",
                err[0] ? err : "out of memory");
        web_server_close(&g_srv);
        return 1;
    }
    web_server_set_sqlbox(&g_srv, &g_sql);
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
                    "/api/metrics, /api/baseline, /api/anomalies, "
                    "/api/devices, /api/device/MAC, /api/lookup, "
                    "/api/wifi/*, /api/history/*, /api/sessions, /api/flows, "
                    "/api/flows/graph%s, /events)\n",
            where, cfg.allow_sql ? ", /api/query, /api/recipes" : "");
    if (cfg.allow_sql)
        fprintf(stderr, "slothweb: SQL box on (--web-allow-sql): one "
                        "read-only SELECT at a time over %s, %d s, %d rows, "
                        "credential columns withheld\n", cfg.sloth_db,
                WEB_SQL_TIMEOUT_MS / 1000, WEB_SQL_ROW_CAP);
    const web_oui_tab_t *ot = web_oui_builtin();
    fprintf(stderr, "slothweb: vendor table: %s (%u MA-L, %u MA-M, %u MA-S)%s\n",
            ot->source, ot->counts[WEB_OUI_MAL], ot->counts[WEB_OUI_MAM],
            ot->counts[WEB_OUI_MAS],
            web_oui_full(ot) ? "" : "; A4 off: built without the IEEE CSVs "
                                   "in web/data/ (web/data/SOURCE.md)");
    if (cfg.sloth_db[0]) {
        int st = web_slothdb_check(&g_sdb, (long long)time(NULL));
        web_sdb_stats_t ss;
        web_slothdb_stats(&g_sdb, &ss);
        if (st == WEB_SDB_OPEN)
            fprintf(stderr, "slothweb: sloth.db %s: schema v%d, %lld devices, "
                            "read-only (%s)\n", cfg.sloth_db, ss.schema, ss.rows,
                    ss.mode);
        else
            fprintf(stderr, "slothweb: sloth.db %s: %s (%s); Devices and A2's "
                            "durable first_seen wait for it, retried on every "
                            "request\n", cfg.sloth_db,
                    web_slothdb_state_word(st), ss.err);
    } else {
        fprintf(stderr, "slothweb: no --sloth-db: the Devices view and the "
                        "drawer's sloth.db record are off; Lookup answers from "
                        "the stream and the vendor table\n");
    }
    fprintf(stderr, "slothweb: reading %s (read-only; reconnects on its "
                    "own)\n", spec);
    if (have_store) {
        fprintf(stderr, "slothweb: time series in %s (10 s for 24 h, 1 min "
                        "for %d d, 1 h for 400 d; ceiling %d MB)\n",
                cfg.store_path, cfg.retain_days, cfg.max_mb);
        fprintf(stderr, "slothweb: baselines (%d restored) and anomaly "
                        "rules A1-A3, A5-A10%s active, kept in %s\n",
                web_baseline_count(&g_baseline),
                web_oui_full(web_oui_builtin()) ? " and A4" : "",
                cfg.store_path);
    } else {
        fprintf(stderr, "slothweb: built without SQLite: time series in "
                        "memory only (10 s buckets, no minute or hour tier "
                        "to read back); baselines and anomaly episodes in "
                        "memory, lost at exit; rules A1 (z only, no MAD), "
                        "A2, A3, A5-A8 and A10 active (A4 with the IEEE "
                        "table), A9 needs the store\n");
    }

    rc = web_server_run(&g_srv);
    web_sqlbox_stop(&g_sql);
    web_ingest_stop(&g_ingest);
    web_tsdb_stop(&g_tsdb);

    web_stats_t st;
    web_server_stats(&g_srv, &st);
    fprintf(stderr, "slothweb: stopped: %lu admitted, %lu refused at accept, "
                    "%lu busy, %lu served, %lu timed out, %lu accept back-offs\n",
            st.accepted, st.refused, st.busy, st.served, st.timeouts,
            st.accept_paused);
    web_server_close(&g_srv);
    web_sqlbox_destroy(&g_sql);
    web_live_destroy(&g_live);
    web_tsdb_destroy(&g_tsdb);
    web_metrics_destroy(&g_metrics);
    web_chmix_destroy(&g_chmix);
    web_rollup_destroy(&g_rollup);
    web_anomaly_destroy(&g_anomaly);
    web_baseline_destroy(&g_baseline);
    web_ident_destroy(&g_ident);
    web_ptr_destroy(&g_ptr);
    web_slothdb_destroy(&g_sdb);
    web_store_close(&g_store);
    return rc == 0 ? 0 : 1;
}
