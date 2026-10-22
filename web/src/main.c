/* slothweb (#157 W0, #158 M0, #159 M1): the allow list and its
 * refusals, the embedded page, /api/health, /api/live, the /events
 * stream, and the data-socket client that feeds them. See
 * web/README.md. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_config.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_server.h"

static web_server_t g_srv;   /* ~2.3 MB: static, not on the stack */
static web_live_t   g_live;
static web_ingest_t g_ingest;

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
    if (web_ingest_start(&g_ingest, &cfg.sock, cfg.sock_backoff_min_ms,
                         cfg.sock_backoff_max_ms, &g_live,
                         err, sizeof(err)) != 0) {
        fprintf(stderr, "slothweb: %s\n", err);
        web_server_close(&g_srv);
        web_live_destroy(&g_live);
        return 1;
    }

    char where[64];
    web_format_bind(cfg.bind_family, cfg.bind_addr, web_server_port(&g_srv),
                    where, sizeof(where));
    fprintf(stderr, "slothweb: listening on http://%s/ "
                    "(/, /api/health, /api/live, /events)\n", where);
    fprintf(stderr, "slothweb: reading %s (read-only; reconnects on its "
                    "own)\n", spec);

    rc = web_server_run(&g_srv);
    web_ingest_stop(&g_ingest);

    web_stats_t st;
    web_server_stats(&g_srv, &st);
    fprintf(stderr, "slothweb: stopped: %lu admitted, %lu refused at accept, "
                    "%lu busy, %lu served, %lu timed out, %lu accept back-offs\n",
            st.accepted, st.refused, st.busy, st.served, st.timeouts,
            st.accept_paused);
    web_server_close(&g_srv);
    web_live_destroy(&g_live);
    return rc == 0 ? 0 : 1;
}
