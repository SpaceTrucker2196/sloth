/* slothweb (#157, W0): the listener, the allow list and the refusals,
 * before any route exists. See web/README.md. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_config.h"
#include "web_server.h"

static web_server_t g_srv;   /* ~300 KB: static, not on the stack */

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

    char where[64];
    web_format_bind(cfg.bind_family, cfg.bind_addr, web_server_port(&g_srv),
                    where, sizeof(where));
    fprintf(stderr, "slothweb: listening on %s; no routes yet "
                    "(GET/HEAD 404, other methods 405)\n", where);

    rc = web_server_run(&g_srv);

    web_stats_t st;
    web_server_stats(&g_srv, &st);
    fprintf(stderr, "slothweb: stopped: %lu admitted, %lu refused at accept, "
                    "%lu busy, %lu served, %lu timed out\n",
            st.accepted, st.refused, st.busy, st.served, st.timeouts);
    web_server_close(&g_srv);
    return rc == 0 ? 0 : 1;
}
