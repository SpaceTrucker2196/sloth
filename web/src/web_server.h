/* slothweb listener and connection loop (#157, W0).
 *
 * One poll() loop on one thread. Each accepted peer is checked against
 * the allow list before anything is read; a refused peer is closed and
 * counted. An admitted peer gets one fixed response (web_http.c) and the
 * connection is closed: there is no keep-alive in W0. */
#ifndef SLOTHWEB_SERVER_H
#define SLOTHWEB_SERVER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_config.h"
#include "web_http.h"

#define WEB_MAX_CONNS 32

typedef struct {
    unsigned long accepted;   /* admitted by the allow list */
    unsigned long refused;    /* closed at accept(): not on the allow list */
    unsigned long busy;       /* admitted but closed: every slot in use */
    unsigned long served;     /* a complete response was written */
    unsigned long timeouts;   /* header or write budget exhausted */
    unsigned long status_404, status_405, status_431, status_400;
} web_stats_t;

typedef struct {
    int       fd;             /* -1 when the slot is free */
    int       state;
    long long deadline_ms;
    size_t    len;
    char      buf[WEB_HDR_MAX];
    size_t    out_len, out_off;
    char      out[1024];
} web_conn_t;

typedef struct {
    int             lfd;
    int             wake[2];
    uint16_t        port;     /* the bound port, after an ephemeral bind */
    web_config_t    cfg;
    web_conn_t      conns[WEB_MAX_CONNS];
    pthread_mutex_t mu;       /* guards stats only */
    web_stats_t     stats;
} web_server_t;

/* Applies web_config_check() again, so a caller that skips the CLI
 * still cannot bind a non-loopback address without allow_remote; the
 * refusal happens before socket(). 0, or -1 with err. Call
 * web_server_close() afterwards either way. */
int      web_server_open(web_server_t *s, const web_config_t *cfg,
                         char *err, size_t errsz);

/* Serve until web_server_stop(). 0 on a requested stop, -1 on a poll
 * failure. */
int      web_server_run(web_server_t *s);

/* Async-signal-safe and thread-safe: one write() to a pipe. */
void     web_server_stop(web_server_t *s);

void     web_server_stats(web_server_t *s, web_stats_t *out);
uint16_t web_server_port(const web_server_t *s);
void     web_server_close(web_server_t *s);

#endif
