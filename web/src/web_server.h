/* slothweb listener and connection loop (#157 W0, #158 M0, #159 M1).
 *
 * One poll() loop on one thread. Each accepted peer is checked against
 * the allow list before anything is read; a refused peer is closed and
 * counted. An admitted peer's request is parsed (web_http.c) and routed
 * (web_routes.c). A plain answer is followed by a close: there is no
 * keep-alive. An /events stream stays open and is fed by the loop's own
 * timers, a tick each tick_ms and a ping each ping_ms, until the client
 * leaves or falls WEB_SSE_MAX_UNSENT bytes behind. Each tick also sends
 * the ticker records the ingest thread has added since the last one.
 * The live state has its own lock (web_live.h); this loop only reads it. */
#ifndef SLOTHWEB_SERVER_H
#define SLOTHWEB_SERVER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_config.h"
#include "web_http.h"
#include "web_live.h"

#define WEB_MAX_CONNS 32
/* Event streams are long-lived, so they may not take every slot: the
 * rest stay free for the page and the API. */
#define WEB_MAX_SSE   24
/* A stream client that has not taken this much is dropped (spec §10.2).
 * It is also the size of every connection's output buffer, which
 * sse_queue() relies on: web_server.c fails to compile if out[] is ever
 * made smaller. */
#define WEB_SSE_MAX_UNSENT 65536
/* SO_SNDBUF asked for on a stream socket, so a stalled client holds a
 * bounded amount of kernel memory as well as of ours. */
#define WEB_SSE_SNDBUF 16384
/* How long the listener is left unpolled after accept() runs out of
 * descriptors or memory. */
#define WEB_ACCEPT_BACKOFF_MS 100
/* Ticker records sent per tick, at most (spec §7.1: coalesced to 20 a
 * second). When more arrived, the newest are sent; the seq gap shows. */
#define WEB_SSE_RECORDS_PER_TICK 20
/* Room for one tick event, the live summary included. */
#define WEB_SSE_EVENT_MAX 1024

typedef struct {
    unsigned long accepted;   /* admitted by the allow list */
    unsigned long refused;    /* closed at accept(): not on the allow list */
    unsigned long busy;       /* admitted but closed: every slot in use */
    unsigned long served;     /* a complete response was written */
    unsigned long timeouts;   /* header or write budget exhausted */
    unsigned long accept_paused; /* accept() out of fds/memory: back-off */
    unsigned long status_404, status_405, status_431, status_400;
    unsigned long status_200, status_304, status_503, status_421;
    unsigned long sse_opened;     /* /events streams started */
    unsigned long sse_closed;     /* ended by the client */
    unsigned long sse_dropped;    /* ended by us: WEB_SSE_MAX_UNSENT behind */
    unsigned long sse_drop_backlog; /* bytes still unsent at the last drop */
    unsigned long ticks;          /* tick events generated (not per client) */
    unsigned long records_sent;   /* record events generated (not per client) */
} web_stats_t;

typedef struct {
    int       fd;             /* -1 when the slot is free */
    int       state;
    long long deadline_ms;
    size_t    len;
    char      buf[WEB_HDR_MAX];
    size_t    out_len, out_off;
    char      out[WEB_SSE_MAX_UNSENT];
    const unsigned char *body;    /* static body sent after out */
    size_t    body_len, body_off;
} web_conn_t;

typedef struct {
    int             lfd;
    int             wake[2];
    uint16_t        port;     /* the bound port, after an ephemeral bind */
    long long       accept_resume_ms; /* listener unpolled until then */
    long long       start_ms;
    long long       next_tick_ms, next_ping_ms;
    unsigned long   tick_seq;
    unsigned        sse_count;
    web_config_t    cfg;
    web_conn_t      conns[WEB_MAX_CONNS];
    web_live_t     *live;     /* NULL: no data socket; set before run */
    unsigned long long rec_sent;  /* newest ticker record broadcast */
    pthread_mutex_t mu;       /* guards stats only */
    web_stats_t     stats;
} web_server_t;

/* The unbound listening socket web_server_open() uses: SO_REUSEADDR,
 * and IPV6_V6ONLY for AF_INET6 (failing if that cannot be set). Its own
 * entry point so the option can be checked without binding [::], which
 * Linux would otherwise only reveal on a wildcard bind: binding a
 * specific v6 address such as ::1 sets V6ONLY by itself. fd or -1. */
int      web_server_socket(int family, char *err, size_t errsz);

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

/* Attach the live state the routes and the stream read. Call after
 * web_server_open() and before web_server_run(). */
void     web_server_set_live(web_server_t *s, web_live_t *live);

void     web_server_stats(web_server_t *s, web_stats_t *out);
uint16_t web_server_port(const web_server_t *s);
void     web_server_close(web_server_t *s);

#endif
