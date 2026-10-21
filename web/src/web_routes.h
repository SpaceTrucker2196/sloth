/* slothweb routes (#158, M0): the exact-match table and the bytes each
 * route sends. Pure: no socket, no clock, so every answer can be checked
 * byte for byte (web/tests/test_routes.c).
 *
 *   /             the embedded page; ETag, If-None-Match gives 304
 *   /api/health   JSON
 *   /events       Server-Sent Events: tick, ping
 *   anything else 404
 *
 * Before the table: no Host, or two, is 400; a Host (or absolute-form
 * authority) that is not localhost or an IP literal is 421.
 *
 * Only GET and HEAD reach the router; web_http.c has already answered
 * every other method 405. */
#ifndef SLOTHWEB_ROUTES_H
#define SLOTHWEB_ROUTES_H

#include <stddef.h>

#include "web_http.h"

/* EventSource reconnect delay sent at the start of every stream. */
#define WEB_SSE_RETRY_MS 3000

typedef struct {
    long long     uptime_s;
    unsigned      sse_clients;
    unsigned long tick_seq;
} web_health_t;

enum { WEB_R_ONESHOT = 0, WEB_R_SSE };

typedef struct {
    int                  kind;      /* WEB_R_ONESHOT or WEB_R_SSE */
    int                  status;
    size_t               out_len;   /* header, plus any small body, in out */
    const unsigned char *body;      /* a static body sent after out, or NULL */
    size_t               body_len;
} web_resp_t;

/* Route rq. sse_room is 0 when every event-stream slot is in use, which
 * makes /events a 503. Returns 0, or -1 if out is too small. */
int    web_route(const web_req_t *rq, const web_health_t *h, int sse_room,
                 char *out, size_t outsz, web_resp_t *r);

/* One "tick" event: id, event name and a JSON data line. 0 if out is
 * too small. */
size_t web_sse_tick(char *out, size_t outsz, unsigned long seq, long long ts,
                    const web_health_t *h);

/* The keep-alive comment. */
size_t web_sse_ping(char *out, size_t outsz);

#endif
