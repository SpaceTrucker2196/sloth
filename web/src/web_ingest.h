/* slothweb data-socket client (#159, M1).
 *
 * One thread connects to sloth's --data-socket, reads JSONL, decodes it
 * (web_jsonl.c) and applies it to the live state (web_live.c). When the
 * peer goes away, or will not answer, it waits a back-off that doubles
 * from backoff_min_ms up to backoff_max_ms and tries again; a
 * connection that delivered at least one whole line resets the back-off.
 *
 * It never writes to the socket (the stream is one-way; sloth never
 * reads from a client) and never resolves a name: --socket takes a path
 * or a literal address only. */
#ifndef SLOTHWEB_INGEST_H
#define SLOTHWEB_INGEST_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_jsonl.h"
#include "web_live.h"

/* sloth's own default since #136 (src/data_socket.h). */
#define WEB_DEFAULT_SOCKET       "unix:/run/sloth/sloth.sock"
#define WEB_SOCK_BACKOFF_MIN_MS  250
/* The cap keeps a restarted sloth on the page within the spec's 5 s
 * (§12, M1): the next attempt is never further away than this. */
#define WEB_SOCK_BACKOFF_MAX_MS  4000
#define WEB_SOCK_CONNECT_MS      3000
#define WEB_SOCK_PATH_MAX        107     /* sun_path less its NUL */

enum { WEB_SOCKSPEC_UNIX = 1, WEB_SOCKSPEC_TCP };

typedef struct {
    int      kind;                    /* WEB_SOCKSPEC_* */
    char     path[WEB_SOCK_PATH_MAX + 1];
    int      family;                  /* AF_INET or AF_INET6, tcp only */
    uint8_t  addr[16];
    uint16_t port;
} web_sockspec_t;

/* "unix:PATH" or "tcp:A.B.C.D:PORT" / "tcp:[V6]:PORT". Literal addresses
 * only. 0, or -1 with err. */
int  web_sockspec_parse(const char *s, web_sockspec_t *out,
                        char *err, size_t errsz);
void web_sockspec_format(const web_sockspec_t *sp, char *buf, size_t sz);
/* A unix socket, or a tcp address on loopback. */
int  web_sockspec_is_local(const web_sockspec_t *sp);

/* The next back-off: min when cur is 0, else twice cur, at most max. */
int  web_backoff_next(int cur, int min_ms, int max_ms);

/* The line framer, without a socket: bytes in, records and decode
 * errors out to the live state. A line over WEB_JL_MAX_LINE is
 * discarded through its newline and counted once. */
typedef struct {
    size_t     len;
    int        discarding;
    char       line[WEB_JL_MAX_LINE + 1];
    web_jrec_t rec;
} web_feed_t;

void web_feed_reset(web_feed_t *f);
/* Returns the number of complete lines seen (decoded or not). */
size_t web_feed_bytes(web_feed_t *f, web_live_t *l, const char *buf,
                      size_t n, long long now_ms);
/* The stream ended: a partial line is counted as truncated. */
void web_feed_eof(web_feed_t *f, web_live_t *l);

typedef struct {
    web_sockspec_t spec;
    int            backoff_min_ms, backoff_max_ms, connect_ms;
    web_live_t    *live;
    int            stop[2];
    pthread_t      th;
    int            running;
    web_feed_t     feed;
    char           rbuf[65536];
} web_ingest_t;

/* Start the thread. 0, or -1 with err. */
int  web_ingest_start(web_ingest_t *g, const web_sockspec_t *spec,
                      int backoff_min_ms, int backoff_max_ms,
                      web_live_t *live, char *err, size_t errsz);
/* Stop and join it; safe to call when it never started. */
void web_ingest_stop(web_ingest_t *g);

#endif
