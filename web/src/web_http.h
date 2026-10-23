/* slothweb request parsing (#157 W0, #158 M0).
 *
 * A request is read only far enough to route it. A well-formed GET or
 * HEAD comes back as WEB_HTTP_ROUTE with its path and If-None-Match;
 * every other method is 405 (forever: slothweb is read-only), a
 * malformed request line or header 400, an HTTP major version other
 * than 1 505, and a header block that does not fit in WEB_HDR_MAX bytes
 * 431. A request body is never read. */
#ifndef SLOTHWEB_HTTP_H
#define SLOTHWEB_HTTP_H

#include <stddef.h>

/* The whole header block, request line through the empty line that ends
 * it, must fit in this many bytes. */
#define WEB_HDR_MAX 8192

/* A path or If-None-Match longer than this is not kept (the *_long flag
 * is set): no route is that long, and an unkept validator only costs a
 * 200 where a 304 would have done. */
#define WEB_PATH_MAX 1024
#define WEB_INM_MAX  512
/* The query string, kept for the routes that take parameters; a longer
 * one is not kept (query_long). Sized for the SQL box (M5, #163): a
 * WEB_SQL_MAX_BYTES statement percent-encoded is longer than any other
 * route's whole query, and every route but /api/query refuses a query
 * of WEB_QUERY_ROUTE_MAX bytes or more as "query_too_long", as the
 * 512-byte buffer once made them. */
#define WEB_QUERY_MAX       6144
#define WEB_QUERY_ROUTE_MAX 512
/* A Host value (or an absolute-form authority) longer than this is not
 * kept: the longest acceptable one, a bracketed IPv6 literal with a
 * port, is 47 bytes. */
#define WEB_HOST_MAX 256

/* Not an HTTP status: "well-formed GET or HEAD, route it". */
#define WEB_HTTP_ROUTE 200

typedef struct {
    int  is_head;
    char path[WEB_PATH_MAX];  /* request target, query removed */
    int  path_long;
    char query[WEB_QUERY_MAX]; /* after the '?', raw; "" when none */
    int  query_long;
    char inm[WEB_INM_MAX];    /* every If-None-Match line, comma-joined */
    int  inm_present, inm_long;
    char host[WEB_HOST_MAX];  /* the Host value, OWS trimmed */
    int  host_count, host_long;
    /* An absolute-form target's authority, which RFC 9112 §3.2.2 says
     * replaces Host for routing. */
    char target_host[WEB_HOST_MAX];
    int  target_abs, target_host_long;
} web_req_t;

/* Parse the bytes received so far. Returns 0 when more are needed,
 * WEB_HTTP_ROUTE, or the error status to answer with. */
int    web_http_parse(const char *buf, size_t len, web_req_t *rq);

/* RFC 9110 §13.1.2: does an If-None-Match value match etag (quoted)?
 * Weak comparison, "*" matches anything. */
int    web_http_inm_matches(const char *inm, const char *etag);

/* Is host (a Host value or an absolute-form authority) one slothweb
 * answers to? "localhost", a literal IPv4 address or a bracketed
 * literal IPv6 address, each with an optional :port. A name other than
 * localhost is refused: an attacker who points their own name at
 * 127.0.0.1 (DNS rebinding) makes the browser send that name, and an IP
 * literal cannot be rebound. No name is ever resolved here. */
int    web_http_host_ok(const char *host);

/* web_http_parse() without the request fields: 0, WEB_HTTP_ROUTE or an
 * error status; *is_head is set when the answer must carry no body.
 * len may exceed WEB_HDR_MAX only in tests; the server never buffers
 * more. */
int    web_http_classify(const char *buf, size_t len, int *is_head);

/* Write the fixed plain-text response for `status` (an error, or 404
 * from the router) into out. Returns its length, or 0 if out is too
 * small. */
size_t web_http_response(int status, int is_head, char *out, size_t outsz);

const char *web_http_reason(int status);

#endif
