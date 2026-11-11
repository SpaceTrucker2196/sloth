/* slothweb-mcp's HTTP: one request to slothweb and its answer.
 *
 * slothweb answers every request "Connection: close", so a request is a
 * connection: connect, send, read to the close. The address is a
 * literal (no name is ever resolved, as slothweb itself resolves none)
 * and must be loopback unless --allow-remote was given: the stream this
 * carries is everything the sensor heard, slothweb has no TLS, and the
 * agent secret would cross the network in the clear. slothweb takes
 * the secret from loopback peers only, so a remote slothweb can be read
 * with --allow-remote and never written.
 *
 * Every wait is bounded (MCP_HTTP_CONNECT_MS, MCP_HTTP_TOTAL_MS) and
 * every buffer is the caller's: an answer that does not fit is an
 * error, never a short one. */
#ifndef SLOTHWEB_MCP_HTTP_H
#define SLOTHWEB_MCP_HTTP_H

#include <stddef.h>

#define MCP_HTTP_CONNECT_MS 3000
#define MCP_HTTP_TOTAL_MS   15000
#define MCP_HOST_MAX        48

typedef struct {
    int  family;                 /* AF_INET or AF_INET6 */
    unsigned char addr[16];
    int  port;
    int  loopback;
    char host[MCP_HOST_MAX + 16]; /* the Host header's value: "127.0.0.1:8770", "[::1]:8770" */
} mcp_addr_t;

/* "http://A.B.C.D[:PORT]" or "http://[V6][:PORT]", nothing after but an
 * optional "/"; PORT defaults to slothweb's own, 8770. 0, or -1 with a
 * word of ours in *why: "bad_url" (not that shape, https, a name, a
 * path, userinfo), "not_loopback" (a literal that is not 127.0.0.0/8 or
 * ::1, without allow_remote). */
int mcp_addr_parse(mcp_addr_t *a, const char *url, int allow_remote, const char **why);

/* One exchange: req (len bytes, a whole HTTP request) sent to the
 * address, the answer read to the close into resp (cap bytes, NUL
 * added). 0 with *got; -1 could not connect, -2 timed out or the
 * connection failed, -3 the answer did not fit. The signature the
 * dispatcher calls through, so the tests can answer in process. */
typedef int (*mcp_xfer_fn)(void *ctx, const char *req, size_t len, char *resp, size_t cap,
                           size_t *got);
int mcp_http_xfer(void *ctx /* const mcp_addr_t * */, const char *req, size_t len, char *resp,
                  size_t cap, size_t *got);

/* The answer taken apart: the status, the Retry-After seconds (-1 when
 * none), whether the body is JSON by its Content-Type, and the body
 * (inside resp). 0, or -1 when it is not an HTTP/1.x answer or its
 * Content-Length disagrees with what arrived. */
typedef struct {
    int         status, retry_after, json;
    const char *body;
    size_t      body_len;
} mcp_resp_t;
int mcp_http_parse(const char *resp, size_t len, mcp_resp_t *out);

#endif
