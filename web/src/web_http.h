/* slothweb request classification (#157, W0).
 *
 * W0 has no routes. A request is read only far enough to decide which
 * fixed answer it gets: 404 for any well-formed GET or HEAD, 405 for
 * every other method (forever: slothweb is read-only), 400 for a
 * malformed request line or header, 505 for an HTTP major version other
 * than 1, 431 for a header block that does not fit in WEB_HDR_MAX
 * bytes. A request body is never read. */
#ifndef SLOTHWEB_HTTP_H
#define SLOTHWEB_HTTP_H

#include <stddef.h>

/* The whole header block, request line through the empty line that ends
 * it, must fit in this many bytes. */
#define WEB_HDR_MAX 8192

/* Classify the bytes received so far. Returns 0 when more are needed,
 * otherwise the status to answer with. *is_head is set when the answer
 * must carry no body. len may exceed WEB_HDR_MAX only in tests; the
 * server never buffers more. */
int    web_http_classify(const char *buf, size_t len, int *is_head);

/* Write the fixed response for `status` into out. Returns its length,
 * or 0 if out is too small. */
size_t web_http_response(int status, int is_head, char *out, size_t outsz);

const char *web_http_reason(int status);

#endif
