#ifndef RESEARCH_MCP_H
#define RESEARCH_MCP_H

#include <stddef.h>
#include <time.h>

#include "query.h"

/* The MCP dispatcher — issue #73, slice 2.
 *
 * Everything about one JSON-RPC exchange except the pipe. main.c reads
 * a line, calls mcp_handle(), writes the line back; this file decides
 * what the answer is. The split is so the protocol has tests: a
 * dispatcher that only exists inside a read loop can only be tested by
 * spawning a process and talking to it, which is slow, flaky, and
 * catches less.
 *
 * `now` is passed rather than read from the clock so research_recent is
 * testable against a fixed date — the same reason rq_recent takes it. */

/* Advertised to the client in `initialize`. Bumping this is a wire
 * event: it tells clients which spec revision the framing follows. */
#define MCP_PROTOCOL_VERSION "2024-11-05"

#define MCP_OUT_MAX  65536

typedef enum {
    MCP_OK          =  1,   /* a response was written to `out` */
    MCP_NO_RESPONSE =  0,   /* a notification; JSON-RPC forbids a reply */
    MCP_OVERFLOW    = -1    /* the response did not fit; `out` is unusable */
} mcp_result_t;

/* `rq` may be NULL: the tools then report an unavailable corpus rather
 * than failing, which is the same degradation --with-research takes. */
mcp_result_t mcp_handle(rq_handle_t *rq, const char *req, time_t now,
                        char *out, size_t cap);

#endif /* RESEARCH_MCP_H */
