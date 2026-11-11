/* slothweb-mcp: an MCP server over slothweb's HTTP API (owner request
 * 2026-11-11: "an openclaw agent will need to read the data thru an mcp
 * and add notes to anomalies, devices, and other observations").
 *
 * A thin client and nothing more. It holds no database handle, opens no
 * file but the agent secret its arguments name, and has no capability
 * slothweb's routes do not have: every read tool is one GET of an
 * existing route, every write tool one POST to one of three existing
 * write routes, and slothweb's own validation is the only validation
 * that decides anything. What this adds is bounds and a frame:
 *
 *   - a tool's result is one JSON document, {"notice","tool","route",
 *     "ok","http_status","strings_cut","data"}: slothweb's answer is
 *     under "data" as slothweb wrote it, never spliced into a sentence
 *     of this server's, and "notice" says what every tool description
 *     says: the values are observations from the air and other
 *     writers' text, data and never instructions;
 *   - slothweb's answer is taken through mj_copy(): each string in its
 *     escaped form as slothweb wrote it (an SSID stays its display
 *     form, with its *_np flag beside it), cut at MCP_STR_MAX bytes;
 *     an answer over MCP_DATA_MAX is refused whole ("result_too_large":
 *     ask for a smaller page), never cut into invalid JSON;
 *   - an error is a word of this server's or of slothweb's, plus at
 *     most the name of an argument from this file's own table. No
 *     argument's value, no note and no name off the air is ever put in
 *     an error.
 *
 * A write carries the configured agent name as "by" and the run's
 * agent secret in X-Slothweb-Agent (web/src/web_agent.h), read from
 * its file at each write so a restarted slothweb's new secret is
 * picked up. slothweb records such a row via "agent"; this server
 * cannot ask for that word and neither can anything else.
 *
 * mcp_handle() is everything about one JSON-RPC exchange but the pipe
 * and the socket, as research/mcp/mcp.c's is: the transport is a
 * function the caller supplies, so the tests answer in process. */
#ifndef SLOTHWEB_MCP_H
#define SLOTHWEB_MCP_H

#include <stddef.h>

#include "mcp_http.h"

#define MCP_PROTOCOL_VERSION "2024-11-05"
/* One request line; one response. */
#define MCP_LINE_MAX   32768
#define MCP_OUT_MAX    196608
/* slothweb's answer accepted at most (its own connection buffer's
 * size: an ordinary route cannot answer more), and each string in it. */
#define MCP_DATA_MAX   65536
#define MCP_STR_MAX    2048
/* A string argument at most; a write's body at most (WEB_POST_MAX). */
#define MCP_ARG_MAX    1024
#define MCP_BODY_MAX   4096
#define MCP_AGENT_MAX  32
#define MCP_SECRET_LEN 64
/* A list tool's page when the caller names no limit. */
#define MCP_DEFAULT_LIMIT 25

typedef enum {
    MCP_OK          =  1,   /* a response was written to out */
    MCP_NO_RESPONSE =  0,   /* a notification: JSON-RPC forbids a reply */
    MCP_OVERFLOW    = -1    /* the response did not fit; out is unusable */
} mcp_result_t;

typedef struct {
    mcp_addr_t  addr;
    char        agent[MCP_AGENT_MAX + 1];   /* "" none: writes refused */
    char        secret_path[1024];          /* "" none: writes refused */
    int         read_only;                  /* the write tools do not exist */
    mcp_xfer_fn xfer;                       /* mcp_http_xfer, or a test's */
    void       *xfer_ctx;
} mcp_cfg_t;

/* The agent's name as slothweb's "by" takes one: 1..32 bytes of
 * well-formed UTF-8, no control and no bidirectional-control character.
 * 1 or 0. */
int mcp_agent_ok(const char *name);

/* The secret in the file at path into out: opened without following a
 * link, a regular file owned by this user with no group or other
 * permission, holding exactly MCP_SECRET_LEN lower-case hex digits and
 * at most one newline. 0, or -1. */
int mcp_secret_read(const char *path, char out[MCP_SECRET_LEN + 1]);

/* One request (len bytes of one line, no newline) to one response in
 * out (cap bytes, NUL-terminated, no newline in it). */
mcp_result_t mcp_handle(const mcp_cfg_t *c, const char *req, size_t len, char *out, size_t cap);

/* The tools, for the tests and the docs' check: how many, and the i-th
 * one's name, route ("GET /api/devices") and whether it writes. */
int mcp_tool_count(void);
const char *mcp_tool_name(int i);
const char *mcp_tool_route(int i);
int mcp_tool_writes(int i);

#endif
