#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mcp.h"
#include "query.h"

/* sloth-research-mcp — the stdio transport for the #73 query layer.
 *
 * Deliberately thin. Everything that decides anything lives in mcp.c
 * where the tests reach it; this file owns exactly the pipe: read a
 * line, hand it over, write a line.
 *
 * Framing is newline-delimited JSON, which is what MCP stdio servers
 * speak. Responses therefore must not contain a raw newline — json.c's
 * escaper turns every one into \n, and its parser rejects raw control
 * characters in strings, so the framing cannot be broken from either
 * side by content.
 *
 * Diagnostics go to stderr, never stdout. A stray printf on stdout is
 * indistinguishable from a malformed response to the client. */

#define LINE_MAX_BYTES 65536

int main(int argc, char **argv) {
    const char *db = "research.db";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            fprintf(stderr,
                "sloth-research-mcp — MCP server over sloth's research corpus\n"
                "\n"
                "usage: sloth-research-mcp [--db PATH]\n"
                "\n"
                "Speaks newline-delimited JSON-RPC on stdin/stdout. Not meant\n"
                "to be run by hand; register it with an MCP client.\n"
                "\n"
                "  --db PATH   corpus to serve (default: research.db)\n"
                "\n"
                "Build the corpus with `make research-index`.\n");
            return 0;
        } else {
            fprintf(stderr, "sloth-research-mcp: unknown argument %s\n", argv[i]);
            return 2;
        }
    }

    /* A missing corpus is not fatal. The server still answers
     * initialize and tools/list, and every tool call reports why it has
     * nothing — a client that cannot start its server sees a connection
     * failure, which says far less than "the corpus is not built". */
    rq_handle_t *rq = rq_open(db);
    if (!rq)
        fprintf(stderr, "sloth-research-mcp: %s — serving with no corpus\n",
                rq_open_error());

    char *line = malloc(LINE_MAX_BYTES);
    char *out  = malloc(MCP_OUT_MAX);
    if (!line || !out) {
        fprintf(stderr, "sloth-research-mcp: out of memory\n");
        return 1;
    }

    while (fgets(line, LINE_MAX_BYTES, stdin)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;

        mcp_result_t r = mcp_handle(rq, line, time(NULL), out, MCP_OUT_MAX);
        if (r == MCP_NO_RESPONSE) continue;
        if (r == MCP_OVERFLOW) {
            /* mcp_handle already refuses over-large tool results with a
             * proper error; reaching here means the error itself did
             * not fit, which cannot happen with MCP_OUT_MAX. Say so
             * rather than emitting half a message. */
            fprintf(stderr, "sloth-research-mcp: response overflow, dropped\n");
            continue;
        }
        fputs(out, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }

    free(line);
    free(out);
    rq_close(rq);
    return 0;
}
