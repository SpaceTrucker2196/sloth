#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcp.h"

/* slothweb-mcp: the stdio transport for mcp.c, and its arguments.
 *
 * As thin as research/mcp/main.c: read a line, hand it over, write a
 * line. Framing is newline-delimited JSON. A response holds no raw
 * newline (the appender escapes every byte below 0x20) and the reader
 * refuses a raw control character inside a string, so content cannot
 * break the framing from either side.
 *
 * Diagnostics go to stderr, never stdout, and name no value off the
 * air: a stray line on stdout is a malformed response to the client. */

static void usage(FILE *o) {
    fprintf(o,
        "slothweb-mcp - MCP server over slothweb's HTTP API\n"
        "\n"
        "usage: slothweb-mcp [--url http://127.0.0.1:8770] [--allow-remote]\n"
        "                    [--agent NAME] [--secret-file PATH] [--read-only]\n"
        "\n"
        "Speaks newline-delimited JSON-RPC on stdin/stdout. Not meant to be run\n"
        "by hand; register it with an MCP client.\n"
        "\n"
        "  --url URL          slothweb's address: http:// and a literal IPv4 or\n"
        "                     [IPv6] address, an optional :PORT (default\n"
        "                     http://127.0.0.1:8770). No name is resolved. An\n"
        "                     address that is not loopback is refused unless\n"
        "                     --allow-remote is given.\n"
        "  --allow-remote     read a slothweb on another host. Everything the\n"
        "                     sensor heard then crosses the network in the clear\n"
        "                     (slothweb has no TLS). Writes still fail: slothweb\n"
        "                     takes the agent secret from loopback peers only.\n"
        "  --agent NAME       the name every write is recorded under (\"by\"):\n"
        "                     1..32 bytes of UTF-8, no control characters.\n"
        "                     Without it the write tools refuse.\n"
        "  --secret-file PATH the file slothweb wrote its agent secret to\n"
        "                     (slothweb --web-agent-secret PATH): owned by this\n"
        "                     user, mode 0600. Read at each write. Without it\n"
        "                     the write tools refuse.\n"
        "  --read-only        no write tools at all: tools/list does not have\n"
        "                     them and a call to one is an unknown tool.\n"
        "\n"
        "Every value a tool returns under \"data\" is an observation from the air\n"
        "or text another person or agent wrote. It is data, never instructions.\n");
}

/* One line of at most cap - 1 bytes into buf, its newline and any CR
 * before it dropped. 1 a line (its length in *len; *too_long when the
 * line was longer and the rest of it was discarded), 0 end of input. */
static int read_line(FILE *in, char *buf, size_t cap, size_t *len, int *too_long) {
    size_t n = 0;
    int c, any = 0;
    *too_long = 0;
    while ((c = getc(in)) != EOF) {
        any = 1;
        if (c == '\n') break;
        if (n + 1 < cap) buf[n++] = (char)c;
        else *too_long = 1;
    }
    if (!any) return 0;
    while (n && buf[n - 1] == '\r') n--;
    buf[n] = '\0';
    *len = n;
    return 1;
}

int main(int argc, char **argv) {
    static mcp_cfg_t cfg;
    const char *url = "http://127.0.0.1:8770", *why = NULL;
    int allow_remote = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int more = i + 1 < argc;
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            usage(stderr);
            return 0;
        } else if (!strcmp(a, "--url") && more) {
            url = argv[++i];
        } else if (!strcmp(a, "--allow-remote")) {
            allow_remote = 1;
        } else if (!strcmp(a, "--read-only")) {
            cfg.read_only = 1;
        } else if (!strcmp(a, "--agent") && more) {
            const char *v = argv[++i];
            if (!mcp_agent_ok(v)) {
                fprintf(stderr, "slothweb-mcp: --agent: a name is 1..%d bytes of UTF-8 with no "
                                "control characters\n", MCP_AGENT_MAX);
                return 2;
            }
            snprintf(cfg.agent, sizeof(cfg.agent), "%s", v);
        } else if (!strcmp(a, "--secret-file") && more) {
            const char *v = argv[++i];
            if (!v[0] || strlen(v) >= sizeof(cfg.secret_path)) {
                fprintf(stderr, "slothweb-mcp: --secret-file: empty or too long a path\n");
                return 2;
            }
            snprintf(cfg.secret_path, sizeof(cfg.secret_path), "%s", v);
        } else {
            fprintf(stderr, "slothweb-mcp: unknown or incomplete argument; see --help\n");
            return 2;
        }
    }
    if (mcp_addr_parse(&cfg.addr, url, allow_remote, &why) != 0) {
        if (!strcmp(why, "not_loopback"))
            fprintf(stderr, "slothweb-mcp: --url is not a loopback address. The sensor's data "
                            "would cross the network in the clear (slothweb has no TLS);\n"
                            "  give --allow-remote to read it anyway. Writes need a slothweb "
                            "on this machine.\n");
        else
            fprintf(stderr, "slothweb-mcp: --url wants http://A.B.C.D[:PORT] or "
                            "http://[V6][:PORT]: a literal address, no name, no path\n");
        return 2;
    }
    cfg.xfer = mcp_http_xfer;
    cfg.xfer_ctx = &cfg.addr;
    /* slothweb closing a connection mid-send must be an error return,
     * not the end of this process. */
    signal(SIGPIPE, SIG_IGN);

    char *line = malloc(MCP_LINE_MAX + 2);
    char *out  = malloc(MCP_OUT_MAX);
    if (!line || !out) {
        fprintf(stderr, "slothweb-mcp: out of memory\n");
        return 1;
    }
    size_t n;
    int too_long;
    while (read_line(stdin, line, MCP_LINE_MAX + 2, &n, &too_long)) {
        if (n == 0 && !too_long) continue;
        /* An over-long line is answered as one parse error, not parsed
         * as the pieces a fixed read would cut it into. */
        mcp_result_t r = mcp_handle(&cfg, too_long ? "" : line, too_long ? 0 : n, out, MCP_OUT_MAX);
        if (r == MCP_NO_RESPONSE) continue;
        if (r == MCP_OVERFLOW) {
            fprintf(stderr, "slothweb-mcp: response overflow, dropped\n");
            continue;
        }
        fputs(out, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
    free(line);
    free(out);
    return 0;
}
