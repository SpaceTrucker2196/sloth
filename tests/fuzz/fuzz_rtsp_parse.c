#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "rtsp_snoop.h"

/* libFuzzer smoke target for rtsp_parse() and the DESCRIBE pairing in
 * rtsp_snoop_observe() (#106 slice B).
 *
 * The input is one TCP payload from 554/8554: a Request-Line or
 * Status-Line (RFC 2326 §6.1 / §7.1, RFC 7826 §7.1 / §8.1), headers
 * up to the blank line, and whatever follows. Everything in it is the
 * sender's — the URI the path and credential scan walk, the CSeq digits,
 * the header names and the line ends — and a segment can stop anywhere.
 *
 * The same bytes are then observed once as a client request and once as
 * the server's answer on the same connection, so a payload that parses as
 * a DESCRIBE leaves a pending row the next input's response can settle,
 * and the stream table and its eviction see adversarial paths. Addresses
 * are RFC 5737 documentation addresses. */
static sloth_state_t g_s;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;
    rtsp_msg_t m;
    if (rtsp_parse(data, (int)size, &m)) {
        size_t n = strnlen(m.method, sizeof(m.method)) +
                   strnlen(m.path, sizeof(m.path)) +
                   strnlen(m.auth_scheme, sizeof(m.auth_scheme));
        (void)n;
    }
    char info[64];
    rtsp_snoop_observe("192.0.2.10", 51000, "198.51.100.5", 554,
                       data, (int)size, info, sizeof(info));
    rtsp_snoop_observe("198.51.100.5", 554, "192.0.2.10", 51000,
                       data, (int)size, info, sizeof(info));
    rtsp_snoop_snapshot(&g_s);
    for (int i = 0; i < g_s.rtsp_stream_count; i++)
        (void)strnlen(g_s.rtsp_streams[i].path,
                      sizeof(g_s.rtsp_streams[i].path));
    return 0;
}
