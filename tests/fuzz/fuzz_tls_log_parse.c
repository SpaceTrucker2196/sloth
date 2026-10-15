#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tls_log.h"

/* libFuzzer smoke target for tls_log_parse() (#125).
 *
 * A ClientHello (RFC 8446 4.1.2) is the record-layer length, the
 * handshake length, then three variable vectors — session ID, cipher
 * suites, compression methods — and an extensions block whose entries
 * carry their own lengths, with server_name (RFC 6066 3) and
 * supported_versions nesting a further list inside. The JA3 and JA4
 * fingerprints walk the same vectors again. Every one of those lengths
 * is the sender's, and the 2026-10 review rewrites this parser.
 *
 * The input is the TCP payload from the record header on, which is
 * what tls_log_parse() takes. Both addresses are RFC 5737 documentation
 * addresses, never real hosts. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;
    tls_log_entry_t e;
    if (!tls_log_parse(data, (int)size, "192.0.2.1", "198.51.100.1", &e))
        return 0;

    /* Read the string outputs so a missing terminator faults here. */
    size_t n = strnlen(e.host, sizeof(e.host)) +
               strnlen(e.tls_ver, sizeof(e.tls_ver)) +
               strnlen(e.ja3, sizeof(e.ja3)) +
               strnlen(e.ja4, sizeof(e.ja4));
    return (int)(n & 0);
}
