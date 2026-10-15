#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dns_log.h"

/* libFuzzer smoke target for DNS name decoding (#125).
 *
 * Named for what it is meant to reach, not for today's entry point.
 * Name decoding — labels, and RFC 1035 4.1.4 compression pointers that
 * may point backward, forward, at themselves or past the message — is
 * the part of a DNS message where an offset the sender chose is
 * followed, and today it is reachable only through dns_log_parse().
 * The 2026-10 review lifts it into its own function (P10a); this target
 * retargets to that function then, and starts here so the rewrite has a
 * sanitizer baseline to keep.
 *
 * The whole message is the fuzzer's, header included: QDCOUNT and
 * ANCOUNT steer how many names are walked, and the QR bit chooses the
 * response path that reads answer records. src_ip is an RFC 5737
 * documentation address, never a real host. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;   /* a DNS message over TCP caps here */
    dns_log_entry_t e;
    if (!dns_log_parse(data, (int)size, "192.0.2.1", &e)) return 0;

    /* Read the string outputs so a missing terminator faults here. */
    size_t n = strnlen(e.qname, sizeof(e.qname)) +
               strnlen(e.qtype, sizeof(e.qtype)) +
               strnlen(e.answer, sizeof(e.answer));
    return (int)(n & 0);
}
