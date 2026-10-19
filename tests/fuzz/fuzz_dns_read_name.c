#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dns_log.h"
#include "dns_wire.h"

/* libFuzzer smoke target for DNS name decoding (#125, retargeted #131).
 *
 * Name decoding — labels, and RFC 1035 4.1.4 compression pointers that
 * may point backward, forward, at themselves or past the message — is
 * the part of a DNS message where an offset the sender chose is
 * followed. #131 lifted it into dns_read_name() / dns_skip_name(), and
 * this target now drives them directly: from a start offset the first
 * input octet chooses, then from each name end the skip walk
 * reaches, so a name in the middle of a message is reached without the
 * header having to describe it. dns_log_parse() stays as the second
 * entry so the counts-steered caller keeps its sanitizer baseline.
 *
 * src_ip is an RFC 5737 documentation address, never a real host. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;   /* a DNS message over TCP caps here */
    int len = (int)size;
    size_t n = 0;

    if (len >= 1) {
        const uint8_t *msg = data + 1;
        int mlen = len - 1;
        int off  = mlen > 0 ? data[0] % mlen : 0;
        char name[256];
        for (int i = 0; i < 16 && off >= 0 && off < mlen; i++) {
            int r = dns_read_name(msg, mlen, off, name, (int)sizeof name);
            n += strnlen(name, sizeof name);
            int s = dns_skip_name(msg, mlen, off);
            /* The two walkers must agree on where a name ends whenever
             * the reader accepts it: they share one framing rule. */
            if (r >= 0 && s != r) abort();
            off = s;
        }
    }

    dns_log_entry_t e;
    if (dns_log_parse(data, len, "192.0.2.1", &e)) {
        /* Read the string outputs so a missing terminator faults here. */
        n += strnlen(e.qname, sizeof(e.qname)) +
             strnlen(e.qtype, sizeof(e.qtype)) +
             strnlen(e.answer, sizeof(e.answer));
    }
    return (int)(n & 0);
}
