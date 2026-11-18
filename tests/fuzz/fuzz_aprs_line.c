#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "aprs.h"

/* libFuzzer smoke target for --aprs (2026-11-05).
 *
 * The bytes are what sits in the file sloth was pointed at: Dire Wolf's
 * packet log (src/log.c, 1.7) or anything else - quotes in every place,
 * fields past 22, CR and NUL inside lines, numbers with exponents,
 * overlong lines. The input is cut at '\n' as the reader cuts it, each
 * line parsed and fed into the table at an input-chosen time, then
 * polled twice (the second past the expiry), so the merge, the ring,
 * the cell and the signature run on whatever the parser let through. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static sloth_state_t s;
    aprs_reset();
    aprs_set_source("file:/fuzz/aprs.log");
    uint64_t step = size ? (uint64_t)data[0] * 1000u : 0;
    const char *p = (const char *)data, *e = p + size;
    while (p < e) {
        const char *nl = memchr(p, '\n', (size_t)(e - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(e - p);
        if (n <= APRS_MAX_LINE) {
            aprs_packet_t pk;
            (void)aprs_line_parse(p, n, &pk);
            (void)aprs_feed_line(p, n, 1800000000, 1000000 + step);
        }
        p += n + (nl ? 1 : 0);
    }
    aprs_health_poll(&s, 1800000001, 1000000 + step);
    for (int i = 0; s.aprs_rows && i < s.aprs_count; i++)
        (void)aprs_station_sig(&s.aprs_rows[i]);
    aprs_health_poll(&s, 1800003700, 1000000 + step + (uint64_t)APRS_EXPIRE_S * 1000u);
    for (int i = 0; s.aprs_gone && i < s.aprs_gone_count; i++)
        (void)aprs_station_sig(&s.aprs_gone[i]);
    return 0;
}
