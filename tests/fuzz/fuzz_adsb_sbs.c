#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "adsb.h"

/* libFuzzer smoke target for --adsb sbs:// (2026-11-09).
 *
 * The bytes are what the decoder's SBS port sends: readsb's CSV lines
 * or anything else - too few or too many fields, numbers with
 * exponents and 'H' suffixes, dates out of range, CR and NUL inside
 * lines, lines past ADSB_SBS_MAX_LINE. The input goes through the
 * reader's framer in two reads split at an input-chosen point, so a
 * line cut across reads is exercised; every line is parsed and fed
 * into the table, which is then polled twice (the second past the
 * expiry), so the merge, the bands, the cell and the signature run on
 * whatever the parser let through. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static sloth_state_t s;
    static adsb_sbs_lines_t l;
    adsb_reset();
    adsb_set_source_sbs("sbs:127.0.0.1:30003");
    adsb_sbs_lines_init(&l);
    size_t cut = size ? (size_t)data[0] % (size + 1) : 0;
    adsb_sbs_lines_feed(&l, data, cut, 1800000000000LL, 1000000);
    adsb_sbs_lines_feed(&l, data + cut, size - cut, 1800000000500LL, 1000500);
    adsb_health_poll(&s, 1800000001, 1001000);
    for (int i = 0; s.adsb_rows && i < s.adsb_count; i++)
        (void)adsb_row_sig(&s.adsb_rows[i]);
    adsb_health_poll(&s, 1800000100, 1001000 + (uint64_t)ADSB_EXPIRE_S * 1000u);
    for (int i = 0; s.adsb_gone && i < s.adsb_gone_count; i++)
        (void)adsb_row_sig(&s.adsb_gone[i]);
    return 0;
}
