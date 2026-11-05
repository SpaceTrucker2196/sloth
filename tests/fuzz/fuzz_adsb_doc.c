#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "adsb.h"

/* libFuzzer smoke target for --adsb (#26 slice 1).
 *
 * The bytes are what sits at the path sloth was pointed at: readsb's
 * aircraft.json (README-json.md) or anything else - nested objects in
 * place of fields, strings holding brackets, numbers with exponents,
 * thousands of entries, a truncated tail. adsb_doc_parse() sees the
 * input whole; a document it accepts is fed into the table at two
 * input-chosen times and polled, so the merge, the bands, the expiry
 * and the signature run on whatever the parser let through. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > ADSB_MAX_DOC) return 0;
    static adsb_doc_t d;
    static sloth_state_t s;
    if (adsb_doc_parse((const char *)data, size, &d) != 0) return 0;
    adsb_reset();
    adsb_set_source("file:/fuzz/aircraft.json");
    uint64_t step = size ? (uint64_t)data[0] * 1000u : 0;
    adsb_feed_doc(&d, 1800000000.0, 1800000000, 1000000);
    adsb_feed_doc(&d, 1800000001.0, 1800000001, 1000000 + step);
    adsb_health_poll(&s, 1800000001, 1000000 + step);
    for (int i = 0; s.adsb_rows && i < s.adsb_count; i++)
        (void)adsb_row_sig(&s.adsb_rows[i]);
    adsb_health_poll(&s, 1800000100, 1000000 + step + 120000);
    for (int i = 0; s.adsb_gone && i < s.adsb_gone_count; i++)
        (void)adsb_row_sig(&s.adsb_gone[i]);
    return 0;
}
