#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "adsb.h"
#include "adsb_beast.h"

/* libFuzzer smoke target for --adsb beast:// (2026-11-09).
 *
 * The bytes are what the decoder's Beast port sends: 0x1A-framed Mode
 * A/C and Mode S frames with doubled 0x1A, or anything else - unknown
 * types, lone 0x1A inside a frame, receiver-id and Radarcape frames cut
 * anywhere, garbage. The input goes through the framer in three reads
 * split at input-chosen points (frames cut across reads), each read a
 * second later on the monotonic clock so CPR pairs, local references
 * and address confirmations age; every frame the framer passes is
 * decoded (CRC, DF11/17/18, the address/parity replies, CPR) and fed
 * into the table, which is then polled twice (the second past the
 * expiry), so the merge, the bands, the cell and the signature run on
 * whatever the decoder let through. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static sloth_state_t s;
    static adsb_beast_t b;
    adsb_reset();
    adsb_set_source_sbs("beast:127.0.0.1:30005");
    adsb_beast_init(&b);
    size_t c1 = size ? (size_t)data[0] % (size + 1) : 0;
    size_t c2 = size > 1 ? c1 + (size_t)data[1] % (size - c1 + 1) : c1;
    adsb_beast_feed(&b, data, c1, 1800000000000LL, 1000000);
    adsb_beast_feed(&b, data + c1, c2 - c1, 1800000001000LL, 1001000);
    adsb_beast_feed(&b, data + c2, size - c2, 1800000002000LL, 1002000);
    adsb_health_poll(&s, 1800000002, 1002000);
    for (int i = 0; s.adsb_rows && i < s.adsb_count; i++)
        (void)adsb_row_sig(&s.adsb_rows[i]);
    adsb_health_poll(&s, 1800000100, 1002000 + (uint64_t)ADSB_EXPIRE_S * 1000u);
    for (int i = 0; s.adsb_gone && i < s.adsb_gone_count; i++)
        (void)adsb_row_sig(&s.adsb_gone[i]);
    return 0;
}
