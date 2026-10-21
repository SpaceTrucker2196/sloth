#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "bredr_bb.h"

/* libFuzzer target for the BR/EDR baseband header decoder (#144 slice 3).
 *
 * One DLT 255 record per input, in the fuzzer's redzoned buffer. The
 * contract checked afterwards is the one the wiki states: a LAP of 24
 * bits, a reference UAP only under its flag, an RF channel inside the
 * 79, and a printed form that is the LAP and nothing more. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    bredr_bb_t b;
    if (bredr_bb_parse(data, size, &b) != 0) {
        if (b.lap || b.ref_uap || b.ref_uap_configured) abort();
        return 0;
    }
    if (b.lap > 0xFFFFFFu || b.ref_lap > 0xFFFFFFu) abort();
    if (b.rf_channel >= BREDR_RF_CHANNELS) abort();
    if (!b.ref_uap_configured && b.ref_uap) abort();
    if (b.iac != bredr_lap_is_iac(b.lap)) abort();
    char buf[16];
    bredr_lap_format(b.lap, buf, sizeof(buf));
    if (strlen(buf) != 10 || strchr(buf, ':')) abort();
    return 0;
}
