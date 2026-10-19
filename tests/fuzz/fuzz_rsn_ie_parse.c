#include <stdint.h>
#include <stddef.h>

#include "rsn_ie.h"

/* libFuzzer smoke target for rsn_ie_parse() (#128).
 *
 * The RSNE carries three sender-chosen counts (Pairwise, AKM, PMKID)
 * in one element, each scaling a list read out of the same bounded
 * body; an overstated count is exactly what the parser must stop on.
 * fuzz_beacon_parse_ies.c reaches this parser too, behind the element
 * walk; this target feeds it a body directly so the fuzzer does not
 * spend its time finding tag 48. The input is the element body after
 * Element ID and Length. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 255) return 0;     /* an element body is at most 255 octets */
    rsn_ie_t r;
    if (rsn_ie_parse(data, (int)size, &r)) {
        /* Touch the borrowed lists so a pointer or count that walked
         * past the input is a sanitizer report, not a silent value. */
        volatile uint8_t sink = 0;
        for (int i = 0; i < r.pairwise_count * 4; i++) sink ^= r.pairwise[i];
        for (int i = 0; i < r.akm_count * 4; i++)      sink ^= r.akm[i];
        for (int i = 0; i < r.pmkid_count * RSN_PMKID_LEN; i++)
            sink ^= r.pmkids[i];
        (void)sink;
    }
    return 0;
}
