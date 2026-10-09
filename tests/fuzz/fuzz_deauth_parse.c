#include <stdint.h>
#include <stddef.h>

#include "deauth_snoop.h"

/* libFuzzer smoke target for deauth_parse() (#95).
 *
 * deauth_parse() is a pure byte parser: no global state, no mutex, no
 * side effect on the module's observation tables. It calls deauth_parse()
 * directly rather than going through deauth_record()/deauth_snapshot(),
 * which would need the shared tables and clock wired up for no benefit
 * to what is actually being fuzzed here.
 *
 * Smoke, not a campaign: this repo keeps no fuzz corpus and does no
 * crash-triage infrastructure. `make fuzz` runs this for a bounded time
 * so CI gets a memory-safety check the hand-built byte tests in
 * tests/test_deauth_snoop.c did not think to try, without taking on a
 * second test suite to maintain. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;   /* no real 802.11 frame is longer */
    deauth_frame_t out;
    deauth_parse(data, (int)size, &out);
    return 0;
}
