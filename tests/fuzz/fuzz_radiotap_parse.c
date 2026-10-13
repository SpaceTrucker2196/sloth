#include <stdint.h>
#include <stddef.h>

#include "radiotap.h"

/* libFuzzer smoke target for radiotap_parse() (#95).
 *
 * Why this parser is worth a fuzzer even though tests/test_radiotap.c
 * already builds headers by hand: radiotap is the one header in the
 * capture path whose length and field layout are BOTH attacker-supplied
 * and self-describing. it_len says how far the header reaches,
 * it_present is a chain of bitmaps each of which can set the
 * "another word follows" bit, and every present bit shifts the offset of
 * every field after it — including alignment padding that depends on
 * the field's own width. That is a walk over a buffer whose stride is
 * computed from the buffer's own contents, which is the exact shape that
 * defeats hand-written cases: a test author picks present-bit
 * combinations that make sense for a real radio, and the overread lives
 * in the combinations that do not.
 *
 * It is a pure parser — no global state, no lock, no clock — so the
 * harness takes the bytes directly and nothing has to be wired up.
 *
 * Smoke, not a campaign, for the reasons in fuzz_deauth_parse.c: no
 * corpus is kept and no triage infrastructure exists. `make fuzz` runs
 * it for a bounded time so a memory-safety regression here fails CI. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* The capture path hands radiotap_parse() a frame, and no frame is
     * longer than this; feeding more would only fuzz input the parser
     * can never receive. */
    if (size > 65535) return 0;
    radiotap_info_t out;
    radiotap_parse(data, (int)size, &out);
    return 0;
}
