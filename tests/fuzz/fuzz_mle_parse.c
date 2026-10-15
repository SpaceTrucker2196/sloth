#include <stdint.h>
#include <stddef.h>

#include "mle.h"

/* libFuzzer smoke target for mle_parse() (#125).
 *
 * The Basic Multi-Link Element (IEEE 802.11be) nests a second TLV
 * chain — Per-STA Profile subelements, each with its own length and its
 * own STA Control presence bits — behind a Common Info block whose
 * length is a byte the sender wrote. That is two levels of
 * attacker-chosen lengths, and the 2026-10 review rewrites both.
 *
 * The input is the element body from the Element ID Extension byte on,
 * which is what mle_parse() takes. The ext ID (107) and the type field
 * are single-byte compares the fuzzer passes immediately, so nothing is
 * fixed. fuzz_assoc_request_parse.c reaches this parser a second way,
 * through a body another parser bounded. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 255) return 0;     /* an element body is at most 255 octets */
    sloth_mld_t mld;
    mle_parse(data, (int)size, &mld);
    return 0;
}
