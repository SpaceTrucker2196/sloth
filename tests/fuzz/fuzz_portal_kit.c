#include <stdint.h>
#include <stddef.h>

#include "captive_portal.h"

/* libFuzzer smoke target for cp_match_kit() (#169).
 *
 * cp_match_kit() reads one HTTP response segment straight off the wire
 * — status line, header lines, body prefix — and walks it with its own
 * line splitter and substring search, so it is a parser of remote bytes
 * like any other. It is pure: no global state, no lock, nothing
 * recorded, so the bytes are the whole harness. The fuzzer's tightly
 * redzoned input buffer is what catches a read past `len`.
 *
 * Smoke, not a campaign: see fuzz_deauth_parse.c. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;   /* larger than any one TCP segment */
    const char *label = NULL;
    (void)cp_match_kit(data, (int)size, &label);
    return 0;
}
