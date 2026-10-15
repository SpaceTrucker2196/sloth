#include <stdint.h>
#include <stddef.h>

#include "action_snoop.h"

/* libFuzzer smoke target for action_observe() (#125).
 *
 * The Action-frame path is one of the parsers the 2026-10 architecture
 * review rewrites (one TLV overrun policy across the 802.11 observers),
 * and sanitizer coverage has to exist before the rewrite so the rewrite
 * has something to be held to. action_observe() is the entry the
 * capture path calls, and the one the review keeps as a byte-pointer
 * wrapper, so a harness written against it stays valid across that
 * slice.
 *
 * It takes the whole management frame from FC onward, so the category
 * byte, the Protected bit, the BTM Request's optional fields (B3 BSS
 * Termination Duration, B4 Session Information URL) and the candidate
 * list are all the fuzzer's own bytes. The FC check is a single-byte
 * compare, which libFuzzer's comparison tracing gets past at once —
 * unlike the eight-byte LLC/SNAP wall fuzz_eapol_observe.c had to build
 * a skeleton for — so no skeleton is fixed here.
 *
 * `now` is a fixed sentinel, not time(NULL): the steering table and the
 * BTM rate ring are keyed on it, and a moving clock would make a crash
 * found here depend on when it ran. The tables are module-static and
 * bounded; nothing is written to disk. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;   /* no real 802.11 frame is longer */
    action_observe(data, (int)size, (time_t)1700000000);
    return 0;
}
