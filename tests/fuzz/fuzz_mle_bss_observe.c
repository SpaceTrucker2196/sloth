#include <stdint.h>
#include <stddef.h>

#include "mle.h"
#include "dot11_frame.h"

/* libFuzzer smoke target for mle_bss_observe_frame() (#104 slice 6).
 *
 * The input is a whole 802.11 frame from Frame Control on, decoded the
 * way on_probe_frame() decodes it, so the subtype, the Protected bit,
 * the BSSID, the element list and every Multi-Link element in it —
 * how many, which variant, which presence bits, which Common Info
 * Length — are the fuzzer's bytes. The Beacon/Probe Response FC byte
 * is a single compare libFuzzer gets past at once, so nothing is fixed.
 *
 * Two frames per input from one buffer: the bytes as given, then the
 * same bytes as the other subtype, so the Beacon baseline and the Probe
 * Response comparison both run on attacker-shaped input in one call.
 * `now` is a fixed sentinel, not time(NULL), so a crash found here does
 * not depend on when it ran. The table is module-static and bounded at
 * SLOTH_MLE_BSS_MAX rows. */
static uint8_t g_copy[65536];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > sizeof g_copy) return 0;
    dot11_frame_t f;
    dot11_frame_decode(data, (int)size, NULL, &f);
    mle_bss_observe_frame(&f, (time_t)1700000000);

    if (size >= 1) {
        for (size_t i = 0; i < size; i++) g_copy[i] = data[i];
        /* Swap Beacon (8) and Probe Response (5) in FC octet 0. */
        uint8_t st = (uint8_t)(g_copy[0] >> 4);
        if (st == 8 || st == 5) {
            g_copy[0] = (uint8_t)((g_copy[0] & 0x0f) | ((st == 8 ? 5 : 8) << 4));
            dot11_frame_decode(g_copy, (int)size, NULL, &f);
            mle_bss_observe_frame(&f, (time_t)1700000001);
        }
    }
    return 0;
}
