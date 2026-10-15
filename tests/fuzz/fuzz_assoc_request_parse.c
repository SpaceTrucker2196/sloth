#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "assoc_track.h"
#include "mle.h"

/* libFuzzer smoke target for assoc_request_parse() (#125).
 *
 * An (re)association request is the client's own statement of what it
 * wants — SSID, rates, RSN AKM and cipher suites, MFP bits, the
 * Multi-Link Element — and every one of those is a TLV whose length the
 * sender chose. The 2026-10 review rewrites this walk; fuzzing it first
 * gives the rewrite a sanitizer baseline.
 *
 * The whole frame from FC onward is the fuzzer's: subtype 0 vs 2 is a
 * one-byte compare and decides the fixed-field length, which is exactly
 * the arithmetic worth fuzzing, so it is not pinned.
 *
 * On a successful parse, req.mle_body points into this same input and
 * is handed straight to mle_parse(). That is the composition the
 * capture path performs, and it is the case a standalone mle_parse()
 * target cannot reach: a body whose bounds one parser computed and
 * another then trusted. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;   /* no real 802.11 frame is longer */

    assoc_req_t req;
    if (!assoc_request_parse(data, (int)size, &req)) return 0;

    /* Read the string outputs so a missing terminator faults here. */
    size_t n = strnlen(req.requested_ssid, sizeof(req.requested_ssid)) +
               strnlen(req.phy, sizeof(req.phy));

    if (req.mle_body && req.mle_len > 0) {
        sloth_mld_t mld;
        mle_parse(req.mle_body, req.mle_len, &mld);
    }
    return (int)(n & 0);
}
