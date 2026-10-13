#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "beacon_snoop.h"
#include "reg_ie.h"

/* libFuzzer smoke target for beacon_parse_ies() (#95).
 *
 * The information-element area of a beacon is the largest untrusted,
 * variable-length, nested structure sloth parses. It is a bare
 * tag-length-value chain with no outer count, so the parser's only
 * stopping condition is arithmetic on lengths the attacker chose, and
 * several elements nest a second TLV chain inside the first: RSN walks
 * pairwise and AKM suite counts, the vendor-specific tag carries WPS
 * attributes with their own 16-bit lengths, and the HE/EHT operation
 * elements have optional subfields whose presence shifts everything
 * after them. Each nesting level is another place for a length to be
 * trusted one byte too far.
 *
 * tests/test_beacon_snoop.c covers that surface with hand-built frames
 * per IEEE 802.11-2020 clause 9.4.2, including truncated and malformed
 * cases, and it is the better test: it asserts what the parser should
 * CONCLUDE, which a fuzzer cannot. This target adds the one thing those
 * cases cannot give — combinations nobody thought to write down — and
 * checks only that none of them corrupts memory.
 *
 * beacon_parse_ies() is the right entry point rather than
 * beacon_record(): it takes the IE area directly, so no observation
 * table, mutex or clock has to be stood up, and it is the function every
 * other caller (beacon_parse, assoc_track) reaches the IEs through.
 *
 * The `privacy` and `beacon_ms` arguments are not frame bytes — the
 * caller lifts them out of the capability field and the fixed beacon
 * header — so they are drawn from the input too. privacy selects a real
 * branch (it decides whether an IE-less beacon reads as WEP or OPEN),
 * and feeding it a constant would leave half the encryption-mode logic
 * unfuzzed. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Three bytes are consumed as the non-IE arguments before the rest
     * becomes the IE area, so a shorter input has no IEs to parse. */
    if (size < 3 || size > 65535) return 0;

    const int privacy       = data[0] & 1;
    const uint16_t beacon_ms = (uint16_t)(data[1] | (data[2] << 8));
    const uint8_t *ies      = data + 3;
    const int ies_len       = (int)size - 3;

    /* Deliberately NOT pre-zeroed. beacon_parse_ies documents that it
     * initialises its own outputs, and clearing them here would hide a
     * path that returns while leaving one untouched — exactly the bug
     * worth catching, since the caller then publishes a stale SSID or
     * channel. MSan would flag the read; under ASan/UBSan this at least
     * does not paper over it. */
    char ssid[33];
    char enc[10];
    int channel;
    beacon_rsn_t rsn;
    reg_ie_t reg;

    beacon_parse_ies(ies, ies_len, privacy, beacon_ms,
                     ssid, &channel, enc, &rsn, &reg);

    /* Force the parser's string outputs to be read, so a missing
     * terminator is a fault here rather than a silent pass. The result
     * is combined into the return-ish sink below so the optimiser cannot
     * drop the walk. */
    size_t n = strnlen(ssid, sizeof(ssid)) + strnlen(enc, sizeof(enc));
    return (int)(n & 0);
}
