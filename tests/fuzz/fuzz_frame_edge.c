#include <stdint.h>
#include <stddef.h>

#include "capture/frame_edge.h"

/* libFuzzer smoke target for the pcap-edge gate (#141):
 * frame_view_init() and frame_view_radiotap(), which between them
 * decide every length both capture callbacks go on to trust.
 *
 * libpcap-free, so it is a plain target built from the archive, and the
 * bytes the gate reads are the fuzzer's own tightly-redzoned buffer.
 *
 * Two leading bytes are arguments rather than frame:
 *   byte 0  how many octets the wire frame was longer than the capture
 *           (origlen - caplen), with 0xFF meaning "one SHORTER" — the
 *           lying header the gate must refuse. The FCS-strip arithmetic
 *           turns on this difference, so pinning it would leave that
 *           unfuzzed.
 *   byte 1  bit 0 set: ts_usec 1000000 (out of range), else 0.
 *
 * Whatever the gate admits is then read end to end: if it hands out a
 * dot11 pointer or length that runs past the input, ASan reports it
 * here rather than in some parser further down. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > (size_t)FRAME_CAPLEN_MAX + 3) return 0;

    const uint32_t caplen  = (uint32_t)(size - 2);
    const uint32_t origlen = data[0] == 0xFF ? caplen - 1u
                                             : caplen + data[0];
    const long     usec    = (data[1] & 1) ? 1000000L : 0L;

    frame_view_t f;
    if (!frame_view_init(&f, data + 2, caplen, origlen, 1, usec, 127))
        return 0;

    radiotap_info_t rti;
    const uint8_t  *dot11 = NULL;
    int             dlen  = 0;
    if (frame_view_radiotap(&f, &rti, &dot11, &dlen) != FRAME_RT_OK)
        return 0;

    volatile uint8_t sink = 0;
    for (int i = 0; i < dlen; i++) sink ^= dot11[i];
    return (int)(sink & 0);
}
