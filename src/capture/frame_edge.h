/* Pcap-edge input gate (#141).
 *
 * The one place a libpcap record header becomes something the decoders
 * may trust. Both capture callbacks — on_packet() in capture.c and
 * on_probe_frame() in probe.c — used to cast hdr->caplen to int
 * unchecked and read hdr->len and hdr->ts as given. That was safe only
 * because libpcap caps a record at 262144 bytes and the kernel does
 * not lie about lengths: an assumption about the producer, not a check
 * at the boundary (CWE-1284). A savefile replayed through the same
 * callbacks, or a future libpcap, is bound by neither.
 *
 * frame_view_init() is that check. frame_view_radiotap() is the second
 * half for the monitor DLT: the radiotap header, the FCS trailer and
 * the 802.11 minimum, decided once for both callbacks instead of once
 * per callback with two slightly different definitions of "valid".
 *
 * libpcap-free on purpose, so sloth_test and the fuzz harness link it
 * without WITH_PCAP and it is tested from hand-built bytes. */

#ifndef SLOTH_FRAME_EDGE_H
#define SLOTH_FRAME_EDGE_H

#include <stdint.h>
#include <time.h>

#include "radiotap.h"

/* Our snaplen: capture.c and probe.c both open with 65535. A record
 * claiming more was not produced by either handle. */
#define FRAME_CAPLEN_MAX 65535

/* The minimum 802.11 framing anything downstream reads: Frame Control
 * (2) + Duration (2) + Address 1 (6). ACK and CTS are exactly this. */
#define FRAME_DOT11_MIN 10

typedef struct {
    const uint8_t *data;
    int            caplen;   /* 1 .. FRAME_CAPLEN_MAX, never > origlen */
    uint32_t       origlen;  /* wire length */
    time_t         ts_sec;   /* as captured; NOT judged here (see .c) */
    uint32_t       ts_usec;  /* 0 .. 999999 */
    int            dlt;
} frame_view_t;

/* 1 = admitted and *f filled; 0 = reject, *f zeroed. Rejects: NULL f or
 * data, caplen 0, caplen > FRAME_CAPLEN_MAX, caplen > origlen (a header
 * that says more was captured than was on the wire), ts_usec outside
 * 0 .. 999999. */
int frame_view_init(frame_view_t *f, const uint8_t *data,
                    uint32_t caplen, uint32_t origlen,
                    long ts_sec, long ts_usec, int dlt);

/* Verdicts of frame_view_radiotap(). Only FRAME_RT_OK admits; the two
 * refusals are kept apart because the monitor stream publishes them as
 * different parse-fault kinds (radiotap_bad, dot11_runt). */
typedef enum {
    FRAME_RT_BAD  = 0,   /* radiotap_parse() refused the header */
    FRAME_RT_OK   = 1,
    FRAME_RT_RUNT = 2    /* header fine, < FRAME_DOT11_MIN of 802.11 after it */
} frame_rt_verdict_t;

/* The shared radiotap gate. Uses radiotap_parse()'s verdict and its
 * hdr_len — never a second read of it_len — so a header the parser
 * refuses (it_len < 8, it_len > caplen, a truncated present chain) is
 * refused here for both callbacks. On FRAME_RT_OK *dot11 points just
 * past the radiotap header and *dot11_len excludes any FCS trailer the
 * radiotap FLAGS declared (computed against origlen, so a snapped
 * capture that lost part of the trailer strips only what it holds), and
 * is at least FRAME_DOT11_MIN. `rti` is always filled by
 * radiotap_parse(), so a refused frame still has defaults, not garbage.
 * *dot11 / *dot11_len are NULL / 0 on any refusal. */
frame_rt_verdict_t frame_view_radiotap(const frame_view_t *f,
                                       radiotap_info_t *rti,
                                       const uint8_t **dot11,
                                       int *dot11_len);

#endif /* SLOTH_FRAME_EDGE_H */
