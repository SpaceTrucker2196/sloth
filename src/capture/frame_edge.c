/* Pcap-edge input gate. Contract in frame_edge.h (#141). */

#include <string.h>

#include "capture/frame_edge.h"
#include "dot11_frame.h"   /* dot11_fcs_strip_len() */

int frame_view_init(frame_view_t *f, const uint8_t *data,
                    uint32_t caplen, uint32_t origlen,
                    long ts_sec, long ts_usec, int dlt) {
    if (!f) return 0;
    memset(f, 0, sizeof(*f));
    if (!data)                     return 0;
    if (caplen == 0)               return 0;
    if (caplen > FRAME_CAPLEN_MAX) return 0;
    /* caplen is what was copied off the wire, origlen what was on it.
     * More copied than existed is a header lying about one of the two,
     * and the FCS-strip decision compares them. */
    if (caplen > origlen)          return 0;
    if (ts_usec < 0 || ts_usec >= 1000000L) return 0;
    /* ts_sec is deliberately not judged: an offline replay carries
     * clocks far from this host's, and "looks wrong" is not decidable
     * here. probe.c counts ts <= 0 as a bad clock without dropping the
     * frame (#92); that policy stays where it is. */
    f->data    = data;
    f->caplen  = (int)caplen;
    f->origlen = origlen;
    f->ts_sec  = (time_t)ts_sec;
    f->ts_usec = (uint32_t)ts_usec;
    f->dlt     = dlt;
    return 1;
}

frame_rt_verdict_t frame_view_radiotap(const frame_view_t *f,
                                       radiotap_info_t *rti,
                                       const uint8_t **dot11,
                                       int *dot11_len) {
    if (dot11)     *dot11     = NULL;
    if (dot11_len) *dot11_len = 0;
    if (!rti) return FRAME_RT_BAD;
    if (!f || !f->data) {
        radiotap_parse(NULL, 0, rti);   /* defaults, per the contract */
        return FRAME_RT_BAD;
    }

    /* The parser's verdict and its hdr_len, and nothing else: it refuses
     * it_len < 8 and it_len > caplen, and restating those bounds here
     * would be the second copy of the rule this gate exists to remove.
     * it_len == caplen is a valid header with no frame behind it — a
     * runt below, not a bad header. */
    if (!radiotap_parse(f->data, f->caplen, rti)) return FRAME_RT_BAD;
    const int rt = rti->hdr_len;

    int len = f->caplen - rt;
    /* origlen is clamped before it meets int arithmetic: four or more
     * past caplen means the whole trailer was cut off, which is all
     * dot11_fcs_strip_len() needs to know. frame_view_init() guarantees
     * origlen >= caplen, so the subtraction cannot wrap. */
    const uint32_t short_by = f->origlen - (uint32_t)f->caplen;
    const int ol = short_by >= 4 ? f->caplen + 4
                                 : f->caplen + (int)short_by;
    int strip = dot11_fcs_strip_len(f->caplen, ol, rti->fcs_present);
    if (strip > len) strip = len;
    len -= strip;
    if (len < FRAME_DOT11_MIN) return FRAME_RT_RUNT;

    if (dot11)     *dot11     = f->data + rt;
    if (dot11_len) *dot11_len = len;
    return FRAME_RT_OK;
}
