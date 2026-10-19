#include <string.h>

#include "dot11_data.h"
#include "dot11_frame.h"

/* Byte-pointer wrappers over the one-decode view (#122).
 *
 * Until #122 this file held its own copy of the MAC-header formula; the
 * fuzz targets, the tests and a dozen observers depend on these entry
 * points, so the signatures stay and the arithmetic moves to
 * dot11_frame.c. Nothing below reads a header offset directly: every
 * answer comes out of a dot11_frame_t, so the s9.2.4.1.10 rule, the
 * Address 4 shift and the QoS Control position each exist once.
 *
 * None of these take radiotap hints, because none of their callers
 * hold a radiotap header: body offsets here are the plain header
 * length, never datapad-rounded. */

int dot11_data_header_len(const uint8_t *dot11, int len) {
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    /* The data-frame header. Every caller has already selected type 2;
     * a frame that is not one has no data header to report. */
    if (!dot11 || f.type != 2) return -1;
    return f.hdr_len;
}

/* See dot11_data.h for why this is a shared function rather than the
 * expression three of the four management parsers were missing. */
int dot11_mgmt_hdr_len(const uint8_t *dot11, int len) {
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    if (!dot11 || f.type != 0) return -1;
    return f.hdr_len;
}

int dot11_data_payload(const uint8_t *dot11, int len,
                       int *payload_off, uint16_t *ethertype) {
    if (payload_off) *payload_off = 0;
    if (ethertype)   *ethertype   = 0;
    if (!dot11 || len < 4) return DOT11_DATA_TRUNCATED;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return dot11_frame_payload(&f, payload_off, ethertype);
}

int dot11_data_addrs(const uint8_t *dot11, int len,
                     uint8_t bssid[6], uint8_t sa[6], uint8_t da[6]) {
    if (!dot11 || len < 24) return 0;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    if (f.type != 2) return 0;

    if (f.has_addr4) {
        /* Address 4 sits after the fixed part; sa is only readable when
         * the frame is long enough to carry it. */
        if (da) memcpy(da, f.da, 6);
        if (sa) {
            if (!f.sa) return 0;
            memcpy(sa, f.sa, 6);
        }
        return DOT11_ADDRS_NO_BSSID;
    }
    if (bssid) memcpy(bssid, f.bssid, 6);
    if (sa)    memcpy(sa,    f.sa,    6);
    if (da)    memcpy(da,    f.da,    6);
    return 1;
}

int dot11_is_group_addr(const uint8_t addr[6]) {
    return addr ? (addr[0] & 0x01) : 0;
}

int dot11_frag_num(const uint8_t *dot11, int len) {
    if (!dot11 || len < 24) return -1;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return f.frag_num;
}

/* A retransmission of one MSDU carries the SAME sequence number, which
 * is what makes this the right key for "have I already counted this
 * frame" — see src/queue_evict.c. */
int dot11_seq_num(const uint8_t *dot11, int len) {
    if (!dot11 || len < 24) return -1;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return f.seq_num;
}

int dot11_more_frags(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return f.more_frag;
}

int dot11_data_tid(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return dot11_frame_tid(&f);
}

int dot11_amsdu_present(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return dot11_frame_amsdu(&f);
}

int64_t dot11_ccmp_pn(const uint8_t *dot11, int len) {
    if (!dot11 || len < 24) return -1;
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return dot11_frame_ccmp_pn(&f);
}
