#include <string.h>

#include "dot11_data.h"

/* LLC/SNAP: DSAP AA, SSAP AA, control 03, then a three-byte
 * organisation code and the two-byte ethertype (RFC 1042). */
#define LLC_SNAP_LEN 8

int dot11_data_header_len(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    int sub     = (dot11[0] >> 4) & 0x0f;
    int to_ds   =  dot11[1]       & 0x01;
    int from_ds = (dot11[1] >> 1) & 0x01;
    int order   = (dot11[1] >> 7) & 0x01;

    int hdr = 24;
    /* Four addresses when the frame crosses two distribution-system
     * hops. Independent of the two below — a QoS WDS frame with HT
     * Control carries all three additions at once. */
    if (to_ds && from_ds) hdr += 6;
    if (sub & 0x08)       hdr += 2;   /* QoS Control */
    if (order)            hdr += 4;   /* HT Control  */
    return len >= hdr ? hdr : -1;
}

int dot11_data_payload(const uint8_t *dot11, int len,
                       int *payload_off, uint16_t *ethertype) {
    if (payload_off) *payload_off = 0;
    if (ethertype)   *ethertype   = 0;
    if (!dot11 || len < 4) return DOT11_DATA_TRUNCATED;

    int type = (dot11[0] >> 2) & 0x03;
    if (type != 2) return DOT11_DATA_NOT_DATA;
    int sub = (dot11[0] >> 4) & 0x0f;

    /* Subtypes with bit 2 set carry no frame body at all — Null,
     * QoS Null and friends exist to move power-management state. */
    if (sub & 0x04) return DOT11_DATA_NO_PAYLOAD;

    /* Protected: the body is ciphertext. Rejected rather than parsed,
     * per MISSION §2 — and distinguished from malformed, because on
     * most networks this is simply the normal case. */
    if (dot11[1] & 0x40) return DOT11_DATA_ENCRYPTED;

    int hdr = dot11_data_header_len(dot11, len);
    if (hdr < 0) return DOT11_DATA_TRUNCATED;

    /* Sequence Control sits at hdr-2 for a non-QoS frame, but is always
     * at offset 22 regardless of the additions before it. Fragment
     * number is the low four bits; anything other than fragment zero is
     * a continuation with no LLC header of its own. */
    if (len >= 24) {
        uint16_t sc = (uint16_t)(dot11[22] | (dot11[23] << 8));
        if ((sc & 0x000f) != 0) return DOT11_DATA_FRAGMENT;
    }
    if (dot11[1] & 0x04) return DOT11_DATA_FRAGMENT;   /* More Fragments */

    /* A-MSDU: the QoS Control field's bit 7 says the body is several
     * aggregated subframes, each with its own header, rather than one
     * LLC-encapsulated packet. Detected and skipped explicitly — a
     * silent misparse here reads as a valid but wrong packet. */
    if (sub & 0x08) {
        int qos_off = 24 + ((( dot11[1] & 0x01) && ((dot11[1] >> 1) & 0x01))
                            ? 6 : 0);
        if (qos_off + 1 < len && (dot11[qos_off] & 0x80))
            return DOT11_DATA_AMSDU;
    }

    if (hdr + LLC_SNAP_LEN > len) return DOT11_DATA_TRUNCATED;
    const uint8_t *llc = dot11 + hdr;
    /* Only SNAP-encapsulated frames carry an ethertype. Bare LLC (IPX,
     * NetBIOS over 802.2) has a protocol identifier in a different
     * place, and reading one as the other invents an ethertype. */
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03)
        return DOT11_DATA_NOT_SNAP;

    if (payload_off) *payload_off = hdr + LLC_SNAP_LEN;
    if (ethertype)   *ethertype   = (uint16_t)((llc[6] << 8) | llc[7]);
    return DOT11_DATA_OK;
}

int dot11_data_addrs(const uint8_t *dot11, int len,
                     uint8_t bssid[6], uint8_t sa[6], uint8_t da[6]) {
    if (!dot11 || len < 24) return 0;
    if (((dot11[0] >> 2) & 0x03) != 2) return 0;

    int to_ds   =  dot11[1]       & 0x01;
    int from_ds = (dot11[1] >> 1) & 0x01;
    const uint8_t *a1 = dot11 + 4, *a2 = dot11 + 10, *a3 = dot11 + 16;

    if (to_ds && from_ds) {
        /* addr4 sits after the header's fixed part; sa is only readable
         * when the frame is long enough to carry it. */
        if (da) memcpy(da, a3, 6);
        if (sa) {
            if (len < 30) return 0;
            memcpy(sa, dot11 + 24, 6);
        }
        return DOT11_ADDRS_NO_BSSID;
    }
    if (from_ds) {                       /* AP -> STA */
        if (da)    memcpy(da,    a1, 6);
        if (bssid) memcpy(bssid, a2, 6);
        if (sa)    memcpy(sa,    a3, 6);
    } else if (to_ds) {                  /* STA -> AP */
        if (bssid) memcpy(bssid, a1, 6);
        if (sa)    memcpy(sa,    a2, 6);
        if (da)    memcpy(da,    a3, 6);
    } else {                             /* IBSS */
        if (da)    memcpy(da,    a1, 6);
        if (sa)    memcpy(sa,    a2, 6);
        if (bssid) memcpy(bssid, a3, 6);
    }
    return 1;
}

int dot11_is_group_addr(const uint8_t addr[6]) {
    return addr ? (addr[0] & 0x01) : 0;
}

int dot11_frag_num(const uint8_t *dot11, int len) {
    if (!dot11 || len < 24) return -1;
    return dot11[22] & 0x0f;
}

int dot11_more_frags(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    return (dot11[1] >> 2) & 0x01;
}

int dot11_data_tid(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    int type = (dot11[0] >> 2) & 0x03;
    if (type != 2) return -1;

    int sub = (dot11[0] >> 4) & 0x0f;
    if (!(sub & 0x08)) return 0;      /* non-QoS: implicit single queue */

    int to_ds   =  dot11[1]       & 0x01;
    int from_ds = (dot11[1] >> 1) & 0x01;
    int qos_off = 24 + ((to_ds && from_ds) ? 6 : 0);
    if (qos_off >= len) return -1;
    return dot11[qos_off] & 0x0f;
}

int dot11_amsdu_present(const uint8_t *dot11, int len) {
    if (!dot11 || len < 2) return -1;
    if (((dot11[0] >> 2) & 0x03) != 2) return -1;
    int sub = (dot11[0] >> 4) & 0x0f;
    if (!(sub & 0x08)) return -1;          /* no QoS Control field */

    int to_ds   =  dot11[1]       & 0x01;
    int from_ds = (dot11[1] >> 1) & 0x01;
    int qos_off = 24 + ((to_ds && from_ds) ? 6 : 0);
    if (qos_off >= len) return -1;
    return (dot11[qos_off] >> 7) & 0x01;
}

int64_t dot11_ccmp_pn(const uint8_t *dot11, int len) {
    if (!dot11 || len < 24) return -1;
    if (((dot11[0] >> 2) & 0x03) != 2) return -1;
    if (!(dot11[1] & 0x40)) return -1;               /* not protected */

    int hdr = dot11_data_header_len(dot11, len);
    if (hdr < 0 || hdr + 8 > len) return -1;
    const uint8_t *iv = dot11 + hdr;

    /* Without the Extended IV bit these eight bytes are a WEP IV or an
     * original-TKIP one, neither of which carries a 48-bit PN. Reading
     * them anyway would invent a number that looks like evidence. */
    if (!(iv[3] & 0x20)) return -1;

    return (int64_t)((uint64_t)iv[0]              |
                     ((uint64_t)iv[1] <<  8)      |
                     ((uint64_t)iv[4] << 16)      |
                     ((uint64_t)iv[5] << 24)      |
                     ((uint64_t)iv[6] << 32)      |
                     ((uint64_t)iv[7] << 40));
}
