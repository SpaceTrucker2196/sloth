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
