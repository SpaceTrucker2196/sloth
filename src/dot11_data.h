#ifndef DOT11_DATA_H
#define DOT11_DATA_H

#include <stdint.h>

/* 802.11 data-frame payload location — issue #72.
 *
 * On the monitor path sloth handled type-2 frames for exactly one
 * purpose (EAPOL-Key extraction) and dropped everything else, while the
 * IP decoder in capture.c only ever saw Ethernet, SLL and SLL2. The two
 * capture paths therefore saw disjoint worlds: 802.11 metadata on one
 * side, IP on the other, with no bridge between them even on an open
 * network where the payload is in the clear.
 *
 * This module is the bridge's arithmetic, kept separate from the wiring
 * because the arithmetic is where the risk is. Getting the header
 * length wrong does not fail loudly — it produces a plausible-looking
 * ethertype from payload bytes and feeds garbage to the IP decoder.
 *
 * ── Scope ──
 *
 * Encrypted frames are out. A frame with the Protected bit set carries
 * ciphertext; sloth does not crack and will not (MISSION §2), so those
 * are rejected here. This is only ever useful on open networks — which
 * is exactly where rogue portals and credential harvesting live. */

/* Why a frame was rejected. Distinguishing these matters because
 * "encrypted" is the normal case on most networks and says nothing is
 * wrong, while "malformed" is a signal. */
typedef enum {
    DOT11_DATA_OK          =  0,
    DOT11_DATA_NOT_DATA    = -1,  /* not a type-2 frame              */
    DOT11_DATA_NO_PAYLOAD  = -2,  /* Null-function subtype, or empty */
    DOT11_DATA_ENCRYPTED   = -3,  /* Protected bit set               */
    DOT11_DATA_FRAGMENT    = -4,  /* More Fragments, or not fragment 0 */
    DOT11_DATA_AMSDU       = -5,  /* aggregated: several subframes   */
    DOT11_DATA_NOT_SNAP    = -6,  /* LLC present but not SNAP-encapsulated */
    DOT11_DATA_TRUNCATED   = -7,
} dot11_data_status_t;

/* Length of the MAC header for a data frame, in bytes, or -1 if `len`
 * cannot hold it.
 *
 *   24 base
 *   +6  when both ToDS and FromDS are set (addr4 — WDS / mesh)
 *   +2  when the subtype has the QoS bit (sub & 0x08)
 *   +4  when the Order bit is set in Frame Control (HT Control)
 *
 * Each addend is independent and they compose. An implementation that
 * treats them as alternatives is wrong in a way that only shows up on
 * the frames that carry more than one. */
int dot11_data_header_len(const uint8_t *dot11, int len);

/* Locate the network-layer payload inside an 802.11 data frame.
 *
 * On DOT11_DATA_OK, *payload_off is the offset of the first byte after
 * the LLC/SNAP header and *ethertype is the protocol it declares.
 * Otherwise the return value says why not. Either output may be NULL. */
int dot11_data_payload(const uint8_t *dot11, int len,
                       int *payload_off, uint16_t *ethertype);

#endif /* DOT11_DATA_H */
