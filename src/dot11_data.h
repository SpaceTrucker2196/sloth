#ifndef DOT11_DATA_H
#define DOT11_DATA_H

#include <stdint.h>
#include <stddef.h>

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

/* Which of the three (or four) address fields is the BSSID, the source
 * and the destination — issue #75.
 *
 * This is the table every 802.11 detector needs and every one of them
 * gets wrong at least once, because the fields *move* with ToDS/FromDS
 * (§9.3.2.1 Table 9-26):
 *
 *   ToDS FromDS   addr1   addr2   addr3   addr4
 *     0     0      DA      SA     BSSID    --      IBSS
 *     0     1      DA     BSSID    SA      --      AP -> STA
 *     1     0     BSSID    SA      DA      --      STA -> AP
 *     1     1      RA      TA      DA      SA      WDS / mesh
 *
 * Reading addr3 as the BSSID unconditionally — the shape that looks
 * right because it holds for a beacon — attributes every downlink frame
 * to its *sender* instead of its AP, which silently merges every
 * station on the network into one bogus BSS.
 *
 * The four-address case has no single BSSID: a WDS frame crosses two
 * of them. Reported as such rather than guessed, so a caller that needs
 * one can skip the frame instead of inventing an attribution.
 *
 * Any output may be NULL. Returns 1 when every requested field was
 * filled, 0 when the frame is too short or is not a data frame, and
 * DOT11_ADDRS_NO_BSSID when the frame is four-address (sa/da are still
 * written; bssid is not). */
#define DOT11_ADDRS_NO_BSSID  2

int dot11_data_addrs(const uint8_t *dot11, int len,
                     uint8_t bssid[6], uint8_t sa[6], uint8_t da[6]);

/* Group-addressed (broadcast or multicast): the I/G bit is the low bit
 * of the first octet (§9.2.4.3.2). Named because `addr[0] & 1` at a
 * call site reads like a typo. */
int dot11_is_group_addr(const uint8_t addr[6]);

/* Fragment number from Sequence Control, and whether More Fragments is
 * set. Sequence Control is always at offset 22 regardless of the QoS,
 * HT-Control and addr4 additions that follow it. Returns -1 if `len`
 * cannot hold it. */
int dot11_frag_num(const uint8_t *dot11, int len);
int dot11_more_frags(const uint8_t *dot11, int len);

/* QoS Control's Traffic Identifier (low nibble, §9.4.1.4 / §9.2.4.5.1)
 * — issue #75 slice 2.
 *
 * Non-QoS data frames carry no TID field; fragmentation for those is
 * grouped implicitly rather than per traffic class, so TID 0 is
 * returned for them, matching how a single best-effort queue behaves.
 * The QoS Control field moves with addr4 the same way it does in
 * dot11_data_header_len — reading it at a fixed offset would land in
 * the middle of the address field on a WDS/mesh frame.
 *
 * Returns -1 if `dot11` is not a data frame or `len` cannot hold the
 * field. */
int dot11_data_tid(const uint8_t *dot11, int len);

/* The QoS Control field's A-MSDU Present bit (bit 7 of its first
 * octet), or -1 when the frame is not a QoS data frame or is too short.
 *
 * Separate from dot11_data_payload(), which returns DOT11_DATA_ENCRYPTED
 * before it ever reaches the A-MSDU check — correct for its purpose,
 * useless for this one. CVE-2020-24588 is an attack on *encrypted*
 * MPDUs, and the QoS Control field sits in the plaintext MAC header, so
 * the bit is readable even though the body is not. */
int dot11_amsdu_present(const uint8_t *dot11, int len);

/* The 48-bit CCMP/TKIP packet number, or -1 when the frame is not
 * protected, carries no Extended IV, or is too short.
 *
 * The PN is transmitted in the clear immediately after the MAC header
 * (IEEE 802.11-2020 §12.5.3.2) as PN0, PN1, reserved, KeyID, PN2..PN5,
 * with the low-order octet first and the high-order four after the
 * KeyID octet — an ordering that exists for hardware reasons and traps
 * anyone who reads the eight bytes as a big-endian integer.
 *
 * Bit 5 of the KeyID octet is the Extended IV bit. Without it the frame
 * is WEP or original TKIP, which have no 48-bit PN at all, so the same
 * eight bytes mean something else entirely.
 *
 * Returned as int64_t because a 48-bit value has no room for a
 * sentinel: every uint64_t is a legal PN. */
int64_t dot11_ccmp_pn(const uint8_t *dot11, int len);

#endif /* DOT11_DATA_H */
