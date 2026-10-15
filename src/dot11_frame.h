#ifndef DOT11_FRAME_H
#define DOT11_FRAME_H

#include <stdint.h>
#include <stddef.h>

#include "dot11_data.h"   /* dot11_data_status_t: the payload status codes */

/* One decode per 802.11 frame — issue #122.
 *
 * Before this existed, a dozen observers re-derived type, subtype,
 * flags, header length, Protected and the address roles from the raw
 * (dot11, len) pair each was handed, and dot11_data.c was an opt-in
 * helper rather than a choke point. Each private copy of the header
 * arithmetic was a place for the §9.2.4.1.10 rule to be wrong on its
 * own: three +HTC fixes on 2026-10-14 were one instance of the class,
 * and eapol_log.c's seventh copy still added HT Control to every data
 * frame with the Order bit set, so a non-QoS StrictlyOrdered EAPOL
 * frame had its LLC header read four bytes late and the handshake was
 * missed. Every offset stayed in bounds, so neither the sanitiser jobs
 * nor the fuzz targets could see it.
 *
 * This header is the one place the MAC-header layout is known. The
 * byte-pointer helpers in dot11_data.h remain as wrappers over it so
 * existing observers, tests and fuzz harnesses keep their entry points.
 *
 * What the view does NOT do: it never reads past `len`, never follows
 * the body of a Protected frame (MISSION §2 — sloth does not crack),
 * and never guesses a role the clause leaves undefined (a WDS frame has
 * no single BSSID; a control frame has no SA/DA). */

/* What radiotap said about the frame. All three default to 0 when the
 * caller has no radiotap header (a test feeding bare 802.11, a unit
 * fuzzing a parser). */
typedef struct {
    int fcs_present;   /* RT_F_FCS: the caller stripped the trailer     */
    int datapad;       /* RT_F_DATAPAD: body starts on a 4-byte boundary */
    int bad_fcs;       /* RT_F_BADFCS: contents are untrustworthy        */
} dot11_rt_hints_t;

typedef struct {
    const uint8_t *p;
    int            len;          /* bytes of frame AFTER the FCS strip */

    uint8_t type, subtype, fc1;
    unsigned to_ds:1, from_ds:1, more_frag:1, retry:1,
             pwr_mgmt:1, more_data:1, protected_:1, order:1;

    /* The §9.2.4.1.10 rule lives HERE and nowhere else: the Order bit
     * means HT Control in a management frame or a QoS data frame, and
     * StrictlyOrdered — no field at all — in a non-QoS data frame. */
    int has_qos, has_htc, has_addr4;

    /* hdr_len is -1 until the whole MAC header is inside `len`.
     * body_off is hdr_len rounded up to 4 when datapad is set, else
     * hdr_len. body_len is never negative. */
    int hdr_len, body_off, body_len;

    /* Address fields by position; NULL when the frame has no such field
     * or `len` does not reach it. */
    const uint8_t *a1, *a2, *a3, *a4;

    /* Address fields by role (IEEE 802.11-2020 Table 9-26 for data,
     * §9.3.3.1 for management, §9.3.1 for control). NULL when the
     * clause defines no such role for this frame: a control frame has
     * RA/TA only, a four-address frame has no single BSSID. */
    const uint8_t *bssid, *sa, *da, *ta, *ra;

    /* -1 when the field is absent or not inside `len`. */
    int seq_num, frag_num, tid, amsdu;

    int fcs_stripped, bad_fcs;
} dot11_frame_t;

/* Decode the MAC header of the `len` bytes at `p`. `rt` may be NULL.
 *
 * Returns 1 when the whole header is readable (hdr_len >= 0). Returns
 * 0 for a runt, a NULL pointer or an Extension (type 3) frame; the
 * type, subtype, flags and whichever address pointers `len` reaches
 * are still filled in so a caller can log what it saw, but hdr_len,
 * body_off, seq_num, frag_num, tid and amsdu read -1 and body_len 0.
 *
 * `len` is the frame WITHOUT its FCS: a caller holding a radiotap
 * header strips first with dot11_fcs_strip_len(). The view does no FCS
 * arithmetic of its own, because it cannot see caplen against origlen
 * and a truncated capture may have lost some or all of the trailer. */
int dot11_frame_decode(const uint8_t *p, int len,
                       const dot11_rt_hints_t *rt, dot11_frame_t *out);

/* The frame body after the MAC header (and any datapad). Returns 1 and
 * fills *body / *blen, or 0 when the header was not readable or the
 * frame is Protected — the body is ciphertext and is not handed out. */
int dot11_frame_body(const dot11_frame_t *f,
                     const uint8_t **body, int *blen);

/* Locate the LLC/SNAP-encapsulated network payload of a data frame.
 * Returns a dot11_data_status_t: DOT11_DATA_OK with *payload_off set to
 * the first byte after the SNAP header and *ethertype to what it
 * declares, or the reason the frame carries no such payload. Either
 * output may be NULL; both are zeroed on failure. */
int dot11_frame_payload(const dot11_frame_t *f,
                        int *payload_off, uint16_t *ethertype);

/* How many trailing bytes of a captured frame are FCS. When radiotap
 * says the FCS is present it is the last 4 octets of the ORIGINAL
 * frame; a capture truncated by snaplen may have lost some or all of
 * them, so the strip is max(0, 4 - (origlen - caplen)). 0 whenever
 * fcs_present is 0. The caller still clamps to the bytes it holds. */
int dot11_fcs_strip_len(int caplen, int origlen, int fcs_present);

#endif /* DOT11_FRAME_H */
