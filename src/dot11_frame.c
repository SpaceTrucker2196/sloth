#include <string.h>

#include "dot11_frame.h"

/* LLC/SNAP: DSAP AA, SSAP AA, control 03, then a three-byte
 * organisation code and the two-byte ethertype (RFC 1042). */
#define LLC_SNAP_LEN 8

/* Control subtypes whose header is RA only (§9.3.1.3, §9.3.1.4). Every
 * other control subtype carries A2 as well, so its header is 16. */
#define CTRL_SUB_CTS 12
#define CTRL_SUB_ACK 13

int dot11_fcs_strip_len(int caplen, int origlen, int fcs_present) {
    if (!fcs_present) return 0;
    int cut = origlen - caplen;
    if (cut < 0) cut = 0;        /* caplen > origlen is not a real capture */
    int strip = 4 - cut;
    return strip > 0 ? strip : 0;
}

int dot11_frame_decode(const uint8_t *p, int len,
                       const dot11_rt_hints_t *rt, dot11_frame_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    out->p        = p;
    out->len      = len > 0 ? len : 0;
    out->hdr_len  = -1;
    out->body_off = -1;
    out->seq_num  = -1;
    out->frag_num = -1;
    out->tid      = -1;
    out->amsdu    = -1;
    if (rt) {
        out->fcs_stripped = rt->fcs_present ? 1 : 0;
        out->bad_fcs      = rt->bad_fcs     ? 1 : 0;
    }
    if (!p || len < 2) return 0;

    const uint8_t fc0 = p[0], fc1 = p[1];
    out->type       = (uint8_t)((fc0 >> 2) & 0x03);
    out->subtype    = (uint8_t)((fc0 >> 4) & 0x0f);
    out->fc1        = fc1;
    out->to_ds      = (fc1 >> 0) & 1u;
    out->from_ds    = (fc1 >> 1) & 1u;
    out->more_frag  = (fc1 >> 2) & 1u;
    out->retry      = (fc1 >> 3) & 1u;
    out->pwr_mgmt   = (fc1 >> 4) & 1u;
    out->more_data  = (fc1 >> 5) & 1u;
    out->protected_ = (fc1 >> 6) & 1u;
    out->order      = (fc1 >> 7) & 1u;

    const int type = out->type;

    /* Extension frames (type 3: DMG beacon, S1G) have their own header
     * layouts and nothing in sloth parses them. Flags and the first
     * address (octets 4-9 in every type-3 layout, §9.3.4) are reported
     * so the frame can be logged; nothing else is claimed. */
    if (type == 3) {
        if (len >= 10) out->a1 = p + 4;
        return 0;
    }

    /* ── The one copy of the header-length rule ──────────────────
     *
     * Data: 24, +6 for Address 4 when both ToDS and FromDS are set,
     * +2 for QoS Control when the subtype has bit 3, +4 for HT
     * Control. Each addend is independent and they compose.
     *
     * HT Control is present only in QoS Data and Management frames
     * (§9.2.4.6). The Frame Control bit that announces it has two
     * unrelated meanings (§9.2.4.1.10): +HTC in a QoS data or
     * management frame, but in a NON-QoS data frame it is the
     * StrictlyOrdered service-class indication and no field follows.
     * Conditioning on the bit alone puts the body four bytes late on
     * any non-QoS data frame carrying it, which is one bit an attacker
     * picks — and the skew reads a plausible LLC header, CCMP PN or
     * EAPOL frame out of the wrong place without touching a byte out
     * of bounds, so no sanitiser ever sees it.
     *
     * Control frames carry neither Sequence Control nor Address 3:
     * RA only (10) for CTS/ACK, RA+TA (16) for the rest. */
    out->has_qos   = (type == 2) && (out->subtype & 0x08);
    out->has_htc   = out->order && (type == 0 || out->has_qos);
    out->has_addr4 = (type == 2) && out->to_ds && out->from_ds;

    int need;
    if (type == 1) {
        need = (out->subtype == CTRL_SUB_CTS ||
                out->subtype == CTRL_SUB_ACK) ? 10 : 16;
    } else {
        need = 24;
        if (out->has_addr4) need += 6;
        if (out->has_qos)   need += 2;
        if (out->has_htc)   need += 4;
    }

    /* Positional fields, each only when `len` reaches it. A runt still
     * yields the addresses it carries so the frame can be logged. */
    if (len >= 10) out->a1 = p + 4;
    if (type == 1) {
        if (need == 16 && len >= 16) out->a2 = p + 10;
    } else {
        if (len >= 16) out->a2 = p + 10;
        if (len >= 22) out->a3 = p + 16;
        if (len >= 24) {
            uint16_t sc   = (uint16_t)(p[22] | (p[23] << 8));
            out->frag_num = sc & 0x000f;
            out->seq_num  = (sc >> 4) & 0x0fff;
        }
        if (out->has_addr4 && len >= 30) out->a4 = p + 24;
        if (out->has_qos) {
            /* QoS Control moves with Address 4; a fixed 24 lands inside
             * the address field on a WDS/mesh frame. */
            int qos_off = 24 + (out->has_addr4 ? 6 : 0);
            if (len > qos_off) {
                out->tid   = p[qos_off] & 0x0f;
                out->amsdu = (p[qos_off] >> 7) & 0x01;
            }
        }
    }

    /* Roles (Table 9-26 for data; §9.3.3.1 for management; §9.3.1 for
     * control). Only ever aliases of positional pointers that exist. */
    out->ra = out->a1;
    out->ta = out->a2;
    if (type == 0) {
        out->da    = out->a1;
        out->sa    = out->a2;
        out->bssid = out->a3;
    } else if (type == 2) {
        if (out->to_ds && out->from_ds) {
            /* A WDS frame crosses two BSSs: no single BSSID. Reported
             * as such rather than guessed. */
            out->da = out->a3;
            out->sa = out->a4;
        } else if (out->from_ds) {           /* AP -> STA */
            out->da    = out->a1;
            out->bssid = out->a2;
            out->sa    = out->a3;
        } else if (out->to_ds) {             /* STA -> AP */
            out->bssid = out->a1;
            out->sa    = out->a2;
            out->da    = out->a3;
        } else {                             /* IBSS */
            out->da    = out->a1;
            out->sa    = out->a2;
            out->bssid = out->a3;
        }
    }

    if (len < need) return 0;

    out->hdr_len  = need;
    out->body_off = (rt && rt->datapad) ? ((need + 3) & ~3) : need;
    out->body_len = len - out->body_off;
    if (out->body_len < 0) out->body_len = 0;
    return 1;
}

int dot11_frame_body(const dot11_frame_t *f,
                     const uint8_t **body, int *blen) {
    if (body) *body = NULL;
    if (blen) *blen = 0;
    if (!f || !f->p || f->hdr_len < 0) return 0;
    /* Ciphertext is not a body. Refused rather than handed out, per
     * MISSION §2 — and this is the normal case on most networks. */
    if (f->protected_) return 0;
    if (body) *body = f->p + f->body_off;
    if (blen) *blen = f->body_len;
    return 1;
}

int dot11_frame_payload(const dot11_frame_t *f,
                        int *payload_off, uint16_t *ethertype) {
    if (payload_off) *payload_off = 0;
    if (ethertype)   *ethertype   = 0;
    if (!f || !f->p) return DOT11_DATA_TRUNCATED;
    if (f->type != 2) return DOT11_DATA_NOT_DATA;

    /* Subtypes with bit 2 set carry no frame body at all — Null,
     * QoS Null and friends exist to move power-management state. */
    if (f->subtype & 0x04) return DOT11_DATA_NO_PAYLOAD;

    /* Protected: the body is ciphertext. Distinguished from malformed,
     * because on most networks this is simply the normal case. */
    if (f->protected_) return DOT11_DATA_ENCRYPTED;

    if (f->hdr_len < 0) return DOT11_DATA_TRUNCATED;

    /* Anything other than fragment zero is a continuation with no LLC
     * header of its own, and a first fragment with More Fragments set
     * is incomplete. */
    if (f->frag_num != 0) return DOT11_DATA_FRAGMENT;
    if (f->more_frag)     return DOT11_DATA_FRAGMENT;

    /* A-MSDU: the body is several subframes each with its own header,
     * not one LLC-encapsulated packet. Detected and skipped explicitly
     * — a silent misparse here reads as a valid but wrong packet. */
    if (f->amsdu == 1) return DOT11_DATA_AMSDU;

    if (f->body_len < LLC_SNAP_LEN) return DOT11_DATA_TRUNCATED;
    const uint8_t *llc = f->p + f->body_off;
    /* Only SNAP-encapsulated frames carry an ethertype. Bare LLC (IPX,
     * NetBIOS over 802.2) has a protocol identifier in a different
     * place, and reading one as the other invents an ethertype. */
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03)
        return DOT11_DATA_NOT_SNAP;

    if (payload_off) *payload_off = f->body_off + LLC_SNAP_LEN;
    if (ethertype)   *ethertype   = (uint16_t)((llc[6] << 8) | llc[7]);
    return DOT11_DATA_OK;
}
