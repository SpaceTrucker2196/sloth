#include "eap_parse.h"
#include <string.h>
#include "bytes.h"
#include "sensor_health.h"

int eap_parse(const uint8_t *p, int len, eap_info_t *out) {
    if (!p || !out || len < 4) return 0;
    memset(out, 0, sizeof(*out));
    out->type = -1;

    out->code = p[0];
    out->id   = p[1];
    int eaplen = (p[2] << 8) | p[3];
    /* The declared EAP length must fit inside the frame and cover at
     * least the 4-byte header. Trust the shorter of declared / actual. */
    if (eaplen < 4) return 0;
    int avail = eaplen < len ? eaplen : len;

    if (out->code == EAP_CODE_REQUEST || out->code == EAP_CODE_RESPONSE) {
        if (avail < 5) return 0;          /* Request/Response carry a Type */
        out->type = p[4];
        /* A Response/Identity frame's Type-Data is the identity string —
         * the username eaphammer harvests when the supplicant isn't set
         * up for an anonymous outer identity. */
        if (out->code == EAP_CODE_RESPONSE && out->type == EAP_TYPE_IDENTITY) {
            int idlen = avail - 5;
            if (idlen < 0) idlen = 0;
            if (idlen > (int)sizeof(out->identity) - 1)
                idlen = (int)sizeof(out->identity) - 1;
            /* Copy only printable bytes; stop at the first control char so
             * a malformed identity can't smuggle terminal escapes. */
            int o = 0;
            for (int i = 0; i < idlen; i++) {
                uint8_t c = p[5 + i];
                if (c < 0x20 || c > 0x7e) break;
                out->identity[o++] = (char)c;
            }
            out->identity[o] = '\0';
        }
        /* TLS-in-EAP: Type-Data is Flags(1), then a 4-byte TLS Message
         * Length when the L bit is set, then TLS record bytes (#65). */
        if (eap_type_is_tls_based(out->type) && avail >= 6) {
            out->tls_flags = p[5];
            int off = 6;
            if (out->tls_flags & EAP_TLS_FLAG_LENGTH) off += 4;
            if (avail > off) {
                out->tls     = p + off;
                out->tls_len = avail - off;
            }
        }
    }
    /* Success (3) / Failure (4) carry no Type — out->type stays -1. */
    return 1;
}

int eap_type_is_tls_based(int type) {
    return type == EAP_TYPE_TLS  ||
           type == EAP_TYPE_TTLS ||
           type == EAP_TYPE_PEAP;
}

/* TLS record: ContentType(1) Version(2) Length(2) then the fragment.
 * Handshake message: HandshakeType(1) Length(3) then the body. */
#define TLS_CT_HANDSHAKE      22
#define TLS_HS_SERVER_HELLO    2
#define TLS_HS_CERTIFICATE    11

int tls_scan_handshake(const uint8_t *data, int len,
                       int *saw_server_hello, int *saw_certificate) {
    if (saw_server_hello) *saw_server_hello = 0;
    if (saw_certificate)  *saw_certificate  = 0;
    if (!data || len < 5) return 0;

    int off = 0, looked_like_tls = 0;
    while (off + 5 <= len) {
        uint8_t  ct    = data[off];
        int      rlen  = (data[off + 3] << 8) | data[off + 4];
        /* Only a buffer that actually starts a record is interpretable.
         * A continuation fragment begins mid-payload, and reading its
         * bytes as a record header invents handshake types out of
         * certificate data — which for this detector would be a false
         * *negative* masquerading as evidence. On the first iteration
         * this rejects such a buffer outright, which is why there is no
         * separate entry guard: mutation testing showed one to be an
         * exact duplicate of this line. */
        if (ct < 20 || ct > 23 || data[off + 1] != 0x03) break;
        looked_like_tls = 1;
        const uint8_t *body = data + off + 5;
        int avail = len - off - 5;
        if (avail <= 0) break;
        int use = rlen < avail ? rlen : avail;   /* truncated record is fine */

        if (ct == TLS_CT_HANDSHAKE) {
            /* Several handshake messages can share one record — the
             * server flight routinely packs ServerHello and Certificate
             * together, which is exactly the pair this looks for. */
            int h = 0;
            while (h + 4 <= use) {
                uint8_t hs   = body[h];
                int     hlen = (body[h + 1] << 16) | (body[h + 2] << 8) |
                                body[h + 3];
                if (hs == TLS_HS_SERVER_HELLO && saw_server_hello)
                    *saw_server_hello = 1;
                if (hs == TLS_HS_CERTIFICATE && saw_certificate)
                    *saw_certificate = 1;
                if (hlen < 0) break;
                h += 4 + hlen;
            }
        }
        off += 5 + rlen;
        if (rlen <= 0) break;
    }
    return looked_like_tls;
}

int eap_type_is_weak(int type) {
    return type == EAP_TYPE_MD5 || type == EAP_TYPE_GTC;
}

const char *eap_type_name(int type) {
    switch (type) {
    case EAP_TYPE_IDENTITY:     return "Identity";
    case EAP_TYPE_NOTIFICATION: return "Notification";
    case EAP_TYPE_NAK:          return "Nak";
    case EAP_TYPE_MD5:          return "MD5";
    case EAP_TYPE_OTP:          return "OTP";
    case EAP_TYPE_GTC:          return "GTC";
    case EAP_TYPE_TLS:          return "TLS";
    case EAP_TYPE_TTLS:         return "TTLS";
    case EAP_TYPE_PEAP:         return "PEAP";
    case EAP_TYPE_MSCHAPV2:     return "MSCHAPv2";
    case EAP_TYPE_EXPANDED:     return "Expanded";
    default:                    return "?";
    }
}

/* Expanded-type header offsets, counted from the EAP Code byte:
 * Code Id Len(2) Type(254) Vendor-Id(3) Vendor-Type(4) Op-Code Flags. */
#define WSC_OFF_VENDOR_ID    5
#define WSC_OFF_VENDOR_TYPE  8
#define WSC_OFF_OPCODE      12
#define WSC_OFF_FLAGS       13
#define WSC_HDR_LEN         14

/* Copy one WSC vendor-string attribute (#77). The bound is the
 * destination, i.e. the §12 maximum, applied to the input index: an
 * attribute longer than its maximum is malformed, and taking only its
 * first `max` octets keeps a hostile length from pushing later bytes
 * into the field. Non-printable octets are dropped rather than mapped,
 * matching the beacon-IE path (wps_attr_str in src/beacon_snoop.c). */
static void wsc_vendor_str(char *dst, int max, const uint8_t *v, int alen,
                           int *clamped) {
    int take = alen;
    if (take > max) { take = max; *clamped = 1; }
    int j = 0;
    for (int i = 0; i < take; i++) {
        unsigned char c = v[i];
        if (c >= 0x20 && c < 0x7f) dst[j++] = (char)c;
    }
    dst[j] = '\0';
}

/* Returns 1 when `type` is one of the four vendor-string attributes
 * (and has been stored), 0 otherwise. Kept apart from the fixed-size
 * attribute chain in wsc_walk_tlvs so the two concerns stay separable. */
static int wsc_take_vendor_str(uint16_t type, const uint8_t *v, int alen,
                               eap_wsc_info_t *out) {
    int *cl = &out->vendor_str_clamped;
    switch (type) {
    case WSC_ATTR_MANUFACTURER:
        wsc_vendor_str(out->manufacturer, WSC_MANUFACTURER_MAX, v, alen, cl);
        return 1;
    case WSC_ATTR_MODEL_NAME:
        wsc_vendor_str(out->model_name, WSC_MODEL_STR_MAX, v, alen, cl);
        return 1;
    case WSC_ATTR_MODEL_NUMBER:
        wsc_vendor_str(out->model_number, WSC_MODEL_STR_MAX, v, alen, cl);
        return 1;
    case WSC_ATTR_SERIAL_NUMBER:
        wsc_vendor_str(out->serial_number, WSC_MODEL_STR_MAX, v, alen, cl);
        return 1;
    default:
        return 0;
    }
}

/* WSC attributes: 2-octet type, 2-octet length, big-endian (WSC 2.0
 * §12) — the shared iterator's 2+2 form (#127). A header or value that
 * does not fit ends the walk, sets `truncated` and is tallied as an
 * element-walk fault; attributes before it are kept. */
static void wsc_walk_tlvs(const uint8_t *b, int n, eap_wsc_info_t *out) {
    tlv_it_t it;
    uint16_t type; int alen; const uint8_t *v;
    out->tlvs_walked = 1;
    tlv_init16(&it, b, n, 1);
    while (tlv_next(&it, &type, &alen, &v) == TLV_OK) {
        if (wsc_take_vendor_str(type, v, alen, out)) continue;
        /* Fixed-size attributes with the wrong length are ignored, not
         * trusted: a short UUID-E copied as 16 bytes would read the next
         * attribute's header into the identifier. */
        if (type == WSC_ATTR_MESSAGE_TYPE && alen == 1) {
            out->msg_type = v[0];
        } else if (type == WSC_ATTR_DEV_PWD_ID && alen == 2) {
            out->dev_pwd_id = (v[0] << 8) | v[1];
        } else if (type == WSC_ATTR_UUID_E && alen == 16) {
            memcpy(out->uuid_e, v, 16);
            out->has_uuid_e = 1;
        } else if (type == WSC_ATTR_MAC_ADDRESS && alen == 6) {
            memcpy(out->mac, v, 6);
            out->has_mac = 1;
        }
    }
    if (it.status == TLV_OVERRUN) {
        out->truncated = 1;
        sh_parse_fault_note(SH_PF_IE_OVERRUN);
    }
}

int eap_wsc_parse(const uint8_t *p, int len, eap_wsc_info_t *out) {
    if (!p || !out) return 0;
    memset(out, 0, sizeof(*out));
    out->msg_type   = -1;
    out->dev_pwd_id = -1;
    out->msg_length = -1;

    eap_info_t e;
    if (!eap_parse(p, len, &e) || e.type != EAP_TYPE_EXPANDED) return 0;
    int eaplen = (p[2] << 8) | p[3];
    int avail  = eaplen < len ? eaplen : len;
    if (avail < WSC_HDR_LEN) return 0;

    uint32_t vid = ((uint32_t)p[WSC_OFF_VENDOR_ID] << 16) |
                   ((uint32_t)p[WSC_OFF_VENDOR_ID + 1] << 8) |
                    (uint32_t)p[WSC_OFF_VENDOR_ID + 2];
    uint32_t vtype = ((uint32_t)p[WSC_OFF_VENDOR_TYPE]     << 24) |
                     ((uint32_t)p[WSC_OFF_VENDOR_TYPE + 1] << 16) |
                     ((uint32_t)p[WSC_OFF_VENDOR_TYPE + 2] << 8) |
                      (uint32_t)p[WSC_OFF_VENDOR_TYPE + 3];
    if (vid != EAP_WSC_VENDOR_ID || vtype != EAP_WSC_VENDOR_TYPE) return 0;

    out->op_code        = p[WSC_OFF_OPCODE];
    out->flags          = p[WSC_OFF_FLAGS];
    out->more_fragments = (out->flags & WSC_FLAG_MF) ? 1 : 0;

    int body = WSC_HDR_LEN;
    if (out->flags & WSC_FLAG_LF) {
        if (avail < WSC_HDR_LEN + 2) return 0;
        out->msg_length = (p[WSC_HDR_LEN] << 8) | p[WSC_HDR_LEN + 1];
        body += 2;
    }
    /* LF marks the first fragment of a fragmented message (WSC 2.0
     * §7.7.1); MF without LF is a continuation whose first bytes are
     * the middle of some attribute value, not a TLV header. The final
     * fragment (MF and LF both clear) is indistinguishable from an
     * unfragmented message without state, so it is walked — the
     * per-attribute length checks are what keep that honest. */
    if (out->more_fragments && !(out->flags & WSC_FLAG_LF)) return 1;
    wsc_walk_tlvs(p + body, avail - body, out);
    return 1;
}

const char *wsc_msg_name(int msg_type) {
    switch (msg_type) {
    case WSC_MSG_M1:   return "M1";
    case WSC_MSG_M2:   return "M2";
    case WSC_MSG_M2D:  return "M2D";
    case WSC_MSG_M3:   return "M3";
    case WSC_MSG_M4:   return "M4";
    case WSC_MSG_M5:   return "M5";
    case WSC_MSG_M6:   return "M6";
    case WSC_MSG_M7:   return "M7";
    case WSC_MSG_M8:   return "M8";
    case WSC_MSG_ACK:  return "ACK";
    case WSC_MSG_NACK: return "NACK";
    case WSC_MSG_DONE: return "Done";
    default:           return "?";
    }
}
