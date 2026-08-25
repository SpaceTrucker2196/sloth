#include "eap_parse.h"
#include <string.h>

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
    default:                    return "?";
    }
}
