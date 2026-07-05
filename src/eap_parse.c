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
    }
    /* Success (3) / Failure (4) carry no Type — out->type stays -1. */
    return 1;
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
