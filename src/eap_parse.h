#ifndef EAP_PARSE_H
#define EAP_PARSE_H

#include <stdint.h>

/* Inner EAP frame decoding for the rogue-RADIUS detector (issue #31).
 *
 * WPA-Enterprise (802.1X) carries an EAP conversation inside EAPOL
 * EAP-Packet frames (EAPOL packet-type 0, as opposed to the type-3
 * EAPOL-Key 4-way handshake). eaphammer / hostapd-wpe stand up a rogue
 * AP that offers a WEAK inner method (EAP-MD5, EAP-GTC) or a mismatched
 * server cert, then harvest crackable challenge/response pairs. Parsing
 * the EAP method type on the air is how we spot the lure. Passive only —
 * this decodes bytes already captured, it never speaks EAP. */

/* EAP codes (RFC 3748 §4). */
#define EAP_CODE_REQUEST   1
#define EAP_CODE_RESPONSE  2
#define EAP_CODE_SUCCESS   3
#define EAP_CODE_FAILURE   4

/* EAP method types (RFC 3748 §5 + IANA registry) we classify. */
#define EAP_TYPE_IDENTITY      1
#define EAP_TYPE_NOTIFICATION  2
#define EAP_TYPE_NAK           3
#define EAP_TYPE_MD5           4   /* weak — offline-crackable MD5 challenge */
#define EAP_TYPE_OTP           5
#define EAP_TYPE_GTC           6   /* weak — cleartext password to the server */
#define EAP_TYPE_TLS          13
#define EAP_TYPE_TTLS         21
#define EAP_TYPE_PEAP         25
#define EAP_TYPE_MSCHAPV2     26

typedef struct {
    int  code;             /* EAP_CODE_* */
    int  id;               /* EAP identifier */
    int  type;             /* method type for Request/Response; -1 otherwise */
    char identity[64];     /* set for Response/Identity frames; "" otherwise */
} eap_info_t;

/* Parse an EAP packet starting at its Code byte. Returns 1 on success
 * (out populated), 0 if too short or malformed. */
int eap_parse(const uint8_t *p, int len, eap_info_t *out);

/* 1 if `type` is a weak inner method an attacker prefers to offer
 * (EAP-MD5 / EAP-GTC) — crackable or cleartext-leaking. */
int eap_type_is_weak(int type);

/* Short human-readable method name ("MD5", "PEAP", ...); "?" if unknown. */
const char *eap_type_name(int type);

#endif /* EAP_PARSE_H */
