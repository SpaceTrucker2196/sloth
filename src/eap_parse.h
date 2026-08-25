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
    /* TLS-in-EAP payload (#65). For PEAP / EAP-TLS / EAP-TTLS the
     * Type-Data is Flags(1) [+ TLS Message Length(4) when the L bit is
     * set] followed by TLS record bytes. These point into the caller's
     * buffer — valid only as long as it is. tls_len is 0 when the
     * method is not TLS-based or the fragment carries no data. */
    const uint8_t *tls;
    int  tls_len;
    int  tls_flags;        /* EAP_TLS_FLAG_* */
} eap_info_t;

/* EAP-TLS Flags octet — RFC 5216 §3.1. */
#define EAP_TLS_FLAG_LENGTH  0x80   /* L — TLS Message Length present */
#define EAP_TLS_FLAG_MORE    0x40   /* M — more fragments follow      */
#define EAP_TLS_FLAG_START   0x20   /* S — start                      */

/* True for the EAP methods that carry a TLS handshake. */
int eap_type_is_tls_based(int type);

/* Walk the TLS records in `data` looking for handshake messages, and
 * report whether a ServerHello (2) and/or a Certificate (11) appear.
 * Either output pointer may be NULL. Returns 1 if the buffer looked
 * like a TLS record at all, 0 otherwise.
 *
 * Deliberately does not reassemble: a continuation fragment carries no
 * record header and is not parseable on its own. ServerHello is the
 * first server handshake message and small, so it lands in the first
 * server fragment and is reliably visible; Certificate usually does
 * too, but a large chain can push it past the fragment boundary. That
 * asymmetry is why the two are reported separately — see #65. */
int tls_scan_handshake(const uint8_t *data, int len,
                       int *saw_server_hello, int *saw_certificate);

/* Parse an EAP packet starting at its Code byte. Returns 1 on success
 * (out populated), 0 if too short or malformed. */
int eap_parse(const uint8_t *p, int len, eap_info_t *out);

/* 1 if `type` is a weak inner method an attacker prefers to offer
 * (EAP-MD5 / EAP-GTC) — crackable or cleartext-leaking. */
int eap_type_is_weak(int type);

/* Short human-readable method name ("MD5", "PEAP", ...); "?" if unknown. */
const char *eap_type_name(int type);

#endif /* EAP_PARSE_H */
