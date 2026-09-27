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

/* ── EAP-WSC (Wi-Fi Simple Configuration / WPS) — issue #82 ──────────
 *
 * WPS registration (M1..M8) rides inside EAP as an Expanded Type
 * (RFC 3748 §5.7): Type 254, then a 3-byte Vendor-Id and a 4-byte
 * Vendor-Type. WSC uses the WFA SMI 0x00372A with Vendor-Type 1
 * (WSC 2.0 §7.7). After that come Op-Code(1), Flags(1), an optional
 * 2-byte Message Length (Flags.LF), then the WSC message body — a run
 * of big-endian Type(2) Length(2) Value TLVs (WSC 2.0 §12).
 *
 * This decoder is parse-only and holds no state: it names the message
 * and pulls the attributes a PIN-brute / Pixie-Dust detector keys on.
 * Sequencing M-messages into sessions is a later layer's job. */

#define EAP_TYPE_EXPANDED        254       /* RFC 3748 §5.7 */
#define EAP_WSC_VENDOR_ID        0x00372Au /* WFA SMI */
#define EAP_WSC_VENDOR_TYPE      1u        /* SimpleConfig */

/* WSC 2.0 §7.7.1 Op-Code. */
#define WSC_OP_START     0x01
#define WSC_OP_ACK       0x02
#define WSC_OP_NACK      0x03
#define WSC_OP_MSG       0x04
#define WSC_OP_DONE      0x05
#define WSC_OP_FRAG_ACK  0x06

/* WSC 2.0 §7.7.1 Flags. */
#define WSC_FLAG_MF      0x01   /* more fragments follow            */
#define WSC_FLAG_LF      0x02   /* 2-byte Message Length is present */

/* WSC 2.0 §12 attribute types this decoder extracts. */
#define WSC_ATTR_MAC_ADDRESS   0x1020   /* Enrollee MAC in M1, 6 bytes */
#define WSC_ATTR_MESSAGE_TYPE  0x1022   /* 1 byte, WSC_MSG_*           */
#define WSC_ATTR_UUID_E        0x1047   /* 16 bytes                    */

/* WSC 2.0 §12 Message Type values (attribute 0x1022). */
#define WSC_MSG_M1    0x04
#define WSC_MSG_M2    0x05
#define WSC_MSG_M2D   0x06
#define WSC_MSG_M3    0x07
#define WSC_MSG_M4    0x08
#define WSC_MSG_M5    0x09
#define WSC_MSG_M6    0x0A
#define WSC_MSG_M7    0x0B
#define WSC_MSG_M8    0x0C
#define WSC_MSG_ACK   0x0D
#define WSC_MSG_NACK  0x0E
#define WSC_MSG_DONE  0x0F

typedef struct {
    int     op_code;          /* WSC_OP_*                                  */
    int     flags;            /* raw Flags octet                           */
    int     more_fragments;   /* Flags.MF                                  */
    int     msg_length;       /* declared Message Length; -1 when no LF    */
    int     tlvs_walked;      /* 1 when the body was read as TLVs          */
    int     truncated;        /* a TLV header or value ran past the frame  */
    int     msg_type;         /* WSC_MSG_*; -1 when absent                 */
    int     has_uuid_e;
    uint8_t uuid_e[16];
    int     has_mac;
    uint8_t mac[6];
} eap_wsc_info_t;

/* Parse an EAP packet starting at its Code byte as EAP-WSC. Returns 1
 * when it is a Request/Response of Expanded Type 254 carrying the WFA
 * vendor id and SimpleConfig vendor type with Op-Code and Flags present
 * (out populated), 0 otherwise — including a Type-254 frame for some
 * other vendor, which is simply not WSC.
 *
 * A fragment with MF set and LF clear is a middle fragment: its body
 * starts mid-message, so it is not walked (tlvs_walked stays 0) rather
 * than inventing attributes out of value bytes. A truncated TLV stops
 * the walk and sets `truncated`; attributes before it are kept. */
int eap_wsc_parse(const uint8_t *p, int len, eap_wsc_info_t *out);

/* "M1".."M8", "M2D", "ACK", "NACK", "Done"; "?" if unknown. */
const char *wsc_msg_name(int msg_type);

#endif /* EAP_PARSE_H */
