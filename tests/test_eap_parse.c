#include "runner.h"
#include "eap_parse.h"
#include "beacon_snoop.h"   /* pins WSC_DEV_PWD_ID_PBC to the beacon path */
#include <string.h>

/* Hand-crafted EAP packets per RFC 3748 §4 — Code(1) Id(1) Len(2) then
 * Type(1) + Type-Data for Request/Response. No parser-fed-its-own-output
 * circularity: every frame is a literal byte array. */

static void test_request_identity(void) {
    /* Request, id 0x11, len 5, Type=Identity(1). */
    uint8_t f[] = { 0x01, 0x11, 0x00, 0x05, 0x01 };
    eap_info_t e;
    ASSERT_EQ(eap_parse(f, sizeof(f), &e), 1);
    ASSERT_EQ(e.code, EAP_CODE_REQUEST);
    ASSERT_EQ(e.id, 0x11);
    ASSERT_EQ(e.type, EAP_TYPE_IDENTITY);
    ASSERT_STR(e.identity, "");
}

static void test_response_identity_leaks_username(void) {
    /* Response/Identity carrying a real username (not anonymous@realm) —
     * the eaphammer identity-leak signal. */
    const char *user = "jkunzelman@corp.example";
    int ul = (int)strlen(user);
    uint8_t f[5 + 64];
    f[0] = 0x02; f[1] = 0x22;
    f[2] = 0x00; f[3] = (uint8_t)(5 + ul);
    f[4] = EAP_TYPE_IDENTITY;
    memcpy(f + 5, user, (size_t)ul);
    eap_info_t e;
    ASSERT_EQ(eap_parse(f, 5 + ul, &e), 1);
    ASSERT_EQ(e.code, EAP_CODE_RESPONSE);
    ASSERT_EQ(e.type, EAP_TYPE_IDENTITY);
    ASSERT_STR(e.identity, "jkunzelman@corp.example");
}

static void test_weak_methods(void) {
    uint8_t md5[] = { 0x01, 0x01, 0x00, 0x05, EAP_TYPE_MD5 };
    uint8_t gtc[] = { 0x01, 0x02, 0x00, 0x05, EAP_TYPE_GTC };
    eap_info_t e;
    ASSERT_EQ(eap_parse(md5, sizeof(md5), &e), 1);
    ASSERT_EQ(e.type, EAP_TYPE_MD5);
    ASSERT(eap_type_is_weak(e.type));
    ASSERT_EQ(eap_parse(gtc, sizeof(gtc), &e), 1);
    ASSERT(eap_type_is_weak(e.type));
}

static void test_strong_methods_not_weak(void) {
    uint8_t peap[] = { 0x01, 0x03, 0x00, 0x05, EAP_TYPE_PEAP };
    uint8_t tls[]  = { 0x01, 0x04, 0x00, 0x05, EAP_TYPE_TLS };
    eap_info_t e;
    ASSERT_EQ(eap_parse(peap, sizeof(peap), &e), 1);
    ASSERT(!eap_type_is_weak(e.type));
    ASSERT_STR(eap_type_name(e.type), "PEAP");
    ASSERT_EQ(eap_parse(tls, sizeof(tls), &e), 1);
    ASSERT(!eap_type_is_weak(e.type));
}

static void test_success_has_no_type(void) {
    uint8_t f[] = { 0x03, 0x05, 0x00, 0x04 };   /* EAP-Success */
    eap_info_t e;
    ASSERT_EQ(eap_parse(f, sizeof(f), &e), 1);
    ASSERT_EQ(e.code, EAP_CODE_SUCCESS);
    ASSERT_EQ(e.type, -1);
}

static void test_rejects_short_and_malformed(void) {
    uint8_t tooshort[] = { 0x01, 0x00, 0x00 };        /* < 4 bytes */
    uint8_t badlen[]   = { 0x01, 0x00, 0x00, 0x02 };  /* eaplen < 4 */
    uint8_t req_notype[] = { 0x01, 0x00, 0x00, 0x04 };/* Request but no Type byte */
    eap_info_t e;
    ASSERT_EQ(eap_parse(tooshort, sizeof(tooshort), &e), 0);
    ASSERT_EQ(eap_parse(badlen, sizeof(badlen), &e), 0);
    ASSERT_EQ(eap_parse(req_notype, sizeof(req_notype), &e), 0);
    ASSERT_EQ(eap_parse(NULL, 0, &e), 0);
}

static void test_identity_strips_control_bytes(void) {
    /* An identity with an embedded escape must be truncated at it. */
    uint8_t f[] = { 0x02, 0x01, 0x00, 0x0a, 0x01,
                    'a', 'b', 0x1b, 'X', 'Y' };
    eap_info_t e;
    ASSERT_EQ(eap_parse(f, sizeof(f), &e), 1);
    ASSERT_STR(e.identity, "ab");
}

/* ── EAP-WSC (#82) ──────────────────────────────────────────────────
 * Frames per RFC 3748 §5.7 (Expanded Type) + WSC 2.0 §7.7 (Op-Code,
 * Flags, Message Length) + §12 (big-endian Type/Length/Value). Header:
 *   Code Id Len(2) | FE | 00 37 2A | 00 00 00 01 | Op | Flags [| MsgLen(2)]
 * Every WSC message body opens with Version (0x104A, 1 byte, 0x10). */

static void test_wsc_m1_full(void) {
    /* Enrollee -> Registrar M1: Response, WSC_MSG, no flags.
     * Body 40 bytes, EAP length 14 + 40 = 54 = 0x36. */
    uint8_t f[] = {
        0x02, 0x07, 0x00, 0x36, 0xFE,
        0x00, 0x37, 0x2A,             /* Vendor-Id: WFA SMI        */
        0x00, 0x00, 0x00, 0x01,       /* Vendor-Type: SimpleConfig */
        0x04, 0x00,                   /* Op WSC_MSG, Flags 0       */
        0x10, 0x4A, 0x00, 0x01, 0x10, /* Version 1.0               */
        0x10, 0x22, 0x00, 0x01, 0x04, /* Message Type = M1         */
        0x10, 0x47, 0x00, 0x10,       /* UUID-E, 16 bytes          */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x10, 0x20, 0x00, 0x06,       /* MAC Address, 6 bytes      */
        0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,
    };
    static const uint8_t uuid[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    static const uint8_t mac[6] = { 0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
    ASSERT_EQ(w.op_code, WSC_OP_MSG);
    ASSERT_EQ(w.flags, 0);
    ASSERT_EQ(w.more_fragments, 0);
    ASSERT_EQ(w.msg_length, -1);
    ASSERT_EQ(w.tlvs_walked, 1);
    ASSERT_EQ(w.truncated, 0);     /* last TLV ends exactly at the frame */
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_STR(wsc_msg_name(w.msg_type), "M1");
    ASSERT_EQ(w.dev_pwd_id, -1);   /* no 0x1012 in this body */
    ASSERT_EQ(w.has_uuid_e, 1);
    ASSERT_EQ(memcmp(w.uuid_e, uuid, 16), 0);
    ASSERT_EQ(w.has_mac, 1);
    ASSERT_EQ(memcmp(w.mac, mac, 6), 0);

    /* The generic decoder still sees it as an Expanded-type Response. */
    eap_info_t e;
    ASSERT_EQ(eap_parse(f, sizeof(f), &e), 1);
    ASSERT_EQ(e.type, EAP_TYPE_EXPANDED);
    ASSERT_STR(eap_type_name(e.type), "Expanded");
}

static void test_wsc_each_message_type(void) {
    /* Version + Message Type body, 10 bytes; EAP length 24 = 0x18.
     * [12] is the Op-Code, [23] the Message Type value. */
    static const struct { int op, msg; const char *name; } cases[] = {
        { WSC_OP_MSG,  0x04, "M1"   }, { WSC_OP_MSG,  0x05, "M2"   },
        { WSC_OP_MSG,  0x06, "M2D"  }, { WSC_OP_MSG,  0x07, "M3"   },
        { WSC_OP_MSG,  0x08, "M4"   }, { WSC_OP_MSG,  0x09, "M5"   },
        { WSC_OP_MSG,  0x0A, "M6"   }, { WSC_OP_MSG,  0x0B, "M7"   },
        { WSC_OP_MSG,  0x0C, "M8"   }, { WSC_OP_ACK,  0x0D, "ACK"  },
        { WSC_OP_NACK, 0x0E, "NACK" }, { WSC_OP_DONE, 0x0F, "Done" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t f[] = {
            0x01, 0x20, 0x00, 0x18, 0xFE,
            0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00,
            0x10, 0x4A, 0x00, 0x01, 0x10,
            0x10, 0x22, 0x00, 0x01, 0x00,
        };
        f[12] = (uint8_t)cases[i].op;
        f[23] = (uint8_t)cases[i].msg;
        eap_wsc_info_t w;
        ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
        ASSERT_EQ(w.op_code, cases[i].op);
        ASSERT_EQ(w.msg_type, cases[i].msg);
        ASSERT_STR(wsc_msg_name(w.msg_type), cases[i].name);
        ASSERT_EQ(w.truncated, 0);
        ASSERT_EQ(w.has_uuid_e, 0);
        ASSERT_EQ(w.has_mac, 0);
    }
    ASSERT_STR(wsc_msg_name(0x01), "?");   /* Beacon: not an EAP message */
    ASSERT_STR(wsc_msg_name(-1), "?");
}

static void test_wsc_start_has_no_body(void) {
    /* WSC_Start (Request, Op 0x01): header only, EAP length 14. */
    uint8_t f[] = { 0x01, 0x01, 0x00, 0x0E, 0xFE,
                    0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
                    0x01, 0x00 };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
    ASSERT_EQ(w.op_code, WSC_OP_START);
    ASSERT_EQ(w.msg_type, -1);
    ASSERT_EQ(w.truncated, 0);
    /* One byte short of the Flags octet: not a WSC header. */
    uint8_t s[] = { 0x01, 0x01, 0x00, 0x0D, 0xFE,
                    0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x01 };
    ASSERT_EQ(eap_wsc_parse(s, sizeof(s), &w), 0);
}

static void test_wsc_truncated_tlv(void) {
    /* UUID-E declares 16 bytes, frame holds 8: the value would overrun.
     * Message Type before it survives; UUID-E must not be copied.
     * Body 5 + 5 + 4 + 8 = 22; EAP length 36 = 0x24. */
    uint8_t f[] = {
        0x02, 0x09, 0x00, 0x24, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x47, 0x00, 0x10,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_EQ(w.has_uuid_e, 0);

    /* Near miss: UUID-E declares 16 and 14 are present. A bound that
     * forgets the 4-byte TLV header lets this through and copies two
     * bytes past the frame. Body 4 + 14 = 18; EAP length 32 = 0x20. */
    uint8_t n[] = {
        0x02, 0x09, 0x00, 0x20, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x47, 0x00, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    };
    ASSERT_EQ(eap_wsc_parse(n, sizeof(n), &w), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.has_uuid_e, 0);

    /* A TLV header cut to 3 bytes (Type + half a Length). */
    uint8_t h[] = {
        0x02, 0x09, 0x00, 0x16, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x05,
        0x10, 0x47, 0x00,
    };
    ASSERT_EQ(eap_wsc_parse(h, sizeof(h), &w), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M2);
}

static void test_wsc_eap_length_bounds_the_walk(void) {
    /* EAP Length says 24 but the capture carries a full MAC Address TLV
     * after it. Bytes past the EAP packet are not part of it and must
     * not be read as an attribute. */
    uint8_t f[] = {
        0x02, 0x0A, 0x00, 0x18, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x20, 0x00, 0x06, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
    };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_EQ(w.has_mac, 0);
    ASSERT_EQ(w.truncated, 0);
}

static void test_wsc_wrong_length_attrs_ignored(void) {
    /* Message Type with length 2, UUID-E with 15, MAC with 5 and 7:
     * each ignored, and the walk continues past them to a well-formed
     * Message Type at the end. Body 6 + 19 + 9 + 11 + 5 = 50;
     * EAP length 64 = 0x40. */
    uint8_t f[] = {
        0x02, 0x0B, 0x00, 0x40, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x02, 0x04, 0x04,
        0x10, 0x47, 0x00, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x20, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01,
        0x10, 0x20, 0x00, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
        0x10, 0x22, 0x00, 0x01, 0x07,
    };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
    ASSERT_EQ(w.has_uuid_e, 0);
    ASSERT_EQ(w.has_mac, 0);
    ASSERT_EQ(w.truncated, 0);
    ASSERT_EQ(w.msg_type, WSC_MSG_M3);

    /* A lone 2-byte Message Type, with nothing valid after it to mask
     * a loosened check. EAP length 14 + 6 = 20 = 0x14. */
    uint8_t m[] = {
        0x02, 0x0B, 0x00, 0x14, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x02, 0x04, 0x05,
    };
    ASSERT_EQ(eap_wsc_parse(m, sizeof(m), &w), 1);
    ASSERT_EQ(w.msg_type, -1);
    ASSERT_EQ(w.truncated, 0);
}

static void test_wsc_bad_vendor(void) {
    /* A valid WSC_Start shape with one vendor field wrong each time;
     * the high-byte cases catch a comparison that drops a byte. */
    uint8_t vid[]      = { 0x01, 0x01, 0x00, 0x0E, 0xFE,
                           0x00, 0x37, 0x2B, 0x00, 0x00, 0x00, 0x01,
                           0x01, 0x00 };
    uint8_t vid_hi[]   = { 0x01, 0x01, 0x00, 0x0E, 0xFE,
                           0x01, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
                           0x01, 0x00 };
    uint8_t vtype[]    = { 0x01, 0x01, 0x00, 0x0E, 0xFE,
                           0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x02,
                           0x01, 0x00 };
    uint8_t vtype_hi[] = { 0x01, 0x01, 0x00, 0x0E, 0xFE,
                           0x00, 0x37, 0x2A, 0x01, 0x00, 0x00, 0x01,
                           0x01, 0x00 };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(vid, sizeof(vid), &w), 0);
    ASSERT_EQ(eap_wsc_parse(vid_hi, sizeof(vid_hi), &w), 0);
    ASSERT_EQ(eap_wsc_parse(vtype, sizeof(vtype), &w), 0);
    ASSERT_EQ(eap_wsc_parse(vtype_hi, sizeof(vtype_hi), &w), 0);
}

static void test_wsc_non_wsc_type_254(void) {
    /* RFC 3748 §5.7 Expanded Nak: Vendor-Id 0 (IETF), Vendor-Type 3,
     * proposing WSC as an alternative. Type 254, but not itself WSC. */
    uint8_t nak[]  = { 0x02, 0x03, 0x00, 0x14, 0xFE,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                       0xFE, 0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01 };
    /* Not Type 254, though the bytes after Type look like WSC. */
    uint8_t peap[] = { 0x01, 0x03, 0x00, 0x0E, EAP_TYPE_PEAP,
                       0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
                       0x04, 0x00 };
    uint8_t ok[]   = { 0x03, 0x03, 0x00, 0x04 };   /* EAP-Success */
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(nak, sizeof(nak), &w), 0);
    ASSERT_EQ(eap_wsc_parse(peap, sizeof(peap), &w), 0);
    ASSERT_EQ(eap_wsc_parse(ok, sizeof(ok), &w), 0);
    ASSERT_EQ(w.msg_type, -1);   /* out is reset even on rejection */
    ASSERT_EQ(eap_wsc_parse(NULL, 0, &w), 0);
}

static void test_wsc_fragments(void) {
    /* First fragment of a fragmented M1: MF|LF, Message Length 0x01A0.
     * Its body opens the message, so it is walked; the last TLV is cut
     * by the fragment boundary. Body 5 + 5 + 4 + 4 = 18; EAP 34 = 0x22. */
    uint8_t first[] = {
        0x02, 0x0C, 0x00, 0x22, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x03, 0x01, 0xA0,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x47, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44,
    };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(first, sizeof(first), &w), 1);
    ASSERT_EQ(w.more_fragments, 1);
    ASSERT_EQ(w.msg_length, 0x01A0);
    ASSERT_EQ(w.tlvs_walked, 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.has_uuid_e, 0);

    /* Middle fragment: MF, no LF. Its first bytes happen to spell a
     * Message Type = M8 TLV, but they are mid-value, not a header. */
    uint8_t mid[] = {
        0x02, 0x0D, 0x00, 0x13, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x01,
        0x10, 0x22, 0x00, 0x01, 0x0C,
    };
    ASSERT_EQ(eap_wsc_parse(mid, sizeof(mid), &w), 1);
    ASSERT_EQ(w.more_fragments, 1);
    ASSERT_EQ(w.msg_length, -1);
    ASSERT_EQ(w.tlvs_walked, 0);
    ASSERT_EQ(w.msg_type, -1);

    /* LF claims a 2-byte Message Length the frame does not hold. */
    uint8_t lf_short[] = {
        0x02, 0x0E, 0x00, 0x0F, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x02, 0x01,
    };
    ASSERT_EQ(eap_wsc_parse(lf_short, sizeof(lf_short), &w), 0);

    /* LF with exactly the 2-byte length and no body: valid, empty. */
    uint8_t lf_exact[] = {
        0x02, 0x0E, 0x00, 0x10, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x02, 0x00, 0x00,
    };
    ASSERT_EQ(eap_wsc_parse(lf_exact, sizeof(lf_exact), &w), 1);
    ASSERT_EQ(w.msg_length, 0);
    ASSERT_EQ(w.truncated, 0);
    ASSERT_EQ(w.msg_type, -1);
}

static void test_wsc_device_password_id(void) {
    /* Device Password ID (0x1012, WSC 2.0 §12): 2 bytes big-endian.
     * Body Version + Message Type + Device Password ID = 16;
     * EAP length 14 + 16 = 30 = 0x1E. [28]/[29] are the value. */
    static const int vals[] = {
        WSC_DEV_PWD_ID_PBC,      /* 0x0004 — proximity-only window   */
        WSC_DEV_PWD_ID_DEFAULT,  /* 0x0000 — label PIN               */
        0x0005,                  /* registrar-specified              */
        0x0008,                  /* reserved in WSC 2.0              */
        0x1234,                  /* out of the enumerated range      */
        0xFFFF,
    };
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        uint8_t f[] = {
            0x02, 0x10, 0x00, 0x1E, 0xFE,
            0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
            0x10, 0x4A, 0x00, 0x01, 0x10,
            0x10, 0x22, 0x00, 0x01, 0x04,
            0x10, 0x12, 0x00, 0x02, 0x00, 0x00,
        };
        f[28] = (uint8_t)(vals[i] >> 8);
        f[29] = (uint8_t)(vals[i] & 0xFF);
        eap_wsc_info_t w;
        ASSERT_EQ(eap_wsc_parse(f, sizeof(f), &w), 1);
        ASSERT_EQ(w.msg_type, WSC_MSG_M1);
        /* Reported as read: an unnamed code still says the enrollee
         * asked for something other than PBC, and coercing it would
         * erase that. */
        ASSERT_EQ(w.dev_pwd_id, vals[i]);
        ASSERT_EQ(w.truncated, 0);
    }
    /* 0x0000 is a value, not an absence — the beacon path cannot tell
     * the two apart and this one must. */
    ASSERT_EQ(WSC_DEV_PWD_ID_DEFAULT, 0x0000);
    /* Same spec code, two layers, two spellings (src/beacon_snoop.h). */
    ASSERT_EQ(WSC_DEV_PWD_ID_PBC, WPS_DEV_PWD_ID_PBC);
}

static void test_wsc_device_password_id_malformed(void) {
    /* A length that lies: 1 byte, then 4. Both ignored rather than read
     * from the wrong width, and the walk continues to the Message Type
     * after them. Body 5 + 8 + 5 = 18; EAP length 32 = 0x20. */
    uint8_t lies[] = {
        0x02, 0x11, 0x00, 0x20, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x12, 0x00, 0x01, 0x04,
        0x10, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
        0x10, 0x22, 0x00, 0x01, 0x04,
    };
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(lies, sizeof(lies), &w), 1);
    ASSERT_EQ(w.dev_pwd_id, -1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_EQ(w.truncated, 0);

    /* A lone 1-byte Device Password ID, with nothing valid after it to
     * mask a loosened width check. Body 5; EAP length 19 = 0x13. */
    uint8_t lone[] = {
        0x02, 0x11, 0x00, 0x13, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x12, 0x00, 0x01, 0x04,
    };
    ASSERT_EQ(eap_wsc_parse(lone, sizeof(lone), &w), 1);
    ASSERT_EQ(w.dev_pwd_id, -1);
    ASSERT_EQ(w.truncated, 0);

    /* Declares 2 bytes, one is present: the value would read a byte
     * past the frame. Body 5 + 5 = 10; EAP length 24 = 0x18. */
    uint8_t cut[] = {
        0x02, 0x12, 0x00, 0x18, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x12, 0x00, 0x02, 0x00,
    };
    ASSERT_EQ(eap_wsc_parse(cut, sizeof(cut), &w), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.dev_pwd_id, -1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);

    /* Header cut to 3 bytes (Type + half a Length).
     * Body 5 + 3 = 8; EAP length 22 = 0x16. */
    uint8_t hdr[] = {
        0x02, 0x13, 0x00, 0x16, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x12, 0x00,
    };
    ASSERT_EQ(eap_wsc_parse(hdr, sizeof(hdr), &w), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.dev_pwd_id, -1);

    /* A complete 0x1012 TLV sitting past the declared EAP Length: those
     * bytes are not part of this packet and must not be read as PBC.
     * EAP length 24 = 0x18 covers Version + Message Type only. */
    uint8_t past[] = {
        0x02, 0x14, 0x00, 0x18, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x12, 0x00, 0x02, 0x00, 0x04,
    };
    ASSERT_EQ(eap_wsc_parse(past, sizeof(past), &w), 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_EQ(w.dev_pwd_id, -1);
    ASSERT_EQ(w.truncated, 0);

    /* A middle fragment is not walked at all, so a 0x1012-shaped run of
     * value bytes inside one must not surface as a password ID. */
    uint8_t mid[] = {
        0x02, 0x15, 0x00, 0x14, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x01,
        0x10, 0x12, 0x00, 0x02, 0x00, 0x04,
    };
    ASSERT_EQ(eap_wsc_parse(mid, sizeof(mid), &w), 1);
    ASSERT_EQ(w.tlvs_walked, 0);
    ASSERT_EQ(w.dev_pwd_id, -1);
}

/* A repeated 0x1012. Found in adversarial review of the slice that
 * added this attribute, and pinned rather than quietly "fixed": every
 * attribute in eap_wsc_parse()'s walk is last-wins by plain
 * assignment, so making this one first-wins would make the parser
 * inconsistent with msg_type, uuid_e and mac for no stated reason.
 *
 * The consequence is real and belongs to whoever writes the detector,
 * not to the parser: a crafted M1 carrying PBC (0x0004) and then a
 * second Device Password ID reports the LATER value, so a station can
 * hide an open PBC window from anything that reads dev_pwd_id alone.
 * WPS_PBC_RACE counts sessions from M1, so it must not treat
 * "dev_pwd_id is not PBC" as evidence that PBC was absent. Reported on
 * #82. If the resolution is ever changed to first-wins or to a sticky
 * PBC, these two assertions fail and name the decision. */
static void test_repeated_device_password_id_is_last_wins(void) {
    eap_wsc_info_t w;
    /* PBC first, then PIN: the evasion direction. */
    uint8_t pbc_then_pin[] = {
        0x02, 0x14, 0x00, 0x22, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x12, 0x00, 0x02, 0x00, 0x04,
        0x10, 0x12, 0x00, 0x02, 0x00, 0x00,
    };
    ASSERT_EQ(eap_wsc_parse(pbc_then_pin, sizeof(pbc_then_pin), &w), 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_EQ(w.dev_pwd_id, 0x0000);   /* the later one wins */

    /* PIN first, then PBC: the same rule, opposite order. */
    uint8_t pin_then_pbc[] = {
        0x02, 0x14, 0x00, 0x22, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x12, 0x00, 0x02, 0x00, 0x00,
        0x10, 0x12, 0x00, 0x02, 0x00, 0x04,
    };
    ASSERT_EQ(eap_wsc_parse(pin_then_pbc, sizeof(pin_then_pbc), &w), 1);
    ASSERT_EQ(w.dev_pwd_id, 0x0004);
}

void run_eap_parse_tests(void) {
    TEST_SUITE("EAP inner-frame parser (#31)");
    RUN_TEST(test_request_identity);
    RUN_TEST(test_response_identity_leaks_username);
    RUN_TEST(test_weak_methods);
    RUN_TEST(test_strong_methods_not_weak);
    RUN_TEST(test_success_has_no_type);
    RUN_TEST(test_rejects_short_and_malformed);
    RUN_TEST(test_identity_strips_control_bytes);
    TEST_SUITE("EAP-WSC decoder (#82)");
    RUN_TEST(test_wsc_m1_full);
    RUN_TEST(test_wsc_each_message_type);
    RUN_TEST(test_wsc_start_has_no_body);
    RUN_TEST(test_wsc_truncated_tlv);
    RUN_TEST(test_wsc_eap_length_bounds_the_walk);
    RUN_TEST(test_wsc_wrong_length_attrs_ignored);
    RUN_TEST(test_wsc_bad_vendor);
    RUN_TEST(test_wsc_non_wsc_type_254);
    RUN_TEST(test_wsc_fragments);
    RUN_TEST(test_wsc_device_password_id);
    RUN_TEST(test_wsc_device_password_id_malformed);
    RUN_TEST(test_repeated_device_password_id_is_last_wins);
}
