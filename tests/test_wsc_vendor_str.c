#include "runner.h"
#include "eap_parse.h"
#include <string.h>

/* WSC M1/M2 vendor-string attributes (#77). Every frame is a literal
 * byte array built from RFC 3748 §5.7 (Expanded Type header) and WSC
 * 2.0 §7.7 (Op-Code, Flags) + §12 (big-endian Type(2) Length(2) Value):
 *
 *   Code Id Len(2) | FE | 00 37 2A | 00 00 00 01 | Op | Flags | TLVs
 *
 * §12 attribute IDs and maxima: Manufacturer 0x1021 (<= 64 B), Model
 * Name 0x1023, Model Number 0x1024, Serial Number 0x1042 (<= 32 B each),
 * all ASCII. M1 carries the Enrollee's strings, M2 the Registrar's.
 * Measurement only: there is no rule over these fields to test. */

static void test_wsc_m1_vendor_strings(void) {
    /* Enrollee -> Registrar M1 (Response). Body 53 B, EAP length
     * 14 + 53 = 67 = 0x43. */
    uint8_t f[] = {
        0x02, 0x21, 0x00, 0x43, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,                               /* WSC_MSG, no flags */
        0x10, 0x4A, 0x00, 0x01, 0x10,             /* Version 1.0       */
        0x10, 0x22, 0x00, 0x01, 0x04,             /* Message Type = M1 */
        0x10, 0x21, 0x00, 0x04, 'A', 'c', 'm', 'e',          /* Manuf. */
        0x10, 0x23, 0x00, 0x06, 'R', 'o', 'u', 't', 'e', 'r',/* Model  */
        0x10, 0x24, 0x00, 0x02, 'X', '1',                    /* Number */
        0x10, 0x42, 0x00, 0x05, 'S', 'N', '1', '2', '3',     /* Serial */
        0x10, 0x20, 0x00, 0x06,                   /* MAC after strings */
        0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,
    };
    ASSERT_EQ((int)sizeof(f), 0x43);     /* the declared length is honest */
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, (int)sizeof(f), &w), 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
    ASSERT_STR(w.manufacturer,  "Acme");
    ASSERT_STR(w.model_name,    "Router");
    ASSERT_STR(w.model_number,  "X1");
    ASSERT_STR(w.serial_number, "SN123");
    ASSERT_EQ(w.vendor_str_clamped, 0);
    ASSERT_EQ(w.truncated, 0);
    /* The string arm returns before the fixed-size chain; an attribute
     * after the strings must still be read. */
    ASSERT_EQ(w.has_mac, 1);
    ASSERT_EQ(w.mac[5], 0x5E);
}

static void test_wsc_m2_registrar_strings(void) {
    /* Registrar -> Enrollee M2 (Request). Only two of the four strings
     * present; the other two must stay "" rather than inherit anything.
     * Body 28 B, EAP length 42 = 0x2A. */
    uint8_t f[] = {
        0x01, 0x22, 0x00, 0x2A, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x22, 0x00, 0x01, 0x05,             /* Message Type = M2 */
        0x10, 0x21, 0x00, 0x03, 'R', 'e', 'g',
        0x10, 0x23, 0x00, 0x07, 'h', 'o', 's', 't', 'a', 'p', 'd',
    };
    ASSERT_EQ((int)sizeof(f), 0x2A);
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, (int)sizeof(f), &w), 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M2);
    ASSERT_STR(w.manufacturer, "Reg");
    ASSERT_STR(w.model_name,   "hostapd");
    ASSERT_STR(w.model_number,  "");
    ASSERT_STR(w.serial_number, "");
}

/* EAP-WSC Response carrying Version, one string attribute of `vlen`
 * octets of `fill`, then a MAC Address attribute. Returns the frame
 * length. The caller's buffer is sized to the largest frame any case
 * builds (vlen 65). */
static int build_one_string(uint8_t *f, uint16_t id, int vlen, uint8_t fill) {
    int n = 0;
    int total = 14 + 5 + 4 + vlen + 10;
    f[n++] = 0x02; f[n++] = 0x30;
    f[n++] = (uint8_t)(total >> 8); f[n++] = (uint8_t)total;
    f[n++] = 0xFE;
    f[n++] = 0x00; f[n++] = 0x37; f[n++] = 0x2A;
    f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x01;
    f[n++] = 0x04; f[n++] = 0x00;
    f[n++] = 0x10; f[n++] = 0x4A; f[n++] = 0x00; f[n++] = 0x01; f[n++] = 0x10;
    f[n++] = (uint8_t)(id >> 8); f[n++] = (uint8_t)id;
    f[n++] = (uint8_t)(vlen >> 8); f[n++] = (uint8_t)vlen;
    memset(f + n, fill, (size_t)vlen); n += vlen;
    f[n++] = 0x10; f[n++] = 0x20; f[n++] = 0x00; f[n++] = 0x06;
    f[n++] = 0x02; f[n++] = 0x00; f[n++] = 0x00;
    f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x77;
    return n;
}

static const char *string_field(const eap_wsc_info_t *w, uint16_t id) {
    switch (id) {
    case WSC_ATTR_MANUFACTURER:  return w->manufacturer;
    case WSC_ATTR_MODEL_NAME:    return w->model_name;
    case WSC_ATTR_MODEL_NUMBER:  return w->model_number;
    default:                     return w->serial_number;
    }
}

static void test_wsc_vendor_strings_clamp_at_the_spec_maximum(void) {
    /* A hostile registrar can claim any length the EAP frame allows.
     * At exactly the §12 maximum the whole value is kept and nothing is
     * flagged; one octet over, the value is cut at the maximum and the
     * clamp is flagged. In both cases the walk carries on to the MAC
     * attribute behind it. */
    static const struct { uint16_t id; int max; } a[] = {
        { WSC_ATTR_MANUFACTURER,  64 },
        { WSC_ATTR_MODEL_NAME,    32 },
        { WSC_ATTR_MODEL_NUMBER,  32 },
        { WSC_ATTR_SERIAL_NUMBER, 32 },
    };
    uint8_t f[14 + 5 + 4 + 65 + 10];
    for (size_t i = 0; i < sizeof(a) / sizeof(a[0]); i++) {
        eap_wsc_info_t w;
        int n = build_one_string(f, a[i].id, a[i].max, 'M');
        ASSERT_EQ(eap_wsc_parse(f, n, &w), 1);
        ASSERT_EQ((int)strlen(string_field(&w, a[i].id)), a[i].max);
        ASSERT_EQ(w.vendor_str_clamped, 0);
        ASSERT_EQ(w.has_mac, 1);

        n = build_one_string(f, a[i].id, a[i].max + 1, 'M');
        ASSERT_EQ(eap_wsc_parse(f, n, &w), 1);
        ASSERT_EQ((int)strlen(string_field(&w, a[i].id)), a[i].max);
        ASSERT_EQ(w.vendor_str_clamped, 1);
        ASSERT_EQ(w.has_mac, 1);
        ASSERT_EQ(w.mac[5], 0x77);
    }
}

static void test_wsc_vendor_strings_drop_non_printable(void) {
    /* §12 defines the four as ASCII. Control bytes, DEL and high bytes
     * are dropped, not mapped, so the stored form is shorter than the
     * attribute. A value of nothing but such bytes is present on the
     * air yet stores "" — the documented meaning of "" includes it. */
    uint8_t f[] = {
        0x02, 0x23, 0x00, 0x24, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x42, 0x00, 0x06, 'A', 'B', 0x01, 0x7F, 0xFF, 'C',
        0x10, 0x23, 0x00, 0x03, 0x1B, 0x00, 0x0A,
    };
    ASSERT_EQ((int)sizeof(f), 0x24);
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, (int)sizeof(f), &w), 1);
    ASSERT_STR(w.serial_number, "ABC");
    ASSERT_STR(w.model_name, "");
    ASSERT_EQ(w.vendor_str_clamped, 0);
}

static void test_wsc_vendor_strings_only_from_their_own_ids(void) {
    /* 0x1011 (Device Name) and 0x1025 sit next to the four IDs in §12's
     * table. Neither is one of the four, so neither may land in a
     * vendor-string field. */
    uint8_t f[] = {
        0x02, 0x24, 0x00, 0x21, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x11, 0x00, 0x03, 'D', 'e', 'v',
        0x10, 0x25, 0x00, 0x03, 'N', 'o', 't',
    };
    ASSERT_EQ((int)sizeof(f), 0x21);
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, (int)sizeof(f), &w), 1);
    ASSERT_EQ(w.tlvs_walked, 1);
    ASSERT_EQ(w.truncated, 0);
    ASSERT_STR(w.manufacturer,  "");
    ASSERT_STR(w.model_name,    "");
    ASSERT_STR(w.model_number,  "");
    ASSERT_STR(w.serial_number, "");
}

static void test_wsc_vendor_strings_repeat_is_last_wins(void) {
    /* The header documents latest-occurrence-wins, the same rule the
     * Device Password ID follows. Two Model Name attributes. */
    uint8_t f[] = {
        0x02, 0x25, 0x00, 0x20, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x23, 0x00, 0x03, 'o', 'n', 'e',
        0x10, 0x23, 0x00, 0x02, 'n', 'o',
    };
    ASSERT_EQ((int)sizeof(f), 0x20);
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(f, (int)sizeof(f), &w), 1);
    ASSERT_STR(w.model_name, "no");
}

static void test_wsc_vendor_strings_not_read_from_unwalked_bytes(void) {
    /* Three ways bytes shaped like a Manufacturer TLV must not become
     * one. (a) A middle fragment (MF set, LF clear): its body starts
     * mid-message. (b) Bytes past the declared EAP length. (c) A
     * Manufacturer whose claimed length runs past the frame. */
    uint8_t mid[] = {
        0x02, 0x26, 0x00, 0x16, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x01,                                /* MF, no LF */
        0x10, 0x21, 0x00, 0x04, 'E', 'v', 'i', 'l',
    };
    ASSERT_EQ((int)sizeof(mid), 0x16);
    eap_wsc_info_t w;
    ASSERT_EQ(eap_wsc_parse(mid, (int)sizeof(mid), &w), 1);
    ASSERT_EQ(w.tlvs_walked, 0);
    ASSERT_STR(w.manufacturer, "");

    /* EAP length 0x13 covers the header + Version only. */
    uint8_t past[] = {
        0x02, 0x27, 0x00, 0x13, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x21, 0x00, 0x04, 'E', 'v', 'i', 'l',
    };
    ASSERT_EQ(eap_wsc_parse(past, (int)sizeof(past), &w), 1);
    ASSERT_EQ(w.tlvs_walked, 1);
    ASSERT_STR(w.manufacturer, "");

    /* Manufacturer claims 32 octets; 4 follow. */
    uint8_t cut[] = {
        0x02, 0x28, 0x00, 0x1B, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x21, 0x00, 0x20, 'E', 'v', 'i', 'l',
    };
    ASSERT_EQ((int)sizeof(cut), 0x1B);
    ASSERT_EQ(eap_wsc_parse(cut, (int)sizeof(cut), &w), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_STR(w.manufacturer, "");
}

void run_wsc_vendor_str_tests(void) {
    TEST_SUITE("EAP-WSC vendor strings (#77)");
    RUN_TEST(test_wsc_m1_vendor_strings);
    RUN_TEST(test_wsc_m2_registrar_strings);
    RUN_TEST(test_wsc_vendor_strings_clamp_at_the_spec_maximum);
    RUN_TEST(test_wsc_vendor_strings_drop_non_printable);
    RUN_TEST(test_wsc_vendor_strings_only_from_their_own_ids);
    RUN_TEST(test_wsc_vendor_strings_repeat_is_last_wins);
    RUN_TEST(test_wsc_vendor_strings_not_read_from_unwalked_bytes);
}
