#include "runner.h"
#include "eap_parse.h"
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

void run_eap_parse_tests(void) {
    TEST_SUITE("EAP inner-frame parser (#31)");
    RUN_TEST(test_request_identity);
    RUN_TEST(test_response_identity_leaks_username);
    RUN_TEST(test_weak_methods);
    RUN_TEST(test_strong_methods_not_weak);
    RUN_TEST(test_success_has_no_type);
    RUN_TEST(test_rejects_short_and_malformed);
    RUN_TEST(test_identity_strips_control_bytes);
}
