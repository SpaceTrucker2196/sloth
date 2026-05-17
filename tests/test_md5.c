#include <string.h>
#include "runner.h"
#include "md5.h"

/* RFC 1321 test vectors. */

static void test_md5_empty(void) {
    char hex[33];
    md5_hex((const uint8_t *)"", 0, hex);
    ASSERT_STR(hex, "d41d8cd98f00b204e9800998ecf8427e");
}

static void test_md5_a(void) {
    char hex[33];
    md5_hex((const uint8_t *)"a", 1, hex);
    ASSERT_STR(hex, "0cc175b9c0f1b6a831c399e269772661");
}

static void test_md5_abc(void) {
    char hex[33];
    md5_hex((const uint8_t *)"abc", 3, hex);
    ASSERT_STR(hex, "900150983cd24fb0d6963f7d28e17f72");
}

static void test_md5_message_digest(void) {
    char hex[33];
    md5_hex((const uint8_t *)"message digest", 14, hex);
    ASSERT_STR(hex, "f96b697d7cb7938d525a2f31aaf161d0");
}

static void test_md5_alphabet(void) {
    char hex[33];
    md5_hex((const uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26, hex);
    ASSERT_STR(hex, "c3fcd3d76192e4007dfb496cca67e13b");
}

static void test_md5_long(void) {
    /* 80 chars - exercises multi-block path */
    char hex[33];
    const char *s = "12345678901234567890123456789012345678901234567890"
                    "123456789012345678901234567890";
    md5_hex((const uint8_t *)s, 80, hex);
    ASSERT_STR(hex, "57edf4a22be3c955ac49da2e2107b67a");
}

static void test_md5_streaming(void) {
    /* Same input via update() in chunks. */
    md5_ctx_t ctx;
    uint8_t   digest[16];
    md5_init(&ctx);
    md5_update(&ctx, (const uint8_t *)"ab",  2);
    md5_update(&ctx, (const uint8_t *)"c",   1);
    md5_final(&ctx, digest);

    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[32] = '\0';
    ASSERT_STR(hex, "900150983cd24fb0d6963f7d28e17f72");
}

void run_md5_tests(void) {
    TEST_SUITE("md5 RFC 1321 vectors");
    RUN_TEST(test_md5_empty);
    RUN_TEST(test_md5_a);
    RUN_TEST(test_md5_abc);
    RUN_TEST(test_md5_message_digest);
    RUN_TEST(test_md5_alphabet);
    RUN_TEST(test_md5_long);
    RUN_TEST(test_md5_streaming);
}
