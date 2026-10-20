#include <string.h>
#include "runner.h"
#include "sha256.h"

/* FIPS 180-4 / NIST CAVP example vectors (the same messages RFC 6234
 * §8.5 reproduces): the empty string, "abc", the 448-bit and 896-bit
 * messages and one million 'a'. Confirms the embedded SHA-256 before
 * JA4 leans on it and before the #92 evidence manifest does — that one
 * puts its output on disk as a claim about evidence files. */

static void test_sha256_empty(void) {
    char hex[65];
    sha256_hex((const uint8_t *)"", 0, hex);
    ASSERT_STR(hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_sha256_abc(void) {
    char hex[65];
    sha256_hex((const uint8_t *)"abc", 3, hex);
    ASSERT_STR(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_sha256_two_block(void) {
    /* Second RFC 6234 vector — spans two 64-byte blocks. */
    const char *msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[65];
    sha256_hex((const uint8_t *)msg, strlen(msg), hex);
    ASSERT_STR(hex,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void test_sha256_896_bit(void) {
    /* FIPS 180-4 SHA-256 example: the 896-bit (112-byte) message, which
     * ends 48 bytes into its second block, so the length goes in a
     * third block. */
    const char *msg =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    ASSERT_EQ((int)strlen(msg), 112);
    char hex[65];
    sha256_hex((const uint8_t *)msg, strlen(msg), hex);
    ASSERT_STR(hex,
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

static void test_sha256_million_a(void) {
    /* Third RFC 6234 vector — one million 'a's exercises the streaming
     * update path (many transform blocks + trailing partial). */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));
    for (int i = 0; i < 1000; i++)
        sha256_update(&ctx, chunk, sizeof(chunk));
    uint8_t digest[32];
    sha256_final(&ctx, digest);
    char hex[65];
    static const char hexc[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i*2    ] = hexc[(digest[i] >> 4) & 0xf];
        hex[i*2 + 1] = hexc[ digest[i]       & 0xf];
    }
    hex[64] = '\0';
    ASSERT_STR(hex,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

void run_sha256_tests(void) {
    TEST_SUITE("sha256 — FIPS 180-4 / CAVP vectors");
    RUN_TEST(test_sha256_empty);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_two_block);
    RUN_TEST(test_sha256_896_bit);
    RUN_TEST(test_sha256_million_a);
}
