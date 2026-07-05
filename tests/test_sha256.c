#include <string.h>
#include "runner.h"
#include "sha256.h"

/* RFC 6234 §8.5 published test vectors. Confirms the SHA-256
 * implementation is correct end-to-end before we lean on it for JA4. */

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
    TEST_SUITE("sha256 — RFC 6234 vectors");
    RUN_TEST(test_sha256_empty);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_two_block);
    RUN_TEST(test_sha256_million_a);
}
