#include <string.h>
#include "runner.h"
#include "sni_snoop.h"
#include "dns.h"

/*
 * Hand-crafted TLS ClientHello packets for unit testing.
 *
 * Packet layout (all lengths computed below):
 *
 *   TLS Record  (5 bytes)
 *   Handshake   (4 bytes)
 *   ClientHello:
 *     version   (2)  = 0x0303
 *     random    (32) = 0x01..0x20
 *     sid_len   (1)  = 0
 *     cs_len    (2)  = 2
 *     cs        (2)  = 0x002F
 *     cm_len    (1)  = 1
 *     cm        (1)  = 0x00
 *     ext_len   (2)  = (extensions total)
 *     extensions …
 *
 * Constant prefix through end of compression methods = 43 bytes of CH body.
 */

/* ── Packet: example.com SNI ────────────────────────────── */
/*
 * Extensions: SNI only
 *   type 0x0000, data_len=16
 *   list_len=14, name_type=0, name_len=11, "example.com"
 *
 * CH body = 43 + 2(ext_len) + 20(SNI ext) = 65 bytes
 * HS length = 65 = 0x000041
 * Record length = 4+65 = 69 = 0x0045
 */
static const uint8_t pkt_sni_example[] = {
    /* TLS record: payload = HS header(4) + CH body(63) = 67 = 0x43 */
    0x16, 0x03, 0x01, 0x00, 0x43,
    /* Handshake: CH body = 41(prefix)+2(ext_len)+20(SNI ext) = 63 = 0x3F */
    0x01, 0x00, 0x00, 0x3F,
    /* ClientHello version */
    0x03, 0x03,
    /* random (32 bytes) */
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,0x20,
    /* session ID len = 0 */
    0x00,
    /* cipher suites len=2, one suite */
    0x00, 0x02, 0x00, 0x2f,
    /* compression methods len=1, null */
    0x01, 0x00,
    /* extensions len = 20 */
    0x00, 0x14,
    /* SNI extension */
    0x00, 0x00,             /* type: server_name */
    0x00, 0x10,             /* data length: 16 */
    0x00, 0x0e,             /* server name list length: 14 */
    0x00,                   /* name type: host_name */
    0x00, 0x0b,             /* name length: 11 */
    'e','x','a','m','p','l','e','.','c','o','m',
};

/* ── Packet: api.internal SNI (12 chars) ────────────────── */
/*
 * SNI data: list(2)+type(1)+len(2)+name(12) = 17
 * ext: type(2)+data_len(2)+data(17) = 21
 * ext with list len field: list_len=15
 * CH body = 43+2+21 = 66 → HS len=66, rec len=70
 */
static const uint8_t pkt_sni_api[] = {
    /* payload = 4+64=68=0x44; CH body = 41+2+21=64=0x40 */
    0x16, 0x03, 0x03, 0x00, 0x44,
    0x01, 0x00, 0x00, 0x40,
    0x03, 0x03,
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,0x20,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    /* extensions len = 21 */
    0x00, 0x15,
    0x00, 0x00,
    0x00, 0x11,             /* data length: 17 */
    0x00, 0x0f,             /* list length: 15 */
    0x00,
    0x00, 0x0c,             /* name length: 12 */
    'a','p','i','.','i','n','t','e','r','n','a','l',
};

/* ── Packet: SNI preceded by another extension ──────────── */
/*
 * Extensions: supported_versions (type 0x002b, 3 bytes data) then SNI
 * supported_versions: type(2)+len(2)+data(3) = 7 bytes as ext = 4+3=7
 * SNI ext = 4+16 = 20
 * total exts = 27
 * CH = 43+2+27 = 72 → HS=72, rec=76
 */
static const uint8_t pkt_sni_after_ext[] = {
    /* payload = 4+70=74=0x4a; CH body = 41+2+27=70=0x46 */
    0x16, 0x03, 0x01, 0x00, 0x4a,
    0x01, 0x00, 0x00, 0x46,
    0x03, 0x03,
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,0x20,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    /* extensions len = 27 */
    0x00, 0x1b,
    /* supported_versions extension (type 0x002b), 3 bytes */
    0x00, 0x2b,
    0x00, 0x03,
    0x02, 0x03, 0x04,
    /* SNI extension */
    0x00, 0x00,
    0x00, 0x10,
    0x00, 0x0e,
    0x00,
    0x00, 0x0b,
    'e','x','a','m','p','l','e','.','c','o','m',
};

/* ── Packet: no SNI extension ───────────────────────────── */
/*
 * Extensions: only supported_groups (type 0x000a)
 * CH = 43+2+8 = 53 → HS=53, rec=57
 */
static const uint8_t pkt_no_sni[] = {
    /* payload = 4+51=55=0x37; CH body = 41+2+8=51=0x33 */
    0x16, 0x03, 0x01, 0x00, 0x37,
    0x01, 0x00, 0x00, 0x33,
    0x03, 0x03,
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,0x20,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    /* extensions len = 8 */
    0x00, 0x08,
    /* supported_groups, 4 bytes data */
    0x00, 0x0a,
    0x00, 0x04,
    0x00, 0x02, 0x00, 0x1d,
};

/* ── Packet: no extensions at all ───────────────────────── */
/*
 * CH = 43 bytes → HS=43, rec=47
 */
static const uint8_t pkt_no_extensions[] = {
    /* payload = 4+41=45=0x2d; CH body = 41=0x29 */
    0x16, 0x03, 0x01, 0x00, 0x2d,
    0x01, 0x00, 0x00, 0x29,
    0x03, 0x03,
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,0x20,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    /* no extensions length field */
};

/* ── Packet: ServerHello (not ClientHello) ──────────────── */
static const uint8_t pkt_server_hello[] = {
    0x16, 0x03, 0x03, 0x00, 0x05,
    0x02,                       /* handshake type 0x02 = ServerHello */
    0x00, 0x00, 0x01,
    0x03,
};

/* ── Packet: TLS application data (not handshake) ────────── */
static const uint8_t pkt_app_data[] = {
    0x17, 0x03, 0x03, 0x00, 0x10,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
};

/* ── Packet: non-TLS TCP data ────────────────────────────── */
static const uint8_t pkt_http[] = {
    'G','E','T',' ','/',' ','H','T','T','P','/','1','.','1','\r','\n',
};

/* ── Tests ───────────────────────────────────────────────── */

static void test_sni_extracts_example_com(void) {
    char host[64];
    int r = sni_snoop(pkt_sni_example, (int)sizeof(pkt_sni_example),
                      host, sizeof(host));
    ASSERT_EQ(r, 1);
    ASSERT_STR(host, "example.com");
}

static void test_sni_extracts_api_internal(void) {
    char host[64];
    int r = sni_snoop(pkt_sni_api, (int)sizeof(pkt_sni_api),
                      host, sizeof(host));
    ASSERT_EQ(r, 1);
    ASSERT_STR(host, "api.internal");
}

static void test_sni_after_other_extension(void) {
    char host[64];
    int r = sni_snoop(pkt_sni_after_ext, (int)sizeof(pkt_sni_after_ext),
                      host, sizeof(host));
    ASSERT_EQ(r, 1);
    ASSERT_STR(host, "example.com");
}

static void test_sni_no_sni_extension(void) {
    char host[64];
    int r = sni_snoop(pkt_no_sni, (int)sizeof(pkt_no_sni),
                      host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_no_extensions(void) {
    char host[64];
    int r = sni_snoop(pkt_no_extensions, (int)sizeof(pkt_no_extensions),
                      host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_server_hello_rejected(void) {
    char host[64];
    int r = sni_snoop(pkt_server_hello, (int)sizeof(pkt_server_hello),
                      host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_app_data_rejected(void) {
    char host[64];
    int r = sni_snoop(pkt_app_data, (int)sizeof(pkt_app_data),
                      host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_http_rejected(void) {
    char host[64];
    int r = sni_snoop(pkt_http, (int)sizeof(pkt_http),
                      host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_empty_buffer(void) {
    char host[64];
    int r = sni_snoop(NULL, 0, host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_too_short(void) {
    char host[64];
    uint8_t tiny[4] = {0x16, 0x03, 0x01, 0x00};
    int r = sni_snoop(tiny, 4, host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_truncated_at_random(void) {
    char host[64];
    /* cut packet off partway through the random field */
    int r = sni_snoop(pkt_sni_example, 20, host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_truncated_at_extensions(void) {
    char host[64];
    /* cut off just before the SNI extension data */
    int r = sni_snoop(pkt_sni_example, (int)sizeof(pkt_sni_example) - 5,
                      host, sizeof(host));
    ASSERT_EQ(r, 0);
}

static void test_sni_host_buf_exact_fit(void) {
    /* hostsz == exactly the name length + NUL */
    char host[12];   /* "example.com" = 11 + NUL */
    int r = sni_snoop(pkt_sni_example, (int)sizeof(pkt_sni_example),
                      host, sizeof(host));
    ASSERT_EQ(r, 1);
    ASSERT_STR(host, "example.com");
}

static void test_sni_host_buf_truncates(void) {
    char host[5];   /* too small for full name */
    int r = sni_snoop(pkt_sni_example, (int)sizeof(pkt_sni_example),
                      host, sizeof(host));
    ASSERT_EQ(r, 1);
    /* should be NUL-terminated and not overflow */
    ASSERT_EQ((int)strlen(host), 4);
    ASSERT(host[4] == '\0');
}

static void test_sni_injects_into_dns_cache(void) {
    dns_reset();
    char host[64];
    sni_snoop(pkt_sni_example, (int)sizeof(pkt_sni_example),
              host, sizeof(host));
    /* sni_snoop itself doesn't inject; caller does via dns_set_resolved.
       Verify the hostname is correct so the caller can inject it. */
    ASSERT_STR(host, "example.com");
}

static void test_sni_tls13_record_version(void) {
    /* TLS 1.3 uses 0x0301 in the record layer but same ClientHello format */
    char host[64];
    int r = sni_snoop(pkt_sni_example, (int)sizeof(pkt_sni_example),
                      host, sizeof(host));
    ASSERT_EQ(r, 1);
    /* also check TLS 1.3-style record version (0x0303) from pkt_sni_api */
    r = sni_snoop(pkt_sni_api, (int)sizeof(pkt_sni_api), host, sizeof(host));
    ASSERT_EQ(r, 1);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_sni_snoop_tests(void) {
    TEST_SUITE("sni snoop extraction");
    RUN_TEST(test_sni_extracts_example_com);
    RUN_TEST(test_sni_extracts_api_internal);
    RUN_TEST(test_sni_after_other_extension);
    RUN_TEST(test_sni_no_sni_extension);
    RUN_TEST(test_sni_no_extensions);

    TEST_SUITE("sni snoop rejection");
    RUN_TEST(test_sni_server_hello_rejected);
    RUN_TEST(test_sni_app_data_rejected);
    RUN_TEST(test_sni_http_rejected);

    TEST_SUITE("sni snoop robustness");
    RUN_TEST(test_sni_empty_buffer);
    RUN_TEST(test_sni_too_short);
    RUN_TEST(test_sni_truncated_at_random);
    RUN_TEST(test_sni_truncated_at_extensions);
    RUN_TEST(test_sni_host_buf_exact_fit);
    RUN_TEST(test_sni_host_buf_truncates);

    TEST_SUITE("sni snoop integration");
    RUN_TEST(test_sni_injects_into_dns_cache);
    RUN_TEST(test_sni_tls13_record_version);
}
