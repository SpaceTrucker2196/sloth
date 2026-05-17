#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "quic_snoop.h"

/*
 * Hand-crafted QUIC Long Header Initial packets for testing.
 *
 * Minimal valid header layout:
 *   [0]   first byte: 0xC0 | type_bits | pnlen_bits
 *   [1-4] version (big-endian)
 *   [5]   DCIL (0-20)
 *   [6..6+DCIL-1]  DCID
 *   [6+DCIL]       SCIL
 *   ...            (at least this byte must be present)
 *
 * Header protection XORs bits 3-0 of byte 0, so on-wire Initial packets
 * may have those bits altered; bits 7-4 are unprotected and are what we
 * inspect for the Long Header / Fixed Bit / Type fields.
 */

/* Build a minimal QUIC Initial Long Header packet into buf.
 * Returns the number of bytes written (>= 8). */
static int make_quic_initial(uint32_t version, uint8_t init_type_bits,
                              uint8_t dcil, uint8_t *buf, int bufsz) {
    int need = 6 + (int)dcil + 1;   /* header through SCIL */
    if (bufsz < need + 1) return 0;
    buf[0] = (uint8_t)(0xC0 | init_type_bits | 0x03); /* Long+Fixed+type+PNLEN */
    buf[1] = (uint8_t)(version >> 24);
    buf[2] = (uint8_t)(version >> 16);
    buf[3] = (uint8_t)(version >>  8);
    buf[4] = (uint8_t)(version);
    buf[5] = dcil;
    for (int i = 0; i < (int)dcil; i++) buf[6 + i] = (uint8_t)(0xAA + i);
    buf[6 + dcil] = 0x00;  /* SCIL = 0 */
    return need;
}

/* ── Detection tests ─────────────────────────────────────── */

static void test_quic_v1_detected(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
    ASSERT_STR("v1", ver);
}

static void test_quic_v2_detected(void) {
    uint8_t buf[32];
    /* QUIC v2 Initial: type bits 5-4 = 01 */
    int len = make_quic_initial(0x6b3343cfu, 0x10, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
    ASSERT_STR("v2", ver);
}

static void test_draft_29_detected(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0xff00001du, 0x00, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
    ASSERT_STR("draft", ver);
}

static void test_draft_32_detected(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0xff000020u, 0x00, 4, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
    ASSERT_STR("draft", ver);
}

static void test_draft_33_detected(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0xff000021u, 0x00, 0, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
    ASSERT_STR("draft", ver);
}

static void test_draft_34_detected(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0xff000022u, 0x00, 0, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
    ASSERT_STR("draft", ver);
}

static void test_zero_length_dcid(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 0, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_max_dcid_length(void) {
    uint8_t buf[64];
    int len = make_quic_initial(0x00000001u, 0x00, 20, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(1, quic_detect(buf, len, ver, sizeof(ver)));
}

/* ── Rejection tests ─────────────────────────────────────── */

static void test_too_short_rejected(void) {
    uint8_t buf[6] = {0xC3, 0x00, 0x00, 0x00, 0x01, 0x00};
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, 6, ver, sizeof(ver)));
}

static void test_short_header_rejected(void) {
    /* bit 7 = 0 → Short Header */
    uint8_t buf[16] = {0x43, 0x00, 0x00, 0x00, 0x01, 0x08};
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, 16, ver, sizeof(ver)));
}

static void test_fixed_bit_zero_rejected(void) {
    /* bit 6 = 0 → Fixed Bit not set (invalid on wire) */
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 8, buf, sizeof(buf));
    buf[0] &= (uint8_t)~0x40;   /* clear Fixed Bit */
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_unknown_version_rejected(void) {
    uint8_t buf[32];
    /* version 0xDEADBEEF is unknown */
    int len = make_quic_initial(0xDEADBEEFu, 0x00, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_version_negotiation_rejected(void) {
    /* Version Negotiation uses version 0x00000000 */
    uint8_t buf[32];
    int len = make_quic_initial(0x00000000u, 0x00, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_v1_handshake_type_rejected(void) {
    /* QUIC v1 Handshake type: bits 5-4 = 10 */
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x20, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_v1_zero_rtt_type_rejected(void) {
    /* QUIC v1 0-RTT type: bits 5-4 = 01 */
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x10, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_v1_retry_type_rejected(void) {
    /* QUIC v1 Retry type: bits 5-4 = 11 */
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x30, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_v2_wrong_initial_type_rejected(void) {
    /* QUIC v2 but using v1's Initial type bits (00) — wrong for v2 */
    uint8_t buf[32];
    int len = make_quic_initial(0x6b3343cfu, 0x00, 8, buf, sizeof(buf));
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_dcil_too_large_rejected(void) {
    /* DCIL = 21 exceeds RFC 9000 maximum of 20 */
    uint8_t buf[64];
    int len = make_quic_initial(0x00000001u, 0x00, 20, buf, sizeof(buf));
    buf[5] = 21;   /* override DCIL to 21 */
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, len, ver, sizeof(ver)));
}

static void test_truncated_after_dcil_rejected(void) {
    /* Header claims DCIL=8 but buffer ends before SCIL byte */
    uint8_t buf[32];
    make_quic_initial(0x00000001u, 0x00, 8, buf, sizeof(buf));
    /* Pass length that cuts off before DCID+SCIL */
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, 7, ver, sizeof(ver)));  /* 7 = header + DCIL only, no DCID */
}

static void test_random_udp_payload_rejected(void) {
    uint8_t buf[32] = {
        0x17, 0x03, 0x03, 0x00, 0x18,  /* TLS record header */
        0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
    };
    char ver[8] = "";
    ASSERT_EQ(0, quic_detect(buf, 15, ver, sizeof(ver)));
}

static void test_ver_null_ok(void) {
    /* Passing NULL for ver_out must not crash */
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 8, buf, sizeof(buf));
    ASSERT_EQ(1, quic_detect(buf, len, NULL, 0));
}

static void test_ver_output_v1(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 4, buf, sizeof(buf));
    char ver[8] = "";
    quic_detect(buf, len, ver, sizeof(ver));
    ASSERT_STR("v1", ver);
}

static void test_ver_output_v2(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x6b3343cfu, 0x10, 4, buf, sizeof(buf));
    char ver[8] = "";
    quic_detect(buf, len, ver, sizeof(ver));
    ASSERT_STR("v2", ver);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_quic_snoop_tests(void) {
    TEST_SUITE("quic_detect — recognition");
    RUN_TEST(test_quic_v1_detected);
    RUN_TEST(test_quic_v2_detected);
    RUN_TEST(test_draft_29_detected);
    RUN_TEST(test_draft_32_detected);
    RUN_TEST(test_draft_33_detected);
    RUN_TEST(test_draft_34_detected);
    RUN_TEST(test_zero_length_dcid);
    RUN_TEST(test_max_dcid_length);

    TEST_SUITE("quic_detect — rejection");
    RUN_TEST(test_too_short_rejected);
    RUN_TEST(test_short_header_rejected);
    RUN_TEST(test_fixed_bit_zero_rejected);
    RUN_TEST(test_unknown_version_rejected);
    RUN_TEST(test_version_negotiation_rejected);
    RUN_TEST(test_v1_handshake_type_rejected);
    RUN_TEST(test_v1_zero_rtt_type_rejected);
    RUN_TEST(test_v1_retry_type_rejected);
    RUN_TEST(test_v2_wrong_initial_type_rejected);
    RUN_TEST(test_dcil_too_large_rejected);
    RUN_TEST(test_truncated_after_dcil_rejected);
    RUN_TEST(test_random_udp_payload_rejected);

    TEST_SUITE("quic_detect — output");
    RUN_TEST(test_ver_null_ok);
    RUN_TEST(test_ver_output_v1);
    RUN_TEST(test_ver_output_v2);
}
