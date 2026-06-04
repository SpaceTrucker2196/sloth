#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "kerb_snoop.h"

/* Kerberos message detection is gated on the outer ASN.1
 * [APPLICATION] tag byte. We don't need a full DER-encoded message
 * for the message-type test — a single byte suffices. The error-
 * code parser walks the inside of a KRB-ERROR message, so those
 * tests build a credible bit of ASN.1 around the error-code field
 * (tag 0xA6 wrapping INTEGER 0x02). */

/* ── Minimal builders ────────────────────────────────────── */

/* Construct a "barely-credible" KRB-ERROR message: outer
 * [APPLICATION 30] = 0x7E, then a SEQUENCE wrapper, then the
 * [6] error-code field with a 1-byte INTEGER. Padding doesn't
 * matter — the parser walks for the 0xA6 tag and decodes the
 * inner INTEGER, ignoring everything else. */
static int build_krb_error_1byte(uint8_t *out, int code) {
    out[0] = 0x7E;                  /* [APPLICATION 30] constructed */
    out[1] = 0x12;                  /* outer length (placeholder) */
    out[2] = 0x30; out[3] = 0x10;   /* SEQUENCE { len=0x10 */
    /* Padding bytes to push the error-code past the front. The
     * parser scans the first ~96 bytes for the 0xA6 tag. */
    out[4] = 0xA0; out[5] = 0x03; out[6] = 0x02; out[7] = 0x01; out[8] = 0x05;
    out[9] = 0xA1; out[10] = 0x03; out[11] = 0x02; out[12] = 0x01; out[13] = 0x1E;
    out[14] = 0xA6;                 /* [6] error-code */
    out[15] = 0x03;                 /* len = 3 */
    out[16] = 0x02;                 /* INTEGER */
    out[17] = 0x01;                 /* INTEGER len = 1 */
    out[18] = (uint8_t)code;
    out[19] = 0x00;                 /* trailing pad */
    return 20;
}

/* AS-REQ — first byte 0x6A is enough for the message-type test. */
static int build_as_req(uint8_t *out) {
    out[0] = 0x6A;                  /* [APPLICATION 10] constructed */
    out[1] = 0x10;                  /* placeholder length */
    memset(out + 2, 0x00, 16);
    return 18;
}

static int build_as_rep(uint8_t *out) {
    out[0] = 0x6B; out[1] = 0x10; memset(out + 2, 0, 16); return 18;
}
static int build_tgs_req(uint8_t *out) {
    out[0] = 0x6C; out[1] = 0x10; memset(out + 2, 0, 16); return 18;
}
static int build_tgs_rep(uint8_t *out) {
    out[0] = 0x6D; out[1] = 0x10; memset(out + 2, 0, 16); return 18;
}

/* ── Message-type detection ──────────────────────────────── */

static void test_detects_as_req(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_as_req(buf);
    ASSERT_EQ(kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88,
                                  buf, n), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_event_count, 1);
    ASSERT_STR(s.kerb_events[0].src_ip, "10.0.0.5");
    ASSERT_EQ(s.kerb_events[0].as_req_count, 1);
}

static void test_detects_as_rep(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_as_rep(buf);
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_events[0].as_rep_count, 1);
}

static void test_detects_tgs_req_and_rep(void) {
    kerb_snoop_clear();
    uint8_t buf[64];
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88,
                        buf, build_tgs_req(buf));
    kerb_snoop_observe("10.0.0.10", 88, "10.0.0.5", 49152,
                        buf, build_tgs_rep(buf));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    /* Both messages attributed to the client side (10.0.0.5). */
    ASSERT_EQ(s.kerb_event_count, 1);
    ASSERT_EQ(s.kerb_events[0].tgs_req_count, 1);
    ASSERT_EQ(s.kerb_events[0].tgs_rep_count, 1);
}

/* ── Error-code extraction ──────────────────────────────── */

static void test_krb_error_preauth_required(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_krb_error_1byte(buf, 25);
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_events[0].preauth_required_count, 1);
    ASSERT_EQ(s.kerb_events[0].preauth_failed_count,   0);
}

static void test_krb_error_preauth_failed(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_krb_error_1byte(buf, 24);
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_events[0].preauth_failed_count, 1);
}

static void test_krb_error_principal_unknown(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_krb_error_1byte(buf, 6);
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_events[0].principal_unknown_count, 1);
}

static void test_krb_error_other_codes_bucketed(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_krb_error_1byte(buf, 13);
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_events[0].error_other_count, 1);
}

/* ── TCP framing ────────────────────────────────────────── */

/* TCP/88 carries a 4-byte length prefix before the ASN.1 message.
 * The parser must look past it. */
static void test_tcp_length_prefix_skipped(void) {
    kerb_snoop_clear();
    uint8_t buf[64];
    /* 4-byte length prefix (network order), then AS-REQ. */
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x10;
    buf[4] = 0x6A; buf[5] = 0x10; memset(buf + 6, 0, 14);
    ASSERT_EQ(kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88,
                                  buf, 20), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_events[0].as_req_count, 1);
}

/* ── Aggregation ────────────────────────────────────────── */

/* Multiple failures from the same source accumulate into one entry. */
static void test_repeated_failures_accumulate(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_krb_error_1byte(buf, 24);
    for (int i = 0; i < 5; i++)
        kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_event_count, 1);
    ASSERT_EQ(s.kerb_events[0].preauth_failed_count, 5);
}

/* Distinct sources → distinct entries. */
static void test_two_sources_tracked_separately(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_krb_error_1byte(buf, 24);
    kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88, buf, n);
    kerb_snoop_observe("10.0.0.6", 49152, "10.0.0.10", 88, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    kerb_snoop_snapshot(&s);
    ASSERT_EQ(s.kerb_event_count, 2);
}

/* ── Negative cases ─────────────────────────────────────── */

static void test_non_kerb_payload_rejected(void) {
    kerb_snoop_clear();
    static const uint8_t HTTP[] = "GET / HTTP/1.1\r\n";
    ASSERT_EQ(kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 88,
                                  HTTP, sizeof(HTTP) - 1), 0);
}

static void test_no_kdc_port_rejected(void) {
    kerb_snoop_clear();
    uint8_t buf[64]; int n = build_as_req(buf);
    ASSERT_EQ(kerb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 8080,
                                  buf, n), 0);
}

/* ── Suite ──────────────────────────────────────────────── */

void run_kerb_snoop_tests(void) {
    TEST_SUITE("kerb_snoop: detection");
    RUN_TEST(test_detects_as_req);
    RUN_TEST(test_detects_as_rep);
    RUN_TEST(test_detects_tgs_req_and_rep);
    RUN_TEST(test_tcp_length_prefix_skipped);
    RUN_TEST(test_repeated_failures_accumulate);
    RUN_TEST(test_two_sources_tracked_separately);

    TEST_SUITE("kerb_snoop: error codes");
    RUN_TEST(test_krb_error_preauth_required);
    RUN_TEST(test_krb_error_preauth_failed);
    RUN_TEST(test_krb_error_principal_unknown);
    RUN_TEST(test_krb_error_other_codes_bucketed);

    TEST_SUITE("kerb_snoop: negative cases");
    RUN_TEST(test_non_kerb_payload_rejected);
    RUN_TEST(test_no_kdc_port_rejected);
}
